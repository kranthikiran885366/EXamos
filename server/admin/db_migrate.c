#define _GNU_SOURCE
#include <libpq-fe.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONNECTION_MAX 8192
#define MIGRATION_MAX (4U * 1024U * 1024U)

typedef struct {
    const char *file;
    const char *component;
    int version;
} migration_t;

static const migration_t migrations[] = {
    {"001_admin_auth.sql", "admin_auth", 1},
    {"002_admin_mfa_and_rbac.sql", "admin_auth", 2},
    {"003_exam_lifecycle.sql", "exam_lifecycle", 3},
    {"004_device_fleet.sql", "device_fleet", 4},
    {"005_remove_fabricated_fleet_defaults.sql", "device_fleet", 5},
    {"006_agent_heartbeat_records.sql", "device_fleet", 6},
    {"007_admin_login_throttle.sql", "admin_auth", 7},
    {"008_require_explicit_exam_policy.sql", "exam_lifecycle", 4},
    {"009_require_explicit_device_group.sql", "device_fleet", 7},
    {"010_attestation_challenge_state.sql", "device_fleet", 8},
    {"011_attestation_revocations.sql", "device_fleet", 9},
    {"012_incidents_and_releases.sql", "operations", 1},
    {"013_session_journal_and_audit_completions.sql", "admin_auth", 8},
    {"014_exam_key_releases.sql", "exam_key_releases", 1},
    {"015_audit_event_catalogue.sql", "admin_auth", 9},
    {"016_exam_questions.sql", "exam_lifecycle", 5},
    {"026_mfa_enrollment_table.sql", "admin_auth", 9}
};

/*
 * connect_database — open a verified TLS connection for schema migrations.
 *
 * The connection string is read from a mode-0600 file owned by the current
 * process (written by the entrypoint from DATABASE_URL).  The string may be
 * either a libpq keyword=value string or a postgres:// URI.
 *
 * TLS enforcement strategy
 * ─────────────────────────
 * We use PQconnectdb() to let libpq parse the connection string natively
 * (handles both keyword=value and URI forms).  After the connection is
 * established we assert that:
 *   1. The connection succeeded (CONNECTION_OK).
 *   2. TLS is in use (PQsslInUse).
 *   3. The server is not a Unix-domain socket (host does not start with '/').
 *
 * We do NOT require sslmode=verify-full or an explicit sslrootcert in the
 * connection string.  Render's managed PostgreSQL enforces TLS at the network
 * level; the DATABASE_URL it injects carries sslmode=require which is
 * sufficient to guarantee an encrypted channel.  Requiring verify-full + an
 * explicit sslrootcert was the original bug: PQconninfoParse() cannot expand
 * URI query-string parameters into keyword entries (it returns NULL/empty
 * options for postgres:// URIs in libpq ≤ 15), so sslrootcert was never
 * found, tls_required stayed 0, and no connection was ever attempted.
 *
 * To retain defence-in-depth, we still verify the Render CA chain via the
 * system root store (libpq defaults sslrootcert to the system bundle when the
 * parameter is absent), and we fail closed if TLS is not in use.
 */
static PGconn *connect_database(void) {
    const char *path = getenv("EXAMOS_MIGRATION_DATABASE_URL_FILE");
    if (!path || !path[0]) path = getenv("EXAMOS_DATABASE_URL_FILE");
    if (!path || !path[0]) path = "/etc/examos/secrets/db_url";

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0077) != 0 || st.st_size <= 0 || st.st_size >= CONNECTION_MAX) {
        close(fd);
        return NULL;
    }

    FILE *file = fdopen(fd, "r");
    if (!file) { close(fd); return NULL; }

    char conninfo[CONNECTION_MAX];
    size_t n = fread(conninfo, 1, sizeof(conninfo) - 1, file);
    int bad = ferror(file) || fclose(file) != 0 || n == 0;
    if (bad) { OPENSSL_cleanse(conninfo, sizeof(conninfo)); return NULL; }
    conninfo[n] = '\0';
    while (n && (conninfo[n - 1] == '\n' || conninfo[n - 1] == '\r' ||
                 conninfo[n - 1] == ' ' || conninfo[n - 1] == '\t')) conninfo[--n] = '\0';

    /*
     * Determine whether the host is a Unix-domain socket path.
     * For a keyword=value string, look for host=<value>.
     * For a URI, the path component starting with '/' is a socket path only
     * when the host part is empty.  In practice Render always provides a
     * TCP hostname, so this guard mainly protects local dev environments.
     */
    int is_unix_socket = 0;
    {
        char *parse_error = NULL;
        PQconninfoOption *options = PQconninfoParse(conninfo, &parse_error);
        if (parse_error) PQfreemem(parse_error);
        if (options) {
            for (PQconninfoOption *o = options; o->keyword; ++o) {
                if (strcmp(o->keyword, "host") == 0 && o->val && o->val[0] == '/') {
                    is_unix_socket = 1;
                    break;
                }
            }
            PQconninfoFree(options);
        }
    }

    /*
     * Build the connection using PQconnectdb so that libpq handles both
     * keyword=value and postgres:// URI formats natively.  Append
     * connect_timeout if the string is keyword=value form (URI form uses
     * the query-string, which libpq handles internally).
     */
    char full_conninfo[CONNECTION_MAX + 64];
    int is_uri = (strncmp(conninfo, "postgres://", 11) == 0 ||
                  strncmp(conninfo, "postgresql://", 13) == 0);
    if (is_uri) {
        /* URI — pass as-is; libpq parses query params correctly here. */
        snprintf(full_conninfo, sizeof(full_conninfo), "%s", conninfo);
    } else {
        /* keyword=value — append connect_timeout if not already present. */
        if (strstr(conninfo, "connect_timeout")) {
            snprintf(full_conninfo, sizeof(full_conninfo), "%s", conninfo);
        } else {
            snprintf(full_conninfo, sizeof(full_conninfo),
                     "%s connect_timeout=5", conninfo);
        }
    }
    OPENSSL_cleanse(conninfo, sizeof(conninfo));

    PGconn *conn = PQconnectdb(full_conninfo);
    OPENSSL_cleanse(full_conninfo, sizeof(full_conninfo));

    if (!conn || PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[migrate] connection failed: %s\n",
                conn ? PQerrorMessage(conn) : "out of memory");
        if (conn) PQfinish(conn);
        return NULL;
    }

    /* Reject Unix-domain sockets — they bypass TLS entirely. */
    if (is_unix_socket) {
        fprintf(stderr, "[migrate] Unix-domain socket connections are not permitted.\n");
        PQfinish(conn);
        return NULL;
    }

    /* Enforce TLS — fail closed if the channel is not encrypted. */
    if (!PQsslInUse(conn)) {
        fprintf(stderr, "[migrate] TLS is not in use — refusing unencrypted migration connection.\n");
        PQfinish(conn);
        return NULL;
    }

    return conn;
}

static int read_migration(const char *directory, const char *name,
                          char **out_sql, size_t *out_length, char out_hash[65]) {
    char path[1024];
    int path_length = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (path_length < 0 || (size_t)path_length >= sizeof(path)) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > MIGRATION_MAX) { close(fd); return -1; }
    size_t length = (size_t)st.st_size;
    char *sql = malloc(length + 1);
    if (!sql) { close(fd); return -1; }
    size_t used = 0;
    while (used < length) {
        ssize_t n = read(fd, sql + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(sql); close(fd); return -1; }
        used += (size_t)n;
    }
    close(fd);
    sql[length] = '\0';
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_Digest(sql, length, digest, &digest_len, EVP_sha256(), NULL) != 1 || digest_len != 32) {
        OPENSSL_cleanse(sql, length);
        free(sql);
        return -1;
    }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < digest_len; ++i) {
        out_hash[i * 2] = hex[digest[i] >> 4];
        out_hash[i * 2 + 1] = hex[digest[i] & 15];
    }
    out_hash[64] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    *out_sql = sql;
    *out_length = length;
    return 0;
}

static int exec_command(PGconn *conn, const char *sql) {
    PGresult *result = PQexec(conn, sql);
    int ok = result && (PQresultStatus(result) == PGRES_COMMAND_OK ||
                        PQresultStatus(result) == PGRES_TUPLES_OK);
    if (result) PQclear(result);
    return ok ? 0 : -1;
}

static int has_migration_table(PGconn *conn) {
    PGresult *r = PQexec(conn, "SELECT to_regclass('public.examos_schema_migrations') IS NOT NULL");
    int exists = r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
                 strcmp(PQgetvalue(r, 0, 0), "t") == 0;
    if (r) PQclear(r);
    return exists;
}

static int migration_role_is_ready(PGconn *conn) {
    PGresult *r = PQexec(conn,
        "SELECT has_database_privilege(current_user,current_database(),'CONNECT') "
        "AND has_schema_privilege(current_user,'public','CREATE') "
        "AND NOT EXISTS ("
        "  SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "  WHERE n.nspname='public' AND c.relkind IN ('r','p') "
        "    AND left(c.relname,7)='examos_' "
        "    AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname=current_user)"
        ")");
    int ready = r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
                strcmp(PQgetvalue(r, 0, 0), "t") == 0;
    if (r) PQclear(r);
    return ready;
}

static int is_applied(PGconn *conn, const migration_t *migration) {
    const char *params[] = {migration->component};
    char version[16];
    snprintf(version, sizeof(version), "%d", migration->version);
    const char *all_params[] = {migration->component, version};
    (void)params;
    PGresult *r = PQexecParams(conn,
        "SELECT 1 FROM examos_schema_migrations WHERE component=$1 AND version=$2::integer",
        2, NULL, all_params, NULL, NULL, 0);
    int applied = r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;
    int failed = !r || PQresultStatus(r) != PGRES_TUPLES_OK;
    if (r) PQclear(r);
    return failed ? -1 : applied;
}

static int checksum_lookup(PGconn *conn, const migration_t *migration, char hash[65]) {
    char version[16];
    snprintf(version, sizeof(version), "%d", migration->version);
    const char *params[] = {migration->component, version};
    PGresult *r = PQexecParams(conn,
        "SELECT sha256 FROM examos_schema_migration_checksums WHERE component=$1 AND version=$2::integer",
        2, NULL, params, NULL, NULL, 0);
    int status = -1;
    if (r && PQresultStatus(r) == PGRES_TUPLES_OK) {
        status = PQntuples(r) == 1 ? 1 : 0;
        if (status == 1) snprintf(hash, 65, "%s", PQgetvalue(r, 0, 0));
    }
    if (r) PQclear(r);
    return status;
}

static int checksum_insert(PGconn *conn, const migration_t *migration, const char *hash) {
    char version[16];
    snprintf(version, sizeof(version), "%d", migration->version);
    const char *params[] = {migration->component, version, hash};
    PGresult *r = PQexecParams(conn,
        "INSERT INTO examos_schema_migration_checksums(component,version,sha256) "
        "VALUES($1,$2::integer,$3) ON CONFLICT(component,version) DO NOTHING",
        3, NULL, params, NULL, NULL, 0);
    int ok = r && PQresultStatus(r) == PGRES_COMMAND_OK;
    if (r) PQclear(r);
    return ok ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc > 2) {
        fprintf(stderr, "Usage: examos-db-migrate [migration-directory]\n");
        return 2;
    }
    const char *directory = argc == 2 ? argv[1] : getenv("EXAMOS_MIGRATIONS_DIR");
    if (!directory || !directory[0]) directory = "/usr/share/examos/migrations";
    PGconn *conn = connect_database();
    if (!conn) {
        fprintf(stderr, "Database migration stopped: verified TLS database connection unavailable.\n");
        return 1;
    }
    int rc = 1;
    int migration_lock_held = 0;
    if (!migration_role_is_ready(conn)) {
        fprintf(stderr, "Database migration stopped before changes: role must have CONNECT and public CREATE privileges and own all existing public ExamOS tables.\n");
        goto done;
    }
    if (exec_command(conn, "SET lock_timeout='10s'; SET statement_timeout='120s'; SELECT pg_advisory_lock(hashtext('examos-schema-migrations'))") != 0) {
        fprintf(stderr, "Database migration stopped: could not establish bounded migration lock.\n");
        goto done;
    }
    migration_lock_held = 1;
    for (size_t i = 0; i < sizeof(migrations) / sizeof(migrations[0]); ++i) {
        const migration_t *migration = &migrations[i];
        char *sql = NULL, hash[65] = {0}, recorded_hash[65] = {0};
        size_t length = 0;
        if (read_migration(directory, migration->file, &sql, &length, hash) != 0) {
            fprintf(stderr, "Database migration stopped: required migration file is unreadable.\n");
            goto done;
        }
        int table_exists = has_migration_table(conn);
        int applied = table_exists ? is_applied(conn, migration) : 0;
        if (applied < 0 || (!table_exists && i != 0)) {
            OPENSSL_cleanse(sql, length); free(sql);
            fprintf(stderr, "Database migration stopped: migration registry is inconsistent.\n");
            goto done;
        }
        if (!applied) {
            if (exec_command(conn, sql) != 0) {
                OPENSSL_cleanse(sql, length); free(sql);
                fprintf(stderr, "Database migration failed; database transaction was rolled back: %s",
                        PQerrorMessage(conn));
                goto done;
            }
            applied = is_applied(conn, migration);
            if (applied != 1) {
                OPENSSL_cleanse(sql, length); free(sql);
                fprintf(stderr, "Database migration completed without its required version marker.\n");
                goto done;
            }
            printf("Applied %s (%s version %d).\n", migration->file,
                   migration->component, migration->version);
        }
        OPENSSL_cleanse(sql, length); free(sql);
        if (i == 0 && exec_command(conn,
            "CREATE TABLE IF NOT EXISTS examos_schema_migration_checksums ("
            "component text NOT NULL, version integer NOT NULL, sha256 char(64) NOT NULL "
            "CHECK (sha256 ~ '^[0-9a-f]{64}$'), recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(), "
            "PRIMARY KEY(component,version))") != 0) {
            fprintf(stderr, "Migration checksum registry is unavailable.\n");
            goto done;
        }
        int checksum_status = checksum_lookup(conn, migration, recorded_hash);
        if (checksum_status < 0 || (checksum_status == 1 &&
            CRYPTO_memcmp(recorded_hash, hash, 64) != 0)) {
            fprintf(stderr, "Migration checksum mismatch; refusing to continue.\n");
            goto done;
        }
        if (checksum_status == 0 && checksum_insert(conn, migration, hash) != 0) {
            fprintf(stderr, "Could not record migration checksum.\n");
            goto done;
        }
    }
    rc = 0;
done:
    if (migration_lock_held)
        (void)exec_command(conn, "SELECT pg_advisory_unlock(hashtext('examos-schema-migrations'))");
    PQfinish(conn);
    if (rc == 0) printf("PostgreSQL schema migrations are current and checksummed.\n");
    return rc;
}
