#define _GNU_SOURCE
#include <libpq-fe.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONNINFO_MAX 8192

static PGconn *connect_configured_database(void)
{
    const char *path = getenv("EXAMOS_DATABASE_URL_FILE");
    if (!path || !path[0]) path = "/etc/examos/secrets/db_url";
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & 0077) != 0 ||
        info.st_size <= 0 || info.st_size >= CONNINFO_MAX) {
        close(fd);
        return NULL;
    }
    FILE *file = fdopen(fd, "r");
    if (!file) { close(fd); return NULL; }
    char conninfo[CONNINFO_MAX];
    size_t length = fread(conninfo, 1, sizeof(conninfo) - 1, file);
    int failed = ferror(file) || fclose(file) != 0 || length == 0;
    if (failed) { OPENSSL_cleanse(conninfo, sizeof(conninfo)); return NULL; }
    conninfo[length] = '\0';
    while (length && (conninfo[length - 1] == '\n' || conninfo[length - 1] == '\r' ||
                      conninfo[length - 1] == ' ' || conninfo[length - 1] == '\t'))
        conninfo[--length] = '\0';

    char *parse_error = NULL;
    PQconninfoOption *options = PQconninfoParse(conninfo, &parse_error);
    const char *host = NULL, *sslmode = NULL, *root_cert = NULL;
    if (options) {
        for (PQconninfoOption *option = options; option->keyword; ++option) {
            if (!option->val || !option->val[0]) continue;
            if (strcmp(option->keyword, "host") == 0) host = option->val;
            else if (strcmp(option->keyword, "sslmode") == 0) sslmode = option->val;
            else if (strcmp(option->keyword, "sslrootcert") == 0) root_cert = option->val;
        }
    }
    int tls_configured = host && host[0] && host[0] != '/' && sslmode &&
        strcmp(sslmode, "verify-full") == 0 && root_cert && root_cert[0];
    PGconn *connection = NULL;
    if (tls_configured) connection = PQconnectdb(conninfo);
    if (options) PQconninfoFree(options);
    if (parse_error) PQfreemem(parse_error);
    OPENSSL_cleanse(conninfo, sizeof(conninfo));
    if (!connection || PQstatus(connection) != CONNECTION_OK || !PQsslInUse(connection)) {
        if (connection) PQfinish(connection);
        return NULL;
    }
    return connection;
}

static int query_ok(PGconn *connection, const char *sql,
                    ExecStatusType expected_status, int expected_rows)
{
    PGresult *result = PQexec(connection, sql);
    int okay = result && PQresultStatus(result) == expected_status &&
        (expected_rows < 0 || PQntuples(result) == expected_rows);
    if (result) PQclear(result);
    return okay;
}

static int migration_ready(PGconn *connection)
{
    PGresult *result = PQexec(connection,
        "SELECT to_regclass('public.examos_attestation_challenges') IS NOT NULL "
        "AND to_regclass('public.examos_attestation_revocations') IS NOT NULL "
        "AND (SELECT max(version) FROM examos_schema_migrations "
        "WHERE component='device_fleet')>=42 "
        "AND (SELECT COUNT(*)=3 FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='examos_attestation_challenges' "
        "AND column_name IN ('institution_id','purpose','created_by'))");
    int ready = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
        PQntuples(result) == 1 && strcmp(PQgetvalue(result, 0, 0), "t") == 0;
    if (result) PQclear(result);
    return ready;
}

static int random_hex(unsigned char *bytes, size_t length, char *out)
{
    static const char alphabet[] = "0123456789abcdef";
    if (RAND_bytes(bytes, (int)length) != 1) return -1;
    for (size_t i = 0; i < length; ++i) {
        out[i * 2] = alphabet[bytes[i] >> 4];
        out[i * 2 + 1] = alphabet[bytes[i] & 15];
    }
    out[length * 2] = '\0';
    return 0;
}

int main(void)
{
    PGconn *connection = connect_configured_database();
    if (!connection) {
        fprintf(stderr, "BLOCKED: configured ExamOS database unavailable or not verified by TLS.\n");
        return 2;
    }
    if (!migration_ready(connection)) {
        fprintf(stderr, "FAIL: attestation challenge/revocation migrations are not current.\n");
        PQfinish(connection);
        return 1;
    }

    unsigned char entropy[32], nonce_digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    char suffix[65], nonce_hash[65], attestation_id[64], session_id[64];
    char device_id[64], release_id[64];
    if (random_hex(entropy, sizeof(entropy), suffix) != 0 ||
        EVP_Digest(suffix, strlen(suffix), nonce_digest, &digest_length,
                   EVP_sha256(), NULL) != 1 || digest_length != 32) {
        fprintf(stderr, "FAIL: cryptographic test identifiers could not be generated.\n");
        PQfinish(connection);
        return 1;
    }
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        nonce_hash[i * 2] = alphabet[nonce_digest[i] >> 4];
        nonce_hash[i * 2 + 1] = alphabet[nonce_digest[i] & 15];
    }
    nonce_hash[64] = '\0';
    snprintf(attestation_id, sizeof(attestation_id), "attest-%.32s", suffix);
    snprintf(session_id, sizeof(session_id), "dbtest-%.32s", suffix);
    snprintf(device_id, sizeof(device_id), "dbtest-%.32s", suffix);
    snprintf(release_id, sizeof(release_id), "dbtest-%.32s", suffix);
    OPENSSL_cleanse(entropy, sizeof(entropy));
    OPENSSL_cleanse(nonce_digest, sizeof(nonce_digest));

    if (!query_ok(connection, "BEGIN", PGRES_COMMAND_OK, -1)) goto fail;
    const char *institution_id = "integration-test";
    const char *purpose = "re_attestation";
    const char *created_by = "integration-test";
    const char *challenge_params[] = {
        attestation_id, session_id, device_id, release_id, institution_id,
        purpose, created_by, nonce_hash
    };
    PGresult *result = PQexecParams(connection,
        "INSERT INTO examos_attestation_challenges "
        "(attestation_id,session_id,device_id,release_id,institution_id,purpose,created_by,"
        "nonce_sha256,state,expires_at) "
        "VALUES($1,$2,$3,$4,$5,$6,$7,$8,'PENDING',clock_timestamp()+interval '120 seconds')",
        8, NULL, challenge_params, NULL, NULL, 0);
    int inserted = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (!inserted) goto rollback_fail;

    result = PQexecParams(connection,
        "UPDATE examos_attestation_challenges SET state='VERIFYING',claimed_at=clock_timestamp() "
        "WHERE nonce_sha256=$1 AND device_id=$2 AND release_id=$3 "
        "AND institution_id=$4 AND purpose=$5 AND state='PENDING' "
        "AND expires_at>clock_timestamp() RETURNING attestation_id",
        5, NULL, (const char *const[]){nonce_hash, device_id, release_id,
                                      institution_id, purpose}, NULL, NULL, 0);
    int claimed = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;
    if (result) PQclear(result);
    if (!claimed) goto rollback_fail;

    result = PQexecParams(connection,
        "UPDATE examos_attestation_challenges SET state='VERIFYING',claimed_at=clock_timestamp() "
        "WHERE nonce_sha256=$1 AND device_id=$2 AND release_id=$3 "
        "AND institution_id=$4 AND purpose=$5 AND state='PENDING' "
        "AND expires_at>clock_timestamp() RETURNING attestation_id",
        5, NULL, (const char *const[]){nonce_hash, device_id, release_id,
                                      institution_id, purpose}, NULL, NULL, 0);
    int replay_blocked = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 0;
    if (result) PQclear(result);
    if (!replay_blocked) goto rollback_fail;

    result = PQexecParams(connection,
        "UPDATE examos_attestation_challenges SET state='TRUSTED',verified_at=clock_timestamp() "
        "WHERE nonce_sha256=$1 AND state='VERIFYING'",
        1, NULL, (const char *const[]){nonce_hash}, NULL, NULL, 0);
    int trusted = result && PQresultStatus(result) == PGRES_COMMAND_OK &&
        strcmp(PQcmdTuples(result), "1") == 0;
    if (result) PQclear(result);
    if (!trusted) goto rollback_fail;

    result = PQexecParams(connection,
        "INSERT INTO examos_attestation_revocations(target_type,target_id,reason) "
        "VALUES('DEVICE',$1,'INTEGRATION_TEST')",
        1, NULL, (const char *const[]){device_id}, NULL, NULL, 0);
    int revoked = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (!revoked) goto rollback_fail;

    result = PQexecParams(connection,
        "UPDATE examos_attestation_challenges SET state='REVOKED',failure_code='DEVICE_REVOKED' "
        "WHERE device_id=$1 AND state IN ('PENDING','VERIFYING','TRUSTED')",
        1, NULL, (const char *const[]){device_id}, NULL, NULL, 0);
    int marked_revoked = result && PQresultStatus(result) == PGRES_COMMAND_OK &&
        strcmp(PQcmdTuples(result), "1") == 0;
    if (result) PQclear(result);
    if (!marked_revoked) goto rollback_fail;

    result = PQexecParams(connection,
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM examos_attestation_revocations r "
        "WHERE r.target_type='DEVICE' AND r.target_id=c.device_id) "
        "THEN 'REVOKED' ELSE c.state END FROM examos_attestation_challenges c "
        "WHERE c.attestation_id=$1",
        1, NULL, (const char *const[]){attestation_id}, NULL, NULL, 0);
    int status_revoked = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
        PQntuples(result) == 1 && strcmp(PQgetvalue(result, 0, 0), "REVOKED") == 0;
    if (result) PQclear(result);
    if (!status_revoked) goto rollback_fail;

    if (!query_ok(connection, "ROLLBACK", PGRES_COMMAND_OK, -1)) goto fail;
    PQfinish(connection);
    OPENSSL_cleanse(nonce_hash, sizeof(nonce_hash));
    puts("PASS: live PostgreSQL TLS, migration 42, tenant/purpose-bound single-use claim, replay rejection, durable revocation, and rollback cleanup");
    return 0;

rollback_fail:
    (void)PQexec(connection, "ROLLBACK");
fail:
    fprintf(stderr, "FAIL: attestation database transaction did not satisfy the expected state transitions.\n");
    PQfinish(connection);
    OPENSSL_cleanse(nonce_hash, sizeof(nonce_hash));
    return 1;
}
