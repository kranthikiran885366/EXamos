#define _GNU_SOURCE
#include "../include/admin_auth_store.h"
#include "../include/config_manager.h"
#include "../include/secure_token.h"
#include "../include/totp.h"

#include <libpq-fe.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define AUTH_DATABASE_URL_MAX 8192

static pthread_mutex_t g_store_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_pool_lock  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_pool_cond  = PTHREAD_COND_INITIALIZER;

static char *g_conninfo = NULL;
static PGconn *g_conn_pool[MAX_POOL_CONNECTIONS] = {NULL};
static int     g_conn_busy[MAX_POOL_CONNECTIONS] = {0};
static int     g_initialized = 0;

/* Helper: parse connection string to enforce secure remote TLS */
static int parse_required_connection_settings(const char *conninfo) {
    char *error = NULL;
    PQconninfoOption *options = PQconninfoParse(conninfo, &error);
    if (!options) {
        if (error) PQfreemem(error);
        return -1;
    }

    const char *host = NULL;
    const char *sslmode = NULL;
    const char *sslrootcert = NULL;
    for (PQconninfoOption *option = options; option->keyword; ++option) {
        if (!option->val || !option->val[0]) continue;
        if (strcmp(option->keyword, "host") == 0) host = option->val;
        else if (strcmp(option->keyword, "sslmode") == 0) sslmode = option->val;
        else if (strcmp(option->keyword, "sslrootcert") == 0) sslrootcert = option->val;
    }
    int valid = host && host[0] && host[0] != '/' &&
                sslmode && strcmp(sslmode, "verify-full") == 0 &&
                sslrootcert && sslrootcert[0];
    PQconninfoFree(options);
    return valid ? 0 : -1;
}

static PGconn *create_raw_connection(void) {
    pthread_mutex_lock(&g_store_lock);
    const char *conninfo = g_conninfo;
    PGconn *connection = conninfo ? PQconnectdb(conninfo) : NULL;
    pthread_mutex_unlock(&g_store_lock);

    if (!connection || PQstatus(connection) != CONNECTION_OK) {
        if (connection) PQfinish(connection);
        return NULL;
    }
    if (strcmp(PQsslAttribute(connection, "library") ? "TLS" : "NO_TLS", "TLS") != 0) {
        PQfinish(connection);
        return NULL;
    }
    return connection;
}

/* Thread-safe connection pool acquisition */
PGconn *acquire_db_connection(void) {
    pthread_mutex_lock(&g_pool_lock);
    while (g_initialized) {
        for (int i = 0; i < MAX_POOL_CONNECTIONS; ++i) {
            if (!g_conn_busy[i]) {
                if (!g_conn_pool[i] || PQstatus(g_conn_pool[i]) != CONNECTION_OK) {
                    if (g_conn_pool[i]) PQfinish(g_conn_pool[i]);
                    g_conn_pool[i] = create_raw_connection();
                }
                if (g_conn_pool[i]) {
                    g_conn_busy[i] = 1;
                    pthread_mutex_unlock(&g_pool_lock);
                    return g_conn_pool[i];
                }
            }
        }
        pthread_cond_wait(&g_pool_cond, &g_pool_lock);
    }
    pthread_mutex_unlock(&g_pool_lock);
    return NULL;
}
static PGconn *acquire_connection(void) { return acquire_db_connection(); }

/* Thread-safe connection pool release */
void release_db_connection(PGconn *conn, int broken) {
    if (!conn) return;
    pthread_mutex_lock(&g_pool_lock);
    for (int i = 0; i < MAX_POOL_CONNECTIONS; ++i) {
        if (g_conn_pool[i] == conn) {
            if (broken || PQstatus(conn) != CONNECTION_OK) {
                PQfinish(conn);
                g_conn_pool[i] = NULL;
            }
            g_conn_busy[i] = 0;
            pthread_cond_signal(&g_pool_cond);
            break;
        }
    }
    pthread_mutex_unlock(&g_pool_lock);
}
static void release_connection(PGconn *conn, int broken) { release_db_connection(conn, broken); }

static int load_database_url(char **out_conninfo) {
    const char *path = getenv("EXAMOS_DATABASE_URL_FILE");
    if (!path || !path[0]) {
        path = "/etc/examos/secrets/db_url";
    }
    FILE *file = fopen(path, "r");
    if (!file) return -1;

    char contents[AUTH_DATABASE_URL_MAX];
    size_t length = fread(contents, 1, sizeof(contents) - 1, file);
    int read_error = ferror(file);
    int close_error = fclose(file);
    if (read_error || close_error || length == 0) {
        OPENSSL_cleanse(contents, sizeof(contents));
        return -1;
    }
    contents[length] = '\0';
    while (length > 0 && (contents[length - 1] == '\n' ||
                          contents[length - 1] == '\r' ||
                          contents[length - 1] == ' ' ||
                          contents[length - 1] == '\t')) {
        contents[--length] = '\0';
    }
    size_t start = 0;
    while (contents[start] == ' ' || contents[start] == '\t') ++start;
    if (start > 0) memmove(contents, contents + start, length - start + 1);

    if (!contents[0] || parse_required_connection_settings(contents) != 0) {
        OPENSSL_cleanse(contents, sizeof(contents));
        return -1;
    }
    *out_conninfo = strdup(contents);
    OPENSSL_cleanse(contents, sizeof(contents));
    return *out_conninfo ? 0 : -1;
}

static int verify_schema(PGconn *connection) {
    PGresult *result = PQexec(connection,
        "SELECT MAX(version) FROM examos_schema_migrations "
        "WHERE component = 'admin_auth'");
    int valid = 0;
    if (result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1) {
        const char *val = PQgetvalue(result, 0, 0);
        if (val && atoi(val) >= 1) valid = 1;
    }
    if (result) PQclear(result);
    return valid ? 0 : -1;
}

int admin_auth_store_init(void) {
    char *conninfo = NULL;
    if (load_database_url(&conninfo) != 0) {
        fprintf(stderr, "[AdminAuth] FATAL: database connection configuration missing or invalid.\n");
        return -1;
    }

    pthread_mutex_lock(&g_store_lock);
    free(g_conninfo);
    g_conninfo = conninfo;
    pthread_mutex_unlock(&g_store_lock);

    pthread_mutex_lock(&g_pool_lock);
    g_initialized = 1;
    pthread_mutex_unlock(&g_pool_lock);

    PGconn *connection = acquire_connection();
    if (!connection) {
        fprintf(stderr, "[AdminAuth] FATAL: PostgreSQL connection or verified TLS handshake failed.\n");
        admin_auth_store_shutdown();
        return -1;
    }

    int schema_ok = verify_schema(connection);
    release_connection(connection, 0);

    if (schema_ok != 0) {
        fprintf(stderr, "[AdminAuth] FATAL: required admin_auth schema migrations not applied.\n");
        admin_auth_store_shutdown();
        return -1;
    }
    return 0;
}

void admin_auth_store_shutdown(void) {
    pthread_mutex_lock(&g_pool_lock);
    g_initialized = 0;
    for (int i = 0; i < MAX_POOL_CONNECTIONS; ++i) {
        if (g_conn_pool[i]) {
            PQfinish(g_conn_pool[i]);
            g_conn_pool[i] = NULL;
        }
        g_conn_busy[i] = 0;
    }
    pthread_cond_broadcast(&g_pool_cond);
    pthread_mutex_unlock(&g_pool_lock);

    pthread_mutex_lock(&g_store_lock);
    if (g_conninfo) {
        OPENSSL_cleanse(g_conninfo, strlen(g_conninfo));
        free(g_conninfo);
        g_conninfo = NULL;
    }
    pthread_mutex_unlock(&g_store_lock);
}

int admin_role_has_permission(user_role_t role, uint32_t permission) {
    if (role == ROLE_PLATFORM_OWNER) return 1;

    switch (permission) {
        case AUTH_PERM_READ:
            return (role >= ROLE_PLATFORM_OWNER && role <= ROLE_SUPPORT_ENGINEER);
        case AUTH_PERM_EXAM_MUTATION:
            return (role == ROLE_INSTITUTION_ADMIN || role == ROLE_EXAM_MANAGER);
        case AUTH_PERM_FLEET_MUTATION:
            return (role == ROLE_INSTITUTION_ADMIN || role == ROLE_TECH_OPERATOR);
        case AUTH_PERM_SECURITY_ADMIN:
            return (role == ROLE_INSTITUTION_ADMIN || role == ROLE_SECURITY_ADMIN);
        case AUTH_PERM_USER_MANAGEMENT:
            return (role == ROLE_PLATFORM_OWNER || role == ROLE_INSTITUTION_ADMIN);
        default:
            return 0;
    }
}

static int parse_user_row(PGresult *result, int row, user_account_t *user,
                          char *out_totp_secret, size_t secret_len) {
    if (PQgetisnull(result, row, 0) || PQgetisnull(result, row, 1) ||
        PQgetisnull(result, row, 2) || PQgetisnull(result, row, 6)) return -1;
    memset(user, 0, sizeof(*user));
    snprintf(user->user_id, sizeof(user->user_id), "%s", PQgetvalue(result, row, 0));
    snprintf(user->username, sizeof(user->username), "%s", PQgetvalue(result, row, 1));
    snprintf(user->password_hash, sizeof(user->password_hash), "%s", PQgetvalue(result, row, 2));
    snprintf(user->full_name, sizeof(user->full_name), "%s", PQgetvalue(result, row, 3));
    snprintf(user->email, sizeof(user->email), "%s", PQgetvalue(result, row, 4));
    snprintf(user->institution_id, sizeof(user->institution_id), "%s", PQgetvalue(result, row, 5));
    user->role = (user_role_t)strtol(PQgetvalue(result, row, 6), NULL, 10);
    user->mfa_enabled = strcmp(PQgetvalue(result, row, 7), "t") == 0;
    user->active = strcmp(PQgetvalue(result, row, 8), "t") == 0;
    user->created_at = (time_t)strtoll(PQgetvalue(result, row, 9), NULL, 10);
    user->last_login = (time_t)strtoll(PQgetvalue(result, row, 10), NULL, 10);

    if (out_totp_secret && secret_len > 0) {
        if (!PQgetisnull(result, row, 11)) {
            snprintf(out_totp_secret, secret_len, "%s", PQgetvalue(result, row, 11));
        } else {
            out_totp_secret[0] = '\0';
        }
    }
    return user->role >= ROLE_PLATFORM_OWNER && user->role <= ROLE_SUPPORT_ENGINEER ? 0 : -1;
}

int admin_auth_store_login(const char *username, const char *password,
                           const char *mfa_code, auth_session_t *out_session) {
    if (!username || !username[0] || !password || !out_session) return AUTH_LOGIN_FAILED;

    PGconn *conn = acquire_connection();
    if (!conn) return AUTH_LOGIN_FAILED;

    const char *user_params[] = { username };
    PGresult *result = PQexecParams(conn,
        "SELECT user_id, username, password_hash, full_name, email, "
        "COALESCE(institution_id, ''), role, mfa_enabled, active, "
        "EXTRACT(EPOCH FROM created_at)::bigint::text, "
        "COALESCE(EXTRACT(EPOCH FROM last_login_at)::bigint::text, '0'), "
        "COALESCE(totp_secret, '') "
        "FROM examos_admin_users WHERE username = $1",
        1, NULL, user_params, NULL, NULL, 0);

    user_account_t account;
    char totp_secret[64] = {0};
    int ok = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
             PQntuples(result) == 1 && parse_user_row(result, 0, &account, totp_secret, sizeof(totp_secret)) == 0 &&
             account.active && config_verify_password_hash(password, account.password_hash);
    if (result) PQclear(result);

    if (!ok) {
        if (result) {
            const char *fail_audit[] = { username, "ADMIN_LOGIN_FAILED" };
            PQexecParams(conn, "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES (NULL, $2)",
                         2, NULL, fail_audit, NULL, NULL, 0);
        }
        OPENSSL_cleanse(&account, sizeof(account));
        OPENSSL_cleanse(totp_secret, sizeof(totp_secret));
        release_connection(conn, 0);
        return AUTH_LOGIN_FAILED;
    }

    /* MFA Verification Step */
    if (account.mfa_enabled) {
        if (!mfa_code || !mfa_code[0]) {
            OPENSSL_cleanse(&account, sizeof(account));
            OPENSSL_cleanse(totp_secret, sizeof(totp_secret));
            release_connection(conn, 0);
            return AUTH_LOGIN_MFA_REQUIRED;
        }

        int mfa_ok = totp_verify_code(totp_secret, mfa_code, time(NULL), 1);
        int recovery_used = 0;

        if (!mfa_ok) {
            /* Check if code is a valid recovery code */
            char rec_hash[65];
            if (totp_hash_recovery_code(mfa_code, rec_hash) == 0) {
                const char *rec_params[] = { account.user_id, rec_hash };
                result = PQexecParams(conn,
                    "UPDATE examos_admin_recovery_codes SET used = true, used_at = clock_timestamp() "
                    "WHERE user_id = $1 AND code_hash = $2 AND NOT used RETURNING code_hash",
                    2, NULL, rec_params, NULL, NULL, 0);
                if (result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1) {
                    mfa_ok = 1;
                    recovery_used = 1;
                }
                if (result) PQclear(result);
            }
        }

        if (!mfa_ok) {
            const char *audit_params[] = { account.user_id, "ADMIN_MFA_FAILED" };
            PQexecParams(conn, "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
                         2, NULL, audit_params, NULL, NULL, 0);
            OPENSSL_cleanse(&account, sizeof(account));
            OPENSSL_cleanse(totp_secret, sizeof(totp_secret));
            release_connection(conn, 0);
            return AUTH_LOGIN_FAILED;
        }

        const char *audit_event = recovery_used ? "ADMIN_RECOVERY_USED" : "ADMIN_MFA_VERIFIED";
        const char *mfa_audit[] = { account.user_id, audit_event };
        PQexecParams(conn, "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
                     2, NULL, mfa_audit, NULL, NULL, 0);
    }

    OPENSSL_cleanse(totp_secret, sizeof(totp_secret));

    /* Create session token */
    char raw_token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    if (secure_token_create(raw_token, token_hash) != 0) {
        OPENSSL_cleanse(&account, sizeof(account));
        release_connection(conn, 0);
        return AUTH_LOGIN_FAILED;
    }

    char role[16];
    snprintf(role, sizeof(role), "%d", (int)account.role);
    const char *session_params[] = { token_hash, account.user_id, role, account.institution_id };

    result = PQexec(conn, "BEGIN");
    if (result) PQclear(result);

    result = PQexecParams(conn,
        "INSERT INTO examos_admin_sessions "
        "(token_hash, user_id, role, institution_id, expires_at) "
        "SELECT $1, user_id, $3::smallint, NULLIF($4, ''), "
        "clock_timestamp() + interval '8 hours' "
        "FROM examos_admin_users WHERE user_id = $2 AND active "
        "RETURNING EXTRACT(EPOCH FROM created_at)::bigint::text, "
        "EXTRACT(EPOCH FROM expires_at)::bigint::text",
        4, NULL, session_params, NULL, NULL, 0);

    int inserted = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;
    if (result && inserted) {
        memset(out_session, 0, sizeof(*out_session));
        snprintf(out_session->session_token, sizeof(out_session->session_token), "%s", raw_token);
        snprintf(out_session->user_id, sizeof(out_session->user_id), "%s", account.user_id);
        snprintf(out_session->username, sizeof(out_session->username), "%s", account.username);
        snprintf(out_session->institution_id, sizeof(out_session->institution_id), "%s", account.institution_id);
        out_session->role = account.role;
        out_session->created_at = (time_t)strtoll(PQgetvalue(result, 0, 0), NULL, 10);
        out_session->expires_at = (time_t)strtoll(PQgetvalue(result, 0, 1), NULL, 10);
    }
    if (result) PQclear(result);

    if (inserted) {
        const char *audit_params[] = { account.user_id, "ADMIN_SESSION_CREATED" };
        result = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (result) PQclear(result);

        const char *last_login_params[] = { account.user_id };
        result = PQexecParams(conn,
            "UPDATE examos_admin_users SET last_login_at = clock_timestamp() "
            "WHERE user_id = $1 AND active",
            1, NULL, last_login_params, NULL, NULL, 0);
        if (result) PQclear(result);
    }

    result = PQexec(conn, inserted ? "COMMIT" : "ROLLBACK");
    int committed = result && PQresultStatus(result) == PGRES_COMMAND_OK && inserted;
    if (result) PQclear(result);

    OPENSSL_cleanse(raw_token, sizeof(raw_token));
    OPENSSL_cleanse(token_hash, sizeof(token_hash));
    OPENSSL_cleanse(&account, sizeof(account));
    release_connection(conn, 0);

    return committed ? AUTH_LOGIN_SUCCESS : AUTH_LOGIN_FAILED;
}

int admin_auth_store_verify(const char *token, auth_session_t *out_session) {
    if (!token || !out_session) return -1;
    char token_hash[EXAMOS_TOKEN_HEX_LEN + 1];
    if (secure_token_hash(token, token_hash) != 0) return -1;

    PGconn *conn = acquire_connection();
    if (!conn) {
        OPENSSL_cleanse(token_hash, sizeof(token_hash));
        return -1;
    }

    const char *params[] = { token_hash };
    PGresult *result = PQexecParams(conn,
        "SELECT s.user_id, u.username, COALESCE(s.institution_id, ''), s.role, "
        "EXTRACT(EPOCH FROM s.created_at)::bigint::text, "
        "EXTRACT(EPOCH FROM s.expires_at)::bigint::text "
        "FROM examos_admin_sessions s JOIN examos_admin_users u USING (user_id) "
        "WHERE s.token_hash = $1 AND s.revoked_at IS NULL "
        "AND s.expires_at > clock_timestamp() AND u.active "
        "AND s.role = u.role AND s.institution_id IS NOT DISTINCT FROM u.institution_id",
        1, NULL, params, NULL, NULL, 0);

    int ok = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;
    if (ok) {
        memset(out_session, 0, sizeof(*out_session));
        snprintf(out_session->session_token, sizeof(out_session->session_token), "%s", token_hash);
        snprintf(out_session->user_id, sizeof(out_session->user_id), "%s", PQgetvalue(result, 0, 0));
        snprintf(out_session->username, sizeof(out_session->username), "%s", PQgetvalue(result, 0, 1));
        snprintf(out_session->institution_id, sizeof(out_session->institution_id), "%s", PQgetvalue(result, 0, 2));
        out_session->role = (user_role_t)strtol(PQgetvalue(result, 0, 3), NULL, 10);
        out_session->created_at = (time_t)strtoll(PQgetvalue(result, 0, 4), NULL, 10);
        out_session->expires_at = (time_t)strtoll(PQgetvalue(result, 0, 5), NULL, 10);
    }
    if (result) PQclear(result);
    release_connection(conn, 0);
    OPENSSL_cleanse(token_hash, sizeof(token_hash));
    return ok ? 0 : -1;
}

int admin_auth_store_authorize(const char *token, uint32_t required_perm,
                               auth_session_t *out_session) {
    auth_session_t sess;
    if (admin_auth_store_verify(token, &sess) != 0) return -1;

    if (!admin_role_has_permission(sess.role, required_perm)) {
        OPENSSL_cleanse(&sess, sizeof(sess));
        return -1;
    }
    if (out_session) *out_session = sess;
    return 0;
}

int admin_auth_store_revoke(const char *token) {
    if (!token) return -1;
    char token_hash[EXAMOS_TOKEN_HEX_LEN + 1];
    if (secure_token_hash(token, token_hash) != 0) return -1;

    PGconn *conn = acquire_connection();
    if (!conn) {
        OPENSSL_cleanse(token_hash, sizeof(token_hash));
        return -1;
    }

    PGresult *result = PQexec(conn, "BEGIN");
    if (result) PQclear(result);

    const char *params[] = { token_hash };
    result = PQexecParams(conn,
        "UPDATE examos_admin_sessions SET revoked_at = clock_timestamp() "
        "WHERE token_hash = $1 AND revoked_at IS NULL RETURNING user_id",
        1, NULL, params, NULL, NULL, 0);
    int ok = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;

    char user_id[64] = {0};
    if (ok) snprintf(user_id, sizeof(user_id), "%s", PQgetvalue(result, 0, 0));
    if (result) PQclear(result);

    if (ok) {
        const char *audit_params[] = { user_id, "ADMIN_SESSION_REVOKED" };
        result = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (result) PQclear(result);
    }

    result = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    int committed = ok && result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);

    release_connection(conn, 0);
    OPENSSL_cleanse(token_hash, sizeof(token_hash));
    OPENSSL_cleanse(user_id, sizeof(user_id));
    return committed ? 0 : -1;
}

static int valid_user_record(const user_account_t *user) {
    if (!user || !user->user_id[0] || !user->username[0] || !user->password_hash[0] ||
        user->role < ROLE_PLATFORM_OWNER || user->role > ROLE_SUPPORT_ENGINEER ||
        !config_verify_password_hash("test-dummy-length-check", user->password_hash)) {
        /* Verify string format only */
        if (!strstr(user->password_hash, ":")) return -1;
    }
    return 0;
}

int admin_auth_store_create_initial_owner(const user_account_t *user) {
    if (valid_user_record(user) != 0 || user->role != ROLE_PLATFORM_OWNER) return -1;

    PGconn *conn = acquire_connection();
    if (!conn) return -1;

    PGresult *result = PQexec(conn, "BEGIN");
    if (result) PQclear(result);

    result = PQexec(conn, "SELECT pg_advisory_xact_lock(613024951)");
    if (result) PQclear(result);

    result = PQexec(conn, "SELECT 1 FROM examos_admin_users LIMIT 1");
    int empty = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 0;
    if (result) PQclear(result);

    int ok = 0;
    if (empty) {
        char role[16];
        snprintf(role, sizeof(role), "%d", (int)user->role);
        const char *params[] = {
            user->user_id, user->username, user->password_hash,
            user->full_name, user->email, user->institution_id, role
        };
        result = PQexecParams(conn,
            "INSERT INTO examos_admin_users "
            "(user_id, username, password_hash, full_name, email, institution_id, role, active) "
            "VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7::smallint, true) "
            "RETURNING user_id",
            7, NULL, params, NULL, NULL, 0);
        ok = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;
        if (result) PQclear(result);
    }

    if (ok) {
        const char *audit_params[] = { user->user_id, "ADMIN_USER_CREATED" };
        result = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (result) PQclear(result);
    }

    result = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    int committed = ok && result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);

    release_connection(conn, 0);
    return committed ? 0 : -1;
}

int admin_auth_store_create_user(const user_account_t *user, const char *actor_user_id) {
    if (valid_user_record(user) != 0 || !actor_user_id || !actor_user_id[0]) return -1;

    PGconn *conn = acquire_connection();
    if (!conn) return -1;

    PGresult *result = PQexec(conn, "BEGIN");
    if (result) PQclear(result);

    char role[16];
    snprintf(role, sizeof(role), "%d", (int)user->role);
    const char *params[] = {
        user->user_id, user->username, user->password_hash,
        user->full_name, user->email, user->institution_id, role,
        actor_user_id
    };

    result = PQexecParams(conn,
        "INSERT INTO examos_admin_users "
        "(user_id, username, password_hash, full_name, email, institution_id, role, active) "
        "SELECT $1, $2, $3, $4, $5, NULLIF($6, ''), $7::smallint, true "
        "WHERE EXISTS (SELECT 1 FROM examos_admin_users "
        "WHERE user_id = $8 AND active AND role IN (1, 2)) "
        "RETURNING user_id",
        8, NULL, params, NULL, NULL, 0);

    int ok = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;
    if (result) PQclear(result);

    if (ok) {
        const char *audit_params[] = { actor_user_id, "ADMIN_USER_CREATED" };
        result = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (result) PQclear(result);
    }

    result = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    int committed = ok && result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);

    release_connection(conn, 0);
    return committed ? 0 : -1;
}

int admin_auth_store_mfa_enroll(const char *username, char out_secret[TOTP_BASE32_LEN + 1],
                                char *out_uri, size_t uri_len,
                                char out_recovery_codes[TOTP_NUM_RECOVERY_CODES][TOTP_RECOVERY_CODE_LEN + 1]) {
    if (!username || !out_secret || !out_uri || !out_recovery_codes) return -1;

    if (totp_generate_secret(out_secret) != 0) return -1;
    if (totp_generate_uri(username, "ExamOS", out_secret, out_uri, uri_len) != 0) return -1;

    char hashes[TOTP_NUM_RECOVERY_CODES][65];
    if (totp_generate_recovery_codes(out_recovery_codes, hashes) != 0) return -1;

    PGconn *conn = acquire_connection();
    if (!conn) return -1;

    PGresult *result = PQexec(conn, "BEGIN");
    if (result) PQclear(result);

    /* Store secret (mfa_enabled stays false until confirmed) */
    const char *sec_params[] = { out_secret, username };
    result = PQexecParams(conn,
        "UPDATE examos_admin_users SET totp_secret = $1 WHERE username = $2 RETURNING user_id",
        2, NULL, sec_params, NULL, NULL, 0);
    int ok = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;

    char user_id[64] = {0};
    if (ok) snprintf(user_id, sizeof(user_id), "%s", PQgetvalue(result, 0, 0));
    if (result) PQclear(result);

    if (ok) {
        /* Clear old recovery codes */
        const char *del_params[] = { user_id };
        result = PQexecParams(conn, "DELETE FROM examos_admin_recovery_codes WHERE user_id = $1",
                              1, NULL, del_params, NULL, NULL, 0);
        if (result) PQclear(result);

        /* Insert new recovery codes */
        for (int i = 0; i < TOTP_NUM_RECOVERY_CODES; ++i) {
            const char *ins_params[] = { hashes[i], user_id };
            result = PQexecParams(conn,
                "INSERT INTO examos_admin_recovery_codes (code_hash, user_id) VALUES ($1, $2)",
                2, NULL, ins_params, NULL, NULL, 0);
            if (!result || PQresultStatus(result) != PGRES_COMMAND_OK) ok = 0;
            if (result) PQclear(result);
        }
    }

    result = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    int committed = ok && result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);

    release_connection(conn, 0);
    return committed ? 0 : -1;
}

int admin_auth_store_mfa_confirm(const char *username, const char *code) {
    if (!username || !code) return -1;

    PGconn *conn = acquire_connection();
    if (!conn) return -1;

    const char *params[] = { username };
    PGresult *result = PQexecParams(conn,
        "SELECT user_id, totp_secret FROM examos_admin_users WHERE username = $1 AND active",
        1, NULL, params, NULL, NULL, 0);

    int ok = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;
    char user_id[64] = {0}, secret[64] = {0};
    if (ok) {
        snprintf(user_id, sizeof(user_id), "%s", PQgetvalue(result, 0, 0));
        snprintf(secret, sizeof(secret), "%s", PQgetvalue(result, 0, 1));
    }
    if (result) PQclear(result);

    if (!ok || !secret[0] || !totp_verify_code(secret, code, time(NULL), 1)) {
        OPENSSL_cleanse(secret, sizeof(secret));
        release_connection(conn, 0);
        return -1;
    }
    OPENSSL_cleanse(secret, sizeof(secret));

    result = PQexec(conn, "BEGIN");
    if (result) PQclear(result);

    const char *upd_params[] = { user_id };
    result = PQexecParams(conn,
        "UPDATE examos_admin_users SET mfa_enabled = true, totp_enrolled_at = clock_timestamp() "
        "WHERE user_id = $1",
        1, NULL, upd_params, NULL, NULL, 0);
    ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);

    if (ok) {
        const char *audit_params[] = { user_id, "ADMIN_MFA_ENROLLED" };
        result = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (result) PQclear(result);
    }

    result = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    int committed = ok && result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);

    release_connection(conn, 0);
    return committed ? 0 : -1;
}

int admin_auth_store_password_reset_request(const char *username, char out_token[65]) {
    if (!username || !out_token) return -1;

    char raw_token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    if (secure_token_create(raw_token, token_hash) != 0) return -1;

    PGconn *conn = acquire_connection();
    if (!conn) {
        OPENSSL_cleanse(raw_token, sizeof(raw_token));
        OPENSSL_cleanse(token_hash, sizeof(token_hash));
        return -1;
    }

    const char *params[] = { username, token_hash };
    PGresult *result = PQexecParams(conn,
        "INSERT INTO examos_admin_password_resets (token_hash, user_id, expires_at) "
        "SELECT $2, user_id, clock_timestamp() + interval '1 hour' "
        "FROM examos_admin_users WHERE username = $1 AND active RETURNING user_id",
        2, NULL, params, NULL, NULL, 0);

    int ok = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;
    char user_id[64] = {0};
    if (ok) snprintf(user_id, sizeof(user_id), "%s", PQgetvalue(result, 0, 0));
    if (result) PQclear(result);

    if (ok) {
        const char *audit_params[] = { user_id, "ADMIN_PASSWORD_RESET_REQUESTED" };
        result = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (result) PQclear(result);
        snprintf(out_token, 65, "%s", raw_token);
    }

    OPENSSL_cleanse(raw_token, sizeof(raw_token));
    OPENSSL_cleanse(token_hash, sizeof(token_hash));
    release_connection(conn, 0);
    return ok ? 0 : -1;
}

int admin_auth_store_password_reset_complete(const char *username, const char *reset_token,
                                             const char *new_password) {
    if (!username || !reset_token || !new_password || strlen(new_password) < 12) return -1;

    char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    if (secure_token_hash(reset_token, token_hash) != 0) return -1;

    /* Generate PBKDF2 hash for new password */
    unsigned char salt[16];
    unsigned char hash[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        PKCS5_PBKDF2_HMAC(new_password, (int)strlen(new_password), salt, sizeof(salt),
                          600000, EVP_sha256(), sizeof(hash), hash) != 1) {
        return -1;
    }

    char salt_hex[33], hash_hex[65];
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; ++i) {
        salt_hex[i * 2]     = hex_chars[salt[i] >> 4];
        salt_hex[i * 2 + 1] = hex_chars[salt[i] & 0x0f];
    }
    salt_hex[32] = '\0';
    for (size_t i = 0; i < 32; ++i) {
        hash_hex[i * 2]     = hex_chars[hash[i] >> 4];
        hash_hex[i * 2 + 1] = hex_chars[hash[i] & 0x0f];
    }
    hash_hex[64] = '\0';

    char new_credential[160];
    snprintf(new_credential, sizeof(new_credential), "600000:%s:%s", salt_hex, hash_hex);
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(hash, sizeof(hash));

    PGconn *conn = acquire_connection();
    if (!conn) {
        OPENSSL_cleanse(new_credential, sizeof(new_credential));
        return -1;
    }

    PGresult *result = PQexec(conn, "BEGIN");
    if (result) PQclear(result);

    /* Verify and mark reset token */
    const char *reset_params[] = { token_hash, username };
    result = PQexecParams(conn,
        "UPDATE examos_admin_password_resets r "
        "SET used = true, used_at = clock_timestamp() "
        "FROM examos_admin_users u "
        "WHERE r.user_id = u.user_id AND r.token_hash = $1 AND u.username = $2 "
        "AND NOT r.used AND r.expires_at > clock_timestamp() RETURNING u.user_id",
        2, NULL, reset_params, NULL, NULL, 0);

    int ok = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;
    char user_id[64] = {0};
    if (ok) snprintf(user_id, sizeof(user_id), "%s", PQgetvalue(result, 0, 0));
    if (result) PQclear(result);

    if (ok) {
        /* Update password */
        const char *pwd_params[] = { new_credential, user_id };
        result = PQexecParams(conn,
            "UPDATE examos_admin_users SET password_hash = $1 WHERE user_id = $2",
            2, NULL, pwd_params, NULL, NULL, 0);
        if (!result || PQresultStatus(result) != PGRES_COMMAND_OK) ok = 0;
        if (result) PQclear(result);

        /* Invalidate all active sessions for security */
        const char *sess_params[] = { user_id };
        result = PQexecParams(conn,
            "UPDATE examos_admin_sessions SET revoked_at = clock_timestamp() "
            "WHERE user_id = $1 AND revoked_at IS NULL",
            1, NULL, sess_params, NULL, NULL, 0);
        if (result) PQclear(result);

        const char *audit_params[] = { user_id, "ADMIN_PASSWORD_RESET_COMPLETED" };
        result = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (result) PQclear(result);
    }

    result = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    int committed = ok && result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);

    OPENSSL_cleanse(new_credential, sizeof(new_credential));
    release_connection(conn, 0);
    return committed ? 0 : -1;
}

const char *admin_role_to_string(user_role_t role) {
    switch (role) {
        case ROLE_PLATFORM_OWNER:          return "Platform Owner";
        case ROLE_INSTITUTION_ADMIN:       return "Institution Admin";
        case ROLE_EXAM_MANAGER:            return "Exam Manager";
        case ROLE_SECURITY_ADMIN:          return "Security Admin";
        case ROLE_INVIGILATOR:             return "Invigilator";
        case ROLE_TECH_OPERATOR:           return "Technical Operator";
        case ROLE_INCIDENT_INVESTIGATOR:   return "Incident Investigator";
        case ROLE_READONLY_AUDITOR:        return "Read-only Auditor";
        case ROLE_SUPPORT_ENGINEER:        return "Support Engineer";
        default:                           return "Operator";
    }
}

int admin_auth_store_list_users_json(char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 64) return -1;

    PGconn *conn = acquire_connection();
    if (!conn) return -1;

    PGresult *result = PQexec(conn,
        "SELECT user_id, username, full_name, email, COALESCE(institution_id, ''), "
        "role, mfa_enabled, active, EXTRACT(EPOCH FROM created_at)::bigint, "
        "COALESCE(EXTRACT(EPOCH FROM last_login_at)::bigint, 0) "
        "FROM examos_admin_users ORDER BY created_at ASC");

    if (!result || PQresultStatus(result) != PGRES_TUPLES_OK) {
        if (result) PQclear(result);
        release_connection(conn, 0);
        return -1;
    }

    int rows = PQntuples(result);
    size_t offset = snprintf(out_buf, max_len, "{\"users\":[");

    for (int i = 0; i < rows; ++i) {
        user_role_t r = (user_role_t)atoi(PQgetvalue(result, i, 5));
        offset += snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0,
            "%s{\"user_id\":\"%s\",\"username\":\"%s\",\"full_name\":\"%s\",\"email\":\"%s\","
            "\"institution_id\":\"%s\",\"role\":\"%s\",\"mfa_enabled\":%s,\"active\":%s,"
            "\"created_at\":%s,\"last_login_at\":%s}",
            (i > 0 ? "," : ""),
            PQgetvalue(result, i, 0),
            PQgetvalue(result, i, 1),
            PQgetvalue(result, i, 2),
            PQgetvalue(result, i, 3),
            PQgetvalue(result, i, 4),
            admin_role_to_string(r),
            strcmp(PQgetvalue(result, i, 6), "t") == 0 ? "true" : "false",
            strcmp(PQgetvalue(result, i, 7), "t") == 0 ? "true" : "false",
            PQgetvalue(result, i, 8),
            PQgetvalue(result, i, 9));
    }
    snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0, "]}");

    PQclear(result);
    release_connection(conn, 0);
    return 0;
}
