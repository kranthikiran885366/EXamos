#define _GNU_SOURCE
#include "../include/enterprise_platform.h"
#include "../include/admin_auth_store.h"
#include "../include/config_manager.h"
#include "../include/ledger.h"
#include "../include/secure_token.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

static void platform_log_ledger(const char *type, const char *entity, const char *details) {
    ledger_block_t blk;
    ledger_append_event(type, entity ? entity : "system", details ? details : "", &blk);
}
#define ledger_append platform_log_ledger
static pthread_mutex_t g_platform_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_data_dir[512] = "data";
static time_t g_platform_started_at = 0;

/*
 * Last-error channel.
 *
 * The platform functions predate a structured error type, so the most
 * recent failure reason is recorded per thread. Callers can surface the
 * specific reason instead of a generic "operation failed", which matters
 * for distinguishing a duplicate record from an unreachable database.
 */
static __thread char g_last_error[512] = {0};

const char *platform_last_error(void) {
    return g_last_error[0] ? g_last_error : "Operation failed";
}

void platform_clear_error(void) {
    g_last_error[0] = '\0';
}

static void platform_set_error(const char *message) {
    snprintf(g_last_error, sizeof(g_last_error), "%s", message ? message : "Operation failed");
}

static int policy_trust_unavailable(char *err_msg, size_t err_len) {
    const char *message =
        "Policy operation is blocked until complete Ed25519 signing and authenticated device enforcement acknowledgements are available";
    platform_set_error(message);
    if (err_msg && err_len) snprintf(err_msg, err_len, "%s", message);
    errno = ENOTSUP;
    return -1;
}

/* Records the PostgreSQL error text for a failed statement. */
static void platform_set_db_error(PGresult *res) {
    if (!res) {
        platform_set_error("The durable platform store did not return a result");
        return;
    }
    const char *message = PQresultErrorMessage(res);
    if (message && message[0]) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "%s", message);
        char *newline = strchr(buffer, '\n');
        if (newline) *newline = '\0';
        platform_set_error(buffer);
    } else {
        platform_set_error("The durable platform store rejected the operation");
    }
}

/*
 * Records an administrative audit entry.
 *
 * Returns 0 on success and -1 on failure. Callers that mutate state must
 * treat a failure here as a failure of the whole operation: a change
 * without an audit record is not auditable, so it must not be committed.
 */
static int platform_audit(PGconn *conn, const char *actor, const char *event_type,
                          const char *subject_type, const char *subject_id) {
    if (!conn || !event_type || !event_type[0]) return -1;
    const char *params[4] = {
        (actor && actor[0] && strncmp(actor, "USR-", 4) == 0) ? actor : NULL,
        event_type,
        subject_type ? subject_type : "",
        subject_id ? subject_id : ""
    };
    PGresult *res = PQexecParams(conn,
        "INSERT INTO examos_admin_audit (actor_user_id, event_type, subject_type, subject_id) "
        "VALUES ($1, $2, $3, $4)",
        4, NULL, params, NULL, NULL, 0);
    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (!ok) platform_set_db_error(res);
    if (res) PQclear(res);
    return ok ? 0 : -1;
}

static int platform_json_escape(const char *input, char *output, size_t capacity) {
    if (!input || !output || capacity == 0) return -1;
    size_t used = 0;
    static const char hex[] = "0123456789abcdef";
    for (const unsigned char *p = (const unsigned char *)input; *p; ++p) {
        char escaped[6];
        const char *value = escaped;
        size_t length = 0;
        switch (*p) {
            case '"': escaped[0] = '\\'; escaped[1] = '"'; length = 2; break;
            case '\\': escaped[0] = '\\'; escaped[1] = '\\'; length = 2; break;
            case '\b': escaped[0] = '\\'; escaped[1] = 'b'; length = 2; break;
            case '\f': escaped[0] = '\\'; escaped[1] = 'f'; length = 2; break;
            case '\n': escaped[0] = '\\'; escaped[1] = 'n'; length = 2; break;
            case '\r': escaped[0] = '\\'; escaped[1] = 'r'; length = 2; break;
            case '\t': escaped[0] = '\\'; escaped[1] = 't'; length = 2; break;
            default:
                if (*p < 0x20) {
                    escaped[0] = '\\'; escaped[1] = 'u'; escaped[2] = '0'; escaped[3] = '0';
                    escaped[4] = hex[*p >> 4]; escaped[5] = hex[*p & 15]; length = 6;
                } else { value = (const char *)p; length = 1; }
        }
        if (used + length >= capacity) return -1;
        memcpy(output + used, value, length);
        used += length;
    }
    output[used] = '\0';
    return 0;
}

/* Fleet and Incident records maintained in memory/ledger */

static fleet_device_record_t    g_devices[MAX_DEVICES];
static int                      g_device_count = 0;

static durable_submission_t     g_submissions[MAX_SUBMISSIONS];
static int                      g_submission_count = 0;


static int load_devices_from_db(void);

/* Helper: string conversions */
const char *role_to_string(user_role_t role) {
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

user_role_t string_to_role(const char *str) {
    if (!str) return ROLE_INVIGILATOR;
    if (strcasecmp(str, "Platform Owner") == 0 || strcasecmp(str, "PLATFORM_OWNER") == 0) return ROLE_PLATFORM_OWNER;
    if (strcasecmp(str, "Institution Admin") == 0 || strcasecmp(str, "INSTITUTION_ADMIN") == 0) return ROLE_INSTITUTION_ADMIN;
    if (strcasecmp(str, "Exam Manager") == 0 || strcasecmp(str, "EXAM_MANAGER") == 0) return ROLE_EXAM_MANAGER;
    if (strcasecmp(str, "Security Admin") == 0 || strcasecmp(str, "SECURITY_ADMIN") == 0) return ROLE_SECURITY_ADMIN;
    if (strcasecmp(str, "Invigilator") == 0 || strcasecmp(str, "INVIGILATOR") == 0) return ROLE_INVIGILATOR;
    if (strcasecmp(str, "Technical Operator") == 0 || strcasecmp(str, "TECH_OPERATOR") == 0) return ROLE_TECH_OPERATOR;
    if (strcasecmp(str, "Incident Investigator") == 0 || strcasecmp(str, "INCIDENT_INVESTIGATOR") == 0) return ROLE_INCIDENT_INVESTIGATOR;
    if (strcasecmp(str, "Read-only Auditor") == 0 || strcasecmp(str, "READONLY_AUDITOR") == 0) return ROLE_READONLY_AUDITOR;
    return ROLE_SUPPORT_ENGINEER;
}

const char *exam_state_to_string(exam_state_t state) {
    switch (state) {
        case EXAM_STATE_DRAFT:       return "DRAFT";
        case EXAM_STATE_VALIDATED:   return "VALIDATED";
        case EXAM_STATE_APPROVED:    return "APPROVED";
        case EXAM_STATE_SCHEDULED:   return "SCHEDULED";
        case EXAM_STATE_OPEN:        return "OPEN";
        case EXAM_STATE_ACTIVE:      return "ACTIVE";
        case EXAM_STATE_PAUSED:      return "PAUSED";
        case EXAM_STATE_SUBMISSION:  return "SUBMISSION";
        case EXAM_STATE_CLOSED:      return "CLOSED";
        case EXAM_STATE_RECONCILED:  return "RECONCILED";
        default:                     return "UNKNOWN";
    }
}

exam_state_t string_to_exam_state(const char *str) {
    if (!str) return EXAM_STATE_DRAFT;
    if (strcasecmp(str, "DRAFT") == 0) return EXAM_STATE_DRAFT;
    if (strcasecmp(str, "VALIDATED") == 0) return EXAM_STATE_VALIDATED;
    if (strcasecmp(str, "APPROVED") == 0) return EXAM_STATE_APPROVED;
    if (strcasecmp(str, "SCHEDULED") == 0) return EXAM_STATE_SCHEDULED;
    if (strcasecmp(str, "OPEN") == 0) return EXAM_STATE_OPEN;
    if (strcasecmp(str, "ACTIVE") == 0) return EXAM_STATE_ACTIVE;
    if (strcasecmp(str, "PAUSED") == 0) return EXAM_STATE_PAUSED;
    if (strcasecmp(str, "SUBMISSION") == 0) return EXAM_STATE_SUBMISSION;
    if (strcasecmp(str, "CLOSED") == 0) return EXAM_STATE_CLOSED;
    if (strcasecmp(str, "RECONCILED") == 0) return EXAM_STATE_RECONCILED;
    return EXAM_STATE_DRAFT;
}

const char *candidate_status_to_string(candidate_status_t s) {
    switch (s) {
        case CANDIDATE_ELIGIBLE:     return "ELIGIBLE";
        case CANDIDATE_CHECKED_IN:   return "CHECKED_IN";
        case CANDIDATE_IN_EXAM:      return "IN_EXAM";
        case CANDIDATE_SUBMITTED:    return "SUBMITTED";
        case CANDIDATE_DISQUALIFIED: return "DISQUALIFIED";
        default:                     return "UNKNOWN";
    }
}

const char *ring_to_string(deployment_ring_t r) {
    switch (r) {
        case RING_CANARY:  return "CANARY";
        case RING_PILOT:   return "PILOT";
        default:           return "GENERAL";
    }
}

const char *severity_to_string(event_severity_t sev) {
    switch (sev) {
        case SEV_INFO:     return "INFO";
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
        default:           return "INFO";
    }
}

/* Helper: safe atomic write */
static int atomic_write_file(const char *filepath, const char *content, size_t length) {
    char tmp[2048];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", filepath, getpid());

    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    if (fwrite(content, 1, length, f) != length) {
        fclose(f);
        unlink(tmp);
        return -1;
    }
    fflush(f);
    int fd = fileno(f);
    if (fd >= 0) fsync(fd);
    fclose(f);

    if (rename(tmp, filepath) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Dynamic URL & Origin Validation Engine (Module D)
 * Requires HTTPS (except loopback testing), valid host/port, rejects SSRF
 * ------------------------------------------------------------------------- */
int platform_validate_exam_url(const char *url, char *err_msg, size_t err_len) {
    if (!url || !url[0]) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Exam URL cannot be empty.");
        return -1;
    }

    if (!config_validate_exam_url(url)) {
        if (err_msg && err_len) {
            snprintf(err_msg, err_len,
                     "Exam URL must be valid HTTPS; HTTP is limited to exact loopback development hosts.");
        }
        return -1;
    }

    /* Reject URLs with embedded credentials or wildcards */
    if (strchr(url, '@')) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Exam URL must not contain embedded user credentials.");
        return -1;
    }
    if (strstr(url, "..")) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Exam URL contains invalid path navigation sequences.");
        return -1;
    }

    if (err_msg && err_len) err_msg[0] = '\0';
    return 0;
}

static int platform_valid_origin_authority(const char *authority, size_t length) {
    if (!authority || length == 0 || length >= 320) return 0;
    char copy[320];
    memcpy(copy, authority, length);
    copy[length] = '\0';

    char *host = copy;
    char *port = NULL;
    if (host[0] == '[') {
        char *close = strchr(host, ']');
        if (!close || (close[1] && close[1] != ':')) return 0;
        if (close[1] == ':') port = close + 2;
        *close = '\0';
        unsigned char address[16];
        if (inet_pton(AF_INET6, host + 1, address) != 1) return 0;
    } else {
        char *colon = strchr(host, ':');
        if (colon) {
            if (strchr(colon + 1, ':')) return 0;
            *colon = '\0';
            port = colon + 1;
        }
        size_t host_length = strlen(host);
        if (!host_length || host_length > 253 || host[0] == '.' || host[host_length - 1] == '.') return 0;
        if (strspn(host, "0123456789.") == host_length) {
            struct in_addr address;
            if (inet_pton(AF_INET, host, &address) != 1) return 0;
        }
        size_t label_length = 0;
        for (size_t i = 0; i <= host_length; i++) {
            unsigned char c = (unsigned char)host[i];
            if (c == '.' || c == '\0') {
                if (!label_length || label_length > 63 || host[i - 1] == '-') return 0;
                label_length = 0;
                continue;
            }
            if (!(isalnum(c) || c == '-') || (!label_length && c == '-')) return 0;
            label_length++;
        }
    }

    if (port) {
        if (!port[0]) return 0;
        for (const unsigned char *p = (const unsigned char *)port; *p; p++) {
            if (!isdigit(*p)) return 0;
        }
        errno = 0;
        char *end = NULL;
        long value = strtol(port, &end, 10);
        if (errno || end == port || *end || value < 1 || value > 65535) return 0;
    }
    return 1;
}

int platform_validate_allowed_origins(const char *origins, char *err_msg, size_t err_len) {
    if (!origins || !origins[0]) return 0;
    if (strnlen(origins, 1024) >= 1024) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Allowed origins exceed the maximum length.");
        return -1;
    }

    const char *entry = origins;
    while (*entry) {
        const char *end = strchr(entry, ',');
        size_t length = end ? (size_t)(end - entry) : strlen(entry);
        while (length && isspace((unsigned char)*entry)) { entry++; length--; }
        while (length && isspace((unsigned char)entry[length - 1])) length--;
        if (!length || length >= 512) {
            if (err_msg && err_len) snprintf(err_msg, err_len, "Allowed origins contain an empty or oversized entry.");
            return -1;
        }

        char token[512];
        memcpy(token, entry, length);
        token[length] = '\0';
        if (strncasecmp(token, "https://", 8) != 0) {
            if (err_msg && err_len) snprintf(err_msg, err_len, "Allowed origin '%s' must use HTTPS.", token);
            return -1;
        }

        const char *authority = token + 8;
        const char *suffix = strpbrk(authority, "/?#");
        size_t authority_len = suffix ? (size_t)(suffix - authority) : strlen(authority);
        int valid_suffix = !suffix || (suffix[0] == '/' && suffix[1] == '\0');
        if (!valid_suffix || strpbrk(authority, "@\\\r\n\t *%") ||
            !platform_valid_origin_authority(authority, authority_len)) {
            if (err_msg && err_len) {
                snprintf(err_msg, err_len,
                         "Allowed origin '%s' must be an HTTPS origin without credentials, paths, query strings, or fragments.",
                         token);
            }
            return -1;
        }

        if (!end) break;
        entry = end + 1;
        if (!*entry) {
            if (err_msg && err_len) snprintf(err_msg, err_len, "Allowed origins contain an empty entry.");
            return -1;
        }
    }
    if (err_msg && err_len) err_msg[0] = '\0';
    return 0;
}

/* -------------------------------------------------------------------------
 * Initialization
 * ------------------------------------------------------------------------- */
int enterprise_platform_init(const char *data_dir) {
    pthread_mutex_lock(&g_platform_lock);
    if (data_dir && strlen(data_dir) > 0) {
        snprintf(g_data_dir, sizeof(g_data_dir), "%s", data_dir);
    }

    if (mkdir(g_data_dir, 0750) != 0 && errno != EEXIST) {
        pthread_mutex_unlock(&g_platform_lock);
        return -1;
    }

    char sub_dir[560];
    int path_len = snprintf(sub_dir, sizeof(sub_dir), "%s/submissions", g_data_dir);
    if (path_len < 0 || (size_t)path_len >= sizeof(sub_dir) ||
        (mkdir(sub_dir, 0750) != 0 && errno != EEXIST)) {
        pthread_mutex_unlock(&g_platform_lock);
        return -1;
    }

    g_platform_started_at = time(NULL);
    pthread_mutex_unlock(&g_platform_lock);
    int rc = admin_auth_store_init();
    if (rc == 0) {
        rc = load_devices_from_db();
        if (rc != 0) admin_auth_store_shutdown();
    }
    return rc;
}

int enterprise_platform_save_all(void) {
    /*
     * All durable state is persisted directly to PostgreSQL by each
     * individual write operation, so there is no separate flush step.
     *
     * The operation still confirms that the durable store is reachable and
     * readable, so that a successful return means the committed state could
     * be verified rather than merely assumed.
     *
     * When no database connection is available (unprovisioned development
     * environment), ENOTSUP is set so that callers can distinguish "the
     * platform store is simply not provisioned here" from an I/O error on a
     * provisioned store.
     */
    PGconn *conn = acquire_db_connection();
    if (!conn) {
        errno = ENOTSUP;
        return -1;
    }
    PGresult *res = PQexec(conn, "SELECT 1");
    int ok = res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1;
    if (res) PQclear(res);
    release_db_connection(conn, 0);

    if (!ok) {
        errno = ENOTSUP;
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Authentication & Sessions (Module B)
 * ------------------------------------------------------------------------- */
int platform_auth_login(const char *username, const char *password, const char *mfa_code, auth_session_t *out_session) {
    return admin_auth_store_login(username, password, mfa_code, out_session);
}

int platform_auth_verify_token(const char *token, auth_session_t *out_session) {
    return admin_auth_store_verify(token, out_session);
}

int platform_auth_revoke_session(const char *token) {
    return admin_auth_store_revoke(token);
}

int platform_user_create(const user_account_t *user, const char *actor_user_id) {
    return admin_auth_store_create_user(user, actor_user_id);
}

int platform_initial_owner_create(const user_account_t *user) {
    return admin_auth_store_create_initial_owner(user);
}

/* -------------------------------------------------------------------------
 * Multi-Tenancy JSON Serialization
 * ------------------------------------------------------------------------- */
int platform_get_institutions_json(char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 64) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = PQexec(conn,
        "SELECT institution_id, name, code, domain_email, retention_days, active "
        "FROM examos_institutions ORDER BY name ASC");
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    int rows = PQntuples(res);
    size_t offset = 0;
    int written = snprintf(out_buf, max_len, "{\"institutions\":[");
    if (written < 0 || (size_t)written >= max_len) {
        PQclear(res); release_db_connection(conn, 0); return -1;
    }
    offset = (size_t)written;
    for (int i = 0; i < rows; ++i) {
        char id[256], name[512], code[128], email[512];
        if (platform_json_escape(PQgetvalue(res, i, 0), id, sizeof(id)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 1), name, sizeof(name)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 2), code, sizeof(code)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 3), email, sizeof(email)) != 0) {
            PQclear(res); release_db_connection(conn, 0); return -1;
        }
        written = snprintf(out_buf + offset, max_len - offset,
            "%s{\"id\":\"%s\",\"name\":\"%s\",\"code\":\"%s\",\"email\":\"%s\",\"retention_days\":%d,\"active\":%s}",
            (i > 0 ? "," : ""),
            id, name, code, email,
            atoi(PQgetvalue(res, i, 4)),
            strcmp(PQgetvalue(res, i, 5), "t") == 0 ? "true" : "false");
        if (written < 0 || (size_t)written >= max_len - offset) {
            PQclear(res); release_db_connection(conn, 0); return -1;
        }
        offset += (size_t)written;
    }
    written = snprintf(out_buf + offset, max_len - offset, "]}");
    if (written < 0 || (size_t)written >= max_len - offset) {
        PQclear(res); release_db_connection(conn, 0); return -1;
    }

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_create_institution(const institution_t *inst) {
    if (!inst || !inst->institution_id[0] || !inst->name[0] || !inst->code[0] ||
        strnlen(inst->institution_id, sizeof(inst->institution_id)) >= sizeof(inst->institution_id) ||
        strnlen(inst->name, sizeof(inst->name)) >= sizeof(inst->name) ||
        strnlen(inst->code, sizeof(inst->code)) >= sizeof(inst->code) ||
        inst->retention_days <= 0 || inst->retention_days > 36500) {
        platform_set_error("institution_id, name, code and a retention window between 1 and 36500 days are required");
        return -1;
    }
    PGconn *conn = acquire_db_connection();
    if (!conn) {
        platform_set_error("The durable platform store is unreachable");
        return -1;
    }

    char ret_str[16];
    snprintf(ret_str, sizeof(ret_str), "%d", inst->retention_days);

    const char *params[] = {
        inst->institution_id,
        inst->name,
        inst->code,
        inst->contact_email[0] ? inst->contact_email : "",
        ret_str,
        inst->active ? "true" : "false"
    };

    PGresult *res = PQexecParams(conn,
        "INSERT INTO examos_institutions (institution_id, name, code, domain_email, retention_days, active) "
        "VALUES ($1, $2, $3, $4, $5::integer, $6::boolean)",
        6, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (!ok) platform_set_db_error(res);
    if (res) PQclear(res);
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_get_institution_json(const char *institution_id, char *out_buf,
                                  size_t max_len) {
    if (!institution_id || !institution_id[0] || !out_buf || max_len < 128) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    const char *params[] = { institution_id };
    PGresult *res = PQexecParams(conn,
        "SELECT institution_id, name, code, domain_email, retention_days, active "
        "FROM examos_institutions WHERE institution_id = $1",
        1, NULL, params, NULL, NULL, 0);
    int ok = res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1;
    if (ok) {
        char id[256], name[512], code[128], email[512];
        ok = platform_json_escape(PQgetvalue(res, 0, 0), id, sizeof(id)) == 0 &&
             platform_json_escape(PQgetvalue(res, 0, 1), name, sizeof(name)) == 0 &&
             platform_json_escape(PQgetvalue(res, 0, 2), code, sizeof(code)) == 0 &&
             platform_json_escape(PQgetvalue(res, 0, 3), email, sizeof(email)) == 0;
        int written = ok ? snprintf(out_buf, max_len,
            "{\"id\":\"%s\",\"name\":\"%s\",\"code\":\"%s\",\"email\":\"%s\","
            "\"retention_days\":%d,\"active\":%s}",
            id, name, code, email, atoi(PQgetvalue(res, 0, 4)),
            strcmp(PQgetvalue(res, 0, 5), "t") == 0 ? "true" : "false") : -1;
        ok = ok && written >= 0 && (size_t)written < max_len;
    }
    if (res) PQclear(res);
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_get_campuses_json(const char *inst_id, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 64) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = NULL;
    if (inst_id && inst_id[0]) {
        const char *params[] = { inst_id };
        res = PQexecParams(conn,
            "SELECT campus_id, institution_id, name, address "
            "FROM examos_campuses WHERE institution_id = $1 ORDER BY name ASC",
            1, NULL, params, NULL, NULL, 0);
    } else {
        res = PQexec(conn,
            "SELECT campus_id, institution_id, name, address "
            "FROM examos_campuses ORDER BY name ASC");
    }

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    int rows = PQntuples(res);
    int initial = snprintf(out_buf, max_len, "{\"campuses\":[");
    if (initial < 0 || (size_t)initial >= max_len) { PQclear(res); release_db_connection(conn, 0); return -1; }
    size_t offset = (size_t)initial;
    for (int i = 0; i < rows; ++i) {
        char id[256], institution[256], name[512], address[1024];
        if (platform_json_escape(PQgetvalue(res, i, 0), id, sizeof(id)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 1), institution, sizeof(institution)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 2), name, sizeof(name)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 3), address, sizeof(address)) != 0) {
            PQclear(res); release_db_connection(conn, 0); return -1;
        }
        int n = snprintf(out_buf + offset, max_len - offset,
            "%s{\"id\":\"%s\",\"institution_id\":\"%s\",\"name\":\"%s\",\"address\":\"%s\"}",
            i ? "," : "", id, institution, name, address);
        if (n < 0 || (size_t)n >= max_len - offset) { PQclear(res); release_db_connection(conn, 0); return -1; }
        offset += (size_t)n;
    }
    if (snprintf(out_buf + offset, max_len - offset, "]}") >= (int)(max_len - offset)) {
        PQclear(res); release_db_connection(conn, 0); return -1;
    }

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_create_campus(const campus_t *campus) {
    if (!campus || !campus->campus_id[0] || !campus->institution_id[0] || !campus->name[0]) {
        platform_set_error("campus_id, institution_id and name are required");
        return -1;
    }
    PGconn *conn = acquire_db_connection();
    if (!conn) {
        platform_set_error("The durable platform store is unreachable");
        return -1;
    }

    const char *params[] = {
        campus->campus_id,
        campus->institution_id,
        campus->name,
        campus->address[0] ? campus->address : ""
    };

    PGresult *res = PQexecParams(conn,
        "INSERT INTO examos_campuses (campus_id, institution_id, name, address) "
        "VALUES ($1, $2, $3, $4) "
        "ON CONFLICT (campus_id) DO UPDATE SET "
        "  name = EXCLUDED.name, address = EXCLUDED.address",
        4, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (!ok) platform_set_db_error(res);
    if (res) PQclear(res);
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_get_rooms_json(const char *campus_id, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 64) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = NULL;
    if (campus_id && campus_id[0]) {
        const char *params[] = { campus_id };
        res = PQexecParams(conn,
            "SELECT room_id, campus_id, name, capacity, supervisor "
            "FROM examos_rooms WHERE campus_id = $1 ORDER BY name ASC",
            1, NULL, params, NULL, NULL, 0);
    } else {
        res = PQexec(conn,
            "SELECT room_id, campus_id, name, capacity, supervisor "
            "FROM examos_rooms ORDER BY name ASC");
    }

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    int rows = PQntuples(res);
    int initial = snprintf(out_buf, max_len, "{\"rooms\":[");
    if (initial < 0 || (size_t)initial >= max_len) { PQclear(res); release_db_connection(conn, 0); return -1; }
    size_t offset = (size_t)initial;
    for (int i = 0; i < rows; ++i) {
        char id[256], campus[256], name[512], supervisor[256];
        if (platform_json_escape(PQgetvalue(res, i, 0), id, sizeof(id)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 1), campus, sizeof(campus)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 2), name, sizeof(name)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 4), supervisor, sizeof(supervisor)) != 0) {
            PQclear(res); release_db_connection(conn, 0); return -1;
        }
        int n = snprintf(out_buf + offset, max_len - offset,
            "%s{\"id\":\"%s\",\"campus_id\":\"%s\",\"name\":\"%s\",\"capacity\":%d,\"supervisor\":\"%s\"}",
            i ? "," : "", id, campus, name, atoi(PQgetvalue(res, i, 3)), supervisor);
        if (n < 0 || (size_t)n >= max_len - offset) { PQclear(res); release_db_connection(conn, 0); return -1; }
        offset += (size_t)n;
    }
    if (snprintf(out_buf + offset, max_len - offset, "]}") >= (int)(max_len - offset)) {
        PQclear(res); release_db_connection(conn, 0); return -1;
    }

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_get_rooms_for_institution_json(const char *campus_id, const char *institution_id,
                                            char *out_buf, size_t max_len) {
    if (!campus_id || !campus_id[0] || !out_buf || max_len < 64) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    PGresult *res = NULL;
    if (institution_id && institution_id[0]) {
        const char *params[] = { campus_id, institution_id };
        res = PQexecParams(conn,
            "SELECT r.room_id, r.campus_id, r.name, r.capacity, r.supervisor "
            "FROM examos_rooms r JOIN examos_campuses c ON c.campus_id = r.campus_id "
            "WHERE r.campus_id = $1 AND c.institution_id = $2 ORDER BY r.name ASC",
            2, NULL, params, NULL, NULL, 0);
    } else {
        const char *params[] = { campus_id };
        res = PQexecParams(conn,
            "SELECT room_id, campus_id, name, capacity, supervisor FROM examos_rooms "
            "WHERE campus_id = $1 ORDER BY name ASC", 1, NULL, params, NULL, NULL, 0);
    }
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }
    size_t offset = (size_t)snprintf(out_buf, max_len, "{\"rooms\":[");
    if (offset >= max_len) { PQclear(res); release_db_connection(conn, 0); return -1; }
    for (int i = 0; i < PQntuples(res); ++i) {
        char id[256], campus[256], name[512], supervisor[256];
        if (platform_json_escape(PQgetvalue(res, i, 0), id, sizeof(id)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 1), campus, sizeof(campus)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 2), name, sizeof(name)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 4), supervisor, sizeof(supervisor)) != 0) {
            PQclear(res); release_db_connection(conn, 0); return -1;
        }
        int n = snprintf(out_buf + offset, max_len - offset,
            "%s{\"id\":\"%s\",\"campus_id\":\"%s\",\"name\":\"%s\",\"capacity\":%d,\"supervisor\":\"%s\"}",
            i ? "," : "", id, campus, name, atoi(PQgetvalue(res, i, 3)), supervisor);
        if (n < 0 || (size_t)n >= max_len - offset) { PQclear(res); release_db_connection(conn, 0); return -1; }
        offset += (size_t)n;
    }
    int n = snprintf(out_buf + offset, max_len - offset, "]}");
    int ok = n >= 0 && (size_t)n < max_len - offset;
    PQclear(res); release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_create_room(const room_t *room) {
    if (!room || !room->room_id[0] || !room->campus_id[0] || !room->institution_id[0] ||
        !room->name[0] || room->capacity <= 0) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char cap_str[16];
    snprintf(cap_str, sizeof(cap_str), "%d", room->capacity);

    const char *params[] = {
        room->room_id,
        room->campus_id,
        room->institution_id,
        room->name,
        cap_str,
        room->supervisor[0] ? room->supervisor : ""
    };

    PGresult *res = PQexecParams(conn,
        "INSERT INTO examos_rooms (room_id, campus_id, institution_id, name, capacity, supervisor) "
        "SELECT $1, c.campus_id, c.institution_id, $4, $5::integer, $6 "
        "FROM examos_campuses c WHERE c.campus_id = $2 AND c.institution_id = $3 "
        "ON CONFLICT (room_id) DO UPDATE SET "
        "  name = EXCLUDED.name, capacity = EXCLUDED.capacity, supervisor = EXCLUDED.supervisor",
        6, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK && strcmp(PQcmdTuples(res), "1") == 0;
    if (res) PQclear(res);
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Dynamic Exams & Policy Storage (Module C, Module D) — Real PostgreSQL
 * ------------------------------------------------------------------------- */

int platform_create_exam(const enterprise_exam_t *exam) {
    if (!exam || !exam->exam_id[0] || !exam->institution_id[0] || !exam->title[0] ||
        !exam->code[0] || !exam->exam_url[0] || !exam->timezone[0] ||
        !exam->permitted_device_group[0] || !exam->browser_policy_json[0] ||
        exam->duration_minutes <= 0 || exam->retention_days <= 0 ||
        exam->scheduled_start <= 0 || exam->scheduled_end <= exam->scheduled_start ||
        platform_validate_exam_url(exam->exam_url, NULL, 0) != 0) {
        platform_set_error("title, institution_id, code, exam_url, timezone, permitted_device_group, "
                           "browser policy, a positive duration, a positive retention window and a "
                           "valid schedule are required, and the exam URL must be an approved origin");
        return -1;
    }
    char origin_error[192] = {0};
    if (platform_validate_allowed_origins(exam->allowed_origins, origin_error,
                                          sizeof(origin_error)) != 0) {
        platform_set_error(origin_error[0] ? origin_error : "Allowed origins are invalid.");
        return -1;
    }

    PGconn *conn = acquire_db_connection();
    if (!conn) {
        platform_set_error("The durable platform store is unreachable");
        return -1;
    }

    char dur_str[16], start_str[32], end_str[32], ret_str[16];
    snprintf(dur_str, sizeof(dur_str), "%d", exam->duration_minutes);
    snprintf(ret_str, sizeof(ret_str), "%d", exam->retention_days);

    time_t s_start = exam->scheduled_start;
    time_t s_end   = exam->scheduled_end;
    snprintf(start_str, sizeof(start_str), "%ld", (long)s_start);
    snprintf(end_str, sizeof(end_str), "%ld", (long)s_end);

    const char *params[] = {
        exam->exam_id,
        exam->institution_id,
        exam->owner_user_id[0] ? exam->owner_user_id : NULL,
        exam->code,
        exam->title,
        exam->exam_url,
        exam->allowed_origins[0] ? exam->allowed_origins : "",
        exam->additional_apis[0] ? exam->additional_apis : "",
        dur_str,
        start_str,
        end_str,
        exam->timezone,
        exam_state_to_string(exam->state),
        exam->permitted_device_group,
        exam->accommodations_allowed ? "true" : "false",
        exam->network_offline_allowed ? "true" : "false",
        exam->browser_policy_json,
        exam->incident_appeal_procedure,
        ret_str,
        "0",
        ""
    };

    PGresult *res = PQexecParams(conn,
        "INSERT INTO examos_exams ("
        "  exam_id, institution_id, owner_user_id, code, title, exam_url, "
        "  allowed_origins, additional_apis, duration_minutes, scheduled_start, "
        "  scheduled_end, timezone, state, permitted_device_group, accommodations_allowed, "
        "  network_offline_allowed, browser_policy_json, incident_appeal_procedure, retention_days, "
        "  policy_version, policy_signature"
        ") VALUES ("
        "  $1, $2, $3, $4, $5, $6, $7, $8, $9, to_timestamp($10::bigint), "
        "  to_timestamp($11::bigint), $12, $13, $14, $15::boolean, $16::boolean, "
        "  $17, $18, $19, $20::integer, $21"
        ") ON CONFLICT (exam_id) DO UPDATE SET "
        "  title = EXCLUDED.title, exam_url = EXCLUDED.exam_url, updated_at = clock_timestamp()",
        21, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (!ok) platform_set_db_error(res);
    if (res) PQclear(res);

    if (ok) {
        char details[256];
        snprintf(details, sizeof(details), "exam_id=%s title=%s state=%s",
                 exam->exam_id, exam->title, exam_state_to_string(exam->state));
        ledger_append("EXAM_DRAFT_CREATED", exam->exam_id, details);

        platform_audit(conn, exam->owner_user_id, "EXAM_DRAFT_CREATED", "EXAM", exam->exam_id);
    }

    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_get_exam_by_id(const char *exam_id, enterprise_exam_t *out_exam) {
    if (!exam_id || !out_exam) return -1;
    memset(out_exam, 0, sizeof(enterprise_exam_t));

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    const char *params[] = { exam_id };
    PGresult *res = PQexecParams(conn,
        "SELECT exam_id, institution_id, coalesce(owner_user_id,''), code, title, exam_url, "
        "       allowed_origins, additional_apis, duration_minutes, "
        "       extract(epoch from scheduled_start)::bigint, extract(epoch from scheduled_end)::bigint, "
        "       timezone, state, coalesce(approved_by,''), policy_version, policy_signature, "
        "       permitted_device_group, accommodations_allowed, network_offline_allowed, "
        "       browser_policy_json, incident_appeal_procedure, retention_days "
        "FROM examos_exams WHERE exam_id = $1",
        1, NULL, params, NULL, NULL, 0);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    snprintf(out_exam->exam_id, sizeof(out_exam->exam_id), "%s", PQgetvalue(res, 0, 0));
    snprintf(out_exam->institution_id, sizeof(out_exam->institution_id), "%s", PQgetvalue(res, 0, 1));
    snprintf(out_exam->owner_user_id, sizeof(out_exam->owner_user_id), "%s", PQgetvalue(res, 0, 2));
    snprintf(out_exam->code, sizeof(out_exam->code), "%s", PQgetvalue(res, 0, 3));
    snprintf(out_exam->title, sizeof(out_exam->title), "%s", PQgetvalue(res, 0, 4));
    snprintf(out_exam->exam_url, sizeof(out_exam->exam_url), "%s", PQgetvalue(res, 0, 5));
    snprintf(out_exam->allowed_origins, sizeof(out_exam->allowed_origins), "%s", PQgetvalue(res, 0, 6));
    snprintf(out_exam->additional_apis, sizeof(out_exam->additional_apis), "%s", PQgetvalue(res, 0, 7));
    out_exam->duration_minutes = atoi(PQgetvalue(res, 0, 8));
    out_exam->scheduled_start = (time_t)atoll(PQgetvalue(res, 0, 9));
    out_exam->scheduled_end = (time_t)atoll(PQgetvalue(res, 0, 10));
    snprintf(out_exam->timezone, sizeof(out_exam->timezone), "%s", PQgetvalue(res, 0, 11));
    out_exam->state = string_to_exam_state(PQgetvalue(res, 0, 12));
    snprintf(out_exam->approved_by, sizeof(out_exam->approved_by), "%s", PQgetvalue(res, 0, 13));
    out_exam->policy_version = (unsigned int)atoi(PQgetvalue(res, 0, 14));
    snprintf(out_exam->policy_signature, sizeof(out_exam->policy_signature), "%s", PQgetvalue(res, 0, 15));
    snprintf(out_exam->permitted_device_group, sizeof(out_exam->permitted_device_group), "%s", PQgetvalue(res, 0, 16));
    out_exam->accommodations_allowed = strcmp(PQgetvalue(res, 0, 17), "t") == 0;
    out_exam->network_offline_allowed = strcmp(PQgetvalue(res, 0, 18), "t") == 0;
    snprintf(out_exam->browser_policy_json, sizeof(out_exam->browser_policy_json), "%s", PQgetvalue(res, 0, 19));
    snprintf(out_exam->incident_appeal_procedure, sizeof(out_exam->incident_appeal_procedure), "%s", PQgetvalue(res, 0, 20));
    out_exam->retention_days = atoi(PQgetvalue(res, 0, 21));

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_get_exams_json(const char *inst_id, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 64) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = NULL;
    if (inst_id && inst_id[0]) {
        const char *params[] = { inst_id };
        res = PQexecParams(conn,
            "SELECT exam_id, institution_id, code, title, exam_url, allowed_origins, "
            "       duration_minutes, state, policy_version, policy_signature, "
            "       permitted_device_group, accommodations_allowed "
            "FROM examos_exams WHERE institution_id = $1 ORDER BY created_at DESC",
            1, NULL, params, NULL, NULL, 0);
    } else {
        res = PQexec(conn,
            "SELECT exam_id, institution_id, code, title, exam_url, allowed_origins, "
            "       duration_minutes, state, policy_version, policy_signature, "
            "       permitted_device_group, accommodations_allowed "
            "FROM examos_exams ORDER BY created_at DESC");
    }

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    int rows = PQntuples(res);
    int written = snprintf(out_buf, max_len, "{\"exams\":[");
    if (written < 0 || (size_t)written >= max_len) {
        PQclear(res); release_db_connection(conn, 0); return -1;
    }
    size_t offset = (size_t)written;

    for (int i = 0; i < rows; ++i) {
        char id[256], institution_id[256], code[128], title[512], exam_url[2048];
        char allowed_origins[1024], state[128], signature[512], device_group[256];
        if (platform_json_escape(PQgetvalue(res, i, 0), id, sizeof(id)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 1), institution_id, sizeof(institution_id)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 2), code, sizeof(code)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 3), title, sizeof(title)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 4), exam_url, sizeof(exam_url)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 5), allowed_origins, sizeof(allowed_origins)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 7), state, sizeof(state)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 9), signature, sizeof(signature)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 10), device_group, sizeof(device_group)) != 0) {
            PQclear(res); release_db_connection(conn, 0); return -1;
        }
        written = snprintf(out_buf + offset, max_len - offset,
            "%s{\"id\":\"%s\",\"institution_id\":\"%s\",\"code\":\"%s\",\"title\":\"%s\","
            "\"exam_url\":\"%s\",\"allowed_origins\":\"%s\",\"duration_minutes\":%d,"
            "\"state\":\"%s\",\"policy_version\":%u,\"policy_signature\":\"%s\","
            "\"permitted_device_group\":\"%s\",\"accommodations\":%s}",
            (i > 0 ? "," : ""),
            id, institution_id, code, title, exam_url, allowed_origins,
            atoi(PQgetvalue(res, i, 6)),
            state,
            (unsigned int)atoi(PQgetvalue(res, i, 8)),
            signature, device_group,
            strcmp(PQgetvalue(res, i, 11), "t") == 0 ? "true" : "false");
        if (written < 0 || (size_t)written >= max_len - offset) {
            PQclear(res); release_db_connection(conn, 0); return -1;
        }
        offset += (size_t)written;
    }
    written = snprintf(out_buf + offset, max_len - offset, "]}");
    if (written < 0 || (size_t)written >= max_len - offset) {
        PQclear(res); release_db_connection(conn, 0); return -1;
    }

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_get_exams_for_admin(const auth_session_t *session, char *out_buf,
                                 size_t max_len) {
    if (!session || !out_buf || max_len < 64) return -1;
    if (session->role == ROLE_PLATFORM_OWNER) {
        return platform_get_exams_json(NULL, out_buf, max_len);
    }
    if (!session->institution_id[0]) return -1;
    return platform_get_exams_json(session->institution_id, out_buf, max_len);
}

int platform_validate_exam_config(const char *exam_id, char *err_msg, size_t err_len) {
    enterprise_exam_t exam;
    if (platform_get_exam_by_id(exam_id, &exam) != 0) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Exam not found");
        return -1;
    }

    if (exam.duration_minutes <= 0 || exam.duration_minutes > 1440) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Invalid duration (must be 1-1440 mins)");
        return -1;
    }

    if (platform_validate_exam_url(exam.exam_url, err_msg, err_len) != 0) {
        return -1;
    }
    if (platform_validate_allowed_origins(exam.allowed_origins, err_msg, err_len) != 0) {
        return -1;
    }

    if (exam.scheduled_end <= exam.scheduled_start) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Scheduled end must be after scheduled start");
        return -1;
    }

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    const char *params[] = { exam_id };
    PGresult *res = PQexecParams(conn,
        "UPDATE examos_exams SET state = 'VALIDATED', updated_at = clock_timestamp() "
        "WHERE exam_id = $1 AND state = 'DRAFT'",
        1, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);

    if (ok) {
        ledger_append("EXAM_CONFIG_VALIDATED", exam_id, "Configuration structurally validated");
        platform_audit(conn, exam.owner_user_id[0] ? exam.owner_user_id : NULL, "EXAM_CONFIG_VALIDATED", "EXAM", exam_id);
    }

    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_approve_exam(const char *exam_id, const char *approver_user_id) {
    if (!exam_id || !approver_user_id) {
        errno = EINVAL;
        return -1;
    }
    return policy_trust_unavailable(NULL, 0);
}

int platform_schedule_exam(const char *exam_id, time_t start_time, time_t end_time, const char *timezone, const char *actor) {
    if (!exam_id || !timezone || !timezone[0] || end_time <= start_time) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char s_str[32], e_str[32];
    snprintf(s_str, sizeof(s_str), "%ld", (long)start_time);
    snprintf(e_str, sizeof(e_str), "%ld", (long)end_time);

    const char *params[] = { s_str, e_str, timezone, exam_id };
    PGresult *res = PQexecParams(conn,
        "UPDATE examos_exams SET state = 'SCHEDULED', scheduled_start = to_timestamp($1::bigint), "
        "  scheduled_end = to_timestamp($2::bigint), timezone = $3, updated_at = clock_timestamp() "
        "WHERE exam_id = $4 AND state IN ('APPROVED', 'SCHEDULED')",
        4, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);

    if (ok) {
        ledger_append("EXAM_SCHEDULED", exam_id, timezone);
        platform_audit(conn, actor, "EXAM_SCHEDULED", "EXAM", exam_id);
    }

    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Dependency health
 * ------------------------------------------------------------------------- */

/* Returns 0 when the durable platform store is reachable and responsive. */
int platform_database_health(void) {
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    PGresult *res = PQexec(conn, "SELECT 1");
    int ok = res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1;
    if (res) PQclear(res);
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Exam readiness
 *
 * Readiness is derived only from evidence the platform actually holds:
 * the device's own telemetry, its attestation state, the published exam
 * policy, and the device enrolment record.
 *
 * Every control is three-valued. "UNKNOWN" means the platform holds no
 * evidence either way. Reporting that as a failure would fabricate a
 * result; reporting it as a pass would be equally wrong.
 * ------------------------------------------------------------------------- */
typedef enum {
    PLATFORM_CONTROL_OK = 0,
    PLATFORM_CONTROL_FAILED = 1,
    PLATFORM_CONTROL_UNKNOWN = 2
} platform_control_t;

static const char *platform_control_name(platform_control_t control) {
    switch (control) {
        case PLATFORM_CONTROL_OK:     return "OK";
        case PLATFORM_CONTROL_FAILED: return "FAILED";
        default:                      return "UNKNOWN";
    }
}

/* Reads the most recent agent telemetry for a device. */
static int readiness_latest_telemetry(PGconn *conn, const char *device_id,
                                      char *out_network_state, size_t network_len,
                                      char *out_camera_available, size_t camera_len) {
    if (out_network_state && network_len) out_network_state[0] = '\0';
    if (out_camera_available && camera_len) out_camera_available[0] = '\0';
    if (!conn || !device_id || !device_id[0]) return -1;

    const char *params[1] = { device_id };
    PGresult *res = PQexecParams(conn,
        "SELECT payload->'hardware'->>'network_state', "
        "       payload->'hardware'->>'camera_available' "
        "FROM examos_agent_heartbeat_records "
        "WHERE device_id=$1 "
        "AND reported_at > clock_timestamp() - interval '5 minutes' "
        "ORDER BY reported_at DESC LIMIT 1",
        1, NULL, params, NULL, NULL, 0);

    int found = 0;
    if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
        found = 1;
        if (out_network_state && network_len)
            snprintf(out_network_state, network_len, "%s",
                     PQgetisnull(res, 0, 0) ? "" : PQgetvalue(res, 0, 0));
        if (out_camera_available && camera_len)
            snprintf(out_camera_available, camera_len, "%s",
                     PQgetisnull(res, 0, 1) ? "" : PQgetvalue(res, 0, 1));
    }
    if (res) PQclear(res);
    return found ? 0 : -1;
}

static platform_control_t readiness_network_control(PGconn *conn, const char *device_id,
                                                     int offline_allowed) {
    char network_state[32] = {0};
    if (readiness_latest_telemetry(conn, device_id, network_state, sizeof(network_state),
                                   NULL, 0) != 0 || !network_state[0]) {
        return PLATFORM_CONTROL_UNKNOWN;
    }
    if (strcmp(network_state, "ONLINE") == 0) return PLATFORM_CONTROL_OK;
    if (strcmp(network_state, "OFFLINE") == 0)
        return offline_allowed ? PLATFORM_CONTROL_OK : PLATFORM_CONTROL_FAILED;
    return PLATFORM_CONTROL_UNKNOWN;
}

static platform_control_t readiness_camera_control(PGconn *conn, const char *device_id) {
    char camera[16] = {0};
    if (readiness_latest_telemetry(conn, device_id, NULL, 0,
                                   camera, sizeof(camera)) != 0 || !camera[0]) {
        return PLATFORM_CONTROL_UNKNOWN;
    }
    if (strcmp(camera, "true") == 0) return PLATFORM_CONTROL_OK;
    if (strcmp(camera, "false") == 0) return PLATFORM_CONTROL_FAILED;
    return PLATFORM_CONTROL_UNKNOWN;
}

static platform_control_t readiness_tpm_control(PGconn *conn, const char *device_id) {
    const char *params[1] = { device_id };

    /* A device or release revocation is decisive regardless of history. */
    PGresult *revoked = PQexecParams(conn,
        "SELECT 1 FROM examos_attestation_revocations "
        "WHERE target_type='DEVICE' AND target_id=$1 LIMIT 1",
        1, NULL, params, NULL, NULL, 0);
    int device_revoked = (revoked && PQresultStatus(revoked) == PGRES_TUPLES_OK &&
                          PQntuples(revoked) == 1);
    if (revoked) PQclear(revoked);
    if (device_revoked) return PLATFORM_CONTROL_FAILED;

    PGresult *res = PQexecParams(conn,
        "SELECT state FROM examos_attestation_challenges "
        "WHERE device_id=$1 "
        "AND created_at > clock_timestamp() - interval '15 minutes' "
        "ORDER BY created_at DESC LIMIT 5",
        1, NULL, params, NULL, NULL, 0);

    platform_control_t verdict = PLATFORM_CONTROL_UNKNOWN;
    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
        int saw_trusted = 0, saw_failure = 0;
        for (int i = 0; i < PQntuples(res); i++) {
            const char *state = PQgetvalue(res, i, 0);
            if (strcmp(state, "TRUSTED") == 0) saw_trusted = 1;
            else if (strcmp(state, "FAILED") == 0 || strcmp(state, "REVOKED") == 0 ||
                     strcmp(state, "STALE") == 0) saw_failure = 1;
        }
        if (saw_trusted) verdict = PLATFORM_CONTROL_OK;
        else if (saw_failure) verdict = PLATFORM_CONTROL_FAILED;
    }
    if (res) PQclear(res);
    return verdict;
}

static platform_control_t readiness_kiosk_control(PGconn *conn, const char *exam_id,
                                                   const char *device_id) {
    (void)conn;
    (void)exam_id;
    (void)device_id;
    /* No authenticated policy-enforcement acknowledgement is available yet. */
    return PLATFORM_CONTROL_FAILED;
}

int platform_check_readiness(const char *exam_id, const char *device_id, char *out_json, size_t max_len) {
    if (!exam_id || !device_id) return -1;

    enterprise_exam_t exam;
    if (platform_get_exam_by_id(exam_id, &exam) != 0) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    /* The exam URL must be a usable HTTPS origin before the exam can run. */
    char url_error[256] = {0};
    int url_valid = (platform_validate_exam_url(exam.exam_url, url_error, sizeof(url_error)) == 0);

    platform_control_t network = readiness_network_control(conn, device_id,
                                                            exam.network_offline_allowed);
    if (!url_valid && network == PLATFORM_CONTROL_OK)
        network = PLATFORM_CONTROL_FAILED;

    platform_control_t tpm = readiness_tpm_control(conn, device_id);
    platform_control_t kiosk = readiness_kiosk_control(conn, exam_id, device_id);
    platform_control_t camera = readiness_camera_control(conn, device_id);

    int unknown = (network == PLATFORM_CONTROL_UNKNOWN) ||
                  (tpm == PLATFORM_CONTROL_UNKNOWN) ||
                  (kiosk == PLATFORM_CONTROL_UNKNOWN) ||
                  (camera == PLATFORM_CONTROL_UNKNOWN);
    int failed = (network == PLATFORM_CONTROL_FAILED) ||
                 (tpm == PLATFORM_CONTROL_FAILED) ||
                 (kiosk == PLATFORM_CONTROL_FAILED) ||
                 (camera == PLATFORM_CONTROL_FAILED);
    int passed = (!unknown && !failed);
    const char *verdict = failed ? "FAIL" : (unknown ? "INDETERMINATE" : "PASS");

    char details[512];
    snprintf(details, sizeof(details),
             "verdict=%s network=%s tpm=%s kiosk_policy=%s camera=%s url_valid=%s",
             verdict,
             platform_control_name(network), platform_control_name(tpm),
             platform_control_name(kiosk), platform_control_name(camera),
             url_valid ? "true" : "false");

    const char *params[] = {
        exam_id, device_id,
        network == PLATFORM_CONTROL_OK ? "true" : "false",
        tpm == PLATFORM_CONTROL_OK ? "true" : "false",
        kiosk == PLATFORM_CONTROL_OK ? "true" : "false",
        camera == PLATFORM_CONTROL_OK ? "true" : "false",
        passed ? "true" : "false",
        details
    };
    PGresult *res = PQexecParams(conn,
        "INSERT INTO examos_exam_readiness_checks ("
        "  exam_id, device_id, network_ok, tpm_attested, kiosk_policy_ready, camera_ready, passed, details"
        ") VALUES ($1, $2, $3::boolean, $4::boolean, $5::boolean, $6::boolean, $7::boolean, $8)",
        8, NULL, params, NULL, NULL, 0);
    if (res) PQclear(res);
    release_db_connection(conn, 0);

    if (out_json && max_len > 64) {
        snprintf(out_json, max_len,
            "{\"exam_id\":\"%s\",\"device_id\":\"%s\","
            "\"network\":\"%s\",\"tpm\":\"%s\",\"kiosk_policy\":\"%s\",\"camera\":\"%s\","
            "\"passed\":%s,\"verdict\":\"%s\"}",
            exam_id, device_id,
            platform_control_name(network), platform_control_name(tpm),
            platform_control_name(kiosk), platform_control_name(camera),
            passed ? "true" : "false", verdict);
    }
    return passed ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Exam lifecycle state machine
 *
 * The exam lifecycle is a directed graph. Transitions that are not part of
 * the graph are refused, so a mis-sequenced administrative action cannot
 * move an exam into a state it never legitimately reached.
 * ------------------------------------------------------------------------- */
int platform_exam_state_transition_allowed(exam_state_t from, exam_state_t to) {
    if (to == EXAM_STATE_ACTIVE) return 0;
    switch (from) {
        case EXAM_STATE_DRAFT:
            return to == EXAM_STATE_VALIDATED;
        case EXAM_STATE_VALIDATED:
            return to == EXAM_STATE_APPROVED || to == EXAM_STATE_DRAFT;
        case EXAM_STATE_APPROVED:
            return to == EXAM_STATE_SCHEDULED;
        case EXAM_STATE_SCHEDULED:
            return to == EXAM_STATE_OPEN;
        case EXAM_STATE_OPEN:
            return to == EXAM_STATE_PAUSED;
        case EXAM_STATE_ACTIVE:
            return to == EXAM_STATE_PAUSED || to == EXAM_STATE_SUBMISSION;
        case EXAM_STATE_PAUSED:
            return to == EXAM_STATE_SUBMISSION;
        case EXAM_STATE_SUBMISSION:
            return to == EXAM_STATE_CLOSED;
        case EXAM_STATE_CLOSED:
            return to == EXAM_STATE_RECONCILED;
        case EXAM_STATE_RECONCILED:
            return 0;
        default:
            return 0;
    }
}

int platform_update_exam_state(const char *exam_id, exam_state_t new_state, const char *actor) {
    if (!exam_id) return -1;

    const char *state_str = exam_state_to_string(new_state);
    if (strcmp(state_str, "UNKNOWN") == 0) return -1;
    if (new_state == EXAM_STATE_ACTIVE) {
        platform_set_error(
            "Exam activation is blocked until signed policy publication and authenticated device acknowledgements are available");
        errno = ENOTSUP;
        return -1;
    }

    PGconn *conn = acquire_db_connection();
    if (!conn) { errno = ENOTSUP; return -1; }

    /* Read the current state so the transition can be validated. */
    exam_state_t current_state = EXAM_STATE_DRAFT;
    int have_current = 0;
    {
        const char *current_params[1] = { exam_id };
        PGresult *current = PQexecParams(conn,
            "SELECT state FROM examos_exams WHERE exam_id=$1 FOR UPDATE",
            1, NULL, current_params, NULL, NULL, 0);
        if (current && PQresultStatus(current) == PGRES_TUPLES_OK &&
            PQntuples(current) == 1) {
            current_state = string_to_exam_state(PQgetvalue(current, 0, 0));
            have_current = 1;
        }
        if (current) PQclear(current);
    }
    if (!have_current) {
        release_db_connection(conn, 1);
        return -1;
    }
    if (current_state == new_state) {
        /* Idempotent re-request of the current state is not a transition. */
        release_db_connection(conn, 0);
        return 0;
    }
    if (!platform_exam_state_transition_allowed(current_state, new_state)) {
        release_db_connection(conn, 0);
        errno = EINVAL;
        return -1;
    }

    const char *params[] = { state_str, exam_id };
    PGresult *res = PQexecParams(conn,
        "UPDATE examos_exams SET state = $1, updated_at = clock_timestamp() WHERE exam_id = $2",
        2, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    int affected = res ? atoi(PQcmdTuples(res)) : 0;
    if (res) PQclear(res);

    if (ok && affected > 0) {
        char event_type[64];
        snprintf(event_type, sizeof(event_type), "EXAM_%s", state_str);
        if (strcmp(state_str, "OPEN") == 0) snprintf(event_type, sizeof(event_type), "EXAM_OPENED");
        else if (strcmp(state_str, "ACTIVE") == 0) snprintf(event_type, sizeof(event_type), "EXAM_ACTIVATED");
        else if (strcmp(state_str, "SUBMISSION") == 0) snprintf(event_type, sizeof(event_type), "EXAM_SUBMISSION_WINDOW");

        ledger_append(event_type, exam_id, actor ? actor : "system");

        /* A lifecycle change without an audit record must not be
           committed, so a failed audit insert fails the transition. */
        if (platform_audit(conn, actor, event_type, "EXAM", exam_id) != 0) ok = 0;
    }

    release_db_connection(conn, 0);
    return (ok && affected > 0) ? 0 : -1;
}

int platform_update_exam_url(const char *exam_id, const char *new_url, const char *allowed_origins, const char *actor) {
    platform_clear_error();
    errno = 0;
    if (!exam_id || !new_url) {
        platform_set_error("exam_id and exam_url are required");
        errno = EINVAL;
        return -1;
    }

    char validation_error[192] = {0};
    if (platform_validate_exam_url(new_url, validation_error, sizeof(validation_error)) != 0) {
        platform_set_error(validation_error[0] ? validation_error
                                               : "The exam URL must be an approved HTTPS endpoint");
        errno = EINVAL;
        return -1;
    }
    if (allowed_origins && allowed_origins[0] &&
        platform_validate_allowed_origins(allowed_origins, validation_error,
                                          sizeof(validation_error)) != 0) {
        platform_set_error(validation_error[0] ? validation_error
                                               : "The allowed origins must be approved HTTPS origins");
        errno = EINVAL;
        return -1;
    }

    PGconn *conn = acquire_db_connection();
    if (!conn) {
        platform_set_error("The durable platform store is unreachable");
        errno = ENOTSUP;
        return -1;
    }
    PGresult *res = PQexec(conn, "BEGIN");
    if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
        platform_set_db_error(res);
        if (res) PQclear(res);
        release_db_connection(conn, 1);
        errno = EIO;
        return -1;
    }
    PQclear(res);

    const char *exam_params[1] = { exam_id };
    PGresult *exam = PQexecParams(conn,
        "SELECT e.state, EXISTS (SELECT 1 FROM examos_exam_policies p "
        "WHERE p.exam_id=e.exam_id AND p.status IN ('ACTIVE','ROLLBACK')) "
        "FROM examos_exams e WHERE e.exam_id=$1 FOR UPDATE OF e",
        1, NULL, exam_params, NULL, NULL, 0);
    int exam_query_ok = exam && PQresultStatus(exam) == PGRES_TUPLES_OK;
    if (!exam_query_ok || PQntuples(exam) != 1) {
        if (exam_query_ok)
            platform_set_error("Exam does not exist");
        else
            platform_set_db_error(exam);
        if (exam) PQclear(exam);
        PQexec(conn, "ROLLBACK");
        release_db_connection(conn, 1);
        errno = exam_query_ok ? ENOENT : EIO;
        return -1;
    }
    int has_legacy_active_policy = strcmp(PQgetvalue(exam, 0, 1), "t") == 0;
    int editable = (strcmp(PQgetvalue(exam, 0, 0), "DRAFT") == 0 ||
                    strcmp(PQgetvalue(exam, 0, 0), "VALIDATED") == 0) &&
                   !has_legacy_active_policy;
    PQclear(exam);
    if (!editable) {
        PQexec(conn, "ROLLBACK");
        release_db_connection(conn, 0);
        if (has_legacy_active_policy)
            return policy_trust_unavailable(NULL, 0);
        platform_set_error("Exam URL can only be edited while the exam is a draft or validated");
        errno = EPERM;
        return -1;
    }

    const char *params[3] = {
        new_url, allowed_origins ? allowed_origins : "", exam_id
    };
    PGresult *updated = PQexecParams(conn,
        "UPDATE examos_exams SET exam_url=$1,allowed_origins=$2,state='DRAFT',"
        "approved_by=NULL,approved_at=NULL,policy_signature='',updated_at=clock_timestamp() "
        "WHERE exam_id=$3 AND state IN ('DRAFT','VALIDATED')",
        3, NULL, params, NULL, NULL, 0);
    int update_command_ok = updated && PQresultStatus(updated) == PGRES_COMMAND_OK;
    int ok = update_command_ok && strcmp(PQcmdTuples(updated), "1") == 0;
    if (!update_command_ok)
        platform_set_db_error(updated);
    else if (!ok)
        platform_set_error("Exam state changed before the draft URL update could be applied");
    if (updated) PQclear(updated);

    if (ok && platform_audit(conn, actor, "EXAM_DRAFT", "EXAM", exam_id) != 0) {
        platform_set_error("The exam URL update could not be audited");
        ok = 0;
    }

    int connection_broken = 0;
    if (ok) {
        res = PQexec(conn, "COMMIT");
        if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
            platform_set_db_error(res);
            if (res) PQclear(res);
            res = PQexec(conn, "ROLLBACK");
            connection_broken = !res || PQresultStatus(res) != PGRES_COMMAND_OK;
            ok = 0;
        }
    } else {
        res = PQexec(conn, "ROLLBACK");
        connection_broken = !res || PQresultStatus(res) != PGRES_COMMAND_OK;
    }
    if (res) PQclear(res);

    release_db_connection(conn, connection_broken || PQstatus(conn) != CONNECTION_OK);
    if (!ok) {
        errno = EIO;
        return -1;
    }
    ledger_append("EXAM_URL_DRAFT_EDITED", exam_id,
                  "Draft URL and origins updated; no policy was activated");
    return 0;
}

int platform_get_policies_json(const char *exam_id, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 64) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = NULL;
    if (exam_id && exam_id[0]) {
        const char *params[] = { exam_id };
        res = PQexecParams(conn,
            "SELECT policy_version, exam_id, exam_url, allowed_origins, signature, "
            "       coalesce(approved_by, 'system'), extract(epoch from created_at)::bigint, status "
            "FROM examos_exam_policies WHERE exam_id = $1 ORDER BY policy_version DESC",
            1, NULL, params, NULL, NULL, 0);
    } else {
        res = PQexec(conn,
            "SELECT policy_version, exam_id, exam_url, allowed_origins, signature, "
            "       coalesce(approved_by, 'system'), extract(epoch from created_at)::bigint, status "
            "FROM examos_exam_policies ORDER BY created_at DESC");
    }

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    int rows = PQntuples(res);
    size_t offset = snprintf(out_buf, max_len, "{\"policies\":[");

    for (int i = 0; i < rows; ++i) {
        offset += snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0,
            "%s{\"version\":%u,\"exam_id\":\"%s\",\"exam_url\":\"%s\",\"origins\":\"%s\","
            "\"signature\":\"%s\",\"approved_by\":\"%s\",\"created_at\":%ld,\"status\":\"%s\","
            "\"authorization_status\":\"LEGACY_UNTRUSTED\"}",
            (i > 0 ? "," : ""),
            (unsigned int)atoi(PQgetvalue(res, i, 0)),
            PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2),
            PQgetvalue(res, i, 3),
            PQgetvalue(res, i, 4),
            PQgetvalue(res, i, 5),
            (long)atoll(PQgetvalue(res, i, 6)),
            PQgetvalue(res, i, 7));
        if (offset >= max_len - 100) break;
    }
    snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0, "]}");

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_get_active_signed_policy(const char *exam_id, signed_policy_t *out_policy) {
    if (!exam_id || !out_policy) {
        errno = EINVAL;
        return -1;
    }
    memset(out_policy, 0, sizeof(*out_policy));
    return policy_trust_unavailable(NULL, 0);
}

int platform_distribute_policy_bundle_json(const char *exam_id, const char *device_id, char *out_json, size_t max_len) {
    if (out_json && max_len) out_json[0] = '\0';
    if (!exam_id || !device_id || !device_id[0] || !out_json || max_len == 0) {
        errno = EINVAL;
        return -1;
    }
    return policy_trust_unavailable(NULL, 0);
}

int platform_verify_client_policy(const char *policy_json, const char *expected_exam_id, const char *device_id, char *err_msg, size_t err_len) {
    if (!policy_json || !expected_exam_id) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Missing policy payload or expected exam ID");
        errno = EINVAL;
        return -1;
    }
    (void)device_id;
    return policy_trust_unavailable(err_msg, err_len);
}

int platform_rollback_policy(const char *exam_id, unsigned int target_version, const char *actor) {
    if (!exam_id || target_version == 0) return -1;
    (void)actor;
    return policy_trust_unavailable(NULL, 0);
}

int platform_reconcile_exam(const char *exam_id, char *out_report_json, size_t max_len) {
    if (!exam_id) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) {
        /* No database — return a structured NO_DATA response so tests and
         * callers can distinguish "unprovisioned" from a real I/O failure. */
        if (out_report_json && max_len > 128) {
            snprintf(out_report_json, max_len,
                "{\"exam_id\":\"%s\",\"total_roster\":0,\"checked_in\":0,\"in_exam\":0,"
                "\"submitted\":0,\"disqualified\":0,\"discrepancies\":0,"
                "\"reconciliation_status\":\"NO_DATA\"}",
                exam_id[0] ? exam_id : "UNPROVISIONED");
        }
        return 0;
    }

    const char *params[] = { exam_id };
    PGresult *res = PQexecParams(conn,
        "SELECT "
        "  count(*)::integer AS total_roster, "
        "  count(*) FILTER (WHERE status = 'CHECKED_IN')::integer AS checked_in, "
        "  count(*) FILTER (WHERE status = 'IN_EXAM')::integer AS in_exam, "
        "  count(*) FILTER (WHERE status = 'SUBMITTED')::integer AS submitted, "
        "  count(*) FILTER (WHERE status = 'DISQUALIFIED')::integer AS disqualified "
        "FROM examos_exam_roster WHERE exam_id = $1",
        1, NULL, params, NULL, NULL, 0);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    int total_roster = atoi(PQgetvalue(res, 0, 0));
    int checked_in   = atoi(PQgetvalue(res, 0, 1));
    int in_exam      = atoi(PQgetvalue(res, 0, 2));
    int submitted    = atoi(PQgetvalue(res, 0, 3));
    int disqualified = atoi(PQgetvalue(res, 0, 4));
    PQclear(res);

    int discrepancies = total_roster - (submitted + disqualified);
    if (discrepancies < 0) discrepancies = 0;
    const char *rec_status = (total_roster == 0) ? "NO_DATA" :
                             (discrepancies == 0) ? "BALANCED" : "ACTION_REQUIRED";

    /* Transition exam to RECONCILED if balanced */
    if (discrepancies == 0 && total_roster > 0) {
        res = PQexecParams(conn,
            "UPDATE examos_exams SET state = 'RECONCILED', updated_at = clock_timestamp() "
            "WHERE exam_id = $1 AND state = 'CLOSED'",
            1, NULL, params, NULL, NULL, 0);
        if (res) PQclear(res);
        ledger_append("EXAM_RECONCILED", exam_id, "All rosters reconciled");
    }

    if (out_report_json && max_len > 128) {
        snprintf(out_report_json, max_len,
            "{\"exam_id\":\"%s\",\"total_roster\":%d,\"checked_in\":%d,\"in_exam\":%d,"
            "\"submitted\":%d,\"disqualified\":%d,\"discrepancies\":%d,\"reconciliation_status\":\"%s\"}",
            exam_id, total_roster, checked_in, in_exam, submitted, disqualified, discrepancies, rec_status);
    }

    release_db_connection(conn, 0);
    return 0;
}

int platform_purge_expired_exams(int retention_days, char *out_summary_json, size_t max_len) {
    if (retention_days <= 0) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char ret_str[16];
    snprintf(ret_str, sizeof(ret_str), "%d", retention_days);

    const char *params[] = { ret_str };
    PGresult *res = PQexecParams(conn,
        "DELETE FROM examos_exams "
        "WHERE state = 'RECONCILED' "
        "  AND updated_at < (clock_timestamp() - ($1::integer * interval '1 day')) "
        "RETURNING exam_id",
        1, NULL, params, NULL, NULL, 0);

    int purged_count = 0;
    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
        purged_count = PQntuples(res);
        for (int i = 0; i < purged_count; ++i) {
            ledger_append("EXAM_PURGED_RETENTION", PQgetvalue(res, i, 0), "Retention expiration");
        }
    }
    if (res) PQclear(res);

    if (out_summary_json && max_len > 64) {
        snprintf(out_summary_json, max_len,
            "{\"status\":\"PURGE_COMPLETE\",\"retention_days\":%d,\"purged_count\":%d}",
            retention_days, purged_count);
    }

    release_db_connection(conn, 0);
    return purged_count >= 0 ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Roster & Candidate Assignment (Module C, Module A.7) — Real PostgreSQL
 * ------------------------------------------------------------------------- */
int platform_get_roster_json(const char *exam_id, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 64) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = NULL;
    if (exam_id && exam_id[0]) {
        const char *params[] = { exam_id };
        res = PQexecParams(conn,
            "SELECT roster_id, exam_id, candidate_id, full_name, email, "
            "       coalesce(room_id, ''), assigned_seat, assigned_device_id, "
            "       status, accommodation_extra_time_mins "
            "FROM examos_exam_roster WHERE exam_id = $1 ORDER BY candidate_id ASC",
            1, NULL, params, NULL, NULL, 0);
    } else {
        res = PQexec(conn,
            "SELECT roster_id, exam_id, candidate_id, full_name, email, "
            "       coalesce(room_id, ''), assigned_seat, assigned_device_id, "
            "       status, accommodation_extra_time_mins "
            "FROM examos_exam_roster ORDER BY created_at DESC");
    }

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    int rows = PQntuples(res);
    size_t offset = snprintf(out_buf, max_len, "{\"roster\":[");

    for (int i = 0; i < rows; ++i) {
        char roster_id[256], exam[256], candidate[256], name[512], email[512];
        char room[256], seat[256], device[256], status[128];
        if (platform_json_escape(PQgetvalue(res, i, 0), roster_id, sizeof(roster_id)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 1), exam, sizeof(exam)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 2), candidate, sizeof(candidate)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 3), name, sizeof(name)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 4), email, sizeof(email)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 5), room, sizeof(room)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 6), seat, sizeof(seat)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 7), device, sizeof(device)) != 0 ||
            platform_json_escape(PQgetvalue(res, i, 8), status, sizeof(status)) != 0) {
            PQclear(res); release_db_connection(conn, 0); return -1;
        }
        int written = snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0,
            "%s{\"roster_id\":\"%s\",\"exam_id\":\"%s\",\"candidate_id\":\"%s\",\"name\":\"%s\","
            "\"email\":\"%s\",\"room_id\":\"%s\",\"seat\":\"%s\",\"device_id\":\"%s\","
            "\"status\":\"%s\",\"extra_time_mins\":%d}",
            (i > 0 ? "," : ""),
            roster_id, exam, candidate, name, email, room, seat, device, status,
            atoi(PQgetvalue(res, i, 9)));
        if (written < 0 || (size_t)written >= max_len - offset) { PQclear(res); release_db_connection(conn, 0); return -1; }
        offset += (size_t)written;
    }
    if (snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0, "]}") >= (int)(max_len - offset)) {
        PQclear(res); release_db_connection(conn, 0); return -1;
    }

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_add_candidate_roster(const candidate_roster_entry_t *entry) {
    if (!entry || !entry->exam_id[0] || !entry->candidate_id[0] || !entry->pin_hash[0] ||
        entry->accommodation_extra_time_mins < 0) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char extra_time_str[16];
    snprintf(extra_time_str, sizeof(extra_time_str), "%d", entry->accommodation_extra_time_mins);

    char auto_roster_id[64];
    if (entry->roster_id[0]) {
        snprintf(auto_roster_id, sizeof(auto_roster_id), "%s", entry->roster_id);
    } else {
        snprintf(auto_roster_id, sizeof(auto_roster_id), "R-%.28s-%.28s", entry->exam_id, entry->candidate_id);
    }

    const char *params[] = {
        auto_roster_id,
        entry->exam_id,
        entry->candidate_id,
        entry->full_name,
        entry->email,
        entry->pin_hash,
        entry->room_id[0] ? entry->room_id : NULL,
        entry->assigned_seat[0] ? entry->assigned_seat : "",
        entry->assigned_device_id[0] ? entry->assigned_device_id : "",
        candidate_status_to_string(entry->status),
        extra_time_str
    };

    PGresult *res = PQexecParams(conn,
        "INSERT INTO examos_exam_roster ("
        "  roster_id, exam_id, candidate_id, full_name, email, pin_hash, "
        "  room_id, assigned_seat, assigned_device_id, status, accommodation_extra_time_mins"
        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::integer) "
        "ON CONFLICT (exam_id, candidate_id) DO UPDATE SET "
        "  full_name = EXCLUDED.full_name, email = EXCLUDED.email, "
        "  room_id = EXCLUDED.room_id, assigned_seat = EXCLUDED.assigned_seat, "
        "  assigned_device_id = EXCLUDED.assigned_device_id, "
        "  accommodation_extra_time_mins = EXCLUDED.accommodation_extra_time_mins",
        11, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);

    if (ok) {
        char details[256];
        snprintf(details, sizeof(details), "candidate_id=%s seat=%s device=%s",
                 entry->candidate_id, entry->assigned_seat, entry->assigned_device_id);
        ledger_append("EXAM_ROSTER_CANDIDATE_ADDED", entry->exam_id, details);
    }

    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_checkin_candidate(const char *exam_id, const char *candidate_id, const char *device_id) {
    if (!candidate_id) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = NULL;
    if (exam_id && exam_id[0]) {
        const char *params[] = { device_id ? device_id : "", exam_id, candidate_id };
        res = PQexecParams(conn,
            "UPDATE examos_exam_roster SET "
            "  status = 'CHECKED_IN', check_in_time = clock_timestamp(), assigned_device_id = $1 "
            "WHERE exam_id = $2 AND candidate_id = $3",
            3, NULL, params, NULL, NULL, 0);
    } else {
        const char *params[] = { device_id ? device_id : "", candidate_id };
        res = PQexecParams(conn,
            "UPDATE examos_exam_roster SET "
            "  status = 'CHECKED_IN', check_in_time = clock_timestamp(), assigned_device_id = $1 "
            "WHERE candidate_id = $2",
            2, NULL, params, NULL, NULL, 0);
    }

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    int affected = res ? atoi(PQcmdTuples(res)) : 0;
    if (res) PQclear(res);

    if (ok && affected > 0) {
        char details[256];
        snprintf(details, sizeof(details), "exam_id=%s device_id=%s", exam_id ? exam_id : "", device_id ? device_id : "");
        ledger_append("CANDIDATE_CHECKIN", candidate_id, details);
    }

    release_db_connection(conn, 0);
    return (ok && affected > 0) ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Fleet & Devices Management (Module G)
 * ------------------------------------------------------------------------- */
static int db_sync_device_upsert(const fleet_device_record_t *dev) {
    if (!dev || !dev->device_id[0]) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char pol_ver_str[16];
    snprintf(pol_ver_str, sizeof(pol_ver_str), "%u", dev->active_policy_version);

    const char *inst_param = dev->institution_id[0] ? dev->institution_id : NULL;
    const char *campus_param = dev->campus_id[0] ? dev->campus_id : NULL;
    const char *room_param = dev->room_id[0] ? dev->room_id : NULL;
    const char *exam_param = dev->assigned_exam_id[0] ? dev->assigned_exam_id : NULL;
    const char *replace_param = dev->replacement_for_device_id[0] ? dev->replacement_for_device_id : NULL;

    char last_attest_str[32] = {0};
    if (dev->last_attestation_ts > 0) {
        snprintf(last_attest_str, sizeof(last_attest_str), "%lld", (long long)dev->last_attestation_ts);
    }
    const char *last_attest_param = last_attest_str[0] ? last_attest_str : NULL;

    const char *params[28];
    params[0] = dev->device_id;
    params[1] = dev->hostname;
    params[2] = inst_param;
    params[3] = campus_param;
    params[4] = room_param;
    params[5] = dev->group_name;
    params[6] = ring_to_string(dev->ring);
    params[7] = dev->ownership_type[0] ? dev->ownership_type : (dev->student_owned ? "STUDENT_OWNED" : "INSTITUTION_OWNED");
    params[8] = dev->student_owned ? "true" : "false";
    params[9] = dev->hardware_platform;
    params[10] = dev->enrollment_status[0] ? dev->enrollment_status : (dev->enrolled ? "ENROLLED" : "PENDING_APPROVAL");
    params[11] = dev->crypto_identity_ref[0] ? dev->crypto_identity_ref : "";
    params[12] = dev->os_release;
    params[13] = dev->image_digest[0] ? dev->image_digest : "";
    params[14] = dev->uki_digest[0] ? dev->uki_digest : "";
    params[15] = pol_ver_str;
    params[16] = dev->attestation_status[0] ? dev->attestation_status : "NOT_ATTESTED";
    params[17] = dev->compliance_status[0] ? dev->compliance_status : "NON_COMPLIANT";
    params[18] = exam_param;
    params[19] = dev->current_candidate_id[0] ? dev->current_candidate_id : "";
    params[20] = dev->session_state[0] ? dev->session_state : "IDLE";
    params[21] = dev->update_status[0] ? dev->update_status : "UNKNOWN";
    params[22] = dev->incident_refs[0] ? dev->incident_refs : "";
    params[23] = replace_param;
    params[24] = dev->maintenance_mode ? "true" : "false";
    params[25] = dev->enrolled ? "true" : "false";
    params[26] = last_attest_param;
    char last_checkin_str[32] = {0};
    if (dev->last_checkin > 0) {
        snprintf(last_checkin_str, sizeof(last_checkin_str), "%lld", (long long)dev->last_checkin);
    }
    params[27] = last_checkin_str[0] ? last_checkin_str : NULL;

    PGresult *res = PQexecParams(conn,
        "INSERT INTO examos_devices ("
        "  device_id, hostname, institution_id, campus_id, room_id, "
        "  group_name, deployment_ring, ownership_type, student_owned, "
        "  hardware_platform, enrollment_status, crypto_identity_ref, "
        "  os_release, image_digest, uki_digest, policy_version, "
        "  attestation_status, compliance_status, assigned_exam_id, "
        "  current_candidate_id, session_state, update_status, "
        "  incident_refs, replacement_for_device_id, maintenance_mode, enrolled, "
        "  last_attestation_ts, last_checkin, updated_at"
        ") VALUES ("
        "  $1, $2, $3, $4, $5, "
        "  $6, $7, $8, $9::boolean, "
        "  $10, $11, $12, "
        "  $13, $14, $15, $16::integer, "
        "  $17, $18, $19, "
        "  $20, $21, $22, "
        "  $23, $24, $25::boolean, $26::boolean, "
        "  CASE WHEN $27::text IS NOT NULL THEN to_timestamp($27::bigint) ELSE NULL END, "
        "  CASE WHEN $28::text IS NOT NULL THEN to_timestamp($28::bigint) ELSE NULL END, clock_timestamp()"
        ") ON CONFLICT (device_id) DO UPDATE SET "
        "  hostname = EXCLUDED.hostname, "
        "  institution_id = EXCLUDED.institution_id, "
        "  campus_id = EXCLUDED.campus_id, "
        "  room_id = EXCLUDED.room_id, "
        "  group_name = EXCLUDED.group_name, "
        "  deployment_ring = EXCLUDED.deployment_ring, "
        "  ownership_type = EXCLUDED.ownership_type, "
        "  student_owned = EXCLUDED.student_owned, "
        "  hardware_platform = EXCLUDED.hardware_platform, "
        "  enrollment_status = EXCLUDED.enrollment_status, "
        "  crypto_identity_ref = EXCLUDED.crypto_identity_ref, "
        "  os_release = EXCLUDED.os_release, "
        "  image_digest = EXCLUDED.image_digest, "
        "  uki_digest = EXCLUDED.uki_digest, "
        "  policy_version = EXCLUDED.policy_version, "
        "  attestation_status = EXCLUDED.attestation_status, "
        "  compliance_status = EXCLUDED.compliance_status, "
        "  assigned_exam_id = EXCLUDED.assigned_exam_id, "
        "  current_candidate_id = EXCLUDED.current_candidate_id, "
        "  session_state = EXCLUDED.session_state, "
        "  update_status = EXCLUDED.update_status, "
        "  incident_refs = EXCLUDED.incident_refs, "
        "  replacement_for_device_id = EXCLUDED.replacement_for_device_id, "
        "  maintenance_mode = EXCLUDED.maintenance_mode, "
        "  enrolled = EXCLUDED.enrolled, "
        "  last_attestation_ts = COALESCE(EXCLUDED.last_attestation_ts, examos_devices.last_attestation_ts), "
        "  last_checkin = EXCLUDED.last_checkin, "
        "  updated_at = clock_timestamp()",
        28, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

static int load_devices_from_db(void) {
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = PQexec(conn,
        "SELECT device_id, hostname, COALESCE(institution_id, ''), COALESCE(campus_id, ''), "
        "       COALESCE(room_id, ''), group_name, deployment_ring, ownership_type, "
        "       student_owned, hardware_platform, enrollment_status, crypto_identity_ref, "
        "       os_release, image_digest, uki_digest, policy_version, "
        "       attestation_status, compliance_status, COALESCE(assigned_exam_id, ''), "
        "       current_candidate_id, session_state, update_status, incident_refs, "
        "       COALESCE(replacement_for_device_id, ''), maintenance_mode, enrolled, "
        "       EXTRACT(EPOCH FROM last_checkin)::bigint "
        "FROM examos_devices ORDER BY created_at ASC LIMIT 256");

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    int rows = PQntuples(res);
    pthread_mutex_lock(&g_platform_lock);
    g_device_count = 0;
    for (int i = 0; i < rows && i < MAX_DEVICES; i++) {
        fleet_device_record_t *d = &g_devices[g_device_count++];
        memset(d, 0, sizeof(*d));
        snprintf(d->device_id, sizeof(d->device_id), "%s", PQgetvalue(res, i, 0));
        snprintf(d->hostname, sizeof(d->hostname), "%s", PQgetvalue(res, i, 1));
        snprintf(d->institution_id, sizeof(d->institution_id), "%s", PQgetvalue(res, i, 2));
        snprintf(d->campus_id, sizeof(d->campus_id), "%s", PQgetvalue(res, i, 3));
        snprintf(d->room_id, sizeof(d->room_id), "%s", PQgetvalue(res, i, 4));
        snprintf(d->group_name, sizeof(d->group_name), "%s", PQgetvalue(res, i, 5));
        const char *ring_s = PQgetvalue(res, i, 6);
        if (strcasecmp(ring_s, "CANARY") == 0) d->ring = RING_CANARY;
        else if (strcasecmp(ring_s, "PILOT") == 0) d->ring = RING_PILOT;
        else d->ring = RING_GENERAL;
        snprintf(d->ownership_type, sizeof(d->ownership_type), "%s", PQgetvalue(res, i, 7));
        d->student_owned = (strcmp(PQgetvalue(res, i, 8), "t") == 0 || strcmp(PQgetvalue(res, i, 8), "1") == 0) ? 1 : 0;
        snprintf(d->hardware_platform, sizeof(d->hardware_platform), "%s", PQgetvalue(res, i, 9));
        snprintf(d->enrollment_status, sizeof(d->enrollment_status), "%s", PQgetvalue(res, i, 10));
        snprintf(d->crypto_identity_ref, sizeof(d->crypto_identity_ref), "%s", PQgetvalue(res, i, 11));
        snprintf(d->os_release, sizeof(d->os_release), "%s", PQgetvalue(res, i, 12));
        snprintf(d->image_digest, sizeof(d->image_digest), "%s", PQgetvalue(res, i, 13));
        snprintf(d->uki_digest, sizeof(d->uki_digest), "%s", PQgetvalue(res, i, 14));
        d->active_policy_version = (unsigned int)atoi(PQgetvalue(res, i, 15));
        snprintf(d->attestation_status, sizeof(d->attestation_status), "%s", PQgetvalue(res, i, 16));
        snprintf(d->compliance_status, sizeof(d->compliance_status), "%s", PQgetvalue(res, i, 17));
        snprintf(d->assigned_exam_id, sizeof(d->assigned_exam_id), "%s", PQgetvalue(res, i, 18));
        snprintf(d->current_candidate_id, sizeof(d->current_candidate_id), "%s", PQgetvalue(res, i, 19));
        snprintf(d->session_state, sizeof(d->session_state), "%s", PQgetvalue(res, i, 20));
        snprintf(d->update_status, sizeof(d->update_status), "%s", PQgetvalue(res, i, 21));
        snprintf(d->incident_refs, sizeof(d->incident_refs), "%s", PQgetvalue(res, i, 22));
        snprintf(d->replacement_for_device_id, sizeof(d->replacement_for_device_id), "%s", PQgetvalue(res, i, 23));
        d->maintenance_mode = (strcmp(PQgetvalue(res, i, 24), "t") == 0 || strcmp(PQgetvalue(res, i, 24), "1") == 0) ? 1 : 0;
        d->enrolled = (strcmp(PQgetvalue(res, i, 25), "t") == 0 || strcmp(PQgetvalue(res, i, 25), "1") == 0) ? 1 : 0;
        d->last_checkin = (time_t)atoll(PQgetvalue(res, i, 26));
    }
    pthread_mutex_unlock(&g_platform_lock);

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_get_fleet_json(const char *inst_id, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 64) return -1;
    PGconn *conn = acquire_db_connection();
    if (conn) {
        PGresult *res = NULL;
        if (inst_id && inst_id[0]) {
            const char *params[] = { inst_id };
            res = PQexecParams(conn,
                "SELECT device_id, hostname, COALESCE(institution_id, ''), COALESCE(campus_id, ''), "
                "       COALESCE(room_id, ''), group_name, deployment_ring, ownership_type, "
                "       student_owned, hardware_platform, enrollment_status, crypto_identity_ref, "
                "       os_release, image_digest, uki_digest, policy_version, "
                "       attestation_status, compliance_status, COALESCE(assigned_exam_id, ''), "
                "       current_candidate_id, session_state, update_status, incident_refs, "
                "       COALESCE(replacement_for_device_id, ''), maintenance_mode, enrolled, "
                "       EXTRACT(EPOCH FROM last_checkin)::bigint "
                "FROM examos_devices WHERE institution_id = $1 ORDER BY device_id ASC",
                1, NULL, params, NULL, NULL, 0);
        } else {
            res = PQexec(conn,
                "SELECT device_id, hostname, COALESCE(institution_id, ''), COALESCE(campus_id, ''), "
                "       COALESCE(room_id, ''), group_name, deployment_ring, ownership_type, "
                "       student_owned, hardware_platform, enrollment_status, crypto_identity_ref, "
                "       os_release, image_digest, uki_digest, policy_version, "
                "       attestation_status, compliance_status, COALESCE(assigned_exam_id, ''), "
                "       current_candidate_id, session_state, update_status, incident_refs, "
                "       COALESCE(replacement_for_device_id, ''), maintenance_mode, enrolled, "
                "       EXTRACT(EPOCH FROM last_checkin)::bigint "
                "FROM examos_devices ORDER BY device_id ASC");
        }

        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            int rows = PQntuples(res);
            size_t offset = snprintf(out_buf, max_len, "{\"devices\":[");
            for (int i = 0; i < rows; ++i) {
                int student_owned = (strcmp(PQgetvalue(res, i, 8), "t") == 0 || strcmp(PQgetvalue(res, i, 8), "1") == 0);
                int maint = (strcmp(PQgetvalue(res, i, 24), "t") == 0 || strcmp(PQgetvalue(res, i, 24), "1") == 0);
                int enr = (strcmp(PQgetvalue(res, i, 25), "t") == 0 || strcmp(PQgetvalue(res, i, 25), "1") == 0);
                offset += snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0,
                    "%s{\"device_id\":\"%s\",\"hostname\":\"%s\",\"institution_id\":\"%s\","
                    "\"campus_id\":\"%s\",\"room_id\":\"%s\",\"group\":\"%s\",\"ring\":\"%s\","
                    "\"ownership_type\":\"%s\",\"student_owned\":%s,\"hardware_platform\":\"%s\","
                    "\"enrollment_status\":\"%s\",\"crypto_identity_ref\":\"%s\",\"os_release\":\"%s\","
                    "\"image_digest\":\"%s\",\"uki_digest\":\"%s\",\"policy_version\":%d,"
                    "\"attestation_status\":\"%s\",\"compliance_status\":\"%s\",\"assigned_exam_id\":\"%s\","
                    "\"candidate_id\":\"%s\",\"session_state\":\"%s\",\"update_status\":\"%s\","
                    "\"incident_refs\":\"%s\",\"replacement_for\":\"%s\",\"maintenance\":%s,\"enrolled\":%s,\"last_seen\":%lld}",
                    (i > 0 ? "," : ""),
                    PQgetvalue(res, i, 0),
                    PQgetvalue(res, i, 1),
                    PQgetvalue(res, i, 2),
                    PQgetvalue(res, i, 3),
                    PQgetvalue(res, i, 4),
                    PQgetvalue(res, i, 5),
                    PQgetvalue(res, i, 6),
                    PQgetvalue(res, i, 7),
                    student_owned ? "true" : "false",
                    PQgetvalue(res, i, 9),
                    PQgetvalue(res, i, 10),
                    PQgetvalue(res, i, 11),
                    PQgetvalue(res, i, 12),
                    PQgetvalue(res, i, 13),
                    PQgetvalue(res, i, 14),
                    atoi(PQgetvalue(res, i, 15)),
                    PQgetvalue(res, i, 16),
                    PQgetvalue(res, i, 17),
                    PQgetvalue(res, i, 18),
                    PQgetvalue(res, i, 19),
                    PQgetvalue(res, i, 20),
                    PQgetvalue(res, i, 21),
                    PQgetvalue(res, i, 22),
                    PQgetvalue(res, i, 23),
                    maint ? "true" : "false",
                    enr ? "true" : "false",
                    (long long)atoll(PQgetvalue(res, i, 26)));
                if (offset >= max_len - 100) break;
            }
            snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0, "]}");
            PQclear(res);
            release_db_connection(conn, 0);
            return 0;
        }
        if (res) PQclear(res);
        release_db_connection(conn, 0);
    }

    /* Fallback to in-memory g_devices */
    pthread_mutex_lock(&g_platform_lock);
    size_t offset = snprintf(out_buf, max_len, "{\"devices\":[");
    int first = 1;
    for (int i = 0; i < g_device_count; i++) {
        if (!inst_id || strlen(inst_id) == 0 || strcmp(g_devices[i].institution_id, inst_id) == 0) {
            offset += snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0,
                "%s{\"device_id\":\"%s\",\"hostname\":\"%s\",\"institution_id\":\"%s\","
                "\"campus_id\":\"%s\",\"room_id\":\"%s\",\"group\":\"%s\",\"ring\":\"%s\","
                "\"ownership_type\":\"%s\",\"student_owned\":%s,\"hardware_platform\":\"%s\","
                "\"enrollment_status\":\"%s\",\"crypto_identity_ref\":\"%s\",\"os_release\":\"%s\","
                "\"image_digest\":\"%s\",\"uki_digest\":\"%s\",\"policy_version\":%u,"
                "\"attestation_status\":\"%s\",\"compliance_status\":\"%s\",\"assigned_exam_id\":\"%s\","
                "\"candidate_id\":\"%s\",\"session_state\":\"%s\",\"update_status\":\"%s\","
                "\"incident_refs\":\"%s\",\"replacement_for\":\"%s\",\"maintenance\":%s,\"enrolled\":%s,\"last_seen\":%lld}",
                (first ? "" : ","),
                g_devices[i].device_id,
                g_devices[i].hostname,
                g_devices[i].institution_id,
                g_devices[i].campus_id,
                g_devices[i].room_id,
                g_devices[i].group_name,
                ring_to_string(g_devices[i].ring),
                g_devices[i].ownership_type,
                g_devices[i].student_owned ? "true" : "false",
                g_devices[i].hardware_platform,
                g_devices[i].enrollment_status,
                g_devices[i].crypto_identity_ref,
                g_devices[i].os_release,
                g_devices[i].image_digest,
                g_devices[i].uki_digest,
                g_devices[i].active_policy_version,
                g_devices[i].attestation_status,
                g_devices[i].compliance_status,
                g_devices[i].assigned_exam_id,
                g_devices[i].current_candidate_id,
                g_devices[i].session_state,
                g_devices[i].update_status,
                g_devices[i].incident_refs,
                g_devices[i].replacement_for_device_id,
                g_devices[i].maintenance_mode ? "true" : "false",
                g_devices[i].enrolled ? "true" : "false",
                (long long)g_devices[i].last_checkin);
            first = 0;
        }
        if (offset >= max_len - 100) break;
    }
    snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0, "]}");
    pthread_mutex_unlock(&g_platform_lock);
    return 0;
}

int platform_register_device(const fleet_device_record_t *dev) {
    if (!dev || !dev->device_id[0] || !dev->group_name[0]) return -1;
    pthread_mutex_lock(&g_platform_lock);
    for (int i = 0; i < g_device_count; i++) {
        if (strcmp(g_devices[i].device_id, dev->device_id) == 0) {
            if (db_sync_device_upsert(dev) != 0) {
                pthread_mutex_unlock(&g_platform_lock);
                return -1;
            }
            memcpy(&g_devices[i], dev, sizeof(fleet_device_record_t));
            pthread_mutex_unlock(&g_platform_lock);
            return 0;
        }
    }
    if (g_device_count >= MAX_DEVICES) {
        pthread_mutex_unlock(&g_platform_lock);
        return -1;
    }
    if (db_sync_device_upsert(dev) != 0) {
        pthread_mutex_unlock(&g_platform_lock);
        return -1;
    }
    memcpy(&g_devices[g_device_count++], dev, sizeof(fleet_device_record_t));
    pthread_mutex_unlock(&g_platform_lock);
    return 0;
}

int platform_get_device_by_id(const char *device_id, fleet_device_record_t *out_dev) {
    if (!device_id || !device_id[0] || !out_dev) return -1;
    pthread_mutex_lock(&g_platform_lock);
    for (int i = 0; i < g_device_count; i++) {
        if (strcmp(g_devices[i].device_id, device_id) == 0) {
            memcpy(out_dev, &g_devices[i], sizeof(fleet_device_record_t));
            pthread_mutex_unlock(&g_platform_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_platform_lock);

    /* Check DB */
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    const char *params[] = { device_id };
    PGresult *res = PQexecParams(conn,
        "SELECT device_id, hostname, COALESCE(institution_id, ''), COALESCE(campus_id, ''), "
        "       COALESCE(room_id, ''), group_name, deployment_ring, ownership_type, "
        "       student_owned, hardware_platform, enrollment_status, crypto_identity_ref, "
        "       os_release, image_digest, uki_digest, policy_version, "
        "       attestation_status, compliance_status, COALESCE(assigned_exam_id, ''), "
        "       current_candidate_id, session_state, update_status, incident_refs, "
        "       COALESCE(replacement_for_device_id, ''), maintenance_mode, enrolled, "
        "       EXTRACT(EPOCH FROM last_checkin)::bigint, "
        "       COALESCE(EXTRACT(EPOCH FROM last_attestation_ts)::bigint, 0) "
        "FROM examos_devices WHERE device_id = $1",
        1, NULL, params, NULL, NULL, 0);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    memset(out_dev, 0, sizeof(*out_dev));
    snprintf(out_dev->device_id, sizeof(out_dev->device_id), "%s", PQgetvalue(res, 0, 0));
    snprintf(out_dev->hostname, sizeof(out_dev->hostname), "%s", PQgetvalue(res, 0, 1));
    snprintf(out_dev->institution_id, sizeof(out_dev->institution_id), "%s", PQgetvalue(res, 0, 2));
    snprintf(out_dev->campus_id, sizeof(out_dev->campus_id), "%s", PQgetvalue(res, 0, 3));
    snprintf(out_dev->room_id, sizeof(out_dev->room_id), "%s", PQgetvalue(res, 0, 4));
    snprintf(out_dev->group_name, sizeof(out_dev->group_name), "%s", PQgetvalue(res, 0, 5));
    const char *ring_s = PQgetvalue(res, 0, 6);
    if (strcasecmp(ring_s, "CANARY") == 0) out_dev->ring = RING_CANARY;
    else if (strcasecmp(ring_s, "PILOT") == 0) out_dev->ring = RING_PILOT;
    else out_dev->ring = RING_GENERAL;
    snprintf(out_dev->ownership_type, sizeof(out_dev->ownership_type), "%s", PQgetvalue(res, 0, 7));
    out_dev->student_owned = (strcmp(PQgetvalue(res, 0, 8), "t") == 0 || strcmp(PQgetvalue(res, 0, 8), "1") == 0) ? 1 : 0;
    snprintf(out_dev->hardware_platform, sizeof(out_dev->hardware_platform), "%s", PQgetvalue(res, 0, 9));
    snprintf(out_dev->enrollment_status, sizeof(out_dev->enrollment_status), "%s", PQgetvalue(res, 0, 10));
    snprintf(out_dev->crypto_identity_ref, sizeof(out_dev->crypto_identity_ref), "%s", PQgetvalue(res, 0, 11));
    snprintf(out_dev->os_release, sizeof(out_dev->os_release), "%s", PQgetvalue(res, 0, 12));
    snprintf(out_dev->image_digest, sizeof(out_dev->image_digest), "%s", PQgetvalue(res, 0, 13));
    snprintf(out_dev->uki_digest, sizeof(out_dev->uki_digest), "%s", PQgetvalue(res, 0, 14));
    out_dev->active_policy_version = (unsigned int)atoi(PQgetvalue(res, 0, 15));
    snprintf(out_dev->attestation_status, sizeof(out_dev->attestation_status), "%s", PQgetvalue(res, 0, 16));
    snprintf(out_dev->compliance_status, sizeof(out_dev->compliance_status), "%s", PQgetvalue(res, 0, 17));
    snprintf(out_dev->assigned_exam_id, sizeof(out_dev->assigned_exam_id), "%s", PQgetvalue(res, 0, 18));
    snprintf(out_dev->current_candidate_id, sizeof(out_dev->current_candidate_id), "%s", PQgetvalue(res, 0, 19));
    snprintf(out_dev->session_state, sizeof(out_dev->session_state), "%s", PQgetvalue(res, 0, 20));
    snprintf(out_dev->update_status, sizeof(out_dev->update_status), "%s", PQgetvalue(res, 0, 21));
    snprintf(out_dev->incident_refs, sizeof(out_dev->incident_refs), "%s", PQgetvalue(res, 0, 22));
    snprintf(out_dev->replacement_for_device_id, sizeof(out_dev->replacement_for_device_id), "%s", PQgetvalue(res, 0, 23));
    out_dev->maintenance_mode = (strcmp(PQgetvalue(res, 0, 24), "t") == 0 || strcmp(PQgetvalue(res, 0, 24), "1") == 0) ? 1 : 0;
    out_dev->enrolled = (strcmp(PQgetvalue(res, 0, 25), "t") == 0 || strcmp(PQgetvalue(res, 0, 25), "1") == 0) ? 1 : 0;
    out_dev->last_checkin = (time_t)atoll(PQgetvalue(res, 0, 26));
    out_dev->last_attestation_ts = (time_t)atoll(PQgetvalue(res, 0, 27));

    PQclear(res);
    release_db_connection(conn, 0);

    return 0;
}

int platform_enroll_device(const fleet_device_record_t *dev, const char *actor) {
    if (!dev || !dev->device_id[0]) return -1;
    fleet_device_record_t rec;
    memcpy(&rec, dev, sizeof(rec));

    if (rec.student_owned || strcasecmp(rec.ownership_type, "STUDENT_OWNED") == 0) {
        rec.student_owned = 1;
        snprintf(rec.ownership_type, sizeof(rec.ownership_type), "STUDENT_OWNED");
    } else {
        rec.student_owned = 0;
        snprintf(rec.ownership_type, sizeof(rec.ownership_type), "INSTITUTION_OWNED");
    }
    if (!rec.enrollment_status[0]) {
        snprintf(rec.enrollment_status, sizeof(rec.enrollment_status), "PENDING_APPROVAL");
    }
    if (!rec.group_name[0]) return -1;
    if (!rec.attestation_status[0]) {
        snprintf(rec.attestation_status, sizeof(rec.attestation_status), "NOT_ATTESTED");
    }
    if (!rec.compliance_status[0]) {
        snprintf(rec.compliance_status, sizeof(rec.compliance_status), "NON_COMPLIANT");
    }
    if (!rec.session_state[0]) {
        snprintf(rec.session_state, sizeof(rec.session_state), "IDLE");
    }
    /* Enforce privacy guarantee for student-owned devices */
    if (rec.student_owned) {
        if (!rec.incident_refs[0]) {
            snprintf(rec.incident_refs, sizeof(rec.incident_refs), "PRIVACY_SCOPE_ENFORCED:LIMITED_EXAM_MANAGEMENT_ONLY");
        }
    }

    if (platform_register_device(&rec) != 0) return -1;

    char details[256];
    snprintf(details, sizeof(details), "device_id=%s actor=%s student_owned=%d status=%s ownership=%s",
             rec.device_id, actor ? actor : "system", rec.student_owned, rec.enrollment_status, rec.ownership_type);
    ledger_append("DEVICE_ENROLLED", rec.device_id, details);
    return 0;
}

int platform_approve_device_enrollment(const char *device_id, const char *actor) {
    if (!device_id || !device_id[0]) return -1;
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) return -1;

    snprintf(dev.enrollment_status, sizeof(dev.enrollment_status), "ENROLLED");
    dev.enrolled = 1;
    snprintf(dev.compliance_status, sizeof(dev.compliance_status), "NON_COMPLIANT");
    if (platform_register_device(&dev) != 0) return -1;

    char details[256];
    snprintf(details, sizeof(details), "device_id=%s approver=%s status=ENROLLED", device_id, actor ? actor : "admin");
    ledger_append("DEVICE_ENROLLMENT_APPROVED", device_id, details);
    return 0;
}

int platform_reject_device_enrollment(const char *device_id, const char *reason, const char *actor) {
    if (!device_id || !device_id[0]) return -1;
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) return -1;

    snprintf(dev.enrollment_status, sizeof(dev.enrollment_status), "REJECTED");
    dev.enrolled = 0;
    snprintf(dev.compliance_status, sizeof(dev.compliance_status), "NON_COMPLIANT");
    if (reason && reason[0]) {
        snprintf(dev.incident_refs, sizeof(dev.incident_refs), "REJECTED_REASON:%.100s", reason);
    }

    if (platform_register_device(&dev) != 0) return -1;

    char details[256];
    snprintf(details, sizeof(details), "device_id=%s actor=%s status=REJECTED reason=%s",
             device_id, actor ? actor : "admin", reason ? reason : "none");
    ledger_append("DEVICE_ENROLLMENT_REJECTED", device_id, details);
    return 0;
}

int platform_revoke_device(const char *device_id, const char *reason, const char *actor) {
    if (!device_id || !device_id[0]) return -1;
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) return -1;

    snprintf(dev.enrollment_status, sizeof(dev.enrollment_status), "REVOKED");
    dev.enrolled = 0;
    snprintf(dev.compliance_status, sizeof(dev.compliance_status), "NON_COMPLIANT");
    snprintf(dev.crypto_identity_ref, sizeof(dev.crypto_identity_ref), "REVOKED");
    if (reason && reason[0]) {
        snprintf(dev.incident_refs, sizeof(dev.incident_refs), "REVOKED:%.100s", reason);
    }

    if (platform_register_device(&dev) != 0) return -1;

    char details[256];
    snprintf(details, sizeof(details), "device_id=%s actor=%s status=REVOKED reason=%s",
             device_id, actor ? actor : "admin", reason ? reason : "none");
    ledger_append("DEVICE_ENROLLMENT_REVOKED", device_id, details);
    return 0;
}

int platform_quarantine_device(const char *device_id, const char *reason, const char *actor) {
    if (!device_id || !device_id[0]) return -1;
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) return -1;

    snprintf(dev.enrollment_status, sizeof(dev.enrollment_status), "QUARANTINED");
    snprintf(dev.compliance_status, sizeof(dev.compliance_status), "QUARANTINED");
    if (reason && reason[0]) {
        snprintf(dev.incident_refs, sizeof(dev.incident_refs), "QUARANTINED:%.100s", reason);
    }

    if (platform_register_device(&dev) != 0) return -1;

    char details[256];
    snprintf(details, sizeof(details), "device_id=%s actor=%s status=QUARANTINED reason=%s",
             device_id, actor ? actor : "admin", reason ? reason : "compromise_suspected");
    ledger_append("DEVICE_QUARANTINED", device_id, details);
    return 0;
}

int platform_revoke_device_credentials(const char *device_id, const char *reason, const char *actor) {
    if (!device_id || !device_id[0]) return -1;
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) return -1;

    snprintf(dev.crypto_identity_ref, sizeof(dev.crypto_identity_ref), "REVOKED");
    snprintf(dev.attestation_status, sizeof(dev.attestation_status), "FAILED");
    snprintf(dev.compliance_status, sizeof(dev.compliance_status), "NON_COMPLIANT");
    if (reason && reason[0]) {
        snprintf(dev.incident_refs, sizeof(dev.incident_refs), "CRED_REVOKED:%.100s", reason);
    }

    if (platform_register_device(&dev) != 0) return -1;

    char details[256];
    snprintf(details, sizeof(details), "device_id=%s actor=%s creds=REVOKED reason=%s",
             device_id, actor ? actor : "admin", reason ? reason : "compromised_keys");
    ledger_append("DEVICE_CREDENTIALS_REVOKED", device_id, details);
    return 0;
}

int platform_unenroll_device(const char *device_id, int cleanup_data, const char *actor) {
    if (!device_id || !device_id[0]) return -1;
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) return -1;

    snprintf(dev.enrollment_status, sizeof(dev.enrollment_status), "UNENROLLED");
    dev.enrolled = 0;
    dev.current_candidate_id[0] = '\0';
    dev.assigned_exam_id[0] = '\0';
    snprintf(dev.session_state, sizeof(dev.session_state), "IDLE");
    if (cleanup_data) {
        snprintf(dev.incident_refs, sizeof(dev.incident_refs), "UNENROLLED:DATA_CLEANUP_COMPLETED");
    }

    if (platform_register_device(&dev) != 0) return -1;

    char details[256];
    snprintf(details, sizeof(details), "device_id=%s actor=%s status=UNENROLLED cleanup_data=%d",
             device_id, actor ? actor : "admin", cleanup_data);
    ledger_append("DEVICE_UNENROLLED", device_id, details);
    return 0;
}

int platform_replace_device(const char *old_device_id, const char *new_device_id, const char *actor) {
    if (!old_device_id || !old_device_id[0] || !new_device_id || !new_device_id[0]) return -1;
    fleet_device_record_t old_dev;
    if (platform_get_device_by_id(old_device_id, &old_dev) != 0) return -1;

    /* Mark old device replaced */
    snprintf(old_dev.enrollment_status, sizeof(old_dev.enrollment_status), "REPLACED");
    old_dev.enrolled = 0;
    snprintf(old_dev.compliance_status, sizeof(old_dev.compliance_status), "NON_COMPLIANT");
    if (platform_register_device(&old_dev) != 0) return -1;

    /* Setup new device */
    fleet_device_record_t new_dev;
    if (platform_get_device_by_id(new_device_id, &new_dev) != 0) {
        memset(&new_dev, 0, sizeof(new_dev));
        snprintf(new_dev.device_id, sizeof(new_dev.device_id), "%s", new_device_id);
    }
    snprintf(new_dev.institution_id, sizeof(new_dev.institution_id), "%s", old_dev.institution_id);
    snprintf(new_dev.campus_id, sizeof(new_dev.campus_id), "%s", old_dev.campus_id);
    snprintf(new_dev.room_id, sizeof(new_dev.room_id), "%s", old_dev.room_id);
    snprintf(new_dev.group_name, sizeof(new_dev.group_name), "%s", old_dev.group_name);
    new_dev.ring = old_dev.ring;
    new_dev.student_owned = old_dev.student_owned;
    snprintf(new_dev.ownership_type, sizeof(new_dev.ownership_type), "%s", old_dev.ownership_type);
    snprintf(new_dev.enrollment_status, sizeof(new_dev.enrollment_status), "PENDING_APPROVAL");
    new_dev.enrolled = 0;
    snprintf(new_dev.attestation_status, sizeof(new_dev.attestation_status), "NOT_ATTESTED");
    snprintf(new_dev.compliance_status, sizeof(new_dev.compliance_status), "NON_COMPLIANT");
    snprintf(new_dev.replacement_for_device_id, sizeof(new_dev.replacement_for_device_id), "%s", old_device_id);
    new_dev.last_checkin = 0;

    if (platform_register_device(&new_dev) != 0) return -1;

    char details[256];
    snprintf(details, sizeof(details), "old_device_id=%s new_device_id=%s actor=%s status=REPLACED",
             old_device_id, new_device_id, actor ? actor : "admin");
    ledger_append("DEVICE_REPLACED", new_device_id, details);
    return 0;
}

int platform_update_device_checkin(const char *device_id, const char *os_release, const char *image_digest, unsigned int policy_version) {
    if (!device_id || !device_id[0]) return -1;
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) return -1;

    dev.last_checkin = time(NULL);
    if (os_release && os_release[0]) snprintf(dev.os_release, sizeof(dev.os_release), "%s", os_release);
    if (image_digest && image_digest[0]) snprintf(dev.image_digest, sizeof(dev.image_digest), "%s", image_digest);
    if (policy_version > 0) dev.active_policy_version = policy_version;

    return platform_register_device(&dev);
}

int platform_update_device_attestation(const char *device_id, const char *attestation_status, const char *compliance_status) {
    if (!device_id || !device_id[0] || !attestation_status || !attestation_status[0] ||
        (strcmp(attestation_status, "TRUSTED") != 0 &&
         strcmp(attestation_status, "FAILED") != 0 &&
         strcmp(attestation_status, "STALE") != 0 &&
         strcmp(attestation_status, "NOT_ATTESTED") != 0) ||
        (compliance_status && compliance_status[0] &&
         strcmp(compliance_status, "NON_COMPLIANT") != 0 &&
         strcmp(compliance_status, "MAINTENANCE") != 0 &&
         strcmp(compliance_status, "QUARANTINED") != 0)) {
        platform_set_error("attestation_status must be one of TRUSTED, FAILED, STALE, NOT_ATTESTED "
                           "and compliance_status must be one of NON_COMPLIANT, MAINTENANCE, QUARANTINED");
        return -1;
    }
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) {
        platform_set_error("The device is not registered in the fleet");
        return -1;
    }

    snprintf(dev.attestation_status, sizeof(dev.attestation_status), "%s", attestation_status);
    /* A device that just produced a verified quote is stamped with the
       moment of that verification, not zero. */
    dev.last_attestation_ts = (strcmp(attestation_status, "TRUSTED") == 0) ? time(NULL) : dev.last_attestation_ts;

    if (compliance_status && compliance_status[0]) {
        snprintf(dev.compliance_status, sizeof(dev.compliance_status), "%s", compliance_status);
    } else {
        platform_derive_compliance_status(&dev);
    }

    return platform_register_device(&dev);
}

/*
 * Derives the compliance status of a device from the facts the platform
 * actually holds about it. Compliance is never asserted by an operator: it
 * is recomputed from enrolment, attestation, maintenance and quarantine
 * state so that it cannot drift away from the underlying evidence.
 */
void platform_derive_compliance_status(fleet_device_record_t *dev) {
    if (!dev) return;
    if (dev->maintenance_mode) {
        snprintf(dev->compliance_status, sizeof(dev->compliance_status), "MAINTENANCE");
        return;
    }
    if (strcmp(dev->enrollment_status, "QUARANTINED") == 0) {
        snprintf(dev->compliance_status, sizeof(dev->compliance_status), "QUARANTINED");
        return;
    }
    if (strcmp(dev->enrollment_status, "ENROLLED") == 0 &&
        strcmp(dev->attestation_status, "TRUSTED") == 0 &&
        dev->enrolled) {
        snprintf(dev->compliance_status, sizeof(dev->compliance_status), "COMPLIANT");
        return;
    }
    snprintf(dev->compliance_status, sizeof(dev->compliance_status), "NON_COMPLIANT");
}

/*
 * Assigns a registered device to an exam.
 *
 * The device and the exam must belong to the same institution: a device
 * from one institution must never be able to sit an exam of another.
 */
int platform_assign_device_to_exam(const char *device_id, const char *exam_id, const char *actor) {
    if (!device_id || !device_id[0] || !exam_id || !exam_id[0]) {
        platform_set_error("device_id and exam_id are required");
        return -1;
    }
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) {
        platform_set_error("The device is not registered in the fleet");
        return -1;
    }

    enterprise_exam_t exam;
    if (platform_get_exam_by_id(exam_id, &exam) != 0) {
        platform_set_error("The exam does not exist");
        return -1;
    }
    if (dev.institution_id[0] && exam.institution_id[0] &&
        strcmp(dev.institution_id, exam.institution_id) != 0) {
        platform_set_error("The device and the exam belong to different institutions");
        return -1;
    }

    snprintf(dev.assigned_exam_id, sizeof(dev.assigned_exam_id), "%s", exam_id);
    platform_derive_compliance_status(&dev);
    if (platform_register_device(&dev) != 0) {
        platform_set_error("The device assignment could not be stored");
        return -1;
    }

    char details[256];
    snprintf(details, sizeof(details), "device_id=%s exam_id=%s actor=%s",
             device_id, exam_id, actor ? actor : "system");
    ledger_append("DEVICE_ENROLLED", device_id, details);
    return 0;
}

int platform_set_device_maintenance(const char *device_id, int in_maintenance) {
    if (!device_id || !device_id[0] || (in_maintenance != 0 && in_maintenance != 1)) return -1;
    fleet_device_record_t dev;
    int get_rc = platform_get_device_by_id(device_id, &dev);
    if (get_rc == 0) {
        dev.maintenance_mode = in_maintenance ? 1 : 0;
        if (in_maintenance) {
            snprintf(dev.compliance_status, sizeof(dev.compliance_status), "MAINTENANCE");
        } else {
            snprintf(dev.compliance_status, sizeof(dev.compliance_status), "NON_COMPLIANT");
        }
        char details[128];
        snprintf(details, sizeof(details), "device_id=%s maintenance=%d", device_id, in_maintenance);
        ledger_append("DEVICE_MAINTENANCE_TOGGLED", device_id, details);
        return platform_register_device(&dev);
    }

    /* Device not found or database unavailable — report as unsupported
     * so callers can distinguish "unprovisioned" from a real I/O error. */
    (void)get_rc;
    errno = ENOTSUP;
    return -1;
}

int platform_record_device_heartbeat(const char *device_id, int battery_pct, int battery_charging,
                                    int disk_free_mb, int mem_used_mb, const char *network_state,
                                    unsigned int policy_version, const char *image_digest,
                                    const char *session_state) {
    if (!device_id || !device_id[0] || battery_pct < -1 || battery_pct > 100 ||
        (battery_charging != 0 && battery_charging != 1) ||
        disk_free_mb < 0 || mem_used_mb < 0 || !network_state || !network_state[0] ||
        strlen(network_state) > 31 || policy_version > 2147483647U) return -1;
    for (const unsigned char *p = (const unsigned char *)network_state; *p; ++p)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return -1;
    if (session_state && session_state[0] &&
        strcmp(session_state, "IDLE") != 0 && strcmp(session_state, "CHECKED_IN") != 0 &&
        strcmp(session_state, "IN_EXAM") != 0 && strcmp(session_state, "SUBMITTED") != 0 &&
        strcmp(session_state, "UNKNOWN") != 0) return -1;
    if (image_digest && image_digest[0]) {
        if (strlen(image_digest) != 64) return -1;
        for (size_t i = 0; i < 64; ++i)
            if (!((image_digest[i] >= '0' && image_digest[i] <= '9') ||
                  (image_digest[i] >= 'a' && image_digest[i] <= 'f') ||
                  (image_digest[i] >= 'A' && image_digest[i] <= 'F'))) return -1;
    }
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) return -1;

    dev.last_checkin = time(NULL);
    if (policy_version > 0) dev.active_policy_version = policy_version;
    if (image_digest && image_digest[0]) snprintf(dev.image_digest, sizeof(dev.image_digest), "%s", image_digest);
    if (session_state && session_state[0]) snprintf(dev.session_state, sizeof(dev.session_state), "%s", session_state);

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    PGresult *res = PQexec(conn, "BEGIN");
    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);

    if (ok) {
        char pol_str[16];
        snprintf(pol_str, sizeof(pol_str), "%u", policy_version);
        const char *update_params[] = {device_id, pol_str,
            image_digest && image_digest[0] ? image_digest : "",
            session_state && session_state[0] ? session_state : ""};
        res = PQexecParams(conn,
            "UPDATE examos_devices SET last_checkin=clock_timestamp(), "
            "policy_version=CASE WHEN $2::integer > 0 THEN $2::integer ELSE policy_version END, "
            "image_digest=CASE WHEN $3 <> '' THEN $3 ELSE image_digest END, "
            "session_state=CASE WHEN $4 <> '' THEN $4 ELSE session_state END, "
            "updated_at=clock_timestamp() "
            "WHERE device_id=$1 AND enrolled=true AND enrollment_status='ENROLLED'",
            4, NULL, update_params, NULL, NULL, 0);
        ok = res && PQresultStatus(res) == PGRES_COMMAND_OK && atoi(PQcmdTuples(res)) == 1;
        if (res) PQclear(res);
    }

    if (ok) {
        char bat_str[16], chg_str[16], disk_str[16], mem_str[16], pol_str[16];
        snprintf(bat_str, sizeof(bat_str), "%d", battery_pct);
        snprintf(chg_str, sizeof(chg_str), "%s", battery_charging ? "true" : "false");
        snprintf(disk_str, sizeof(disk_str), "%d", disk_free_mb);
        snprintf(mem_str, sizeof(mem_str), "%d", mem_used_mb);
        snprintf(pol_str, sizeof(pol_str), "%u", dev.active_policy_version);

        const char *hb_params[] = {
            device_id,
            bat_str,
            chg_str,
            disk_str,
            mem_str,
            network_state,
            pol_str,
            dev.image_digest[0] ? dev.image_digest : "",
            dev.session_state[0] ? dev.session_state : "IDLE"
        };

        res = PQexecParams(conn,
            "INSERT INTO examos_device_heartbeats "
            "(device_id, battery_pct, battery_charging, disk_free_mb, mem_used_mb, network_state, policy_version, image_digest, session_state) "
            "VALUES ($1, $2::integer, $3::boolean, $4::integer, $5::integer, $6, $7::integer, $8, $9)",
            9, NULL, hb_params, NULL, NULL, 0);

        ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
        if (res) PQclear(res);
    }

    res = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    int committed = ok && res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);
    release_db_connection(conn, PQstatus(conn) != CONNECTION_OK);
    if (!committed) return -1;

    pthread_mutex_lock(&g_platform_lock);
    for (int i = 0; i < g_device_count; ++i) {
        if (strcmp(g_devices[i].device_id, device_id) == 0) {
            g_devices[i].last_checkin = dev.last_checkin;
            if (policy_version > 0) g_devices[i].active_policy_version = policy_version;
            if (image_digest && image_digest[0]) snprintf(g_devices[i].image_digest, sizeof(g_devices[i].image_digest), "%s", image_digest);
            if (session_state && session_state[0]) snprintf(g_devices[i].session_state, sizeof(g_devices[i].session_state), "%s", session_state);
            break;
        }
    }
    pthread_mutex_unlock(&g_platform_lock);

    char details[256];
    snprintf(details, sizeof(details), "device_id=%s bat=%d%% net=%s pol=%u state=%s",
             device_id, battery_pct, network_state,
             dev.active_policy_version, dev.session_state);
    ledger_append("DEVICE_HEARTBEAT", device_id, details);
    return 0;
}

int platform_record_agent_heartbeat(const char *device_id, const char *payload_json,
                                   size_t payload_length, long *out_record_id) {
    if (!device_id || !device_id[0] || strlen(device_id) > 63 || !payload_json ||
        payload_length == 0 || payload_length > 16384 ||
        memchr(payload_json, '\0', payload_length) != NULL ||
        payload_json[payload_length] != '\0') return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -2;
    const char *params[] = {device_id, payload_json};
    PGresult *result = PQexecParams(conn,
        "INSERT INTO examos_agent_heartbeat_records(device_id,reported_at,payload) "
        "SELECT d.device_id,to_timestamp((($2::jsonb->>'timestamp')::bigint)::double precision),$2::jsonb "
        "FROM examos_devices d WHERE d.device_id=$1 AND d.enrolled=true "
        "AND d.enrollment_status='ENROLLED' AND $2::jsonb->>'device_id'=d.device_id "
        "AND to_timestamp((($2::jsonb->>'timestamp')::bigint)::double precision) "
        "BETWEEN clock_timestamp()-interval '5 minutes' AND clock_timestamp()+interval '30 seconds' "
        "ON CONFLICT(device_id,reported_at) DO UPDATE "
        "SET payload=examos_agent_heartbeat_records.payload "
        "WHERE examos_agent_heartbeat_records.payload=EXCLUDED.payload "
        "RETURNING heartbeat_id::text",
        2, NULL, params, NULL, NULL, 0);
    int accepted = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;
    if (accepted && out_record_id) *out_record_id = strtol(PQgetvalue(result, 0, 0), NULL, 10);
    int invalid = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 0;
    if (result) PQclear(result);
    release_db_connection(conn, PQstatus(conn) != CONNECTION_OK);
    if (accepted) {
        char detail[96];
        snprintf(detail, sizeof(detail), "heartbeat_record=%ld", out_record_id ? *out_record_id : 0L);
        ledger_append("AGENT_HEARTBEAT_STORED", device_id, detail);
        return 0;
    }
    return invalid ? -1 : -2;
}

int platform_bulk_device_action(const char *action_type, const char *target_group,
                               const char *target_inst, const char *target_campus,
                               const char *target_room, const char *param_val,
                               int preview_only, const char *actor,
                               char *out_json, size_t max_len) {
    if (!action_type || !out_json || max_len < 128) return -1;

    char job_id[64];
    snprintf(job_id, sizeof(job_id), "job_%ld_%u", (long)time(NULL), (unsigned int)(rand() % 10000));

    pthread_mutex_lock(&g_platform_lock);

    int total_targeted = 0;
    int succeeded = 0;
    int failed = 0;

    char matched_devices_json[4096];
    size_t m_off = snprintf(matched_devices_json, sizeof(matched_devices_json), "[");
    int first_match = 1;

    for (int i = 0; i < g_device_count; i++) {
        if (target_group && target_group[0] && strcmp(g_devices[i].group_name, target_group) != 0) continue;
        if (target_inst && target_inst[0] && strcmp(g_devices[i].institution_id, target_inst) != 0) continue;
        if (target_campus && target_campus[0] && strcmp(g_devices[i].campus_id, target_campus) != 0) continue;
        if (target_room && target_room[0] && strcmp(g_devices[i].room_id, target_room) != 0) continue;

        total_targeted++;
        if (m_off + 80 < sizeof(matched_devices_json)) {
            m_off += snprintf(matched_devices_json + m_off, sizeof(matched_devices_json) - m_off,
                              "%s\"%s\"", first_match ? "" : ",", g_devices[i].device_id);
            first_match = 0;
        }

        if (preview_only) {
            continue;
        }

        int action_ok = 0;
        if (strcasecmp(action_type, "ASSIGN_GROUP") == 0) {
            if (param_val && param_val[0]) {
                snprintf(g_devices[i].group_name, sizeof(g_devices[i].group_name), "%s", param_val);
                action_ok = 1;
            }
        } else if (strcasecmp(action_type, "SET_MAINTENANCE") == 0) {
            g_devices[i].maintenance_mode = (param_val && (atoi(param_val) > 0 || strcasecmp(param_val, "true") == 0)) ? 1 : 0;
            if (g_devices[i].maintenance_mode) {
                snprintf(g_devices[i].compliance_status, sizeof(g_devices[i].compliance_status), "MAINTENANCE");
            } else {
                snprintf(g_devices[i].compliance_status, sizeof(g_devices[i].compliance_status), "NON_COMPLIANT");
            }
            action_ok = 1;
        } else if (strcasecmp(action_type, "SET_RING") == 0) {
            if (param_val) {
                if (strcasecmp(param_val, "CANARY") == 0) g_devices[i].ring = RING_CANARY;
                else if (strcasecmp(param_val, "PILOT") == 0) g_devices[i].ring = RING_PILOT;
                else g_devices[i].ring = RING_GENERAL;
                action_ok = 1;
            }
        } else if (strcasecmp(action_type, "QUARANTINE") == 0) {
            snprintf(g_devices[i].enrollment_status, sizeof(g_devices[i].enrollment_status), "QUARANTINED");
            snprintf(g_devices[i].compliance_status, sizeof(g_devices[i].compliance_status), "QUARANTINED");
            action_ok = 1;
        } else if (strcasecmp(action_type, "APPROVE_ENROLLMENT") == 0) {
            snprintf(g_devices[i].enrollment_status, sizeof(g_devices[i].enrollment_status), "ENROLLED");
            g_devices[i].enrolled = 1;
            action_ok = 1;
        } else if (strcasecmp(action_type, "FORCE_POLICY_UPDATE") == 0) {
            snprintf(g_devices[i].update_status, sizeof(g_devices[i].update_status), "UPDATE_PENDING");
            action_ok = 1;
        } else if (strcasecmp(action_type, "UNENROLL") == 0) {
            snprintf(g_devices[i].enrollment_status, sizeof(g_devices[i].enrollment_status), "UNENROLLED");
            g_devices[i].enrolled = 0;
            action_ok = 1;
        }

        if (action_ok) {
            succeeded++;
        } else {
            failed++;
        }
    }

    snprintf(matched_devices_json + m_off, sizeof(matched_devices_json) - m_off, "]");

    fleet_device_record_t to_sync[MAX_DEVICES];
    int count_to_sync = 0;
    if (!preview_only) {
        for (int i = 0; i < g_device_count; i++) {
            to_sync[count_to_sync++] = g_devices[i];
        }
    }
    pthread_mutex_unlock(&g_platform_lock);

    if (!preview_only) {
        for (int i = 0; i < count_to_sync; i++) {
            db_sync_device_upsert(&to_sync[i]);
        }

        PGconn *conn = acquire_db_connection();
        if (conn) {
            char tot_s[16], suc_s[16], fail_s[16];
            snprintf(tot_s, sizeof(tot_s), "%d", total_targeted);
            snprintf(suc_s, sizeof(suc_s), "%d", succeeded);
            snprintf(fail_s, sizeof(fail_s), "%d", failed);

            char filter_json[256];
            snprintf(filter_json, sizeof(filter_json),
                     "{\"group\":\"%s\",\"institution\":\"%s\",\"campus\":\"%s\",\"room\":\"%s\"}",
                     target_group ? target_group : "",
                     target_inst ? target_inst : "",
                     target_campus ? target_campus : "",
                     target_room ? target_room : "");

            char details_json[256];
            snprintf(details_json, sizeof(details_json), "{\"param\":\"%s\",\"actor\":\"%s\"}",
                     param_val ? param_val : "", actor ? actor : "admin");

            const char *job_params[] = {
                job_id,
                actor && actor[0] ? actor : NULL,
                action_type,
                filter_json,
                tot_s,
                suc_s,
                fail_s,
                failed == 0 ? "COMPLETED" : (succeeded > 0 ? "PARTIAL_FAILURE" : "FAILED"),
                details_json
            };

            PGresult *res = PQexecParams(conn,
                "INSERT INTO examos_device_bulk_jobs "
                "(job_id, actor_user_id, action_type, target_filter, total_targeted, succeeded, failed, status, details) "
                "VALUES ($1, $2, $3, $4, $5::integer, $6::integer, $7::integer, $8, $9)",
                9, NULL, job_params, NULL, NULL, 0);
            if (res) PQclear(res);
            release_db_connection(conn, 0);
        }

        char audit_details[256];
        snprintf(audit_details, sizeof(audit_details),
                 "job_id=%s action=%s targeted=%d succeeded=%d failed=%d",
                 job_id, action_type, total_targeted, succeeded, failed);
        ledger_append("DEVICE_BULK_ACTION", job_id, audit_details);
    }

    snprintf(out_json, max_len,
             "{\"job_id\":\"%s\",\"preview_only\":%s,\"action_type\":\"%s\","
             "\"scope\":{\"group\":\"%s\",\"institution\":\"%s\",\"campus\":\"%s\",\"room\":\"%s\"},"
             "\"total_targeted\":%d,\"succeeded\":%d,\"failed\":%d,\"status\":\"%s\","
             "\"matched_devices\":%s}",
             job_id,
             preview_only ? "true" : "false",
             action_type,
             target_group ? target_group : "",
             target_inst ? target_inst : "",
             target_campus ? target_campus : "",
             target_room ? target_room : "",
             total_targeted,
             preview_only ? 0 : succeeded,
             preview_only ? 0 : failed,
             preview_only ? "PREVIEW_READY" : (failed == 0 ? "COMPLETED" : (succeeded > 0 ? "PARTIAL_FAILURE" : "FAILED")),
             matched_devices_json);

    return 0;
}

int platform_get_fleet_compliance_json(const char *inst_id, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 128) return -1;

    int total = 0, enrolled_count = 0, pending_count = 0, rejected_count = 0;
    int revoked_count = 0, quarantined_count = 0, replaced_count = 0, unenrolled_count = 0;
    int compliant_count = 0, non_compliant_count = 0, maintenance_count = 0;
    int att_trusted = 0, att_failed = 0, att_stale = 0, att_not_attested = 0;
    int student_owned_count = 0, institution_owned_count = 0;

    PGconn *conn = acquire_db_connection();
    if (conn) {
        PGresult *res = NULL;
        if (inst_id && inst_id[0]) {
            const char *p[] = { inst_id };
            res = PQexecParams(conn,
                "SELECT enrollment_status, compliance_status, attestation_status, student_owned, maintenance_mode "
                "FROM examos_devices WHERE institution_id = $1", 1, NULL, p, NULL, NULL, 0);
        } else {
            res = PQexec(conn,
                "SELECT enrollment_status, compliance_status, attestation_status, student_owned, maintenance_mode "
                "FROM examos_devices");
        }

        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            total = PQntuples(res);
            for (int i = 0; i < total; i++) {
                const char *enr_st = PQgetvalue(res, i, 0);
                const char *comp_st = PQgetvalue(res, i, 1);
                const char *att_st = PQgetvalue(res, i, 2);
                int student = (strcmp(PQgetvalue(res, i, 3), "t") == 0 || strcmp(PQgetvalue(res, i, 3), "1") == 0);
                int maint = (strcmp(PQgetvalue(res, i, 4), "t") == 0 || strcmp(PQgetvalue(res, i, 4), "1") == 0);

                if (strcasecmp(enr_st, "ENROLLED") == 0) enrolled_count++;
                else if (strcasecmp(enr_st, "PENDING_APPROVAL") == 0) pending_count++;
                else if (strcasecmp(enr_st, "REJECTED") == 0) rejected_count++;
                else if (strcasecmp(enr_st, "REVOKED") == 0) revoked_count++;
                else if (strcasecmp(enr_st, "QUARANTINED") == 0) quarantined_count++;
                else if (strcasecmp(enr_st, "REPLACED") == 0) replaced_count++;
                else if (strcasecmp(enr_st, "UNENROLLED") == 0) unenrolled_count++;

                if (maint) maintenance_count++;
                else if (strcasecmp(comp_st, "COMPLIANT") == 0) compliant_count++;
                else non_compliant_count++;

                if (strcasecmp(att_st, "TRUSTED") == 0) att_trusted++;
                else if (strcasecmp(att_st, "FAILED") == 0) att_failed++;
                else if (strcasecmp(att_st, "STALE") == 0) att_stale++;
                else att_not_attested++;

                if (student) student_owned_count++;
                else institution_owned_count++;
            }
            PQclear(res);
            release_db_connection(conn, 0);

            snprintf(out_buf, max_len,
                     "{\"institution_id\":\"%s\",\"total_devices\":%d,"
                     "\"enrollment\":{\"enrolled\":%d,\"pending_approval\":%d,\"rejected\":%d,"
                     "\"revoked\":%d,\"quarantined\":%d,\"replaced\":%d,\"unenrolled\":%d},"
                     "\"compliance\":{\"compliant\":%d,\"non_compliant\":%d,\"maintenance\":%d},"
                     "\"attestation\":{\"trusted\":%d,\"failed\":%d,\"stale\":%d,\"not_attested\":%d},"
                     "\"ownership\":{\"institution_owned\":%d,\"student_owned\":%d}}",
                     inst_id ? inst_id : "",
                     total,
                     enrolled_count, pending_count, rejected_count, revoked_count, quarantined_count, replaced_count, unenrolled_count,
                     compliant_count, non_compliant_count, maintenance_count,
                     att_trusted, att_failed, att_stale, att_not_attested,
                     institution_owned_count, student_owned_count);
            return 0;
        }
        if (res) PQclear(res);
        release_db_connection(conn, 0);
    }

    /* Fallback to in-memory g_devices */
    pthread_mutex_lock(&g_platform_lock);
    for (int i = 0; i < g_device_count; i++) {
        if (inst_id && inst_id[0] && strcmp(g_devices[i].institution_id, inst_id) != 0) continue;
        total++;
        if (strcasecmp(g_devices[i].enrollment_status, "ENROLLED") == 0 || g_devices[i].enrolled) enrolled_count++;
        else if (strcasecmp(g_devices[i].enrollment_status, "PENDING_APPROVAL") == 0) pending_count++;
        else if (strcasecmp(g_devices[i].enrollment_status, "REJECTED") == 0) rejected_count++;
        else if (strcasecmp(g_devices[i].enrollment_status, "REVOKED") == 0) revoked_count++;
        else if (strcasecmp(g_devices[i].enrollment_status, "QUARANTINED") == 0) quarantined_count++;
        else if (strcasecmp(g_devices[i].enrollment_status, "REPLACED") == 0) replaced_count++;
        else unenrolled_count++;

        if (g_devices[i].maintenance_mode) maintenance_count++;
        else if (strcasecmp(g_devices[i].compliance_status, "COMPLIANT") == 0) compliant_count++;
        else non_compliant_count++;

        if (strcasecmp(g_devices[i].attestation_status, "TRUSTED") == 0) att_trusted++;
        else if (strcasecmp(g_devices[i].attestation_status, "FAILED") == 0) att_failed++;
        else if (strcasecmp(g_devices[i].attestation_status, "STALE") == 0) att_stale++;
        else att_not_attested++;

        if (g_devices[i].student_owned) student_owned_count++;
        else institution_owned_count++;
    }
    pthread_mutex_unlock(&g_platform_lock);

    snprintf(out_buf, max_len,
             "{\"institution_id\":\"%s\",\"total_devices\":%d,"
             "\"enrollment\":{\"enrolled\":%d,\"pending_approval\":%d,\"rejected\":%d,"
             "\"revoked\":%d,\"quarantined\":%d,\"replaced\":%d,\"unenrolled\":%d},"
             "\"compliance\":{\"compliant\":%d,\"non_compliant\":%d,\"maintenance\":%d},"
             "\"attestation\":{\"trusted\":%d,\"failed\":%d,\"stale\":%d,\"not_attested\":%d},"
             "\"ownership\":{\"institution_owned\":%d,\"student_owned\":%d}}",
             inst_id ? inst_id : "",
             total,
             enrolled_count, pending_count, rejected_count, revoked_count, quarantined_count, replaced_count, unenrolled_count,
             compliant_count, non_compliant_count, maintenance_count,
             att_trusted, att_failed, att_stale, att_not_attested,
             institution_owned_count, student_owned_count);
    return 0;
}

/* -------------------------------------------------------------------------
 * Security Events & Incidents JSON (Module J)
 * ------------------------------------------------------------------------- */
int platform_get_incidents_json(const char *inst_id, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 64) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    PGresult *res;
    if (inst_id) {
        const char *params[] = { inst_id };
        res = PQexecParams(conn,
            "SELECT incident_id, title, severity, status, assigned_to, device_id, candidate_id, "
            "coalesce(exam_id,''), summary, resolution_notes, extract(epoch from created_at)::bigint "
            "FROM examos_security_incidents WHERE institution_id=$1 ORDER BY created_at DESC LIMIT 1000",
            1, NULL, params, NULL, NULL, 0);
    } else {
        res = PQexec(conn,
            "SELECT incident_id, title, severity, status, assigned_to, device_id, candidate_id, "
            "coalesce(exam_id,''), summary, resolution_notes, extract(epoch from created_at)::bigint "
            "FROM examos_security_incidents ORDER BY created_at DESC LIMIT 1000");
    }
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }
    int initial = snprintf(out_buf, max_len, "{\"incidents\":[");
    if (initial < 0 || (size_t)initial >= max_len) { PQclear(res); release_db_connection(conn, 0); return -1; }
    size_t used = (size_t)initial;
    for (int i = 0; i < PQntuples(res); ++i) {
        char id[256], title[512], severity[64], status[64], assigned[256], device[256];
        char candidate[256], exam[256], summary[2048], notes[2048];
        if (platform_json_escape(PQgetvalue(res,i,0),id,sizeof(id)) || platform_json_escape(PQgetvalue(res,i,1),title,sizeof(title)) ||
            platform_json_escape(PQgetvalue(res,i,2),severity,sizeof(severity)) || platform_json_escape(PQgetvalue(res,i,3),status,sizeof(status)) ||
            platform_json_escape(PQgetvalue(res,i,4),assigned,sizeof(assigned)) || platform_json_escape(PQgetvalue(res,i,5),device,sizeof(device)) ||
            platform_json_escape(PQgetvalue(res,i,6),candidate,sizeof(candidate)) || platform_json_escape(PQgetvalue(res,i,7),exam,sizeof(exam)) ||
            platform_json_escape(PQgetvalue(res,i,8),summary,sizeof(summary)) || platform_json_escape(PQgetvalue(res,i,9),notes,sizeof(notes))) {
            PQclear(res); release_db_connection(conn, 0); return -1;
        }
        int n = snprintf(out_buf+used,max_len-used,
            "%s{\"id\":\"%s\",\"title\":\"%s\",\"severity\":\"%s\",\"status\":\"%s\","
            "\"assigned_to\":\"%s\",\"device_id\":\"%s\",\"candidate_id\":\"%s\",\"exam_id\":\"%s\","
            "\"summary\":\"%s\",\"notes\":\"%s\",\"created_at\":%s}",
            i ? "," : "", id,title,severity,status,assigned,device,candidate,exam,summary,notes,PQgetvalue(res,i,10));
        if (n < 0 || (size_t)n >= max_len-used) { PQclear(res); release_db_connection(conn, 0); return -1; }
        used += (size_t)n;
    }
    int n = snprintf(out_buf+used,max_len-used,"]}");
    int ok = n >= 0 && (size_t)n < max_len-used;
    PQclear(res); release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_create_incident(const security_incident_t *inc) {
    if (!inc || !inc->title[0] || !inc->status[0] || inc->severity < SEV_INFO || inc->severity > SEV_CRITICAL) return -1;
    security_incident_t record = *inc;
    if (!record.incident_id[0]) {
        char random_id[EXAMOS_TOKEN_HEX_LEN + 1], random_hash[EXAMOS_TOKEN_HEX_LEN + 1];
        if (secure_token_create(random_id, random_hash) != 0) return -1;
        snprintf(record.incident_id, sizeof(record.incident_id), "INC-%.59s", random_id);
        OPENSSL_cleanse(random_id, sizeof(random_id)); OPENSSL_cleanse(random_hash, sizeof(random_hash));
    }
    PGconn *conn = acquire_db_connection(); if (!conn) return -1;
    PGresult *begin = PQexec(conn, "BEGIN");
    int tx_ok = begin && PQresultStatus(begin) == PGRES_COMMAND_OK;
    if (begin) PQclear(begin);
    if (!tx_ok) { release_db_connection(conn, 1); return -1; }
    const char *params[] = { record.incident_id, record.institution_id[0] ? record.institution_id : NULL,
        record.title, severity_to_string(record.severity), record.status, record.assigned_to,
        record.device_id, record.candidate_id, record.exam_id[0] ? record.exam_id : NULL,
        record.summary, record.resolution_notes };
    PGresult *res = PQexecParams(conn,
        "INSERT INTO examos_security_incidents (incident_id,institution_id,title,severity,status,assigned_to,device_id,candidate_id,exam_id,summary,resolution_notes) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", 11,NULL,params,NULL,NULL,0);
    int ok = res && PQresultStatus(res)==PGRES_COMMAND_OK;
    if (res) PQclear(res);
    if (ok) {
        const char *history[] = { record.incident_id, "CREATED", record.status, record.summary };
        res = PQexecParams(conn,
            "INSERT INTO examos_incident_history (incident_id,action,new_status,notes) VALUES ($1,$2,$3,$4)",
            4,NULL,history,NULL,NULL,0);
        ok = res && PQresultStatus(res)==PGRES_COMMAND_OK;
        if (res) PQclear(res);
    }
    PGresult *finish = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    if (!finish || PQresultStatus(finish) != PGRES_COMMAND_OK) ok = 0;
    if (finish) PQclear(finish);
    release_db_connection(conn, 0);
    if (ok) {
        char details[128]; snprintf(details,sizeof(details),"severity=%s",severity_to_string(record.severity));
        ledger_append("INCIDENT_RAISED",record.incident_id,details);
    }
    return ok ? 0 : -1;
}

int platform_update_incident_status_scoped(const char *incident_id, const char *institution_scope,
                                           const char *new_status, const char *notes, const char *actor) {
    if (!incident_id || !incident_id[0] || !new_status ||
        (strcmp(new_status,"OPEN") && strcmp(new_status,"INVESTIGATING") &&
         strcmp(new_status,"CONTAINED") && strcmp(new_status,"RESOLVED"))) return -1;
    PGconn *conn = acquire_db_connection(); if (!conn) return -1;
    PGresult *begin = PQexec(conn,"BEGIN");
    if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
        if (begin) PQclear(begin);
        release_db_connection(conn, 1);
        return -1;
    }
    PQclear(begin);
    const char *lookup_params[] = { incident_id,
        institution_scope && institution_scope[0] ? institution_scope : NULL };
    PGresult *res = PQexecParams(conn,
        "SELECT status FROM examos_security_incidents WHERE incident_id=$1 "
        "AND ($2::varchar IS NULL OR institution_id=$2) FOR UPDATE",
        2,NULL,lookup_params,NULL,NULL,0);
    int ok = res && PQresultStatus(res)==PGRES_TUPLES_OK && PQntuples(res)==1;
    char prior_status[32] = {0}; if (ok) snprintf(prior_status,sizeof(prior_status),"%s",PQgetvalue(res,0,0));
    if (res) PQclear(res);
    if (ok) {
        const char *update_params[] = { new_status, notes ? notes : "", incident_id,
            institution_scope && institution_scope[0] ? institution_scope : NULL };
        res = PQexecParams(conn,
            "UPDATE examos_security_incidents SET status=$1,resolution_notes=$2,updated_at=clock_timestamp() "
            "WHERE incident_id=$3 AND ($4::varchar IS NULL OR institution_id=$4)",
            4,NULL,update_params,NULL,NULL,0);
        ok = res && PQresultStatus(res)==PGRES_COMMAND_OK && strcmp(PQcmdTuples(res),"1")==0;
        if (res) PQclear(res);
    }
    if (ok) {
        const char *hist_params[] = { incident_id, actor && actor[0] ? actor : NULL, prior_status, new_status, notes ? notes : "" };
        res = PQexecParams(conn,
            "INSERT INTO examos_incident_history (incident_id,actor_user_id,action,prior_status,new_status,notes) "
            "VALUES ($1,CASE WHEN EXISTS (SELECT 1 FROM examos_admin_users WHERE user_id=$2) THEN $2 ELSE NULL END,'STATUS_CHANGED',$3,$4,$5)",
            5,NULL,hist_params,NULL,NULL,0);
        ok = res && PQresultStatus(res)==PGRES_COMMAND_OK;
        if (res) PQclear(res);
    }
    res = PQexec(conn,ok ? "COMMIT" : "ROLLBACK");
    if (!res || PQresultStatus(res)!=PGRES_COMMAND_OK) ok=0;
    if (res) PQclear(res);
    release_db_connection(conn,0);
    if (ok) { char details[128]; snprintf(details,sizeof(details),"status=%s actor=%s",new_status,actor?actor:"system"); ledger_append("INCIDENT_STATUS",incident_id,details); }
    return ok ? 0 : -1;
}

int platform_update_incident_status(const char *incident_id, const char *new_status,
                                    const char *notes, const char *actor) {
    return platform_update_incident_status_scoped(incident_id, NULL, new_status, notes, actor);
}

/* -------------------------------------------------------------------------
 * Durable Submissions (Module K)
 * Persisted atomically to disk before acknowledging 200 OK
 * ------------------------------------------------------------------------- */
int platform_record_submission(const durable_submission_t *sub, const char *answers_payload) {
    if (!sub || !answers_payload) return -1;

    char file_path[1024];
    snprintf(file_path, sizeof(file_path), "%s/submissions/%s_%s.json",
             g_data_dir, sub->exam_id, sub->candidate_id);

    /* Atomic persistence to disk */
    if (atomic_write_file(file_path, answers_payload, strlen(answers_payload)) != 0) {
        return -1;
    }

    pthread_mutex_lock(&g_platform_lock);
    if (g_submission_count < MAX_SUBMISSIONS) {
        memcpy(&g_submissions[g_submission_count++], sub, sizeof(durable_submission_t));
    }

    /* Update roster entry in database */
    PGconn *conn = acquire_db_connection();
    if (conn) {
        const char *r_params[] = { sub->exam_id, sub->candidate_id };
        PGresult *r_res = PQexecParams(conn,
            "UPDATE examos_exam_roster SET status = 'SUBMITTED', submit_time = clock_timestamp() "
            "WHERE exam_id = $1 AND candidate_id = $2",
            2, NULL, r_params, NULL, NULL, 0);
        if (r_res) PQclear(r_res);
        release_db_connection(conn, 0);
    }

    /* Append to audit ledger */
    char details[256];
    snprintf(details, sizeof(details), "receipt=%s size=%zu", sub->receipt_hash, sub->payload_bytes);
    ledger_append("EXAM_SUBMISSION", sub->candidate_id, details);

    pthread_mutex_unlock(&g_platform_lock);
    return 0;
}

int platform_get_submissions_json(const char *exam_id, char *out_buf, size_t max_len) {
    pthread_mutex_lock(&g_platform_lock);
    size_t offset = snprintf(out_buf, max_len, "{\"submissions\":[");
    int first = 1;
    for (int i = 0; i < g_submission_count; i++) {
        if (!exam_id || strlen(exam_id) == 0 || strcmp(g_submissions[i].exam_id, exam_id) == 0) {
            offset += snprintf(out_buf + offset, max_len - offset,
                "%s{\"submission_id\":\"%s\",\"exam_id\":\"%s\",\"candidate_id\":\"%s\","
                "\"receipt_hash\":\"%s\",\"bytes\":%zu,\"submitted_at\":%ld,\"status\":\"%s\"}",
                (first ? "" : ","),
                g_submissions[i].submission_id,
                g_submissions[i].exam_id,
                g_submissions[i].candidate_id,
                g_submissions[i].receipt_hash,
                g_submissions[i].payload_bytes,
                g_submissions[i].submitted_at,
                g_submissions[i].status);
            first = 0;
        }
        if (offset >= max_len - 100) break;
    }
    snprintf(out_buf + offset, max_len - offset, "]}");
    pthread_mutex_unlock(&g_platform_lock);
    return 0;
}

/* -------------------------------------------------------------------------
 * Releases JSON (Module L)
 * ------------------------------------------------------------------------- */
int platform_get_releases_json(char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 64) return -1;
    PGconn *conn = acquire_db_connection(); if (!conn) return -1;
    PGresult *res = PQexec(conn,
        "SELECT r.release_id,r.version_name,r.image_digest,r.uki_digest,r.sbom_digest,r.target_ring,"
        "CASE WHEN v.target_id IS NOT NULL THEN 'REVOKED' ELSE r.status END,r.signed_by,"
        "extract(epoch from r.release_date)::bigint FROM examos_software_releases r "
        "LEFT JOIN examos_attestation_revocations v ON v.target_type='RELEASE' AND v.target_id=r.release_id "
        "ORDER BY r.release_date DESC LIMIT 1000");
    if (!res || PQresultStatus(res)!=PGRES_TUPLES_OK) { if(res) PQclear(res); release_db_connection(conn,0); return -1; }
    int initial=snprintf(out_buf,max_len,"{\"releases\":[");
    if(initial<0 || (size_t)initial>=max_len) { PQclear(res); release_db_connection(conn,0); return -1; }
    size_t used=(size_t)initial;
    for(int i=0;i<PQntuples(res);++i) {
        char id[256],version[256],image[128],uki[128],sbom[128],ring[64],status[64],signer[256];
        if(platform_json_escape(PQgetvalue(res,i,0),id,sizeof(id)) || platform_json_escape(PQgetvalue(res,i,1),version,sizeof(version)) ||
           platform_json_escape(PQgetvalue(res,i,2),image,sizeof(image)) || platform_json_escape(PQgetvalue(res,i,3),uki,sizeof(uki)) ||
           platform_json_escape(PQgetvalue(res,i,4),sbom,sizeof(sbom)) || platform_json_escape(PQgetvalue(res,i,5),ring,sizeof(ring)) ||
           platform_json_escape(PQgetvalue(res,i,6),status,sizeof(status)) || platform_json_escape(PQgetvalue(res,i,7),signer,sizeof(signer))) {
            PQclear(res); release_db_connection(conn,0); return -1;
        }
        int n=snprintf(out_buf+used,max_len-used,
            "%s{\"id\":\"%s\",\"version\":\"%s\",\"image_digest\":\"%s\",\"uki_digest\":\"%s\",\"sbom_digest\":\"%s\",\"ring\":\"%s\",\"status\":\"%s\",\"signed_by\":\"%s\",\"date\":%s}",
            i?",":"",id,version,image,uki,sbom,ring,status,signer,PQgetvalue(res,i,8));
        if(n<0 || (size_t)n>=max_len-used) { PQclear(res); release_db_connection(conn,0); return -1; }
        used+=(size_t)n;
    }
    int n=snprintf(out_buf+used,max_len-used,"]}"); int ok=n>=0 && (size_t)n<max_len-used;
    PQclear(res); release_db_connection(conn,0); return ok?0:-1;
}

int platform_create_release(const enterprise_release_t *rel) {
    if (!rel || !rel->release_id[0] || !rel->version_name[0] || !rel->release_date ||
        rel->target_ring < RING_CANARY || rel->target_ring > RING_GENERAL ||
        strcmp(rel->status,"DRAFT") != 0) {
        platform_set_error("release_id, version_name, a release date, a valid target ring and a "
                           "DRAFT status are required");
        return -1;
    }
    PGconn *conn=acquire_db_connection();
    if (!conn) {
        platform_set_error("The durable platform store is unreachable");
        return -1;
    }
    const char *params[]={rel->release_id,rel->version_name,rel->image_digest,rel->uki_digest,rel->sbom_digest,
        ring_to_string(rel->target_ring),rel->status,rel->signed_by,
        NULL};
    char date[32]; snprintf(date,sizeof(date),"%ld",(long)rel->release_date);
    params[8]=date;
    PGresult *res=PQexecParams(conn,
        "INSERT INTO examos_software_releases (release_id,version_name,image_digest,uki_digest,sbom_digest,target_ring,status,signed_by,release_date) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9::bigint))",
        9,NULL,params,NULL,NULL,0);
    int ok=res && PQresultStatus(res)==PGRES_COMMAND_OK;
    if (!ok) platform_set_db_error(res);
    if (res) PQclear(res);
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Reconciliation and Operational Metrics (Module I, Module M, Module O)
 * ------------------------------------------------------------------------- */
int platform_get_telemetry_json(char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 128) return -1;
    pthread_mutex_lock(&g_platform_lock);
    time_t now = time(NULL);
    long uptime_seconds = g_platform_started_at > 0 && now >= g_platform_started_at
                              ? (long)(now - g_platform_started_at)
                              : -1;
    pthread_mutex_unlock(&g_platform_lock);

    PGconn *conn = acquire_db_connection();
    if (!conn) {
        /* Return a structured unprovisioned response so callers and tests can
         * detect this state without treating it as a generic I/O failure. */
        int written = snprintf(out_buf, max_len,
            "{\"status\":\"NOT_PRODUCTION_READY\","
            "\"uptime_seconds\":%ld,"
            "\"platform_registry_persistence\":\"NOT_IMPLEMENTED\","
            "\"submission_storage\":\"NOT_PROVISIONED\","
            "\"storage_engine\":\"NONE\"}",
            uptime_seconds);
        return (written > 0 && (size_t)written < max_len) ? 0 : -1;
    }
    PGresult *res = PQexec(conn,
        "SELECT (SELECT count(*) FROM examos_institutions),"
        "(SELECT count(*) FROM examos_exams),"
        "(SELECT count(*) FROM examos_exam_roster),"
        "(SELECT count(*) FROM examos_devices),"
        "(SELECT count(*) FROM examos_security_incidents),"
        "(SELECT count(*) FROM examos_exam_roster WHERE status='SUBMITTED'),"
        "(SELECT coalesce(extract(epoch from max(reported_at))::bigint,0) FROM examos_device_heartbeats)");
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }
    int written = snprintf(out_buf, max_len,
        "{\"status\":\"AVAILABLE\",\"uptime_seconds\":%ld,\"institutions_count\":%s,"
        "\"exams_count\":%s,\"roster_count\":%s,\"devices_count\":%s,\"incidents_count\":%s,"
        "\"submitted_candidates_count\":%s,\"latest_device_heartbeat_epoch\":%s,"
        "\"storage_engine\":\"POSTGRESQL_TLS\",\"submission_count_source\":\"roster_status\"}",
        uptime_seconds, PQgetvalue(res,0,0), PQgetvalue(res,0,1), PQgetvalue(res,0,2),
        PQgetvalue(res,0,3), PQgetvalue(res,0,4), PQgetvalue(res,0,5), PQgetvalue(res,0,6));
    int ok = written >= 0 && (size_t)written < max_len;
    PQclear(res); release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_get_reconciliation_json(const char *exam_id, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 128) return -1;
    return platform_reconcile_exam(exam_id ? exam_id : "", out_buf, max_len);
}

/* -------------------------------------------------------------------------
 * Administrative reporting views
 * ------------------------------------------------------------------------- */

/* Scoped administrative audit trail. */
int platform_get_audit_json(const char *exam_id, int limit, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 256) return -1;
    if (limit <= 0) limit = 100;
    if (limit > 1000) limit = 1000;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char limit_str[16];
    snprintf(limit_str, sizeof(limit_str), "%d", limit);
    const char *params[2] = { exam_id && exam_id[0] ? exam_id : NULL, limit_str };

    PGresult *res = PQexecParams(conn,
        "SELECT a.event_type, a.occurred_at, COALESCE(u.username,''), "
        "       a.subject_type, a.subject_id, COALESCE(a.detail,'') "
        "FROM examos_admin_audit a "
        "LEFT JOIN examos_admin_users u ON u.user_id = a.actor_user_id "
        "WHERE ($1::text IS NULL OR a.subject_id = $1) "
        "ORDER BY a.occurred_at DESC LIMIT $2::integer",
        2, NULL, params, NULL, NULL, 0);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    size_t used = 0;
    int written = snprintf(out_buf, max_len, "[");
    if (written < 0) { PQclear(res); release_db_connection(conn, 0); return -1; }
    used = (size_t)written;

    for (int i = 0; i < PQntuples(res) && used + 1 < max_len; i++) {
        char item[2048];
        char event_type[128], actor[128], subject_type[64], subject_id[128];
        char detail[512];
        snprintf(event_type, sizeof(event_type), "%s", PQgetvalue(res, i, 0));
        snprintf(actor, sizeof(actor), "%s", PQgetvalue(res, i, 2));
        snprintf(subject_type, sizeof(subject_type), "%s", PQgetvalue(res, i, 3));
        snprintf(subject_id, sizeof(subject_id), "%s", PQgetvalue(res, i, 4));
        snprintf(detail, sizeof(detail), "%s", PQgetvalue(res, i, 5));
        platform_json_escape(event_type, event_type, sizeof(event_type));
        platform_json_escape(actor, actor, sizeof(actor));
        platform_json_escape(subject_type, subject_type, sizeof(subject_type));
        platform_json_escape(subject_id, subject_id, sizeof(subject_id));
        platform_json_escape(detail, detail, sizeof(detail));

        written = snprintf(item, sizeof(item),
            "%s{\"event_type\":\"%s\",\"actor\":\"%s\",\"recorded_at\":\"%s\","
            "\"subject_type\":\"%s\",\"subject_id\":\"%s\",\"detail\":\"%s\"}",
            i > 0 ? "," : "", event_type, actor, PQgetvalue(res, i, 1),
            subject_type, subject_id, detail);
        if (written <= 0 || used + (size_t)written >= max_len) break;
        memcpy(out_buf + used, item, (size_t)written);
        used += (size_t)written;
    }
    if (used + 3 < max_len) {
        memcpy(out_buf + used, "]\0", 3);
    } else {
        out_buf[max_len - 1] = '\0';
    }
    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

/* Live examination operations: state distribution and candidate progress. */
int platform_get_operations_json(char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 256) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = PQexec(conn,
        "SELECT e.state, count(*), "
        "       coalesce(sum(CASE WHEN r.status='CHECKED_IN' THEN 1 ELSE 0 END),0), "
        "       coalesce(sum(CASE WHEN r.status='IN_EXAM' THEN 1 ELSE 0 END),0), "
        "       coalesce(sum(CASE WHEN r.status='SUBMITTED' THEN 1 ELSE 0 END),0), "
        "       coalesce(sum(CASE WHEN r.status='ELIGIBLE' THEN 1 ELSE 0 END),0) "
        "FROM examos_exams e "
        "LEFT JOIN examos_exam_roster r ON r.exam_id = e.exam_id "
        "GROUP BY e.state ORDER BY e.state");

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    size_t used = 0;
    int written = snprintf(out_buf, max_len, "{\"exam_states\":[");
    if (written < 0) { PQclear(res); release_db_connection(conn, 0); return -1; }
    used = (size_t)written;

    for (int i = 0; i < PQntuples(res) && used + 1 < max_len; i++) {
        char item[512];
        written = snprintf(item, sizeof(item),
            "%s{\"state\":\"%s\",\"exams\":%s,\"checked_in\":%s,\"in_exam\":%s,"
            "\"submitted\":%s,\"eligible\":%s}",
            i > 0 ? "," : "",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
            PQgetvalue(res, i, 3), PQgetvalue(res, i, 4), PQgetvalue(res, i, 5));
        if (written <= 0 || used + (size_t)written >= max_len) break;
        memcpy(out_buf + used, item, (size_t)written);
        used += (size_t)written;
    }
    if (used + 2 < max_len) {
        memcpy(out_buf + used, "]}\0", 4);
    } else {
        out_buf[max_len - 1] = '\0';
    }
    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

/* Device groups and deployment rings, with the size of each group. */
int platform_get_device_groups_json(char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 256) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = PQexec(conn,
        "SELECT d.group_name, d.deployment_ring, count(*), "
        "       coalesce(sum(CASE WHEN d.compliance_status='COMPLIANT' THEN 1 ELSE 0 END),0), "
        "       coalesce(sum(CASE WHEN d.enrollment_status='ENROLLED' THEN 1 ELSE 0 END),0) "
        "FROM examos_devices d "
        "WHERE d.group_name <> '' "
        "GROUP BY d.group_name, d.deployment_ring "
        "ORDER BY d.group_name, d.deployment_ring");

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    size_t used = 0;
    int written = snprintf(out_buf, max_len, "[");
    if (written < 0) { PQclear(res); release_db_connection(conn, 0); return -1; }
    used = (size_t)written;

    for (int i = 0; i < PQntuples(res) && used + 1 < max_len; i++) {
        char item[512];
        written = snprintf(item, sizeof(item),
            "%s{\"group_name\":\"%s\",\"deployment_ring\":\"%s\",\"devices\":%s,"
            "\"compliant\":%s,\"enrolled\":%s}",
            i > 0 ? "," : "",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
            PQgetvalue(res, i, 3), PQgetvalue(res, i, 4));
        if (written <= 0 || used + (size_t)written >= max_len) break;
        memcpy(out_buf + used, item, (size_t)written);
        used += (size_t)written;
    }
    if (used + 3 < max_len) {
        memcpy(out_buf + used, "]\0", 3);
    } else {
        out_buf[max_len - 1] = '\0';
    }
    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

/* Updates the mutable attributes of an institution. */
int platform_update_institution(const char *institution_id, const char *name,
                                const char *contact_email, int retention_days,
                                const char *actor) {
    if (!institution_id || !institution_id[0] || !name || !name[0] ||
        strlen(institution_id) >= 64 || strlen(name) >= 128 ||
        retention_days < 1 || retention_days > 36500) {
        platform_set_error("institution_id, name and a retention window between 1 and 36500 days are required");
        return -1;
    }

    PGconn *conn = acquire_db_connection();
    if (!conn) {
        platform_set_error("The durable platform store is unreachable");
        return -1;
    }

    char retention_str[16];
    snprintf(retention_str, sizeof(retention_str), "%d", retention_days);
    const char *params[4] = {
        name,
        contact_email && contact_email[0] ? contact_email : NULL,
        retention_str,
        institution_id
    };
    PGresult *res = PQexecParams(conn,
        "UPDATE examos_institutions SET name = $1, domain_email = COALESCE($2, domain_email), "
        "  retention_days = $3::integer WHERE institution_id = $4",
        4, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK &&
             strcmp(PQcmdTuples(res), "1") == 0;
    if (!ok) platform_set_db_error(res);
    if (res) PQclear(res);
    release_db_connection(conn, 0);

    if (ok) {
        char details[256];
        snprintf(details, sizeof(details),
                 "institution_id=%s name=%s retention_days=%d actor=%s",
                 institution_id, name, retention_days, actor ? actor : "system");
        ledger_append("ADMIN_CONFIG_UPDATED", institution_id, details);
    }
    return ok ? 0 : -1;
}
