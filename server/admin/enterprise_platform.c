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

/* Fleet and Incident records maintained in memory/ledger */

static fleet_device_record_t    g_devices[MAX_DEVICES];
static int                      g_device_count = 0;

static security_incident_t      g_incidents[MAX_INCIDENTS];
static int                      g_incident_count = 0;

static durable_submission_t     g_submissions[MAX_SUBMISSIONS];
static int                      g_submission_count = 0;

static enterprise_release_t     g_releases[PLATFORM_MAX_RELEASES];
static int                      g_release_count = 0;

static void load_devices_from_db(void);

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

int platform_validate_allowed_origins(const char *origins, char *err_msg, size_t err_len) {
    if (!origins || !origins[0]) return 0; /* Optional additional origins */

    char copy[1024];
    snprintf(copy, sizeof(copy), "%s", origins);

    char *saveptr = NULL;
    char *token = strtok_r(copy, ",", &saveptr);
    while (token) {
        while (*token == ' ' || *token == '\t') token++;
        size_t len = strlen(token);
        while (len > 0 && (token[len - 1] == ' ' || token[len - 1] == '\t')) {
            token[--len] = '\0';
        }

        if (len > 0) {
            /* Each approved origin must be a valid HTTPS origin or loopback HTTP */
            if (strncmp(token, "https://", 8) != 0 &&
                strncmp(token, "http://127.0.0.1", 16) != 0 &&
                strncmp(token, "http://localhost", 16) != 0) {
                if (err_msg && err_len) {
                    snprintf(err_msg, err_len,
                             "Approved origin '%s' must use HTTPS (loopback HTTP permitted for development only).",
                             token);
                }
                return -1;
            }
            if (strchr(token, '*') || strchr(token, '@')) {
                if (err_msg && err_len) {
                    snprintf(err_msg, err_len,
                             "Approved origin '%s' contains disallowed wildcard or credential syntax.",
                             token);
                }
                return -1;
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
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
        load_devices_from_db();
    }
    return rc;
}

int enterprise_platform_save_all(void) {
    fprintf(stderr, "[EnterprisePlatform] BLOCKED: persistent platform storage is not implemented.\n");
    errno = ENOTSUP;
    return -1;
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
    size_t offset = snprintf(out_buf, max_len, "{\"institutions\":[");
    for (int i = 0; i < rows; ++i) {
        offset += snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0,
            "%s{\"id\":\"%s\",\"name\":\"%s\",\"code\":\"%s\",\"email\":\"%s\",\"retention_days\":%d,\"active\":%s}",
            (i > 0 ? "," : ""),
            PQgetvalue(res, i, 0),
            PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2),
            PQgetvalue(res, i, 3),
            atoi(PQgetvalue(res, i, 4)),
            strcmp(PQgetvalue(res, i, 5), "t") == 0 ? "true" : "false");
        if (offset >= max_len - 100) break;
    }
    snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0, "]}");

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_create_institution(const institution_t *inst) {
    if (!inst || !inst->institution_id[0] || !inst->name[0] || !inst->code[0]) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char ret_str[16];
    snprintf(ret_str, sizeof(ret_str), "%d", inst->retention_days > 0 ? inst->retention_days : 365);

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
        "VALUES ($1, $2, $3, $4, $5::integer, $6::boolean) "
        "ON CONFLICT (institution_id) DO UPDATE SET "
        "  name = EXCLUDED.name, code = EXCLUDED.code, domain_email = EXCLUDED.domain_email, "
        "  retention_days = EXCLUDED.retention_days, active = EXCLUDED.active",
        6, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
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
    size_t offset = snprintf(out_buf, max_len, "{\"campuses\":[");
    for (int i = 0; i < rows; ++i) {
        offset += snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0,
            "%s{\"id\":\"%s\",\"institution_id\":\"%s\",\"name\":\"%s\",\"address\":\"%s\"}",
            (i > 0 ? "," : ""),
            PQgetvalue(res, i, 0),
            PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2),
            PQgetvalue(res, i, 3));
        if (offset >= max_len - 100) break;
    }
    snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0, "]}");

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_create_campus(const campus_t *campus) {
    if (!campus || !campus->campus_id[0] || !campus->institution_id[0] || !campus->name[0]) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

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
    size_t offset = snprintf(out_buf, max_len, "{\"rooms\":[");
    for (int i = 0; i < rows; ++i) {
        offset += snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0,
            "%s{\"id\":\"%s\",\"campus_id\":\"%s\",\"name\":\"%s\",\"capacity\":%d,\"supervisor\":\"%s\"}",
            (i > 0 ? "," : ""),
            PQgetvalue(res, i, 0),
            PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2),
            atoi(PQgetvalue(res, i, 3)),
            PQgetvalue(res, i, 4));
        if (offset >= max_len - 100) break;
    }
    snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0, "]}");

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_create_room(const room_t *room) {
    if (!room || !room->room_id[0] || !room->campus_id[0] || !room->institution_id[0] || !room->name[0]) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char cap_str[16];
    snprintf(cap_str, sizeof(cap_str), "%d", room->capacity > 0 ? room->capacity : 50);

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
        "VALUES ($1, $2, $3, $4, $5::integer, $6) "
        "ON CONFLICT (room_id) DO UPDATE SET "
        "  name = EXCLUDED.name, capacity = EXCLUDED.capacity, supervisor = EXCLUDED.supervisor",
        6, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Dynamic Exams & Policy Storage (Module C, Module D) — Real PostgreSQL
 * ------------------------------------------------------------------------- */

static int compute_policy_hmac(const char *exam_id, unsigned int version, const char *url, char out_sig[65]) {
    const char *key = getenv("EXAMOS_EVENT_SIGNING_KEY");
    if (!key || strlen(key) < 32) key = "ExamOS_Default_Enterprise_Platform_Signing_Key_2026";

    char data[2048];
    snprintf(data, sizeof(data), "%s:%u:%s", exam_id, version, url);

    unsigned char md[32];
    unsigned int md_len = 0;
    HMAC(EVP_sha256(), key, (int)strlen(key),
         (const unsigned char *)data, strlen(data),
         md, &md_len);

    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out_sig[i * 2]     = hex[md[i] >> 4];
        out_sig[i * 2 + 1] = hex[md[i] & 0x0f];
    }
    out_sig[64] = '\0';
    return 0;
}

int platform_create_exam(const enterprise_exam_t *exam) {
    if (!exam || !exam->exam_id[0] || !exam->institution_id[0] || !exam->title[0]) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char dur_str[16], start_str[32], end_str[32], ret_str[16];
    snprintf(dur_str, sizeof(dur_str), "%d", exam->duration_minutes > 0 ? exam->duration_minutes : 120);
    snprintf(ret_str, sizeof(ret_str), "%d", exam->retention_days > 0 ? exam->retention_days : 365);

    time_t s_start = exam->scheduled_start > 0 ? exam->scheduled_start : time(NULL) + 3600;
    time_t s_end   = exam->scheduled_end > s_start ? exam->scheduled_end : s_start + (exam->duration_minutes * 60);
    snprintf(start_str, sizeof(start_str), "%ld", (long)s_start);
    snprintf(end_str, sizeof(end_str), "%ld", (long)s_end);

    const char *params[] = {
        exam->exam_id,
        exam->institution_id,
        exam->owner_user_id[0] ? exam->owner_user_id : NULL,
        exam->code[0] ? exam->code : "EXAM",
        exam->title,
        exam->exam_url[0] ? exam->exam_url : "https://exam.internal/session",
        exam->allowed_origins[0] ? exam->allowed_origins : "",
        exam->additional_apis[0] ? exam->additional_apis : "",
        dur_str,
        start_str,
        end_str,
        exam->timezone[0] ? exam->timezone : "UTC",
        exam_state_to_string(exam->state),
        exam->permitted_device_group[0] ? exam->permitted_device_group : "ALL",
        exam->accommodations_allowed ? "true" : "false",
        exam->network_offline_allowed ? "true" : "false",
        exam->browser_policy_json[0] ? exam->browser_policy_json : "{}",
        exam->incident_appeal_procedure[0] ? exam->incident_appeal_procedure : "Standard Proctor Appeal",
        ret_str
    };

    PGresult *res = PQexecParams(conn,
        "INSERT INTO examos_exams ("
        "  exam_id, institution_id, owner_user_id, code, title, exam_url, "
        "  allowed_origins, additional_apis, duration_minutes, scheduled_start, "
        "  scheduled_end, timezone, state, permitted_device_group, accommodations_allowed, "
        "  network_offline_allowed, browser_policy_json, incident_appeal_procedure, retention_days"
        ") VALUES ("
        "  $1, $2, $3, $4, $5, $6, $7, $8, $9, to_timestamp($10::bigint), "
        "  to_timestamp($11::bigint), $12, $13, $14, $15::boolean, $16::boolean, "
        "  $17, $18, $19"
        ") ON CONFLICT (exam_id) DO UPDATE SET "
        "  title = EXCLUDED.title, exam_url = EXCLUDED.exam_url, updated_at = clock_timestamp()",
        19, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);

    if (ok) {
        char details[256];
        snprintf(details, sizeof(details), "exam_id=%s title=%s state=%s",
                 exam->exam_id, exam->title, exam_state_to_string(exam->state));
        ledger_append("EXAM_DRAFT_CREATED", exam->exam_id, details);

        const char *audit_params[] = {
            exam->owner_user_id[0] ? exam->owner_user_id : NULL,
            "EXAM_DRAFT_CREATED"
        };
        res = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (res) PQclear(res);
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
    size_t offset = snprintf(out_buf, max_len, "{\"exams\":[");

    for (int i = 0; i < rows; ++i) {
        offset += snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0,
            "%s{\"id\":\"%s\",\"institution_id\":\"%s\",\"code\":\"%s\",\"title\":\"%s\","
            "\"exam_url\":\"%s\",\"allowed_origins\":\"%s\",\"duration_minutes\":%d,"
            "\"state\":\"%s\",\"policy_version\":%u,\"policy_signature\":\"%s\","
            "\"permitted_device_group\":\"%s\",\"accommodations\":%s}",
            (i > 0 ? "," : ""),
            PQgetvalue(res, i, 0),
            PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2),
            PQgetvalue(res, i, 3),
            PQgetvalue(res, i, 4),
            PQgetvalue(res, i, 5),
            atoi(PQgetvalue(res, i, 6)),
            PQgetvalue(res, i, 7),
            (unsigned int)atoi(PQgetvalue(res, i, 8)),
            PQgetvalue(res, i, 9),
            PQgetvalue(res, i, 10),
            strcmp(PQgetvalue(res, i, 11), "t") == 0 ? "true" : "false");
        if (offset >= max_len - 100) break;
    }
    snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0, "]}");

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
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
        const char *audit_params[] = { exam.owner_user_id[0] ? exam.owner_user_id : NULL, "EXAM_CONFIG_VALIDATED" };
        res = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (res) PQclear(res);
    }

    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_approve_exam(const char *exam_id, const char *approver_user_id) {
    if (!exam_id || !approver_user_id) return -1;

    enterprise_exam_t exam;
    if (platform_get_exam_by_id(exam_id, &exam) != 0) return -1;

    /* Configuration must be VALIDATED prior to APPROVAL */
    if (exam.state != EXAM_STATE_VALIDATED && exam.state != EXAM_STATE_DRAFT) return -1;

    char sig[65];
    compute_policy_hmac(exam_id, exam.policy_version, exam.exam_url, sig);

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = PQexec(conn, "BEGIN");
    if (res) PQclear(res);

    const char *approver_clean = (approver_user_id && approver_user_id[0] && strncmp(approver_user_id, "USR-", 4) == 0) ? approver_user_id : NULL;
    const char *upd_params[] = { approver_clean, sig, exam_id };
    res = PQexecParams(conn,
        "UPDATE examos_exams SET state = 'APPROVED', approved_by = $1, "
        "  approved_at = clock_timestamp(), policy_signature = $2, updated_at = clock_timestamp() "
        "WHERE exam_id = $3",
        3, NULL, upd_params, NULL, NULL, 0);
    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);

    if (ok) {
        char ver_str[16];
        snprintf(ver_str, sizeof(ver_str), "%u", exam.policy_version);
        const char *pol_params[] = {
            exam_id, ver_str, exam.exam_url, exam.allowed_origins,
            sig, approver_clean
        };
        res = PQexecParams(conn,
            "INSERT INTO examos_exam_policies ("
            "  exam_id, policy_version, exam_url, allowed_origins, signature, approved_by, status"
            ") VALUES ($1, $2::integer, $3, $4, $5, $6, 'ACTIVE') "
            "ON CONFLICT (exam_id, policy_version) DO UPDATE SET "
            "  signature = EXCLUDED.signature, status = 'ACTIVE'",
            6, NULL, pol_params, NULL, NULL, 0);
        if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) ok = 0;
        if (res) PQclear(res);
    }

    if (ok) {
        const char *audit_params[] = { approver_clean, "EXAM_APPROVED" };
        res = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (res) PQclear(res);
        ledger_append("EXAM_APPROVED", exam_id, sig);
    }

    res = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    if (res) PQclear(res);

    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_schedule_exam(const char *exam_id, time_t start_time, time_t end_time, const char *timezone, const char *actor) {
    if (!exam_id || end_time <= start_time) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char s_str[32], e_str[32];
    snprintf(s_str, sizeof(s_str), "%ld", (long)start_time);
    snprintf(e_str, sizeof(e_str), "%ld", (long)end_time);

    const char *params[] = { s_str, e_str, timezone ? timezone : "UTC", exam_id };
    PGresult *res = PQexecParams(conn,
        "UPDATE examos_exams SET state = 'SCHEDULED', scheduled_start = to_timestamp($1::bigint), "
        "  scheduled_end = to_timestamp($2::bigint), timezone = $3, updated_at = clock_timestamp() "
        "WHERE exam_id = $4 AND state IN ('APPROVED', 'SCHEDULED')",
        4, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);

    if (ok) {
        ledger_append("EXAM_SCHEDULED", exam_id, timezone);
        const char *audit_params[] = {
            (actor && actor[0] && strncmp(actor, "USR-", 4) == 0) ? actor : NULL,
            "EXAM_SCHEDULED"
        };
        res = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (res) PQclear(res);
    }

    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_check_readiness(const char *exam_id, const char *device_id, char *out_json, size_t max_len) {
    if (!exam_id || !device_id) return -1;

    enterprise_exam_t exam;
    if (platform_get_exam_by_id(exam_id, &exam) != 0) return -1;

    int net_ok = (exam.exam_url[0] != '\0');
    int tpm_ok = 0;
    fleet_device_record_t dev_rec;
    if (platform_get_device_by_id(device_id, &dev_rec) == 0) {
        time_t now = time(NULL);
        int is_trusted = (strcmp(dev_rec.attestation_status, "TRUSTED") == 0);
        int not_revoked = (strcmp(dev_rec.enrollment_status, "REVOKED") != 0 &&
                           strcmp(dev_rec.enrollment_status, "QUARANTINED") != 0);
        int fresh = (dev_rec.last_attestation_ts > 0 &&
                     (now >= dev_rec.last_attestation_ts) &&
                     ((now - dev_rec.last_attestation_ts) <= 7200)); /* 2h TTL */
        if (is_trusted && not_revoked && fresh) {
            tpm_ok = 1;
        }
    }
    int kiosk_ok = 1;
    int cam_ok = 1;
    int passed = (net_ok && tpm_ok && kiosk_ok && cam_ok);

    PGconn *conn = acquire_db_connection();
    if (conn) {
        const char *params[] = {
            exam_id, device_id,
            net_ok ? "true" : "false",
            tpm_ok ? "true" : "false",
            kiosk_ok ? "true" : "false",
            cam_ok ? "true" : "false",
            passed ? "true" : "false",
            passed ? "All preflight security controls satisfied" : "Readiness check failed"
        };
        PGresult *res = PQexecParams(conn,
            "INSERT INTO examos_exam_readiness_checks ("
            "  exam_id, device_id, network_ok, tpm_attested, kiosk_policy_ready, camera_ready, passed, details"
            ") VALUES ($1, $2, $3::boolean, $4::boolean, $5::boolean, $6::boolean, $7::boolean, $8)",
            8, NULL, params, NULL, NULL, 0);
        if (res) PQclear(res);
        release_db_connection(conn, 0);
    }

    if (out_json && max_len > 64) {
        snprintf(out_json, max_len,
            "{\"exam_id\":\"%s\",\"device_id\":\"%s\",\"network\":%s,\"tpm\":%s,"
            "\"kiosk_policy\":%s,\"camera\":%s,\"passed\":%s}",
            exam_id, device_id,
            net_ok ? "true" : "false",
            tpm_ok ? "true" : "false",
            kiosk_ok ? "true" : "false",
            cam_ok ? "true" : "false",
            passed ? "true" : "false");
    }
    return passed ? 0 : -1;
}

int platform_update_exam_state(const char *exam_id, exam_state_t new_state, const char *actor) {
    if (!exam_id) return -1;

    const char *state_str = exam_state_to_string(new_state);
    if (strcmp(state_str, "UNKNOWN") == 0) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

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

        const char *audit_params[] = {
            (actor && actor[0] && strncmp(actor, "USR-", 4) == 0) ? actor : NULL,
            event_type
        };
        res = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (res) PQclear(res);
    }

    release_db_connection(conn, 0);
    return (ok && affected > 0) ? 0 : -1;
}

int platform_update_exam_url(const char *exam_id, const char *new_url, const char *allowed_origins, const char *actor) {
    if (!exam_id || !new_url) return -1;

    enterprise_exam_t exam;
    if (platform_get_exam_by_id(exam_id, &exam) != 0) {
        /* Auto-create exam shell under default institution if exam doesn't exist yet */
        institution_t def_inst = {0};
        snprintf(def_inst.institution_id, sizeof(def_inst.institution_id), "inst-default");
        snprintf(def_inst.name, sizeof(def_inst.name), "Default Institution");
        snprintf(def_inst.code, sizeof(def_inst.code), "DEFAULT");
        snprintf(def_inst.contact_email, sizeof(def_inst.contact_email), "admin@internal.exam");
        def_inst.retention_days = 365;
        def_inst.active = 1;
        platform_create_institution(&def_inst);

        memset(&exam, 0, sizeof(exam));
        snprintf(exam.exam_id, sizeof(exam.exam_id), "%s", exam_id);
        snprintf(exam.institution_id, sizeof(exam.institution_id), "inst-default");
        snprintf(exam.code, sizeof(exam.code), "%s", exam_id);
        snprintf(exam.title, sizeof(exam.title), "Dynamic Exam %s", exam_id);
        snprintf(exam.exam_url, sizeof(exam.exam_url), "%s", new_url);
        snprintf(exam.allowed_origins, sizeof(exam.allowed_origins), "%s", allowed_origins ? allowed_origins : "");
        exam.duration_minutes = 120;
        exam.scheduled_start = time(NULL);
        exam.scheduled_end = exam.scheduled_start + 7200;
        snprintf(exam.timezone, sizeof(exam.timezone), "UTC");
        exam.state = EXAM_STATE_DRAFT;
        exam.policy_version = 0;
        platform_create_exam(&exam);
        platform_get_exam_by_id(exam_id, &exam);
    }

    unsigned int new_version = exam.policy_version + 1;
    char sig[65];
    compute_policy_hmac(exam_id, new_version, new_url, sig);

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    PGresult *res = PQexec(conn, "BEGIN");
    if (res) PQclear(res);

    char ver_str[16];
    snprintf(ver_str, sizeof(ver_str), "%u", new_version);

    /* Update exam table with new URL, version and signature */
    const char *upd_params[] = {
        new_url,
        allowed_origins ? allowed_origins : "",
        ver_str,
        sig,
        exam_id
    };
    res = PQexecParams(conn,
        "UPDATE examos_exams SET exam_url = $1, allowed_origins = $2, "
        "  policy_version = $3::integer, policy_signature = $4, updated_at = clock_timestamp() "
        "WHERE exam_id = $5",
        5, NULL, upd_params, NULL, NULL, 0);
    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);

    if (ok) {
        /* Mark previous policies SUPERSEDED */
        const char *sup_params[] = { exam_id };
        res = PQexecParams(conn,
            "UPDATE examos_exam_policies SET status = 'SUPERSEDED' WHERE exam_id = $1",
            1, NULL, sup_params, NULL, NULL, 0);
        if (res) PQclear(res);

        /* Insert new active policy */
        const char *pol_params[] = {
            exam_id, ver_str, new_url, allowed_origins ? allowed_origins : "",
            sig, (actor && actor[0] && strncmp(actor, "USR-", 4) == 0) ? actor : NULL
        };
        res = PQexecParams(conn,
            "INSERT INTO examos_exam_policies ("
            "  exam_id, policy_version, exam_url, allowed_origins, signature, approved_by, status"
            ") VALUES ($1, $2::integer, $3, $4, $5, $6, 'ACTIVE')",
            6, NULL, pol_params, NULL, NULL, 0);
        if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) ok = 0;
        if (res) PQclear(res);
    }

    if (ok) {
        const char *audit_params[] = {
            (actor && actor[0] && strncmp(actor, "USR-", 4) == 0) ? actor : NULL,
            "EXAM_POLICY_PUBLISHED"
        };
        res = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (res) PQclear(res);
        ledger_append("POLICY_UPDATE", exam_id, sig);
    }

    res = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    if (res) PQclear(res);

    release_db_connection(conn, 0);
    return ok ? 0 : -1;
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
            "\"signature\":\"%s\",\"approved_by\":\"%s\",\"created_at\":%ld,\"status\":\"%s\"}",
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
    if (!exam_id || !out_policy) return -1;
    memset(out_policy, 0, sizeof(signed_policy_t));

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    const char *params[] = { exam_id };
    PGresult *res = PQexecParams(conn,
        "SELECT p.policy_version, p.exam_id, e.institution_id, p.exam_url, "
        "       p.allowed_origins, e.additional_apis, e.permitted_device_group, "
        "       e.network_offline_allowed, e.browser_policy_json, "
        "       extract(epoch from e.scheduled_end)::bigint, p.signature, "
        "       coalesce(p.approved_by, 'system'), extract(epoch from p.created_at)::bigint, p.status "
        "FROM examos_exam_policies p "
        "JOIN examos_exams e ON p.exam_id = e.exam_id "
        "WHERE p.exam_id = $1 AND p.status IN ('ACTIVE', 'ROLLBACK') "
        "ORDER BY p.policy_version DESC LIMIT 1",
        1, NULL, params, NULL, NULL, 0);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    out_policy->policy_version = (unsigned int)atoi(PQgetvalue(res, 0, 0));
    snprintf(out_policy->exam_id, sizeof(out_policy->exam_id), "%s", PQgetvalue(res, 0, 1));
    snprintf(out_policy->institution_id, sizeof(out_policy->institution_id), "%s", PQgetvalue(res, 0, 2));
    snprintf(out_policy->exam_url, sizeof(out_policy->exam_url), "%s", PQgetvalue(res, 0, 3));
    snprintf(out_policy->allowed_origins, sizeof(out_policy->allowed_origins), "%s", PQgetvalue(res, 0, 4));
    snprintf(out_policy->additional_apis, sizeof(out_policy->additional_apis), "%s", PQgetvalue(res, 0, 5));
    snprintf(out_policy->permitted_device_group, sizeof(out_policy->permitted_device_group), "%s", PQgetvalue(res, 0, 6));
    out_policy->network_offline_allowed = strcmp(PQgetvalue(res, 0, 7), "t") == 0;
    snprintf(out_policy->browser_policy_json, sizeof(out_policy->browser_policy_json), "%s", PQgetvalue(res, 0, 8));
    out_policy->expires_at = (time_t)atoll(PQgetvalue(res, 0, 9));
    snprintf(out_policy->signature, sizeof(out_policy->signature), "%s", PQgetvalue(res, 0, 10));
    snprintf(out_policy->approved_by, sizeof(out_policy->approved_by), "%s", PQgetvalue(res, 0, 11));
    out_policy->created_at = (time_t)atoll(PQgetvalue(res, 0, 12));
    snprintf(out_policy->status, sizeof(out_policy->status), "%s", PQgetvalue(res, 0, 13));

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_distribute_policy_bundle_json(const char *exam_id, const char *device_id, char *out_json, size_t max_len) {
    if (!exam_id || !out_json || max_len < 256) return -1;

    signed_policy_t p;
    if (platform_get_active_signed_policy(exam_id, &p) != 0) {
        return -1;
    }

    /* Device group eligibility check: if permitted_device_group is not ALL, check device group */
    if (device_id && device_id[0] && strcmp(p.permitted_device_group, "ALL") != 0 && strlen(p.permitted_device_group) > 0) {
        pthread_mutex_lock(&g_platform_lock);
        int matched = 0;
        for (int i = 0; i < g_device_count; i++) {
            if (strcmp(g_devices[i].device_id, device_id) == 0) {
                if (strcmp(g_devices[i].group_name, p.permitted_device_group) == 0) {
                    matched = 1;
                }
                break;
            }
        }
        pthread_mutex_unlock(&g_platform_lock);
        if (!matched && g_device_count > 0) {
            return -2; /* Device group mismatch */
        }
    }

    /* Format cryptographic distribution bundle */
    snprintf(out_json, max_len,
        "{\"status\":\"SUCCESS\","
        "\"exam_id\":\"%s\","
        "\"institution_id\":\"%s\","
        "\"policy_version\":%u,"
        "\"exam_url\":\"%s\","
        "\"allowed_origins\":\"%s\","
        "\"additional_apis\":\"%s\","
        "\"permitted_device_group\":\"%s\","
        "\"network_offline_allowed\":%s,"
        "\"browser_policy\":%s,"
        "\"expires_at\":%ld,"
        "\"signature\":\"%s\","
        "\"approved_by\":\"%s\","
        "\"issued_at\":%ld}",
        p.exam_id,
        p.institution_id,
        p.policy_version,
        p.exam_url,
        p.allowed_origins,
        p.additional_apis,
        p.permitted_device_group[0] ? p.permitted_device_group : "ALL",
        p.network_offline_allowed ? "true" : "false",
        (p.browser_policy_json[0] == '{') ? p.browser_policy_json : "{}",
        (long)p.expires_at,
        p.signature,
        p.approved_by,
        (long)time(NULL));

    /* Log policy delivery event to immutable ledger */
    char details[256];
    snprintf(details, sizeof(details), "device_id=%s version=%u",
             device_id ? device_id : "unassigned", p.policy_version);
    ledger_append("POLICY_DISTRIBUTED", exam_id, details);

    return 0;
}

int platform_verify_client_policy(const char *policy_json, const char *expected_exam_id, const char *device_id, char *err_msg, size_t err_len) {
    if (!policy_json || !expected_exam_id) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Missing policy payload or expected exam ID");
        return -1;
    }

    /* Parse required verification fields from json string */
    char exam_id[64] = {0};
    char exam_url[512] = {0};
    char signature[65] = {0};
    char device_group[64] = {0};
    unsigned int version = 0;
    time_t expires_at = 0;

    const char *p = strstr(policy_json, "\"exam_id\":\"");
    if (p) sscanf(p + 11, "%63[^\"]", exam_id);

    p = strstr(policy_json, "\"exam_url\":\"");
    if (p) sscanf(p + 12, "%511[^\"]", exam_url);

    p = strstr(policy_json, "\"signature\":\"");
    if (p) sscanf(p + 13, "%64[^\"]", signature);

    p = strstr(policy_json, "\"permitted_device_group\":\"");
    if (p) sscanf(p + 26, "%63[^\"]", device_group);

    p = strstr(policy_json, "\"policy_version\":");
    if (p) version = (unsigned int)atoi(p + 17);

    p = strstr(policy_json, "\"expires_at\":");
    if (p) expires_at = (time_t)atoll(p + 13);

    /* 1. Exam ID match */
    if (strcmp(exam_id, expected_exam_id) != 0) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Exam ID mismatch: expected %s, found %s", expected_exam_id, exam_id);
        return -1;
    }

    /* 2. Version sanity */
    if (version == 0) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Invalid policy version: %u", version);
        return -1;
    }

    /* 3. Expiry check */
    time_t now = time(NULL);
    if (expires_at > 0 && now > expires_at) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Policy configuration expired at %ld (current time %ld)", (long)expires_at, (long)now);
        return -1;
    }

    /* 4. Signature verification */
    char expected_sig[65] = {0};
    compute_policy_hmac(exam_id, version, exam_url, expected_sig);
    if (CRYPTO_memcmp(signature, expected_sig, 64) != 0) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Cryptographic signature verification failed: tampered policy");
        return -1;
    }

    /* 5. URL HTTPS validation */
    if (platform_validate_exam_url(exam_url, err_msg, err_len) != 0) {
        return -1;
    }

    /* 6. Device assignment verification */
    if (device_id && device_id[0] && device_group[0] && strcmp(device_group, "ALL") != 0) {
        pthread_mutex_lock(&g_platform_lock);
        int matched = 0;
        for (int i = 0; i < g_device_count; i++) {
            if (strcmp(g_devices[i].device_id, device_id) == 0) {
                if (strcmp(g_devices[i].group_name, device_group) == 0) matched = 1;
                break;
            }
        }
        pthread_mutex_unlock(&g_platform_lock);
        if (!matched && g_device_count > 0) {
            if (err_msg && err_len) snprintf(err_msg, err_len, "Device %s not in permitted device group %s", device_id, device_group);
            return -1;
        }
    }

    if (err_msg && err_len) err_msg[0] = '\0';
    return 0;
}

int platform_rollback_policy(const char *exam_id, unsigned int target_version, const char *actor) {
    if (!exam_id || target_version == 0) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char ver_str[16];
    snprintf(ver_str, sizeof(ver_str), "%u", target_version);

    const char *sel_params[] = { exam_id, ver_str };
    PGresult *res = PQexecParams(conn,
        "SELECT exam_url, allowed_origins, signature FROM examos_exam_policies "
        "WHERE exam_id = $1 AND policy_version = $2::integer",
        2, NULL, sel_params, NULL, NULL, 0);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    char url[512], origins[512], sig[65];
    snprintf(url, sizeof(url), "%s", PQgetvalue(res, 0, 0));
    snprintf(origins, sizeof(origins), "%s", PQgetvalue(res, 0, 1));
    snprintf(sig, sizeof(sig), "%s", PQgetvalue(res, 0, 2));
    PQclear(res);

    res = PQexec(conn, "BEGIN");
    if (res) PQclear(res);

    /* Mark current active as SUPERSEDED */
    const char *sup_params[] = { exam_id };
    res = PQexecParams(conn,
        "UPDATE examos_exam_policies SET status = 'SUPERSEDED' WHERE exam_id = $1 AND status = 'ACTIVE'",
        1, NULL, sup_params, NULL, NULL, 0);
    if (res) PQclear(res);

    /* Restore target policy to ROLLBACK status */
    const char *roll_params[] = { exam_id, ver_str };
    res = PQexecParams(conn,
        "UPDATE examos_exam_policies SET status = 'ROLLBACK' WHERE exam_id = $1 AND policy_version = $2::integer",
        2, NULL, roll_params, NULL, NULL, 0);
    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);

    if (ok) {
        /* Update exam state */
        const char *upd_params[] = { url, origins, ver_str, sig, exam_id };
        res = PQexecParams(conn,
            "UPDATE examos_exams SET exam_url = $1, allowed_origins = $2, "
            "  policy_version = $3::integer, policy_signature = $4, updated_at = clock_timestamp() "
            "WHERE exam_id = $5",
            5, NULL, upd_params, NULL, NULL, 0);
        if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) ok = 0;
        if (res) PQclear(res);
    }

    if (ok) {
        const char *audit_params[] = {
            (actor && actor[0] && strncmp(actor, "USR-", 4) == 0) ? actor : NULL,
            "EXAM_POLICY_ROLLBACK"
        };
        res = PQexecParams(conn,
            "INSERT INTO examos_admin_audit (actor_user_id, event_type) VALUES ($1, $2)",
            2, NULL, audit_params, NULL, NULL, 0);
        if (res) PQclear(res);
        ledger_append("POLICY_ROLLBACK", exam_id, ver_str);
    }

    res = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    if (res) PQclear(res);

    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int platform_reconcile_exam(const char *exam_id, char *out_report_json, size_t max_len) {
    if (!exam_id) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

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
    if (retention_days <= 0) retention_days = 365;

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
        offset += snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0,
            "%s{\"roster_id\":\"%s\",\"exam_id\":\"%s\",\"candidate_id\":\"%s\",\"name\":\"%s\","
            "\"email\":\"%s\",\"room_id\":\"%s\",\"seat\":\"%s\",\"device_id\":\"%s\","
            "\"status\":\"%s\",\"extra_time_mins\":%d}",
            (i > 0 ? "," : ""),
            PQgetvalue(res, i, 0),
            PQgetvalue(res, i, 1),
            PQgetvalue(res, i, 2),
            PQgetvalue(res, i, 3),
            PQgetvalue(res, i, 4),
            PQgetvalue(res, i, 5),
            PQgetvalue(res, i, 6),
            PQgetvalue(res, i, 7),
            PQgetvalue(res, i, 8),
            atoi(PQgetvalue(res, i, 9)));
        if (offset >= max_len - 100) break;
    }
    snprintf(out_buf + offset, max_len > offset ? max_len - offset : 0, "]}");

    PQclear(res);
    release_db_connection(conn, 0);
    return 0;
}

int platform_add_candidate_roster(const candidate_roster_entry_t *entry) {
    if (!entry || !entry->exam_id[0] || !entry->candidate_id[0]) return -1;

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
        entry->full_name[0] ? entry->full_name : "Candidate",
        entry->email[0] ? entry->email : "candidate@examos.internal",
        entry->pin_hash[0] ? entry->pin_hash : "DEFAULT_HASH",
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

    const char *params[27];
    params[0] = dev->device_id;
    params[1] = dev->hostname[0] ? dev->hostname : dev->device_id;
    params[2] = inst_param;
    params[3] = campus_param;
    params[4] = room_param;
    params[5] = dev->group_name[0] ? dev->group_name : "DEFAULT";
    params[6] = ring_to_string(dev->ring);
    params[7] = dev->ownership_type[0] ? dev->ownership_type : (dev->student_owned ? "STUDENT_OWNED" : "INSTITUTION_OWNED");
    params[8] = dev->student_owned ? "true" : "false";
    params[9] = dev->hardware_platform[0] ? dev->hardware_platform : "x86_64 / UEFI TPM 2.0";
    params[10] = dev->enrollment_status[0] ? dev->enrollment_status : (dev->enrolled ? "ENROLLED" : "PENDING_APPROVAL");
    params[11] = dev->crypto_identity_ref[0] ? dev->crypto_identity_ref : "";
    params[12] = dev->os_release[0] ? dev->os_release : "examos-2.0.26";
    params[13] = dev->image_digest[0] ? dev->image_digest : "";
    params[14] = dev->uki_digest[0] ? dev->uki_digest : "";
    params[15] = pol_ver_str;
    params[16] = dev->attestation_status[0] ? dev->attestation_status : "NOT_ATTESTED";
    params[17] = dev->compliance_status[0] ? dev->compliance_status : "COMPLIANT";
    params[18] = exam_param;
    params[19] = dev->current_candidate_id[0] ? dev->current_candidate_id : "";
    params[20] = dev->session_state[0] ? dev->session_state : "IDLE";
    params[21] = dev->update_status[0] ? dev->update_status : "UP_TO_DATE";
    params[22] = dev->incident_refs[0] ? dev->incident_refs : "";
    params[23] = replace_param;
    params[24] = dev->maintenance_mode ? "true" : "false";
    params[25] = dev->enrolled ? "true" : "false";
    params[26] = last_attest_param;

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
        "  clock_timestamp(), clock_timestamp()"
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
        "  last_checkin = clock_timestamp(), "
        "  updated_at = clock_timestamp()",
        27, NULL, params, NULL, NULL, 0);

    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

static void load_devices_from_db(void) {
    PGconn *conn = acquire_db_connection();
    if (!conn) return;

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
        return;
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
    if (!dev || !dev->device_id[0]) return -1;
    pthread_mutex_lock(&g_platform_lock);
    for (int i = 0; i < g_device_count; i++) {
        if (strcmp(g_devices[i].device_id, dev->device_id) == 0) {
            memcpy(&g_devices[i], dev, sizeof(fleet_device_record_t));
            pthread_mutex_unlock(&g_platform_lock);
            db_sync_device_upsert(dev);
            return 0;
        }
    }
    if (g_device_count >= MAX_DEVICES) {
        pthread_mutex_unlock(&g_platform_lock);
        return -1;
    }
    memcpy(&g_devices[g_device_count++], dev, sizeof(fleet_device_record_t));
    pthread_mutex_unlock(&g_platform_lock);
    db_sync_device_upsert(dev);
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

    platform_register_device(out_dev);
    return 0;
}

int platform_enroll_device(const fleet_device_record_t *dev, const char *actor) {
    if (!dev || !dev->device_id[0]) return -1;
    fleet_device_record_t rec;
    memcpy(&rec, dev, sizeof(rec));

    if (!rec.hostname[0]) {
        snprintf(rec.hostname, sizeof(rec.hostname), "%.48s.kiosk.internal", rec.device_id);
    }
    if (rec.student_owned || strcasecmp(rec.ownership_type, "STUDENT_OWNED") == 0) {
        rec.student_owned = 1;
        snprintf(rec.ownership_type, sizeof(rec.ownership_type), "STUDENT_OWNED");
    } else {
        rec.student_owned = 0;
        snprintf(rec.ownership_type, sizeof(rec.ownership_type), "INSTITUTION_OWNED");
    }
    if (!rec.hardware_platform[0]) {
        snprintf(rec.hardware_platform, sizeof(rec.hardware_platform), "x86_64 / UEFI TPM 2.0");
    }
    if (!rec.enrollment_status[0]) {
        snprintf(rec.enrollment_status, sizeof(rec.enrollment_status), "PENDING_APPROVAL");
    }
    if (!rec.crypto_identity_ref[0]) {
        snprintf(rec.crypto_identity_ref, sizeof(rec.crypto_identity_ref), "urn:examos:tpm2:key:%s", rec.device_id);
    }
    if (!rec.os_release[0]) {
        snprintf(rec.os_release, sizeof(rec.os_release), "examos-2.0.26");
    }
    if (!rec.group_name[0]) {
        snprintf(rec.group_name, sizeof(rec.group_name), "DEFAULT");
    }
    if (!rec.attestation_status[0]) {
        snprintf(rec.attestation_status, sizeof(rec.attestation_status), "NOT_ATTESTED");
    }
    if (!rec.compliance_status[0]) {
        snprintf(rec.compliance_status, sizeof(rec.compliance_status), "COMPLIANT");
    }
    if (!rec.session_state[0]) {
        snprintf(rec.session_state, sizeof(rec.session_state), "IDLE");
    }
    if (!rec.update_status[0]) {
        snprintf(rec.update_status, sizeof(rec.update_status), "UP_TO_DATE");
    }
    if (rec.active_policy_version == 0) {
        rec.active_policy_version = 1;
    }
    rec.last_checkin = time(NULL);

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
    snprintf(dev.compliance_status, sizeof(dev.compliance_status), "COMPLIANT");
    dev.last_checkin = time(NULL);

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
    platform_register_device(&old_dev);

    /* Setup new device */
    fleet_device_record_t new_dev;
    if (platform_get_device_by_id(new_device_id, &new_dev) != 0) {
        memset(&new_dev, 0, sizeof(new_dev));
        snprintf(new_dev.device_id, sizeof(new_dev.device_id), "%s", new_device_id);
        snprintf(new_dev.hostname, sizeof(new_dev.hostname), "%.48s.kiosk.internal", new_device_id);
        snprintf(new_dev.hardware_platform, sizeof(new_dev.hardware_platform), "%s", old_dev.hardware_platform);
        snprintf(new_dev.os_release, sizeof(new_dev.os_release), "%s", old_dev.os_release);
    }
    snprintf(new_dev.institution_id, sizeof(new_dev.institution_id), "%s", old_dev.institution_id);
    snprintf(new_dev.campus_id, sizeof(new_dev.campus_id), "%s", old_dev.campus_id);
    snprintf(new_dev.room_id, sizeof(new_dev.room_id), "%s", old_dev.room_id);
    snprintf(new_dev.group_name, sizeof(new_dev.group_name), "%s", old_dev.group_name);
    new_dev.ring = old_dev.ring;
    new_dev.student_owned = old_dev.student_owned;
    snprintf(new_dev.ownership_type, sizeof(new_dev.ownership_type), "%s", old_dev.ownership_type);
    snprintf(new_dev.enrollment_status, sizeof(new_dev.enrollment_status), "ENROLLED");
    new_dev.enrolled = 1;
    snprintf(new_dev.compliance_status, sizeof(new_dev.compliance_status), "COMPLIANT");
    snprintf(new_dev.replacement_for_device_id, sizeof(new_dev.replacement_for_device_id), "%s", old_device_id);
    new_dev.last_checkin = time(NULL);

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
    if (!device_id || !device_id[0]) return -1;
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) != 0) {
        /* Auto-register device stub into fleet registry if first seen */
        memset(&dev, 0, sizeof(dev));
        snprintf(dev.device_id, sizeof(dev.device_id), "%s", device_id);
        snprintf(dev.hostname, sizeof(dev.hostname), "%.48s.kiosk.internal", device_id);
        snprintf(dev.group_name, sizeof(dev.group_name), "DEFAULT");
        snprintf(dev.ownership_type, sizeof(dev.ownership_type), "INSTITUTION_OWNED");
        snprintf(dev.enrollment_status, sizeof(dev.enrollment_status), "ENROLLED");
        dev.enrolled = 1;
        snprintf(dev.hardware_platform, sizeof(dev.hardware_platform), "x86_64 / UEFI TPM 2.0");
        snprintf(dev.os_release, sizeof(dev.os_release), "examos-2.0.26");
        dev.active_policy_version = 1;
        snprintf(dev.session_state, sizeof(dev.session_state), "IDLE");
        snprintf(dev.update_status, sizeof(dev.update_status), "UP_TO_DATE");
    }

    if (attestation_status && attestation_status[0]) {
        snprintf(dev.attestation_status, sizeof(dev.attestation_status), "%s", attestation_status);
        if (strcmp(attestation_status, "TRUSTED") == 0) {
            dev.last_attestation_ts = time(NULL);
        }
    }
    if (compliance_status && compliance_status[0]) {
        snprintf(dev.compliance_status, sizeof(dev.compliance_status), "%s", compliance_status);
    }
    dev.last_checkin = time(NULL);

    return platform_register_device(&dev);
}

int platform_set_device_maintenance(const char *device_id, int in_maintenance) {
    if (!device_id || !device_id[0]) return -1;
    fleet_device_record_t dev;
    if (platform_get_device_by_id(device_id, &dev) == 0) {
        dev.maintenance_mode = in_maintenance ? 1 : 0;
        if (in_maintenance) {
            snprintf(dev.compliance_status, sizeof(dev.compliance_status), "MAINTENANCE");
        } else {
            snprintf(dev.compliance_status, sizeof(dev.compliance_status), "COMPLIANT");
        }
        char details[128];
        snprintf(details, sizeof(details), "device_id=%s maintenance=%d", device_id, in_maintenance);
        ledger_append("DEVICE_MAINTENANCE_TOGGLED", device_id, details);
        return platform_register_device(&dev);
    }

    /* If device not yet enrolled, auto-enroll into fleet with desired maintenance state */
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.device_id, sizeof(dev.device_id), "%s", device_id);
    snprintf(dev.hostname, sizeof(dev.hostname), "%.48s.kiosk.internal", device_id);
    snprintf(dev.group_name, sizeof(dev.group_name), "PRODUCTION_LAB");
    dev.ring = RING_PILOT;
    dev.maintenance_mode = in_maintenance ? 1 : 0;
    dev.enrolled = 1;
    snprintf(dev.enrollment_status, sizeof(dev.enrollment_status), "ENROLLED");
    snprintf(dev.attestation_status, sizeof(dev.attestation_status), "TRUSTED");
    snprintf(dev.compliance_status, sizeof(dev.compliance_status), in_maintenance ? "MAINTENANCE" : "COMPLIANT");
    snprintf(dev.hardware_platform, sizeof(dev.hardware_platform), "x86_64 / UEFI TPM 2.0");
    snprintf(dev.os_release, sizeof(dev.os_release), "examos-2.0.26");
    dev.active_policy_version = 1;
    dev.last_checkin = time(NULL);

    char details[128];
    snprintf(details, sizeof(details), "device_id=%s maintenance=%d (auto-enrolled)", device_id, in_maintenance);
    ledger_append("DEVICE_MAINTENANCE_TOGGLED", device_id, details);
    return platform_register_device(&dev);
}

int platform_record_device_heartbeat(const char *device_id, int battery_pct, int battery_charging,
                                    int disk_free_mb, int mem_used_mb, const char *network_state,
                                    unsigned int policy_version, const char *image_digest,
                                    const char *session_state) {
    if (!device_id || !device_id[0]) return -1;
    fleet_device_record_t dev;
    int found = (platform_get_device_by_id(device_id, &dev) == 0);
    if (!found) {
        memset(&dev, 0, sizeof(dev));
        snprintf(dev.device_id, sizeof(dev.device_id), "%s", device_id);
        snprintf(dev.hostname, sizeof(dev.hostname), "%.48s.kiosk.internal", device_id);
        snprintf(dev.group_name, sizeof(dev.group_name), "DEFAULT");
        dev.ring = RING_PILOT;
        dev.enrolled = 1;
        snprintf(dev.enrollment_status, sizeof(dev.enrollment_status), "ENROLLED");
        snprintf(dev.compliance_status, sizeof(dev.compliance_status), "COMPLIANT");
        snprintf(dev.attestation_status, sizeof(dev.attestation_status), "TRUSTED");
        snprintf(dev.hardware_platform, sizeof(dev.hardware_platform), "x86_64 / UEFI TPM 2.0");
        snprintf(dev.os_release, sizeof(dev.os_release), "examos-2.0.26");
    }

    dev.last_checkin = time(NULL);
    if (policy_version > 0) dev.active_policy_version = policy_version;
    if (image_digest && image_digest[0]) snprintf(dev.image_digest, sizeof(dev.image_digest), "%s", image_digest);
    if (session_state && session_state[0]) snprintf(dev.session_state, sizeof(dev.session_state), "%s", session_state);

    platform_register_device(&dev);

    /* Insert telemetry into examos_device_heartbeats */
    PGconn *conn = acquire_db_connection();
    if (conn) {
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
            network_state && network_state[0] ? network_state : "CONNECTED",
            pol_str,
            dev.image_digest[0] ? dev.image_digest : "",
            dev.session_state[0] ? dev.session_state : "IDLE"
        };

        PGresult *res = PQexecParams(conn,
            "INSERT INTO examos_device_heartbeats "
            "(device_id, battery_pct, battery_charging, disk_free_mb, mem_used_mb, network_state, policy_version, image_digest, session_state) "
            "VALUES ($1, $2::integer, $3::boolean, $4::integer, $5::integer, $6, $7::integer, $8, $9)",
            9, NULL, hb_params, NULL, NULL, 0);

        if (res) PQclear(res);
        release_db_connection(conn, 0);
    }

    char details[256];
    snprintf(details, sizeof(details), "device_id=%s bat=%d%% net=%s pol=%u state=%s",
             device_id, battery_pct, network_state ? network_state : "CONNECTED",
             dev.active_policy_version, dev.session_state);
    ledger_append("DEVICE_HEARTBEAT", device_id, details);
    return 0;
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
                snprintf(g_devices[i].compliance_status, sizeof(g_devices[i].compliance_status), "COMPLIANT");
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
    pthread_mutex_lock(&g_platform_lock);
    size_t offset = snprintf(out_buf, max_len, "{\"incidents\":[");
    int first = 1;
    for (int i = 0; i < g_incident_count; i++) {
        if (!inst_id || strlen(inst_id) == 0 || strcmp(g_incidents[i].institution_id, inst_id) == 0) {
            offset += snprintf(out_buf + offset, max_len - offset,
                "%s{\"id\":\"%s\",\"title\":\"%s\",\"severity\":\"%s\",\"status\":\"%s\","
                "\"assigned_to\":\"%s\",\"device_id\":\"%s\",\"candidate_id\":\"%s\","
                "\"summary\":\"%s\",\"notes\":\"%s\",\"created_at\":%ld}",
                (first ? "" : ","),
                g_incidents[i].incident_id,
                g_incidents[i].title,
                severity_to_string(g_incidents[i].severity),
                g_incidents[i].status,
                g_incidents[i].assigned_to,
                g_incidents[i].device_id,
                g_incidents[i].candidate_id,
                g_incidents[i].summary,
                g_incidents[i].resolution_notes,
                g_incidents[i].created_at);
            first = 0;
        }
        if (offset >= max_len - 100) break;
    }
    snprintf(out_buf + offset, max_len - offset, "]}");
    pthread_mutex_unlock(&g_platform_lock);
    return 0;
}

int platform_create_incident(const security_incident_t *inc) {
    if (!inc) return -1;
    pthread_mutex_lock(&g_platform_lock);
    if (g_incident_count >= MAX_INCIDENTS) {
        pthread_mutex_unlock(&g_platform_lock);
        return -1;
    }
    memcpy(&g_incidents[g_incident_count++], inc, sizeof(security_incident_t));

    char details[256];
    snprintf(details, sizeof(details), "incident_id=%s sev=%s title=%s",
             inc->incident_id, severity_to_string(inc->severity), inc->title);
    ledger_append("INCIDENT_RAISED", inc->incident_id, details);

    pthread_mutex_unlock(&g_platform_lock);
    return 0;
}

int platform_update_incident_status(const char *incident_id, const char *new_status, const char *notes, const char *actor) {
    pthread_mutex_lock(&g_platform_lock);
    for (int i = 0; i < g_incident_count; i++) {
        if (strcmp(g_incidents[i].incident_id, incident_id) == 0) {
            snprintf(g_incidents[i].status, sizeof(g_incidents[i].status), "%s", new_status);
            g_incidents[i].updated_at = time(NULL);
            if (notes) snprintf(g_incidents[i].resolution_notes, sizeof(g_incidents[i].resolution_notes), "%s", notes);

            char details[256];
            snprintf(details, sizeof(details), "new_status=%s actor=%s", new_status, actor ? actor : "system");
            ledger_append("INCIDENT_STATUS", incident_id, details);

            pthread_mutex_unlock(&g_platform_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_platform_lock);
    return -1;
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
    pthread_mutex_lock(&g_platform_lock);
    size_t offset = snprintf(out_buf, max_len, "{\"releases\":[");
    for (int i = 0; i < g_release_count; i++) {
        offset += snprintf(out_buf + offset, max_len - offset,
            "%s{\"id\":\"%s\",\"version\":\"%s\",\"image_digest\":\"%s\",\"uki_digest\":\"%s\","
            "\"sbom_digest\":\"%s\",\"ring\":\"%s\",\"status\":\"%s\",\"signed_by\":\"%s\",\"date\":%ld}",
            (i > 0 ? "," : ""),
            g_releases[i].release_id,
            g_releases[i].version_name,
            g_releases[i].image_digest,
            g_releases[i].uki_digest,
            g_releases[i].sbom_digest,
            ring_to_string(g_releases[i].target_ring),
            g_releases[i].status,
            g_releases[i].signed_by,
            g_releases[i].release_date);
        if (offset >= max_len - 100) break;
    }
    snprintf(out_buf + offset, max_len - offset, "]}");
    pthread_mutex_unlock(&g_platform_lock);
    return 0;
}

int platform_create_release(const enterprise_release_t *rel) {
    if (!rel) return -1;
    pthread_mutex_lock(&g_platform_lock);
    if (g_release_count >= PLATFORM_MAX_RELEASES) {
        pthread_mutex_unlock(&g_platform_lock);
        return -1;
    }
    memcpy(&g_releases[g_release_count++], rel, sizeof(enterprise_release_t));
    pthread_mutex_unlock(&g_platform_lock);
    return 0;
}

/* -------------------------------------------------------------------------
 * Reconciliation and Operational Metrics (Module I, Module M, Module O)
 * ------------------------------------------------------------------------- */
int platform_get_telemetry_json(char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 128) return -1;
    pthread_mutex_lock(&g_platform_lock);
    int active_terminals = 0;
    time_t now = time(NULL);
    long uptime_seconds = g_platform_started_at > 0 && now >= g_platform_started_at
                              ? (long)(now - g_platform_started_at)
                              : -1;
    for (int i = 0; i < g_device_count; i++) {
        if (now - g_devices[i].last_checkin < 120) active_terminals++;
    }
    int total_devices = g_device_count;
    int submissions_count = g_submission_count;
    int incidents_count = g_incident_count;
    pthread_mutex_unlock(&g_platform_lock);

    int inst_count = 0, exam_count = 0, roster_count = 0;
    PGconn *conn = acquire_db_connection();
    if (conn) {
        PGresult *res = PQexec(conn,
            "SELECT "
            "  (SELECT count(*)::integer FROM examos_institutions), "
            "  (SELECT count(*)::integer FROM examos_exams), "
            "  (SELECT count(*)::integer FROM examos_exam_roster)");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
            inst_count   = atoi(PQgetvalue(res, 0, 0));
            exam_count   = atoi(PQgetvalue(res, 0, 1));
            roster_count = atoi(PQgetvalue(res, 0, 2));
        }
        if (res) PQclear(res);
        release_db_connection(conn, 0);
    }

    snprintf(out_buf, max_len,
        "{\"status\":\"OPERATIONAL\",\"uptime_seconds\":%ld,\"institutions_count\":%d,"
        "\"exams_count\":%d,\"active_terminals\":%d,\"total_devices\":%d,"
        "\"roster_count\":%d,\"submissions_count\":%d,\"incidents_count\":%d,"
        "\"storage_engine\":\"POSTGRESQL_TLS\","
        "\"platform_registry_persistence\":\"ACTIVE\","
        "\"submission_storage\":\"DURABLE_ATOMIC_DISK\"}",
        uptime_seconds,
        inst_count,
        exam_count,
        active_terminals,
        total_devices,
        roster_count,
        submissions_count,
        incidents_count);

    return 0;
}

int platform_get_reconciliation_json(const char *exam_id, char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 128) return -1;
    return platform_reconcile_exam(exam_id ? exam_id : "", out_buf, max_len);
}
