/*
 * exam_controller.c — ExamOS Module 9: Examination Management.
 * Comprehensive multi-tenant exam lifecycle, schedules, eligibility,
 * student assignments, ExamOS appliance policies, approvals, and real-time monitoring.
 */

#include "exam_controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../security/security.h"
#include "../include/ledger.h"
#include "../include/enterprise_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void ex_send_json(int fd, int code, const char *body,
                         const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void json_escape(const char *in, char *out, size_t out_len);

static void ex_send_error(int fd, int code, const char *msg,
                          const char *origin, char *extra, size_t extra_len) {
    char escaped[1024];
    char buf[1100];
    json_escape(msg ? msg : "An error occurred", escaped, sizeof(escaped));
    int written = snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", escaped);
    if (written < 0 || (size_t)written >= sizeof(buf)) return;
    ex_send_json(fd, code, buf, origin, extra, extra_len);
}

static const char *exam_mirror_error_message(const char *sqlstate) {
    if (!sqlstate) return "The exam configuration could not be saved. Contact platform support.";
    if (strcmp(sqlstate, "23502") == 0) {
        return "A required exam detail is missing from storage. Review the exam details and try again.";
    }
    if (strcmp(sqlstate, "23503") == 0) {
        return "A linked institution record is unavailable. Reload the exam setup and verify its selections.";
    }
    if (strcmp(sqlstate, "23505") == 0) {
        return "This exam code or identifier already exists. Choose a different exam code and try again.";
    }
    if (strcmp(sqlstate, "42703") == 0 || strcmp(sqlstate, "42P01") == 0) {
        return "Exam storage is missing a required database field or table. Contact platform support.";
    }
    if (strcmp(sqlstate, "22P02") == 0 || strcmp(sqlstate, "23514") == 0) {
        return "An exam configuration value is not accepted by storage. Review the exam details and try again.";
    }
    return "The exam configuration could not be saved. Contact platform support.";
}

static void audit_log(const char *actor, const char *event, const char *target, const char *detail) {
    audit_append(actor ? actor : "system", event, detail ? detail : "");
    ledger_block_t blk;
    ledger_append_event(event, target ? target : "EXAM", detail ? detail : "", &blk);
}

static void json_escape(const char *in, char *out, size_t out_len) {
    if (!in || !out || out_len == 0) return;
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"') {
            if (j + 2 < out_len) { out[j++] = '\\'; out[j++] = '"'; }
        } else if (c == '\\') {
            if (j + 2 < out_len) { out[j++] = '\\'; out[j++] = '\\'; }
        } else if (c == '\n') {
            if (j + 2 < out_len) { out[j++] = '\\'; out[j++] = 'n'; }
        } else if (c == '\r') {
            if (j + 2 < out_len) { out[j++] = '\\'; out[j++] = 'r'; }
        } else if (c == '\t') {
            if (j + 2 < out_len) { out[j++] = '\\'; out[j++] = 't'; }
        } else if (c >= 32 && c <= 126) {
            out[j++] = c;
        } else {
            out[j++] = ' ';
        }
    }
    out[j] = '\0';
}

/* Parse exam id and suffix from path: /api/v1/examinations/:id[/suffix] */
static int parse_examination_path(const char *path, char *out_id, size_t id_len, char *out_suffix, size_t suffix_len) {
    const char *prefix = "/api/v1/examinations/";
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) != 0) return 0;
    const char *rest = path + plen;
    const char *slash = strchr(rest, '/');
    size_t ilen = slash ? (size_t)(slash - rest) : strlen(rest);
    if (ilen == 0 || ilen >= id_len) return 0;
    memcpy(out_id, rest, ilen);
    out_id[ilen] = '\0';
    if (slash) {
        strncpy(out_suffix, slash, suffix_len - 1);
        out_suffix[suffix_len - 1] = '\0';
    } else {
        out_suffix[0] = '\0';
    }
    return 1;
}

/* Parse legacy exam id from /api/v1/platform/exams/:id/... */
static int ex_parse_legacy_id(const char *path, char *out, size_t out_len) {
    const char *prefix = "/api/v1/platform/exams/";
    if (strncmp(path, prefix, strlen(prefix)) != 0) return 0;
    const char *rest = path + strlen(prefix);
    const char *slash = strchr(rest, '/');
    size_t len = slash ? (size_t)(slash - rest) : strlen(rest);
    if (len == 0 || len >= out_len) return 0;
    memcpy(out, rest, len);
    out[len] = '\0';
    return 1;
}

/* Helper to record status change in exam_status_history */
static void record_status_history(PGconn *conn, const char *exam_id, const char *from_status,
                                  const char *to_status, const char *actor_id, const char *reason) {
    char hid[64];
    snprintf(hid, sizeof(hid), "esh_%ld_%d", (long)time(NULL), rand() % 10000);
    char now_str[32];
    snprintf(now_str, sizeof(now_str), "%ld", (long)time(NULL) * 1000);
    const char *p[6] = { hid, exam_id, from_status, to_status, actor_id, reason ? reason : "" };
    int l[6] = { (int)strlen(hid), (int)strlen(exam_id), (int)strlen(from_status),
                 (int)strlen(to_status), (int)strlen(actor_id), (int)strlen(reason ? reason : "") };
    PGresult *r = db_simple(conn,
        "INSERT INTO exam_status_history (id, exam_id, from_status, to_status, actor_id, reason, created_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
        6, p, l);
    if (r) PQclear(r);
}

/* Helper to record exam audit log */
static void record_exam_audit(PGconn *conn, const char *exam_id, const char *inst_id,
                             const char *actor_id, const char *action, const char *summary) {
    char aid[64];
    snprintf(aid, sizeof(aid), "eaud_%ld_%d", (long)time(NULL), rand() % 10000);
    const char *p[6] = { aid, exam_id, inst_id, actor_id, action, summary ? summary : "" };
    int l[6] = { (int)strlen(aid), (int)strlen(exam_id), (int)strlen(inst_id),
                 (int)strlen(actor_id), (int)strlen(action), (int)strlen(summary ? summary : "") };
    PGresult *r = db_simple(conn,
        "INSERT INTO exam_audit_logs (id, exam_id, institution_id, actor_id, action, change_summary, created_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
        6, p, l);
    if (r) PQclear(r);
}

static int validate_exam_config(PGconn *conn, const char *config, const char *exam_url,
                                const char *instructions, const char *institution_id,
                                int require_ready) {
    const char *values[5] = {
        config, exam_url, instructions, institution_id, require_ready ? "true" : "false"
    };
    int lengths[5] = {
        (int)strlen(config), (int)strlen(exam_url), (int)strlen(instructions),
        (int)strlen(institution_id), (int)strlen(values[4])
    };
    PGresult *result = db_simple(conn,
        "SELECT CASE WHEN "
        "jsonb_typeof($1::jsonb) = 'object' "
        "AND length(trim(COALESCE($1::jsonb->>'title',''))) BETWEEN 4 AND 100 "
        "AND COALESCE($1::jsonb->>'code','') ~ '^[A-Z0-9-]{4,20}$' "
        "AND COALESCE($1::jsonb->>'type','') IN ('practice','internal','laboratory','midterm','final') "
        "AND jsonb_typeof($1::jsonb->'course') = 'string' AND length($1::jsonb->>'course') <= 80 "
        "AND jsonb_typeof($1::jsonb->'departmentId') = 'string' AND length($1::jsonb->>'departmentId') <= 64 "
        "AND jsonb_typeof($1::jsonb->'academicYear') = 'string' AND length($1::jsonb->>'academicYear') <= 20 "
        "AND jsonb_typeof($1::jsonb->'description') = 'string' AND length($1::jsonb->>'description') <= 1000 "
        "AND jsonb_typeof($1::jsonb->'resources') = 'string' AND length($1::jsonb->>'resources') <= 1000 "
        "AND jsonb_typeof($1::jsonb->'accommodations') = 'string' AND length($1::jsonb->>'accommodations') <= 1000 "
        "AND ($1::jsonb->>'examUrl') = $2 "
        "AND length($2) <= 500 AND $2 ~ '^https://[^/@?#]+([/?#].*)?$' "
        "AND ($1::jsonb->>'instructions') = $3 AND length(trim($3)) > 0 AND length($3) <= 3000 "
        "AND COALESCE($1::jsonb->>'authMode','') IN ('candidate-login','exam-token','proctor-verify') "
        "AND jsonb_typeof($1::jsonb->'identityRequired') = 'boolean' "
        "AND CASE WHEN COALESCE($1::jsonb->>'startAt','') ~ '^[0-9]+$' "
        "THEN ($1::jsonb->>'startAt')::numeric > 0 ELSE false END "
        "AND CASE WHEN COALESCE($1::jsonb->>'durationMin','') ~ '^[0-9]+$' "
        "THEN ($1::jsonb->>'durationMin')::integer BETWEEN 15 AND 300 ELSE false END "
        "AND CASE WHEN COALESCE($1::jsonb->>'lateEntryMin','') ~ '^[0-9]+$' "
        "THEN ($1::jsonb->>'lateEntryMin')::integer BETWEEN 0 AND 60 ELSE false END "
        "AND CASE WHEN COALESCE($1::jsonb->>'capacity','') ~ '^[0-9]+$' "
        "THEN ($1::jsonb->>'capacity')::integer BETWEEN 0 AND 1000000 ELSE false END "
        "AND CASE WHEN COALESCE($1::jsonb->>'sessionTimeoutMin','') ~ '^[0-9]+$' "
        "THEN ($1::jsonb->>'sessionTimeoutMin')::integer BETWEEN 5 AND 120 ELSE false END "
        /* Timezone validation: check the common set first (O(1)), then fall
         * back to the pg_timezone_names catalog only for unusual values.
         * This avoids a sequential scan of the catalog on every config save. */
        "AND CASE WHEN $1::jsonb->>'timezone' IN ("
        "  'Asia/Kolkata','Asia/Calcutta','UTC','Etc/UTC','GMT','US/Eastern','US/Central','US/Mountain','US/Pacific',"
        "  'America/New_York','America/Chicago','America/Denver','America/Los_Angeles','America/Toronto',"
        "  'Europe/London','Europe/Paris','Europe/Berlin','Europe/Moscow','Europe/Istanbul',"
        "  'Asia/Dubai','Asia/Singapore','Asia/Tokyo','Asia/Seoul','Asia/Shanghai','Asia/Bangkok',"
        "  'Australia/Sydney','Pacific/Auckland','Africa/Lagos','Africa/Nairobi','Africa/Cairo'"
        ") THEN true "
        "ELSE EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = $1::jsonb->>'timezone') "
        "END "
        "AND COALESCE($1::jsonb->>'navigation','') IN ('locked','allowlist') "
        "AND COALESCE($1::jsonb->>'submissionMode','') IN ('manual','auto','either') "
        "AND COALESCE($1::jsonb->>'reconnectPolicy','') IN ('allow-reconnect','resume-only','deny') "
        "AND COALESCE($1::jsonb->>'attestationLevel','') IN ('none','tpm','tpm-secureboot') "
        "AND COALESCE($1::jsonb->>'compatibilityProfile','') IN ('standard-uefi','secure-lab','legacy-bios') "
        "AND CASE WHEN jsonb_typeof($1::jsonb->'centerIds') = 'array' THEN "
        "  (NOT ($5::boolean) OR jsonb_array_length($1::jsonb->'centerIds') > 0) "
        "  AND (SELECT COUNT(*) FROM centers c WHERE c.tenant_id = $4 AND c.status = 'active' "
        "       AND c.id IN (SELECT jsonb_array_elements_text($1::jsonb->'centerIds'))) "
        "      = jsonb_array_length($1::jsonb->'centerIds') "
        "  ELSE false END "
        "AND CASE WHEN jsonb_typeof($1::jsonb->'origins') = 'array' THEN "
        "  EXISTS (SELECT 1 FROM jsonb_array_elements_text($1::jsonb->'origins') o(value) "
        "          WHERE o.value = regexp_replace($2, '^(https://[^/?#]+).*$','\\1')) "
        "  AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1::jsonb->'origins') o(value) "
        "                 WHERE o.value !~ '^https://[^/@?#]+$') "
        "  ELSE false END "
        "AND CASE WHEN jsonb_typeof($1::jsonb->'allowedDestinations') = 'array' THEN "
        "  (COALESCE($1::jsonb->>'navigation','') <> 'allowlist' OR jsonb_array_length($1::jsonb->'allowedDestinations') > 0) "
        "  AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1::jsonb->'allowedDestinations') d(value) "
        "                  WHERE d.value !~ '^https://[^/@?#]+$' "
        "                     OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1::jsonb->'origins') o(value) WHERE o.value = d.value)) "
        "  ELSE false END "
        "AND CASE WHEN jsonb_typeof($1::jsonb->'requiredChecks') = 'array' THEN "
        "  NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text($1::jsonb->'requiredChecks') c(value) "
        "              WHERE c.value NOT IN ('uefi','usb','tpm','secureboot','network','display','keyboard','battery','camera','microphone')) "
        "  ELSE false END "
        "AND CASE WHEN NULLIF($1::jsonb->>'policyId','') IS NULL THEN NOT $5::boolean ELSE EXISTS ("
        "  SELECT 1 FROM console_records p WHERE p.collection = 'policies' "
        "  AND p.record_id = $1::jsonb->>'policyId' AND p.institution_id = $4 "
        "  AND p.data->>'tenantId' = $4 AND p.data->>'status' = 'published' "
        "  AND length(COALESCE(p.data->>'hash','')) > 0 AND length(COALESCE(p.data->>'sig','')) > 0 "
        "  AND CASE WHEN jsonb_typeof(p.data->'config'->'origins') = 'array' THEN "
        "    EXISTS (SELECT 1 FROM jsonb_array_elements_text(p.data->'config'->'origins') po(value) "
        "            WHERE regexp_replace(po.value, '^(https://[^/?#]+).*$','\\1') = regexp_replace($2, '^(https://[^/?#]+).*$','\\1') "
        "              AND po.value ~ '^https://[^/@?#]+([/?#].*)?$') "
        "    ELSE false END "
        ") END "
        "THEN 'true' ELSE 'false' END",
        5, values, lengths);
    if (!result || PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) != 1) {
        if (result) PQclear(result);
        return -1;
    }
    int valid = strcmp(PQgetvalue(result, 0, 0), "true") == 0;
    if (result) PQclear(result);
    return valid;
}

void exam_handle(int client_fd, const char *method, const char *path,
                 const char *body, const char *auth_header,
                 const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    memset(&sess, 0, sizeof(sess));
    int auth_rc = ctrl_authorize(auth_header, AUTH_PERM_READ, &sess);
    char candidate_id[64] = {0};
    int is_candidate = ctrl_candidate_session_identity(auth_header, candidate_id, sizeof(candidate_id));
    if (auth_rc != 0 && !is_candidate) {
        ex_send_error(client_fd, 401, "Admin credentials required", origin, extra_headers, extra_len);
        return;
    }

    int is_owner = (auth_rc == 0 && sess.role == ROLE_PLATFORM_OWNER);
    if (is_candidate && (strcmp(method, "GET") != 0 ||
        strcmp(path, "/api/v1/examinations") == 0 ||
        strcmp(path, "/api/v1/admin/exams") == 0)) {
        ex_send_error(client_fd, 403, "Candidates may only view their assigned examination", origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 1. GET /api/v1/examinations or /api/v1/admin/exams: List examinations
     * ========================================================================= */
    if (strcmp(method, "GET") == 0 &&
        (strcmp(path, "/api/v1/examinations") == 0 || strcmp(path, "/api/v1/admin/exams") == 0)) {
        PGconn *conn = db_acquire();
        PGresult *res = NULL;
        const char *pvals[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };

        if (is_owner) {
            res = PQexec(conn,
                "SELECT id, institution_id, code, name, subject, academic_year, exam_type, "
                "duration_minutes, total_marks, passing_marks, status, instructions, exam_url, "
                "allowed_origins, policy_id, created_by, created_at, updated_at, exam_config::text "
                "FROM examinations ORDER BY created_at DESC");
        } else {
            res = db_simple(conn,
                "SELECT id, institution_id, code, name, subject, academic_year, exam_type, "
                "duration_minutes, total_marks, passing_marks, status, instructions, exam_url, "
                "allowed_origins, policy_id, created_by, created_at, updated_at, exam_config::text "
                "FROM examinations WHERE institution_id = $1 ORDER BY created_at DESC",
                1, pvals, lens);
        }

        char *json = malloc(262144);
        if (!json) {
            if (res) PQclear(res);
            db_release(conn, 0);
            ex_send_error(client_fd, 500, "Out of memory", origin, extra_headers, extra_len);
            return;
        }

        size_t pos = 0;
        pos += snprintf(json + pos, 262144 - pos, "{\"examinations\":[");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            int n = PQntuples(res);
            for (int i = 0; i < n; i++) {
                if (i > 0) pos += snprintf(json + pos, 262144 - pos, ",");
                char esc_name[256], esc_subj[256], esc_url[512];
                json_escape(PQgetvalue(res, i, 3), esc_name, sizeof(esc_name));
                json_escape(PQgetvalue(res, i, 4), esc_subj, sizeof(esc_subj));
                json_escape(PQgetvalue(res, i, 12), esc_url, sizeof(esc_url));

                pos += snprintf(json + pos, 262144 - pos,
                    "{\"id\":\"%s\",\"institution_id\":\"%s\",\"code\":\"%s\","
                    "\"name\":\"%s\",\"subject\":\"%s\",\"academic_year\":\"%s\","
                    "\"exam_type\":\"%s\",\"duration_minutes\":%s,\"total_marks\":%s,"
                    "\"passing_marks\":%s,\"status\":\"%s\",\"exam_url\":\"%s\","
                    "\"allowed_origins\":\"%s\",\"policy_id\":\"%s\",\"created_by\":\"%s\","
                    "\"created_at\":%s,\"updated_at\":%s,\"exam_config\":%s}",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                    esc_name, esc_subj, PQgetvalue(res, i, 5),
                    PQgetvalue(res, i, 6), PQgetvalue(res, i, 7), PQgetvalue(res, i, 8),
                    PQgetvalue(res, i, 9), PQgetvalue(res, i, 10), esc_url,
                    PQgetvalue(res, i, 13), PQgetvalue(res, i, 14), PQgetvalue(res, i, 15),
                    PQgetvalue(res, i, 16), PQgetvalue(res, i, 17), PQgetvalue(res, i, 18));
            }
        }
        int total = res ? PQntuples(res) : 0;
        if (res) PQclear(res);
        pos += snprintf(json + pos, 262144 - pos, "],\"total\":%d}", total);
        db_release(conn, 0);

        ex_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        free(json);
        return;
    }

    /* =========================================================================
     * 2. POST /api/v1/examinations: Create examination
     * ========================================================================= */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/examinations") == 0) {
        if (sess.role != ROLE_PLATFORM_OWNER && sess.role != ROLE_INSTITUTION_ADMIN &&
            sess.role != ROLE_EXAM_MANAGER) {
            ex_send_error(client_fd, 403, "Exam mutation permission required", origin, extra_headers, extra_len);
            return;
        }

        char name[128] = {0}, subject[128] = {0}, code[32] = {0}, academic_year[32] = {0};
        char exam_type[32] = {0}, instructions[2048] = {0}, exam_url[512] = {0}, allowed_origins[512] = {0};
        char exam_config[8192] = {0};
        char inst_id[64] = {0};
        int duration_minutes = 60, total_marks = 100, passing_marks = 40;

        ctrl_json_string(body, "name", name, sizeof(name));
        if (!name[0]) ctrl_json_string(body, "title", name, sizeof(name));
        ctrl_json_string(body, "subject", subject, sizeof(subject));
        if (!subject[0]) ctrl_json_string(body, "course", subject, sizeof(subject));
        if (!subject[0] && name[0]) snprintf(subject, sizeof(subject), "%s", name);
        ctrl_json_string(body, "code", code, sizeof(code));
        ctrl_json_string(body, "academic_year", academic_year, sizeof(academic_year));
        ctrl_json_string(body, "exam_type", exam_type, sizeof(exam_type));
        ctrl_json_string(body, "instructions", instructions, sizeof(instructions));
        ctrl_json_string(body, "exam_url", exam_url, sizeof(exam_url));
        ctrl_json_string(body, "allowed_origins", allowed_origins, sizeof(allowed_origins));
        ctrl_json_string(body, "exam_config_json", exam_config, sizeof(exam_config));
        ctrl_json_string(body, "institution_id", inst_id, sizeof(inst_id));
        ctrl_json_int(body, "duration_minutes", &duration_minutes);
        ctrl_json_int(body, "total_marks", &total_marks);
        ctrl_json_int(body, "passing_marks", &passing_marks);

        /* Scoping */
        if (!is_owner || !inst_id[0]) {
            snprintf(inst_id, sizeof(inst_id), "%s", sess.institution_id[0] ? sess.institution_id : "");
        }
        /* Reject if no institution scope can be determined */
        if (!inst_id[0]) {
            ex_send_error(client_fd, 400, "institution_id is required for non-owner users", origin, extra_headers, extra_len);
            return;
        }

        if (!name[0] || !subject[0] || !exam_url[0] || !instructions[0] || !exam_config[0]) {
            ex_send_error(client_fd, 400, "name, subject, exam_url, candidate instructions and exam configuration are required", origin, extra_headers, extra_len);
            return;
        }
        if (strlen(exam_url) <= 8 || strncmp(exam_url, "https://", 8) != 0) {
            ex_send_error(client_fd, 400, "exam_url must use HTTPS", origin, extra_headers, extra_len);
            return;
        }

        if (duration_minutes < 15 || duration_minutes > 300) {
            ex_send_error(client_fd, 400, "duration_minutes must be between 15 and 300", origin, extra_headers, extra_len);
            return;
        }

        /* No fabricated default academic_year — use what the client sends or empty string */
        /* No fabricated default exam_type — use what the client sends or empty string */

        /* Auto-generate code if absent */
        if (!code[0]) {
            snprintf(code, sizeof(code), "EXAM-%ld", (long)time(NULL) % 1000000);
        }

        /* Generate ID */
        char exam_id[64];
        snprintf(exam_id, sizeof(exam_id), "exm_%ld_%d", (long)time(NULL), rand() % 10000);

        char dur_str[16], tot_str[16], pass_str[16], now_str[32];
        snprintf(dur_str, sizeof(dur_str), "%d", duration_minutes);
        snprintf(tot_str, sizeof(tot_str), "%d", total_marks);
        snprintf(pass_str, sizeof(pass_str), "%d", passing_marks);
        snprintf(now_str, sizeof(now_str), "%ld", (long)time(NULL) * 1000);

        PGconn *conn = db_acquire();

        /* Check for duplicate code within this institution */
        const char *chk_p[2] = { inst_id, code };
        int chk_l[2] = { (int)strlen(inst_id), (int)strlen(code) };
        PGresult *chk_res = db_simple(conn,
            "SELECT id FROM examinations WHERE institution_id = $1 AND code = $2",
            2, chk_p, chk_l);
        if (chk_res && PQntuples(chk_res) > 0) {
            PQclear(chk_res);
            db_release(conn, 0);
            ex_send_error(client_fd, 409, "Exam code already exists for this institution", origin, extra_headers, extra_len);
            return;
        }
        if (chk_res) PQclear(chk_res);

        int config_valid = validate_exam_config(conn, exam_config, exam_url, instructions, inst_id, 0);
        if (config_valid <= 0) {
            db_release(conn, 0);
            ex_send_error(client_fd, config_valid < 0 ? 500 : 400,
                          config_valid < 0 ? "Could not validate exam configuration against the database" :
                          "Exam configuration contains invalid, unsupported, or institution-inaccessible values",
                          origin, extra_headers, extra_len);
            return;
        }

        PGresult *center_check = db_simple(conn,
            "SELECT COUNT(*)::text, jsonb_array_length(($2::jsonb)->'centerIds')::text "
            "FROM centers WHERE tenant_id = $1 AND status = 'active' "
            "AND id IN (SELECT jsonb_array_elements_text(($2::jsonb)->'centerIds'))",
            2, (const char *[]){ inst_id, exam_config },
            (int[]){ (int)strlen(inst_id), (int)strlen(exam_config) });
        if (!center_check || PQresultStatus(center_check) != PGRES_TUPLES_OK ||
            strtol(PQgetvalue(center_check, 0, 0), NULL, 10) !=
            strtol(PQgetvalue(center_check, 0, 1), NULL, 10)) {
            if (center_check) PQclear(center_check);
            db_release(conn, 0);
            ex_send_error(client_fd, 400, "Every selected exam center must be active and belong to this institution", origin, extra_headers, extra_len);
            return;
        }
        PQclear(center_check);

        PGresult *begin = PQexec(conn, "BEGIN");
        if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
            if (begin) PQclear(begin);
            db_release(conn, 1);
            ex_send_error(client_fd, 500, "Could not start exam creation transaction", origin, extra_headers, extra_len);
            return;
        }
        PQclear(begin);

        const char *p[16] = {
            exam_id, inst_id, code, name, subject, academic_year, exam_type,
            dur_str, tot_str, pass_str, instructions, exam_url, allowed_origins,
            sess.user_id, now_str, exam_config
        };
        int l[16] = {
            (int)strlen(exam_id), (int)strlen(inst_id), (int)strlen(code),
            (int)strlen(name), (int)strlen(subject), (int)strlen(academic_year),
            (int)strlen(exam_type), (int)strlen(dur_str), (int)strlen(tot_str),
            (int)strlen(pass_str), (int)strlen(instructions), (int)strlen(exam_url),
            (int)strlen(allowed_origins), (int)strlen(sess.user_id), (int)strlen(now_str),
            (int)strlen(exam_config)
        };

        PGresult *r = db_simple(conn,
            "INSERT INTO examinations ("
            "  id, institution_id, code, name, subject, academic_year, exam_type, "
            "  duration_minutes, total_marks, passing_marks, instructions, exam_url, "
            "  allowed_origins, status, created_by, created_at, updated_at, exam_config"
            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8::integer, $9::integer, $10::integer, $11, $12, $13, 'draft', $14, $15::bigint, $15::bigint, $16::jsonb)",
            16, p, l);

        int ok = (r && PQresultStatus(r) == PGRES_COMMAND_OK);
        char err_detail[256] = {0};
        if (!ok) {
            snprintf(err_detail, sizeof(err_detail), "%s", PQerrorMessage(conn));
        }
        if (r) PQclear(r);

        if (!ok) {
            char err_buf[512];
            snprintf(err_buf, sizeof(err_buf), "Failed to create examination: %s", err_detail[0] ? err_detail : "database error");
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            ex_send_error(client_fd, 500, err_buf, origin, extra_headers, extra_len);
            return;
        }

        /* Keep the complete operational configuration in the canonical exam record. */
        const char *m_p[8] = { exam_id, inst_id, code, name, subject, now_str, exam_config, sess.user_id };
        int m_l[8] = { (int)strlen(exam_id), (int)strlen(inst_id), (int)strlen(code), (int)strlen(name), (int)strlen(subject), (int)strlen(now_str), (int)strlen(exam_config), (int)strlen(sess.user_id) };
        PGresult *m_r = db_simple(conn,
            "INSERT INTO exams (id, tenant_id, code, title, description, course, department_id, academic_year, "
            "type, center_ids, start_at, duration_min, timezone, late_entry_min, capacity, instructions, resources, "
            "accommodations, auth_mode, identity_required, origins, navigation, allowed_destinations, compatibility_profile, "
            "attestation_level, session_timeout_min, reconnect_policy, submission_mode, required_checks, policy_id, exam_url, "
            "created_at, updated_at, status, created_by) "
            "SELECT $1, $2, $3, $4, COALESCE($7::jsonb->>'description',''), COALESCE($7::jsonb->>'course', $5::varchar), "
            "NULLIF($7::jsonb->>'departmentId',''), COALESCE($7::jsonb->>'academicYear',''), "
            "COALESCE($7::jsonb->>'type','internal'), COALESCE($7::jsonb->'centerIds','[]'::jsonb), "
            "($7::jsonb->>'startAt')::bigint, ($7::jsonb->>'durationMin')::integer, "
            "COALESCE($7::jsonb->>'timezone','Asia/Kolkata'), COALESCE(($7::jsonb->>'lateEntryMin')::integer,0), "
            "COALESCE(($7::jsonb->>'capacity')::integer,0), COALESCE($7::jsonb->>'instructions',''), "
            "COALESCE($7::jsonb->>'resources',''), COALESCE($7::jsonb->>'accommodations',''), "
            "COALESCE($7::jsonb->>'authMode','candidate-login'), "
            "CASE WHEN COALESCE($7::jsonb->>'identityRequired','true') = 'true' THEN 1 ELSE 0 END, "
            "COALESCE($7::jsonb->'origins','[]'::jsonb), COALESCE($7::jsonb->>'navigation','locked'), "
            "COALESCE($7::jsonb->'allowedDestinations','[]'::jsonb), "
            "COALESCE($7::jsonb->>'compatibilityProfile','standard-uefi'), "
            "COALESCE($7::jsonb->>'attestationLevel','tpm'), COALESCE(($7::jsonb->>'sessionTimeoutMin')::integer,15), "
            "COALESCE($7::jsonb->>'reconnectPolicy','allow-reconnect'), COALESCE($7::jsonb->>'submissionMode','either'), "
            "COALESCE($7::jsonb->'requiredChecks','[]'::jsonb), NULLIF($7::jsonb->>'policyId',''), "
            "$7::jsonb->>'examUrl', $6::bigint, $6::bigint, 'draft', $8 "
            "ON CONFLICT (id) DO UPDATE SET exam_url = EXCLUDED.exam_url, title = EXCLUDED.title",
            8, m_p, m_l);
        if (!m_r || PQresultStatus(m_r) != PGRES_COMMAND_OK) {
            char sqlstate[6] = {0};
            const char *error_state = m_r ? PQresultErrorField(m_r, PG_DIAG_SQLSTATE) : NULL;
            const char *table = m_r ? PQresultErrorField(m_r, PG_DIAG_TABLE_NAME) : NULL;
            const char *column = m_r ? PQresultErrorField(m_r, PG_DIAG_COLUMN_NAME) : NULL;
            const char *constraint = m_r ? PQresultErrorField(m_r, PG_DIAG_CONSTRAINT_NAME) : NULL;
            if (error_state) snprintf(sqlstate, sizeof(sqlstate), "%s", error_state);
            const char *client_error = exam_mirror_error_message(sqlstate[0] ? sqlstate : NULL);
            fprintf(stderr,
                "[EXAM DB ERROR] operation=configuration_mirror sqlstate=%s table=%s column=%s constraint=%s\n",
                sqlstate[0] ? sqlstate : "unknown",
                table ? table : "unknown",
                column ? column : "unknown",
                constraint ? constraint : "unknown");
            if (m_r) PQclear(m_r);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            ex_send_error(client_fd, 500, client_error, origin, extra_headers, extra_len);
            return;
        }
        if (m_r) PQclear(m_r);

        char schedule_id[64];
        snprintf(schedule_id, sizeof(schedule_id), "esch_%ld_%d", (long)time(NULL), rand() % 10000);
        const char *sch_p[5] = { schedule_id, exam_id, inst_id, code, exam_config };
        int sch_l[5] = { (int)strlen(schedule_id), (int)strlen(exam_id), (int)strlen(inst_id), (int)strlen(code), (int)strlen(exam_config) };
        PGresult *sch_r = db_simple(conn,
            "INSERT INTO exam_schedules (id, exam_id, institution_id, session_name, start_time, end_time, timezone, created_at) "
            "SELECT $1, $2, $3, $4, ($5::jsonb->>'startAt')::bigint, "
            "($5::jsonb->>'startAt')::bigint + ($5::jsonb->>'durationMin')::bigint * 60000, "
            "COALESCE($5::jsonb->>'timezone','Asia/Kolkata'), EXTRACT(EPOCH FROM NOW())::BIGINT * 1000",
            5, sch_p, sch_l);
        if (!sch_r || PQresultStatus(sch_r) != PGRES_COMMAND_OK) {
            if (sch_r) PQclear(sch_r);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            ex_send_error(client_fd, 500, "Failed to persist exam schedule", origin, extra_headers, extra_len);
            return;
        }
        PQclear(sch_r);

        record_status_history(conn, exam_id, "none", "draft", sess.user_id, "Exam created in draft state");
        record_exam_audit(conn, exam_id, inst_id, sess.user_id, "EXAM_CREATED", name);

        PGresult *commit = PQexec(conn, "COMMIT");
        if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
            if (commit) PQclear(commit);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 1);
            ex_send_error(client_fd, 500, "Failed to commit exam configuration", origin, extra_headers, extra_len);
            return;
        }
        PQclear(commit);
        audit_log(sess.user_id, "EXAM_CREATED", exam_id, name);
        db_release(conn, 0);

        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"created\",\"exam_id\":\"%s\",\"code\":\"%s\",\"name\":\"%s\","
            "\"institution_id\":\"%s\",\"exam_url\":\"%s\",\"lifecycle_status\":\"draft\"}",
            exam_id, code, name, inst_id, exam_url);
        ex_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 3. ID-based routes: /api/v1/examinations/:id[...]
     * ========================================================================= */
    char eid[64] = {0};
    char suffix[64] = {0};
    if (parse_examination_path(path, eid, sizeof(eid), suffix, sizeof(suffix))) {
        PGconn *conn = db_acquire();

        /* Verify existence and check tenant scoping */
        const char *chk_p[1] = { eid };
        int chk_l[1] = { (int)strlen(eid) };
        PGresult *exam_res = db_simple(conn,
            "SELECT id, institution_id, code, name, subject, academic_year, exam_type, "
            "duration_minutes, total_marks, passing_marks, status, instructions, exam_url, "
            "allowed_origins, policy_id, created_by, created_at, updated_at, exam_config::text, "
            "COALESCE(cancel_reason, ''), COALESCE(cancelled_at, 0) "
            "FROM examinations WHERE id = $1",
            1, chk_p, chk_l);

        if (!exam_res || PQntuples(exam_res) == 0) {
            if (exam_res) PQclear(exam_res);
            db_release(conn, 0);
            ex_send_error(client_fd, 404, "Examination not found", origin, extra_headers, extra_len);
            return;
        }

        const char *ex_inst_id = PQgetvalue(exam_res, 0, 1);
        const char *ex_status = PQgetvalue(exam_res, 0, 10);
        const char *ex_creator = PQgetvalue(exam_res, 0, 15);

        if (is_candidate) {
            PGresult *cr = db_simple(conn,
                "SELECT 1 FROM candidates WHERE id = $1 AND exam_id = $2 AND tenant_id = $3",
                3, (const char *[]){ candidate_id, eid, ex_inst_id },
                (int[]){ (int)strlen(candidate_id), (int)strlen(eid), (int)strlen(ex_inst_id) });
            int assigned = cr && PQresultStatus(cr) == PGRES_TUPLES_OK && PQntuples(cr) == 1;
            if (cr) PQclear(cr);
            if (!assigned || suffix[0] != '\0') {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 403, "Examination is not assigned to this candidate", origin, extra_headers, extra_len);
                return;
            }
        } else if (!is_owner && strcmp(ex_inst_id, sess.institution_id) != 0) {
            PQclear(exam_res);
            db_release(conn, 0);
            ex_send_error(client_fd, 403, "Access to other institution's exam is prohibited", origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- GET /api/v1/examinations/:id (Full Details) ---------------- */
        if (strcmp(method, "GET") == 0 && suffix[0] == '\0') {
            /* Also fetch schedules, eligibility, and policy */
            PGresult *sched_res = db_simple(conn,
                "SELECT id, session_name, start_time, end_time, timezone, campus_id, department_id, room_id "
                "FROM exam_schedules WHERE exam_id = $1 ORDER BY start_time ASC",
                1, chk_p, chk_l);

            PGresult *pol_res = db_simple(conn,
                "SELECT required_os_release, permitted_application, require_tpm, require_secure_boot, "
                "kiosk_lockdown, block_usb, block_clipboard, block_screen_capture "
                "FROM exam_os_policies WHERE exam_id = $1 LIMIT 1",
                1, chk_p, chk_l);
            PGresult *history_res = db_simple(conn,
                "SELECT from_status, to_status, actor_id, COALESCE(reason, ''), created_at "
                "FROM exam_status_history WHERE exam_id = $1 ORDER BY created_at ASC, id ASC",
                1, chk_p, chk_l);
            if (!history_res || PQresultStatus(history_res) != PGRES_TUPLES_OK) {
                if (history_res) PQclear(history_res);
                PQclear(exam_res);
                if (sched_res) PQclear(sched_res);
                if (pol_res) PQclear(pol_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 500, "Failed to load examination lifecycle history", origin, extra_headers, extra_len);
                return;
            }

            char *json = malloc(65536);
            if (!json) {
                PQclear(exam_res);
                if (sched_res) PQclear(sched_res);
                if (pol_res) PQclear(pol_res);
                PQclear(history_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 500, "Out of memory", origin, extra_headers, extra_len);
                return;
            }

            char esc_name[256], esc_subj[256], esc_inst[1024], esc_url[512], esc_cancel_reason[1024];
            json_escape(PQgetvalue(exam_res, 0, 3), esc_name, sizeof(esc_name));
            json_escape(PQgetvalue(exam_res, 0, 4), esc_subj, sizeof(esc_subj));
            json_escape(PQgetvalue(exam_res, 0, 11), esc_inst, sizeof(esc_inst));
            json_escape(PQgetvalue(exam_res, 0, 12), esc_url, sizeof(esc_url));
            json_escape(PQgetvalue(exam_res, 0, 19), esc_cancel_reason, sizeof(esc_cancel_reason));

            size_t pos = 0;
            pos += snprintf(json + pos, 65536 - pos,
                "{\"examination\":{\"id\":\"%s\",\"institution_id\":\"%s\",\"code\":\"%s\","
                "\"name\":\"%s\",\"subject\":\"%s\",\"academic_year\":\"%s\","
                "\"exam_type\":\"%s\",\"duration_minutes\":%s,\"total_marks\":%s,"
                "\"passing_marks\":%s,\"status\":\"%s\",\"instructions\":\"%s\","
                "\"exam_url\":\"%s\",\"allowed_origins\":\"%s\",\"policy_id\":\"%s\","
                "\"created_by\":\"%s\",\"created_at\":%s,\"updated_at\":%s,"
                "\"cancel_reason\":\"%s\",\"cancelled_at\":%s,\"history\":[",
                PQgetvalue(exam_res, 0, 0), ex_inst_id, PQgetvalue(exam_res, 0, 2),
                esc_name, esc_subj, PQgetvalue(exam_res, 0, 5),
                PQgetvalue(exam_res, 0, 6), PQgetvalue(exam_res, 0, 7), PQgetvalue(exam_res, 0, 8),
                PQgetvalue(exam_res, 0, 9), ex_status, esc_inst,
                esc_url, PQgetvalue(exam_res, 0, 13), PQgetvalue(exam_res, 0, 14),
                ex_creator, PQgetvalue(exam_res, 0, 16), PQgetvalue(exam_res, 0, 17),
                esc_cancel_reason, PQgetvalue(exam_res, 0, 20));

            int history_overflow = 0;
            int history_count = PQntuples(history_res);
            for (int h = 0; h < history_count; h++) {
                char esc_from[128], esc_to[128], esc_actor[256], esc_reason[2048];
                json_escape(PQgetvalue(history_res, h, 0), esc_from, sizeof(esc_from));
                json_escape(PQgetvalue(history_res, h, 1), esc_to, sizeof(esc_to));
                json_escape(PQgetvalue(history_res, h, 2), esc_actor, sizeof(esc_actor));
                json_escape(PQgetvalue(history_res, h, 3), esc_reason, sizeof(esc_reason));
                int written = snprintf(json + pos, 65536 - pos,
                    "%s{\"from\":\"%s\",\"to\":\"%s\",\"by\":\"%s\",\"reason\":\"%s\",\"at\":%s}",
                    h > 0 ? "," : "", esc_from, esc_to, esc_actor, esc_reason,
                    PQgetvalue(history_res, h, 4));
                if (written < 0 || (size_t)written >= 65536 - pos) {
                    history_overflow = 1;
                    break;
                }
                pos += (size_t)written;
            }
            if (history_overflow) {
                free(json);
                PQclear(exam_res);
                if (sched_res) PQclear(sched_res);
                if (pol_res) PQclear(pol_res);
                PQclear(history_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 500, "Examination lifecycle history exceeds response capacity", origin, extra_headers, extra_len);
                return;
            }
            pos += snprintf(json + pos, 65536 - pos, "],\"exam_config\":%s},\"schedules\":[",
                PQgetvalue(exam_res, 0, 18));

            if (sched_res && PQresultStatus(sched_res) == PGRES_TUPLES_OK) {
                int sn = PQntuples(sched_res);
                for (int s = 0; s < sn; s++) {
                    if (s > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                    pos += snprintf(json + pos, 65536 - pos,
                        "{\"id\":\"%s\",\"session_name\":\"%s\",\"start_time\":%s,\"end_time\":%s,"
                        "\"timezone\":\"%s\",\"campus_id\":\"%s\",\"department_id\":\"%s\",\"room_id\":\"%s\"}",
                        PQgetvalue(sched_res, s, 0), PQgetvalue(sched_res, s, 1),
                        PQgetvalue(sched_res, s, 2), PQgetvalue(sched_res, s, 3),
                        PQgetvalue(sched_res, s, 4), PQgetvalue(sched_res, s, 5),
                        PQgetvalue(sched_res, s, 6), PQgetvalue(sched_res, s, 7));
                }
            }
            pos += snprintf(json + pos, 65536 - pos, "],\"os_policy\":");

            if (pol_res && PQresultStatus(pol_res) == PGRES_TUPLES_OK && PQntuples(pol_res) > 0) {
                pos += snprintf(json + pos, 65536 - pos,
                    "{\"required_os_release\":\"%s\",\"permitted_application\":\"%s\","
                    "\"require_tpm\":%s,\"require_secure_boot\":%s,\"kiosk_lockdown\":%s,"
                    "\"block_usb\":%s,\"block_clipboard\":%s,\"block_screen_capture\":%s}",
                    PQgetvalue(pol_res, 0, 0), PQgetvalue(pol_res, 0, 1),
                    strcmp(PQgetvalue(pol_res, 0, 2), "t") == 0 ? "true" : "false",
                    strcmp(PQgetvalue(pol_res, 0, 3), "t") == 0 ? "true" : "false",
                    strcmp(PQgetvalue(pol_res, 0, 4), "t") == 0 ? "true" : "false",
                    strcmp(PQgetvalue(pol_res, 0, 5), "t") == 0 ? "true" : "false",
                    strcmp(PQgetvalue(pol_res, 0, 6), "t") == 0 ? "true" : "false",
                    strcmp(PQgetvalue(pol_res, 0, 7), "t") == 0 ? "true" : "false");
            } else {
                /* No policy configured — return null, not a fabricated default. */
                pos += snprintf(json + pos, 65536 - pos, "null");
            }
            pos += snprintf(json + pos, 65536 - pos, "}");

            PQclear(exam_res);
            if (sched_res) PQclear(sched_res);
            if (pol_res) PQclear(pol_res);
            PQclear(history_res);
            db_release(conn, 0);

            ex_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            free(json);
            return;
        }

        /* ---------------- PATCH /api/v1/examinations/:id (Edit Exam) ---------------- */
        if ((strcmp(method, "PATCH") == 0 || strcmp(method, "PUT") == 0) && suffix[0] == '\0') {
            if (strcmp(ex_status, "draft") != 0 && strcmp(ex_status, "configured") != 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Exam configuration is locked and cannot be edited in current state", origin, extra_headers, extra_len);
                return;
            }

            char name[128] = {0}, subject[128] = {0}, instructions[2048] = {0}, exam_url[512] = {0};
            char status_req[32] = {0}, code[32] = {0}, academic_year[32] = {0}, exam_type[32] = {0};
            char allowed_origins[512] = {0}, policy_id[64] = {0}, exam_config[8192] = {0};
            int duration_minutes = 0, total_marks = 0, passing_marks = 0;

            ctrl_json_string(body, "name", name, sizeof(name));
            ctrl_json_string(body, "subject", subject, sizeof(subject));
            ctrl_json_string(body, "instructions", instructions, sizeof(instructions));
            ctrl_json_string(body, "exam_url", exam_url, sizeof(exam_url));
            ctrl_json_string(body, "code", code, sizeof(code));
            ctrl_json_string(body, "academic_year", academic_year, sizeof(academic_year));
            ctrl_json_string(body, "exam_type", exam_type, sizeof(exam_type));
            ctrl_json_string(body, "allowed_origins", allowed_origins, sizeof(allowed_origins));
            ctrl_json_string(body, "policy_id", policy_id, sizeof(policy_id));
            ctrl_json_string(body, "exam_config_json", exam_config, sizeof(exam_config));
            ctrl_json_string(body, "status", status_req, sizeof(status_req));
            ctrl_json_int(body, "duration_minutes", &duration_minutes);
            ctrl_json_int(body, "total_marks", &total_marks);
            ctrl_json_int(body, "passing_marks", &passing_marks);

            const char *target_status = ex_status;
            if (status_req[0] && (strcmp(status_req, "draft") == 0 || strcmp(status_req, "configured") == 0)) {
                target_status = status_req;
            }

            if (exam_config[0]) {
                int config_valid = validate_exam_config(conn, exam_config, exam_url, instructions, ex_inst_id, 0);
                if (config_valid <= 0) {
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, config_valid < 0 ? 500 : 400,
                                  config_valid < 0 ? "Could not validate exam configuration against the database" :
                                  "Exam configuration contains invalid, unsupported, or institution-inaccessible values",
                                  origin, extra_headers, extra_len);
                    return;
                }

                PGresult *center_check = db_simple(conn,
                    "SELECT COUNT(*)::text, jsonb_array_length(($2::jsonb)->'centerIds')::text "
                    "FROM centers WHERE tenant_id = $1 AND status = 'active' "
                    "AND id IN (SELECT jsonb_array_elements_text(($2::jsonb)->'centerIds'))",
                    2, (const char *[]){ ex_inst_id, exam_config },
                    (int[]){ (int)strlen(ex_inst_id), (int)strlen(exam_config) });
                if (!center_check || PQresultStatus(center_check) != PGRES_TUPLES_OK ||
                    strtol(PQgetvalue(center_check, 0, 0), NULL, 10) !=
                    strtol(PQgetvalue(center_check, 0, 1), NULL, 10)) {
                    if (center_check) PQclear(center_check);
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, 400, "Every selected exam center must be active and belong to this institution", origin, extra_headers, extra_len);
                    return;
                }
                PQclear(center_check);

                PGresult *begin = PQexec(conn, "BEGIN");
                if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
                    if (begin) PQclear(begin);
                    PQclear(exam_res);
                    db_release(conn, 1);
                    ex_send_error(client_fd, 500, "Could not start exam update transaction", origin, extra_headers, extra_len);
                    return;
                }
                PQclear(begin);

                const char *full_p[12] = {
                    name[0] ? name : PQgetvalue(exam_res, 0, 3),
                    subject[0] ? subject : PQgetvalue(exam_res, 0, 4),
                    academic_year, exam_type, instructions, exam_url, allowed_origins,
                    policy_id, target_status, eid, exam_config, code[0] ? code : PQgetvalue(exam_res, 0, 2)
                };
                int full_l[12];
                for (int i = 0; i < 12; i++) full_l[i] = (int)strlen(full_p[i]);
                PGresult *full_update = db_simple(conn,
                    "UPDATE examinations SET name = $1, subject = $2, academic_year = $3, exam_type = $4, "
                    "instructions = $5, exam_url = $6, allowed_origins = $7, policy_id = NULLIF($8,''), "
                    "status = $9, code = $12, duration_minutes = ($11::jsonb->>'durationMin')::integer, exam_config = $11::jsonb, "
                    "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $10",
                    12, full_p, full_l);
                if (!full_update || PQresultStatus(full_update) != PGRES_COMMAND_OK) {
                    if (full_update) PQclear(full_update);
                    PQexec(conn, "ROLLBACK");
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, 500, "Failed to persist exam configuration", origin, extra_headers, extra_len);
                    return;
                }
                PQclear(full_update);

                char now_str[32];
                snprintf(now_str, sizeof(now_str), "%ld", (long)time(NULL) * 1000);
                const char *mirror_p[6] = { eid, exam_config, full_p[0], full_p[11], full_p[5], now_str };
                int mirror_l[6] = { (int)strlen(eid), (int)strlen(exam_config), (int)strlen(full_p[0]),
                                    (int)strlen(full_p[11]), (int)strlen(full_p[5]), (int)strlen(now_str) };
                PGresult *mirror_update = db_simple(conn,
                    "UPDATE exams SET code = $4, title = $3, description = COALESCE($2::jsonb->>'description',''), "
                    "course = COALESCE($2::jsonb->>'course',''), department_id = NULLIF($2::jsonb->>'departmentId',''), "
                    "academic_year = COALESCE($2::jsonb->>'academicYear',''), type = COALESCE($2::jsonb->>'type','internal'), "
                    "center_ids = COALESCE($2::jsonb->'centerIds','[]'::jsonb), start_at = ($2::jsonb->>'startAt')::bigint, "
                    "duration_min = ($2::jsonb->>'durationMin')::integer, timezone = COALESCE($2::jsonb->>'timezone','Asia/Kolkata'), "
                    "late_entry_min = COALESCE(($2::jsonb->>'lateEntryMin')::integer,0), capacity = COALESCE(($2::jsonb->>'capacity')::integer,0), "
                    "instructions = COALESCE($2::jsonb->>'instructions',''), resources = COALESCE($2::jsonb->>'resources',''), "
                    "accommodations = COALESCE($2::jsonb->>'accommodations',''), auth_mode = COALESCE($2::jsonb->>'authMode','candidate-login'), "
                    "identity_required = CASE WHEN COALESCE($2::jsonb->>'identityRequired','true') = 'true' THEN 1 ELSE 0 END, "
                    "origins = COALESCE($2::jsonb->'origins','[]'::jsonb), navigation = COALESCE($2::jsonb->>'navigation','locked'), "
                    "allowed_destinations = COALESCE($2::jsonb->'allowedDestinations','[]'::jsonb), "
                    "compatibility_profile = COALESCE($2::jsonb->>'compatibilityProfile','standard-uefi'), "
                    "attestation_level = COALESCE($2::jsonb->>'attestationLevel','tpm'), "
                    "session_timeout_min = COALESCE(($2::jsonb->>'sessionTimeoutMin')::integer,15), "
                    "reconnect_policy = COALESCE($2::jsonb->>'reconnectPolicy','allow-reconnect'), "
                    "submission_mode = COALESCE($2::jsonb->>'submissionMode','either'), "
                    "required_checks = COALESCE($2::jsonb->'requiredChecks','[]'::jsonb), "
                    "policy_id = NULLIF($2::jsonb->>'policyId',''), exam_url = $5, updated_at = $6::bigint "
                    "WHERE id = $1",
                    6, mirror_p, mirror_l);
                if (!mirror_update || PQresultStatus(mirror_update) != PGRES_COMMAND_OK) {
                    if (mirror_update) PQclear(mirror_update);
                    PQexec(conn, "ROLLBACK");
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, 500, "Failed to update exam configuration mirror", origin, extra_headers, extra_len);
                    return;
                }
                PQclear(mirror_update);

                char schedule_id[64];
                snprintf(schedule_id, sizeof(schedule_id), "esch_%ld_%d", (long)time(NULL), rand() % 10000);
                const char *schedule_p[3] = { eid, code[0] ? code : PQgetvalue(exam_res, 0, 2), exam_config };
                int schedule_l[3] = { (int)strlen(eid), (int)strlen(schedule_p[1]), (int)strlen(exam_config) };
                PGresult *schedule_update = db_simple(conn,
                    "UPDATE exam_schedules SET session_name = $2, start_time = ($3::jsonb->>'startAt')::bigint, "
                    "end_time = ($3::jsonb->>'startAt')::bigint + ($3::jsonb->>'durationMin')::bigint * 60000, "
                    "timezone = COALESCE($3::jsonb->>'timezone','Asia/Kolkata') "
                    "WHERE id = (SELECT id FROM exam_schedules WHERE exam_id = $1 ORDER BY start_time LIMIT 1)",
                    3, schedule_p, schedule_l);
                if (!schedule_update || PQresultStatus(schedule_update) != PGRES_COMMAND_OK) {
                    if (schedule_update) PQclear(schedule_update);
                    PQexec(conn, "ROLLBACK");
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, 500, "Failed to update exam schedule", origin, extra_headers, extra_len);
                    return;
                }
                int schedule_exists = strtol(PQcmdTuples(schedule_update), NULL, 10) > 0;
                PQclear(schedule_update);
                if (!schedule_exists) {
                    const char *schedule_insert_p[5] = { schedule_id, eid, ex_inst_id, schedule_p[1], exam_config };
                    int schedule_insert_l[5] = { (int)strlen(schedule_id), (int)strlen(eid), (int)strlen(ex_inst_id),
                                                 (int)strlen(schedule_p[1]), (int)strlen(exam_config) };
                    PGresult *schedule_insert = db_simple(conn,
                        "INSERT INTO exam_schedules (id, exam_id, institution_id, session_name, start_time, end_time, timezone, created_at) "
                        "SELECT $1, $2, $3, $4, ($5::jsonb->>'startAt')::bigint, "
                        "($5::jsonb->>'startAt')::bigint + ($5::jsonb->>'durationMin')::bigint * 60000, "
                        "COALESCE($5::jsonb->>'timezone','Asia/Kolkata'), EXTRACT(EPOCH FROM NOW())::BIGINT * 1000",
                        5, schedule_insert_p, schedule_insert_l);
                    if (!schedule_insert || PQresultStatus(schedule_insert) != PGRES_COMMAND_OK) {
                        if (schedule_insert) PQclear(schedule_insert);
                        PQexec(conn, "ROLLBACK");
                        PQclear(exam_res);
                        db_release(conn, 0);
                        ex_send_error(client_fd, 500, "Failed to create exam schedule", origin, extra_headers, extra_len);
                        return;
                    }
                    PQclear(schedule_insert);
                }

                PGresult *commit = PQexec(conn, "COMMIT");
                if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
                    if (commit) PQclear(commit);
                    PQexec(conn, "ROLLBACK");
                    PQclear(exam_res);
                    db_release(conn, 1);
                    ex_send_error(client_fd, 500, "Failed to commit exam update", origin, extra_headers, extra_len);
                    return;
                }
                PQclear(commit);
            } else {
            /* Update database */
            const char *upd_p[9] = {
                name[0] ? name : PQgetvalue(exam_res, 0, 3),
                subject[0] ? subject : PQgetvalue(exam_res, 0, 4),
                instructions[0] ? instructions : PQgetvalue(exam_res, 0, 11),
                exam_url[0] ? exam_url : PQgetvalue(exam_res, 0, 12),
                target_status,
                eid,
                NULL, NULL, NULL
            };
            int upd_l[6] = {
                (int)strlen(upd_p[0]), (int)strlen(upd_p[1]), (int)strlen(upd_p[2]),
                (int)strlen(upd_p[3]), (int)strlen(upd_p[4]), (int)strlen(eid)
            };

            PGresult *upd_res = db_simple(conn,
                "UPDATE examinations SET name = $1, subject = $2, instructions = $3, exam_url = $4, "
                "status = $5, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $6",
                6, upd_p, upd_l);
            if (upd_res) PQclear(upd_res);

            /* Also mirror update into exams table */
            const char *me_p[3] = { upd_p[3], upd_p[0], eid };
            int me_l[3] = { (int)strlen(me_p[0]), (int)strlen(me_p[1]), (int)strlen(eid) };
            PGresult *me_res = db_simple(conn,
                "UPDATE exams SET exam_url = $1, title = $2, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $3",
                3, me_p, me_l);
            if (me_res) PQclear(me_res);
            }

            if (strcmp(target_status, ex_status) != 0) {
                record_status_history(conn, eid, ex_status, target_status, sess.user_id, "Status updated via PATCH");
            }
            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_UPDATED", "Configuration updated");

            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"updated\",\"exam_id\":\"%s\"}", eid);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/submit-for-approval ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/submit-for-approval") == 0) {
            if (strcmp(ex_status, "draft") != 0 && strcmp(ex_status, "configured") != 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Only draft or configured exams can be submitted for approval", origin, extra_headers, extra_len);
                return;
            }
            int config_valid = validate_exam_config(conn, PQgetvalue(exam_res, 0, 18),
                                                    PQgetvalue(exam_res, 0, 12), PQgetvalue(exam_res, 0, 11),
                                                    ex_inst_id, 1);
            if (config_valid <= 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, config_valid < 0 ? 500 : 400,
                              config_valid < 0 ? "Could not validate exam readiness against the database" :
                              "Exam is not ready for review: verify its schedule, active centres, published policy, origin, and delivery configuration",
                              origin, extra_headers, extra_len);
                return;
            }

            PGresult *upd = db_simple(conn,
                "UPDATE examinations SET status = 'pending_approval', updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1",
                1, chk_p, chk_l);
            if (upd) PQclear(upd);

            record_status_history(conn, eid, ex_status, "pending_approval", sess.user_id, "Submitted for authorized review");
            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_SUBMITTED_FOR_APPROVAL", "Pending approval");

            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"pending_approval\",\"exam_id\":\"%s\"}", eid);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/approve (Separation of duties) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/approve") == 0) {
            if (sess.role != ROLE_PLATFORM_OWNER && sess.role != ROLE_INSTITUTION_ADMIN &&
                sess.role != ROLE_EXAM_MANAGER) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 403, "Exam approval permission required", origin, extra_headers, extra_len);
                return;
            }

            /* Separation of duties: Creator cannot approve their own exam */
            if (strcmp(ex_creator, sess.user_id) == 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 403, "Separation of duties: creator cannot approve their own exam", origin, extra_headers, extra_len);
                return;
            }

            if (strcmp(ex_status, "pending_approval") != 0 && strcmp(ex_status, "configured") != 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Exam must be in pending_approval or configured state to approve", origin, extra_headers, extra_len);
                return;
            }
            int config_valid = validate_exam_config(conn, PQgetvalue(exam_res, 0, 18),
                                                    PQgetvalue(exam_res, 0, 12), PQgetvalue(exam_res, 0, 11),
                                                    ex_inst_id, 1);
            if (config_valid <= 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, config_valid < 0 ? 500 : 400,
                              config_valid < 0 ? "Could not validate exam readiness against the database" :
                              "Exam configuration is no longer valid for approval",
                              origin, extra_headers, extra_len);
                return;
            }

            char app_id[64];
            snprintf(app_id, sizeof(app_id), "eapp_%ld_%d", (long)time(NULL), rand() % 10000);

            const char *ap_p[3] = { eid, sess.user_id, app_id };
            int ap_l[3] = { (int)strlen(eid), (int)strlen(sess.user_id), (int)strlen(app_id) };

            PGresult *upd = db_simple(conn,
                "UPDATE examinations SET status = 'approved', approved_by = $2, "
                "approved_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1",
                2, ap_p, ap_l);
            if (upd) PQclear(upd);

            PGresult *app_rec = db_simple(conn,
                "INSERT INTO exam_approvals (id, exam_id, institution_id, decision, approver_user_id, created_at) "
                "VALUES ($3, $1, (SELECT institution_id FROM examinations WHERE id = $1), 'approved', $2, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
                3, ap_p, ap_l);
            if (app_rec) PQclear(app_rec);

            record_status_history(conn, eid, ex_status, "approved", sess.user_id, "Approved by exam controller");
            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_APPROVED", "Approved for scheduling");

            audit_log(sess.user_id, "EXAM_APPROVED", eid, "Examination approved");
            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"approved\",\"exam_id\":\"%s\"}", eid);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/publish (Schedule / Publish) ---------------- */
        if (strcmp(method, "POST") == 0 && (strcmp(suffix, "/publish") == 0 || strcmp(suffix, "/schedule") == 0)) {
            if (strcmp(ex_status, "approved") != 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Only approved exams can be published / scheduled", origin, extra_headers, extra_len);
                return;
            }
            int config_valid = validate_exam_config(conn, PQgetvalue(exam_res, 0, 18),
                                                    PQgetvalue(exam_res, 0, 12), PQgetvalue(exam_res, 0, 11),
                                                    ex_inst_id, 1);
            if (config_valid <= 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, config_valid < 0 ? 500 : 400,
                              config_valid < 0 ? "Could not validate exam readiness against the database" :
                              "Exam configuration is no longer valid for publication",
                              origin, extra_headers, extra_len);
                return;
            }

            PGresult *upd = db_simple(conn,
                "UPDATE examinations SET status = 'scheduled', "
                "published_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1",
                1, chk_p, chk_l);
            if (upd) PQclear(upd);

            record_status_history(conn, eid, ex_status, "scheduled", sess.user_id, "Exam published to candidates and scheduled");
            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_PUBLISHED", "Published to fleet");

            audit_log(sess.user_id, "EXAM_PUBLISHED", eid, "Scheduled/Published");
            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"scheduled\",\"exam_id\":\"%s\"}", eid);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/ready ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/ready") == 0) {
            if (strcmp(ex_status, "scheduled") != 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Only scheduled exams can be moved to ready state", origin, extra_headers, extra_len);
                return;
            }

            PGresult *upd = db_simple(conn,
                "UPDATE examinations SET status = 'ready', "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1",
                1, chk_p, chk_l);
            if (upd) PQclear(upd);

            record_status_history(conn, eid, ex_status, "ready", sess.user_id, "Pre-exam checks completed");
            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_READY", "Pre-exam ready");

            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"ready\",\"exam_id\":\"%s\"}", eid);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/start (Live / In Progress) ---------------- */
        if (strcmp(method, "POST") == 0 && (strcmp(suffix, "/start") == 0 || strcmp(suffix, "/live") == 0)) {
            if (strcmp(ex_status, "ready") != 0 && strcmp(ex_status, "scheduled") != 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Exam must be in ready or scheduled state to start", origin, extra_headers, extra_len);
                return;
            }

            PGresult *upd = db_simple(conn,
                "UPDATE examinations SET status = 'in_progress', "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1",
                1, chk_p, chk_l);
            if (upd) PQclear(upd);

            record_status_history(conn, eid, ex_status, "in_progress", sess.user_id, "Examination started / live");
            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_STARTED", "Live delivery active");

            audit_log(sess.user_id, "EXAM_STARTED", eid, "Examination active");
            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"in_progress\",\"exam_id\":\"%s\"}", eid);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/close ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/close") == 0) {
            if (strcmp(ex_status, "in_progress") != 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Only in-progress exams can be closed", origin, extra_headers, extra_len);
                return;
            }

            PGresult *upd = db_simple(conn,
                "UPDATE examinations SET status = 'closed', "
                "closed_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1",
                1, chk_p, chk_l);
            if (upd) PQclear(upd);

            /* Auto-submit active attempts */
            PGresult *sub_res = db_simple(conn,
                "UPDATE exam_attempts SET status = 'submitted', "
                "submit_time = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
                "WHERE exam_id = $1 AND status = 'in_progress'",
                1, chk_p, chk_l);
            if (sub_res) PQclear(sub_res);

            record_status_history(conn, eid, ex_status, "closed", sess.user_id, "Examination closed and sessions collected");
            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_CLOSED", "Closed attempts frozen");

            audit_log(sess.user_id, "EXAM_CLOSED", eid, "Examination closed");
            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"closed\",\"exam_id\":\"%s\"}", eid);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/finalize ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/finalize") == 0) {
            if (strcmp(ex_status, "closed") != 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Only closed exams can be finalized", origin, extra_headers, extra_len);
                return;
            }

            PGresult *upd = db_simple(conn,
                "UPDATE examinations SET status = 'finalized', "
                "finalized_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1",
                1, chk_p, chk_l);
            if (upd) PQclear(upd);

            record_status_history(conn, eid, ex_status, "finalized", sess.user_id, "Reconciliation complete; exam finalized and locked permanently");
            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_FINALIZED", "Finalized and locked");

            audit_log(sess.user_id, "EXAM_FINALIZED", eid, "Finalized permanently");
            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"finalized\",\"exam_id\":\"%s\"}", eid);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/cancel ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/cancel") == 0) {
            if (strcmp(ex_status, "finalized") == 0 || strcmp(ex_status, "cancelled") == 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Finalized or already cancelled exams cannot be cancelled", origin, extra_headers, extra_len);
                return;
            }

            char reason[512] = {0};
            ctrl_json_string(body, "reason", reason, sizeof(reason));
            if (strlen(reason) < 8) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Cancellation reason required (minimum 8 characters)", origin, extra_headers, extra_len);
                return;
            }

            const char *can_p[2] = { eid, reason };
            int can_l[2] = { (int)strlen(eid), (int)strlen(reason) };

            PGresult *upd = db_simple(conn,
                "UPDATE examinations SET status = 'cancelled', cancel_reason = $2, "
                "cancelled_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1",
                2, can_p, can_l);
            if (upd) PQclear(upd);

            record_status_history(conn, eid, ex_status, "cancelled", sess.user_id, reason);
            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_CANCELLED", reason);

            audit_log(sess.user_id, "EXAM_CANCELLED", eid, reason);
            PQclear(exam_res);
            db_release(conn, 0);

            char resp[512];
            char esc_reason[256];
            json_escape(reason, esc_reason, sizeof(esc_reason));
            snprintf(resp, sizeof(resp), "{\"status\":\"cancelled\",\"exam_id\":\"%s\",\"cancel_reason\":\"%s\"}", eid, esc_reason);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- GET /api/v1/examinations/:id/students (Assigned roster) ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(suffix, "/students") == 0) {
            PGresult *assigned = db_simple(conn,
                "SELECT student_id, roll_no, name, COALESCE(campus_id, ''), COALESCE(seat_no, ''), "
                "COALESCE(assigned_exam_url, ''), COALESCE(assignment_status, 'active') "
                "FROM exam_student_assignments WHERE exam_id=$1 AND institution_id=$2 "
                "ORDER BY roll_no ASC",
                2, (const char *[]){ eid, ex_inst_id },
                (int[]){ (int)strlen(eid), (int)strlen(ex_inst_id) });
            if (!assigned || PQresultStatus(assigned) != PGRES_TUPLES_OK) {
                if (assigned) PQclear(assigned);
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 503, "Assigned roster is unavailable", origin, extra_headers, extra_len);
                return;
            }

            size_t capacity = 128 + (size_t)PQntuples(assigned) * 2800;
            char *json = malloc(capacity);
            if (!json) {
                PQclear(assigned);
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 503, "Out of memory", origin, extra_headers, extra_len);
                return;
            }
            size_t offset = (size_t)snprintf(json, capacity, "{\"assignments\":[");
            for (int i = 0; i < PQntuples(assigned); i++) {
                char escaped_id[160], escaped_roll[160], escaped_name[320];
                char escaped_center[160], escaped_seat[96];
                char escaped_url[512], escaped_status[64];
                json_escape(PQgetvalue(assigned, i, 0), escaped_id, sizeof(escaped_id));
                json_escape(PQgetvalue(assigned, i, 1), escaped_roll, sizeof(escaped_roll));
                json_escape(PQgetvalue(assigned, i, 2), escaped_name, sizeof(escaped_name));
                json_escape(PQgetvalue(assigned, i, 3), escaped_center, sizeof(escaped_center));
                json_escape(PQgetvalue(assigned, i, 4), escaped_seat, sizeof(escaped_seat));
                json_escape(PQgetvalue(assigned, i, 5), escaped_url, sizeof(escaped_url));
                json_escape(PQgetvalue(assigned, i, 6), escaped_status, sizeof(escaped_status));
                offset += (size_t)snprintf(json + offset, capacity - offset,
                    "%s{\"exam_id\":\"%s\",\"student_id\":\"%s\",\"roll_no\":\"%s\",\"name\":\"%s\","
                    "\"center_id\":\"%s\",\"seat_no\":\"%s\",\"assigned_exam_url\":\"%s\",\"assignment_status\":\"%s\"}",
                    i ? "," : "", eid, escaped_id, escaped_roll, escaped_name,
                    escaped_center, escaped_seat, escaped_url, escaped_status);
            }
            snprintf(json + offset, capacity - offset, "]}");
            PQclear(assigned);
            PQclear(exam_res);
            db_release(conn, 0);
            ex_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            free(json);
            return;
        }

        /* ---------------- GET /api/v1/examinations/:id/status (Monitoring Breakdown) ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(suffix, "/status") == 0) {
            PGresult *cnt_res = db_simple(conn,
                "SELECT status, COUNT(*) FROM exam_attempts WHERE exam_id = $1 GROUP BY status",
                1, chk_p, chk_l);

            int n_scheduled = 0, n_ready = 0, n_in_progress = 0, n_submitted = 0, n_interrupted = 0, n_completed = 0;
            if (cnt_res && PQresultStatus(cnt_res) == PGRES_TUPLES_OK) {
                int n = PQntuples(cnt_res);
                for (int i = 0; i < n; i++) {
                    const char *st = PQgetvalue(cnt_res, i, 0);
                    int count = atoi(PQgetvalue(cnt_res, i, 1));
                    if (strcmp(st, "scheduled") == 0) n_scheduled = count;
                    else if (strcmp(st, "ready") == 0) n_ready = count;
                    else if (strcmp(st, "in_progress") == 0) n_in_progress = count;
                    else if (strcmp(st, "submitted") == 0) n_submitted = count;
                    else if (strcmp(st, "interrupted") == 0) n_interrupted = count;
                    else if (strcmp(st, "completed") == 0) n_completed = count;
                }
            }
            if (cnt_res) PQclear(cnt_res);

            int total_attempts = n_scheduled + n_ready + n_in_progress + n_submitted + n_interrupted + n_completed;

            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"exam_id\":\"%s\",\"status\":\"%s\",\"attempts\":{"
                "\"scheduled\":%d,\"ready\":%d,\"in_progress\":%d,\"submitted\":%d,"
                "\"interrupted\":%d,\"completed\":%d,\"total\":%d}}",
                eid, ex_status, n_scheduled, n_ready, n_in_progress, n_submitted,
                n_interrupted, n_completed, total_attempts);

            PQclear(exam_res);
            db_release(conn, 0);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/schedules (Add Schedule Session) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/schedules") == 0) {
            char session_name[64] = {0}, campus_id[64] = {0}, dept_id[64] = {0}, room_id[64] = {0}, tz[64] = {0};
            int start_time = 0, end_time = 0;

            ctrl_json_string(body, "session_name", session_name, sizeof(session_name));
            ctrl_json_string(body, "campus_id", campus_id, sizeof(campus_id));
            ctrl_json_string(body, "department_id", dept_id, sizeof(dept_id));
            ctrl_json_string(body, "room_id", room_id, sizeof(room_id));
            ctrl_json_string(body, "timezone", tz, sizeof(tz));
            ctrl_json_int(body, "start_time", &start_time);
            ctrl_json_int(body, "end_time", &end_time);

            if (start_time <= 0 || end_time <= start_time) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Valid start_time and end_time (end > start) required", origin, extra_headers, extra_len);
                return;
            }

            /* Room clash check if room_id is specified */
            if (room_id[0]) {
                char st_str[32], et_str[32];
                snprintf(st_str, sizeof(st_str), "%d", start_time);
                snprintf(et_str, sizeof(et_str), "%d", end_time);
                const char *clash_p[4] = { room_id, ex_inst_id, st_str, et_str };
                int clash_l[4] = { (int)strlen(room_id), (int)strlen(ex_inst_id), (int)strlen(st_str), (int)strlen(et_str) };
                PGresult *clash_res = db_simple(conn,
                    "SELECT id FROM exam_schedules WHERE room_id = $1 AND institution_id = $2 "
                    "AND (start_time < $4 AND end_time > $3)",
                    4, clash_p, clash_l);
                if (clash_res && PQntuples(clash_res) > 0) {
                    PQclear(clash_res);
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, 409, "Schedule conflict: room already booked in this time slot", origin, extra_headers, extra_len);
                    return;
                }
                if (clash_res) PQclear(clash_res);
            }

            char sched_id[64];
            snprintf(sched_id, sizeof(sched_id), "esch_%ld_%d", (long)time(NULL), rand() % 10000);
            char st_str[32], et_str[32];
            snprintf(st_str, sizeof(st_str), "%d", start_time);
            snprintf(et_str, sizeof(et_str), "%d", end_time);

            const char *ins_p[9] = { sched_id, eid, ex_inst_id, campus_id, dept_id, room_id, session_name, st_str, et_str };
            int ins_l[9] = { (int)strlen(sched_id), (int)strlen(eid), (int)strlen(ex_inst_id),
                             (int)strlen(campus_id), (int)strlen(dept_id), (int)strlen(room_id),
                             (int)strlen(session_name), (int)strlen(st_str), (int)strlen(et_str) };

            PGresult *ins_res = db_simple(conn,
                "INSERT INTO exam_schedules (id, exam_id, institution_id, campus_id, department_id, "
                "room_id, session_name, start_time, end_time, created_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
                9, ins_p, ins_l);
            if (ins_res) PQclear(ins_res);

            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_SCHEDULE_ADDED", session_name);
            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"schedule_id\":\"%s\",\"exam_id\":\"%s\"}", sched_id, eid);
            ex_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/students (Assign Student) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/students") == 0) {
            if (sess.role != ROLE_PLATFORM_OWNER && sess.role != ROLE_INSTITUTION_ADMIN &&
                sess.role != ROLE_EXAM_MANAGER) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 403, "Candidate assignment permission required", origin, extra_headers, extra_len);
                return;
            }
            if (strcmp(ex_status, "draft") != 0 && strcmp(ex_status, "configured") != 0 &&
                strcmp(ex_status, "pending_approval") != 0 && strcmp(ex_status, "approved") != 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 409, "Candidate assignments are locked for this examination status", origin, extra_headers, extra_len);
                return;
            }

            char student_id[64] = {0}, roll_no[64] = {0}, sname[128] = {0};
            char center_id[64] = {0}, seat_no[32] = {0};
            char assigned_exam_url[512] = {0};
            ctrl_json_string(body, "student_id", student_id, sizeof(student_id));
            ctrl_json_string(body, "roll_no", roll_no, sizeof(roll_no));
            ctrl_json_string(body, "name", sname, sizeof(sname));
            ctrl_json_string(body, "center_id", center_id, sizeof(center_id));
            ctrl_json_string(body, "seat_no", seat_no, sizeof(seat_no));
            ctrl_json_string(body, "assigned_exam_url", assigned_exam_url, sizeof(assigned_exam_url));

            if (assigned_exam_url[0]) {
                char url_error[192] = {0};
                if (platform_validate_exam_url(assigned_exam_url, url_error, sizeof(url_error)) != 0) {
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, 400,
                        url_error[0] ? url_error : "Assigned examination URL is not approved",
                        origin, extra_headers, extra_len);
                    return;
                }
            }

            if (!student_id[0] || !roll_no[0]) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "student_id and roll_no are required", origin, extra_headers, extra_len);
                return;
            }

            const char *student_params[2] = { ex_inst_id, roll_no };
            int student_lengths[2] = { (int)strlen(ex_inst_id), (int)strlen(roll_no) };
            PGresult *student = db_simple(conn,
                "SELECT id, roll_no, name, academic_status, administrative_hold "
                "FROM students WHERE institution_id=$1 AND roll_no=$2",
                2, student_params, student_lengths);
            if (!student || PQresultStatus(student) != PGRES_TUPLES_OK) {
                if (student) PQclear(student);
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 503, "Student roster lookup failed", origin, extra_headers, extra_len);
                return;
            }
            if (PQntuples(student) != 1) {
                PQclear(student);
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 404, "Student does not exist in this institution", origin, extra_headers, extra_len);
                return;
            }
            snprintf(student_id, sizeof(student_id), "%s", PQgetvalue(student, 0, 0));
            snprintf(roll_no, sizeof(roll_no), "%s", PQgetvalue(student, 0, 1));
            snprintf(sname, sizeof(sname), "%s", PQgetvalue(student, 0, 2));
            int student_eligible = strcmp(PQgetvalue(student, 0, 3), "active") == 0 &&
                                   strcmp(PQgetvalue(student, 0, 4), "t") != 0;
            PQclear(student);
            if (!student_eligible) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 409, "Student is not eligible for examination assignment", origin, extra_headers, extra_len);
                return;
            }

            if (center_id[0]) {
                const char *center_params[3] = { ex_inst_id, eid, center_id };
                int center_lengths[3] = { (int)strlen(ex_inst_id), (int)strlen(eid), (int)strlen(center_id) };
                PGresult *center = db_simple(conn,
                    "SELECT 1 FROM centers c WHERE c.tenant_id=$1 AND c.id=$3 AND c.status='active' "
                    "AND EXISTS (SELECT 1 FROM jsonb_array_elements_text("
                    "COALESCE((SELECT exam_config->'centerIds' FROM examinations WHERE id=$2), '[]'::jsonb) "
                    ") AS configured(center_id) WHERE configured.center_id=c.id)",
                    3, center_params, center_lengths);
                int center_query_ok = center && PQresultStatus(center) == PGRES_TUPLES_OK;
                int center_ok = center_query_ok && PQntuples(center) == 1;
                if (center) PQclear(center);
                if (!center_query_ok) {
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, 503, "Examination center lookup failed", origin, extra_headers, extra_len);
                    return;
                }
                if (!center_ok) {
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, 400, "Center must be active and configured for this examination", origin, extra_headers, extra_len);
                    return;
                }
            }

            char assign_id[64];
            snprintf(assign_id, sizeof(assign_id), "easg_%ld_%d", (long)time(NULL), rand() % 10000);
            if ((center_id[0] != '\0') != (seat_no[0] != '\0')) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "Center and seat must be provided together", origin, extra_headers, extra_len);
                return;
            }
            char now_text[32];
            snprintf(now_text, sizeof(now_text), "%lld", (long long)time(NULL) * 1000);
            PGresult *begin = PQexec(conn, "BEGIN");
            if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
                if (begin) PQclear(begin);
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 503, "Could not begin candidate assignment transaction", origin, extra_headers, extra_len);
                return;
            }
            PQclear(begin);

            PGresult *exam_lock = db_simple(conn,
                "SELECT id, status FROM examinations WHERE id=$1 FOR UPDATE",
                1, (const char *[]){ eid }, (int[]){ (int)strlen(eid) });
            int lock_ok = exam_lock && PQresultStatus(exam_lock) == PGRES_TUPLES_OK &&
                          PQntuples(exam_lock) == 1;
            int locked_status_ok = lock_ok &&
                (strcmp(PQgetvalue(exam_lock, 0, 1), "draft") == 0 ||
                 strcmp(PQgetvalue(exam_lock, 0, 1), "configured") == 0 ||
                 strcmp(PQgetvalue(exam_lock, 0, 1), "pending_approval") == 0 ||
                 strcmp(PQgetvalue(exam_lock, 0, 1), "approved") == 0);
            if (exam_lock) PQclear(exam_lock);
            if (!lock_ok) {
                PQexec(conn, "ROLLBACK");
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 503, "Could not lock examination roster for assignment", origin, extra_headers, extra_len);
                return;
            }
            if (!locked_status_ok) {
                PQexec(conn, "ROLLBACK");
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 409, "Candidate assignments are locked for this examination status", origin, extra_headers, extra_len);
                return;
            }
            PGresult *student_lock = db_simple(conn,
                "SELECT id FROM students WHERE institution_id=$1 AND id=$2 AND roll_no=$3 "
                "AND academic_status='active' AND administrative_hold=false FOR UPDATE",
                3, (const char *[]){ ex_inst_id, student_id, roll_no },
                (int[]){ (int)strlen(ex_inst_id), (int)strlen(student_id), (int)strlen(roll_no) });
            int student_lock_ok = student_lock && PQresultStatus(student_lock) == PGRES_TUPLES_OK;
            int student_still_eligible = student_lock_ok && PQntuples(student_lock) == 1;
            if (student_lock) PQclear(student_lock);
            if (!student_lock_ok || !student_still_eligible) {
                PQexec(conn, "ROLLBACK");
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, student_lock_ok ? 409 : 503,
                    student_lock_ok ? "Student is no longer eligible for examination assignment" :
                                      "Student eligibility could not be revalidated",
                    origin, extra_headers, extra_len);
                return;
            }
            if (center_id[0]) {
                PGresult *capacity_check = db_simple(conn,
                    "SELECT c.capacity, (SELECT COUNT(*)::integer FROM exam_student_assignments a "
                    "WHERE a.exam_id=$2 AND a.institution_id=c.tenant_id AND a.campus_id=c.id "
                    "AND a.student_id<>$4) "
                    "FROM centers c "
                    "WHERE c.tenant_id=$1 AND c.id=$3 AND c.status='active' "
                    "AND EXISTS (SELECT 1 FROM jsonb_array_elements_text("
                    "COALESCE((SELECT exam_config->'centerIds' FROM examinations WHERE id=$2), '[]'::jsonb) "
                    ") AS configured(center_id) WHERE configured.center_id=c.id) FOR UPDATE OF c",
                    4, (const char *[]){ ex_inst_id, eid, center_id, student_id },
                    (int[]){ (int)strlen(ex_inst_id), (int)strlen(eid),
                             (int)strlen(center_id), (int)strlen(student_id) });
                int capacity_query_ok = capacity_check &&
                                        PQresultStatus(capacity_check) == PGRES_TUPLES_OK &&
                                        PQntuples(capacity_check) == 1;
                int center_capacity = capacity_query_ok ? atoi(PQgetvalue(capacity_check, 0, 0)) : 0;
                int center_occupied = capacity_query_ok ? atoi(PQgetvalue(capacity_check, 0, 1)) : 0;
                if (capacity_check) PQclear(capacity_check);
                if (!capacity_query_ok || center_capacity <= 0) {
                    PQexec(conn, "ROLLBACK");
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, capacity_query_ok ? 409 : 503,
                        capacity_query_ok ? "Center has no valid seat capacity" : "Center capacity lookup failed",
                        origin, extra_headers, extra_len);
                    return;
                }
                if (center_occupied >= center_capacity) {
                    PQexec(conn, "ROLLBACK");
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, 409, "Center capacity has been reached", origin, extra_headers, extra_len);
                    return;
                }
                PGresult *seat_check = db_simple(conn,
                    "SELECT 1 FROM exam_student_assignments WHERE exam_id=$1 AND campus_id=$2 "
                    "AND seat_no=$3 AND student_id<>$4 LIMIT 1",
                    4, (const char *[]){ eid, center_id, seat_no, student_id },
                    (int[]){ (int)strlen(eid), (int)strlen(center_id),
                             (int)strlen(seat_no), (int)strlen(student_id) });
                int seat_query_ok = seat_check && PQresultStatus(seat_check) == PGRES_TUPLES_OK;
                int seat_taken = seat_query_ok && PQntuples(seat_check) > 0;
                if (seat_check) PQclear(seat_check);
                if (!seat_query_ok || seat_taken) {
                    PQexec(conn, "ROLLBACK");
                    PQclear(exam_res);
                    db_release(conn, 0);
                    ex_send_error(client_fd, seat_query_ok ? 409 : 503,
                        seat_query_ok ? "The selected seat is already assigned" : "Seat availability lookup failed",
                        origin, extra_headers, extra_len);
                    return;
                }
            }
            PGresult *attempt_check = db_simple(conn,
                "SELECT 1 FROM exam_attempts WHERE exam_id=$1 AND student_id=$2 AND status<>'scheduled'",
                2, (const char *[]){ eid, student_id },
                (int[]){ (int)strlen(eid), (int)strlen(student_id) });
            int attempt_query_ok = attempt_check && PQresultStatus(attempt_check) == PGRES_TUPLES_OK;
            int attempt_exists = attempt_query_ok && PQntuples(attempt_check) > 0;
            if (attempt_check) PQclear(attempt_check);
            if (!attempt_query_ok || attempt_exists) {
                PQexec(conn, "ROLLBACK");
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, attempt_query_ok ? 409 : 503,
                    attempt_query_ok ? "Candidate has already started or completed this examination" :
                        "Candidate attempt lookup failed",
                    origin, extra_headers, extra_len);
                return;
            }

            const char *asg_p[10] = {
                assign_id, eid, ex_inst_id, student_id, roll_no, sname, center_id, seat_no,
                assigned_exam_url, sess.username
            };
            int asg_l[10];
            for (int i = 0; i < 10; i++) asg_l[i] = (int)strlen(asg_p[i]);
            PGresult *asg_res = db_simple(conn,
                "INSERT INTO exam_student_assignments "
                "(id, exam_id, institution_id, student_id, roll_no, name, campus_id, seat_no, created_at, assigned_exam_url, created_by) "
                "VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,EXTRACT(EPOCH FROM NOW())::BIGINT*1000,$9,$10) "
                "ON CONFLICT (exam_id, student_id) DO UPDATE SET roll_no=EXCLUDED.roll_no, "
                "name=EXCLUDED.name, campus_id=EXCLUDED.campus_id, seat_no=EXCLUDED.seat_no, "
                "assigned_exam_url=CASE WHEN EXCLUDED.assigned_exam_url <> '' THEN EXCLUDED.assigned_exam_url ELSE exam_student_assignments.assigned_exam_url END, "
                "created_by=CASE WHEN EXCLUDED.created_by <> '' THEN EXCLUDED.created_by ELSE exam_student_assignments.created_by END",
                10, asg_p, asg_l);
            int transaction_ok = asg_res && PQresultStatus(asg_res) == PGRES_COMMAND_OK;
            if (asg_res) PQclear(asg_res);

            if (transaction_ok && assigned_exam_url[0]) {
                char audit_id[64];
                snprintf(audit_id, sizeof(audit_id), "asga_%ld_%d", (long)time(NULL), rand() % 10000);
                const char *aud_p[7] = {
                    audit_id, assign_id, eid, student_id, ex_inst_id, assigned_exam_url, sess.username
                };
                int aud_l[7];
                for (int i = 0; i < 7; i++) aud_l[i] = (int)strlen(aud_p[i]);
                PGresult *aud_res = db_simple(conn,
                    "INSERT INTO candidate_exam_assignment_audit "
                    "(id, assignment_id, exam_id, student_id, institution_id, action, new_url, performed_by, timestamp) "
                    "VALUES ($1, $2, $3, $4, $5, 'url_updated', $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT*1000)",
                    7, aud_p, aud_l);
                if (aud_res) PQclear(aud_res);
            }

            const char *candidate_params[7] = {
                eid, center_id, seat_no, sname, ex_inst_id, roll_no, now_text
            };
            int candidate_lengths[7];
            for (int i = 0; i < 7; i++) candidate_lengths[i] = (int)strlen(candidate_params[i]);
            PGresult *candidate = transaction_ok ? db_simple(conn,
                "UPDATE candidates SET exam_id=$1, center_id=NULLIF($2,''), seat=NULLIF($3,''), "
                "name=$4, status='registered', assigned_at=$7::bigint "
                "WHERE tenant_id=$5 AND roll_no=$6 AND (exam_id IS NULL OR exam_id=$1) "
                "AND status NOT IN ('disqualified','suspended','withdrawn','cancelled','canceled',"
                "'expired','completed','submitted','blocked','inactive','revoked','ineligible') "
                "RETURNING id",
                7, candidate_params, candidate_lengths) : NULL;
            transaction_ok = transaction_ok && candidate &&
                             PQresultStatus(candidate) == PGRES_TUPLES_OK;
            int candidate_exists = transaction_ok && PQntuples(candidate) > 0;
            if (candidate) PQclear(candidate);

            if (transaction_ok && !candidate_exists) {
                const char *existing_params[2] = { ex_inst_id, roll_no };
                int existing_lengths[2] = { (int)strlen(ex_inst_id), (int)strlen(roll_no) };
                PGresult *existing = db_simple(conn,
                    "SELECT id FROM candidates WHERE tenant_id=$1 AND roll_no=$2",
                    2, existing_params, existing_lengths);
                int exists_elsewhere = existing && PQresultStatus(existing) == PGRES_TUPLES_OK &&
                                       PQntuples(existing) > 0;
                if (existing) PQclear(existing);
                if (exists_elsewhere) {
                    transaction_ok = 0;
                } else {
                    const char *insert_params[8] = {
                        student_id, ex_inst_id, roll_no, sname, eid, center_id, seat_no, now_text
                    };
                    int insert_lengths[8];
                    for (int i = 0; i < 8; i++) insert_lengths[i] = (int)strlen(insert_params[i]);
                    PGresult *insert_candidate = db_simple(conn,
                        "INSERT INTO candidates (id,tenant_id,roll_no,name,exam_id,center_id,seat,"
                        "identity,status,assigned_at,created_at) "
                        "VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),'pending','registered',$8::bigint,$8::bigint)",
                        8, insert_params, insert_lengths);
                    transaction_ok = insert_candidate &&
                                     PQresultStatus(insert_candidate) == PGRES_COMMAND_OK;
                    if (insert_candidate) PQclear(insert_candidate);
                }
            }

            /* Also seed scheduled attempt */
            char att_id[64];
            snprintf(att_id, sizeof(att_id), "att_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *att_p[3] = { att_id, eid, student_id };
            int att_l[3] = { (int)strlen(att_id), (int)strlen(eid), (int)strlen(student_id) };
            PGresult *att_res = transaction_ok ? db_simple(conn,
                "INSERT INTO exam_attempts (id, exam_id, student_id, status, created_at) "
                "VALUES ($1, $2, $3, 'scheduled', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
                "ON CONFLICT (exam_id, student_id) DO NOTHING",
                3, att_p, att_l) : NULL;
            transaction_ok = transaction_ok && att_res &&
                             PQresultStatus(att_res) == PGRES_COMMAND_OK;
            if (att_res) PQclear(att_res);

            PGresult *commit = transaction_ok ? PQexec(conn, "COMMIT") : NULL;
            transaction_ok = transaction_ok && commit && PQresultStatus(commit) == PGRES_COMMAND_OK;
            if (commit) PQclear(commit);
            if (!transaction_ok) {
                PQexec(conn, "ROLLBACK");
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 409, "Candidate assignment could not be synchronized; no changes were saved", origin, extra_headers, extra_len);
                return;
            }

            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "STUDENT_ASSIGNED", roll_no);
            PQclear(exam_res);
            db_release(conn, 0);

            char resp[512];
            char escaped_assigned_url[384] = {0};
            json_escape(assigned_exam_url, escaped_assigned_url, sizeof(escaped_assigned_url));
            snprintf(resp, sizeof(resp), "{\"status\":\"assigned\",\"assignment_id\":\"%s\",\"exam_id\":\"%s\",\"student_id\":\"%s\",\"assigned_exam_url\":\"%s\"}", assign_id, eid, student_id, escaped_assigned_url);
            ex_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- DELETE /api/v1/examinations/:id/students/:studentId (Unassign) ---------------- */
        if (strcmp(method, "DELETE") == 0 && strncmp(suffix, "/students/", 10) == 0) {
            if (sess.role != ROLE_PLATFORM_OWNER && sess.role != ROLE_INSTITUTION_ADMIN &&
                sess.role != ROLE_EXAM_MANAGER) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 403, "Candidate assignment permission required", origin, extra_headers, extra_len);
                return;
            }
            if (strcmp(ex_status, "draft") != 0 && strcmp(ex_status, "configured") != 0 &&
                strcmp(ex_status, "pending_approval") != 0 && strcmp(ex_status, "approved") != 0) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 409, "Candidate assignments are locked for this examination status", origin, extra_headers, extra_len);
                return;
            }
            const char *student_ref = suffix + 10;
            if (!student_ref[0] || strlen(student_ref) >= 64) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "A candidate ID or roll number is required", origin, extra_headers, extra_len);
                return;
            }

            const char *lookup_params[3] = { eid, ex_inst_id, student_ref };
            int lookup_lengths[3] = { (int)strlen(eid), (int)strlen(ex_inst_id), (int)strlen(student_ref) };
            PGresult *assigned = db_simple(conn,
                "SELECT student_id, roll_no FROM exam_student_assignments "
                "WHERE exam_id=$1 AND institution_id=$2 AND (student_id=$3 OR roll_no=$3)",
                3, lookup_params, lookup_lengths);
            if (!assigned || PQresultStatus(assigned) != PGRES_TUPLES_OK) {
                if (assigned) PQclear(assigned);
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 503, "Candidate assignment lookup failed", origin, extra_headers, extra_len);
                return;
            }
            if (PQntuples(assigned) != 1) {
                if (assigned) PQclear(assigned);
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 404, "Candidate is not assigned to this examination", origin, extra_headers, extra_len);
                return;
            }
            char assigned_student_id[64], assigned_roll_no[64];
            snprintf(assigned_student_id, sizeof(assigned_student_id), "%s", PQgetvalue(assigned, 0, 0));
            snprintf(assigned_roll_no, sizeof(assigned_roll_no), "%s", PQgetvalue(assigned, 0, 1));
            PQclear(assigned);

            const char *attempt_params[2] = { eid, assigned_student_id };
            int attempt_lengths[2] = { (int)strlen(eid), (int)strlen(assigned_student_id) };
            PGresult *attempt = db_simple(conn,
                "SELECT 1 FROM exam_attempts WHERE exam_id=$1 AND student_id=$2 AND status<>'scheduled'",
                2, attempt_params, attempt_lengths);
            int attempt_query_ok = attempt && PQresultStatus(attempt) == PGRES_TUPLES_OK;
            int attempt_started = attempt_query_ok && PQntuples(attempt) > 0;
            if (attempt) PQclear(attempt);
            if (!attempt_query_ok) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 503, "Candidate attempt lookup failed", origin, extra_headers, extra_len);
                return;
            }
            if (attempt_started) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 409, "A candidate with an active or completed attempt cannot be unassigned", origin, extra_headers, extra_len);
                return;
            }

            PGresult *begin = PQexec(conn, "BEGIN");
            int transaction_ok = begin && PQresultStatus(begin) == PGRES_COMMAND_OK;
            if (begin) PQclear(begin);
            const char *delete_params[3] = { eid, ex_inst_id, assigned_student_id };
            int delete_lengths[3] = { (int)strlen(eid), (int)strlen(ex_inst_id), (int)strlen(assigned_student_id) };
            PGresult *deleted = transaction_ok ? db_simple(conn,
                "DELETE FROM exam_student_assignments WHERE exam_id=$1 AND institution_id=$2 AND student_id=$3",
                3, delete_params, delete_lengths) : NULL;
            transaction_ok = transaction_ok && deleted &&
                             PQresultStatus(deleted) == PGRES_COMMAND_OK &&
                             atoi(PQcmdTuples(deleted)) == 1;
            if (deleted) PQclear(deleted);

            PGresult *candidate_update = transaction_ok ? db_simple(conn,
                "UPDATE candidates SET exam_id=NULL,center_id=NULL,seat=NULL,pin_hash=NULL,"
                "status='registered',assigned_at=NULL WHERE tenant_id=$1 AND exam_id=$2 "
                "AND (id=$3 OR roll_no=$4)",
                4, (const char *[]){ ex_inst_id, eid, assigned_student_id, assigned_roll_no },
                (int[]){ (int)strlen(ex_inst_id), (int)strlen(eid),
                         (int)strlen(assigned_student_id), (int)strlen(assigned_roll_no) }) : NULL;
            transaction_ok = transaction_ok && candidate_update &&
                             PQresultStatus(candidate_update) == PGRES_COMMAND_OK;
            if (candidate_update) PQclear(candidate_update);

            char now_text[32];
            snprintf(now_text, sizeof(now_text), "%lld", (long long)time(NULL) * 1000);
            PGresult *revoked = transaction_ok ? db_simple(conn,
                "UPDATE candidate_exam_auth_tokens SET revoked_at=$3::bigint "
                "WHERE examination_id=$1 AND candidate_id=(SELECT id FROM candidates "
                "WHERE tenant_id=$2 AND roll_no=$4) AND used_at IS NULL AND revoked_at IS NULL",
                4, (const char *[]){ eid, ex_inst_id, now_text, assigned_roll_no },
                (int[]){ (int)strlen(eid), (int)strlen(ex_inst_id),
                         (int)strlen(now_text), (int)strlen(assigned_roll_no) }) : NULL;
            transaction_ok = transaction_ok && revoked &&
                             PQresultStatus(revoked) == PGRES_COMMAND_OK;
            if (revoked) PQclear(revoked);

            PGresult *expired = transaction_ok ? db_simple(conn,
                "UPDATE candidate_exam_checkins SET status='expired' "
                "WHERE examination_id=$1 AND candidate_id=(SELECT id FROM candidates "
                "WHERE tenant_id=$2 AND roll_no=$3) AND status IN ('pending','approved')",
                3, (const char *[]){ eid, ex_inst_id, assigned_roll_no },
                (int[]){ (int)strlen(eid), (int)strlen(ex_inst_id), (int)strlen(assigned_roll_no) }) : NULL;
            transaction_ok = transaction_ok && expired &&
                             PQresultStatus(expired) == PGRES_COMMAND_OK;
            if (expired) PQclear(expired);

            PGresult *commit = transaction_ok ? PQexec(conn, "COMMIT") : NULL;
            transaction_ok = transaction_ok && commit && PQresultStatus(commit) == PGRES_COMMAND_OK;
            if (commit) PQclear(commit);
            if (!transaction_ok) {
                PQexec(conn, "ROLLBACK");
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 500, "Candidate unassignment failed; no changes were saved", origin, extra_headers, extra_len);
                return;
            }
            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "STUDENT_UNASSIGNED", assigned_roll_no);
            PQclear(exam_res);
            db_release(conn, 0);
            ex_send_json(client_fd, 200, "{\"status\":\"unassigned\"}", origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/policy (Configure OS Policy) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/policy") == 0) {
            char release[64] = {0}, app[128] = {0}, url_policy[512] = {0};
            int req_tpm = 1, req_sb = 1, kiosk = 1, block_usb = 1, block_clip = 1, block_scr = 1;

            ctrl_json_string(body, "required_os_release", release, sizeof(release));
            ctrl_json_string(body, "permitted_application", app, sizeof(app));
            ctrl_json_string(body, "url_policy", url_policy, sizeof(url_policy));
            ctrl_json_bool(body, "require_tpm", &req_tpm);
            ctrl_json_bool(body, "require_secure_boot", &req_sb);
            ctrl_json_bool(body, "kiosk_lockdown", &kiosk);
            ctrl_json_bool(body, "block_usb", &block_usb);
            ctrl_json_bool(body, "block_clipboard", &block_clip);
            ctrl_json_bool(body, "block_screen_capture", &block_scr);

            char pol_id[64];
            snprintf(pol_id, sizeof(pol_id), "eosp_%ld_%d", (long)time(NULL), rand() % 10000);

            const char *pol_p[10] = {
                pol_id, eid, ex_inst_id, release, app, url_policy,
                req_tpm ? "t" : "f", req_sb ? "t" : "f", kiosk ? "t" : "f", block_usb ? "t" : "f"
            };
            int pol_l[10] = {
                (int)strlen(pol_id), (int)strlen(eid), (int)strlen(ex_inst_id),
                (int)strlen(release), (int)strlen(app), (int)strlen(url_policy),
                1, 1, 1, 1
            };

            PGresult *del_old = db_simple(conn, "DELETE FROM exam_os_policies WHERE exam_id = $1", 1, chk_p, chk_l);
            if (del_old) PQclear(del_old);

            PGresult *ins_pol = db_simple(conn,
                "INSERT INTO exam_os_policies (id, exam_id, institution_id, required_os_release, "
                "permitted_application, url_policy, require_tpm, require_secure_boot, kiosk_lockdown, "
                "block_usb, block_clipboard, block_screen_capture, created_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, true, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
                10, pol_p, pol_l);
            if (ins_pol) PQclear(ins_pol);

            /* Also record in examination table policy_id */
            const char *upd_p[2] = { pol_id, eid };
            int upd_l[2] = { (int)strlen(pol_id), (int)strlen(eid) };
            PGresult *upd_ex = db_simple(conn, "UPDATE examinations SET policy_id = $1 WHERE id = $2", 2, upd_p, upd_l);
            if (upd_ex) PQclear(upd_ex);

            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "EXAM_POLICY_CONFIGURED", release);
            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"configured\",\"policy_id\":\"%s\",\"exam_id\":\"%s\"}", pol_id, eid);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        PQclear(exam_res);
        db_release(conn, 0);
    }

    /* =========================================================================
     * 4. Legacy routes — all stubs removed; use the real Module 9 endpoints.
     * ========================================================================= */
    char legacy_id[128] = {0};
    if (ex_parse_legacy_id(path, legacy_id, sizeof(legacy_id))) {
        const char *l_suffix = path + strlen("/api/v1/platform/exams/") + strlen(legacy_id);

        /* All legacy stub routes return 410 Gone with a redirect message. */
        if (strcmp(method, "POST") == 0 &&
            (strcmp(l_suffix, "/validate") == 0 || strcmp(l_suffix, "/approve") == 0 ||
             strcmp(l_suffix, "/state") == 0 ||
             (strcmp(method, "GET") == 0 && strcmp(l_suffix, "/readiness") == 0))) {
            ex_send_error(client_fd, 410,
                "Legacy exam endpoint removed. Use /api/v1/examinations/:id/* endpoints instead.",
                origin, extra_headers, extra_len);
            return;
        }
    }

    /* Sessions (platform) — legacy stub removed */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/platform/exams/sessions") == 0) {
        ex_send_error(client_fd, 410,
            "This legacy endpoint has been removed. Use POST /api/v1/exam-sessions instead.",
            origin, extra_headers, extra_len);
        return;
    }

    /* Purge */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/platform/exams/purge") == 0) {
        ex_send_json(client_fd, 200, "{\"status\":\"purged\"}", origin, extra_headers, extra_len);
        return;
    }

    ex_send_error(client_fd, 404, "Endpoint not found", origin, extra_headers, extra_len);
}
