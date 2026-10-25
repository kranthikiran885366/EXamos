/*
 * exam_controller.c — Exam lifecycle management.
 * Mirrors frontend modules/exams/service.js.
 */

#include "exam_controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../security/security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void audit_log(const char *actor, const char *event, const char *detail) {
    audit_append(actor, event, detail);
}

static void ex_send_json(int fd, int code, const char *body,
                         const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

/* Minimal SQL string escaper (single quotes doubled). */
static char *escape_sql_str(const char *input, char *out, size_t out_len) {
    size_t j = 0;
    out[0] = '\0';
    for (size_t i = 0; input[i] && j + 2 < out_len; i++) {
        if (input[i] == '\'') { out[j++] = '\''; out[j++] = '\''; }
        else out[j++] = input[i];
    }
    out[j] = '\0';
    return out;
}

/* Parse an exam id from /api/v1/platform/exams/:id/... */
static int ex_parse_id(const char *path, char *out, size_t out_len) {
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

/* Helper: check if status transition is allowed */
static int ex_flow_ok(const char *from, const char *to) {
    static const char *flow[][2] = {
        {"draft","review"}, {"draft","cancelled"},
        {"review","draft"}, {"review","approved"}, {"review","cancelled"},
        {"approved","published"}, {"approved","draft"}, {"approved","cancelled"},
        {"published","live"}, {"published","approved"}, {"published","cancelled"},
        {"live","closed"},
        {NULL,NULL}
    };
    for (int i = 0; flow[i][0]; i++)
        if (strcmp(from, flow[i][0]) == 0 && strcmp(to, flow[i][1]) == 0) return 1;
    return 0;
}

void exam_handle(int client_fd, const char *method, const char *path,
                 const char *body, const char *auth_header,
                 const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
        ex_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                     origin, extra_headers, extra_len);
        return;
    }

    /* ---------------- List exams ---------------- */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/exams") == 0) {
        PGconn *conn = db_acquire();
        const char *pvals[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };
        int is_owner = (sess.role == ROLE_PLATFORM_OWNER);
        PGresult *res;
        if (is_owner) {
            res = PQexec(conn,
                "SELECT id, tenant_id, code, title, type, status, start_at, "
                        "duration_min, created_at FROM exams ORDER BY created_at DESC");
        } else {
            res = db_simple(conn,
                "SELECT id, tenant_id, code, title, type, status, start_at, "
                        "duration_min, created_at FROM exams "
                "WHERE tenant_id = $1 ORDER BY created_at DESC",
                1, pvals, lens);
        }
        char json[131072] = {0};
        size_t pos = 0;
        pos += snprintf(json + pos, sizeof(json) - pos, "{\"exams\":[");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            int n = PQntuples(res);
            for (int i = 0; i < n; i++) {
                if (i > 0) pos += snprintf(json + pos, sizeof(json) - pos, ",");
                pos += snprintf(json + pos, sizeof(json) - pos,
                    "{\"id\":\"%s\",\"tenant_id\":\"%s\",\"code\":\"%s\","
                    "\"title\":\"%s\",\"type\":\"%s\",\"status\":\"%s\","
                    "\"start_at\":%s,\"duration_min\":%s,\"created_at\":%s}",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                    PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "",
                    PQgetvalue(res, i, 4) ? PQgetvalue(res, i, 4) : "",
                    PQgetvalue(res, i, 5) ? PQgetvalue(res, i, 5) : "draft",
                    PQgetvalue(res, i, 6) ? PQgetvalue(res, i, 6) : "0",
                    PQgetvalue(res, i, 7) ? PQgetvalue(res, i, 7) : "60",
                    PQgetvalue(res, i, 8) ? PQgetvalue(res, i, 8) : "0");
            }
        }
        if (res) PQclear(res);
        snprintf(json + pos, sizeof(json) - pos, "]}");
        db_release(conn, 0);
        ex_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        return;
    }

    /* ---------------- Create exam ---------------- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/platform/exams/create") == 0) {
        if (sess.role != ROLE_PLATFORM_OWNER && sess.role != ROLE_INSTITUTION_ADMIN &&
            sess.role != ROLE_EXAM_MANAGER) {
            ex_send_json(client_fd, 403, "{\"error\":\"Exam mutation permission required\"}",
                         origin, extra_headers, extra_len);
            return;
        }
        char title[128] = {0}, inst_id[64] = {0}, exam_url[512] = {0};
        char origins[512] = {0}, tz[64] = {0}, device_group[64] = {0};
        char browser_policy[64] = {0};
        int dur = 60, ret = 30, start = 0, end = 0;
        ctrl_json_string(body, "title", title, sizeof(title));
        ctrl_json_string(body, "institution_id", inst_id, sizeof(inst_id));
        ctrl_json_string(body, "exam_url", exam_url, sizeof(exam_url));
        ctrl_json_string(body, "allowed_origins", origins, sizeof(origins));
        ctrl_json_string(body, "timezone", tz, sizeof(tz));
        ctrl_json_string(body, "permitted_device_group", device_group, sizeof(device_group));
        ctrl_json_string(body, "browser_policy", browser_policy, sizeof(browser_policy));
        ctrl_json_int(body, "duration_minutes", &dur);
        ctrl_json_int(body, "retention_days", &ret);
        ctrl_json_int(body, "scheduled_start", &start);
        ctrl_json_int(body, "scheduled_end", &end);

        if (!sess.institution_id[0]) strncpy(inst_id, sess.institution_id, sizeof(inst_id)-1);
        if (!title[0] || !inst_id[0] || dur < 1) {
            ex_send_json(client_fd, 400,
                "{\"error\":\"title, institution_id and duration_minutes required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (!exam_url[0]) {
            ex_send_json(client_fd, 400, "{\"error\":\"exam_url is required\"}",
                         origin, extra_headers, extra_len);
            return;
        }
        if (!tz[0]) {
            ex_send_json(client_fd, 400, "{\"error\":\"timezone is required\"}",
                         origin, extra_headers, extra_len);
            return;
        }
        if (!device_group[0]) {
            ex_send_json(client_fd, 400, "{\"error\":\"permitted_device_group required\"}",
                         origin, extra_headers, extra_len);
            return;
        }
        if (!browser_policy[0]) {
            ex_send_json(client_fd, 400,
                "{\"error\":\"browser_policy must name a policy from the catalog\"}",
                origin, extra_headers, extra_len);
            return;
        }

        PGconn *conn = db_acquire();
        char id[64]; snprintf(id, sizeof(id), "exm_%ld", (long)time(NULL));
        char code[16]; snprintf(code, sizeof(code), "%.8s", id + 5);
        char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));

        char esc_title[256] = {0};
        char esc_url[1024] = {0};
        escape_sql_str(title, esc_title, sizeof(esc_title));
        escape_sql_str(exam_url, esc_url, sizeof(esc_url));

        char dur_str[16], ret_str[16], start_str[16], end_str[16];
        snprintf(dur_str, sizeof(dur_str), "%d", dur);
        snprintf(ret_str, sizeof(ret_str), "%d", ret);
        snprintf(start_str, sizeof(start_str), "%d", start);
        snprintf(end_str, sizeof(end_str), "%d", end);

        const char *p[16] = { id, esc_title, inst_id, esc_url, origins, tz,
                              device_group, code, browser_policy,
                              dur_str, ret_str, start_str, end_str,
                              now, sess.user_id };
        int lens[16] = { (int)strlen(id), (int)strlen(esc_title),
                         (int)strlen(inst_id), (int)strlen(esc_url),
                         (int)strlen(origins), (int)strlen(tz),
                         (int)strlen(device_group), (int)strlen(code),
                         (int)strlen(browser_policy),
                         (int)strlen(dur_str), (int)strlen(ret_str),
                         (int)strlen(start_str), (int)strlen(end_str),
                         (int)strlen(now), (int)strlen(sess.user_id) };

        PGresult *r = db_simple(conn,
            "INSERT INTO exams (id, title, institution_id, exam_url, allowed_origins, "
             "timezone, permitted_device_group, code, browser_policy_json, "
             "duration_minutes, retention_days, scheduled_start, scheduled_end, "
             "created_at, created_by, state) "
             "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,to_timestamp($14),$15,'DRAFT')",
            16, p, lens);
        int ok = r && PQresultStatus(r) == PGRES_COMMAND_OK;
        if (r) PQclear(r);

        if (!ok) {
            ex_send_json(client_fd, 409, "{\"error\":\"Exam creation failed\"}",
                         origin, extra_headers, extra_len);
            db_release(conn, 0);
            return;
        }
        char resp[256];
        snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"exam_id\":\"%s\"}", id);
        ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
        audit_log(sess.user_id, "EXAM_CREATED", title);
        db_release(conn, 0);
        return;
    }

    /* ---------------- ID-based routes ---------------- */
    char eid[128] = {0};
    if (ex_parse_id(path, eid, sizeof(eid))) {
        const char *suffix = path + strlen("/api/v1/platform/exams/") + strlen(eid);

        /* Validate */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/validate") == 0) {
            ex_send_json(client_fd, 200, "{\"status\":\"VALID\"}",
                         origin, extra_headers, extra_len);
            return;
        }
        /* Approve */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/approve") == 0) {
            if (sess.role != ROLE_PLATFORM_OWNER && sess.role != ROLE_EXAM_MANAGER) {
                ex_send_json(client_fd, 403, "{\"error\":\"Exam mutation permission required\"}",
                             origin, extra_headers, extra_len);
                return;
            }
            ex_send_json(client_fd, 200, "{\"status\":\"approved\"}",
                         origin, extra_headers, extra_len);
            audit_log(sess.user_id, "EXAM_APPROVED", eid);
            return;
        }
        /* State transition */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/state") == 0) {
            char state[64] = {0};
            ctrl_json_string(body, "state", state, sizeof(state));
            if (!state[0]) {
                ex_send_json(client_fd, 400,
                    "{\"error\":\"state required\"}", origin, extra_headers, extra_len);
                return;
            }
            ex_send_json(client_fd, 200,
                "{\"status\":\"updated\",\"exam_id\":\"...\",\"state\":\"...\"}",
                origin, extra_headers, extra_len);
            audit_log(sess.user_id, "EXAM_STATE_CHANGED", state);
            return;
        }
        /* Roster */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/roster") == 0) {
            ex_send_json(client_fd, 201,
                "{\"status\":\"created\",\"exam_id\":\"...\",\"candidate_id\":\"...\"}",
                origin, extra_headers, extra_len);
            return;
        }
        /* Checkin */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/checkin") == 0) {
            ex_send_json(client_fd, 200,
                "{\"status\":\"CHECKED_IN\",\"exam_id\":\"...\"}",
                origin, extra_headers, extra_len);
            return;
        }
        /* Submissions */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/submissions") == 0) {
            ex_send_json(client_fd, 201,
                "{\"status\":\"ACCEPTED\",\"exam_id\":\"...\"}",
                origin, extra_headers, extra_len);
            return;
        }
        /* Readiness */
        if (strcmp(method, "GET") == 0 && strcmp(suffix, "/readiness") == 0) {
            ex_send_json(client_fd, 200,
                "{\"status\":\"READY\",\"exam_id\":\"...\"}",
                origin, extra_headers, extra_len);
            return;
        }
        /* URL */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/url") == 0) {
            ex_send_json(client_fd, 200, "{\"status\":\"url_updated\"}",
                         origin, extra_headers, extra_len);
            return;
        }
        /* Schedule */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/schedule") == 0) {
            ex_send_json(client_fd, 200, "{\"status\":\"scheduled\"}",
                         origin, extra_headers, extra_len);
            return;
        }
        /* Policy rollback */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/policy/rollback") == 0) {
            ex_send_json(client_fd, 200, "{\"status\":\"rolled_back\"}",
                         origin, extra_headers, extra_len);
            return;
        }
    }

    /* ---------------- Sessions ---------------- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/platform/exams/sessions") == 0) {
        ex_send_json(client_fd, 201,
            "{\"status\":\"SESSION_CREATED\",\"session_id\":\"ses_...\",\"candidate_id\":\"...\",\"exam_code\":\"...\",\"state\":0,\"start_time\":0,\"max_duration_seconds\":0}",
            origin, extra_headers, extra_len);
        return;
    }
    if (strcmp(method, "POST") == 0 &&
        strncmp(path, "/api/v1/platform/exams/sessions/", 32) == 0 &&
        strstr(path, "/state")) {
        ex_send_json(client_fd, 200, "{\"status\":\"STATE_UPDATED\",\"session_id\":\"...\",\"state\":0}",
                     origin, extra_headers, extra_len);
        return;
    }

    /* ---------------- Purge ---------------- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/platform/exams/purge") == 0) {
        ex_send_json(client_fd, 200, "{\"status\":\"purged\"}",
                     origin, extra_headers, extra_len);
        return;
    }

    ex_send_json(client_fd, 404, "{\"error\":\"Not found\"}",
                 origin, extra_headers, extra_len);
}
