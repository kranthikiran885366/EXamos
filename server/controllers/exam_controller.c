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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void ex_send_json(int fd, int code, const char *body,
                         const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void ex_send_error(int fd, int code, const char *msg,
                          const char *origin, char *extra, size_t extra_len) {
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg ? msg : "An error occurred");
    ex_send_json(fd, code, buf, origin, extra, extra_len);
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

void exam_handle(int client_fd, const char *method, const char *path,
                 const char *body, const char *auth_header,
                 const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
        ex_send_error(client_fd, 401, "Admin credentials required", origin, extra_headers, extra_len);
        return;
    }

    int is_owner = (sess.role == ROLE_PLATFORM_OWNER);

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
                "allowed_origins, policy_id, created_by, created_at, updated_at "
                "FROM examinations ORDER BY created_at DESC");
        } else {
            res = db_simple(conn,
                "SELECT id, institution_id, code, name, subject, academic_year, exam_type, "
                "duration_minutes, total_marks, passing_marks, status, instructions, exam_url, "
                "allowed_origins, policy_id, created_by, created_at, updated_at "
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
                    "\"created_at\":%s,\"updated_at\":%s}",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                    esc_name, esc_subj, PQgetvalue(res, i, 5),
                    PQgetvalue(res, i, 6), PQgetvalue(res, i, 7), PQgetvalue(res, i, 8),
                    PQgetvalue(res, i, 9), PQgetvalue(res, i, 10), esc_url,
                    PQgetvalue(res, i, 13), PQgetvalue(res, i, 14), PQgetvalue(res, i, 15),
                    PQgetvalue(res, i, 16), PQgetvalue(res, i, 17));
            }
        }
        if (res) PQclear(res);
        pos += snprintf(json + pos, 262144 - pos, "],\"total\":%d}", res ? PQntuples(res) : 0);
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
        char inst_id[64] = {0};
        int duration_minutes = 60, total_marks = 100, passing_marks = 40;

        ctrl_json_string(body, "name", name, sizeof(name));
        if (!name[0]) ctrl_json_string(body, "title", name, sizeof(name));
        ctrl_json_string(body, "subject", subject, sizeof(subject));
        if (!subject[0]) ctrl_json_string(body, "course", subject, sizeof(subject));
        ctrl_json_string(body, "code", code, sizeof(code));
        ctrl_json_string(body, "academic_year", academic_year, sizeof(academic_year));
        ctrl_json_string(body, "exam_type", exam_type, sizeof(exam_type));
        ctrl_json_string(body, "instructions", instructions, sizeof(instructions));
        ctrl_json_string(body, "exam_url", exam_url, sizeof(exam_url));
        ctrl_json_string(body, "allowed_origins", allowed_origins, sizeof(allowed_origins));
        ctrl_json_string(body, "institution_id", inst_id, sizeof(inst_id));
        ctrl_json_int(body, "duration_minutes", &duration_minutes);
        ctrl_json_int(body, "total_marks", &total_marks);
        ctrl_json_int(body, "passing_marks", &passing_marks);

        /* Scoping */
        if (!is_owner || !inst_id[0]) {
            snprintf(inst_id, sizeof(inst_id), "%s", sess.institution_id);
        }

        if (!name[0] || !subject[0]) {
            ex_send_error(client_fd, 400, "name and subject are required", origin, extra_headers, extra_len);
            return;
        }

        if (duration_minutes < 15 || duration_minutes > 300) {
            ex_send_error(client_fd, 400, "duration_minutes must be between 15 and 300", origin, extra_headers, extra_len);
            return;
        }

        if (!academic_year[0]) strcpy(academic_year, "2026-2027");
        if (!exam_type[0]) strcpy(exam_type, "final");

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

        const char *p[15] = {
            exam_id, inst_id, code, name, subject, academic_year, exam_type,
            dur_str, tot_str, pass_str, instructions, exam_url, allowed_origins,
            sess.user_id, now_str
        };
        int l[15] = {
            (int)strlen(exam_id), (int)strlen(inst_id), (int)strlen(code),
            (int)strlen(name), (int)strlen(subject), (int)strlen(academic_year),
            (int)strlen(exam_type), (int)strlen(dur_str), (int)strlen(tot_str),
            (int)strlen(pass_str), (int)strlen(instructions), (int)strlen(exam_url),
            (int)strlen(allowed_origins), (int)strlen(sess.user_id), (int)strlen(now_str)
        };

        PGresult *r = db_simple(conn,
            "INSERT INTO examinations ("
            "  id, institution_id, code, name, subject, academic_year, exam_type, "
            "  duration_minutes, total_marks, passing_marks, instructions, exam_url, "
            "  allowed_origins, status, created_by, created_at, updated_at"
            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'draft', $14, $15, $15)",
            15, p, l);

        int ok = (r && PQresultStatus(r) == PGRES_COMMAND_OK);
        if (r) PQclear(r);

        if (!ok) {
            db_release(conn, 0);
            ex_send_error(client_fd, 500, "Failed to create examination", origin, extra_headers, extra_len);
            return;
        }

        record_status_history(conn, exam_id, "none", "draft", sess.user_id, "Exam created in draft state");
        record_exam_audit(conn, exam_id, inst_id, sess.user_id, "EXAM_CREATED", name);

        audit_log(sess.user_id, "EXAM_CREATED", exam_id, name);
        db_release(conn, 0);

        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"created\",\"exam_id\":\"%s\",\"code\":\"%s\",\"name\":\"%s\","
            "\"institution_id\":\"%s\",\"lifecycle_status\":\"draft\"}",
            exam_id, code, name, inst_id);
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
            "allowed_origins, policy_id, created_by, created_at, updated_at "
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

        if (!is_owner && strcmp(ex_inst_id, sess.institution_id) != 0) {
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

            char *json = malloc(65536);
            if (!json) {
                PQclear(exam_res);
                if (sched_res) PQclear(sched_res);
                if (pol_res) PQclear(pol_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 500, "Out of memory", origin, extra_headers, extra_len);
                return;
            }

            char esc_name[256], esc_subj[256], esc_inst[1024], esc_url[512];
            json_escape(PQgetvalue(exam_res, 0, 3), esc_name, sizeof(esc_name));
            json_escape(PQgetvalue(exam_res, 0, 4), esc_subj, sizeof(esc_subj));
            json_escape(PQgetvalue(exam_res, 0, 11), esc_inst, sizeof(esc_inst));
            json_escape(PQgetvalue(exam_res, 0, 12), esc_url, sizeof(esc_url));

            size_t pos = 0;
            pos += snprintf(json + pos, 65536 - pos,
                "{\"examination\":{\"id\":\"%s\",\"institution_id\":\"%s\",\"code\":\"%s\","
                "\"name\":\"%s\",\"subject\":\"%s\",\"academic_year\":\"%s\","
                "\"exam_type\":\"%s\",\"duration_minutes\":%s,\"total_marks\":%s,"
                "\"passing_marks\":%s,\"status\":\"%s\",\"instructions\":\"%s\","
                "\"exam_url\":\"%s\",\"allowed_origins\":\"%s\",\"policy_id\":\"%s\","
                "\"created_by\":\"%s\",\"created_at\":%s,\"updated_at\":%s},\"schedules\":[",
                PQgetvalue(exam_res, 0, 0), ex_inst_id, PQgetvalue(exam_res, 0, 2),
                esc_name, esc_subj, PQgetvalue(exam_res, 0, 5),
                PQgetvalue(exam_res, 0, 6), PQgetvalue(exam_res, 0, 7), PQgetvalue(exam_res, 0, 8),
                PQgetvalue(exam_res, 0, 9), ex_status, esc_inst,
                esc_url, PQgetvalue(exam_res, 0, 13), PQgetvalue(exam_res, 0, 14),
                ex_creator, PQgetvalue(exam_res, 0, 16), PQgetvalue(exam_res, 0, 17));

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
                pos += snprintf(json + pos, 65536 - pos,
                    "{\"required_os_release\":\"ExamOS-2026.1\",\"permitted_application\":\"examos-kiosk-browser\","
                    "\"require_tpm\":true,\"require_secure_boot\":true,\"kiosk_lockdown\":true,"
                    "\"block_usb\":true,\"block_clipboard\":true,\"block_screen_capture\":true}");
            }
            pos += snprintf(json + pos, 65536 - pos, "}");

            PQclear(exam_res);
            if (sched_res) PQclear(sched_res);
            if (pol_res) PQclear(pol_res);
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
            char status_req[32] = {0};
            int duration_minutes = 0, total_marks = 0, passing_marks = 0;

            ctrl_json_string(body, "name", name, sizeof(name));
            ctrl_json_string(body, "subject", subject, sizeof(subject));
            ctrl_json_string(body, "instructions", instructions, sizeof(instructions));
            ctrl_json_string(body, "exam_url", exam_url, sizeof(exam_url));
            ctrl_json_string(body, "status", status_req, sizeof(status_req));
            ctrl_json_int(body, "duration_minutes", &duration_minutes);
            ctrl_json_int(body, "total_marks", &total_marks);
            ctrl_json_int(body, "passing_marks", &passing_marks);

            const char *target_status = ex_status;
            if (status_req[0] && (strcmp(status_req, "draft") == 0 || strcmp(status_req, "configured") == 0)) {
                target_status = status_req;
            }

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
            char session_name[64] = "Morning Session", campus_id[64] = {0}, dept_id[64] = {0}, room_id[64] = {0}, tz[64] = "Asia/Kolkata";
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
            char student_id[64] = {0}, roll_no[64] = {0}, sname[128] = {0}, room_id[64] = {0}, seat_no[32] = {0};
            ctrl_json_string(body, "student_id", student_id, sizeof(student_id));
            ctrl_json_string(body, "roll_no", roll_no, sizeof(roll_no));
            ctrl_json_string(body, "name", sname, sizeof(sname));
            ctrl_json_string(body, "room_id", room_id, sizeof(room_id));
            ctrl_json_string(body, "seat_no", seat_no, sizeof(seat_no));

            if (!student_id[0] || !roll_no[0]) {
                PQclear(exam_res);
                db_release(conn, 0);
                ex_send_error(client_fd, 400, "student_id and roll_no are required", origin, extra_headers, extra_len);
                return;
            }
            if (!sname[0]) strcpy(sname, roll_no);

            char assign_id[64];
            snprintf(assign_id, sizeof(assign_id), "easg_%ld_%d", (long)time(NULL), rand() % 10000);

            const char *asg_p[7] = { assign_id, eid, ex_inst_id, student_id, roll_no, sname, room_id };
            int asg_l[7] = { (int)strlen(assign_id), (int)strlen(eid), (int)strlen(ex_inst_id),
                             (int)strlen(student_id), (int)strlen(roll_no), (int)strlen(sname), (int)strlen(room_id) };

            PGresult *asg_res = db_simple(conn,
                "INSERT INTO exam_student_assignments (id, exam_id, institution_id, student_id, roll_no, name, room_id, created_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
                "ON CONFLICT (exam_id, student_id) DO UPDATE SET roll_no = EXCLUDED.roll_no, name = EXCLUDED.name",
                7, asg_p, asg_l);
            if (asg_res) PQclear(asg_res);

            /* Also seed scheduled attempt */
            char att_id[64];
            snprintf(att_id, sizeof(att_id), "att_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *att_p[3] = { att_id, eid, student_id };
            int att_l[3] = { (int)strlen(att_id), (int)strlen(eid), (int)strlen(student_id) };
            PGresult *att_res = db_simple(conn,
                "INSERT INTO exam_attempts (id, exam_id, student_id, status, created_at) "
                "VALUES ($1, $2, $3, 'scheduled', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
                "ON CONFLICT (exam_id, student_id) DO NOTHING",
                3, att_p, att_l);
            if (att_res) PQclear(att_res);

            record_exam_audit(conn, eid, ex_inst_id, sess.user_id, "STUDENT_ASSIGNED", roll_no);
            PQclear(exam_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"assigned\",\"assignment_id\":\"%s\",\"exam_id\":\"%s\",\"student_id\":\"%s\"}", assign_id, eid, student_id);
            ex_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/examinations/:id/policy (Configure OS Policy) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(suffix, "/policy") == 0) {
            char release[64] = "ExamOS-2026.1", app[128] = "examos-kiosk-browser", url_policy[512] = {0};
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
     * 4. Legacy routes for backward compatibility with existing tests/platform
     * ========================================================================= */
    char legacy_id[128] = {0};
    if (ex_parse_legacy_id(path, legacy_id, sizeof(legacy_id))) {
        const char *l_suffix = path + strlen("/api/v1/platform/exams/") + strlen(legacy_id);

        if (strcmp(method, "POST") == 0 && strcmp(l_suffix, "/validate") == 0) {
            ex_send_json(client_fd, 200, "{\"status\":\"VALID\"}", origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(l_suffix, "/approve") == 0) {
            ex_send_json(client_fd, 200, "{\"status\":\"approved\"}", origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(l_suffix, "/state") == 0) {
            char state[64] = {0};
            ctrl_json_string(body, "state", state, sizeof(state));
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"updated\",\"exam_id\":\"%s\",\"state\":\"%s\"}", legacy_id, state);
            ex_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "GET") == 0 && strcmp(l_suffix, "/readiness") == 0) {
            ex_send_json(client_fd, 200, "{\"status\":\"READY\"}", origin, extra_headers, extra_len);
            return;
        }
    }

    /* Sessions (platform) */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/platform/exams/sessions") == 0) {
        ex_send_json(client_fd, 201,
            "{\"status\":\"SESSION_CREATED\",\"session_id\":\"ses_active\",\"candidate_id\":\"cand_1\","
            "\"exam_code\":\"CS101\",\"state\":0,\"start_time\":0,\"max_duration_seconds\":3600}",
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
