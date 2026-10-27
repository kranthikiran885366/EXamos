/*
 * registration_controller.c — ExamOS Module 10: Examination Registration & Eligibility Management.
 * Controls student registration, multi-factor eligibility rule evaluation,
 * approvals, exceptions, bulk imports, versioned roster publications, and real-time exam-start gate.
 */

#include "registration_controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../security/security.h"
#include "../include/ledger.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static void reg_send_json(int fd, int code, const char *body,
                          const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void reg_send_error(int fd, int code, const char *msg,
                           const char *origin, char *extra, size_t extra_len) {
    char esc[512] = {0};
    json_escape(msg ? msg : "An error occurred", esc, sizeof(esc));
    char buf[600];
    snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", esc);
    reg_send_json(fd, code, buf, origin, extra, extra_len);
}

static void audit_log(const char *actor, const char *event, const char *target, const char *detail) {
    audit_append(actor ? actor : "system", event, detail ? detail : "");
    ledger_block_t blk;
    ledger_append_event(event, target ? target : "REGISTRATION", detail ? detail : "", &blk);
}

static void compute_sha256(const char *in, size_t in_len, char *out_hex, size_t out_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)in, in_len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH && (size_t)(i * 2 + 2) < out_len; i++) {
        sprintf(out_hex + (i * 2), "%02x", hash[i]);
    }
}

/* Helper to record registration audit log */
static void record_reg_audit(PGconn *conn, const char *reg_id, const char *exam_id,
                             const char *inst_id, const char *actor_id,
                             const char *action, const char *details) {
    char aid[64];
    snprintf(aid, sizeof(aid), "raud_%ld_%d", (long)time(NULL), rand() % 10000);
    const char *p[7] = { aid, reg_id ? reg_id : "", exam_id, inst_id, actor_id, action, details ? details : "" };
    int l[7];
    for (int i = 0; i < 7; i++) l[i] = p[i] ? (int)strlen(p[i]) : 0;
    PGresult *r = db_simple(conn,
        "INSERT INTO registration_audit_logs (id, registration_id, examination_id, institution_id, actor_id, action, details, created_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
        7, p, l);
    if (r) PQclear(r);
}

/* 
 * Rules evaluation engine:
 * Evaluates student against configured eligibility rules for the exam.
 * Returns 1 if all passed, 0 if any failed. Fills fail_reason if any failed.
 */
static int evaluate_student_eligibility(PGconn *conn, const char *exam_id, const char *student_id,
                                        char *out_details, size_t details_len, char *out_fail_reason, size_t reason_len) {
    out_details[0] = '\0';
    out_fail_reason[0] = '\0';

    /* Fetch student */
    const char *sp[1] = { student_id };
    int sl[1] = { (int)strlen(student_id) };
    PGresult *s_res = db_simple(conn,
        "SELECT id, institution_id, roll_no, name, course, semester, academic_status, "
        "attendance_pct, prerequisites_completed, administrative_hold, hold_reason "
        "FROM students WHERE id = $1", 1, sp, sl);

    if (!s_res || PQntuples(s_res) == 0) {
        if (s_res) PQclear(s_res);
        snprintf(out_fail_reason, reason_len, "Student record not found in institution database");
        return 0;
    }

    const char *s_course = PQgetvalue(s_res, 0, 4);
    int s_sem = atoi(PQgetvalue(s_res, 0, 5));
    const char *s_status = PQgetvalue(s_res, 0, 6);
    int s_att = atoi(PQgetvalue(s_res, 0, 7));
    const char *s_prereq = PQgetvalue(s_res, 0, 8);
    int s_hold = (strcmp(PQgetvalue(s_res, 0, 9), "t") == 0);
    const char *s_hold_reason = PQgetvalue(s_res, 0, 10);

    /* Fetch active eligibility rules for exam */
    const char *ep[1] = { exam_id };
    int el[1] = { (int)strlen(exam_id) };
    PGresult *r_res = db_simple(conn,
        "SELECT id, rule_type, rule_config_json FROM eligibility_rules "
        "WHERE examination_id = $1 AND active = true ORDER BY created_at ASC", 1, ep, el);

    int all_passed = 1;
    char details[2048] = "{\"checks\":[";
    size_t dpos = strlen(details);

    /* Check 1: Base Academic Status (must be 'active') */
    if (strcmp(s_status, "active") != 0) {
        all_passed = 0;
        snprintf(out_fail_reason, reason_len, "Student academic status is %s (must be active)", s_status);
        dpos += snprintf(details + dpos, sizeof(details) - dpos,
            "{\"rule\":\"academic_status\",\"passed\":false,\"reason\":\"Status is %s\"}", s_status);
    } else {
        dpos += snprintf(details + dpos, sizeof(details) - dpos,
            "{\"rule\":\"academic_status\",\"passed\":true}");
    }

    /* Check 2: Administrative Hold */
    if (s_hold) {
        all_passed = 0;
        if (!out_fail_reason[0]) {
            snprintf(out_fail_reason, reason_len, "Administrative hold: %s", s_hold_reason[0] ? s_hold_reason : "Pending clearance");
        }
        dpos += snprintf(details + dpos, sizeof(details) - dpos,
            ",{\"rule\":\"administrative_hold\",\"passed\":false,\"reason\":\"%s\"}", s_hold_reason[0] ? s_hold_reason : "Active hold");
    } else {
        dpos += snprintf(details + dpos, sizeof(details) - dpos,
            ",{\"rule\":\"administrative_hold\",\"passed\":true}");
    }

    /* Check 3: Configured rules from eligibility_rules */
    if (r_res && PQresultStatus(r_res) == PGRES_TUPLES_OK) {
        int n = PQntuples(r_res);
        for (int i = 0; i < n; i++) {
            const char *rtype = PQgetvalue(r_res, i, 1);
            const char *rconf = PQgetvalue(r_res, i, 2);

            int rule_ok = 1;
            char rfail[256] = {0};

            if (strcmp(rtype, "attendance") == 0) {
                int min_att = 75;
                ctrl_json_int(rconf, "minimum_attendance_pct", &min_att);
                if (s_att < min_att) {
                    rule_ok = 0;
                    snprintf(rfail, sizeof(rfail), "Attendance %d%% is below required threshold of %d%%", s_att, min_att);
                }
            } else if (strcmp(rtype, "semester") == 0) {
                int req_sem = 0;
                ctrl_json_int(rconf, "semester", &req_sem);
                if (req_sem > 0 && s_sem != req_sem) {
                    rule_ok = 0;
                    snprintf(rfail, sizeof(rfail), "Enrolled in semester %d, exam requires semester %d", s_sem, req_sem);
                }
            } else if (strcmp(rtype, "course_enrollment") == 0) {
                char req_course[128] = {0};
                ctrl_json_string(rconf, "course", req_course, sizeof(req_course));
                if (req_course[0] && strcasecmp(s_course, req_course) != 0) {
                    rule_ok = 0;
                    snprintf(rfail, sizeof(rfail), "Enrolled course '%s' does not match required '%s'", s_course, req_course);
                }
            } else if (strcmp(rtype, "registration_deadline") == 0) {
                int deadline = 0;
                ctrl_json_int(rconf, "deadline", &deadline);
                if (deadline > 0 && (long)time(NULL) > deadline) {
                    rule_ok = 0;
                    snprintf(rfail, sizeof(rfail), "Registration deadline has passed");
                }
            } else if (strcmp(rtype, "prerequisites") == 0) {
                char req_pre[128] = {0};
                ctrl_json_string(rconf, "required_course", req_pre, sizeof(req_pre));
                if (req_pre[0] && (!strstr(s_prereq, req_pre))) {
                    rule_ok = 0;
                    snprintf(rfail, sizeof(rfail), "Prerequisite course '%s' not satisfied", req_pre);
                }
            }

            if (!rule_ok) {
                all_passed = 0;
                if (!out_fail_reason[0]) snprintf(out_fail_reason, reason_len, "%s", rfail);
                dpos += snprintf(details + dpos, sizeof(details) - dpos,
                    ",{\"rule\":\"%s\",\"passed\":false,\"reason\":\"%s\"}", rtype, rfail);
            } else {
                dpos += snprintf(details + dpos, sizeof(details) - dpos,
                    ",{\"rule\":\"%s\",\"passed\":true}", rtype);
            }
        }
    }
    if (r_res) PQclear(r_res);
    PQclear(s_res);

    snprintf(details + dpos, sizeof(details) - dpos, "]}");
    strncpy(out_details, details, details_len - 1);
    out_details[details_len - 1] = '\0';

    return all_passed;
}

void registration_handle(int client_fd, const char *method, const char *path,
                         const char *body, const char *auth_header,
                         const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
        reg_send_error(client_fd, 401, "Admin credentials required", origin, extra_headers, extra_len);
        return;
    }

    int is_owner = (sess.role == ROLE_PLATFORM_OWNER);
    PGconn *conn = db_acquire();

    /* =========================================================================
     * 1. POST /api/v1/admin/students: Create or update student profile
     * ========================================================================= */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/students") == 0) {
        char sid[64] = {0}, roll_no[64] = {0}, name[128] = {0}, email[128] = {0};
        char course[128] = {0}, dept_id[64] = {0}, campus_id[64] = {0}, status[32] = "active";
        char prereq[256] = {0}, hold_reason[256] = {0}, inst_id[64] = {0};
        int semester = 1, attendance = 100, hold = 0;

        ctrl_json_string(body, "id", sid, sizeof(sid));
        ctrl_json_string(body, "roll_no", roll_no, sizeof(roll_no));
        ctrl_json_string(body, "name", name, sizeof(name));
        ctrl_json_string(body, "email", email, sizeof(email));
        ctrl_json_string(body, "course", course, sizeof(course));
        ctrl_json_string(body, "department_id", dept_id, sizeof(dept_id));
        ctrl_json_string(body, "campus_id", campus_id, sizeof(campus_id));
        ctrl_json_string(body, "academic_status", status, sizeof(status));
        if (!status[0]) strcpy(status, "active");
        ctrl_json_string(body, "prerequisites_completed", prereq, sizeof(prereq));
        ctrl_json_string(body, "hold_reason", hold_reason, sizeof(hold_reason));
        ctrl_json_string(body, "institution_id", inst_id, sizeof(inst_id));
        ctrl_json_int(body, "semester", &semester);
        ctrl_json_int(body, "attendance_pct", &attendance);
        ctrl_json_bool(body, "administrative_hold", &hold);

        if (!is_owner || !inst_id[0]) {
            snprintf(inst_id, sizeof(inst_id), "%s", sess.institution_id);
        }

        if (!roll_no[0] || !name[0]) {
            db_release(conn, 0);
            reg_send_error(client_fd, 400, "roll_no and name are required", origin, extra_headers, extra_len);
            return;
        }

        if (!sid[0]) {
            snprintf(sid, sizeof(sid), "stu_%ld_%d", (long)time(NULL), rand() % 10000);
        }

        char sem_str[16], att_str[16];
        snprintf(sem_str, sizeof(sem_str), "%d", semester);
        snprintf(att_str, sizeof(att_str), "%d", attendance);

        const char *p[14] = {
            sid, inst_id, roll_no, name, email, course, dept_id,
            campus_id, sem_str, status, att_str, prereq, hold ? "t" : "f", hold_reason
        };
        int l[14];
        for (int i = 0; i < 14; i++) l[i] = p[i] ? (int)strlen(p[i]) : 0;

        PGresult *r = db_simple(conn,
            "INSERT INTO students (id, institution_id, roll_no, name, email, course, department_id, "
            "campus_id, semester, academic_status, attendance_pct, prerequisites_completed, administrative_hold, "
            "hold_reason, created_at, updated_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, "
            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
            "ON CONFLICT (institution_id, roll_no) DO UPDATE SET "
            "name = EXCLUDED.name, email = EXCLUDED.email, course = EXCLUDED.course, "
            "semester = EXCLUDED.semester, academic_status = EXCLUDED.academic_status, "
            "attendance_pct = EXCLUDED.attendance_pct, prerequisites_completed = EXCLUDED.prerequisites_completed, "
            "administrative_hold = EXCLUDED.administrative_hold, hold_reason = EXCLUDED.hold_reason, "
            "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
            "RETURNING id",
            14, p, l);

        int ok = (r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0);
        if (ok) {
            strncpy(sid, PQgetvalue(r, 0, 0), sizeof(sid) - 1);
        }
        if (r) PQclear(r);

        if (!ok) {
            char err_buf[512];
            snprintf(err_buf, sizeof(err_buf), "Failed to provision student record: %s", PQerrorMessage(conn));
            db_release(conn, 0);
            reg_send_error(client_fd, 500, err_buf, origin, extra_headers, extra_len);
            return;
        }

        db_release(conn, 0);
        char resp[256];
        snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"student_id\":\"%s\",\"roll_no\":\"%s\"}", sid, roll_no);
        reg_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 2. GET /api/v1/admin/students: List students
     * ========================================================================= */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/students") == 0) {
        PGresult *res = NULL;
        const char *pvals[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };

        if (is_owner) {
            res = PQexec(conn, "SELECT id, institution_id, roll_no, name, email, course, semester, academic_status, attendance_pct, administrative_hold FROM students ORDER BY roll_no ASC");
        } else {
            res = db_simple(conn, "SELECT id, institution_id, roll_no, name, email, course, semester, academic_status, attendance_pct, administrative_hold FROM students WHERE institution_id = $1 ORDER BY roll_no ASC", 1, pvals, lens);
        }

        char *json = malloc(131072);
        size_t pos = 0;
        pos += snprintf(json + pos, 131072 - pos, "{\"students\":[");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            int n = PQntuples(res);
            for (int i = 0; i < n; i++) {
                if (i > 0) pos += snprintf(json + pos, 131072 - pos, ",");
                pos += snprintf(json + pos, 131072 - pos,
                    "{\"id\":\"%s\",\"institution_id\":\"%s\",\"roll_no\":\"%s\",\"name\":\"%s\",\"email\":\"%s\","
                    "\"course\":\"%s\",\"semester\":%s,\"academic_status\":\"%s\",\"attendance_pct\":%s,\"administrative_hold\":%s}",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                    PQgetvalue(res, i, 3), PQgetvalue(res, i, 4), PQgetvalue(res, i, 5),
                    PQgetvalue(res, i, 6), PQgetvalue(res, i, 7), PQgetvalue(res, i, 8),
                    strcmp(PQgetvalue(res, i, 9), "t") == 0 ? "true" : "false");
            }
        }
        if (res) PQclear(res);
        pos += snprintf(json + pos, 131072 - pos, "]}");
        db_release(conn, 0);

        reg_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        free(json);
        return;
    }

    /* =========================================================================
     * 3. Examination-based routes: /api/v1/examinations/:id/...
     * ========================================================================= */
    const char *ex_prefix = "/api/v1/examinations/";
    size_t ex_plen = strlen(ex_prefix);
    if (strncmp(path, ex_prefix, ex_plen) == 0) {
        const char *sub = path + ex_plen;
        const char *slash = strchr(sub, '/');
        if (slash) {
            char exam_id[64] = {0};
            size_t id_len = (size_t)(slash - sub);
            if (id_len < sizeof(exam_id)) {
                memcpy(exam_id, sub, id_len);
                exam_id[id_len] = '\0';
                const char *action = slash; /* e.g. /rules, /registrations, /roster/publish, /eligibility/:sid */

                /* Verify Exam existence & Tenant boundary */
                const char *ep[1] = { exam_id };
                int el[1] = { (int)strlen(exam_id) };
                PGresult *ex_chk = db_simple(conn, "SELECT id, institution_id, status FROM examinations WHERE id = $1", 1, ep, el);
                if (!ex_chk || PQntuples(ex_chk) == 0) {
                    if (ex_chk) PQclear(ex_chk);
                    db_release(conn, 0);
                    reg_send_error(client_fd, 404, "Examination not found", origin, extra_headers, extra_len);
                    return;
                }
                char ex_inst[64] = {0};
                char ex_stat[32] = {0};
                strncpy(ex_inst, PQgetvalue(ex_chk, 0, 1), sizeof(ex_inst) - 1);
                strncpy(ex_stat, PQgetvalue(ex_chk, 0, 2), sizeof(ex_stat) - 1);
                if (!is_owner && strcmp(ex_inst, sess.institution_id) != 0) {
                    PQclear(ex_chk);
                    db_release(conn, 0);
                    reg_send_error(client_fd, 403, "Access to other institution's exam is prohibited", origin, extra_headers, extra_len);
                    return;
                }
                PQclear(ex_chk);

                /* ---------------- POST /api/v1/examinations/:id/rules (Configure Rule) ---------------- */
                if (strcmp(method, "POST") == 0 && strcmp(action, "/rules") == 0) {
                    char rule_type[32] = {0}, rule_conf[1024] = "{}";
                    ctrl_json_string(body, "rule_type", rule_type, sizeof(rule_type));
                    ctrl_json_string(body, "rule_config_json", rule_conf, sizeof(rule_conf));

                    if (!rule_type[0]) {
                        db_release(conn, 0);
                        reg_send_error(client_fd, 400, "rule_type is required", origin, extra_headers, extra_len);
                        return;
                    }

                    char rid[64];
                    snprintf(rid, sizeof(rid), "erul_%ld_%d", (long)time(NULL), rand() % 10000);
                    const char *rp[5] = { rid, ex_inst, exam_id, rule_type, rule_conf };
                    int rl[5];
                    for (int i = 0; i < 5; i++) rl[i] = (int)strlen(rp[i]);

                    PGresult *ins_r = db_simple(conn,
                        "INSERT INTO eligibility_rules (id, institution_id, examination_id, rule_type, rule_config_json, created_at) "
                        "VALUES ($1, $2, $3, $4, $5, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, rp, rl);
                    if (ins_r) PQclear(ins_r);

                    db_release(conn, 0);
                    char resp[256];
                    snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"rule_id\":\"%s\",\"exam_id\":\"%s\"}", rid, exam_id);
                    reg_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
                    return;
                }

                /* ---------------- GET /api/v1/examinations/:id/rules (List Rules) ---------------- */
                if (strcmp(method, "GET") == 0 && strcmp(action, "/rules") == 0) {
                    PGresult *res = db_simple(conn,
                        "SELECT id, rule_type, rule_config_json, version, active, created_at "
                        "FROM eligibility_rules WHERE examination_id = $1 ORDER BY created_at ASC", 1, ep, el);

                    char *json = malloc(65536);
                    size_t pos = 0;
                    pos += snprintf(json + pos, 65536 - pos, "{\"rules\":[");
                    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
                        int n = PQntuples(res);
                        for (int i = 0; i < n; i++) {
                            if (i > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                            pos += snprintf(json + pos, 65536 - pos,
                                "{\"id\":\"%s\",\"rule_type\":\"%s\",\"rule_config_json\":%s,\"version\":%s,\"active\":%s}",
                                PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                                PQgetvalue(res, i, 3), strcmp(PQgetvalue(res, i, 4), "t") == 0 ? "true" : "false");
                        }
                    }
                    if (res) PQclear(res);
                    pos += snprintf(json + pos, 65536 - pos, "]}");
                    db_release(conn, 0);

                    reg_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
                    free(json);
                    return;
                }

                /* ---------------- POST /api/v1/examinations/:id/registrations (Register Student) ---------------- */
                if (strcmp(method, "POST") == 0 && strcmp(action, "/registrations") == 0) {
                    char student_id[64] = {0}, roll_no[64] = {0}, sname[128] = {0};
                    ctrl_json_string(body, "student_id", student_id, sizeof(student_id));
                    ctrl_json_string(body, "roll_no", roll_no, sizeof(roll_no));
                    ctrl_json_string(body, "name", sname, sizeof(sname));

                    /* If student_id is empty but roll_no provided, lookup student */
                    if (!student_id[0] && roll_no[0]) {
                        const char *lk_p[2] = { ex_inst, roll_no };
                        int lk_l[2] = { (int)strlen(ex_inst), (int)strlen(roll_no) };
                        PGresult *lk_res = db_simple(conn,
                            "SELECT id, name FROM students WHERE institution_id = $1 AND roll_no = $2", 2, lk_p, lk_l);
                        if (lk_res && PQntuples(lk_res) > 0) {
                            strncpy(student_id, PQgetvalue(lk_res, 0, 0), sizeof(student_id) - 1);
                            if (!sname[0]) strncpy(sname, PQgetvalue(lk_res, 0, 1), sizeof(sname) - 1);
                        }
                        if (lk_res) PQclear(lk_res);
                    }

                    if (!student_id[0]) {
                        db_release(conn, 0);
                        reg_send_error(client_fd, 400, "student_id (or registered roll_no) is required", origin, extra_headers, extra_len);
                        return;
                    }

                    /* Tenant Check on Student */
                    const char *st_p[1] = { student_id };
                    int st_l[1] = { (int)strlen(student_id) };
                    PGresult *st_res = db_simple(conn,
                        "SELECT institution_id, roll_no, name FROM students WHERE id = $1", 1, st_p, st_l);
                    if (!st_res || PQntuples(st_res) == 0) {
                        if (st_res) PQclear(st_res);
                        db_release(conn, 0);
                        reg_send_error(client_fd, 404, "Student record not found in system", origin, extra_headers, extra_len);
                        return;
                    }
                    const char *st_inst = PQgetvalue(st_res, 0, 0);
                    if (strcmp(st_inst, ex_inst) != 0) {
                        PQclear(st_res);
                        db_release(conn, 0);
                        reg_send_error(client_fd, 403, "Student belongs to another institution (tenant mismatch)", origin, extra_headers, extra_len);
                        return;
                    }
                    PQclear(st_res);

                    /* Duplicate Check */
                    const char *dup_p[3] = { ex_inst, exam_id, student_id };
                    int dup_l[3] = { (int)strlen(ex_inst), (int)strlen(exam_id), (int)strlen(student_id) };
                    PGresult *dup_res = db_simple(conn,
                        "SELECT id, registration_status FROM exam_registrations "
                        "WHERE institution_id = $1 AND examination_id = $2 AND student_id = $3", 3, dup_p, dup_l);
                    if (dup_res && PQntuples(dup_res) > 0) {
                        PQclear(dup_res);
                        db_release(conn, 0);
                        reg_send_error(client_fd, 409, "Duplicate registration: student is already registered for this examination", origin, extra_headers, extra_len);
                        return;
                    }
                    if (dup_res) PQclear(dup_res);

                    /* Evaluate Eligibility */
                    char eval_details[2048] = {0};
                    char eval_fail[512] = {0};
                    int passed = evaluate_student_eligibility(conn, exam_id, student_id,
                                                              eval_details, sizeof(eval_details),
                                                              eval_fail, sizeof(eval_fail));

                    const char *reg_status = passed ? "approved" : "exception_review";
                    const char *elig_status = passed ? "eligible" : "ineligible";

                    char reg_id[64];
                    snprintf(reg_id, sizeof(reg_id), "ereg_%ld_%d", (long)time(NULL), rand() % 10000);

                    const char *ins_p[7] = {
                        reg_id, ex_inst, exam_id, student_id, reg_status, elig_status, eval_fail
                    };
                    int ins_l[7];
                    for (int i = 0; i < 7; i++) ins_l[i] = (int)strlen(ins_p[i]);

                    PGresult *ins_res = db_simple(conn,
                        "INSERT INTO exam_registrations (id, institution_id, examination_id, student_id, "
                        "registration_status, eligibility_status, rejection_reason, submitted_at, evaluated_at, created_at, updated_at) "
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                        "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
                        7, ins_p, ins_l);
                    if (ins_res) PQclear(ins_res);

                    /* Insert evaluation log */
                    char eval_id[64];
                    snprintf(eval_id, sizeof(eval_id), "eval_%ld_%d", (long)time(NULL), rand() % 10000);
                    const char *ev_p[6] = { eval_id, reg_id, exam_id, student_id, passed ? "t" : "f", eval_details };
                    int ev_l[6];
                    for (int i = 0; i < 6; i++) ev_l[i] = (int)strlen(ev_p[i]);

                    PGresult *ev_res = db_simple(conn,
                        "INSERT INTO eligibility_evaluations (id, registration_id, examination_id, student_id, passed, details_json, evaluated_at) "
                        "VALUES ($1, $2, $3, $4, $5, $6, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 6, ev_p, ev_l);
                    if (ev_res) PQclear(ev_res);

                    record_reg_audit(conn, reg_id, exam_id, ex_inst, sess.user_id, "REGISTRATION_SUBMITTED",
                                     passed ? "Passed automatic eligibility rules" : eval_fail);
                    audit_log(sess.user_id, "REGISTRATION_SUBMITTED", reg_id, passed ? "Eligible" : "Requires Review");
                    db_release(conn, 0);

                    char resp[512];
                    snprintf(resp, sizeof(resp),
                        "{\"status\":\"created\",\"registration_id\":\"%s\",\"student_id\":\"%s\","
                        "\"registration_status\":\"%s\",\"eligibility_status\":\"%s\",\"eligible\":%s,\"reason\":\"%s\"}",
                        reg_id, student_id, reg_status, elig_status, passed ? "true" : "false", eval_fail);
                    reg_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
                    return;
                }

                /* ---------------- GET /api/v1/examinations/:id/registrations (List Registrations) ---------------- */
                if (strcmp(method, "GET") == 0 && strcmp(action, "/registrations") == 0) {
                    PGresult *res = db_simple(conn,
                        "SELECT r.id, r.student_id, s.roll_no, s.name, s.course, s.semester, "
                        "r.registration_status, r.eligibility_status, r.rejection_reason, r.exception_reason, r.submitted_at "
                        "FROM exam_registrations r "
                        "LEFT JOIN students s ON s.id = r.student_id "
                        "WHERE r.examination_id = $1 ORDER BY r.submitted_at DESC", 1, ep, el);

                    char *json = malloc(131072);
                    size_t pos = 0;
                    pos += snprintf(json + pos, 131072 - pos, "{\"registrations\":[");
                    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
                        int n = PQntuples(res);
                        for (int i = 0; i < n; i++) {
                            if (i > 0) pos += snprintf(json + pos, 131072 - pos, ",");
                            char esc_name[256], esc_reason[256];
                            json_escape(PQgetvalue(res, i, 3), esc_name, sizeof(esc_name));
                            json_escape(PQgetvalue(res, i, 8), esc_reason, sizeof(esc_reason));

                            pos += snprintf(json + pos, 131072 - pos,
                                "{\"id\":\"%s\",\"student_id\":\"%s\",\"roll_no\":\"%s\",\"name\":\"%s\","
                                "\"course\":\"%s\",\"semester\":%s,\"registration_status\":\"%s\","
                                "\"eligibility_status\":\"%s\",\"rejection_reason\":\"%s\",\"submitted_at\":%s}",
                                PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                                esc_name, PQgetvalue(res, i, 4), PQgetvalue(res, i, 5),
                                PQgetvalue(res, i, 6), PQgetvalue(res, i, 7), esc_reason,
                                PQgetvalue(res, i, 10));
                        }
                    }
                    if (res) PQclear(res);
                    pos += snprintf(json + pos, 131072 - pos, "]}");
                    db_release(conn, 0);

                    reg_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
                    free(json);
                    return;
                }

                /* ---------------- POST /api/v1/examinations/:id/registrations/import (Bulk Import) ---------------- */
                if (strcmp(method, "POST") == 0 && strcmp(action, "/registrations/import") == 0) {
                    char job_id[64];
                    snprintf(job_id, sizeof(job_id), "rimp_%ld_%d", (long)time(NULL), rand() % 10000);

                    const char *j_p[4] = { job_id, exam_id, ex_inst, sess.user_id };
                    int j_l[4];
                    for (int i = 0; i < 4; i++) j_l[i] = (int)strlen(j_p[i]);

                    PGresult *j_res = db_simple(conn,
                        "INSERT INTO registration_import_jobs (id, examination_id, institution_id, status, created_by, created_at) "
                        "VALUES ($1, $2, $3, 'processing', $4, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 4, j_p, j_l);
                    if (j_res) PQclear(j_res);

                    int total = 0, valid = 0, errors = 0;

                    /* Parse JSON records array: expects [ { "roll_no": "...", "name": "...", "course": "..." }, ... ] */
                    const char *ptr = strstr(body, "\"records\":");
                    if (ptr) ptr = strchr(ptr, '[');
                    else ptr = strchr(body, '[');

                    if (ptr) {
                        ptr++;
                        while (*ptr && *ptr != ']') {
                            while (*ptr && (*ptr == ' ' || *ptr == '\n' || *ptr == '\r' || *ptr == ',')) ptr++;
                            if (*ptr == '{') {
                                total++;
                                const char *obj_start = ptr;
                                const char *obj_end = strchr(obj_start, '}');
                                if (!obj_end) break;
                                size_t obj_len = (size_t)(obj_end - obj_start + 1);
                                char row_buf[512];
                                if (obj_len < sizeof(row_buf)) {
                                    memcpy(row_buf, obj_start, obj_len);
                                    row_buf[obj_len] = '\0';

                                    char r_roll[64] = {0}, r_name[128] = {0}, r_inst[64] = {0};
                                    ctrl_json_string(row_buf, "roll_no", r_roll, sizeof(r_roll));
                                    ctrl_json_string(row_buf, "name", r_name, sizeof(r_name));
                                    ctrl_json_string(row_buf, "institution_id", r_inst, sizeof(r_inst));

                                    /* Validation 1: Required roll_no */
                                    if (!r_roll[0]) {
                                        errors++;
                                        char err_id[64];
                                        snprintf(err_id, sizeof(err_id), "rerr_%ld_%d", (long)time(NULL), rand() % 10000);
                                        char row_idx_str[16]; snprintf(row_idx_str, sizeof(row_idx_str), "%d", total);
                                        const char *er_p[5] = { err_id, job_id, row_idx_str, "MISSING_FIELD", "Missing required student roll_no" };
                                        int er_l[5]; for (int i = 0; i < 5; i++) er_l[i] = (int)strlen(er_p[i]);
                                        PGresult *er_r = db_simple(conn,
                                            "INSERT INTO registration_import_errors (id, job_id, row_index, error_code, error_message, created_at) "
                                            "VALUES ($1, $2, $3, $4, $5, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, er_p, er_l);
                                        if (er_r) PQclear(er_r);
                                    }
                                    /* Validation 2: Tenant mismatch */
                                    else if (r_inst[0] && strcmp(r_inst, ex_inst) != 0) {
                                        errors++;
                                        char err_id[64];
                                        snprintf(err_id, sizeof(err_id), "rerr_%ld_%d", (long)time(NULL), rand() % 10000);
                                        char row_idx_str[16]; snprintf(row_idx_str, sizeof(row_idx_str), "%d", total);
                                        const char *er_p[5] = { err_id, job_id, row_idx_str, "INSTITUTION_MISMATCH", "Student institution does not match examination tenant" };
                                        int er_l[5]; for (int i = 0; i < 5; i++) er_l[i] = (int)strlen(er_p[i]);
                                        PGresult *er_r = db_simple(conn,
                                            "INSERT INTO registration_import_errors (id, job_id, row_index, error_code, error_message, created_at) "
                                            "VALUES ($1, $2, $3, $4, $5, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, er_p, er_l);
                                        if (er_r) PQclear(er_r);
                                    }
                                    /* Validation 3: Check student exists */
                                    else {
                                        const char *sp[2] = { ex_inst, r_roll };
                                        int sl[2] = { (int)strlen(ex_inst), (int)strlen(r_roll) };
                                        PGresult *s_res = db_simple(conn, "SELECT id FROM students WHERE institution_id = $1 AND roll_no = $2", 2, sp, sl);
                                        if (!s_res || PQntuples(s_res) == 0) {
                                            errors++;
                                            if (s_res) PQclear(s_res);
                                            char err_id[64];
                                            snprintf(err_id, sizeof(err_id), "rerr_%ld_%d", (long)time(NULL), rand() % 10000);
                                            char row_idx_str[16]; snprintf(row_idx_str, sizeof(row_idx_str), "%d", total);
                                            const char *er_p[5] = { err_id, job_id, row_idx_str, "STUDENT_NOT_FOUND", "Student roll_no not enrolled in institution" };
                                            int er_l[5]; for (int i = 0; i < 5; i++) er_l[i] = (int)strlen(er_p[i]);
                                            PGresult *er_r = db_simple(conn,
                                                "INSERT INTO registration_import_errors (id, job_id, row_index, error_code, error_message, created_at) "
                                                "VALUES ($1, $2, $3, $4, $5, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, er_p, er_l);
                                            if (er_r) PQclear(er_r);
                                        } else {
                                            const char *found_sid = PQgetvalue(s_res, 0, 0);

                                            /* Validation 4: Duplicate in DB */
                                            const char *dp[3] = { ex_inst, exam_id, found_sid };
                                            int dl[3] = { (int)strlen(ex_inst), (int)strlen(exam_id), (int)strlen(found_sid) };
                                            PGresult *dup_r = db_simple(conn,
                                                "SELECT id FROM exam_registrations WHERE institution_id = $1 AND examination_id = $2 AND student_id = $3", 3, dp, dl);
                                            if (dup_r && PQntuples(dup_r) > 0) {
                                                errors++;
                                                PQclear(dup_r);
                                                PQclear(s_res);
                                                char err_id[64];
                                                snprintf(err_id, sizeof(err_id), "rerr_%ld_%d", (long)time(NULL), rand() % 10000);
                                                char row_idx_str[16]; snprintf(row_idx_str, sizeof(row_idx_str), "%d", total);
                                                const char *er_p[5] = { err_id, job_id, row_idx_str, "DUPLICATE_REGISTRATION", "Student already registered for this exam" };
                                                int er_l[5]; for (int i = 0; i < 5; i++) er_l[i] = (int)strlen(er_p[i]);
                                                PGresult *er_r = db_simple(conn,
                                                    "INSERT INTO registration_import_errors (id, job_id, row_index, error_code, error_message, created_at) "
                                                    "VALUES ($1, $2, $3, $4, $5, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, er_p, er_l);
                                                if (er_r) PQclear(er_r);
                                            } else {
                                                if (dup_r) PQclear(dup_r);
                                                valid++;
                                                char reg_id[64];
                                                snprintf(reg_id, sizeof(reg_id), "ereg_%ld_%d", (long)time(NULL), rand() % 10000);

                                                /* Evaluate */
                                                char eval_details[2048] = {0};
                                                char eval_fail[512] = {0};
                                                int passed = evaluate_student_eligibility(conn, exam_id, found_sid,
                                                                                          eval_details, sizeof(eval_details),
                                                                                          eval_fail, sizeof(eval_fail));

                                                const char *reg_status = passed ? "approved" : "exception_review";
                                                const char *elig_status = passed ? "eligible" : "ineligible";

                                                const char *inp[7] = {
                                                    reg_id, ex_inst, exam_id, found_sid, reg_status, elig_status, eval_fail
                                                };
                                                int inpl[7];
                                                for (int i = 0; i < 7; i++) inpl[i] = (int)strlen(inp[i]);
                                                PGresult *in_res = db_simple(conn,
                                                    "INSERT INTO exam_registrations (id, institution_id, examination_id, student_id, "
                                                    "registration_status, eligibility_status, rejection_reason, submitted_at, evaluated_at, created_at, updated_at) "
                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                                                    "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
                                                    7, inp, inpl);
                                                if (in_res) PQclear(in_res);
                                                PQclear(s_res);
                                            }
                                        }
                                    }
                                }
                                ptr = obj_end + 1;
                            } else {
                                ptr++;
                            }
                        }
                    }

                    /* Complete job */
                    char tot_s[16], val_s[16], err_s[16];
                    snprintf(tot_s, sizeof(tot_s), "%d", total);
                    snprintf(val_s, sizeof(val_s), "%d", valid);
                    snprintf(err_s, sizeof(err_s), "%d", errors);

                    const char *uj_p[5] = { tot_s, val_s, err_s, job_id, "completed" };
                    int uj_l[5];
                    for (int i = 0; i < 5; i++) uj_l[i] = (int)strlen(uj_p[i]);

                    PGresult *uj_res = db_simple(conn,
                        "UPDATE registration_import_jobs SET total_rows = $1, valid_rows = $2, error_rows = $3, "
                        "status = $5, completed_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $4", 5, uj_p, uj_l);
                    if (uj_res) PQclear(uj_res);

                    record_reg_audit(conn, NULL, exam_id, ex_inst, sess.user_id, "BULK_IMPORT_COMPLETED", tot_s);
                    db_release(conn, 0);

                    char resp[256];
                    snprintf(resp, sizeof(resp),
                        "{\"job_id\":\"%s\",\"status\":\"completed\",\"total_rows\":%d,\"valid_rows\":%d,\"error_rows\":%d}",
                        job_id, total, valid, errors);
                    reg_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                    return;
                }

                /* ---------------- POST /api/v1/examinations/:id/roster/publish (Publish Roster) ---------------- */
                if (strcmp(method, "POST") == 0 && strcmp(action, "/roster/publish") == 0) {
                    /* Fetch next roster version */
                    PGresult *v_res = db_simple(conn,
                        "SELECT COALESCE(MAX(version), 0) + 1 FROM exam_roster_versions WHERE examination_id = $1", 1, ep, el);
                    int next_version = 1;
                    if (v_res && PQntuples(v_res) > 0) next_version = atoi(PQgetvalue(v_res, 0, 0));
                    if (v_res) PQclear(v_res);

                    /* Fetch all approved registrations */
                    PGresult *app_res = db_simple(conn,
                        "SELECT r.id, r.student_id, s.roll_no, s.name, s.campus_id, s.department_id "
                        "FROM exam_registrations r "
                        "JOIN students s ON s.id = r.student_id "
                        "WHERE r.examination_id = $1 AND r.registration_status = 'approved' ORDER BY s.roll_no ASC", 1, ep, el);

                    int total_students = (app_res && PQresultStatus(app_res) == PGRES_TUPLES_OK) ? PQntuples(app_res) : 0;

                    /* Compute cumulative SHA-256 hash of roster for tamper-evident verification */
                    char hash_input[32768] = {0};
                    size_t hpos = 0;
                    for (int i = 0; i < total_students && hpos + 128 < sizeof(hash_input); i++) {
                        hpos += snprintf(hash_input + hpos, sizeof(hash_input) - hpos, "%s:%s;",
                            PQgetvalue(app_res, i, 2), PQgetvalue(app_res, i, 3));
                    }
                    char roster_hash[65] = {0};
                    compute_sha256(hash_input, hpos, roster_hash, sizeof(roster_hash));

                    char rvid[64];
                    snprintf(rvid, sizeof(rvid), "erv_%ld_%d", (long)time(NULL), rand() % 10000);
                    char ver_str[16], tot_str[16];
                    snprintf(ver_str, sizeof(ver_str), "%d", next_version);
                    snprintf(tot_str, sizeof(tot_str), "%d", total_students);

                    const char *rv_p[7] = { rvid, exam_id, ex_inst, ver_str, sess.user_id, tot_str, roster_hash };
                    int rv_l[7];
                    for (int i = 0; i < 7; i++) rv_l[i] = (int)strlen(rv_p[i]);

                    PGresult *rv_res = db_simple(conn,
                        "INSERT INTO exam_roster_versions (id, examination_id, institution_id, version, published_by, total_students, roster_hash, published_at) "
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 7, rv_p, rv_l);
                    if (rv_res) PQclear(rv_res);

                    /* Insert entries and sync into exam_student_assignments and candidates */
                    for (int i = 0; i < total_students; i++) {
                        const char *sid = PQgetvalue(app_res, i, 1);
                        const char *sroll = PQgetvalue(app_res, i, 2);
                        const char *sname = PQgetvalue(app_res, i, 3);
                        const char *scampus = PQgetvalue(app_res, i, 4);

                        char entry_id[64];
                        snprintf(entry_id, sizeof(entry_id), "rent_%ld_%d", (long)time(NULL), rand() % 10000);
                        const char *ent_p[7] = { entry_id, rvid, exam_id, sid, sroll, sname, scampus };
                        int ent_l[7];
                        for (int k = 0; k < 7; k++) ent_l[k] = (int)strlen(ent_p[k]);

                        PGresult *ent_r = db_simple(conn,
                            "INSERT INTO exam_roster_entries (id, roster_version_id, examination_id, student_id, roll_no, name, campus_id, created_at) "
                            "VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 7, ent_p, ent_l);
                        if (ent_r) PQclear(ent_r);

                        /* Sync into exam_student_assignments */
                        char asg_id[64];
                        snprintf(asg_id, sizeof(asg_id), "easg_%ld_%d", (long)time(NULL), rand() % 10000);
                        const char *asg_p[6] = { asg_id, exam_id, ex_inst, sid, sroll, sname };
                        int asg_l[6];
                        for (int k = 0; k < 6; k++) asg_l[k] = (int)strlen(asg_p[k]);
                        PGresult *asg_r = db_simple(conn,
                            "INSERT INTO exam_student_assignments (id, exam_id, institution_id, student_id, roll_no, name, created_at) "
                            "VALUES ($1, $2, $3, $4, $5, $6, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
                            "ON CONFLICT (exam_id, student_id) DO UPDATE SET roll_no = EXCLUDED.roll_no, name = EXCLUDED.name",
                            6, asg_p, asg_l);
                        if (asg_r) PQclear(asg_r);

                        /* Sync into candidates table */
                        char cand_id[64];
                        snprintf(cand_id, sizeof(cand_id), "cnd_%ld_%d", (long)time(NULL), rand() % 10000);
                        const char *cnd_p[5] = { cand_id, ex_inst, sroll, sname, exam_id };
                        int cnd_l[5];
                        for (int k = 0; k < 5; k++) cnd_l[k] = (int)strlen(cnd_p[k]);
                        PGresult *cnd_r = db_simple(conn,
                            "INSERT INTO candidates (id, tenant_id, roll_no, name, exam_id, status, identity, created_at) "
                            "VALUES ($1, $2, $3, $4, $5, 'registered', 'verified', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
                            "ON CONFLICT (id) DO NOTHING", 5, cnd_p, cnd_l);
                        if (cnd_r) PQclear(cnd_r);
                    }

                    /* Update registrations to roster_published */
                    PGresult *upd_r = db_simple(conn,
                        "UPDATE exam_registrations SET registration_status = 'roster_published', "
                        "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
                        "WHERE examination_id = $1 AND registration_status = 'approved'", 1, ep, el);
                    if (upd_r) PQclear(upd_r);

                    if (app_res) PQclear(app_res);

                    record_reg_audit(conn, NULL, exam_id, ex_inst, sess.user_id, "ROSTER_PUBLISHED", ver_str);
                    audit_log(sess.user_id, "ROSTER_PUBLISHED", rvid, roster_hash);
                    db_release(conn, 0);

                    char resp[512];
                    snprintf(resp, sizeof(resp),
                        "{\"status\":\"published\",\"version\":%d,\"total_students\":%d,\"roster_hash\":\"%s\",\"roster_version_id\":\"%s\"}",
                        next_version, total_students, roster_hash, rvid);
                    reg_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                    return;
                }

                /* ---------------- GET /api/v1/examinations/:id/eligibility/:studentId (Real-time Gate) ---------------- */
                const char *elig_prefix = "/eligibility/";
                if (strcmp(method, "GET") == 0 && strncmp(action, elig_prefix, strlen(elig_prefix)) == 0) {
                    const char *target_sid = action + strlen(elig_prefix);

                    /* Step 1: Check exam status */
                    if (strcmp(ex_stat, "closed") == 0 || strcmp(ex_stat, "finalized") == 0 || strcmp(ex_stat, "cancelled") == 0) {
                        db_release(conn, 0);
                        char resp[256];
                        snprintf(resp, sizeof(resp), "{\"access_granted\":false,\"eligibility_status\":\"exam_not_accessible\",\"reason\":\"Exam is %s\"}", ex_stat);
                        reg_send_json(client_fd, 403, resp, origin, extra_headers, extra_len);
                        return;
                    }

                    /* Step 2: Check published roster */
                    const char *chk_p[2] = { exam_id, target_sid };
                    int chk_l[2] = { (int)strlen(exam_id), (int)strlen(target_sid) };
                    PGresult *r_chk = db_simple(conn,
                        "SELECT e.id, e.roll_no, e.name, s.academic_status, s.administrative_hold, s.hold_reason "
                        "FROM exam_roster_entries e "
                        "JOIN students s ON s.id = e.student_id "
                        "WHERE e.examination_id = $1 AND e.student_id = $2 ORDER BY e.created_at DESC LIMIT 1",
                        2, chk_p, chk_l);

                    if (!r_chk || PQntuples(r_chk) == 0) {
                        if (r_chk) PQclear(r_chk);
                        db_release(conn, 0);
                        reg_send_json(client_fd, 403,
                            "{\"access_granted\":false,\"eligibility_status\":\"not_in_roster\",\"reason\":\"Student is not present in the published exam roster\"}",
                            origin, extra_headers, extra_len);
                        return;
                    }

                    const char *ac_status = PQgetvalue(r_chk, 0, 3);
                    int is_hold = (strcmp(PQgetvalue(r_chk, 0, 4), "t") == 0);
                    const char *h_reason = PQgetvalue(r_chk, 0, 5);

                    /* Step 3: Re-verify student active status at exam-start */
                    if (strcmp(ac_status, "active") != 0) {
                        PQclear(r_chk);
                        db_release(conn, 0);
                        char resp[256];
                        snprintf(resp, sizeof(resp), "{\"access_granted\":false,\"eligibility_status\":\"ineligible\",\"reason\":\"Student status is %s\"}", ac_status);
                        reg_send_json(client_fd, 403, resp, origin, extra_headers, extra_len);
                        return;
                    }

                    /* Step 4: Re-verify administrative hold at exam-start */
                    if (is_hold) {
                        PQclear(r_chk);
                        db_release(conn, 0);
                        char resp[256];
                        snprintf(resp, sizeof(resp), "{\"access_granted\":false,\"eligibility_status\":\"hold\",\"reason\":\"Administrative hold: %s\"}", h_reason[0] ? h_reason : "Active hold");
                        reg_send_json(client_fd, 403, resp, origin, extra_headers, extra_len);
                        return;
                    }

                    char resp[256];
                    snprintf(resp, sizeof(resp),
                        "{\"access_granted\":true,\"eligibility_status\":\"eligible\",\"student_id\":\"%s\",\"roll_no\":\"%s\",\"exam_id\":\"%s\"}",
                        target_sid, PQgetvalue(r_chk, 0, 1), exam_id);
                    PQclear(r_chk);
                    db_release(conn, 0);

                    reg_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                    return;
                }
            }
        }
    }

    /* =========================================================================
     * 4. Single Registration routes: /api/v1/registrations/:id[...]
     * ========================================================================= */
    const char *reg_prefix = "/api/v1/registrations/";
    size_t reg_plen = strlen(reg_prefix);
    if (strncmp(path, reg_prefix, reg_plen) == 0) {
        const char *sub = path + reg_plen;
        const char *slash = strchr(sub, '/');
        char reg_id[64] = {0};
        char action[32] = {0};

        if (slash) {
            size_t id_len = (size_t)(slash - sub);
            if (id_len < sizeof(reg_id)) {
                memcpy(reg_id, sub, id_len);
                reg_id[id_len] = '\0';
                strncpy(action, slash, sizeof(action) - 1);
            }
        } else {
            strncpy(reg_id, sub, sizeof(reg_id) - 1);
        }

        /* Fetch registration record */
        const char *rp[1] = { reg_id };
        int rl[1] = { (int)strlen(reg_id) };
        PGresult *r_res = db_simple(conn,
            "SELECT id, institution_id, examination_id, student_id, registration_status, "
            "eligibility_status, rejection_reason, exception_reason, approved_by, approved_at "
            "FROM exam_registrations WHERE id = $1", 1, rp, rl);

        if (!r_res || PQntuples(r_res) == 0) {
            if (r_res) PQclear(r_res);
            db_release(conn, 0);
            reg_send_error(client_fd, 404, "Registration not found", origin, extra_headers, extra_len);
            return;
        }

        char r_inst[64] = {0}, r_exam[64] = {0}, r_sid[64] = {0}, r_status[64] = {0};
        strncpy(r_inst, PQgetvalue(r_res, 0, 1), sizeof(r_inst) - 1);
        strncpy(r_exam, PQgetvalue(r_res, 0, 2), sizeof(r_exam) - 1);
        strncpy(r_sid, PQgetvalue(r_res, 0, 3), sizeof(r_sid) - 1);
        strncpy(r_status, PQgetvalue(r_res, 0, 4), sizeof(r_status) - 1);

        if (!is_owner && strcmp(r_inst, sess.institution_id) != 0) {
            PQclear(r_res);
            db_release(conn, 0);
            reg_send_error(client_fd, 403, "Access to other institution's registration is prohibited", origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- GET /api/v1/registrations/:id ---------------- */
        if (strcmp(method, "GET") == 0 && action[0] == '\0') {
            char resp[1024];
            snprintf(resp, sizeof(resp),
                "{\"registration\":{\"id\":\"%s\",\"institution_id\":\"%s\",\"examination_id\":\"%s\","
                "\"student_id\":\"%s\",\"registration_status\":\"%s\",\"eligibility_status\":\"%s\","
                "\"rejection_reason\":\"%s\",\"exception_reason\":\"%s\"}}",
                PQgetvalue(r_res, 0, 0), r_inst, r_exam, r_sid, r_status,
                PQgetvalue(r_res, 0, 5), PQgetvalue(r_res, 0, 6), PQgetvalue(r_res, 0, 7));
            PQclear(r_res);
            db_release(conn, 0);
            reg_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/registrations/:id/evaluate (Re-evaluate) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/evaluate") == 0) {
            char eval_details[2048] = {0};
            char eval_fail[512] = {0};
            int passed = evaluate_student_eligibility(conn, r_exam, r_sid,
                                                      eval_details, sizeof(eval_details),
                                                      eval_fail, sizeof(eval_fail));

            const char *new_status = passed ? "approved" : "exception_review";
            const char *elig_status = passed ? "eligible" : "ineligible";

            const char *up_p[4] = { new_status, elig_status, eval_fail, reg_id };
            int up_l[4];
            for (int i = 0; i < 4; i++) up_l[i] = (int)strlen(up_p[i]);

            PGresult *up_r = db_simple(conn,
                "UPDATE exam_registrations SET registration_status = $1, eligibility_status = $2, rejection_reason = $3, "
                "evaluated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
                "WHERE id = $4", 4, up_p, up_l);
            if (up_r) PQclear(up_r);

            record_reg_audit(conn, reg_id, r_exam, r_inst, sess.user_id, "REGISTRATION_EVALUATED",
                             passed ? "Passed" : eval_fail);
            PQclear(r_res);
            db_release(conn, 0);

            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"evaluated\",\"registration_id\":\"%s\",\"registration_status\":\"%s\","
                "\"eligibility_status\":\"%s\",\"eligible\":%s,\"reason\":\"%s\"}",
                reg_id, new_status, elig_status, passed ? "true" : "false", eval_fail);
            reg_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/registrations/:id/approve (Manual Approval) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/approve") == 0) {
            if (sess.role != ROLE_PLATFORM_OWNER && sess.role != ROLE_INSTITUTION_ADMIN &&
                sess.role != ROLE_EXAM_MANAGER) {
                PQclear(r_res);
                db_release(conn, 0);
                reg_send_error(client_fd, 403, "Permission required to approve registrations", origin, extra_headers, extra_len);
                return;
            }

            /* Separation of duties: caller cannot be the student being approved */
            if (strcmp(sess.user_id, r_sid) == 0) {
                PQclear(r_res);
                db_release(conn, 0);
                reg_send_error(client_fd, 403, "Separation of duties: student cannot approve their own registration", origin, extra_headers, extra_len);
                return;
            }

            char ap_id[64];
            snprintf(ap_id, sizeof(ap_id), "rapp_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *ap_p[3] = { reg_id, sess.user_id, ap_id };
            int ap_l[3];
            for (int i = 0; i < 3; i++) ap_l[i] = (int)strlen(ap_p[i]);

            PGresult *up_r = db_simple(conn,
                "UPDATE exam_registrations SET registration_status = 'approved', eligibility_status = 'eligible', "
                "approved_by = $2, approved_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1", 2, ap_p, ap_l);
            if (up_r) PQclear(up_r);

            PGresult *ap_r = db_simple(conn,
                "INSERT INTO registration_approvals (id, registration_id, decision, decided_by, created_at) "
                "VALUES ($3, $1, 'approved', $2, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 3, ap_p, ap_l);
            if (ap_r) PQclear(ap_r);

            record_reg_audit(conn, reg_id, r_exam, r_inst, sess.user_id, "REGISTRATION_APPROVED", "Manual approval");
            audit_log(sess.user_id, "REGISTRATION_APPROVED", reg_id, "Approved");
            PQclear(r_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"approved\",\"registration_id\":\"%s\"}", reg_id);
            reg_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/registrations/:id/reject (Rejection with reason) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/reject") == 0) {
            char reason[512] = {0};
            ctrl_json_string(body, "reason", reason, sizeof(reason));
            if (strlen(reason) < 8) {
                PQclear(r_res);
                db_release(conn, 0);
                reg_send_error(client_fd, 400, "Rejection reason required (minimum 8 characters)", origin, extra_headers, extra_len);
                return;
            }

            char rj_id[64];
            snprintf(rj_id, sizeof(rj_id), "rapp_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *rj_p[4] = { reg_id, sess.user_id, reason, rj_id };
            int rj_l[4];
            for (int i = 0; i < 4; i++) rj_l[i] = (int)strlen(rj_p[i]);

            PGresult *up_r = db_simple(conn,
                "UPDATE exam_registrations SET registration_status = 'rejected', eligibility_status = 'ineligible', "
                "rejection_reason = $3, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1", 3, rj_p, rj_l);
            if (up_r) PQclear(up_r);

            PGresult *rj_r = db_simple(conn,
                "INSERT INTO registration_approvals (id, registration_id, decision, decided_by, reason, created_at) "
                "VALUES ($4, $1, 'rejected', $2, $3, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 4, rj_p, rj_l);
            if (rj_r) PQclear(rj_r);

            record_reg_audit(conn, reg_id, r_exam, r_inst, sess.user_id, "REGISTRATION_REJECTED", reason);
            audit_log(sess.user_id, "REGISTRATION_REJECTED", reg_id, reason);
            PQclear(r_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"rejected\",\"registration_id\":\"%s\"}", reg_id);
            reg_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/registrations/:id/exception (Authorized Exception) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/exception") == 0) {
            char reason[512] = {0};
            ctrl_json_string(body, "reason", reason, sizeof(reason));
            if (strlen(reason) < 8) {
                PQclear(r_res);
                db_release(conn, 0);
                reg_send_error(client_fd, 400, "Exception justification required (minimum 8 characters)", origin, extra_headers, extra_len);
                return;
            }

            char ex_id[64];
            snprintf(ex_id, sizeof(ex_id), "rapp_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *ex_p[4] = { reg_id, sess.user_id, reason, ex_id };
            int ex_l[4];
            for (int i = 0; i < 4; i++) ex_l[i] = (int)strlen(ex_p[i]);

            PGresult *up_r = db_simple(conn,
                "UPDATE exam_registrations SET registration_status = 'approved', eligibility_status = 'exempted', "
                "exception_reason = $3, exception_by = $2, approved_by = $2, "
                "approved_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1", 3, ex_p, ex_l);
            if (up_r) PQclear(up_r);

            PGresult *ex_r = db_simple(conn,
                "INSERT INTO registration_approvals (id, registration_id, decision, decided_by, reason, created_at) "
                "VALUES ($4, $1, 'exception_approved', $2, $3, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 4, ex_p, ex_l);
            if (ex_r) PQclear(ex_r);

            record_reg_audit(conn, reg_id, r_exam, r_inst, sess.user_id, "REGISTRATION_EXCEPTION_GRANTED", reason);
            audit_log(sess.user_id, "REGISTRATION_EXCEPTION_GRANTED", reg_id, reason);
            PQclear(r_res);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"exception_approved\",\"registration_id\":\"%s\"}", reg_id);
            reg_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        PQclear(r_res);
    }

    /* =========================================================================
     * 5. Bulk Import Job status: /api/v1/registration-imports/:jobId
     * ========================================================================= */
    const char *job_prefix = "/api/v1/registration-imports/";
    size_t job_plen = strlen(job_prefix);
    if (strncmp(path, job_prefix, job_plen) == 0 && strcmp(method, "GET") == 0) {
        const char *job_id = path + job_plen;
        const char *jp[1] = { job_id };
        int jl[1] = { (int)strlen(job_id) };

        PGresult *j_res = db_simple(conn,
            "SELECT id, examination_id, institution_id, total_rows, valid_rows, error_rows, status "
            "FROM registration_import_jobs WHERE id = $1", 1, jp, jl);

        if (!j_res || PQntuples(j_res) == 0) {
            if (j_res) PQclear(j_res);
            db_release(conn, 0);
            reg_send_error(client_fd, 404, "Import job not found", origin, extra_headers, extra_len);
            return;
        }

        const char *j_inst = PQgetvalue(j_res, 0, 2);
        if (!is_owner && strcmp(j_inst, sess.institution_id) != 0) {
            PQclear(j_res);
            db_release(conn, 0);
            reg_send_error(client_fd, 403, "Access to other institution's import job is prohibited", origin, extra_headers, extra_len);
            return;
        }

        /* Fetch errors */
        PGresult *e_res = db_simple(conn,
            "SELECT row_index, error_code, error_message FROM registration_import_errors "
            "WHERE job_id = $1 ORDER BY row_index ASC", 1, jp, jl);

        char *json = malloc(65536);
        size_t pos = 0;
        pos += snprintf(json + pos, 65536 - pos,
            "{\"job_id\":\"%s\",\"examination_id\":\"%s\",\"status\":\"%s\","
            "\"total_rows\":%s,\"valid_rows\":%s,\"error_rows\":%s,\"errors\":[",
            PQgetvalue(j_res, 0, 0), PQgetvalue(j_res, 0, 1), PQgetvalue(j_res, 0, 6),
            PQgetvalue(j_res, 0, 3), PQgetvalue(j_res, 0, 4), PQgetvalue(j_res, 0, 5));

        if (e_res && PQresultStatus(e_res) == PGRES_TUPLES_OK) {
            int en = PQntuples(e_res);
            for (int k = 0; k < en; k++) {
                if (k > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                pos += snprintf(json + pos, 65536 - pos,
                    "{\"row_index\":%s,\"error_code\":\"%s\",\"error_message\":\"%s\"}",
                    PQgetvalue(e_res, k, 0), PQgetvalue(e_res, k, 1), PQgetvalue(e_res, k, 2));
            }
        }
        if (e_res) PQclear(e_res);
        PQclear(j_res);

        pos += snprintf(json + pos, 65536 - pos, "]}");
        db_release(conn, 0);

        reg_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        free(json);
        return;
    }

    db_release(conn, 0);
    reg_send_error(client_fd, 404, "Endpoint not found", origin, extra_headers, extra_len);
}
