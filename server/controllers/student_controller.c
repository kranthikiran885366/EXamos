/*
 * student_controller.c — Module 5: Student Management System (Complete Specification)
 *
 * Implements:
 * - Canonical student profiles & institutional identity lifecycle
 * - Academic details & multi-semester enrollment history
 * - Identity verification states & student correction workflows
 * - Bulk student CSV import (preview, duplicate detection, row-level reporting)
 * - Integration endpoints with Modules 10 (Eligibility), 11 (Sessions), and 13 (Device Trust)
 * - Role-based permissions, tenant isolation, and durable audit trail
 */

#include "student_controller.h"
#include "controller.h"
#include "../db/db.h"
#include "../audit/audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

static void stu_audit_log(PGconn *conn, const char *student_id, const char *inst_id,
                          const char *actor, const char *action, const char *details) {
    char aid[64];
    snprintf(aid, sizeof(aid), "staud_%ld_%d", (long)time(NULL), rand() % 10000);
    const char *p[6] = { aid, student_id, inst_id, actor ? actor : "system", action, details ? details : "" };
    int l[6];
    for (int i = 0; i < 6; i++) l[i] = p[i] ? (int)strlen(p[i]) : 0;

    PGresult *r = db_simple(conn,
        "INSERT INTO student_audit_events (id, student_id, institution_id, actor_id, action, details, occurred_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 6, p, l);
    if (r) PQclear(r);

    /* Also record to unified append-only audit ledger */
    audit_append(actor, action, details ? details : student_id);
}

static void stu_send_json(int fd, int code, const char *body,
                          const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void stu_send_error(int fd, int code, const char *msg,
                           const char *origin, char *extra, size_t extra_len) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "{\"error\":\"%.512s\"}", msg ? msg : "Unknown error");
    stu_send_json(fd, code, buf, origin, extra, extra_len);
}

static int tenant_exists(PGconn *conn, const char *inst_id) {
    if (!conn || !inst_id || !inst_id[0]) return 0;
    const char *tp[1] = { inst_id };
    int tl[1] = { (int)strlen(inst_id) };
    PGresult *result = db_simple(conn, "SELECT 1 FROM tenants WHERE id = $1", 1, tp, tl);
    if (!result || PQresultStatus(result) != PGRES_TUPLES_OK) {
        if (result) PQclear(result);
        return -1;
    }
    int exists = result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1;
    if (result) PQclear(result);
    return exists;
}

void student_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    memset(&sess, 0, sizeof(sess));

    int auth_rc = ctrl_authorize(auth_header, AUTH_PERM_READ, &sess);
    char candidate_id[64] = {0};
    int is_candidate = ctrl_candidate_session_identity(auth_header, candidate_id, sizeof(candidate_id));
    if (auth_rc != 0 && !is_candidate) {
        stu_send_error(client_fd, 401, "Authentication required", origin, extra_headers, extra_len);
        return;
    }
    int is_owner = auth_rc == 0 && sess.role == ROLE_PLATFORM_OWNER;
    if (is_candidate &&
        (strcmp(method, "GET") != 0 ||
         strcmp(path, "/api/v1/students") == 0 ||
         strcmp(path, "/api/v1/admin/students") == 0 ||
         strncmp(path, "/api/v1/student-imports", 23) == 0)) {
        stu_send_error(client_fd, 403, "Candidates cannot manage or enumerate the institutional roster", origin, extra_headers, extra_len);
        return;
    }
    if (!is_candidate && strcmp(method, "GET") != 0 &&
        sess.role != ROLE_PLATFORM_OWNER && sess.role != ROLE_INSTITUTION_ADMIN &&
        sess.role != ROLE_EXAM_MANAGER) {
        stu_send_error(client_fd, 403, "Student management permission required", origin, extra_headers, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        stu_send_error(client_fd, 503, "Database connection unavailable", origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 1. POST /api/v1/students & /api/v1/admin/students: Create / Upsert Student
     * ========================================================================= */
    if (strcmp(method, "POST") == 0 &&
        (strcmp(path, "/api/v1/students") == 0 || strcmp(path, "/api/v1/admin/students") == 0)) {
        char sid[64] = {0}, roll_no[64] = {0}, name[128] = {0}, disp_name[128] = {0};
        char email[128] = {0}, p_email[128] = {0}, phone[32] = {0};
        char course[128] = {0}, dept_id[64] = {0}, campus_id[64] = {0};
        char batch[64] = {0}, section[32] = {0}, status[32] = {0};
        char prereq[256] = {0}, hold_reason[256] = {0}, inst_id[64] = {0};
        char accommodations[256] = {0}, notes[256] = {0};
        int semester = 1, attendance = 100, hold = 0;

        ctrl_json_string(body, "id", sid, sizeof(sid));
        ctrl_json_string(body, "student_id", sid, sizeof(sid));
        ctrl_json_string(body, "roll_no", roll_no, sizeof(roll_no));
        ctrl_json_string(body, "name", name, sizeof(name));
        ctrl_json_string(body, "display_name", disp_name, sizeof(disp_name));
        ctrl_json_string(body, "email", email, sizeof(email));
        ctrl_json_string(body, "personal_email", p_email, sizeof(p_email));
        ctrl_json_string(body, "phone_number", phone, sizeof(phone));
        ctrl_json_string(body, "course", course, sizeof(course));
        ctrl_json_string(body, "department_id", dept_id, sizeof(dept_id));
        ctrl_json_string(body, "campus_id", campus_id, sizeof(campus_id));
        ctrl_json_string(body, "batch", batch, sizeof(batch));
        ctrl_json_string(body, "section", section, sizeof(section));
        ctrl_json_string(body, "academic_status", status, sizeof(status));
        if (!status[0]) strcpy(status, "active");
        ctrl_json_string(body, "prerequisites_completed", prereq, sizeof(prereq));
        ctrl_json_string(body, "hold_reason", hold_reason, sizeof(hold_reason));
        ctrl_json_string(body, "accommodations", accommodations, sizeof(accommodations));
        ctrl_json_string(body, "notes", notes, sizeof(notes));
        ctrl_json_string(body, "institution_id", inst_id, sizeof(inst_id));
        ctrl_json_int(body, "semester", &semester);
        ctrl_json_int(body, "attendance_pct", &attendance);
        ctrl_json_bool(body, "administrative_hold", &hold);

        if (!is_owner || !inst_id[0]) {
            snprintf(inst_id, sizeof(inst_id), "%s", sess.institution_id[0] ? sess.institution_id : "");
        }
        /* Reject if no institution scope can be determined */
        if (!inst_id[0]) {
            db_release(conn, 0);
            stu_send_error(client_fd, 400, "institution_id is required to create a student record", origin, extra_headers, extra_len);
            return;
        }

        if (!roll_no[0] || !name[0]) {
            db_release(conn, 0);
            stu_send_error(client_fd, 400, "roll_no and name are required", origin, extra_headers, extra_len);
            return;
        }
        if (email[0]) {
            PGresult *email_check = db_simple(conn,
                "SELECT 1 FROM students WHERE institution_id=$1 AND lower(email)=lower($2) LIMIT 1",
                2, (const char *[]){ inst_id, email },
                (int[]){ (int)strlen(inst_id), (int)strlen(email) });
            int email_query_ok = email_check && PQresultStatus(email_check) == PGRES_TUPLES_OK;
            int email_exists = email_query_ok && PQntuples(email_check) > 0;
            if (email_check) PQclear(email_check);
            if (!email_query_ok || email_exists) {
                db_release(conn, 0);
                stu_send_error(client_fd, email_query_ok ? 409 : 503,
                    email_query_ok ? "A student with this email already exists in this institution" :
                                     "Student email lookup failed",
                    origin, extra_headers, extra_len);
                return;
            }
        }

        int tenant_status = tenant_exists(conn, inst_id);
        if (tenant_status != 1) {
            db_release(conn, 0);
            stu_send_error(client_fd, tenant_status < 0 ? 503 : 404,
                tenant_status < 0 ? "Institution lookup failed" : "Institution does not exist",
                origin, extra_headers, extra_len);
            return;
        }

        if (!sid[0]) {
            snprintf(sid, sizeof(sid), "stu_%ld_%d", (long)time(NULL), rand() % 10000);
        }
        if (!disp_name[0]) {
            snprintf(disp_name, sizeof(disp_name), "%s", name);
        }

        char sem_str[16], att_str[16];
        snprintf(sem_str, sizeof(sem_str), "%d", semester);
        snprintf(att_str, sizeof(att_str), "%d", attendance);

        const char *p[21] = {
            sid, inst_id, roll_no, name, disp_name, email, p_email, phone,
            course, dept_id, campus_id, batch, sem_str, section, status,
            att_str, prereq, hold ? "t" : "f", hold_reason, accommodations, notes
        };
        int l[21];
        for (int i = 0; i < 21; i++) l[i] = p[i] ? (int)strlen(p[i]) : 0;

        PGresult *r = db_simple(conn,
            "INSERT INTO students (id, institution_id, roll_no, name, display_name, email, personal_email, "
            "phone_number, course, department_id, campus_id, batch, semester, section, academic_status, "
            "attendance_pct, prerequisites_completed, administrative_hold, hold_reason, accommodations, notes, "
            "created_at, updated_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::int, $14, $15, $16::int, $17, $18, $19, $20, $21, "
            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
            "ON CONFLICT (institution_id, roll_no) DO NOTHING "
            "RETURNING id", 21, p, l);

        int ok = (r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0);
        int duplicate = r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 0;
        if (ok) {
            strncpy(sid, PQgetvalue(r, 0, 0), sizeof(sid) - 1);
        }
        if (r) PQclear(r);

        if (!ok) {
            db_release(conn, 0);
            stu_send_error(client_fd, duplicate ? 409 : 500,
                duplicate ? "A student with this roll number already exists" : "Failed to provision student record",
                origin, extra_headers, extra_len);
            return;
        }

        /* Auto-create initial active enrollment record if student has none */
        const char *eq[1] = { sid };
        int eql[1] = { (int)strlen(sid) };
        PGresult *echk = db_simple(conn, "SELECT id FROM student_enrollments WHERE student_id = $1 LIMIT 1", 1, eq, eql);
        if (!echk || PQntuples(echk) == 0) {
            char enr_id[64];
            snprintf(enr_id, sizeof(enr_id), "enr_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *ep[8] = { enr_id, sid, inst_id, campus_id, dept_id, course, batch, sem_str };
            int el[8];
            for (int i = 0; i < 8; i++) el[i] = ep[i] ? (int)strlen(ep[i]) : 0;
            PGresult *er = db_simple(conn,
                "INSERT INTO student_enrollments (id, student_id, institution_id, campus_id, department_id, program_id, batch, semester, status, start_date) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8::int, 'current', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 8, ep, el);
            if (er) PQclear(er);
        }
        if (echk) PQclear(echk);

        stu_audit_log(conn, sid, inst_id, sess.username, "STUDENT_CREATED", roll_no);
        db_release(conn, 0);

        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"ok\",\"student_id\":\"%s\",\"id\":\"%s\",\"roll_no\":\"%s\",\"name\":\"%s\","
            "\"institution_id\":\"%s\",\"semester\":%d,\"academic_status\":\"%s\"}",
            sid, sid, roll_no, name, inst_id, semester, status);
        stu_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 2. GET /api/v1/students & /api/v1/admin/students: List, Filter, Search
     * ========================================================================= */
    if (strcmp(method, "GET") == 0 &&
        (strcmp(path, "/api/v1/students") == 0 || strcmp(path, "/api/v1/admin/students") == 0)) {
        PGresult *res = NULL;
        const char *pvals[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };

        if (is_owner) {
            res = PQexec(conn,
                "SELECT id, institution_id, roll_no, name, display_name, email, personal_email, phone_number, "
                "course, batch, semester, section, academic_status, attendance_pct, administrative_hold, "
                "verification_status, accommodations, notes, created_at "
                "FROM students ORDER BY roll_no ASC");
        } else {
            res = db_simple(conn,
                "SELECT id, institution_id, roll_no, name, display_name, email, personal_email, phone_number, "
                "course, batch, semester, section, academic_status, attendance_pct, administrative_hold, "
                "verification_status, accommodations, notes, created_at "
                "FROM students WHERE institution_id = $1 ORDER BY roll_no ASC", 1, pvals, lens);
        }

        char *json = malloc(262144);
        if (!json) {
            if (res) PQclear(res);
            db_release(conn, 0);
            stu_send_error(client_fd, 500, "Out of memory", origin, extra_headers, extra_len);
            return;
        }

        size_t pos = 0;
        pos += snprintf(json + pos, 262144 - pos, "{\"students\":[");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            int n = PQntuples(res);
            for (int i = 0; i < n; i++) {
                char escaped[18][512];
                for (int j = 0; j < 18; j++) ctrl_json_escape(PQgetvalue(res, i, j), escaped[j], sizeof(escaped[j]));
                if (i > 0) pos += snprintf(json + pos, 262144 - pos, ",");
                pos += snprintf(json + pos, 262144 - pos,
                    "{\"id\":\"%s\",\"institution_id\":\"%s\",\"roll_no\":\"%s\",\"name\":\"%s\","
                    "\"display_name\":\"%s\",\"email\":\"%s\",\"personal_email\":\"%s\","
                    "\"phone_number\":\"%s\",\"course\":\"%s\",\"batch\":\"%s\",\"semester\":%s,"
                    "\"section\":\"%s\",\"academic_status\":\"%s\",\"attendance_pct\":%s,"
                    "\"administrative_hold\":%s,\"verification_status\":\"%s\","
                    "\"accommodations\":\"%s\",\"notes\":\"%s\",\"created_at\":%s}",
                    escaped[0], escaped[1], escaped[2], escaped[3], escaped[4], escaped[5],
                    escaped[6], escaped[7], escaped[8], escaped[9], PQgetvalue(res, i, 10),
                    escaped[11], escaped[12], PQgetvalue(res, i, 13),
                    strcmp(PQgetvalue(res, i, 14), "t") == 0 ? "true" : "false",
                    escaped[15], escaped[16], escaped[17], PQgetvalue(res, i, 18));
            }
        }
        if (res) PQclear(res);
        pos += snprintf(json + pos, 262144 - pos, "]}");
        db_release(conn, 0);

        stu_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        free(json);
        return;
    }

    /* =========================================================================
     * 3. Specific Student Sub-routes: /api/v1/students/:id/...
     * ========================================================================= */
    const char *stu_pfx = "/api/v1/students/";
    size_t stu_plen = strlen(stu_pfx);
    if (strncmp(path, stu_pfx, stu_plen) == 0) {
        const char *sub = path + stu_plen;
        char student_id[64] = {0};
        const char *slash = strchr(sub, '/');
        size_t len = slash ? (size_t)(slash - sub) : strlen(sub);
        if (len >= sizeof(student_id)) {
            db_release(conn, 0);
            stu_send_error(client_fd, 400, "Invalid student ID", origin, extra_headers, extra_len);
            return;
        }
        memcpy(student_id, sub, len);
        student_id[len] = '\0';
        const char *action = slash ? slash : "";

        if (is_candidate &&
            (strcmp(method, "GET") != 0 ||
             (action[0] != '\0' && strcmp(action, "/exam-sessions") != 0))) {
            db_release(conn, 0);
            stu_send_error(client_fd, 403, "Candidates have read-only access to their own exam workspace", origin, extra_headers, extra_len);
            return;
        }

        /* Load Student Profile */
        PGresult *s_res = NULL;
        if (is_candidate) {
            if (strcmp(student_id, candidate_id) != 0) {
                db_release(conn, 0);
                stu_send_error(client_fd, 403, "Candidates may only access their own record", origin, extra_headers, extra_len);
                return;
            }
            const char *qp[1] = { candidate_id };
            int ql[1] = { (int)strlen(candidate_id) };
            s_res = db_simple(conn,
                "SELECT s.id, s.institution_id, s.roll_no, s.name, s.display_name, s.email, s.personal_email, s.phone_number, "
                "s.course, s.department_id, s.campus_id, s.batch, s.semester, s.section, s.academic_status, s.attendance_pct, "
                "s.prerequisites_completed, s.administrative_hold, s.hold_reason, "
                "CASE WHEN lower(c.identity) = 'verified' OR lower(s.verification_status) = 'verified' THEN 'verified' "
                "WHEN lower(c.identity) = 'rejected' OR lower(s.verification_status) = 'rejected' THEN 'rejected' "
                "ELSE COALESCE(NULLIF(s.verification_status, ''), c.identity, '') END, s.accommodations, s.notes "
                "FROM candidates c JOIN students s ON s.institution_id = c.tenant_id "
                "AND (s.roll_no = c.roll_no OR s.id = c.id) WHERE c.id = $1 LIMIT 1", 1, qp, ql);
        } else {
            const char *qp[1] = { student_id };
            int ql[1] = { (int)strlen(student_id) };
            s_res = db_simple(conn,
                "SELECT id, institution_id, roll_no, name, display_name, email, personal_email, phone_number, "
                "course, department_id, campus_id, batch, semester, section, academic_status, attendance_pct, "
                "prerequisites_completed, administrative_hold, hold_reason, verification_status, accommodations, notes "
                "FROM students WHERE id = $1 OR roll_no = $1", 1, qp, ql);
        }

        if (!s_res || PQntuples(s_res) == 0) {
            if (s_res) PQclear(s_res);
            db_release(conn, 0);
            stu_send_error(client_fd, 404, "Student record not found", origin, extra_headers, extra_len);
            return;
        }

        char s_pk[64], s_inst[64], s_roll[64], s_name[128], s_disp[128], s_email[128], s_p_email[128], s_phone[32];
        char s_course[128], s_batch[64], s_sec[32], s_status[32], s_verif[32], s_accommodations[256], s_notes[256];
        int s_sem = 1, s_att = 100, s_hold = 0;

        snprintf(s_pk, sizeof(s_pk), "%s", PQgetvalue(s_res, 0, 0));
        snprintf(s_inst, sizeof(s_inst), "%s", PQgetvalue(s_res, 0, 1));
        snprintf(s_roll, sizeof(s_roll), "%s", PQgetvalue(s_res, 0, 2));
        snprintf(s_name, sizeof(s_name), "%s", PQgetvalue(s_res, 0, 3));
        snprintf(s_disp, sizeof(s_disp), "%s", PQgetvalue(s_res, 0, 4));
        snprintf(s_email, sizeof(s_email), "%s", PQgetvalue(s_res, 0, 5));
        snprintf(s_p_email, sizeof(s_p_email), "%s", PQgetvalue(s_res, 0, 6));
        snprintf(s_phone, sizeof(s_phone), "%s", PQgetvalue(s_res, 0, 7));
        snprintf(s_course, sizeof(s_course), "%s", PQgetvalue(s_res, 0, 8));
        snprintf(s_batch, sizeof(s_batch), "%s", PQgetvalue(s_res, 0, 11));
        s_sem = atoi(PQgetvalue(s_res, 0, 12));
        snprintf(s_sec, sizeof(s_sec), "%s", PQgetvalue(s_res, 0, 13));
        snprintf(s_status, sizeof(s_status), "%s", PQgetvalue(s_res, 0, 14));
        s_att = atoi(PQgetvalue(s_res, 0, 15));
        s_hold = (strcmp(PQgetvalue(s_res, 0, 17), "t") == 0);
        snprintf(s_verif, sizeof(s_verif), "%s", PQgetvalue(s_res, 0, 19));
        snprintf(s_accommodations, sizeof(s_accommodations), "%s", PQgetvalue(s_res, 0, 20));
        snprintf(s_notes, sizeof(s_notes), "%s", PQgetvalue(s_res, 0, 21));
        PQclear(s_res);

        /* Multi-tenant isolation check */
        if (!is_owner && (!sess.institution_id[0] || strcmp(s_inst, sess.institution_id) != 0)) {
            db_release(conn, 0);
            stu_send_error(client_fd, 403, "Access to other institution's student records is prohibited", origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- GET /api/v1/students/:id (Profile Details) ---------------- */
        if (strcmp(method, "GET") == 0 && action[0] == '\0') {
            db_release(conn, 0);
            const char *profile_fields[15] = {
                s_pk, s_inst, s_roll, s_name, s_disp, s_email, s_p_email, s_phone,
                s_course, s_batch, s_sec, s_status, s_verif, s_accommodations, s_notes
            };
            char escaped_profile[15][512];
            for (int i = 0; i < 15; i++)
                ctrl_json_escape(profile_fields[i], escaped_profile[i], sizeof(escaped_profile[i]));
            char resp[8192];
            snprintf(resp, sizeof(resp),
                "{\"student\":{\"id\":\"%s\",\"institution_id\":\"%s\",\"roll_no\":\"%s\",\"name\":\"%s\","
                "\"display_name\":\"%s\",\"email\":\"%s\",\"personal_email\":\"%s\",\"phone_number\":\"%s\",\"course\":\"%s\","
                "\"batch\":\"%s\",\"semester\":%d,\"section\":\"%s\",\"academic_status\":\"%s\","
                "\"attendance_pct\":%d,\"administrative_hold\":%s,\"verification_status\":\"%s\","
                "\"accommodations\":\"%s\",\"notes\":\"%s\"}}",
                escaped_profile[0], escaped_profile[1], escaped_profile[2], escaped_profile[3],
                escaped_profile[4], escaped_profile[5], escaped_profile[6], escaped_profile[7],
                escaped_profile[8], escaped_profile[9], s_sem, escaped_profile[10],
                escaped_profile[11], s_att, s_hold ? "true" : "false", escaped_profile[12],
                escaped_profile[13], escaped_profile[14]);
            stu_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- PATCH /api/v1/students/:id (Update Profile Fields) ---------------- */
        if ((strcmp(method, "PATCH") == 0 || strcmp(method, "PUT") == 0) && action[0] == '\0') {
            char u_name[128] = {0}, u_disp[128] = {0}, u_email[128] = {0}, u_phone[32] = {0};
            int u_att = s_att, u_hold = s_hold;
            char u_hold_reason[256] = {0};

            ctrl_json_string(body, "name", u_name, sizeof(u_name));
            ctrl_json_string(body, "display_name", u_disp, sizeof(u_disp));
            ctrl_json_string(body, "email", u_email, sizeof(u_email));
            ctrl_json_string(body, "phone_number", u_phone, sizeof(u_phone));
            ctrl_json_int(body, "attendance_pct", &u_att);
            ctrl_json_bool(body, "administrative_hold", &u_hold);
            ctrl_json_string(body, "hold_reason", u_hold_reason, sizeof(u_hold_reason));

            if (!u_name[0]) snprintf(u_name, sizeof(u_name), "%s", s_name);
            if (!u_disp[0]) snprintf(u_disp, sizeof(u_disp), "%s", s_disp);
            if (!u_email[0]) snprintf(u_email, sizeof(u_email), "%s", s_email);

            char att_buf[16];
            snprintf(att_buf, sizeof(att_buf), "%d", u_att);

            const char *up[7] = { u_name, u_disp, u_email, u_phone, att_buf, u_hold ? "t" : "f", s_pk };
            int ul[7];
            for (int i = 0; i < 7; i++) ul[i] = up[i] ? (int)strlen(up[i]) : 0;

            PGresult *ur = db_simple(conn,
                "UPDATE students SET name = $1, display_name = $2, email = $3, phone_number = $4, "
                "attendance_pct = $5::int, administrative_hold = $6, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
                "WHERE id = $7", 7, up, ul);
            if (ur) PQclear(ur);

            stu_audit_log(conn, s_pk, s_inst, sess.username, "STUDENT_UPDATED", "Profile updated");
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"updated\",\"student_id\":\"%s\"}", s_pk);
            stu_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/students/:id/verify (Identity Verification) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/verify") == 0) {
            char v_stat[32] = {0}, v_type[64] = {0}, notes[256] = {0};
            ctrl_json_string(body, "status", v_stat, sizeof(v_stat));
            ctrl_json_string(body, "verification_type", v_type, sizeof(v_type));
            ctrl_json_string(body, "notes", notes, sizeof(notes));
            if ((strcmp(v_stat, "VERIFIED") != 0 && strcmp(v_stat, "REJECTED") != 0 &&
                 strcmp(v_stat, "EXEMPT") != 0) || !v_type[0]) {
                db_release(conn, 0);
                stu_send_error(client_fd, 400, "A supported verification status and verification_type are required",
                               origin, extra_headers, extra_len);
                return;
            }

            PGresult *begin = PQexec(conn, "BEGIN");
            if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
                if (begin) PQclear(begin);
                db_release(conn, 0);
                stu_send_error(client_fd, 503, "Unable to begin identity verification", origin, extra_headers, extra_len);
                return;
            }
            PQclear(begin);
            const char *up[2] = { v_stat, s_pk };
            int ul[2] = { (int)strlen(v_stat), (int)strlen(s_pk) };
            PGresult *ur = db_simple(conn,
                "UPDATE students SET verification_status = $1, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $2", 2, up, ul);
            int student_updated = ur && PQresultStatus(ur) == PGRES_COMMAND_OK &&
                                  strcmp(PQcmdTuples(ur), "1") == 0;
            if (ur) PQclear(ur);
            if (!student_updated) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                stu_send_error(client_fd, 503, "Student verification status could not be updated", origin, extra_headers, extra_len);
                return;
            }

            char vid[64];
            snprintf(vid, sizeof(vid), "vrf_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *vp[5] = { vid, s_pk, v_type, v_stat, sess.username };
            int vl[5];
            for (int i = 0; i < 5; i++) vl[i] = vp[i] ? (int)strlen(vp[i]) : 0;
            PGresult *vr = db_simple(conn,
                "INSERT INTO student_verification_records (id, student_id, verification_type, status, verifier_id, verified_at) "
                "VALUES ($1, $2, $3, $4, $5, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, vp, vl);
            int verification_saved = vr && PQresultStatus(vr) == PGRES_COMMAND_OK;
            if (vr) PQclear(vr);
            if (!verification_saved) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                stu_send_error(client_fd, 503, "Identity verification evidence could not be saved", origin, extra_headers, extra_len);
                return;
            }
            PGresult *commit = PQexec(conn, "COMMIT");
            int committed = commit && PQresultStatus(commit) == PGRES_COMMAND_OK;
            if (commit) PQclear(commit);
            if (!committed) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 1);
                stu_send_error(client_fd, 503, "Identity verification transaction failed", origin, extra_headers, extra_len);
                return;
            }

            stu_audit_log(conn, s_pk, s_inst, sess.username, "STUDENT_VERIFIED", v_stat);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"%s\",\"student_id\":\"%s\"}", v_stat, s_pk);
            stu_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/students/:id/suspend (Institutional Suspension) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/suspend") == 0) {
            char reason[256] = {0};
            ctrl_json_string(body, "reason", reason, sizeof(reason));

            const char *up[2] = { reason, s_pk };
            int ul[2] = { (int)strlen(reason), (int)strlen(s_pk) };
            PGresult *ur = db_simple(conn,
                "UPDATE students SET academic_status = 'suspended', hold_reason = $1, administrative_hold = true, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $2", 2, up, ul);
            if (ur) PQclear(ur);

            stu_audit_log(conn, s_pk, s_inst, sess.username, "STUDENT_SUSPENDED", reason);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"suspended\",\"student_id\":\"%s\",\"reason\":\"%s\"}", s_pk, reason);
            stu_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/students/:id/reactivate (Reactivation) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/reactivate") == 0) {
            const char *up[1] = { s_pk };
            int ul[1] = { (int)strlen(s_pk) };
            PGresult *ur = db_simple(conn,
                "UPDATE students SET academic_status = 'active', hold_reason = '', administrative_hold = false, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1", 1, up, ul);
            if (ur) PQclear(ur);

            stu_audit_log(conn, s_pk, s_inst, sess.username, "STUDENT_REACTIVATED", "Reactivated");
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"active\",\"student_id\":\"%s\"}", s_pk);
            stu_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/students/:id/archive (Retention Archival) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/archive") == 0) {
            const char *up[1] = { s_pk };
            int ul[1] = { (int)strlen(s_pk) };
            PGresult *ur = db_simple(conn,
                "UPDATE students SET academic_status = 'archived', updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1", 1, up, ul);
            if (ur) PQclear(ur);

            stu_audit_log(conn, s_pk, s_inst, sess.username, "STUDENT_ARCHIVED", "Archived");
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"archived\",\"student_id\":\"%s\"}", s_pk);
            stu_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- GET /api/v1/students/:id/history (Durable Audit Trail) ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(action, "/history") == 0) {
            const char *hp[1] = { s_pk };
            int hl[1] = { (int)strlen(s_pk) };
            PGresult *hr = db_simple(conn,
                "SELECT id, action, actor_id, details, occurred_at FROM student_audit_events "
                "WHERE student_id = $1 ORDER BY occurred_at DESC", 1, hp, hl);

            char *json = malloc(65536);
            size_t pos = 0;
            pos += snprintf(json + pos, 65536 - pos, "{\"history\":[");
            if (hr) {
                int n = PQntuples(hr);
                for (int i = 0; i < n; i++) {
                    if (i > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                    pos += snprintf(json + pos, 65536 - pos,
                        "{\"id\":\"%s\",\"action\":\"%s\",\"actor_id\":\"%s\",\"details\":\"%s\",\"occurred_at\":%s}",
                        PQgetvalue(hr, i, 0), PQgetvalue(hr, i, 1), PQgetvalue(hr, i, 2),
                        PQgetvalue(hr, i, 3), PQgetvalue(hr, i, 4));
                }
                PQclear(hr);
            }
            pos += snprintf(json + pos, 65536 - pos, "]}");
            db_release(conn, 0);

            stu_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            free(json);
            return;
        }

        /* ---------------- GET /api/v1/students/:id/enrollments (Multi-Semester History) ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(action, "/enrollments") == 0) {
            const char *ep[1] = { s_pk };
            int el[1] = { (int)strlen(s_pk) };
            PGresult *er = db_simple(conn,
                "SELECT id, semester, section, program_id, batch, academic_year, status, start_date, end_date "
                "FROM student_enrollments WHERE student_id = $1 ORDER BY semester ASC", 1, ep, el);

            char *json = malloc(65536);
            size_t pos = 0;
            pos += snprintf(json + pos, 65536 - pos, "{\"enrollments\":[");
            if (er) {
                int n = PQntuples(er);
                for (int i = 0; i < n; i++) {
                    if (i > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                    pos += snprintf(json + pos, 65536 - pos,
                        "{\"id\":\"%s\",\"semester\":%s,\"section\":\"%s\",\"program_id\":\"%s\","
                        "\"batch\":\"%s\",\"academic_year\":\"%s\",\"status\":\"%s\",\"start_date\":%s}",
                        PQgetvalue(er, i, 0), PQgetvalue(er, i, 1), PQgetvalue(er, i, 2),
                        PQgetvalue(er, i, 3), PQgetvalue(er, i, 4), PQgetvalue(er, i, 5),
                        PQgetvalue(er, i, 6), PQgetvalue(er, i, 7));
                }
                PQclear(er);
            }
            pos += snprintf(json + pos, 65536 - pos, "]}");
            db_release(conn, 0);

            stu_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            free(json);
            return;
        }

        /* ---------------- POST /api/v1/students/:id/enrollments (Progression / Transfer) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/enrollments") == 0) {
            int new_sem = s_sem + 1;
            char new_sec[32] = {0}, new_prog[128] = {0}, new_acad[32] = {0};
            ctrl_json_int(body, "semester", &new_sem);
            ctrl_json_string(body, "section", new_sec, sizeof(new_sec));
            ctrl_json_string(body, "program_id", new_prog, sizeof(new_prog));
            ctrl_json_string(body, "academic_year", new_acad, sizeof(new_acad));

            if (!new_prog[0]) snprintf(new_prog, sizeof(new_prog), "%s", s_course);

            /* Mark previous current enrollments as 'completed' (Historical Preservation) */
            const char *cls_p[1] = { s_pk };
            int cls_l[1] = { (int)strlen(s_pk) };
            PGresult *cr = db_simple(conn,
                "UPDATE student_enrollments SET status = 'completed', end_date = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
                "WHERE student_id = $1 AND status = 'current'", 1, cls_p, cls_l);
            if (cr) PQclear(cr);

            /* Insert new enrollment record */
            char eid[64];
            snprintf(eid, sizeof(eid), "enr_%ld_%d", (long)time(NULL), rand() % 10000);
            char sem_str[16];
            snprintf(sem_str, sizeof(sem_str), "%d", new_sem);

            const char *np[8] = { eid, s_pk, s_inst, new_prog, s_batch, sem_str, new_sec, new_acad };
            int nl[8];
            for (int i = 0; i < 8; i++) nl[i] = np[i] ? (int)strlen(np[i]) : 0;

            PGresult *ir = db_simple(conn,
                "INSERT INTO student_enrollments (id, student_id, institution_id, program_id, batch, semester, section, academic_year, status, start_date) "
                "VALUES ($1, $2, $3, $4, $5, $6::int, $7, $8, 'current', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 8, np, nl);
            if (ir) PQclear(ir);

            /* Update current semester and section on students table */
            const char *sup[3] = { sem_str, new_sec, s_pk };
            int supl[3] = { (int)strlen(sem_str), (int)strlen(new_sec), (int)strlen(s_pk) };
            PGresult *sur = db_simple(conn,
                "UPDATE students SET semester = $1::int, section = $2, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $3", 3, sup, supl);
            if (sur) PQclear(sur);

            char log_msg[128];
            snprintf(log_msg, sizeof(log_msg), "Progressed to Semester %d (%s)", new_sem, new_sec);
            stu_audit_log(conn, s_pk, s_inst, sess.username, "SEMESTER_PROGRESSED", log_msg);
            db_release(conn, 0);

            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"enrolled\",\"enrollment_id\":\"%s\",\"student_id\":\"%s\",\"semester\":%d,\"section\":\"%s\"}",
                eid, s_pk, new_sem, new_sec);
            stu_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/students/:id/correction-requests (Correction Request) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/correction-requests") == 0) {
            char f_name[64] = {0}, p_val[256] = {0}, reason[256] = {0};
            ctrl_json_string(body, "field_name", f_name, sizeof(f_name));
            ctrl_json_string(body, "proposed_value", p_val, sizeof(p_val));
            if (!p_val[0]) ctrl_json_string(body, "new_value", p_val, sizeof(p_val));
            ctrl_json_string(body, "reason", reason, sizeof(reason));
            if (!reason[0]) ctrl_json_string(body, "justification", reason, sizeof(reason));

            if (!f_name[0] || !p_val[0]) {
                db_release(conn, 0);
                stu_send_error(client_fd, 400, "field_name and proposed_value are required", origin, extra_headers, extra_len);
                return;
            }

            char req_id[64];
            snprintf(req_id, sizeof(req_id), "corr_%ld_%d", (long)time(NULL), rand() % 10000);

            const char *cp[6] = { req_id, s_pk, s_inst, f_name, p_val, reason };
            int cl[6];
            for (int i = 0; i < 6; i++) cl[i] = cp[i] ? (int)strlen(cp[i]) : 0;

            PGresult *cr = db_simple(conn,
                "INSERT INTO student_correction_requests (id, student_id, institution_id, field_name, proposed_value, reason, status, created_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, 'pending', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 6, cp, cl);
            if (cr) PQclear(cr);

            stu_audit_log(conn, s_pk, s_inst, sess.username, "CORRECTION_REQUESTED", f_name);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"pending\",\"request_id\":\"%s\"}", req_id);
            stu_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- Integration: GET /api/v1/students/:id/exam-eligibility (Module 10) ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(action, "/exam-eligibility") == 0) {
            const char *qp[1] = { s_pk };
            int ql[1] = { (int)strlen(s_pk) };
            PGresult *er = db_simple(conn,
                "SELECT examination_id, registration_status, eligibility_status, approval_decision, created_at "
                "FROM exam_registrations WHERE student_id = $1", 1, qp, ql);

            char *json = malloc(65536);
            size_t pos = 0;
            pos += snprintf(json + pos, 65536 - pos, "{\"student_id\":\"%s\",\"eligibility_records\":[", s_pk);
            if (er) {
                int n = PQntuples(er);
                for (int i = 0; i < n; i++) {
                    if (i > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                    pos += snprintf(json + pos, 65536 - pos,
                        "{\"examination_id\":\"%s\",\"registration_status\":\"%s\",\"eligibility_status\":\"%s\","
                        "\"approval_decision\":\"%s\",\"registered_at\":%s}",
                        PQgetvalue(er, i, 0), PQgetvalue(er, i, 1), PQgetvalue(er, i, 2),
                        PQgetvalue(er, i, 3), PQgetvalue(er, i, 4));
                }
                PQclear(er);
            }
            pos += snprintf(json + pos, 65536 - pos, "]}");
            db_release(conn, 0);

            stu_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            free(json);
            return;
        }

        /* ---------------- Integration: GET /api/v1/students/:id/device-assignments (Module 13) ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(action, "/device-assignments") == 0) {
            const char *qp[1] = { s_pk };
            int ql[1] = { (int)strlen(s_pk) };
            PGresult *dr = db_simple(conn,
                "SELECT a.id, a.device_id, d.hostname, d.device_name, d.status, a.assigned_exam_id, a.status "
                "FROM device_assignments a JOIN devices d ON a.device_id = d.id "
                "WHERE a.assigned_student_id = $1", 1, qp, ql);

            char *json = malloc(65536);
            size_t pos = 0;
            pos += snprintf(json + pos, 65536 - pos, "{\"student_id\":\"%s\",\"assigned_devices\":[", s_pk);
            if (dr) {
                int n = PQntuples(dr);
                for (int i = 0; i < n; i++) {
                    if (i > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                    pos += snprintf(json + pos, 65536 - pos,
                        "{\"assignment_id\":\"%s\",\"device_id\":\"%s\",\"hostname\":\"%s\","
                        "\"device_name\":\"%s\",\"device_status\":\"%s\",\"exam_id\":\"%s\",\"assignment_status\":\"%s\"}",
                        PQgetvalue(dr, i, 0), PQgetvalue(dr, i, 1), PQgetvalue(dr, i, 2),
                        PQgetvalue(dr, i, 3), PQgetvalue(dr, i, 4), PQgetvalue(dr, i, 5), PQgetvalue(dr, i, 6));
                }
                PQclear(dr);
            }
            pos += snprintf(json + pos, 65536 - pos, "]}");
            db_release(conn, 0);

            stu_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            free(json);
            return;
        }

        /* ---------------- Integration: GET /api/v1/students/:id/exam-sessions (Module 11) ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(action, "/exam-sessions") == 0) {
            const char *qp[1] = { s_pk };
            int ql[1] = { (int)strlen(s_pk) };
            const char *candidate_scope = is_candidate
                ? "r.student_id = (SELECT s.id FROM candidates cx JOIN students s "
                  "ON s.institution_id = cx.tenant_id AND s.roll_no = cx.roll_no WHERE cx.id = $1 LIMIT 1) "
                  "AND r.examination_id = (SELECT exam_id FROM candidates WHERE id = $1)"
                : "r.student_id = $1";
            char query[4096];
            snprintf(query, sizeof(query),
                "SELECT COALESCE(es.id, ''), e.id, COALESCE(NULLIF(es.device_id, ''), d.id, ''), "
                "COALESCE(es.status, 'scheduled'), sch.start_time, sch.end_time, es.launched_at, "
                "e.code, e.name, e.status, e.duration_minutes, "
                "e.instructions, e.exam_url, COALESCE(c.seat, ''), COALESCE(c.center_id, ''), "
                "COALESCE(ce.code, ''), COALESCE(ce.name, ''), COALESCE(ce.city, ''), COALESCE(ce.status, ''), "
                "COALESCE(d.hostname, ''), COALESCE(d.status, ''), COALESCE(d.trust, ''), "
                "COALESCE(c.identity, ''), COALESCE(d.compat_status, '') "
                "FROM exam_registrations r JOIN examinations e ON e.id = r.examination_id "
                "LEFT JOIN LATERAL (SELECT id, device_id, status, launched_at FROM exam_sessions "
                "WHERE student_id = r.student_id AND examination_id = r.examination_id "
                "ORDER BY created_at DESC LIMIT 1) es ON TRUE "
                "LEFT JOIN LATERAL (SELECT start_time, end_time FROM exam_schedules "
                "WHERE exam_id = r.examination_id ORDER BY start_time LIMIT 1) sch ON TRUE "
                "LEFT JOIN candidates c ON c.tenant_id = r.institution_id AND c.exam_id = r.examination_id AND c.roll_no = "
                "(SELECT roll_no FROM students WHERE id = r.student_id LIMIT 1) "
                "LEFT JOIN centers ce ON ce.id = c.center_id "
                "LEFT JOIN devices d ON (d.id = es.device_id OR "
                "(NULLIF(es.device_id, '') IS NULL AND d.center_id = c.center_id AND d.seat = c.seat)) "
                "AND d.tenant_id = r.institution_id "
                "WHERE %s AND r.registration_status IN ('approved', 'roster_published') "
                "AND r.eligibility_status IN ('eligible', 'exempted') ORDER BY sch.start_time",
                candidate_scope);
            PGresult *sr = db_simple(conn,
                query, 1, qp, ql);

            if (!sr || PQresultStatus(sr) != PGRES_TUPLES_OK) {
                if (sr) PQclear(sr);
                db_release(conn, 0);
                stu_send_error(client_fd, 500, "Failed to load candidate exam assignments", origin, extra_headers, extra_len);
                return;
            }
            char *json = malloc(65536);
            if (!json) {
                PQclear(sr);
                db_release(conn, 0);
                stu_send_error(client_fd, 500, "Unable to allocate exam assignment response", origin, extra_headers, extra_len);
                return;
            }
            size_t pos = 0;
            pos += snprintf(json + pos, 65536 - pos, "{\"exam_sessions\":[");
            {
                int n = PQntuples(sr);
                for (int i = 0; i < n; i++) {
                    char escaped[24][1024];
                    for (int j = 0; j < 24; j++)
                        ctrl_json_escape(PQgetvalue(sr, i, j), escaped[j], sizeof(escaped[j]));
                    if (i > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                    pos += snprintf(json + pos, 65536 - pos,
                        "{\"session_id\":\"%s\",\"examination_id\":\"%s\",\"device_id\":\"%s\","
                        "\"status\":\"%s\",\"start_time\":%s,\"end_time\":%s,\"launched_at\":%s,"
                        "\"exam_code\":\"%s\",\"exam_name\":\"%s\",\"exam_status\":\"%s\","
                        "\"duration_minutes\":%s,\"instructions\":\"%s\",\"exam_url\":\"%s\","
                        "\"seat\":\"%s\",\"center_id\":\"%s\",\"center_code\":\"%s\",\"center_name\":\"%s\","
                        "\"center_city\":\"%s\",\"center_status\":\"%s\",\"device_hostname\":\"%s\","
                        "\"device_status\":\"%s\",\"device_trust\":\"%s\",\"identity\":\"%s\",\"compat_status\":\"%s\"}",
                        escaped[0], escaped[1], escaped[2], escaped[3],
                        PQgetvalue(sr, i, 4)[0] ? PQgetvalue(sr, i, 4) : "null",
                        PQgetvalue(sr, i, 5)[0] ? PQgetvalue(sr, i, 5) : "null",
                        PQgetvalue(sr, i, 6)[0] ? PQgetvalue(sr, i, 6) : "null",
                        escaped[7], escaped[8], escaped[9], PQgetvalue(sr, i, 10),
                        escaped[11], escaped[12], escaped[13], escaped[14], escaped[15],
                        escaped[16], escaped[17], escaped[18], escaped[19], escaped[20],
                        escaped[21], escaped[22], escaped[23]);
                }
                PQclear(sr);
            }
            pos += snprintf(json + pos, 65536 - pos, "]}");
            db_release(conn, 0);

            stu_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            free(json);
            return;
        }
    }

    /* =========================================================================
     * 4. POST /api/v1/student-correction-requests/:id/review (Approve / Reject)
     * ========================================================================= */
    const char *cr_pfx = "/api/v1/student-correction-requests/";
    size_t cr_plen = strlen(cr_pfx);
    if (strncmp(path, cr_pfx, cr_plen) == 0 && strcmp(method, "POST") == 0) {
        const char *sub = path + cr_plen;
        char req_id[64] = {0};
        const char *slash = strchr(sub, '/');
        size_t len = slash ? (size_t)(slash - sub) : strlen(sub);
        if (len >= sizeof(req_id)) {
            db_release(conn, 0);
            stu_send_error(client_fd, 400, "Invalid request ID", origin, extra_headers, extra_len);
            return;
        }
        memcpy(req_id, sub, len);
        req_id[len] = '\0';

        char decision[32] = "approved", review_notes[256] = "";
        ctrl_json_string(body, "decision", decision, sizeof(decision));
        ctrl_json_string(body, "review_notes", review_notes, sizeof(review_notes));
        if (strcasecmp(decision, "approved") != 0 && strcasecmp(decision, "rejected") != 0) {
            db_release(conn, 0);
            stu_send_error(client_fd, 400, "Decision must be approved or rejected", origin, extra_headers, extra_len);
            return;
        }

        PGresult *begin = PQexec(conn, "BEGIN");
        if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
            if (begin) PQclear(begin);
            db_release(conn, 0);
            stu_send_error(client_fd, 503, "Unable to begin correction review", origin, extra_headers, extra_len);
            return;
        }
        PQclear(begin);
        const char *rp[1] = { req_id };
        int rl[1] = { (int)strlen(req_id) };
        PGresult *cr = db_simple(conn,
            "SELECT institution_id, student_id, field_name, proposed_value, status "
            "FROM student_correction_requests WHERE id = $1 FOR UPDATE", 1, rp, rl);

        if (!cr || PQresultStatus(cr) != PGRES_TUPLES_OK || PQntuples(cr) == 0) {
            if (cr) PQclear(cr);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            stu_send_error(client_fd, 404, "Correction request not found", origin, extra_headers, extra_len);
            return;
        }

        char request_institution[64], stu_id[64], field[64], prop_val[256], request_status[32];
        snprintf(request_institution, sizeof(request_institution), "%s", PQgetvalue(cr, 0, 0));
        snprintf(stu_id, sizeof(stu_id), "%s", PQgetvalue(cr, 0, 1));
        snprintf(field, sizeof(field), "%s", PQgetvalue(cr, 0, 2));
        snprintf(prop_val, sizeof(prop_val), "%s", PQgetvalue(cr, 0, 3));
        snprintf(request_status, sizeof(request_status), "%s", PQgetvalue(cr, 0, 4));
        PQclear(cr);
        if (!is_owner && (!sess.institution_id[0] ||
                          strcmp(request_institution, sess.institution_id) != 0)) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            stu_send_error(client_fd, 403, "Correction request belongs to another institution", origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(request_status, "pending") != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            stu_send_error(client_fd, 409, "Correction request has already been reviewed", origin, extra_headers, extra_len);
            return;
        }

        const char *up[4] = { decision, sess.username, review_notes, req_id };
        int ul[4] = { (int)strlen(decision), (int)strlen(sess.username),
                      (int)strlen(review_notes), (int)strlen(req_id) };
        PGresult *ur = db_simple(conn,
            "UPDATE student_correction_requests SET status = lower($1), reviewed_by = $2, review_notes = $3, "
            "reviewed_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
            "WHERE id = $4 AND status = 'pending'", 4, up, ul);
        int request_updated = ur && PQresultStatus(ur) == PGRES_COMMAND_OK &&
                              strcmp(PQcmdTuples(ur), "1") == 0;
        if (ur) PQclear(ur);
        if (!request_updated) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            stu_send_error(client_fd, 503, "Correction request could not be updated", origin, extra_headers, extra_len);
            return;
        }

        if (strcasecmp(decision, "approved") == 0) {
            const char *column = NULL;
            if (strcmp(field, "display_name") == 0) column = "display_name";
            else if (strcmp(field, "name") == 0) column = "name";
            else if (strcmp(field, "email") == 0) column = "email";
            else if (strcmp(field, "personal_email") == 0) column = "personal_email";
            else if (strcmp(field, "phone_number") == 0) column = "phone_number";
            else if (strcmp(field, "accommodations") == 0) column = "accommodations";
            else if (strcmp(field, "notes") == 0) column = "notes";
            if (!column) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                stu_send_error(client_fd, 400, "This student field cannot be corrected through this workflow", origin, extra_headers, extra_len);
                return;
            }
            {
                char sql[512];
                snprintf(sql, sizeof(sql),
                    "UPDATE students SET %s = $1, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
                    "WHERE id = $2 AND institution_id = $3", column);
                const char *sp[3] = { prop_val, stu_id, request_institution };
                int sl[3] = { (int)strlen(prop_val), (int)strlen(stu_id),
                              (int)strlen(request_institution) };
                PGresult *sur = db_simple(conn, sql, 3, sp, sl);
                int student_updated = sur && PQresultStatus(sur) == PGRES_COMMAND_OK &&
                                      strcmp(PQcmdTuples(sur), "1") == 0;
                if (sur) PQclear(sur);
                if (!student_updated) {
                    PQexec(conn, "ROLLBACK");
                    db_release(conn, 0);
                    stu_send_error(client_fd, 503, "Corrected student profile could not be saved", origin, extra_headers, extra_len);
                    return;
                }
            }
        }

        PGresult *commit = PQexec(conn, "COMMIT");
        int committed = commit && PQresultStatus(commit) == PGRES_COMMAND_OK;
        if (commit) PQclear(commit);
        if (!committed) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 1);
            stu_send_error(client_fd, 503, "Correction review transaction failed", origin, extra_headers, extra_len);
            return;
        }
        stu_audit_log(conn, stu_id, request_institution, sess.username,
                      strcasecmp(decision, "approved") == 0 ? "CORRECTION_APPROVED" : "CORRECTION_REJECTED",
                      field);
        db_release(conn, 0);
        char resp[256];
        snprintf(resp, sizeof(resp), "{\"status\":\"%s\",\"request_id\":\"%s\"}", decision, req_id);
        stu_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 5. POST /api/v1/student-imports: Create / Preview Bulk Import Job
     * ========================================================================= */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/student-imports") == 0) {
        char inst_id[64] = {0}, filename[256] = "students_import.csv";
        ctrl_json_string(body, "institution_id", inst_id, sizeof(inst_id));
        ctrl_json_string(body, "filename", filename, sizeof(filename));

        if (!is_owner || !inst_id[0]) {
            snprintf(inst_id, sizeof(inst_id), "%s", sess.institution_id);
        }
        if (!inst_id[0]) {
            db_release(conn, 0);
            stu_send_error(client_fd, 400, "A valid institution scope is required for student imports", origin, extra_headers, extra_len);
            return;
        }
        int tenant_status = tenant_exists(conn, inst_id);
        if (tenant_status != 1) {
            db_release(conn, 0);
            stu_send_error(client_fd, tenant_status < 0 ? 503 : 404,
                tenant_status < 0 ? "Institution lookup failed" : "Institution does not exist",
                origin, extra_headers, extra_len);
            return;
        }

        const char *rows_pos = strstr(body, "\"rows\"");
        if (!rows_pos || !strstr(rows_pos, "{\"roll_no\"")) {
            db_release(conn, 0);
            stu_send_error(client_fd, 400, "A non-empty rows array is required for student imports", origin, extra_headers, extra_len);
            return;
        }

        char jid[64];
        snprintf(jid, sizeof(jid), "imp_%ld_%d", (long)time(NULL), rand() % 10000);

        int total = 0, valid = 0, invalid = 0, duplicates = 0;
        int row_num = 1;
        int storage_failed = 0;
        PGresult *begin = PQexec(conn, "BEGIN");
        if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
            if (begin) PQclear(begin);
            db_release(conn, 0);
            stu_send_error(client_fd, 503, "Unable to begin student import preview", origin, extra_headers, extra_len);
            return;
        }
        PQclear(begin);

        const char *jp[4] = { jid, inst_id, sess.username, filename };
        int jl[4];
        for (int i = 0; i < 4; i++) jl[i] = jp[i] ? (int)strlen(jp[i]) : 0;

        PGresult *jr = db_simple(conn,
            "INSERT INTO student_import_jobs (id, institution_id, uploaded_by, filename, status, created_at) "
            "VALUES ($1, $2, $3, $4, 'preview', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 4, jp, jl);
        if (!jr || PQresultStatus(jr) != PGRES_COMMAND_OK) {
            if (jr) PQclear(jr);
            db_release(conn, 0);
            stu_send_error(client_fd, 503, "Unable to create student import job", origin, extra_headers, extra_len);
            return;
        }
        PQclear(jr);

        if (rows_pos) {
            const char *p = rows_pos;
            while ((p = strstr(p, "{\"roll_no\"")) != NULL) {
                total++;
                char r_roll[64] = {0}, r_name[128] = {0}, r_email[128] = {0};
                char r_course[128] = {0}, r_batch[64] = {0}, r_semester[16] = {0}, r_section[32] = {0};
                ctrl_json_string(p, "roll_no", r_roll, sizeof(r_roll));
                ctrl_json_string(p, "name", r_name, sizeof(r_name));
                ctrl_json_string(p, "email", r_email, sizeof(r_email));
                ctrl_json_string(p, "course", r_course, sizeof(r_course));
                ctrl_json_string(p, "batch", r_batch, sizeof(r_batch));
                ctrl_json_string(p, "semester", r_semester, sizeof(r_semester));
                ctrl_json_string(p, "section", r_section, sizeof(r_section));
                int parsed_semester = atoi(r_semester);
                const char *semester_value = parsed_semester >= 1 && parsed_semester <= 12
                    ? r_semester : "1";

                char row_id[64], rnum_str[16];
                snprintf(row_id, sizeof(row_id), "%.48s_%d", jid, row_num);
                snprintf(rnum_str, sizeof(rnum_str), "%d", row_num);

                if (!r_roll[0] || !r_name[0] || !r_email[0] ||
                    !strchr(r_email, '@') || !strchr(strchr(r_email, '@') + 1, '.') ||
                    !r_course[0] || !r_batch[0] || !r_semester[0] ||
                    parsed_semester < 1 || parsed_semester > 12 ||
                    strspn(r_semester, "0123456789") != strlen(r_semester) ||
                    strlen(r_semester) > 2 || !r_section[0]) {
                    invalid++;
                    const char *rp[11] = { row_id, jid, rnum_str, r_roll, r_name, r_email,
                        r_course, r_batch, semester_value, r_section,
                        "Candidate identity, contact, and academic fields are required" };
                    int rl[11];
                    for (int i = 0; i < 11; i++) rl[i] = (int)strlen(rp[i]);
                    PGresult *irr = db_simple(conn,
                        "INSERT INTO student_import_row_results "
                        "(id, job_id, row_number, roll_no, name, email, course, batch, semester, section, status, error_reason, created_at) "
                        "VALUES ($1, $2, $3::int, $4, $5, $6, $7, $8, $9::int, $10, 'REJECTED', $11, "
                        "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 11, rp, rl);
                    if (!irr || PQresultStatus(irr) != PGRES_COMMAND_OK) storage_failed = 1;
                    if (irr) PQclear(irr);
                } else {
                    const char *dp[4] = { inst_id, r_roll, r_email, jid };
                    int dl[4] = { (int)strlen(inst_id), (int)strlen(r_roll),
                                  (int)strlen(r_email), (int)strlen(jid) };
                    PGresult *dchk = db_simple(conn,
                        "SELECT 1 FROM students WHERE institution_id=$1 "
                        "AND (roll_no=$2 OR (email<>'' AND lower(email)=lower($3))) "
                        "UNION ALL SELECT 1 FROM student_import_row_results "
                        "WHERE job_id=$4 AND (roll_no=$2 OR (email<>'' AND lower(email)=lower($3))) "
                        "AND status IN ('CREATED','SKIPPED_DUPLICATE') LIMIT 1",
                        4, dp, dl);
                    if (!dchk || PQresultStatus(dchk) != PGRES_TUPLES_OK) {
                        if (dchk) PQclear(dchk);
                        storage_failed = 1;
                        break;
                    }
                    if (PQntuples(dchk) > 0) {
                        duplicates++;
                        const char *rp[10] = { row_id, jid, rnum_str, r_roll, r_name, r_email,
                                               r_course, r_batch, r_semester, r_section };
                        int rl[10];
                        for (int i = 0; i < 10; i++) rl[i] = (int)strlen(rp[i]);
                        PGresult *irr = db_simple(conn,
                            "INSERT INTO student_import_row_results "
                            "(id, job_id, row_number, roll_no, name, email, course, batch, semester, section, status, error_reason, created_at) "
                            "VALUES ($1, $2, $3::int, $4, $5, $6, $7, $8, $9::int, $10, 'SKIPPED_DUPLICATE', "
                            "'Student roll number or email already exists in this institution or import', "
                            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 10, rp, rl);
                        if (!irr || PQresultStatus(irr) != PGRES_COMMAND_OK) storage_failed = 1;
                        if (irr) PQclear(irr);
                    } else {
                        valid++;
                        const char *rp[10] = { row_id, jid, rnum_str, r_roll, r_name, r_email,
                                               r_course, r_batch, r_semester, r_section };
                        int rl[10];
                        for (int i = 0; i < 10; i++) rl[i] = (int)strlen(rp[i]);
                        PGresult *irr = db_simple(conn,
                            "INSERT INTO student_import_row_results "
                            "(id, job_id, row_number, roll_no, name, email, course, batch, semester, section, status, error_reason, created_at) "
                            "VALUES ($1, $2, $3::int, $4, $5, $6, $7, $8, $9::int, $10, 'CREATED', '', "
                            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 10, rp, rl);
                        if (!irr || PQresultStatus(irr) != PGRES_COMMAND_OK) storage_failed = 1;
                        if (irr) PQclear(irr);
                    }
                    PQclear(dchk);
                }
                if (storage_failed) break;
                row_num++;
                p += 10;
            }
        } else {
            /* Support csv_data in payload */
            const char *cpos = strstr(body, "\"csv_data\"");
            if (cpos) cpos = strchr(cpos, ':');
            if (cpos) {
                while (*cpos == ' ' || *cpos == '"' || *cpos == ':') cpos++;
                const char *line = cpos;
                int is_header = 1;
                while (*line && *line != '"') {
                    const char *next = line;
                    while (*next && *next != '"' && *next != '\n' && *next != '\r' && !(next[0] == '\\' && next[1] == 'n')) {
                        next++;
                    }
                    size_t linelen = (size_t)(next - line);
                    if (linelen > 0) {
                        char linebuf[512];
                        if (linelen >= sizeof(linebuf)) linelen = sizeof(linebuf) - 1;
                        memcpy(linebuf, line, linelen);
                        linebuf[linelen] = '\0';

                        if (is_header && (strstr(linebuf, "roll_no") || strstr(linebuf, "roll"))) {
                            is_header = 0;
                        } else if (linebuf[0] != '\0') {
                            is_header = 0;
                            total++;
                            char r_roll[64] = {0}, r_name[128] = {0};
                            char *tok = strtok(linebuf, ",\t");
                            if (tok) {
                                while (*tok == ' ') tok++;
                                snprintf(r_roll, sizeof(r_roll), "%s", tok);
                                tok = strtok(NULL, ",\t");
                                if (tok) {
                                    while (*tok == ' ') tok++;
                                    snprintf(r_name, sizeof(r_name), "%s", tok);
                                }
                            }

                            char row_id[64], rnum_str[16];
                            snprintf(row_id, sizeof(row_id), "impr_%ld_%d", (long)time(NULL), row_num);
                            snprintf(rnum_str, sizeof(rnum_str), "%d", row_num);

                            if (!r_roll[0] || !r_name[0]) {
                                invalid++;
                                const char *rp[5] = { row_id, jid, rnum_str, r_roll, "Missing required roll_no or name" };
                                int rl[5];
                                for (int i = 0; i < 5; i++) rl[i] = (int)strlen(rp[i]);
                                PGresult *irr = db_simple(conn,
                                    "INSERT INTO student_import_row_results (id, job_id, row_number, roll_no, name, status, error_reason, created_at) "
                                    "VALUES ($1, $2, $3::int, $4, '', 'REJECTED', $5, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, rp, rl);
                                if (irr) PQclear(irr);
                            } else {
                                const char *dp[2] = { inst_id, r_roll };
                                int dl[2] = { (int)strlen(inst_id), (int)strlen(r_roll) };
                                PGresult *dchk = db_simple(conn, "SELECT id FROM students WHERE institution_id = $1 AND roll_no = $2", 2, dp, dl);
                                if (dchk && PQntuples(dchk) > 0) {
                                    duplicates++;
                                    const char *rp[4] = { row_id, jid, rnum_str, r_roll };
                                    int rl[4] = { (int)strlen(row_id), (int)strlen(jid), (int)strlen(rnum_str), (int)strlen(r_roll) };
                                    PGresult *irr = db_simple(conn,
                                        "INSERT INTO student_import_row_results (id, job_id, row_number, roll_no, name, status, error_reason, created_at) "
                                        "VALUES ($1, $2, $3::int, $4, '', 'SKIPPED_DUPLICATE', 'Student roll number already exists', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 4, rp, rl);
                                    if (irr) PQclear(irr);
                                    PQclear(dchk);
                                } else {
                                    if (dchk) PQclear(dchk);
                                    valid++;
                                    const char *rp[5] = { row_id, jid, rnum_str, r_roll, r_name };
                                    int rl[5];
                                    for (int i = 0; i < 5; i++) rl[i] = (int)strlen(rp[i]);
                                    PGresult *irr = db_simple(conn,
                                        "INSERT INTO student_import_row_results (id, job_id, row_number, roll_no, name, status, error_reason, created_at) "
                                        "VALUES ($1, $2, $3::int, $4, $5, 'CREATED', '', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, rp, rl);
                                    if (irr) PQclear(irr);
                                }
                            }
                            row_num++;
                        }
                    }
                    if (*next == '\n' || *next == '\r') next++;
                    else if (next[0] == '\\' && next[1] == 'n') next += 2;
                    line = next;
                }
            }
        }

        /* Update counts */
        char tot_s[16], val_s[16], inv_s[16], dup_s[16];
        snprintf(tot_s, sizeof(tot_s), "%d", total);
        snprintf(val_s, sizeof(val_s), "%d", valid);
        snprintf(inv_s, sizeof(inv_s), "%d", invalid);
        snprintf(dup_s, sizeof(dup_s), "%d", duplicates);

        const char *up[5] = { tot_s, val_s, inv_s, dup_s, jid };
        int ul[5];
        for (int i = 0; i < 5; i++) ul[i] = (int)strlen(up[i]);
        PGresult *ur = db_simple(conn,
            "UPDATE student_import_jobs SET total_rows = $1::int, valid_rows = $2::int, invalid_rows = $3::int, "
            "duplicate_rows = $4::int WHERE id = $5", 5, up, ul);
        int counts_saved = ur && PQresultStatus(ur) == PGRES_COMMAND_OK &&
                           strcmp(PQcmdTuples(ur), "1") == 0;
        if (ur) PQclear(ur);
        if (storage_failed || total == 0 || !counts_saved) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            stu_send_error(client_fd, 503, "Student import preview failed; no preview was saved", origin, extra_headers, extra_len);
            return;
        }
        PGresult *commit = PQexec(conn, "COMMIT");
        int committed = commit && PQresultStatus(commit) == PGRES_COMMAND_OK;
        if (commit) PQclear(commit);
        if (!committed) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 1);
            stu_send_error(client_fd, 503, "Student import preview transaction failed", origin, extra_headers, extra_len);
            return;
        }

        db_release(conn, 0);
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"job_id\":\"%s\",\"status\":\"preview\",\"total_rows\":%d,\"valid_rows\":%d,"
            "\"invalid_rows\":%d,\"duplicate_rows\":%d}",
            jid, total, valid, invalid, duplicates);
        stu_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 6. POST /api/v1/student-imports/:id/confirm: Process Import Job
     * ========================================================================= */
    const char *imp_pfx = "/api/v1/student-imports/";
    size_t imp_plen = strlen(imp_pfx);
    if (strncmp(path, imp_pfx, imp_plen) == 0) {
        const char *sub = path + imp_plen;
        char job_id[64] = {0};
        const char *slash = strchr(sub, '/');
        size_t len = slash ? (size_t)(slash - sub) : strlen(sub);
        if (len >= sizeof(job_id)) {
            db_release(conn, 0);
            stu_send_error(client_fd, 400, "Invalid job ID", origin, extra_headers, extra_len);
            return;
        }
        memcpy(job_id, sub, len);
        job_id[len] = '\0';
        const char *action = slash ? slash : "";

        if (strcmp(method, "POST") == 0 && strcmp(action, "/confirm") == 0) {
            PGresult *begin = PQexec(conn, "BEGIN");
            if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
                if (begin) PQclear(begin);
                db_release(conn, 0);
                stu_send_error(client_fd, 503, "Unable to begin import confirmation", origin, extra_headers, extra_len);
                return;
            }
            PQclear(begin);
            const char *jp[1] = { job_id };
            int jl[1] = { (int)strlen(job_id) };
            PGresult *jr = db_simple(conn,
                "SELECT institution_id, status FROM student_import_jobs WHERE id = $1 FOR UPDATE",
                1, jp, jl);
            if (!jr || PQresultStatus(jr) != PGRES_TUPLES_OK || PQntuples(jr) == 0) {
                if (jr) PQclear(jr);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                stu_send_error(client_fd, 404, "Import job not found", origin, extra_headers, extra_len);
                return;
            }
            char inst_id[64];
            snprintf(inst_id, sizeof(inst_id), "%s", PQgetvalue(jr, 0, 0));
            int preview_state = strcmp(PQgetvalue(jr, 0, 1), "preview") == 0;
            PQclear(jr);
            if (!is_owner && (!sess.institution_id[0] || strcmp(inst_id, sess.institution_id) != 0)) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                stu_send_error(client_fd, 403, "Import job belongs to another institution", origin, extra_headers, extra_len);
                return;
            }
            if (!preview_state) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                stu_send_error(client_fd, 409, "Import job is not awaiting confirmation", origin, extra_headers, extra_len);
                return;
            }

            PGresult *rr = db_simple(conn,
                "SELECT row_number, roll_no, name, email, course, batch, semester, section "
                "FROM student_import_row_results "
                "WHERE job_id = $1 AND status = 'CREATED' ORDER BY row_number FOR UPDATE",
                1, jp, jl);
            if (!rr || PQresultStatus(rr) != PGRES_TUPLES_OK) {
                if (rr) PQclear(rr);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                stu_send_error(client_fd, 503, "Unable to load import rows", origin, extra_headers, extra_len);
                return;
            }

            int imported = 0;
            int skipped = 0;
            int import_failed = 0;
            int n = PQntuples(rr);
            for (int i = 0; i < n; i++) {
                char sid[64], row_num[16];
                snprintf(sid, sizeof(sid), "stu_%s_%s", job_id, PQgetvalue(rr, i, 0));
                snprintf(row_num, sizeof(row_num), "%s", PQgetvalue(rr, i, 0));
                const char *sp[9] = {
                    sid, inst_id, PQgetvalue(rr, i, 1), PQgetvalue(rr, i, 2),
                    PQgetvalue(rr, i, 3), PQgetvalue(rr, i, 4), PQgetvalue(rr, i, 5),
                    PQgetvalue(rr, i, 6), PQgetvalue(rr, i, 7)
                };
                int sl[9];
                for (int j = 0; j < 9; j++) sl[j] = (int)strlen(sp[j]);
                PGresult *ins = db_simple(conn,
                    "INSERT INTO students "
                    "(id, institution_id, roll_no, name, display_name, email, course, batch, semester, section, "
                    "academic_status, attendance_pct, administrative_hold, record_source, created_at, updated_at) "
                    "VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8::int, $9, 'active', 100, false, 'bulk_import', "
                    "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
                    "ON CONFLICT (institution_id, roll_no) DO NOTHING RETURNING id",
                    9, sp, sl);
                if (!ins || PQresultStatus(ins) != PGRES_TUPLES_OK) {
                    if (ins) PQclear(ins);
                    import_failed = 1;
                    break;
                }
                int inserted = PQntuples(ins) == 1;
                PQclear(ins);
                if (inserted) {
                    imported++;
                    char enrollment_id[96];
                    snprintf(enrollment_id, sizeof(enrollment_id), "enr_%s", sid);
                    const char *ep[7] = {
                        enrollment_id, sid, inst_id, PQgetvalue(rr, i, 4),
                        PQgetvalue(rr, i, 5), PQgetvalue(rr, i, 6), PQgetvalue(rr, i, 7)
                    };
                    int el[7];
                    for (int j = 0; j < 7; j++) el[j] = (int)strlen(ep[j]);
                    PGresult *enrollment = db_simple(conn,
                        "INSERT INTO student_enrollments "
                        "(id, student_id, institution_id, campus_id, department_id, program_id, batch, semester, section, status, start_date) "
                        "VALUES ($1, $2, $3, '', '', $4, $5, $6::int, $7, 'current', "
                        "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
                        7, ep, el);
                    int enrollment_saved = enrollment &&
                                           PQresultStatus(enrollment) == PGRES_COMMAND_OK;
                    if (enrollment) PQclear(enrollment);
                    if (!enrollment_saved) { import_failed = 1; break; }
                    char audit_id[96];
                    snprintf(audit_id, sizeof(audit_id), "staud_%s_%s", job_id, row_num);
                    const char *audit_params[5] = {
                        audit_id, sid, inst_id, sess.user_id, PQgetvalue(rr, i, 1)
                    };
                    int audit_lengths[5];
                    for (int j = 0; j < 5; j++) audit_lengths[j] = (int)strlen(audit_params[j]);
                    PGresult *audit = db_simple(conn,
                        "INSERT INTO student_audit_events "
                        "(id, student_id, institution_id, actor_id, action, details, occurred_at) "
                        "VALUES ($1, $2, $3, $4, 'STUDENT_IMPORTED', $5, "
                        "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
                        5, audit_params, audit_lengths);
                    int audit_saved = audit && PQresultStatus(audit) == PGRES_COMMAND_OK;
                    if (audit) PQclear(audit);
                    if (!audit_saved) { import_failed = 1; break; }
                    const char *up[2] = { job_id, row_num };
                    int ul[2] = { (int)strlen(job_id), (int)strlen(row_num) };
                    PGresult *updated_row = db_simple(conn,
                        "UPDATE student_import_row_results SET status='IMPORTED' "
                        "WHERE job_id=$1 AND row_number=$2::int AND status='CREATED'",
                        2, up, ul);
                    int update_ok = updated_row && PQresultStatus(updated_row) == PGRES_COMMAND_OK &&
                                    strcmp(PQcmdTuples(updated_row), "1") == 0;
                    if (updated_row) PQclear(updated_row);
                    if (!update_ok) { import_failed = 1; break; }
                } else {
                    skipped++;
                    const char *up[2] = { job_id, row_num };
                    int ul[2] = { (int)strlen(job_id), (int)strlen(row_num) };
                    PGresult *updated_row = db_simple(conn,
                        "UPDATE student_import_row_results SET status='SKIPPED_DUPLICATE', "
                        "error_reason='Student roll number was registered after preview' "
                        "WHERE job_id=$1 AND row_number=$2::int AND status='CREATED'",
                        2, up, ul);
                    int update_ok = updated_row && PQresultStatus(updated_row) == PGRES_COMMAND_OK &&
                                    strcmp(PQcmdTuples(updated_row), "1") == 0;
                    if (updated_row) PQclear(updated_row);
                    if (!update_ok) { import_failed = 1; break; }
                }
            }
            PQclear(rr);
            if (import_failed) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                stu_send_error(client_fd, 503, "Import confirmation failed; no rows were committed", origin, extra_headers, extra_len);
                return;
            }

            const char *uj[1] = { job_id };
            int ujl[1] = { (int)strlen(job_id) };
            PGresult *ur = db_simple(conn,
                "UPDATE student_import_jobs SET status = 'completed', completed_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1", 1, uj, ujl);
            int job_updated = ur && PQresultStatus(ur) == PGRES_COMMAND_OK &&
                              strcmp(PQcmdTuples(ur), "1") == 0;
            if (ur) PQclear(ur);
            if (!job_updated) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                stu_send_error(client_fd, 503, "Import job status could not be committed", origin, extra_headers, extra_len);
                return;
            }
            PGresult *commit = PQexec(conn, "COMMIT");
            int committed = commit && PQresultStatus(commit) == PGRES_COMMAND_OK;
            if (commit) PQclear(commit);
            if (!committed) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 1);
                stu_send_error(client_fd, 503, "Import confirmation transaction failed", origin, extra_headers, extra_len);
                return;
            }

            db_release(conn, 0);
            char resp[320];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"completed\",\"job_id\":\"%s\",\"processed_rows\":%d,"
                "\"imported_count\":%d,\"duplicate_count\":%d}",
                job_id, n, imported, skipped);
            stu_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- GET /api/v1/student-imports/:id/results (Row-Level Results) ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(action, "/results") == 0) {
            const char *jp[1] = { job_id };
            int jl[1] = { (int)strlen(job_id) };
            PGresult *job = db_simple(conn,
                "SELECT institution_id FROM student_import_jobs WHERE id=$1", 1, jp, jl);
            if (!job || PQresultStatus(job) != PGRES_TUPLES_OK || PQntuples(job) == 0) {
                if (job) PQclear(job);
                db_release(conn, 0);
                stu_send_error(client_fd, 404, "Import job not found", origin, extra_headers, extra_len);
                return;
            }
            char job_institution[64];
            snprintf(job_institution, sizeof(job_institution), "%s", PQgetvalue(job, 0, 0));
            PQclear(job);
            if (!is_owner && (!sess.institution_id[0] ||
                              strcmp(job_institution, sess.institution_id) != 0)) {
                db_release(conn, 0);
                stu_send_error(client_fd, 403, "Import job belongs to another institution", origin, extra_headers, extra_len);
                return;
            }
            PGresult *rr = db_simple(conn,
                "SELECT row_number, roll_no, name, status, error_reason FROM student_import_row_results WHERE job_id = $1 ORDER BY row_number ASC", 1, jp, jl);

            char *json = malloc(65536);
            if (!json) {
                if (rr) PQclear(rr);
                db_release(conn, 0);
                stu_send_error(client_fd, 503, "Out of memory", origin, extra_headers, extra_len);
                return;
            }
            if (!rr || PQresultStatus(rr) != PGRES_TUPLES_OK) {
                if (rr) PQclear(rr);
                free(json);
                db_release(conn, 0);
                stu_send_error(client_fd, 503, "Import results are unavailable", origin, extra_headers, extra_len);
                return;
            }
            size_t pos = 0;
            pos += snprintf(json + pos, 65536 - pos, "{\"job_id\":\"%s\",\"results\":[", job_id);
            int n = PQntuples(rr);
            for (int i = 0; i < n; i++) {
                char escaped_roll[384], escaped_name[768], escaped_status[192], escaped_error[1024];
                ctrl_json_escape(PQgetvalue(rr, i, 1), escaped_roll, sizeof(escaped_roll));
                ctrl_json_escape(PQgetvalue(rr, i, 2), escaped_name, sizeof(escaped_name));
                ctrl_json_escape(PQgetvalue(rr, i, 3), escaped_status, sizeof(escaped_status));
                ctrl_json_escape(PQgetvalue(rr, i, 4), escaped_error, sizeof(escaped_error));
                if (i > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                pos += snprintf(json + pos, 65536 - pos,
                    "{\"row\":%s,\"roll_no\":\"%s\",\"name\":\"%s\",\"status\":\"%s\",\"error_reason\":\"%s\"}",
                    PQgetvalue(rr, i, 0), escaped_roll, escaped_name, escaped_status, escaped_error);
            }
            PQclear(rr);
            pos += snprintf(json + pos, 65536 - pos, "]}");
            db_release(conn, 0);

            stu_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            free(json);
            return;
        }
    }

    db_release(conn, 0);
    stu_send_error(client_fd, 404, "Student endpoint not found", origin, extra_headers, extra_len);
}
