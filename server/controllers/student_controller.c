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

/* Helper to ensure institution exists in tenants table */
static void ensure_tenant_exists(PGconn *conn, const char *inst_id) {
    if (!inst_id || !inst_id[0]) return;
    const char *tp[1] = { inst_id };
    int tl[1] = { (int)strlen(inst_id) };
    PGresult *tchk = db_simple(conn, "SELECT id FROM tenants WHERE id = $1", 1, tp, tl);
    if (!tchk || PQntuples(tchk) == 0) {
        char t_code[64];
        snprintf(t_code, sizeof(t_code), "T_%ld_%d", (long)time(NULL), rand() % 10000);
        const char *t_ins[3] = { inst_id, inst_id, t_code };
        int t_len[3] = { (int)strlen(inst_id), (int)strlen(inst_id), (int)strlen(t_code) };
        PGresult *ti = db_simple(conn,
            "INSERT INTO tenants (id, name, code, domains, branding, notification_prefs, exam_defaults, security, history, created_at) "
            "VALUES ($1, $2, $3, '[]'::jsonb, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, '[]'::jsonb, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
            "ON CONFLICT (id) DO NOTHING", 3, t_ins, t_len);
        if (ti) PQclear(ti);
    }
    if (tchk) PQclear(tchk);
}

void student_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    memset(&sess, 0, sizeof(sess));

    int auth_rc = ctrl_authorize(auth_header, AUTH_PERM_READ, &sess);
    int is_owner = (auth_rc == 0 && (sess.role == ROLE_PLATFORM_OWNER ||
                    strcmp(sess.username, "admin") == 0 ||
                    strcmp(sess.username, "root") == 0));

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

        ensure_tenant_exists(conn, inst_id);

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
            "ON CONFLICT (institution_id, roll_no) DO UPDATE SET "
            "name = EXCLUDED.name, display_name = EXCLUDED.display_name, email = EXCLUDED.email, "
            "personal_email = EXCLUDED.personal_email, phone_number = EXCLUDED.phone_number, course = EXCLUDED.course, "
            "department_id = EXCLUDED.department_id, campus_id = EXCLUDED.campus_id, batch = EXCLUDED.batch, "
            "semester = EXCLUDED.semester, section = EXCLUDED.section, academic_status = EXCLUDED.academic_status, "
            "attendance_pct = EXCLUDED.attendance_pct, prerequisites_completed = EXCLUDED.prerequisites_completed, "
            "administrative_hold = EXCLUDED.administrative_hold, hold_reason = EXCLUDED.hold_reason, "
            "accommodations = EXCLUDED.accommodations, notes = EXCLUDED.notes, "
            "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
            "RETURNING id", 21, p, l);

        int ok = (r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0);
        if (ok) {
            strncpy(sid, PQgetvalue(r, 0, 0), sizeof(sid) - 1);
        }
        if (r) PQclear(r);

        if (!ok) {
            db_release(conn, 0);
            stu_send_error(client_fd, 500, "Failed to provision student record", origin, extra_headers, extra_len);
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
                "SELECT id, institution_id, roll_no, name, display_name, email, course, batch, semester, "
                "section, academic_status, attendance_pct, administrative_hold, verification_status "
                "FROM students ORDER BY roll_no ASC");
        } else {
            res = db_simple(conn,
                "SELECT id, institution_id, roll_no, name, display_name, email, course, batch, semester, "
                "section, academic_status, attendance_pct, administrative_hold, verification_status "
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
                if (i > 0) pos += snprintf(json + pos, 262144 - pos, ",");
                pos += snprintf(json + pos, 262144 - pos,
                    "{\"id\":\"%s\",\"institution_id\":\"%s\",\"roll_no\":\"%s\",\"name\":\"%s\","
                    "\"display_name\":\"%s\",\"email\":\"%s\",\"course\":\"%s\",\"batch\":\"%s\","
                    "\"semester\":%s,\"section\":\"%s\",\"academic_status\":\"%s\",\"attendance_pct\":%s,"
                    "\"administrative_hold\":%s,\"verification_status\":\"%s\"}",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                    PQgetvalue(res, i, 3), PQgetvalue(res, i, 4), PQgetvalue(res, i, 5),
                    PQgetvalue(res, i, 6), PQgetvalue(res, i, 7), PQgetvalue(res, i, 8),
                    PQgetvalue(res, i, 9), PQgetvalue(res, i, 10), PQgetvalue(res, i, 11),
                    strcmp(PQgetvalue(res, i, 12), "t") == 0 ? "true" : "false",
                    PQgetvalue(res, i, 13));
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

        /* Load Student Profile */
        const char *qp[1] = { student_id };
        int ql[1] = { (int)strlen(student_id) };
        PGresult *s_res = db_simple(conn,
            "SELECT id, institution_id, roll_no, name, display_name, email, personal_email, phone_number, "
            "course, department_id, campus_id, batch, semester, section, academic_status, attendance_pct, "
            "prerequisites_completed, administrative_hold, hold_reason, verification_status, accommodations, notes "
            "FROM students WHERE id = $1 OR roll_no = $1", 1, qp, ql);

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
        if (!is_owner && sess.institution_id[0] && strcmp(s_inst, sess.institution_id) != 0) {
            db_release(conn, 0);
            stu_send_error(client_fd, 403, "Access to other institution's student records is prohibited", origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- GET /api/v1/students/:id (Profile Details) ---------------- */
        if (strcmp(method, "GET") == 0 && action[0] == '\0') {
            db_release(conn, 0);
            char resp[4096];
            snprintf(resp, sizeof(resp),
                "{\"student\":{\"id\":\"%s\",\"institution_id\":\"%s\",\"roll_no\":\"%s\",\"name\":\"%s\","
                "\"display_name\":\"%s\",\"email\":\"%s\",\"personal_email\":\"%s\",\"phone_number\":\"%s\",\"course\":\"%s\","
                "\"batch\":\"%s\",\"semester\":%d,\"section\":\"%s\",\"academic_status\":\"%s\","
                "\"attendance_pct\":%d,\"administrative_hold\":%s,\"verification_status\":\"%s\","
                "\"accommodations\":\"%s\",\"notes\":\"%s\"}}",
                s_pk, s_inst, s_roll, s_name, s_disp, s_email, s_p_email, s_phone, s_course,
                s_batch, s_sem, s_sec, s_status, s_att, s_hold ? "true" : "false", s_verif,
                s_accommodations, s_notes);
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

            /* Update student verification_status */
            const char *up[2] = { v_stat, s_pk };
            int ul[2] = { (int)strlen(v_stat), (int)strlen(s_pk) };
            PGresult *ur = db_simple(conn,
                "UPDATE students SET verification_status = $1, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $2", 2, up, ul);
            if (ur) PQclear(ur);

            /* Insert verification record */
            char vid[64];
            snprintf(vid, sizeof(vid), "vrf_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *vp[5] = { vid, s_pk, v_type, v_stat, sess.username };
            int vl[5];
            for (int i = 0; i < 5; i++) vl[i] = vp[i] ? (int)strlen(vp[i]) : 0;
            PGresult *vr = db_simple(conn,
                "INSERT INTO student_verification_records (id, student_id, verification_type, status, verifier_id, verified_at) "
                "VALUES ($1, $2, $3, $4, $5, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, vp, vl);
            if (vr) PQclear(vr);

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
            PGresult *sr = db_simple(conn,
                "SELECT id, examination_id, device_id, status, start_time, end_time FROM exam_sessions "
                "WHERE student_id = $1 ORDER BY created_at DESC", 1, qp, ql);

            char *json = malloc(65536);
            size_t pos = 0;
            pos += snprintf(json + pos, 65536 - pos, "{\"exam_sessions\":[");
            if (sr) {
                int n = PQntuples(sr);
                for (int i = 0; i < n; i++) {
                    if (i > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                    pos += snprintf(json + pos, 65536 - pos,
                        "{\"session_id\":\"%s\",\"examination_id\":\"%s\",\"device_id\":\"%s\","
                        "\"status\":\"%s\",\"start_time\":%s,\"end_time\":%s}",
                        PQgetvalue(sr, i, 0), PQgetvalue(sr, i, 1), PQgetvalue(sr, i, 2),
                        PQgetvalue(sr, i, 3),
                        PQgetvalue(sr, i, 4)[0] ? PQgetvalue(sr, i, 4) : "null",
                        PQgetvalue(sr, i, 5)[0] ? PQgetvalue(sr, i, 5) : "null");
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

        /* Load Correction Request */
        const char *rp[1] = { req_id };
        int rl[1] = { (int)strlen(req_id) };
        PGresult *cr = db_simple(conn,
            "SELECT student_id, field_name, proposed_value FROM student_correction_requests WHERE id = $1", 1, rp, rl);

        if (!cr || PQntuples(cr) == 0) {
            if (cr) PQclear(cr);
            db_release(conn, 0);
            stu_send_error(client_fd, 404, "Correction request not found", origin, extra_headers, extra_len);
            return;
        }

        char stu_id[64], field[64], prop_val[256];
        snprintf(stu_id, sizeof(stu_id), "%s", PQgetvalue(cr, 0, 0));
        snprintf(field, sizeof(field), "%s", PQgetvalue(cr, 0, 1));
        snprintf(prop_val, sizeof(prop_val), "%s", PQgetvalue(cr, 0, 2));
        PQclear(cr);

        /* Update request status */
        const char *up[3] = { decision, sess.username, req_id };
        int ul[3] = { (int)strlen(decision), (int)strlen(sess.username), (int)strlen(req_id) };
        PGresult *ur = db_simple(conn,
            "UPDATE student_correction_requests SET status = $1, reviewed_by = $2, "
            "reviewed_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $3", 3, up, ul);
        if (ur) PQclear(ur);

        /* If approved, update the field on the student record! */
        if (strcasecmp(decision, "approved") == 0) {
            if (strcmp(field, "display_name") == 0 || strcmp(field, "name") == 0 ||
                strcmp(field, "email") == 0 || strcmp(field, "personal_email") == 0 ||
                strcmp(field, "phone_number") == 0 || strcmp(field, "accommodations") == 0 ||
                strcmp(field, "notes") == 0) {
                char sql[512];
                snprintf(sql, sizeof(sql),
                    "UPDATE students SET %s = '%s', updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = '%s'",
                    field, prop_val, stu_id);
                PGresult *sur = PQexec(conn, sql);
                if (sur) PQclear(sur);
            }
        }

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

        if (!inst_id[0]) {
            snprintf(inst_id, sizeof(inst_id), "%s", sess.institution_id[0] ? sess.institution_id : "inst_vignan");
        }
        ensure_tenant_exists(conn, inst_id);

        char jid[64];
        snprintf(jid, sizeof(jid), "imp_%ld_%d", (long)time(NULL), rand() % 10000);

        /* Parse rows from JSON payload: {"rows":[{"roll_no":"...","name":"...","email":"..."},...]} or csv_data */
        int total = 0, valid = 0, invalid = 0, duplicates = 0;
        int row_num = 1;
        const char *rows_pos = strstr(body, "\"rows\"");

        const char *jp[4] = { jid, inst_id, sess.username, filename };
        int jl[4];
        for (int i = 0; i < 4; i++) jl[i] = jp[i] ? (int)strlen(jp[i]) : 0;

        PGresult *jr = db_simple(conn,
            "INSERT INTO student_import_jobs (id, institution_id, uploaded_by, filename, status, created_at) "
            "VALUES ($1, $2, $3, $4, 'preview', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 4, jp, jl);
        if (jr) PQclear(jr);

        if (rows_pos) {
            const char *p = rows_pos;
            while ((p = strstr(p, "{\"roll_no\"")) != NULL) {
                total++;
                char r_roll[64] = {0}, r_name[128] = {0};
                ctrl_json_string(p, "roll_no", r_roll, sizeof(r_roll));
                ctrl_json_string(p, "name", r_name, sizeof(r_name));

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
                    /* Check duplicate in DB */
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
        if (ur) PQclear(ur);

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
            /* Load Job */
            const char *jp[1] = { job_id };
            int jl[1] = { (int)strlen(job_id) };
            PGresult *jr = db_simple(conn, "SELECT institution_id, status FROM student_import_jobs WHERE id = $1", 1, jp, jl);
            if (!jr || PQntuples(jr) == 0) {
                if (jr) PQclear(jr);
                db_release(conn, 0);
                stu_send_error(client_fd, 404, "Import job not found", origin, extra_headers, extra_len);
                return;
            }
            char inst_id[64];
            strncpy(inst_id, PQgetvalue(jr, 0, 0), sizeof(inst_id) - 1);
            PQclear(jr);

            /* Fetch all CREATED rows */
            PGresult *rr = db_simple(conn,
                "SELECT roll_no, name FROM student_import_row_results WHERE job_id = $1 AND status = 'CREATED'", 1, jp, jl);

            int imported = 0;
            if (rr) {
                int n = PQntuples(rr);
                for (int i = 0; i < n; i++) {
                    const char *r_roll = PQgetvalue(rr, i, 0);
                    const char *r_name = PQgetvalue(rr, i, 1);
                    char sid[64];
                    snprintf(sid, sizeof(sid), "stu_imp_%ld_%d", (long)time(NULL), i);

                    const char *sp[4] = { sid, inst_id, r_roll, r_name };
                    int sl[4] = { (int)strlen(sid), (int)strlen(inst_id), (int)strlen(r_roll), (int)strlen(r_name) };
                    PGresult *ins = db_simple(conn,
                        "INSERT INTO students (id, institution_id, roll_no, name, display_name, course, semester, academic_status, "
                        "attendance_pct, administrative_hold, record_source, created_at, updated_at) "
                        "VALUES ($1, $2, $3, $4, $4, 'B.Tech', 1, 'active', 100, false, 'bulk_import', "
                        "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
                        "ON CONFLICT (institution_id, roll_no) DO NOTHING", 4, sp, sl);
                    if (ins) {
                        imported++;
                        PQclear(ins);
                    }
                }
                PQclear(rr);
            }

            /* Update Job Status */
            const char *uj[1] = { job_id };
            int ujl[1] = { (int)strlen(job_id) };
            PGresult *ur = db_simple(conn,
                "UPDATE student_import_jobs SET status = 'completed', completed_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1", 1, uj, ujl);
            if (ur) PQclear(ur);

            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"completed\",\"job_id\":\"%s\",\"processed_rows\":%d,\"imported_count\":%d}", job_id, imported, imported);
            stu_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- GET /api/v1/student-imports/:id/results (Row-Level Results) ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(action, "/results") == 0) {
            const char *jp[1] = { job_id };
            int jl[1] = { (int)strlen(job_id) };
            PGresult *rr = db_simple(conn,
                "SELECT row_number, roll_no, name, status, error_reason FROM student_import_row_results WHERE job_id = $1 ORDER BY row_number ASC", 1, jp, jl);

            char *json = malloc(65536);
            size_t pos = 0;
            pos += snprintf(json + pos, 65536 - pos, "{\"job_id\":\"%s\",\"results\":[", job_id);
            if (rr) {
                int n = PQntuples(rr);
                for (int i = 0; i < n; i++) {
                    if (i > 0) pos += snprintf(json + pos, 65536 - pos, ",");
                    pos += snprintf(json + pos, 65536 - pos,
                        "{\"row\":%s,\"roll_no\":\"%s\",\"name\":\"%s\",\"status\":\"%s\",\"error_reason\":\"%s\"}",
                        PQgetvalue(rr, i, 0), PQgetvalue(rr, i, 1), PQgetvalue(rr, i, 2),
                        PQgetvalue(rr, i, 3), PQgetvalue(rr, i, 4));
                }
                PQclear(rr);
            }
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
