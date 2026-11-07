/*
 * exam_session_controller.c — ExamOS Module 11: Exam Session Management
 *
 * Implements complete session lifecycle and runtime control:
 * - Session authorization & pre-flight verification
 * - Dynamic session creation & device binding
 * - Secure launch token generation & URL authorization
 * - Heartbeat tracking & stale detection
 * - Interruption handling & recovery policy evaluation
 * - Reconnection and session resumption
 * - Session termination and closure
 * - Multi-tenant isolation & immutable audit logging
 */

#include "exam_session_controller.h"
#include "controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../include/attestation_service.h"
#include "../include/enterprise_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void audit_log(const char *actor, const char *event, const char *detail) {
    audit_append(actor, event, detail);
}

static void ses_send_json(int fd, int code, const char *body,
                          const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void ses_send_error(int fd, int code, const char *msg,
                           const char *origin, char *extra, size_t extra_len) {
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg);
    ses_send_json(fd, code, buf, origin, extra, extra_len);
}

static void record_session_event(PGconn *conn, const char *session_id, const char *exam_id,
                                 const char *inst_id, const char *event_type, const char *payload_json) {
    char eid[64];
    snprintf(eid, sizeof(eid), "sev_%ld_%d", (long)time(NULL), rand() % 10000);
    const char *p[6] = { eid, session_id, exam_id, inst_id, event_type, payload_json ? payload_json : "{}" };
    int l[6];
    for (int i = 0; i < 6; i++) l[i] = p[i] ? (int)strlen(p[i]) : 0;

    PGresult *r = db_simple(conn,
        "INSERT INTO exam_session_events (id, session_id, examination_id, institution_id, event_type, payload_json, created_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 6, p, l);
    if (r) PQclear(r);
}

static void record_session_audit(PGconn *conn, const char *session_id, const char *exam_id,
                                 const char *inst_id, const char *actor_id, const char *action, const char *details) {
    char aid[64];
    snprintf(aid, sizeof(aid), "saud_%ld_%d", (long)time(NULL), rand() % 10000);
    const char *p[7] = { aid, session_id, exam_id, inst_id, actor_id, action, details ? details : "" };
    int l[7];
    for (int i = 0; i < 7; i++) l[i] = p[i] ? (int)strlen(p[i]) : 0;

    PGresult *r = db_simple(conn,
        "INSERT INTO exam_session_audit_logs (id, session_id, examination_id, institution_id, actor_id, action, details, created_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 7, p, l);
    if (r) PQclear(r);
}

static int candidate_owns_exam_student(PGconn *conn, const char *candidate_id,
                                       const char *exam_id, const char *student_id) {
    if (!conn || !candidate_id || !candidate_id[0] || !exam_id || !exam_id[0] ||
        !student_id || !student_id[0]) return 0;
    const char *p[3] = { candidate_id, exam_id, student_id };
    int l[3] = { (int)strlen(candidate_id), (int)strlen(exam_id), (int)strlen(student_id) };
    PGresult *r = db_simple(conn,
        "SELECT 1 FROM candidates c JOIN students s ON s.institution_id = c.tenant_id "
        "AND s.roll_no = c.roll_no WHERE c.id = $1 AND c.exam_id = $2 "
        "AND (s.id = $3 OR s.roll_no = $3) LIMIT 1", 3, p, l);
    int owns = r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;
    if (r) PQclear(r);
    return owns;
}

/*
 * Evaluates session authorization:
 * Returns:
 *   1  -> Authorized to launch/enter
 *   2  -> Pending: early login (wait until start time)
 *  -1  -> Denied / ineligible / window expired / concurrent session
 */
static int verify_session_authorization(PGconn *conn, const char *exam_id, const char *student_id_or_roll,
                                        int is_candidate,
                                        char *out_student_id, size_t sid_len,
                                        char *out_inst_id, size_t inst_len,
                                        char *out_exam_url, size_t url_len,
                                        char *out_allowed_origins, size_t org_len,
                                        long long *out_wait_seconds,
                                        char *out_reason, size_t reason_len) {
    if (out_reason && reason_len > 0) out_reason[0] = '\0';
    if (out_wait_seconds) *out_wait_seconds = 0;
    if (is_candidate) {
        snprintf(out_reason, reason_len,
                 "Candidate launch is unavailable until server-side TPM quote verification is implemented");
        return -1;
    }

    /* 1. Verify Examination */
    const char *ep[1] = { exam_id };
    int el[1] = { (int)strlen(exam_id) };
    PGresult *ex_res = db_simple(conn,
        "SELECT id, institution_id, status, exam_url, allowed_origins FROM examinations WHERE id = $1", 1, ep, el);
    if (!ex_res || PQntuples(ex_res) == 0) {
        if (ex_res) PQclear(ex_res);
        snprintf(out_reason, reason_len, "Examination not found in system");
        return -1;
    }
    char ex_inst[64] = {0}, ex_stat[32] = {0}, ex_url[512] = {0}, ex_orgs[512] = {0};
    strncpy(ex_inst, PQgetvalue(ex_res, 0, 1), sizeof(ex_inst) - 1);
    strncpy(ex_stat, PQgetvalue(ex_res, 0, 2), sizeof(ex_stat) - 1);
    strncpy(ex_url, PQgetvalue(ex_res, 0, 3), sizeof(ex_url) - 1);
    strncpy(ex_orgs, PQgetvalue(ex_res, 0, 4), sizeof(ex_orgs) - 1);
    PQclear(ex_res);

    if (is_candidate && strcmp(ex_stat, "scheduled") != 0 &&
        strcmp(ex_stat, "ready") != 0 && strcmp(ex_stat, "in_progress") != 0) {
        snprintf(out_reason, reason_len, "Examination is not available for candidates (status: %s)", ex_stat);
        return -1;
    }
    if (!is_candidate && (strcmp(ex_stat, "cancelled") == 0 || strcmp(ex_stat, "closed") == 0)) {
        snprintf(out_reason, reason_len, "Examination is closed or cancelled (status: %s)", ex_stat);
        return -1;
    }
    if (out_inst_id && inst_len > 0) snprintf(out_inst_id, inst_len, "%s", ex_inst);
    if (out_exam_url && url_len > 0) snprintf(out_exam_url, url_len, "%s", ex_url);
    if (out_allowed_origins && org_len > 0) snprintf(out_allowed_origins, org_len, "%s", ex_orgs);

    /* 2. Verify Student Identity */
    const char *sp[2] = { student_id_or_roll, ex_inst };
    int sl[2] = { (int)strlen(student_id_or_roll), (int)strlen(ex_inst) };
    PGresult *st_res = db_simple(conn,
        "SELECT id, institution_id, roll_no, name, academic_status, administrative_hold, hold_reason "
        "FROM students WHERE (id = $1 OR roll_no = $1) AND institution_id = $2", 2, sp, sl);
    if (!st_res || PQntuples(st_res) == 0) {
        if (st_res) PQclear(st_res);
        snprintf(out_reason, reason_len, "Student record not found in institution database");
        return -1;
    }
    char sid[64] = {0}, st_status[32] = {0}, st_hold[8] = {0}, st_hreason[256] = {0};
    strncpy(sid, PQgetvalue(st_res, 0, 0), sizeof(sid) - 1);
    strncpy(st_status, PQgetvalue(st_res, 0, 4), sizeof(st_status) - 1);
    strncpy(st_hold, PQgetvalue(st_res, 0, 5), sizeof(st_hold) - 1);
    strncpy(st_hreason, PQgetvalue(st_res, 0, 6), sizeof(st_hreason) - 1);
    PQclear(st_res);

    if (out_student_id && sid_len > 0) snprintf(out_student_id, sid_len, "%s", sid);

    if (strcmp(st_status, "active") != 0) {
        snprintf(out_reason, reason_len, "Student academic standing is not active (status: %s)", st_status);
        return -1;
    }
    if (strcmp(st_hold, "t") == 0) {
        snprintf(out_reason, reason_len, "Student has an active administrative hold: %s", st_hreason[0] ? st_hreason : "Fee or disciplinary hold");
        return -1;
    }

    /* 3. Verify Registration and Approved Eligibility (Module 10) */
    const char *rp[2] = { exam_id, sid };
    int rl[2] = { (int)strlen(exam_id), (int)strlen(sid) };
    PGresult *rg_res = db_simple(conn,
        "SELECT registration_status, eligibility_status FROM exam_registrations "
        "WHERE examination_id = $1 AND student_id = $2", 2, rp, rl);
    if (!rg_res || PQntuples(rg_res) == 0) {
        if (rg_res) PQclear(rg_res);
        snprintf(out_reason, reason_len, "Student is not registered for this examination");
        return -1;
    }
    char r_stat[32] = {0}, r_elig[32] = {0};
    strncpy(r_stat, PQgetvalue(rg_res, 0, 0), sizeof(r_stat) - 1);
    strncpy(r_elig, PQgetvalue(rg_res, 0, 1), sizeof(r_elig) - 1);
    PQclear(rg_res);

    if (strcmp(r_stat, "approved") != 0 && strcmp(r_stat, "roster_published") != 0) {
        snprintf(out_reason, reason_len, "Student examination registration is not approved (status: %s)", r_stat);
        return -1;
    }
    if (strcmp(r_elig, "eligible") != 0 && strcmp(r_elig, "exempted") != 0) {
        snprintf(out_reason, reason_len, "Student does not meet eligibility requirements for this examination");
        return -1;
    }

    /* 4. Concurrency Policy Check (Single Active Session per Student/Exam) */
    const char *cp[2] = { exam_id, sid };
    int cl[2] = { (int)strlen(exam_id), (int)strlen(sid) };
    PGresult *cn_res = db_simple(conn,
        "SELECT id, status FROM exam_sessions "
        "WHERE examination_id = $1 AND student_id = $2 AND status IN ('active', 'launching', 'resuming')", 2, cp, cl);
    if (cn_res && PQntuples(cn_res) > 0) {
        char existing_sid[64];
        strncpy(existing_sid, PQgetvalue(cn_res, 0, 0), sizeof(existing_sid) - 1);
        PQclear(cn_res);
        snprintf(out_reason, reason_len, "Active session already in progress for this student (session_id: %s)", existing_sid);
        return -2; /* Concurrency conflict */
    }
    if (cn_res) PQclear(cn_res);

    /* 5. Schedule & Timing Window Check (Module 9) */
    const char *sch_p[1] = { exam_id };
    int sch_l[1] = { (int)strlen(exam_id) };
    PGresult *sch_res = db_simple(conn,
        "SELECT start_time, end_time FROM exam_schedules WHERE exam_id = $1 ORDER BY start_time ASC LIMIT 1", 1, sch_p, sch_l);
    if (sch_res && PQntuples(sch_res) > 0) {
        long long st = atoll(PQgetvalue(sch_res, 0, 0));
        long long et = atoll(PQgetvalue(sch_res, 0, 1));
        PQclear(sch_res);

        long long now_ms = (long long)time(NULL) * 1000;
        /* Normalize seconds to ms if necessary */
        if (st < 10000000000LL) st *= 1000;
        if (et < 10000000000LL) et *= 1000;

        if (now_ms < st) {
            long long wait_sec = (st - now_ms) / 1000;
            if (out_wait_seconds) *out_wait_seconds = wait_sec > 0 ? wait_sec : 1;
            snprintf(out_reason, reason_len, "Examination has not started yet. Please wait until scheduled start time.");
            return 2; /* Early login -> pending */
        }
        if (now_ms > et) {
            snprintf(out_reason, reason_len, "Examination access window has expired.");
            return -1; /* Window expired */
        }
    } else {
        if (sch_res) PQclear(sch_res);
    }

    snprintf(out_reason, reason_len, "Student authorized for examination session");
    return 1;
}

void exam_session_handle(int client_fd, const char *method, const char *path,
                         const char *body, const char *auth_header,
                         const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    memset(&sess, 0, sizeof(sess));

    /* Authenticate user or candidate */
    int auth_rc = ctrl_authorize(auth_header, AUTH_PERM_READ, &sess);
    char candidate_id[64] = {0}, candidate_exam_session_id[64] = {0};
    int is_candidate = ctrl_candidate_session_context(auth_header, candidate_id,
        sizeof(candidate_id), candidate_exam_session_id,
        sizeof(candidate_exam_session_id));
    if (auth_rc != 0 && !is_candidate) {
        ses_send_error(client_fd, 401, "Authentication required", origin, extra_headers, extra_len);
        return;
    }
    int is_owner = (auth_rc == 0 && (sess.role == ROLE_PLATFORM_OWNER ||
                    strcmp(sess.username, "admin") == 0 ||
                    strcmp(sess.username, "root") == 0));

    PGconn *conn = db_acquire();
    if (!conn) {
        ses_send_error(client_fd, 503, "Database connection unavailable", origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 1. POST /api/v1/exam-sessions/authorize (Pre-flight authorization check)
     * ========================================================================= */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/exam-sessions/authorize") == 0) {
        char exam_id[64] = {0}, student_id[64] = {0}, device_id[64] = {0};
        ctrl_json_string(body, "examination_id", exam_id, sizeof(exam_id));
        ctrl_json_string(body, "student_id", student_id, sizeof(student_id));
        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));

        if (!exam_id[0] || !student_id[0]) {
            db_release(conn, 0);
            ses_send_error(client_fd, 400, "examination_id and student_id are required", origin, extra_headers, extra_len);
            return;
        }
        if (is_candidate && !candidate_owns_exam_student(conn, candidate_id, exam_id, student_id)) {
            db_release(conn, 0);
            ses_send_error(client_fd, 403, "Candidate is not assigned to this examination", origin, extra_headers, extra_len);
            return;
        }

        char resolved_sid[64] = {0}, inst_id[64] = {0}, exam_url[512] = {0}, allowed_origins[512] = {0};
        char reason[256] = {0};
        long long wait_sec = 0;

        int res = verify_session_authorization(conn, exam_id, student_id, is_candidate,
                                               resolved_sid, sizeof(resolved_sid),
                                               inst_id, sizeof(inst_id),
                                               exam_url, sizeof(exam_url),
                                               allowed_origins, sizeof(allowed_origins),
                                               &wait_sec, reason, sizeof(reason));

        if (res == -2) {
            /* Concurrency Conflict */
            db_release(conn, 0);
            ses_send_json(client_fd, 409,
                "{\"status\":\"denied\",\"can_create\":false,\"error\":\"CONCURRENT_SESSION_EXISTS\","
                "\"reason\":\"Active session already in progress for this student\"}",
                origin, extra_headers, extra_len);
            return;
        }

        if (res == -1) {
            db_release(conn, 0);
            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"denied\",\"can_create\":false,\"examination_id\":\"%s\",\"student_id\":\"%s\",\"reason\":\"%s\"}",
                exam_id, student_id, reason);
            ses_send_json(client_fd, 403, resp, origin, extra_headers, extra_len);
            return;
        }

        if (res == 2) {
            /* Early Login -> Pending State */
            db_release(conn, 0);
            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"pending\",\"can_create\":false,\"wait_seconds\":%lld,\"examination_id\":\"%s\","
                "\"student_id\":\"%s\",\"reason\":\"%s\"}",
                wait_sec, exam_id, resolved_sid, reason);
            ses_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* res == 1 -> Authorized */
        db_release(conn, 0);
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"authorized\",\"can_create\":true,\"examination_id\":\"%s\",\"student_id\":\"%s\","
            "\"institution_id\":\"%s\",\"reason\":\"%s\"}",
            exam_id, resolved_sid, inst_id, reason);
        ses_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 2. POST /api/v1/exam-sessions (Create Session)
     * ========================================================================= */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/exam-sessions") == 0) {
        char exam_id[64] = {0}, student_id[64] = {0}, device_id[64] = {0};
        char os_rel[64] = "ExamOS 2.0", mac_addr[32] = {0}, ip_addr[45] = {0};

        ctrl_json_string(body, "examination_id", exam_id, sizeof(exam_id));
        ctrl_json_string(body, "student_id", student_id, sizeof(student_id));
        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        ctrl_json_string(body, "os_release", os_rel, sizeof(os_rel));
        ctrl_json_string(body, "mac_address", mac_addr, sizeof(mac_addr));
        ctrl_json_string(body, "ip_address", ip_addr, sizeof(ip_addr));

        if (!exam_id[0] || !student_id[0]) {
            db_release(conn, 0);
            ses_send_error(client_fd, 400, "examination_id and student_id are required", origin, extra_headers, extra_len);
            return;
        }
        if (is_candidate && !candidate_owns_exam_student(conn, candidate_id, exam_id, student_id)) {
            db_release(conn, 0);
            ses_send_error(client_fd, 403, "Candidate is not assigned to this examination", origin, extra_headers, extra_len);
            return;
        }

        char resolved_sid[64] = {0}, inst_id[64] = {0}, exam_url[512] = {0}, allowed_origins[512] = {0};
        char reason[256] = {0};
        long long wait_sec = 0;

        int res = verify_session_authorization(conn, exam_id, student_id, is_candidate,
                                               resolved_sid, sizeof(resolved_sid),
                                               inst_id, sizeof(inst_id),
                                               exam_url, sizeof(exam_url),
                                               allowed_origins, sizeof(allowed_origins),
                                               &wait_sec, reason, sizeof(reason));

        if (res == -2) {
            db_release(conn, 0);
            ses_send_json(client_fd, 409,
                "{\"error\":\"CONCURRENT_SESSION_EXISTS\",\"reason\":\"Active session already in progress for this student\"}",
                origin, extra_headers, extra_len);
            return;
        }

        if (res == -1) {
            db_release(conn, 0);
            char resp[512];
            snprintf(resp, sizeof(resp), "{\"error\":\"SESSION_DENIED\",\"reason\":\"%s\"}", reason);
            ses_send_json(client_fd, 403, resp, origin, extra_headers, extra_len);
            return;
        }

        const char *initial_status = (res == 2) ? "pending" : "authorized";

        char sess_id[64];
        snprintf(sess_id, sizeof(sess_id), "sess_%ld_%d", (long)time(NULL), rand() % 10000);

        long long now_ms = (long long)time(NULL) * 1000;
        char now_str[32];
        snprintf(now_str, sizeof(now_str), "%lld", now_ms);

        const char *sp[6] = { sess_id, inst_id, exam_id, resolved_sid, device_id, initial_status };
        int sl[6];
        for (int i = 0; i < 6; i++) sl[i] = (int)strlen(sp[i]);

        PGresult *ins_s = db_simple(conn,
            "INSERT INTO exam_sessions (id, institution_id, examination_id, student_id, device_id, status, "
            "authorized_at, created_at, updated_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 6, sp, sl);
        if (ins_s) PQclear(ins_s);

        /* Link device record */
        if (device_id[0]) {
            char dev_rec_id[64];
            snprintf(dev_rec_id, sizeof(dev_rec_id), "sdev_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *dp[6] = { dev_rec_id, sess_id, device_id, os_rel, mac_addr, ip_addr };
            int dl[6];
            for (int i = 0; i < 6; i++) dl[i] = (int)strlen(dp[i]);

            PGresult *ins_d = db_simple(conn,
                "INSERT INTO exam_session_devices (id, session_id, device_id, os_release, mac_address, ip_address, bound_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 6, dp, dl);
            if (ins_d) PQclear(ins_d);
        }

        /* Record event and audit */
        char ev_payload[256];
        snprintf(ev_payload, sizeof(ev_payload), "{\"initial_status\":\"%s\",\"wait_seconds\":%lld}", initial_status, wait_sec);
        record_session_event(conn, sess_id, exam_id, inst_id, "authorized", ev_payload);
        record_session_audit(conn, sess_id, exam_id, inst_id, sess.user_id[0] ? sess.user_id : resolved_sid,
                             "SESSION_CREATED", initial_status);
        audit_log(sess.user_id[0] ? sess.user_id : resolved_sid, "EXAM_SESSION_CREATED", sess_id);

        db_release(conn, 0);
        char resp[1024];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"%s\",\"session\":{\"id\":\"%s\",\"institution_id\":\"%s\",\"examination_id\":\"%s\","
            "\"student_id\":\"%s\",\"device_id\":\"%s\",\"status\":\"%s\",\"wait_seconds\":%lld,"
            "\"exam_url\":\"%s\",\"allowed_origins\":\"%s\"}}",
            initial_status, sess_id, inst_id, exam_id, resolved_sid, device_id, initial_status, wait_sec, exam_url, allowed_origins);
        ses_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 3. Examination Session sub-routes: /api/v1/exam-sessions/:id/...
     * ========================================================================= */
    const char *ses_prefix = "/api/v1/exam-sessions/";
    size_t ses_plen = strlen(ses_prefix);
    if (strncmp(path, ses_prefix, ses_plen) == 0) {
        const char *sub = path + ses_plen;
        char session_id[64] = {0};
        const char *slash = strchr(sub, '/');
        size_t id_len = slash ? (size_t)(slash - sub) : strlen(sub);
        if (id_len >= sizeof(session_id)) {
            db_release(conn, 0);
            ses_send_error(client_fd, 400, "Invalid session ID", origin, extra_headers, extra_len);
            return;
        }
        memcpy(session_id, sub, id_len);
        session_id[id_len] = '\0';
        const char *action = slash ? slash : "";
        if (is_candidate && strcmp(candidate_exam_session_id, session_id) != 0) {
            db_release(conn, 0);
            ses_send_error(client_fd, 403,
                "Candidate token is bound to a different exam session",
                origin, extra_headers, extra_len);
            return;
        }

        /* Load Session and verify tenant */
        const char *sp[1] = { session_id };
        int sl[1] = { (int)strlen(session_id) };
        PGresult *s_res = db_simple(conn,
            "SELECT s.id, s.institution_id, s.examination_id, s.student_id, s.device_id, "
            "s.status, s.authorized_at, s.launched_at, s.last_heartbeat_at, s.interrupted_at, "
            "s.closed_at, s.closure_reason, s.interruption_count, "
            "e.exam_url, e.allowed_origins, st.name, st.roll_no "
            "FROM exam_sessions s "
            "JOIN examinations e ON s.examination_id = e.id "
            "JOIN students st ON s.student_id = st.id "
            "WHERE s.id = $1", 1, sp, sl);

        if (!s_res || PQntuples(s_res) == 0) {
            if (s_res) PQclear(s_res);
            db_release(conn, 0);
            ses_send_error(client_fd, 404, "Exam session not found", origin, extra_headers, extra_len);
            return;
        }

        char s_inst[64] = {0}, s_exam[64] = {0}, s_sid[64] = {0}, s_dev[64] = {0}, s_status[32] = {0};
        char s_authat[32] = {0}, s_lnchat[32] = {0}, s_hbat[32] = {0}, s_intat[32] = {0}, s_clsat[32] = {0};
        char s_clsrsn[128] = {0}, s_icnt[16] = {0}, s_url[512] = {0}, s_orgs[512] = {0}, s_sname[128] = {0}, s_sroll[64] = {0};

        strncpy(s_inst, PQgetvalue(s_res, 0, 1), sizeof(s_inst) - 1);
        strncpy(s_exam, PQgetvalue(s_res, 0, 2), sizeof(s_exam) - 1);
        strncpy(s_sid, PQgetvalue(s_res, 0, 3), sizeof(s_sid) - 1);
        strncpy(s_dev, PQgetvalue(s_res, 0, 4), sizeof(s_dev) - 1);
        strncpy(s_status, PQgetvalue(s_res, 0, 5), sizeof(s_status) - 1);
        strncpy(s_authat, PQgetvalue(s_res, 0, 6), sizeof(s_authat) - 1);
        strncpy(s_lnchat, PQgetvalue(s_res, 0, 7), sizeof(s_lnchat) - 1);
        strncpy(s_hbat, PQgetvalue(s_res, 0, 8), sizeof(s_hbat) - 1);
        strncpy(s_intat, PQgetvalue(s_res, 0, 9), sizeof(s_intat) - 1);
        strncpy(s_clsat, PQgetvalue(s_res, 0, 10), sizeof(s_clsat) - 1);
        strncpy(s_clsrsn, PQgetvalue(s_res, 0, 11), sizeof(s_clsrsn) - 1);
        strncpy(s_icnt, PQgetvalue(s_res, 0, 12), sizeof(s_icnt) - 1);
        strncpy(s_url, PQgetvalue(s_res, 0, 13), sizeof(s_url) - 1);
        strncpy(s_orgs, PQgetvalue(s_res, 0, 14), sizeof(s_orgs) - 1);
        strncpy(s_sname, PQgetvalue(s_res, 0, 15), sizeof(s_sname) - 1);
        strncpy(s_sroll, PQgetvalue(s_res, 0, 16), sizeof(s_sroll) - 1);
        PQclear(s_res);

        if (!is_owner && strcmp(s_inst, sess.institution_id) != 0) {
            if (is_candidate && candidate_owns_exam_student(conn, candidate_id, s_exam, s_sid)) {
                /* Candidate sessions are scoped to the roster record and exam below. */
            } else {
                db_release(conn, 0);
                ses_send_error(client_fd, 403, "Access to other institution's exam session is prohibited", origin, extra_headers, extra_len);
                return;
            }
        }
        if (is_candidate &&
            !candidate_owns_exam_student(conn, candidate_id, s_exam, s_sid)) {
            db_release(conn, 0);
            ses_send_error(client_fd, 403, "Candidate may only access their own exam session", origin, extra_headers, extra_len);
            return;
        }
        /* ---------------- GET /api/v1/exam-sessions/:id ---------------- */
        if (strcmp(method, "GET") == 0 && action[0] == '\0') {
            db_release(conn, 0);
            char resp[2048];
            snprintf(resp, sizeof(resp),
                "{\"session\":{\"id\":\"%s\",\"institution_id\":\"%s\",\"examination_id\":\"%s\","
                "\"student_id\":\"%s\",\"student_name\":\"%s\",\"roll_no\":\"%s\",\"device_id\":\"%s\","
                "\"status\":\"%s\",\"authorized_at\":%s,\"launched_at\":%s,\"last_heartbeat_at\":%s,"
                "\"interrupted_at\":%s,\"closed_at\":%s,\"closure_reason\":\"%s\",\"interruption_count\":%s,"
                "\"exam_url\":\"%s\",\"allowed_origins\":\"%s\"}}",
                session_id, s_inst, s_exam, s_sid, s_sname, s_sroll, s_dev, s_status,
                s_authat[0] ? s_authat : "null", s_lnchat[0] ? s_lnchat : "null",
                s_hbat[0] ? s_hbat : "null", s_intat[0] ? s_intat : "null",
                s_clsat[0] ? s_clsat : "null", s_clsrsn, s_icnt, s_url, s_orgs);
            ses_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/exam-sessions/:id/launch (Authorized URL launch) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/launch") == 0) {
            if (is_candidate) {
                const char *runtime_params[1] = { session_id };
                int runtime_lengths[1] = { (int)strlen(session_id) };
                PGresult *runtime_state = db_simple(conn,
                    "SELECT CASE "
                    "WHEN s.status='closed' AND EXISTS ("
                    "SELECT 1 FROM candidate_exam_submissions sub "
                    "WHERE sub.exam_session_id=s.id) THEN 'submission_recorded' "
                    "WHEN s.status IN ('authorized','active','interrupted') AND s.deadline_at<="
                    "EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000 "
                    "THEN 'deadline_expired' ELSE '' END "
                    "FROM exam_sessions s WHERE s.id=$1",
                    1, runtime_params, runtime_lengths);
                if (!runtime_state ||
                    PQresultStatus(runtime_state) != PGRES_TUPLES_OK ||
                    PQntuples(runtime_state) != 1) {
                    if (runtime_state) PQclear(runtime_state);
                    db_release(conn, 1);
                    ses_send_error(client_fd, 503,
                        "Could not verify candidate exam deadline or submission state",
                        origin, extra_headers, extra_len);
                    return;
                }
                char runtime_status[32];
                snprintf(runtime_status, sizeof(runtime_status), "%s",
                         PQgetvalue(runtime_state, 0, 0));
                PQclear(runtime_state);
                if (runtime_status[0]) {
                    db_release(conn, 0);
                    char response[160];
                    snprintf(response, sizeof(response),
                        "{\"status\":\"%s\",\"session_id\":\"%s\"}",
                        runtime_status, session_id);
                    ses_send_json(client_fd, 200, response, origin,
                                  extra_headers, extra_len);
                    return;
                }
                if (!s_url[0] || platform_validate_exam_url(s_url, NULL, 0) != 0) {
                    db_release(conn, 0);
                    ses_send_error(client_fd, 503,
                        "A valid, approved external assessment URL is not configured for this exam",
                        origin, extra_headers, extra_len);
                    return;
                }
                if ((strcmp(s_status, "authorized") != 0 &&
                     strcmp(s_status, "active") != 0) ||
                    attestation_check_device_binding(session_id, s_dev) != 0 ||
                    attestation_check_exam_key_ready(session_id, s_dev) != 0) {
                    db_release(conn, 0);
                    ses_send_error(client_fd, 403,
                        "A fresh TPM-verified authorized exam session is required",
                        origin, extra_headers, extra_len);
                    return;
                }
                const char *launch_params[1] = { session_id };
                int launch_lengths[1] = { (int)strlen(session_id) };
                PGresult *launched = db_simple(conn,
                    "UPDATE exam_sessions s SET status='active',"
                    "launched_at=COALESCE(s.launched_at,EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000),"
                    "deadline_at=COALESCE(s.deadline_at,LEAST("
                    "COALESCE(s.launched_at,EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000)"
                    "+e.duration_minutes::bigint*60000,"
                    "COALESCE((SELECT CASE WHEN schedule.end_time<10000000000 "
                    "THEN schedule.end_time*1000 ELSE schedule.end_time END "
                    "FROM exam_schedules schedule WHERE schedule.exam_id=s.examination_id "
                    "ORDER BY schedule.start_time ASC LIMIT 1),"
                    "COALESCE(s.launched_at,EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000)"
                    "+e.duration_minutes::bigint*60000))),"
                    "updated_at=EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000 "
                    "FROM examinations e WHERE s.id=$1 AND e.id=s.examination_id "
                    "AND s.status IN ('authorized','active') "
                    "AND COALESCE(s.deadline_at,LEAST("
                    "COALESCE(s.launched_at,EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000)"
                    "+e.duration_minutes::bigint*60000,"
                    "COALESCE((SELECT CASE WHEN schedule.end_time<10000000000 "
                    "THEN schedule.end_time*1000 ELSE schedule.end_time END "
                    "FROM exam_schedules schedule WHERE schedule.exam_id=s.examination_id "
                    "ORDER BY schedule.start_time ASC LIMIT 1),"
                    "COALESCE(s.launched_at,EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000)"
                    "+e.duration_minutes::bigint*60000)))>"
                    "EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000 "
                    "RETURNING s.deadline_at",
                    1, launch_params, launch_lengths);
                int launch_ok = launched &&
                    PQresultStatus(launched) == PGRES_TUPLES_OK &&
                    PQntuples(launched) == 1;
                char deadline_at[32] = {0};
                if (launch_ok)
                    snprintf(deadline_at, sizeof(deadline_at), "%s",
                             PQgetvalue(launched, 0, 0));
                if (launched) PQclear(launched);
                if (!launch_ok) {
                    db_release(conn, 1);
                    ses_send_error(client_fd, 409,
                        "Exam session changed before launch",
                        origin, extra_headers, extra_len);
                    return;
                }
                if (strcmp(s_status, "active") != 0) {
                    record_session_event(conn, session_id, s_exam, s_inst,
                                         "launched", "{\"source\":\"candidate\"}");
                    record_session_audit(conn, session_id, s_exam, s_inst,
                        candidate_id, "CANDIDATE_SESSION_LAUNCHED", s_dev);
                    audit_log(candidate_id, "CANDIDATE_SESSION_LAUNCHED", session_id);
                }
                db_release(conn, 0);
                char escaped_session[160], escaped_url[1024];
                ctrl_json_escape(session_id, escaped_session, sizeof(escaped_session));
                ctrl_json_escape(s_url, escaped_url, sizeof(escaped_url));
                char response[1400];
                snprintf(response, sizeof(response),
                    "{\"status\":\"launched\",\"session_id\":\"%s\","
                    "\"exam_url\":\"%s\",\"deadline_at\":%s,\"server_time\":%lld}",
                    escaped_session, escaped_url, deadline_at,
                    (long long)time(NULL) * 1000);
                ses_send_json(client_fd, 200, response, origin,
                              extra_headers, extra_len);
                return;
            }
            db_release(conn, 0);
            ses_send_json(client_fd, 503,
                "{\"status\":\"UNAVAILABLE\",\"error\":\"Exam launch authorization requires verified device trust and durable candidate-session binding.\"}",
                origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/exam-sessions/:id/heartbeat (Liveness report) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/heartbeat") == 0) {
            if (strcmp(s_status, "closed") == 0) {
                db_release(conn, 0);
                ses_send_error(client_fd, 400, "Session is closed", origin, extra_headers, extra_len);
                return;
            }
            if (is_candidate &&
                (attestation_check_device_binding(session_id, s_dev) != 0 ||
                 attestation_check_exam_key_ready(session_id, s_dev) != 0)) {
                db_release(conn, 0);
                ses_send_error(client_fd, 403,
                    "Fresh TPM verification is required to continue the exam session",
                    origin, extra_headers, extra_len);
                return;
            }
            if (is_candidate) {
                const char *deadline_params[1] = { session_id };
                int deadline_lengths[1] = { (int)strlen(session_id) };
                PGresult *deadline = db_simple(conn,
                    "SELECT 1 FROM exam_sessions WHERE id=$1 AND deadline_at>"
                    "EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000",
                    1, deadline_params, deadline_lengths);
                int deadline_valid = deadline &&
                    PQresultStatus(deadline) == PGRES_TUPLES_OK &&
                    PQntuples(deadline) == 1;
                if (deadline) PQclear(deadline);
                if (!deadline_valid) {
                    db_release(conn, 0);
                    ses_send_error(client_fd, 409,
                        "The candidate exam deadline has passed; submit the saved answers",
                        origin, extra_headers, extra_len);
                    return;
                }
            }

            const char *hb_status = strcmp(s_status, "resuming") == 0 ? "active" : s_status;
            const char *hb_p[2] = { hb_status, session_id };
            int hb_l[2] = { (int)strlen(hb_status), (int)strlen(session_id) };

            PGresult *hb_r = db_simple(conn,
                "UPDATE exam_sessions SET status = $1, last_heartbeat_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $2", 2, hb_p, hb_l);
            if (hb_r) PQclear(hb_r);

            record_session_event(conn, session_id, s_exam, s_inst, "heartbeat", "{}");

            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"alive\",\"session_id\":\"%s\",\"session_status\":\"%s\",\"server_time\":%lld}",
                session_id, hb_status, (long long)time(NULL) * 1000);
            ses_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/exam-sessions/:id/interrupt (Interruption notification) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/interrupt") == 0) {
            char reason[128] = "network_loss";
            ctrl_json_string(body, "reason", reason, sizeof(reason));

            if (strcmp(s_status, "closed") == 0) {
                db_release(conn, 0);
                ses_send_error(client_fd, 400, "Session is already closed", origin, extra_headers, extra_len);
                return;
            }

            /* Load Session Policy */
            int max_int = 3, rec_win = 600, allow_re = 1;
            const char *pol_p[1] = { s_exam };
            int pol_l[1] = { (int)strlen(s_exam) };
            PGresult *pol_res = db_simple(conn,
                "SELECT max_interruptions, reconnect_window_sec, allow_reentry FROM exam_session_policies WHERE examination_id = $1", 1, pol_p, pol_l);
            if (pol_res && PQntuples(pol_res) > 0) {
                max_int = atoi(PQgetvalue(pol_res, 0, 0));
                rec_win = atoi(PQgetvalue(pol_res, 0, 1));
                allow_re = (strcmp(PQgetvalue(pol_res, 0, 2), "t") == 0);
                PQclear(pol_res);
            } else {
                if (pol_res) PQclear(pol_res);
            }

            int cur_count = atoi(s_icnt) + 1;
            char cnt_str[16];
            snprintf(cnt_str, sizeof(cnt_str), "%d", cur_count);

            const char *int_p[2] = { cnt_str, session_id };
            int int_l[2] = { (int)strlen(cnt_str), (int)strlen(session_id) };

            PGresult *int_r = db_simple(conn,
                "UPDATE exam_sessions SET status = 'interrupted', interruption_count = $1, "
                "interrupted_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $2", 2, int_p, int_l);
            if (int_r) PQclear(int_r);

            int reentry_allowed = (allow_re && cur_count <= max_int);

            char ev_pay[256];
            snprintf(ev_pay, sizeof(ev_pay), "{\"reason\":\"%s\",\"interruption_count\":%d,\"reentry_allowed\":%s}",
                     reason, cur_count, reentry_allowed ? "true" : "false");
            record_session_event(conn, session_id, s_exam, s_inst, "interruption_detected", ev_pay);
            record_session_audit(conn, session_id, s_exam, s_inst, sess.user_id[0] ? sess.user_id : s_sid,
                                 "SESSION_INTERRUPTED", reason);
            audit_log(sess.user_id[0] ? sess.user_id : s_sid, "EXAM_SESSION_INTERRUPTED", session_id);

            db_release(conn, 0);
            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"interrupted\",\"session_id\":\"%s\",\"interruption_count\":%d,"
                "\"reconnect_window_sec\":%d,\"reentry_allowed\":%s,\"reason\":\"%s\"}",
                session_id, cur_count, rec_win, reentry_allowed ? "true" : "false", reason);
            ses_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/exam-sessions/:id/resume (Reconnection & Resumption) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/resume") == 0) {
            if (is_candidate) {
                if (strcmp(s_status, "interrupted") != 0 || !s_intat[0]) {
                    db_release(conn, 0);
                    ses_send_error(client_fd, 409,
                        "Only an interrupted exam session can be resumed",
                        origin, extra_headers, extra_len);
                    return;
                }
                int max_interruptions = 0, reconnect_window_sec = 0;
                int allow_reentry = 0;
                const char *policy_params[1] = { s_exam };
                int policy_lengths[1] = { (int)strlen(s_exam) };
                PGresult *policy = db_simple(conn,
                    "SELECT max_interruptions,reconnect_window_sec,allow_reentry "
                    "FROM exam_session_policies WHERE examination_id=$1",
                    1, policy_params, policy_lengths);
                int policy_ok = policy &&
                    PQresultStatus(policy) == PGRES_TUPLES_OK &&
                    PQntuples(policy) == 1;
                if (policy_ok) {
                    max_interruptions = atoi(PQgetvalue(policy, 0, 0));
                    reconnect_window_sec = atoi(PQgetvalue(policy, 0, 1));
                    allow_reentry = strcmp(PQgetvalue(policy, 0, 2), "t") == 0;
                }
                if (policy) PQclear(policy);
                long long now_ms = (long long)time(NULL) * 1000;
                long long interrupted_ms = atoll(s_intat);
                int interruptions = atoi(s_icnt);
                int within_window = interrupted_ms > 0 && now_ms >= interrupted_ms &&
                    now_ms - interrupted_ms <= (long long)reconnect_window_sec * 1000;
                if (!policy_ok || !allow_reentry || !within_window ||
                    interruptions > max_interruptions ||
                    attestation_check_device_binding(session_id, s_dev) != 0 ||
                    attestation_check_exam_key_ready(session_id, s_dev) != 0) {
                    db_release(conn, 0);
                    ses_send_error(client_fd, 403,
                        "Exam session resumption policy or fresh TPM verification was not satisfied",
                        origin, extra_headers, extra_len);
                    return;
                }
                const char *resume_params[2] = { session_id, s_icnt };
                int resume_lengths[2] = { (int)strlen(session_id), (int)strlen(s_icnt) };
                PGresult *resumed = db_simple(conn,
                    "UPDATE exam_sessions SET status='active',"
                    "last_heartbeat_at=EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000,"
                    "updated_at=EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000 "
                    "WHERE id=$1 AND interruption_count=$2::integer AND status='interrupted' "
                    "AND deadline_at>EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000",
                    2, resume_params, resume_lengths);
                int resume_ok = resumed &&
                    PQresultStatus(resumed) == PGRES_COMMAND_OK &&
                    strcmp(PQcmdTuples(resumed), "1") == 0;
                if (resumed) PQclear(resumed);
                if (!resume_ok) {
                    db_release(conn, 1);
                    ses_send_error(client_fd, 409,
                        "Exam session changed before resumption",
                        origin, extra_headers, extra_len);
                    return;
                }
                record_session_event(conn, session_id, s_exam, s_inst,
                                     "resumed", "{\"source\":\"candidate\"}");
                record_session_audit(conn, session_id, s_exam, s_inst,
                    candidate_id, "CANDIDATE_SESSION_RESUMED", s_dev);
                audit_log(candidate_id, "CANDIDATE_SESSION_RESUMED", session_id);
                db_release(conn, 0);
                char response[256];
                snprintf(response, sizeof(response),
                    "{\"status\":\"resumed\",\"session_id\":\"%s\"}", session_id);
                ses_send_json(client_fd, 200, response, origin,
                              extra_headers, extra_len);
                return;
            }
            db_release(conn, 0);
            ses_send_json(client_fd, 503,
                "{\"status\":\"UNAVAILABLE\",\"error\":\"Exam session resumption requires renewed device attestation and durable candidate-session binding.\"}",
                origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/exam-sessions/:id/close (Session Closure) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/close") == 0) {
            char reason[128] = "student_completed";
            if (is_candidate) {
                if (strcmp(s_status, "active") != 0) {
                    db_release(conn, 0);
                    ses_send_error(client_fd, 409, "Candidate can only confirm completion for an active session", origin, extra_headers, extra_len);
                    return;
                }
                const char *submission_params[1] = { session_id };
                int submission_lengths[1] = { (int)strlen(session_id) };
                PGresult *submission = db_simple(conn,
                    "SELECT 1 FROM candidate_exam_submissions WHERE exam_session_id=$1",
                    1, submission_params, submission_lengths);
                int submitted = submission &&
                    PQresultStatus(submission) == PGRES_TUPLES_OK &&
                    PQntuples(submission) == 1;
                if (submission) PQclear(submission);
                if (!submitted) {
                    db_release(conn, 0);
                    ses_send_error(client_fd, 409,
                        "Candidate exam sessions can close only after durable submission",
                        origin, extra_headers, extra_len);
                    return;
                }
                snprintf(reason, sizeof(reason), "candidate_confirmed_portal_submission");
            } else {
                ctrl_json_string(body, "reason", reason, sizeof(reason));
            }

            if (strcmp(s_status, "closed") == 0) {
                db_release(conn, 0);
                ses_send_json(client_fd, 200, "{\"status\":\"already_closed\",\"session_id\":\"...\"}", origin, extra_headers, extra_len);
                return;
            }

            const char *cls_p[2] = { reason, session_id };
            int cls_l[2] = { (int)strlen(reason), (int)strlen(session_id) };

            PGresult *cls_r = db_simple(conn,
                "UPDATE exam_sessions SET status = 'closed', closure_reason = $1, "
                "closed_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $2", 2, cls_p, cls_l);
            if (cls_r) PQclear(cls_r);

            char ev_pay[256];
            snprintf(ev_pay, sizeof(ev_pay), "{\"closure_reason\":\"%s\"}", reason);
            record_session_event(conn, session_id, s_exam, s_inst, "closed", ev_pay);
            record_session_audit(conn, session_id, s_exam, s_inst, sess.user_id[0] ? sess.user_id : s_sid,
                                 "SESSION_CLOSED", reason);
            audit_log(sess.user_id[0] ? sess.user_id : s_sid, "EXAM_SESSION_CLOSED", session_id);

            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"closed\",\"session_id\":\"%s\",\"closure_reason\":\"%s\"}",
                session_id, reason);
            ses_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        db_release(conn, 0);
        ses_send_error(client_fd, 404, "Endpoint not found", origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 4. GET /api/v1/examinations/:id/sessions (List sessions for examination)
     * ========================================================================= */
    const char *ex_prefix = "/api/v1/examinations/";
    size_t ex_plen = strlen(ex_prefix);
    if (strncmp(path, ex_prefix, ex_plen) == 0 && strstr(path, "/sessions")) {
        const char *sub = path + ex_plen;
        const char *slash = strchr(sub, '/');
        if (slash) {
            char exam_id[64] = {0};
            size_t id_len = (size_t)(slash - sub);
            if (id_len < sizeof(exam_id)) {
                memcpy(exam_id, sub, id_len);
                exam_id[id_len] = '\0';

                /* Verify Exam existence & Tenant boundary */
                const char *ep[1] = { exam_id };
                int el[1] = { (int)strlen(exam_id) };
                PGresult *ex_chk = db_simple(conn, "SELECT id, institution_id FROM examinations WHERE id = $1", 1, ep, el);
                if (!ex_chk || PQntuples(ex_chk) == 0) {
                    if (ex_chk) PQclear(ex_chk);
                    db_release(conn, 0);
                    ses_send_error(client_fd, 404, "Examination not found", origin, extra_headers, extra_len);
                    return;
                }
                char ex_inst[64] = {0};
                strncpy(ex_inst, PQgetvalue(ex_chk, 0, 1), sizeof(ex_inst) - 1);
                PQclear(ex_chk);

                if (!is_owner && strcmp(ex_inst, sess.institution_id) != 0) {
                    db_release(conn, 0);
                    ses_send_error(client_fd, 403, "Access to other institution's exam sessions is prohibited", origin, extra_headers, extra_len);
                    return;
                }

                /* Query sessions */
                const char *qp[1] = { exam_id };
                int ql[1] = { (int)strlen(exam_id) };
                PGresult *ses_list = db_simple(conn,
                    "SELECT s.id, s.institution_id, s.examination_id, s.student_id, s.device_id, "
                    "s.status, s.authorized_at, s.launched_at, s.last_heartbeat_at, s.interrupted_at, "
                    "s.closed_at, s.closure_reason, s.interruption_count, "
                    "st.name, st.roll_no "
                    "FROM exam_sessions s "
                    "JOIN students st ON s.student_id = st.id "
                    "WHERE s.examination_id = $1 ORDER BY s.created_at DESC", 1, qp, ql);

                char *json = malloc(262144);
                if (!json) {
                    if (ses_list) PQclear(ses_list);
                    db_release(conn, 0);
                    ses_send_error(client_fd, 500, "Out of memory", origin, extra_headers, extra_len);
                    return;
                }

                size_t pos = 0;
                pos += snprintf(json + pos, 262144 - pos, "{\"sessions\":[");
                if (ses_list && PQresultStatus(ses_list) == PGRES_TUPLES_OK) {
                    int n = PQntuples(ses_list);
                    for (int i = 0; i < n; i++) {
                        if (i > 0) pos += snprintf(json + pos, 262144 - pos, ",");
                        const char *auth_at = PQgetvalue(ses_list, i, 6);
                        const char *lnch_at = PQgetvalue(ses_list, i, 7);
                        const char *hb_at = PQgetvalue(ses_list, i, 8);
                        const char *int_at = PQgetvalue(ses_list, i, 9);
                        const char *cls_at = PQgetvalue(ses_list, i, 10);

                        pos += snprintf(json + pos, 262144 - pos,
                            "{\"id\":\"%s\",\"institution_id\":\"%s\",\"examination_id\":\"%s\","
                            "\"student_id\":\"%s\",\"device_id\":\"%s\",\"status\":\"%s\","
                            "\"authorized_at\":%s,\"launched_at\":%s,\"last_heartbeat_at\":%s,"
                            "\"interrupted_at\":%s,\"closed_at\":%s,\"closure_reason\":\"%s\","
                            "\"interruption_count\":%s,\"student_name\":\"%s\",\"roll_no\":\"%s\"}",
                            PQgetvalue(ses_list, i, 0), PQgetvalue(ses_list, i, 1), PQgetvalue(ses_list, i, 2),
                            PQgetvalue(ses_list, i, 3), PQgetvalue(ses_list, i, 4), PQgetvalue(ses_list, i, 5),
                            auth_at[0] ? auth_at : "null", lnch_at[0] ? lnch_at : "null",
                            hb_at[0] ? hb_at : "null", int_at[0] ? int_at : "null",
                            cls_at[0] ? cls_at : "null", PQgetvalue(ses_list, i, 11),
                            PQgetvalue(ses_list, i, 12), PQgetvalue(ses_list, i, 13), PQgetvalue(ses_list, i, 14));
                    }
                }
                if (ses_list) PQclear(ses_list);
                pos += snprintf(json + pos, 262144 - pos, "]}");

                db_release(conn, 0);
                ses_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
                free(json);
                return;
            }
        }
    }

    db_release(conn, 0);
    ses_send_error(client_fd, 404, "Exam session endpoint not found", origin, extra_headers, extra_len);
}
