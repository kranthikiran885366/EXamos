/*
 * department_controller.c — Department Management Module 4
 *
 * Full lifecycle: create → validate → approve → activate → suspend → archive → transfer
 * Multi-tenant isolation, approval workflows, RBAC, audit trail,
 * tamper-evident ledger, PostgreSQL persistence.
 */

#include "department_controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../security/security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void dept_send_json(int fd, int code, const char *body,
                           const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void dept_send_error(int fd, int code, const char *msg,
                            const char *origin, char *extra, size_t extra_len) {
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg ? msg : "An unexpected error occurred");
    dept_send_json(fd, code, buf, origin, extra, extra_len);
}

static void dept_audit(const char *actor, const char *event,
                       const char *target, const char *detail) {
    audit_append(actor ? actor : "system", event, detail ? detail : "");
    ledger_block_t blk;
    ledger_append_event(event, target ? target : "SYSTEM", detail ? detail : "", &blk);
}

static int dept_authz(const char *auth_header, uint32_t perm,
                      auth_session_t *out) {
    return ctrl_authorize(auth_header, perm, out) == 0;
}

static int dept_in_scope(const auth_session_t *s, const char *inst_id) {
    if (!s || !inst_id) return 0;
    if (s->role == ROLE_PLATFORM_OWNER) return 1;
    if (s->institution_id[0] && strcmp(s->institution_id, inst_id) == 0) return 1;
    return 0;
}

static void dept_gen_id(char *out, size_t out_len, const char *prefix) {
    time_t t = time(NULL);
    snprintf(out, out_len, "%s_%lu", prefix, (unsigned long)t);
}

static void dept_escape_sql(char *out, size_t out_len, const char *in) {
    size_t j = 0;
    out[0] = '\0';
    for (size_t i = 0; in[i] && j + 2 < out_len; i++) {
        if (in[i] == '\'') { out[j++] = '\''; out[j++] = '\''; }
        else out[j++] = in[i];
    }
    out[j] = '\0';
}

static PGresult *dept_db_simple(PGconn *conn, const char *sql,
                                int n_params, const char **params, const int *lens) {
    return PQexecParams(conn, sql, n_params, (const Oid *)NULL,
                        params, lens)
}

/* ============================================================================
 * Department CRUD + Lifecycle
 * ============================================================================ */

static void dept_list(int client_fd, const char *auth_header,
                      const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_READ, &sess)) {
        dept_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    int is_owner = (sess.role == ROLE_PLATFORM_OWNER);
    PGresult *res;
    if (is_owner) {
        res = PQexec(conn,
            "SELECT id, tenant_id, campus_id, name, code, type, department_head_id, "
                    "programs, status, approval_status, effective_from, "
                    "effective_to, created_by, created_at, updated_at "
            "FROM departments ORDER BY created_at DESC");
    } else {
        const char *pv[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };
        res = PQexecParams(conn,
            "SELECT id, tenant_id, campus_id, name, code, type, department_head_id, "
                    "programs, status, approval_status, effective_from, "
                    "effective_to, created_by, created_at, updated_at "
            "FROM departments WHERE tenant_id = $1 ORDER BY created_at DESC",
            1, pv, lens)
    }

    char json[262144] = {0};
    size_t pos = 0;
    pos += snprintf(json + pos, sizeof(json) - pos, "{\"departments\":[");

    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
        int n = PQntuples(res);
        for (int i = 0; i < n; i++) {
            if (i > 0) pos += snprintf(json + pos, sizeof(json) - pos, ",");
            pos += snprintf(json + pos, sizeof(json) - pos,
                "{\"id\":\"%s\",\"tenant_id\":\"%s\",\"campus_id\":\"%s\","
                "\"name\":\"%s\",\"code\":\"%s\",\"type\":\"%s\","
                "\"department_head_id\":\"%s\",\"programs\":\"%s\","
                "\"status\":\"%s\",\"approval_status\":\"%s\","
                "\"effective_from\":%s,\"effective_to\":%s,"
                "\"created_by\":\"%s\",\"created_at\":%s,\"updated_at\":%s}",
                PQgetvalue(res, i, 0) ? PQgetvalue(res, i, 0) : "",
                PQgetvalue(res, i, 1) ? PQgetvalue(res, i, 1) : "",
                PQgetvalue(res, i, 2) ? PQgetvalue(res, i, 2) : "",
                PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "",
                PQgetvalue(res, i, 4) ? PQgetvalue(res, i, 4) : "",
                PQgetvalue(res, i, 5) ? PQgetvalue(res, i, 5) : "",
                PQgetvalue(res, i, 6) ? PQgetvalue(res, i, 6) : "",
                PQgetvalue(res, i, 7) ? PQgetvalue(res, i, 7) : "",
                PQgetvalue(res, i, 8) ? PQgetvalue(res, i, 8) : "",
                PQgetvalue(res, i, 9) ? PQgetvalue(res, i, 9) : "",
                PQgetvalue(res, i, 10) ? PQgetvalue(res, i, 10) : "0",
                PQgetvalue(res, i, 11) ? PQgetvalue(res, i, 11) : "0",
                PQgetvalue(res, i, 12) ? PQgetvalue(res, i, 12) : "",
                PQgetvalue(res, i, 13) ? PQgetvalue(res, i, 13) : "",
                PQgetvalue(res, i, 14) ? PQgetvalue(res, i, 14) : "");
        }
    }
    if (res) PQclear(res);
    snprintf(json + pos, sizeof(json) - pos, "]}");
    db_release(conn, 0);
    dept_send_json(client_fd, 200, json, origin, extra, extra_len);
}

static void dept_create(int client_fd, const char *body,
                        const char *auth_header,
                        const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        dept_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    char name[128] = {0}, code[32] = {0}, type[40] = {0};
    char campus_id[64] = {0}, head_id[64] = {0};
    char eff_from[32] = {0}, eff_to[32] = {0};
    char programs[1024] = {0};

    ctrl_json_string(body, "name", name, sizeof(name));
    ctrl_json_string(body, "code", code, sizeof(code));
    ctrl_json_string(body, "type", type, sizeof(type));
    ctrl_json_string(body, "campus_id", campus_id, sizeof(campus_id));
    ctrl_json_string(body, "department_head_id", head_id, sizeof(head_id));
    ctrl_json_string(body, "effective_from", eff_from, sizeof(eff_from));
    ctrl_json_string(body, "effective_to", eff_to, sizeof(eff_to));
    ctrl_json_string(body, "programs", programs, sizeof(programs));

    if (!name[0] || !code[0] || !campus_id[0] || !sess.institution_id[0]) {
        dept_send_json(client_fd, 400, "{\"error\":\"name, code, campus_id and institution context required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    /* Verify campus belongs to same institution */
    const char *chk_p[1] = { campus_id };
    int chk_l[1] = { (int)strlen(campus_id) };
    PGresult *chk = db_simple(conn,
        "SELECT id, tenant_id FROM campuses WHERE id = $1",
        1, chk_p, chk_l);
    if (!chk || PQresultStatus(chk) != PGRES_TUPLES_OK || PQntuples(chk) == 0) {
        if (chk) PQclear(chk);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Campus not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *campus_inst_id = PQgetvalue(chk, 0, 1);
    if (strcmp(sess.institution_id, campus_inst_id) != 0 &&
        sess.role != ROLE_PLATFORM_OWNER) {
        PQclear(chk);
        db_release(conn, 0);
        dept_send_json(client_fd, 403, "{\"error\":\"Campus belongs to another institution\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(chk);

    /* Check duplicate code within institution */
    const char *dup_p[2] = { code, sess.institution_id };
    int dup_l[2] = { (int)strlen(code), (int)strlen(sess.institution_id) };
    PGresult *dup = db_simple(conn,
        "SELECT id FROM departments WHERE code = $1 AND tenant_id = $2",
        2, dup_p, dup_l);
    int is_dup = dup && PQresultStatus(dup) == PGRES_TUPLES_OK && PQntuples(dup) > 0;
    if (dup) PQclear(dup);

    if (is_dup) {
        dept_send_json(client_fd, 409, "{\"error\":\"Department code already exists in this institution\"}",
                       origin, extra, extra_len);
        db_release(conn, 0);
        return;
    }

    char id[64]; dept_gen_id(id, sizeof(id), "dep");
    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));

    char esc_name[256] = {0}, esc_code[64] = {0}, esc_type[80] = {0};
    char esc_head[64] = {0}, esc_eff_from[64] = {0}, esc_eff_to[64] = {0};
    char esc_programs[2048] = {0};
    dept_escape_sql(name, esc_name, sizeof(esc_name));
    dept_escape_sql(code, esc_code, sizeof(esc_code));
    dept_escape_sql(type, esc_type, sizeof(esc_type));
    dept_escape_sql(head_id, esc_head, sizeof(esc_head));
    dept_escape_sql(eff_from, esc_eff_from, sizeof(esc_eff_from));
    dept_escape_sql(eff_to, esc_eff_to, sizeof(esc_eff_to));
    dept_escape_sql(programs, esc_programs, sizeof(esc_programs));

    const char *ins_p[14] = { id, sess.institution_id, campus_id, name, code, type,
                              head_id, eff_from, eff_to, programs,
                              now, sess.user_id };
    int il[14];
    for (int i = 0; i < 14; i++) il[i] = 0;
    il[0] = (int)strlen(id); il[1] = (int)strlen(sess.institution_id);
    il[2] = (int)strlen(campus_id); il[3] = (int)strlen(esc_name);
    il[4] = (int)strlen(esc_code); il[5] = (int)strlen(esc_type);
    il[6] = (int)strlen(esc_head); il[7] = (int)strlen(esc_eff_from);
    il[8] = (int)strlen(esc_eff_to); il[9] = (int)strlen(esc_programs);
    il[10] = (int)strlen(now); il[11] = (int)strlen(sess.user_id);

    PGresult *ins = db_simple(conn,
        "INSERT INTO departments (id, tenant_id, campus_id, name, code, type, "
         "department_head_id, effective_from, effective_to, programs, "
         "status, approval_status, created_by, created_at, updated_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending','pending',$11,"
         "to_timestamp($12),to_timestamp($12))",
        12, ins_p, il)
    int ok_created = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
    if (ins) PQclear(ins);

    if (!ok_created) {
        dept_send_json(client_fd, 503, "{\"error\":\"Department creation failed\"}",
                       origin, extra, extra_len);
        db_release(conn, 0);
        return;
    }

    /* Create approval request */
    char ap_id[64]; dept_gen_id(ap_id, sizeof(ap_id), "apr");
    const char *ap_p[9] = { ap_id, id, sess.institution_id, campus_id,
                            "create", sess.user_id, now, "pending", sess.user_id };
    int ap_l[9];
    for (int i = 0; i < 9; i++) ap_l[i] = (int)strlen(ap_p[i]);
    PGresult *apr = db_simple(conn,
        "INSERT INTO department_approvals (id, department_id, institution_id, campus_id, "
         "action, requested_by, requested_at, status, decided_by, decided_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7),$8,$9,to_timestamp($9))",
        9, ap_p, ap_l)
    if (apr) PQclear(apr);

    /* Record history */
    char och_id[64]; dept_gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, sess.institution_id, NULL, id,
                              sess.user_id, "department_create", "departments", id,
                              NULL, NULL, NULL, now };
    int och_l[12];
    for (int i = 0; i < 12; i++) och_l[i] = (int)strlen(och_p[i]);
    PGresult *och = db_simple(conn,
        "INSERT INTO organization_change_history (id, institution_id, campus_id, "
         "department_id, actor_id, action, target_table, target_id, "
         "previous_values, new_values, reason, created_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12))",
        12, och_p, och_l);
    if (och) PQclear(och);

    db_release(conn, 0);

    if (!ok_created) {
        dept_send_json(client_fd, 503, "{\"error\":\"Department creation failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"submitted\",\"department_id\":\"%s\"}", id);
    dept_send_json(client_fd, 201, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "DEPARTMENT_CREATE_REQUESTED", id);
}

static void dept_get(int client_fd, const char *dept_id,
                     const char *auth_header,
                     const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_READ, &sess)) {
        dept_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { dept_id };
    int l[1] = { (int)strlen(dept_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, campus_id, name, code, type, department_head_id, "
                "programs, status, approval_status, effective_from, effective_to, "
                "created_by, created_at, updated_at "
         "FROM departments WHERE id = $1",
        1, p, l);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Department not found\"}",
                       origin, extra, extra_len);
        return;
    }

    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, PQgetvalue(res, 0, 1)) != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 403, "{\"error\":\"Department scope denied\"}",
                       origin, extra, extra_len);
        return;
    }

    char json[16384] = {0};
    snprintf(json, sizeof(json),
        "{\"department\":{\"id\":\"%s\",\"tenant_id\":\"%s\",\"campus_id\":\"%s\","
        "\"name\":\"%s\",\"code\":\"%s\",\"type\":\"%s\","
        "\"department_head_id\":\"%s\",\"programs\":\"%s\","
        "\"status\":\"%s\",\"approval_status\":\"%s\","
        "\"effective_from\":%s,\"effective_to\":%s,"
        "\"created_by\":\"%s\",\"created_at\":%s,\"updated_at\":%s}}",
        PQgetvalue(res, 0, 0) ? PQgetvalue(res, 0, 0) : "",
        PQgetvalue(res, 0, 1) ? PQgetvalue(res, 0, 1) : "",
        PQgetvalue(res, 0, 2) ? PQgetvalue(res, 0, 2) : "",
        PQgetvalue(res, 0, 3) ? PQgetvalue(res, i, 3) : "",
        PQgetvalue(res, 0, 4) ? PQgetvalue(res, 0, 4) : "",
        PQgetvalue(res, 0, 5) ? PQgetvalue(res, 0, 5) : "",
        PQgetvalue(res, 0, 6) ? PQgetvalue(res, i, 6) : "",
        PQgetvalue(res, 0, 7) ? PQgetvalue(res, i, 7) : "",
        PQgetvalue(res, 0, 8) ? PQgetvalue(res, 0, 8) : "",
        PQgetvalue(res, 0, 9) ? PQgetvalue(res, i, 9) : "",
        PQgetvalue(res, 0, 10) ? PQgetvalue(res, i, 10) : "0",
        PQgetvalue(res, 0, 11) ? PQgetvalue(res, i, 11) : "0",
        PQgetvalue(res, 0, 12) ? PQgetvalue(res, i, 12) : "",
        PQgetvalue(res, 0, 13) ? PQgetvalue(res, i, 13) : "",
        PQgetvalue(res, 0, 14) ? PQgetvalue(res, i, 14) : "");
    if (res) PQclear(res);
    db_release(conn, 0);
    dept_send_json(client_fd, 200, json, origin, extra, extra_len);
}

static void dept_submit_approval(int client_fd, const char *dept_id,
                                 const char *auth_header,
                                 const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        dept_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { dept_id };
    int l[1] = { (int)strlen(dept_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, approval_status FROM departments WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Department not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 1);
    const char *cur_status = PQgetvalue(res, 0, 2);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 403, "{\"error\":\"Department scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(cur_status, "pending") != 0 && strcmp(cur_status, "rejected") != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 400, "{\"error\":\"Department already submitted or approved\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char ap_id[64]; dept_gen_id(ap_id, sizeof(ap_id), "apr");
    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *ap_p[9] = { ap_id, dept_id, inst_id, "", "create",
                            sess.user_id, now, "pending", sess.user_id };
    int ap_l[9];
    for (int i = 0; i < 9; i++) ap_l[i] = (int)strlen(ap_p[i]);
    PGresult *apr = db_simple(conn,
        "INSERT INTO department_approvals (id, department_id, institution_id, campus_id, "
         "action, requested_by, requested_at, status, decided_by, decided_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7),$8,$9,to_timestamp($9))",
        9, ap_p, ap_l)
    int ok = apr && PQresultStatus(apr) == PGRES_COMMAND_OK;
    if (apr) PQclear(apr);

    const char *up_p[3] = { "pending", now, dept_id };
    int up_l[3] = { 7, (int)strlen(now), (int)strlen(dept_id) };
    PGresult *up = db_simple(conn,
        "UPDATE departments SET approval_status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    if (up) PQclear(up);

    char och_id[64]; dept_gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, NULL, dept_id, sess.user_id,
                              "department_submit", "departments", dept_id,
                              NULL, NULL, NULL, now };
    int och_l[12];
    for (int i = 0; i < 12; i++) och_l[i] = (int)strlen(och_p[i]);
    PGresult *och = db_simple(conn,
        "INSERT INTO organization_change_history (id, institution_id, campus_id, "
         "department_id, actor_id, action, target_table, target_id, "
         "previous_values, new_values, reason, created_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12))",
        12, och_p, och_l);
    if (och) PQclear(och);

    db_release(conn, 0);

    if (!ok) {
        dept_send_json(client_fd, 503, "{\"error\":\"Approval submission failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"submitted\",\"department_id\":\"%s\"}", dept_id);
    dept_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "DEPARTMENT_SUBMIT_APPROVAL", dept_id);
}

static void dept_activate(int client_fd, const char *dept_id,
                          const char *auth_header,
                          const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        dept_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { dept_id };
    int l[1] = { (int)strlen(dept_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, approval_status, status FROM departments WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Department not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 1);
    const char *appr = PQgetvalue(res, 0, 2);
    const char *cur = PQgetvalue(res, 0, 3);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 403, "{\"error\":\"Department scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(appr, "approved") != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 400, "{\"error\":\"Department not approved yet\"}",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(cur, "active") == 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 400, "{\"error\":\"Department already active\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *up_p[3] = { "active", now, dept_id };
    int up_l[3] = { 6, (int)strlen(now), (int)strlen(dept_id) };
    PGresult *up = db_simple(conn,
        "UPDATE departments SET status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    int ok = up && PQresultStatus(up) == PGRES_COMMAND_OK;
    if (up) PQclear(up);

    char och_id[64]; dept_gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, NULL, dept_id, sess.user_id,
                              "department_activate", "departments", dept_id,
                              NULL, NULL, NULL, now };
    int och_l[12];
    for (int i = 0; i < 12; i++) och_l[i] = (int)strlen(och_p[i]);
    PGresult *och = db_simple(conn,
        "INSERT INTO organization_change_history (id, institution_id, campus_id, "
         "department_id, actor_id, action, target_table, target_id, "
         "previous_values, new_values, reason, created_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12))",
        12, och_p, och_l);
    if (och) PQclear(och);

    db_release(conn, 0);

    if (!ok) {
        dept_send_json(client_fd, 503, "{\"error\":\"Activation failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"active\",\"department_id\":\"%s\"}", dept_id);
    dept_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "DEPARTMENT_ACTIVATED", dept_id);
}

static void dept_suspend(int client_fd, const char *dept_id,
                         const char *auth_header,
                         const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        dept_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { dept_id };
    int l[1] = { (int)strlen(dept_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, status FROM departments WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Department not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 1);
    const char *cur = PQgetvalue(res, 0, 2);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 403, "{\"error\":\"Department scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(cur, "suspended") == 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 400, "{\"error\":\"Department already suspended\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *up_p[3] = { "suspended", now, dept_id };
    int up_l[3] = { 9, (int)strlen(now), (int)strlen(dept_id) };
    PGresult *up = db_simple(conn,
        "UPDATE departments SET status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    int ok = up && PQresultStatus(up) == PGRES_COMMAND_OK;
    if (up) PQclear(up);

    char och_id[64]; dept_gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, NULL, dept_id, sess.user_id,
                              "department_suspend", "departments", dept_id,
                              NULL, NULL, NULL, now };
    int och_l[12];
    for (int i = 0; i < 12; i++) och_l[i] = (int)strlen(och_p[i]);
    PGresult *och = db_simple(conn,
        "INSERT INTO organization_change_history (id, institution_id, campus_id, "
         "department_id, actor_id, action, target_table, target_id, "
         "previous_values, new_values, reason, created_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12))",
        12, och_p, och_l);
    if (och) PQclear(och);

    db_release(conn, 0);

    if (!ok) {
        dept_send_json(client_fd, 503, "{\"error\":\"Suspension failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"suspended\",\"department_id\":\"%s\"}", dept_id);
    dept_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "DEPARTMENT_SUSPENDED", dept_id);
}

static void dept_archive(int client_fd, const char *dept_id,
                         const char *auth_header,
                         const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authorized(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        dept_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { dept_id };
    int l[1] = { (int)strlen(dept_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, status FROM departments WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Department not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 1);
    const char *cur = PQgetvalue(res, 0, 2);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 403, "{\"error\":\"Department scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(cur, "archived") == 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 400, "{\"error\":\"Department already archived\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *up_p[3] = { "archived", now, dept_id };
    int up_l[3] = { 9, (int)strlen(now), (int)strlen(dept_id) };
    PGresult *up = db_simple(conn,
        "UPDATE departments SET status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    int ok = up && PQresultStatus(up) == PGRES_COMMAND_OK;
    if (up) PQclear(up);

    char och_id[64]; dept_gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, NULL, dept_id, sess.user_id,
                              "department_archive", "departments", dept_id,
                              NULL, NULL, NULL, now };
    int och_l[12];
    for (int i = 0; i < 12; i++) och_l[i] = (int)strlen(och_p[i]);
    PGresult *och = db_simple(conn,
        "INSERT INTO organization_change_history (id, institution_id, campus_id, "
         "department_id, actor_id, action, target_table, target_id, "
         "previous_values, new_values, reason, created_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12))",
        12, och_p, och_l);
    if (och) PQclear(och);

    db_release(conn, 0);

    if (!ok) {
        dept_send_json(client_fd, 503, "{\"error\":\"Archive failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"archived\",\"department_id\":\"%s\"}", dept_id);
    dept_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "DEPARTMENT_ARCHIVED", dept_id);
}

static void dept_transfer(int client_fd, const char *dept_id,
                          const char *body,
                          const char *auth_header,
                          const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        dept_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    char new_campus_id[64] = {0};
    ctrl_json_string(body, "campus_id", new_campus_id, sizeof(new_campus_id));
    if (!new_campus_id[0]) {
        dept_send_json(client_fd, 400, "{\"error\":\"campus_id required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { dept_id };
    int l[1] = { (int)strlen(dept_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, campus_id, status FROM departments WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Department not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 1);
    const char *old_campus_id = PQgetvalue(res, 0, 2);
    const char *cur = PQgetvalue(res, 0, 3);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 403, "{\"error\":\"Department scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    /* Verify new campus exists and belongs to same institution */
    const char *nc_p[1] = { new_campus_id };
    int nc_l[1] = { (int)strlen(new_campus_id) };
    PGresult *nc_res = db_simple(conn,
        "SELECT id, tenant_id FROM campuses WHERE id = $1",
        1, nc_p, nc_l);
    if (!nc_res || PQresultStatus(nc_res) != PGRES_TUPLES_OK || PQntuples(nc_res) == 0) {
        if (nc_res) PQclear(nc_res);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Target campus not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *nc_inst_id = PQgetvalue(nc_res, 0, 1);
    if (strcmp(inst_id, nc_inst_id) != 0) {
        PQclear(nc_res);
        db_release(conn, 0);
        dept_send_json(client_fd, 400, "{\"error\":\"Target campus belongs to another institution\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(nc_res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *up_p[3] = { new_campus_id, now, dept_id };
    int up_l[3] = { (int)strlen(new_campus_id), (int)strlen(now), (int)strlen(dept_id) };
    PGresult *up = db_simple(conn,
        "UPDATE departments SET campus_id = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    int ok = up && PQresultStatus(up) == PGRES_COMMAND_OK;
    if (up) PQclear(up);

    char och_id[64]; dept_gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, new_campus_id, dept_id, sess.user_id,
                              "department_transfer", "departments", dept_id,
                              old_campus_id, new_campus_id, "Transferred campus", now };
    int och_l[12];
    for (int i = 0; i < 12; i++) och_l[i] = (int)strlen(och_p[i]);
    PGresult *och = db_simple(conn,
        "INSERT INTO organization_change_history (id, institution_id, campus_id, "
         "department_id, actor_id, action, target_table, target_id, "
         "previous_values, new_values, reason, created_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12))",
        12, och_p, och_l);
    if (och) PQclear(och);

    db_release(conn, 0);

    if (!ok) {
        dept_send_json(client_fd, 503, "{\"error\":\"Transfer failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"transferred\",\"department_id\":\"%s\",\"campus_id\":\"%s\"}",
             dept_id, new_campus_id);
    dept_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "DEPARTMENT_TRANSFERRED", dept_id);
}

static void dept_approvals_list(int client_fd, const char *auth_header,
                                const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_READ, &sess)) {
        dept_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    PGresult *res;
    if (sess.role == ROLE_PLATFORM_OWNER) {
        res = db_simple(conn,
            "SELECT da.id, da.department_id, da.institution_id, da.campus_id, "
                    "da.action, da.requested_by, da.requested_at, da.status, "
                    "u.username as requester_name, d.name as department_name, c.name as campus_name "
            "FROM department_approvals da "
            "LEFT JOIN users u ON u.id = da.requested_by "
            "LEFT JOIN departments d ON d.id = da.department_id "
            "LEFT JOIN campuses c ON c.id = da.campus_id "
            "WHERE da.status = 'pending' ORDER BY da.requested_at ASC",
            0, NULL, NULL);
    } else {
        const char *pvals[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };
        res = db_simple(conn,
            "SELECT da.id, da.department_id, da.institution_id, da.campus_id, "
                    "da.action, da.requested_by, da.requested_at, da.status, "
                    "u.username as requester_name, d.name as department_name, c.name as campus_name "
            "FROM department_approvals da "
            "LEFT JOIN users u ON u.id = da.requested_by "
            "LEFT JOIN departments d ON d.id = da.department_id "
            "LEFT JOIN campuses c ON c.id = da.campus_id "
            "WHERE da.institution_id = $1 AND da.status = 'pending' "
            "ORDER BY da.requested_at ASC",
            1, pvals, lens);
    }

    char json[131072] = {0};
    size_t pos = 0;
    pos += snprintf(json + pos, sizeof(json) - pos, "{\"approvals\":[");

    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
        int n = PQntuples(res);
        for (int i = 0; i < n; i++) {
            if (i > 0) pos += snprintf(json + pos, sizeof(json) - pos, ",");
            pos += snprintf(json + pos, sizeof(json) - pos,
                "{\"id\":\"%s\",\"department_id\":\"%s\",\"institution_id\":\"%s\","
                "\"campus_id\":\"%s\",\"action\":\"%s\",\"requested_by\":\"%s\","
                "\"requested_at\":%s,\"status\":\"%s\",\"requester_name\":\"%s\","
                "\"department_name\":\"%s\",\"campus_name\":\"%s\"}",
                PQgetvalue(res, i, 0) ? PQgetvalue(res, i, 0) : "",
                PQgetvalue(res, i, 1) ? PQgetvalue(res, i, 1) : "",
                PQgetvalue(res, i, 2) ? PQgetvalue(res, i, 2) : "",
                PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "",
                PQgetvalue(res, i, 4) ? PQgetvalue(res, i, 4) : "",
                PQgetvalue(res, i, 5) ? PQgetvalue(res, i, 5) : "0",
                PQgetvalue(res, i, 6) ? PQgetvalue(res, i, 6) : "",
                PQgetvalue(res, i, 7) ? PQgetvalue(res, i, 7) : "",
                PQgetvalue(res, i, 8) ? PQgetvalue(res, i, 8) : "",
                PQgetvalue(res, i, 9) ? PQgetvalue(res, i, 9) : "",
                PQgetvalue(res, i, 10) ? PQgetvalue(res, i, 10) : "");
        }
    }
    if (res) PQclear(res);
    snprintf(json + pos, sizeof(json) - pos, "]}");
    db_release(conn, 0);
    dept_send_json(client_fd, 200, json, origin, extra, extra_len);
}

static void dept_approval_decide(int client_fd, const char *approval_id,
                                 const char *body,
                                 const char *auth_header,
                                 const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        dept_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    char decision[16] = {0}, reason[512] = {0};
    ctrl_json_string(body, "decision", decision, sizeof(decision));
    ctrl_json_string(body, "reason", reason, sizeof(reason));

    if (strcmp(decision, "approved") != 0 && strcmp(decision, "rejected") != 0) {
        dept_send_json(client_fd, 400, "{\"error\":\"decision must be approved or rejected\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { approval_id };
    int l[1] = { (int)strlen(approval_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, department_id, institution_id, campus_id, action, requested_by, status "
        "FROM department_approvals WHERE id = $1 AND status = 'pending'",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Approval not found or already decided\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *dept_id = PQgetvalue(res, 0, 1);
    const char *inst_id = PQgetvalue(res, 0, 2);
    const char *campus_id = PQgetvalue(res, 0, 3);
    const char *action = PQgetvalue(res, 0, 4);
    const char *req_by = PQgetvalue(res, 0, 5);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 403, "{\"error\":\"Approval scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));

    const char *ap_p[4] = { decision, sess.user_id, now, approval_id };
    int ap_l[4] = { (int)strlen(decision), (int)strlen(sess.user_id),
                    (int)strlen(now), (int)strlen(approval_id) };
    PGresult *apr = db_simple(conn,
        "UPDATE department_approvals SET status = $1, decided_by = $2, "
         "decided_at = to_timestamp($3), decision_reason = $4 WHERE id = $4",
        4, ap_p, ap_l)
    int ok = apr && PQresultStatus(apr) == PGRES_COMMAND_OK;
    if (apr) PQclear(apr);

    const char *new_status = strcmp(decision, "approved") == 0 ? "approved" : "rejected";
    const char *up_p[3] = { new_status, now, dept_id };
    int up_l[3] = { (int)strlen(new_status), (int)strlen(now), (int)strlen(dept_id) };
    PGresult *up = db_simple(conn,
        "UPDATE departments SET approval_status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    if (up) PQclear(up);

    char och_id[64]; dept_gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, campus_id, dept_id, sess.user_id,
                              "department_approval_decide", "departments", dept_id,
                              NULL, NULL, NULL, now };
    int och_l[12];
    for (int i = 0; i < 12; i++) och_l[i] = (int)strlen(och_p[i]);
    PGresult *och = db_simple(conn,
        "INSERT INTO organization_change_history (id, institution_id, campus_id, "
         "department_id, actor_id, action, target_table, target_id, "
         "previous_values, new_values, reason, created_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12))",
        12, och_p, och_l);
    if (och) PQclear(och);

    db_release(conn, 0);

    if (!ok) {
        dept_send_json(client_fd, 503, "{\"error\":\"Decision recording failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"%s\",\"department_id\":\"%s\"}",
             decision, dept_id);
    dept_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "DEPARTMENT_APPROVAL_DECIDED", dept_id);
}

static void dept_user_assignments_list(int client_fd, const char *auth_header,
                                       const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_READ, &sess)) {
        dept_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    PGresult *res;
    if (sess.role == ROLE_PLATFORM_OWNER) {
        res = db_simple(conn,
            "SELECT dua.id, dua.department_id, dua.institution_id, dua.campus_id, "
                    "dua.user_id, dua.role, dua.status, dua.assigned_by, "
                    "dua.assigned_at, dua.expires_at, dua.reason, "
                    "u.username, u.name, d.name as department_name, c.name as campus_name "
            "FROM department_user_assignments dua "
            "LEFT JOIN users u ON u.id = dua.user_id "
            "LEFT JOIN departments d ON d.id = dua.department_id "
            "LEFT JOIN campuses c ON c.id = dua.campus_id "
            "ORDER BY dua.assigned_at DESC",
            0, NULL, NULL);
    } else {
        const char *pvals[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };
        res = db_simple(conn,
            "SELECT dua.id, dua.department_id, dua.institution_id, dua.campus_id, "
                    "dua.user_id, dua.role, dua.status, dua.assigned_by, "
                    "dua.assigned_at, dua.expires_at, dua.reason, "
                    "u.username, u.name, d.name as department_name, c.name as campus_name "
            "FROM department_user_assignments dua "
            "LEFT JOIN users u ON u.id = dua.user_id "
            "LEFT JOIN departments d ON d.id = dua.department_id "
            "LEFT JOIN campuses c ON c.id = dua.campus_id "
            "WHERE dua.institution_id = $1 ORDER BY dua.assigned_at DESC",
            1, pvals, lens);
    }

    char json[262144] = {0};
    size_t pos = 0;
    pos += snprintf(json + pos, sizeof(json) - pos, "{\"assignments\":[");

    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
        int n = PQntuples(res);
        for (int i = 0; i < n; i++) {
            if (i > 0) pos += snprintf(json + pos, sizeof(json) - pos, ",");
            pos += snprintf(json + pos, sizeof(json) - pos,
                "{\"id\":\"%s\",\"department_id\":\"%s\",\"institution_id\":\"%s\","
                "\"campus_id\":\"%s\",\"user_id\":\"%s\",\"role\":\"%s\",\"status\":\"%s\","
                "\"assigned_by\":\"%s\",\"assigned_at\":%s,\"expires_at\":%s,"
                "\"reason\":\"%s\",\"username\":\"%s\",\"user_name\":\"%s\","
                "\"department_name\":\"%s\",\"campus_name\":\"%s\"}",
                PQgetvalue(res, i, 0) ? PQgetvalue(res, i, 0) : "",
                PQgetvalue(res, i, 1) ? PQgetvalue(res, i, 1) : "",
                PQgetvalue(res, i, 2) ? PQgetvalue(res, i, 2) : "",
                PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "",
                PQgetvalue(res, i, 4) ? PQgetvalue(res, i, 4) : "",
                PQgetvalue(res, i, 5) ? PQgetvalue(res, i, 5) : "",
                PQgetvalue(res, i, 6) ? PQgetvalue(res, i, 6) : "",
                PQgetvalue(res, i, 7) ? PQgetvalue(res, i, 7) : "0",
                PQgetvalue(res, i, 8) ? PQgetvalue(res, i, 8) : "0",
                PQgetvalue(res, i, 9) ? PQgetvalue(res, i, 9) : "",
                PQgetvalue(res, i, 10) ? PQgetvalue(res, i, 10) : "",
                PQgetvalue(res, i, 11) ? PQgetvalue(res, i, 11) : "",
                PQgetvalue(res, i, 12) ? PQgetvalue(res, i, 12) : "");
        }
    }
    if (res) PQclear(res);
    snprintf(json + pos, sizeof(json) - pos, "]}");
    db_release(conn, 0);
    dept_send_json(client_fd, 200, json, origin, extra, extra_len);
}

static void dept_user_assign(int client_fd, const char *body,
                             const char *auth_header,
                             const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        dept_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    char dept_id[64] = {0}, user_id[64] = {0}, role[40] = {0};
    ctrl_json_string(body, "department_id", dept_id, sizeof(dept_id));
    ctrl_json_string(body, "user_id", user_id, sizeof(user_id));
    ctrl_json_string(body, "role", role, sizeof(role));
    if (!dept_id[0] || !user_id[0] || !role[0]) {
        dept_send_json(client_fd, 400, "{\"error\":\"department_id, user_id and role required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { dept_id };
    int l[1] = { (int)strlen(dept_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, campus_id FROM departments WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Department not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 1);
    const char *campus_id = PQgetvalue(res, 0, 2);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 403, "{\"error\":\"Department scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char id[64]; dept_gen_id(id, sizeof(id), "dua");
    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));

    const char *ap_p[10] = { id, dept_id, inst_id, campus_id, user_id, role,
                             "active", sess.user_id, now, NULL };
    int ap_l[10];
    for (int i = 0; i < 9; i++) ap_l[i] = (int)strlen(ap_p[i]);
    ap_l[9] = 0;

    PGresult *ins = db_simple(conn,
        "INSERT INTO department_user_assignments (id, department_id, institution_id, campus_id, "
         "user_id, role, status, assigned_by, assigned_at, expires_at, reason) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,to_timestamp($8),$9,$10)",
        10, ap_p, ap_l)
    int ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
    if (ins) PQclear(ins);

    char och_id[64]; dept_gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, campus_id, dept_id, sess.user_id,
                              "department_user_assign", "department_user_assignments", id,
                              NULL, NULL, NULL, now };
    int och_l[12];
    for (int i = 0; i < 12; i++) och_l[i] = (int)strlen(och_p[i]);
    PGresult *och = db_simple(conn,
        "INSERT INTO organization_change_history (id, institution_id, campus_id, "
         "department_id, actor_id, action, target_table, target_id, "
         "previous_values, new_values, reason, created_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12))",
        12, och_p, och_l);
    if (och) PQclear(och);

    db_release(conn, 0);

    if (!ok) {
        dept_send_json(client_fd, 503, "{\"error\":\"Assignment failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"assigned\",\"assignment_id\":\"%s\"}", id);
    dept_send_json(client_fd, 201, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "DEPARTMENT_USER_ASSIGNED", user_id);
}

static void dept_user_revoke(int client_fd, const char *assign_id,
                             const char *auth_header,
                             const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        dept_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { assign_id };
    int l[1] = { (int)strlen(assign_id) };
    PGresult *res = db_simple(conn,
        "SELECT dua.id, dua.department_id, dua.institution_id, dua.campus_id, dua.user_id "
        "FROM department_user_assignments dua WHERE dua.id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 404, "{\"error\":\"Assignment not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 2);
    const char *user_id = PQgetvalue(res, 0, 3);
    const char *campus_id = PQgetvalue(res, 0, 1);
    const char *dept_id = PQgetvalue(res, 0, 1);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        dept_send_json(client_fd, 403, "{\"error\":\"Assignment scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *up_p[3] = { "revoked", now, assign_id };
    int up_l[3] = { 8, (int)strlen(now), (int)strlen(assign_id) };
    PGresult *up = db_simple(conn,
        "UPDATE department_user_assignments SET status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    int ok = up && PQresultStatus(up) == PGRES_COMMAND_OK;
    if (up) PQclear(up);

    char och_id[64]; dept_gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, campus_id, dept_id, sess.user_id,
                              "department_user_revoke", "department_user_assignments", assign_id,
                              NULL, NULL, NULL, now };
    int och_l[12];
    for (int i = 0; i < 12; i++) och_l[i] = (int)strlen(och_p[i]);
    PGresult *och = db_simple(conn,
        "INSERT INTO organization_change_history (id, institution_id, campus_id, "
         "department_id, actor_id, action, target_table, target_id, "
         "previous_values, new_values, reason, created_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,to_timestamp($12))",
        12, och_p, och_l);
    if (och) PQclear(och);

    db_release(conn, 0);

    if (!ok) {
        dept_send_json(client_fd, 503, "{\"error\":\"Revocation failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"revoked\",\"assignment_id\":\"%s\"}", assign_id);
    dept_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "DEPARTMENT_USER_REVOKED", user_id);
}

static void dept_programs_list(int client_fd, const char *auth_header,
                               const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_READ, &sess)) {
        dept_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    PGresult *res;
    if (sess.role == ROLE_PLATFORM_OWNER) {
        res = db_simple(conn,
            "SELECT id, tenant_id, campus_id, department_id, program_code, program_name, "
                    "program_type, degree_level, duration_months, total_seats, "
                    "status, created_by, created_at, updated_at, updated_by "
            "FROM academic_programs ORDER BY created_at DESC",
            0, NULL, NULL);
    } else {
        const char *p[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };
        res = db_simple(conn,
            "SELECT id, tenant_id, campus_id, department_id, program_code, program_name, "
                    "program_type, degree_level, duration_months, total_seats, "
                    "status, created_by, created_at, updated_at, updated_by "
            "FROM academic_programs WHERE tenant_id = $1 ORDER BY created_at DESC",
            1, p, lens);
    }

    char json[262144] = {0};
    size_t pos = 0;
    pos += snprintf(json + pos, sizeof(json) - pos, "{\"programs\":[");

    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
        int n = PQntuples(res);
        for (int i = 0; i < n; i++) {
            if (i > 0) pos += snprintf(json + pos, sizeof(json) - pos, ",");
            pos += snprintf(json + pos, sizeof(json) - pos,
                "{\"id\":\"%s\",\"tenant_id\":\"%s\",\"campus_id\":\"%s\","
                "\"department_id\":\"%s\",\"program_code\":\"%s\",\"program_name\":\"%s\","
                "\"program_type\":\"%s\",\"degree_level\":\"%s\","
                "\"duration_months\":%s,\"total_seats\":%s,\"status\":\"%s\","
                "\"created_by\":\"%s\",\"created_at\":%s,\"updated_at\":%s,\"updated_by\":\"%s\"}",
                PQgetvalue(res, i, 0) ? PQgetvalue(res, i, 0) : "",
                PQgetvalue(res, i, 1) ? PQgetvalue(res, i, 1) : "",
                PQgetvalue(res, i, 2) ? PQgetvalue(res, i, 2) : "",
                PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "",
                PQgetvalue(res, i, 4) ? PQgetvalue(res, i, 4) : "",
                PQgetvalue(res, i, 5) ? PQgetvalue(res, i, 5) : "",
                PQgetvalue(res, i, 6) ? PQgetvalue(res, i, 6) : "",
                PQgetvalue(res, i, 7) ? PQgetvalue(res, i, 7) : "",
                PQgetvalue(res, i, 8) ? PQgetvalue(res, i, 8) : "0",
                PQgetvalue(res, i, 9) ? PQgetvalue(res, i, 9) : "0",
                PQgetvalue(res, i, 10) ? PQgetvalue(res, i, 10) : "",
                PQgetvalue(res, i, 11) ? PQgetvalue(res, i, 11) : "",
                PQgetvalue(res, i, 12) ? PQgetvalue(res, i, 12) : "",
                PQgetvalue(res, i, 13) ? PQgetvalue(res, i, 13) : "");
        }
    }
    if (res) PQclear(res);
    snprintf(json + pos, sizeof(json) - pos, "]}");
    db_release(conn, 0);
    dept_send_json(client_fd, 200, json, origin, extra, extra_len);
}

static void dept_programs_create(int client_fd, const char *body,
                                 const char *auth_header,
                                 const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!dept_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        dept_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    char program_code[32] = {0}, program_name[128] = {0};
    char program_type[40] = {0}, degree_level[40] = {0};
    char department_id[64] = {0}, duration_months[16] = {0};
    char total_seats[16] = {0};

    ctrl_json_string(body, "program_code", program_code, sizeof(program_code));
    ctrl_json_string(body, "program_name", program_name, sizeof(program_name));
    ctrl_json_string(body, "program_type", program_type, sizeof(program_type));
    ctrl_json_string(body, "degree_level", degree_level, sizeof(degree_level));
    ctrl_json_string(body, "department_id", department_id, sizeof(department_id));
    ctrl_json_string(body, "duration_months", duration_months, sizeof(duration_months));
    ctrl_json_string(body, "total_seats", total_seats, sizeof(total_seats));

    if (!program_code[0] || !program_name[0] || !department_id[0] ||
        !sess.institution_id[0]) {
        dept_send_json(client_fd, 400, "{\"error\":\"program_code, program_name, department_id and institution context required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        dept_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *chk_p[1] = { program_code };
    int chk_l[1] = { (int)strlen(program_code) };
    PGresult *chk = db_simple(conn,
        "SELECT id FROM academic_programs WHERE program_code = $1 AND tenant_id = $2",
        1, chk_p, chk_l);
    int is_dup = chk && PQresultStatus(chk) == PGRES_TUPLES_OK && PQntuples(chk) > 0;
    if (chk) PQclear(chk);

    if (is_dup) {
        dept_send_json(client_fd, 409, "{\"error\":\"Program code already exists in this institution\"}",
                       origin, extra, extra_len);
        db_release(conn, 0);
        return;
    }

    char id[64]; dept_gen_id(id, sizeof(id), "prog");
    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));

    const char *ins_p[13] = { id, sess.institution_id, department_id, program_code,
                              program_name, program_type, degree_level,
                              duration_months[0] ? duration_months : NULL,
                              total_seats[0] ? total_seats : NULL, "draft",
                              now, sess.user_id, sess.user_id };
    int il[13];
    for (int i = 0; i < 13; i++) il[i] = 0;
    il[0] = (int)strlen(id);
    il[1] = (int)strlen(sess.institution_id);
    il[2] = (int)strlen(department_id);
    il[3] = (int)strlen(program_code);
    il[4] = (int)strlen(program_name);
    il[5] = (int)strlen(program_type);
    il[6] = (int)strlen(degree_level);
    il[7] = (int)strlen(duration_months);
    il[8] = (int)strlen(total_seats);
    il[9] = 6;
    il[10] = (int)strlen(now);
    il[11] = (int)strlen(sess.user_id);
    il[12] = (int)strlen(sess.user_id);

    PGresult *ins = db_simple(conn,
        "INSERT INTO academic_programs (id, tenant_id, department_id, program_code, "
         "program_name, program_type, degree_level, duration_months, total_seats, "
         "status, created_by, created_at, updated_at, updated_by) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        13, ins_p, il)
    int ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
    if (ins) PQclear(ins);

    db_release(conn, 0);

    if (!ok) {
        dept_send_json(client_fd, 503, "{\"error\":\"Program creation failed\"}",
                       origin, extra, extra_len);
        return;
    }

    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"program_id\":\"%s\"}", id);
    dept_send_json(client_fd, 201, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "DEPARTMENT_PROGRAM_CREATE", program_name);
}

void department_handle(int client_fd, const char *method, const char *path,
                       const char *body, const char *auth_header,
                       const char *origin, char *extra_headers, size_t extra_len) {
    char sub_id[128] = {0};
    char action[64] = {0};

    if (strncmp(path, "/api/v1/admin/departments/", 26) == 0) {
        const char *rest = path + 26;
        const char *slash = strchr(rest, '/');
        if (slash) {
            size_t id_len = (size_t)(slash - rest);
            if (id_len > 0 && id_len < sizeof(sub_id)) {
                memcpy(sub_id, rest, id_len);
                sub_id[id_len] = '\0';
            }
            const char *action_start = slash + 1;
            size_t act_len = strlen(action_start);
            if (act_len > 0 && act_len < sizeof(action)) {
                memcpy(action, action_start, act_len);
                action[act_len] = '\0';
            }
        } else {
            size_t rest_len = strlen(rest);
            if (rest_len > 0 && rest_len < sizeof(sub_id)) {
                memcpy(sub_id, rest, rest_len);
                sub_id[rest_len] = '\0';
            }
        }
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/departments") == 0) {
        dept_list(client_fd, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/departments") == 0) {
        dept_create(client_fd, body, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (sub_id[0]) {
        if (strcmp(method, "GET") == 0 && action[0] == '\0') {
            dept_get(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(action, "submit-for-approval") == 0) {
            dept_submit_approval(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(action, "activate") == 0) {
            dept_activate(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(action, "suspend") == 0) {
            dept_suspend(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(action, "archive") == 0) {
            dept_archive(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(action, "transfer") == 0) {
            dept_transfer(client_fd, sub_id, body, auth_header, origin, extra_headers, extra_len);
            return;
        }
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/department-approvals") == 0) {
        dept_approvals_list(client_fd, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 &&
        strncmp(path, "/api/v1/admin/department-approvals/", 36) == 0) {
        const char *rest = path + 36;
        const char *slash = strchr(rest, '/');
        if (slash && strcmp(slash, "/decide") == 0) {
            char ap_id[128] = {0};
            size_t id_len = (size_t)(slash - rest);
            if (id_len > 0 && id_len < sizeof(ap_id)) {
                memcpy(ap_id, rest, id_len);
                ap_id[id_len] = '\0';
            }
            dept_approval_decide(client_fd, ap_id, body, auth_header, origin, extra_headers, extra_len);
            return;
        }
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/department-user-assignments") == 0) {
        dept_user_assignments_list(client_fd, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/department-user-assignments") == 0) {
        dept_user_assign(client_fd, body, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 &&
        strncmp(path, "/api/v1/admin/department-user-assignments/", 44) == 0) {
        const char *rest = path + 44;
        size_t id_len = strlen(rest);
        if (id_len > 0 && id_len < sizeof(sub_id)) {
            memcpy(sub_id, rest, id_len);
            sub_id[id_len] = '\0';
        }
        dept_user_revoke(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/academic-programs") == 0) {
        dept_programs_list(client_fd, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/academic-programs") == 0) {
        dept_programs_create(client_fd, body, auth_header, origin, extra_headers, extra_len);
        return;
    }

    dept_send_json(client_fd, 404, "{\"error\":\"Department route not found\"}",
                   origin, extra_headers, extra_len);
}
