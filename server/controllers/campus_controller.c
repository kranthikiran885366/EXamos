/*
 * campus_controller.c — Campus Management Module 4
 *
 * Full lifecycle: register → validate → approve → activate → suspend → close
 * Multi-tenant isolation, approval workflows, RBAC, audit trail,
 * tamper-evident ledger, PostgreSQL persistence.
 */

#include "campus_controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../security/security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void camp_send_json(int fd, int code, const char *body,
                           const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void camp_send_error(int fd, int code, const char *msg,
                            const char *origin, char *extra, size_t extra_len) {
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg ? msg : "An unexpected error occurred");
    camp_send_json(fd, code, buf, origin, extra, extra_len);
}

static void camp_audit(const char *actor, const char *event,
                       const char *target, const char *detail) {
    audit_append(actor ? actor : "system", event, detail ? detail : "");
    ledger_block_t blk;
    ledger_append_event(event, target ? target : "SYSTEM", detail ? detail : "", &blk);
}

static int campus_authz(const char *auth_header, uint32_t perm,
                        auth_session_t *out) {
    return ctrl_authorize(auth_header, perm, out) == 0;
}

static int campus_in_scope(const auth_session_t *s, const char *inst_id) {
    if (!s || !inst_id) return 0;
    if (s->role == ROLE_PLATFORM_OWNER) return 1;
    if (s->institution_id[0] && strcmp(s->institution_id, inst_id) == 0) return 1;
    return 0;
}

static void gen_id(char *out, size_t out_len, const char *prefix) {
    time_t t = time(NULL);
    snprintf(out, out_len, "%s_%lu", prefix, (unsigned long)t);
}

static void escape_sql(char *out, size_t out_len, const char *in) {
    size_t j = 0;
    out[0] = '\0';
    for (size_t i = 0; in[i] && j + 2 < out_len; i++) {
        if (in[i] == '\'') { out[j++] = '\''; out[j++] = '\''; }
        else out[j++] = in[i];
    }
    out[j] = '\0';
}

static int run_sql(PGconn *conn, const char *sql) {
    PGresult *r = PQexec(conn, sql);
    int ok = (r && PQresultStatus(r) == PGRES_COMMAND_OK);
    if (r) PQclear(r);
    return ok;
}

/* ============================================================================
 * Campus CRUD + Lifecycle
 * ============================================================================ */

static void campus_list(int client_fd, const char *auth_header,
                        const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_READ, &sess)) {
        camp_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    int is_owner = (sess.role == ROLE_PLATFORM_OWNER);
    PGresult *res;
    if (is_owner) {
        res = PQexec(conn,
            "SELECT id, tenant_id, name, code, address, city, state, country, "
                    "postal_code, contact_name, contact_phone, contact_email, "
                    "campus_type, timezone, exam_capacity, device_capacity, "
                    "status, approval_status, created_at, updated_at "
            "FROM campuses ORDER BY created_at DESC");
    } else {
        const char *pv[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };
        res = db_simple(conn,
            "SELECT id, tenant_id, name, code, address, city, state, country, "
                    "postal_code, contact_name, contact_phone, contact_email, "
                    "campus_type, timezone, exam_capacity, device_capacity, "
                    "status, approval_status, created_at, updated_at "
            "FROM campuses WHERE tenant_id = $1 ORDER BY created_at DESC",
            1, pv, lens);
    }

    char json[262144] = {0};
    size_t pos = 0;
    pos += snprintf(json + pos, sizeof(json) - pos, "{\"campuses\":[");

    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
        int n = PQntuples(res);
        for (int i = 0; i < n; i++) {
            if (i > 0) pos += snprintf(json + pos, sizeof(json) - pos, ",");
            pos += snprintf(json + pos, sizeof(json) - pos,
                "{\"id\":\"%s\",\"tenant_id\":\"%s\",\"name\":\"%s\",\"code\":\"%s\","
                "\"address\":\"%s\",\"city\":\"%s\",\"state\":\"%s\",\"country\":\"%s\","
                "\"postal_code\":\"%s\",\"contact_name\":\"%s\",\"contact_phone\":\"%s\","
                "\"contact_email\":\"%s\",\"campus_type\":\"%s\",\"timezone\":\"%s\","
                "\"exam_capacity\":%s,\"device_capacity\":%s,\"status\":\"%s\","
                "\"approval_status\":\"%s\",\"created_at\":%s,\"updated_at\":%s}",
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
                PQgetvalue(res, i, 10) ? PQgetvalue(res, i, 10) : "",
                PQgetvalue(res, i, 11) ? PQgetvalue(res, i, 11) : "",
                PQgetvalue(res, i, 12) ? PQgetvalue(res, i, 12) : "",
                PQgetvalue(res, i, 13) ? PQgetvalue(res, i, 13) : "",
                PQgetvalue(res, i, 14) ? PQgetvalue(res, i, 14) : "",
                PQgetvalue(res, i, 15) ? PQgetvalue(res, i, 15) : "",
                PQgetvalue(res, i, 16) ? PQgetvalue(res, i, 16) : "",
                PQgetvalue(res, i, 17) ? PQgetvalue(res, i, 17) : "0",
                PQgetvalue(res, i, 18) ? PQgetvalue(res, i, 18) : "0");
        }
    }
    if (res) PQclear(res);
    snprintf(json + pos, sizeof(json) - pos, "]}");
    db_release(conn, 0);
    camp_send_json(client_fd, 200, json, origin, extra, extra_len);
}

static void campus_create(int client_fd, const char *body,
                          const char *auth_header,
                          const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        camp_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    char name[128] = {0}, code[32] = {0}, address[256] = {0}, city[80] = {0};
    char state[80] = {0}, country[80] = {0}, postal[32] = {0};
    char contact_name[128] = {0}, contact_phone[40] = {0}, contact_email[120] = {0};
    char campus_type[40] = {0}, timezone[64] = {0};
    int exam_cap = 0, dev_cap = 0;

    ctrl_json_string(body, "name", name, sizeof(name));
    ctrl_json_string(body, "code", code, sizeof(code));
    ctrl_json_string(body, "address", address, sizeof(address));
    ctrl_json_string(body, "city", city, sizeof(city));
    ctrl_json_string(body, "state", state, sizeof(state));
    ctrl_json_string(body, "country", country, sizeof(country));
    ctrl_json_string(body, "postal_code", postal, sizeof(postal));
    ctrl_json_string(body, "contact_name", contact_name, sizeof(contact_name));
    ctrl_json_string(body, "contact_phone", contact_phone, sizeof(contact_phone));
    ctrl_json_string(body, "contact_email", contact_email, sizeof(contact_email));
    ctrl_json_string(body, "campus_type", campus_type, sizeof(campus_type));
    ctrl_json_string(body, "timezone", timezone, sizeof(timezone));
    ctrl_json_int(body, "exam_capacity", &exam_cap);
    ctrl_json_int(body, "device_capacity", &dev_cap);

    /* Platform owners have no institution scope in their session token.
     * The console sends institution_id (or tenantId) in the request body. */
    if (sess.role == ROLE_PLATFORM_OWNER && !sess.institution_id[0]) {
        char body_inst[64] = {0};
        ctrl_json_string(body, "institution_id", body_inst, sizeof(body_inst));
        if (!body_inst[0])
            ctrl_json_string(body, "tenantId", body_inst, sizeof(body_inst));
        if (body_inst[0])
            strncpy(sess.institution_id, body_inst, sizeof(sess.institution_id) - 1);
    }

    if (!name[0] || !code[0] || !sess.institution_id[0]) {
        camp_send_json(client_fd, 400, "{\"error\":\"name, code and institution context required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *chk_p[2] = { code, sess.institution_id };
    int chk_l[2] = { (int)strlen(code), (int)strlen(sess.institution_id) };
    PGresult *chk = db_simple(conn,
        "SELECT id FROM campuses WHERE code = $1 AND tenant_id = $2",
        2, chk_p, chk_l);
    int dup = chk && PQresultStatus(chk) == PGRES_TUPLES_OK && PQntuples(chk) > 0;
    if (chk) PQclear(chk);

    if (dup) {
        camp_send_json(client_fd, 409, "{\"error\":\"Campus code already exists in this institution\"}",
                       origin, extra, extra_len);
        db_release(conn, 0);
        return;
    }

    char id[64]; gen_id(id, sizeof(id), "cmp");
    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));

    char esc_name[256] = {0}, esc_code[64] = {0}, esc_addr[512] = {0};
    char esc_city[160] = {0}, esc_state[160] = {0}, esc_country[160] = {0};
    char esc_postal[64] = {0}, esc_contact_name[256] = {0}, esc_contact_phone[80] = {0};
    char esc_contact_email[240] = {0}, esc_campus_type[80] = {0}, esc_timezone[128] = {0};
    escape_sql(name, esc_name, sizeof(esc_name));
    escape_sql(code, esc_code, sizeof(esc_code));
    escape_sql(address, esc_addr, sizeof(esc_addr));
    escape_sql(city, esc_city, sizeof(esc_city));
    escape_sql(state, esc_state, sizeof(esc_state));
    escape_sql(country, esc_country, sizeof(esc_country));
    escape_sql(postal, esc_postal, sizeof(esc_postal));
    escape_sql(contact_name, esc_contact_name, sizeof(esc_contact_name));
    escape_sql(contact_phone, esc_contact_phone, sizeof(esc_contact_phone));
    escape_sql(contact_email, esc_contact_email, sizeof(esc_contact_email));
    escape_sql(campus_type, esc_campus_type, sizeof(esc_campus_type));
    escape_sql(timezone, esc_timezone, sizeof(esc_timezone));

    /* $1...$14: id, tenant_id, name, code, addr, city, state, country,
     *           postal, contact_name, contact_phone, contact_email,
     *           campus_type, timezone
     * $15: exam_capacity  $16: device_capacity
     * $17: created_at (epoch)  $18: created_by */
    char exam_cap_str[16], dev_cap_str[16];
    snprintf(exam_cap_str, sizeof(exam_cap_str), "%d", exam_cap);
    snprintf(dev_cap_str, sizeof(dev_cap_str), "%d", dev_cap);

    const char *ins_p[18] = {
        id, sess.institution_id, esc_name, esc_code, esc_addr,
        esc_city, esc_state, esc_country, esc_postal,
        esc_contact_name, esc_contact_phone, esc_contact_email,
        esc_campus_type, esc_timezone,
        exam_cap_str, dev_cap_str, now, sess.user_id
    };
    int il[18];
    for (int i = 0; i < 18; i++) il[i] = (int)strlen(ins_p[i] ? ins_p[i] : "");

    PGresult *ins = db_simple(conn,
        "INSERT INTO campuses "
        "(id, tenant_id, name, code, address, city, state, country, postal_code, "
        " contact_name, contact_phone, contact_email, campus_type, timezone, "
        " exam_capacity, device_capacity, status, approval_status, "
        " created_at, updated_at, created_by) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,"
        "'pending','pending',"
        "to_timestamp($17::bigint),to_timestamp($17::bigint),$18)",
        18, ins_p, il);
    int created_ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
    if (ins) PQclear(ins);

    db_release(conn, 0);

    if (!created_ok) {
        camp_send_json(client_fd, 503, "{\"error\":\"Campus creation failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[256];
    snprintf(resp, sizeof(resp),
        "{\"status\":\"created\",\"campus_id\":\"%s\",\"approval_status\":\"pending\"}", id);
    camp_send_json(client_fd, 201, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "CAMPUS_CREATED", id);
}

static void campus_get(int client_fd, const char *campus_id,
                       const char *auth_header,
                       const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_READ, &sess)) {
        camp_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { campus_id };
    int l[1] = { (int)strlen(campus_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, name, code, address, city, state, country, "
                "postal_code, contact_name, contact_phone, contact_email, "
                "campus_type, timezone, exam_capacity, device_capacity, "
                "status, approval_status, created_at, updated_at, "
                "approved_by, approved_at, deployment_status, last_deployed_at "
         "FROM campuses WHERE id = $1",
        1, p, l);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 404, "{\"error\":\"Campus not found\"}",
                       origin, extra, extra_len);
        return;
    }

    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, PQgetvalue(res, 0, 1)) != 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 403, "{\"error\":\"Campus scope denied\"}",
                       origin, extra, extra_len);
        return;
    }

    char json[16384] = {0};
    snprintf(json, sizeof(json),
        "{\"campus\":{\"id\":\"%s\",\"tenant_id\":\"%s\",\"name\":\"%s\",\"code\":\"%s\","
        "\"address\":\"%s\",\"city\":\"%s\",\"state\":\"%s\",\"country\":\"%s\","
        "\"postal_code\":\"%s\",\"contact_name\":\"%s\",\"contact_phone\":\"%s\","
        "\"contact_email\":\"%s\",\"campus_type\":\"%s\",\"timezone\":\"%s\","
        "\"exam_capacity\":%s,\"device_capacity\":%s,\"status\":\"%s\","
        "\"approval_status\":\"%s\",\"created_at\":%s,\"updated_at\":%s,"
        "\"approved_by\":\"%s\",\"approved_at\":%s,"
        "\"deployment_status\":\"%s\",\"last_deployed_at\":%s}}",
        PQgetvalue(res, 0, 0) ? PQgetvalue(res, 0, 0) : "",
        PQgetvalue(res, 0, 1) ? PQgetvalue(res, 0, 1) : "",
        PQgetvalue(res, 0, 2) ? PQgetvalue(res, 0, 2) : "",
        PQgetvalue(res, 0, 3) ? PQgetvalue(res, 0, 3) : "",
        PQgetvalue(res, 0, 4) ? PQgetvalue(res, 0, 4) : "",
        PQgetvalue(res, 0, 5) ? PQgetvalue(res, 0, 5) : "",
        PQgetvalue(res, 0, 6) ? PQgetvalue(res, 0, 6) : "",
        PQgetvalue(res, 0, 7) ? PQgetvalue(res, 0, 7) : "",
        PQgetvalue(res, 0, 8) ? PQgetvalue(res, 0, 8) : "",
        PQgetvalue(res, 0, 9) ? PQgetvalue(res, 0, 9) : "",
        PQgetvalue(res, 0, 10) ? PQgetvalue(res, 0, 10) : "",
        PQgetvalue(res, 0, 11) ? PQgetvalue(res, 0, 11) : "",
        PQgetvalue(res, 0, 12) ? PQgetvalue(res, 0, 12) : "",
        PQgetvalue(res, 0, 13) ? PQgetvalue(res, 0, 13) : "",
        PQgetvalue(res, 0, 14) ? PQgetvalue(res, 0, 14) : "",
        PQgetvalue(res, 0, 15) ? PQgetvalue(res, 0, 15) : "",
        PQgetvalue(res, 0, 16) ? PQgetvalue(res, 0, 16) : "",
        PQgetvalue(res, 0, 17) ? PQgetvalue(res, 0, 17) : "",
        PQgetvalue(res, 0, 18) ? PQgetvalue(res, 0, 18) : "0",
        PQgetvalue(res, 0, 19) ? PQgetvalue(res, 0, 19) : "0",
        PQgetvalue(res, 0, 20) ? PQgetvalue(res, 0, 20) : "",
        PQgetvalue(res, 0, 21) ? PQgetvalue(res, 0, 21) : "");
    if (res) PQclear(res);
    db_release(conn, 0);
    camp_send_json(client_fd, 200, json, origin, extra, extra_len);
}

static void campus_submit_approval(int client_fd, const char *campus_id,
                                   const char *auth_header,
                                   const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        camp_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { campus_id };
    int l[1] = { (int)strlen(campus_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, approval_status FROM campuses WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 404, "{\"error\":\"Campus not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 1);
    const char *cur_status = PQgetvalue(res, 0, 2);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 403, "{\"error\":\"Campus scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(cur_status, "pending") != 0 && strcmp(cur_status, "rejected") != 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 400, "{\"error\":\"Campus already submitted or approved\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char ap_id[64]; gen_id(ap_id, sizeof(ap_id), "apr");
    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *ap_p[9] = { ap_id, campus_id, inst_id, "create",
                            sess.user_id, now, "pending", sess.user_id, now };
    int ap_l[9];
    for (int i = 0; i < 9; i++) ap_l[i] = (int)strlen(ap_p[i]);
    PGresult *apr = db_simple(conn,
        "INSERT INTO campus_approvals (id, campus_id, institution_id, action, "
         "requested_by, requested_at, status, decided_by, decided_at) "
         "VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7),$8,$9,to_timestamp($9))",
        9, ap_p, ap_l);
    int ok = apr && PQresultStatus(apr) == PGRES_COMMAND_OK;
    if (apr) PQclear(apr);

    const char *up_p[3] = { "pending", now, campus_id };
    int up_l[3] = { 7, (int)strlen(now), (int)strlen(campus_id) };
    PGresult *up = db_simple(conn,
        "UPDATE campuses SET approval_status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    if (up) PQclear(up);

    char och_id[64]; gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, campus_id, NULL, sess.user_id,
                              "campus_submit", "campuses", campus_id,
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
        camp_send_json(client_fd, 503, "{\"error\":\"Approval submission failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"submitted\",\"campus_id\":\"%s\"}", campus_id);
    camp_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "CAMPUS_SUBMIT_APPROVAL", campus_id);
}

static void campus_activate(int client_fd, const char *campus_id,
                            const char *auth_header,
                            const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        camp_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { campus_id };
    int l[1] = { (int)strlen(campus_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, approval_status, status FROM campuses WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 404, "{\"error\":\"Campus not found\"}",
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
        camp_send_json(client_fd, 403, "{\"error\":\"Campus scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(appr, "approved") != 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 400, "{\"error\":\"Campus not approved yet\"}",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(cur, "active") == 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 400, "{\"error\":\"Campus already active\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *up_p[3] = { "active", now, campus_id };
    int up_l[3] = { 6, (int)strlen(now), (int)strlen(campus_id) };
    PGresult *up = db_simple(conn,
        "UPDATE campuses SET status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    int ok = up && PQresultStatus(up) == PGRES_COMMAND_OK;
    if (up) PQclear(up);

    char och_id[64]; gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, campus_id, NULL, sess.user_id,
                              "campus_activate", "campuses", campus_id,
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
        camp_send_json(client_fd, 503, "{\"error\":\"Activation failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"active\",\"campus_id\":\"%s\"}", campus_id);
    camp_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "CAMPUS_ACTIVATED", campus_id);
}

static void campus_suspend(int client_fd, const char *campus_id,
                           const char *auth_header,
                           const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        camp_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { campus_id };
    int l[1] = { (int)strlen(campus_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, status FROM campuses WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 404, "{\"error\":\"Campus not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 1);
    const char *cur = PQgetvalue(res, 0, 2);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 403, "{\"error\":\"Campus scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(cur, "suspended") == 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 400, "{\"error\":\"Campus already suspended\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *up_p[3] = { "suspended", now, campus_id };
    int up_l[3] = { 9, (int)strlen(now), (int)strlen(campus_id) };
    PGresult *up = db_simple(conn,
        "UPDATE campuses SET status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    int ok = up && PQresultStatus(up) == PGRES_COMMAND_OK;
    if (up) PQclear(up);

    char och_id[64]; gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, campus_id, NULL, sess.user_id,
                              "campus_suspend", "campuses", campus_id,
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
        camp_send_json(client_fd, 503, "{\"error\":\"Suspension failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"suspended\",\"campus_id\":\"%s\"}", campus_id);
    camp_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "CAMPUS_SUSPENDED", campus_id);
}

static void campus_close(int client_fd, const char *campus_id,
                         const char *auth_header,
                         const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        camp_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { campus_id };
    int l[1] = { (int)strlen(campus_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id, status FROM campuses WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 404, "{\"error\":\"Campus not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 1);
    const char *cur = PQgetvalue(res, 0, 2);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 403, "{\"error\":\"Campus scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(cur, "closed") == 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 400, "{\"error\":\"Campus already closed\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *up_p[3] = { "closed", now, campus_id };
    int up_l[3] = { 6, (int)strlen(now), (int)strlen(campus_id) };
    PGresult *up = db_simple(conn,
        "UPDATE campuses SET status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    int ok = up && PQresultStatus(up) == PGRES_COMMAND_OK;
    if (up) PQclear(up);

    char och_id[64]; gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, campus_id, NULL, sess.user_id,
                              "campus_close", "campuses", campus_id,
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
        camp_send_json(client_fd, 503, "{\"error\":\"Close failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"closed\",\"campus_id\":\"%s\"}", campus_id);
    camp_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "CAMPUS_CLOSED", campus_id);
}

static void campus_approvals_list(int client_fd, const char *auth_header,
                                  const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_READ, &sess)) {
        camp_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    PGresult *res;
    if (sess.role == ROLE_PLATFORM_OWNER) {
        res = db_simple(conn,
            "SELECT ca.id, ca.campus_id, ca.institution_id, ca.action, "
                    "ca.requested_by, ca.requested_at, ca.status, "
                    "u.username as requester_name, c.name as campus_name "
            "FROM campus_approvals ca "
            "LEFT JOIN users u ON u.id = ca.requested_by "
            "LEFT JOIN campuses c ON c.id = ca.campus_id "
            "WHERE ca.status = 'pending' ORDER BY ca.requested_at ASC",
            0, NULL, NULL);
    } else {
        const char *pvals[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };
        res = db_simple(conn,
            "SELECT ca.id, ca.campus_id, ca.institution_id, ca.action, "
                    "ca.requested_by, ca.requested_at, ca.status, "
                    "u.username as requester_name, c.name as campus_name "
            "FROM campus_approvals ca "
            "LEFT JOIN users u ON u.id = ca.requested_by "
            "LEFT JOIN campuses c ON c.id = ca.campus_id "
            "WHERE ca.institution_id = $1 AND ca.status = 'pending' "
            "ORDER BY ca.requested_at ASC",
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
                "{\"id\":\"%s\",\"campus_id\":\"%s\",\"institution_id\":\"%s\","
                "\"action\":\"%s\",\"requested_by\":\"%s\",\"requested_at\":%s,"
                "\"status\":\"%s\",\"requester_name\":\"%s\",\"campus_name\":\"%s\"}",
                PQgetvalue(res, i, 0) ? PQgetvalue(res, i, 0) : "",
                PQgetvalue(res, i, 1) ? PQgetvalue(res, i, 1) : "",
                PQgetvalue(res, i, 2) ? PQgetvalue(res, i, 2) : "",
                PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "",
                PQgetvalue(res, i, 4) ? PQgetvalue(res, i, 4) : "",
                PQgetvalue(res, i, 5) ? PQgetvalue(res, i, 5) : "0",
                PQgetvalue(res, i, 6) ? PQgetvalue(res, i, 6) : "",
                PQgetvalue(res, i, 7) ? PQgetvalue(res, i, 7) : "",
                PQgetvalue(res, i, 8) ? PQgetvalue(res, i, 8) : "");
        }
    }
    if (res) PQclear(res);
    snprintf(json + pos, sizeof(json) - pos, "]}");
    db_release(conn, 0);
    camp_send_json(client_fd, 200, json, origin, extra, extra_len);
}

static void campus_approval_decide(int client_fd, const char *approval_id,
                                   const char *body,
                                   const char *auth_header,
                                   const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        camp_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { approval_id };
    int l[1] = { (int)strlen(approval_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, campus_id, institution_id, action, requested_by, status "
        "FROM campus_approvals WHERE id = $1 AND status = 'pending'",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 404, "{\"error\":\"Approval not found or already decided\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *campus_id = PQgetvalue(res, 0, 1);
    const char *inst_id = PQgetvalue(res, 0, 2);
    const char *action = PQgetvalue(res, 0, 3);
    const char *req_by = PQgetvalue(res, 0, 4);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 403, "{\"error\":\"Approval scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));

    const char *ap_p[4] = { decision, sess.user_id, now, approval_id };
    int ap_l[4] = { (int)strlen(decision), (int)strlen(sess.user_id),
                    (int)strlen(now), (int)strlen(approval_id) };
    PGresult *apr = db_simple(conn,
        "UPDATE campus_approvals SET status = $1, decided_by = $2, "
         "decided_at = to_timestamp($3), decision_reason = $4 WHERE id = $4",
        4, ap_p, ap_l);
    int ok = apr && PQresultStatus(apr) == PGRES_COMMAND_OK;
    if (apr) PQclear(apr);

    const char *new_status = strcmp(decision, "approved") == 0 ? "approved" : "rejected";
    const char *up_p[3] = { new_status, now, campus_id };
    int up_l[3] = { (int)strlen(new_status), (int)strlen(now), (int)strlen(campus_id) };
    PGresult *up = db_simple(conn,
        "UPDATE campuses SET approval_status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    if (up) PQclear(up);

    char och_id[64]; gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, campus_id, NULL, sess.user_id,
                              "campus_approval_decide", "campuses", campus_id,
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
        camp_send_json(client_fd, 503, "{\"error\":\"Decision recording failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"%s\",\"campus_id\":\"%s\"}",
             decision, campus_id);
    camp_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "CAMPUS_APPROVAL_DECIDED", campus_id);
}

static void campus_user_assignments_list(int client_fd, const char *auth_header,
                                         const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_READ, &sess)) {
        camp_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    PGresult *res;
    if (sess.role == ROLE_PLATFORM_OWNER) {
        res = db_simple(conn,
            "SELECT cua.id, cua.campus_id, cua.institution_id, cua.user_id, "
                    "cua.role, cua.status, cua.assigned_by, cua.assigned_at, "
                    "cua.expires_at, cua.reason, u.username, u.name, c.name as campus_name "
            "FROM campus_user_assignments cua "
            "LEFT JOIN users u ON u.id = cua.user_id "
            "LEFT JOIN campuses c ON c.id = cua.campus_id "
            "ORDER BY cua.assigned_at DESC",
            0, NULL, NULL);
    } else {
        const char *pvals[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };
        res = db_simple(conn,
            "SELECT cua.id, cua.campus_id, cua.institution_id, cua.user_id, "
                    "cua.role, cua.status, cua.assigned_by, cua.assigned_at, "
                    "cua.expires_at, cua.reason, u.username, u.name, c.name as campus_name "
            "FROM campus_user_assignments cua "
            "LEFT JOIN users u ON u.id = cua.user_id "
            "LEFT JOIN campuses c ON c.id = cua.campus_id "
            "WHERE cua.institution_id = $1 ORDER BY cua.assigned_at DESC",
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
                "{\"id\":\"%s\",\"campus_id\":\"%s\",\"institution_id\":\"%s\","
                "\"user_id\":\"%s\",\"role\":\"%s\",\"status\":\"%s\","
                "\"assigned_by\":\"%s\",\"assigned_at\":%s,\"expires_at\":%s,"
                "\"reason\":\"%s\",\"username\":\"%s\",\"user_name\":\"%s\","
                "\"campus_name\":\"%s\"}",
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
    camp_send_json(client_fd, 200, json, origin, extra, extra_len);
}

static void campus_user_assign(int client_fd, const char *body,
                               const char *auth_header,
                               const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        camp_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    char campus_id[64] = {0}, user_id[64] = {0}, role[40] = {0};
    ctrl_json_string(body, "campus_id", campus_id, sizeof(campus_id));
    ctrl_json_string(body, "user_id", user_id, sizeof(user_id));
    ctrl_json_string(body, "role", role, sizeof(role));
    if (!campus_id[0] || !user_id[0] || !role[0]) {
        camp_send_json(client_fd, 400, "{\"error\":\"campus_id, user_id and role required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { campus_id };
    int l[1] = { (int)strlen(campus_id) };
    PGresult *res = db_simple(conn,
        "SELECT id, tenant_id FROM campuses WHERE id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 404, "{\"error\":\"Campus not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 1);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 403, "{\"error\":\"Campus scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char id[64]; gen_id(id, sizeof(id), "cua");
    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));

    const char *ap_p[10] = { id, campus_id, inst_id, user_id, role,
                             "active", sess.user_id, now, NULL, NULL };
    int ap_l[10];
    for (int i = 0; i < 9; i++) ap_l[i] = (int)strlen(ap_p[i]);
    ap_l[9] = 0;

    PGresult *ins = db_simple(conn,
        "INSERT INTO campus_user_assignments (id, campus_id, institution_id, user_id, "
         "role, status, assigned_by, assigned_at, expires_at, reason) "
         "VALUES ($1,$2,$3,$4,$5,$6,$7,to_timestamp($8),$9,$10)",
        10, ap_p, ap_l);
    int ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
    if (ins) PQclear(ins);

    char och_id[64]; gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, campus_id, NULL, sess.user_id,
                              "campus_user_assign", "campus_user_assignments", id,
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
        camp_send_json(client_fd, 503, "{\"error\":\"Assignment failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"assigned\",\"assignment_id\":\"%s\"}", id);
    camp_send_json(client_fd, 201, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "CAMPUS_USER_ASSIGNED", user_id);
}

static void campus_user_revoke(int client_fd, const char *assign_id,
                               const char *auth_header,
                               const char *origin, char *extra, size_t extra_len) {
    auth_session_t sess;
    if (!campus_authz(auth_header, AUTH_PERM_LOCATION_ADMIN, &sess)) {
        camp_send_json(client_fd, 403, "{\"error\":\"Location admin permission required\"}",
                       origin, extra, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        camp_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                       origin, extra, extra_len);
        return;
    }

    const char *p[1] = { assign_id };
    int l[1] = { (int)strlen(assign_id) };
    PGresult *res = db_simple(conn,
        "SELECT cua.id, cua.campus_id, cua.institution_id, cua.user_id "
        "FROM campus_user_assignments cua WHERE cua.id = $1",
        1, p, l);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        if (res) PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 404, "{\"error\":\"Assignment not found\"}",
                       origin, extra, extra_len);
        return;
    }
    const char *inst_id = PQgetvalue(res, 0, 2);
    const char *user_id = PQgetvalue(res, 0, 3);
    const char *campus_id = PQgetvalue(res, 0, 1);
    if (sess.role != ROLE_PLATFORM_OWNER &&
        strcmp(sess.institution_id, inst_id) != 0) {
        PQclear(res);
        db_release(conn, 0);
        camp_send_json(client_fd, 403, "{\"error\":\"Assignment scope denied\"}",
                       origin, extra, extra_len);
        return;
    }
    PQclear(res);

    char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));
    const char *up_p[3] = { "revoked", now, assign_id };
    int up_l[3] = { 8, (int)strlen(now), (int)strlen(assign_id) };
    PGresult *up = db_simple(conn,
        "UPDATE campus_user_assignments SET status = $1, updated_at = to_timestamp($2) WHERE id = $3",
        3, up_p, up_l);
    int ok = up && PQresultStatus(up) == PGRES_COMMAND_OK;
    if (up) PQclear(up);

    char och_id[64]; gen_id(och_id, sizeof(och_id), "och");
    const char *och_p[12] = { och_id, inst_id, campus_id, NULL, sess.user_id,
                              "campus_user_revoke", "campus_user_assignments", assign_id,
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
        camp_send_json(client_fd, 503, "{\"error\":\"Revocation failed\"}",
                       origin, extra, extra_len);
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"status\":\"revoked\",\"assignment_id\":\"%s\"}", assign_id);
    camp_send_json(client_fd, 200, resp, origin, extra, extra_len);
    audit_log(sess.user_id, "CAMPUS_USER_REVOKED", user_id);
}

void campus_handle(int client_fd, const char *method, const char *path,
                   const char *body, const char *auth_header,
                   const char *origin, char *extra_headers, size_t extra_len) {
    char sub_id[128] = {0};
    char action[64] = {0};

    if (strncmp(path, "/api/v1/admin/campuses/", 23) == 0) {
        const char *rest = path + 23;
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

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/campuses") == 0) {
        campus_list(client_fd, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/campuses") == 0) {
        campus_create(client_fd, body, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (sub_id[0]) {
        if (strcmp(method, "GET") == 0 && action[0] == '\0') {
            campus_get(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(action, "submit-for-approval") == 0) {
            campus_submit_approval(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(action, "activate") == 0) {
            campus_activate(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(action, "suspend") == 0) {
            campus_suspend(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(method, "POST") == 0 && strcmp(action, "close") == 0) {
            campus_close(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
            return;
        }
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/campus-approvals") == 0) {
        campus_approvals_list(client_fd, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 &&
        strncmp(path, "/api/v1/admin/campus-approvals/", 33) == 0) {
        const char *rest = path + 33;
        const char *slash = strchr(rest, '/');
        if (slash && strcmp(slash, "/decide") == 0) {
            char ap_id[128] = {0};
            size_t id_len = (size_t)(slash - rest);
            if (id_len > 0 && id_len < sizeof(ap_id)) {
                memcpy(ap_id, rest, id_len);
                ap_id[id_len] = '\0';
            }
            campus_approval_decide(client_fd, ap_id, body, auth_header, origin, extra_headers, extra_len);
            return;
        }
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/campus-user-assignments") == 0) {
        campus_user_assignments_list(client_fd, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/campus-user-assignments") == 0) {
        campus_user_assign(client_fd, body, auth_header, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 &&
        strncmp(path, "/api/v1/admin/campus-user-assignments/", 40) == 0) {
        const char *rest = path + 40;
        size_t id_len = strlen(rest);
        if (id_len > 0 && id_len < sizeof(sub_id)) {
            memcpy(sub_id, rest, id_len);
            sub_id[id_len] = '\0';
        }
        campus_user_revoke(client_fd, sub_id, auth_header, origin, extra_headers, extra_len);
        return;
    }

    camp_send_json(client_fd, 404, "{\"error\":\"Campus route not found\"}",
                   origin, extra_headers, extra_len);
}
