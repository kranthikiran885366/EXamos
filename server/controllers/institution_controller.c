/*
 * institution_controller.c — Institution (tenant) CRUD.
 * Mirrors frontend modules/institutions/service.js.
 */

#include "institution_controller.h"
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

/* Build a JSON array of institutions from a PGresult */
static void inst_list_json(PGresult *res, char *out, size_t out_len) {
    int n = PQntuples(res);
    size_t pos = 0;
    pos += snprintf(out + pos, out_len - pos, "{\"institutions\":[");
    for (int i = 0; i < n; i++) {
        if (i > 0) pos += snprintf(out + pos, out_len - pos, ",");
        pos += snprintf(out + pos, out_len - pos,
            "{\"id\":\"%s\",\"name\":\"%s\",\"code\":\"%s\","
            "\"status\":\"%s\",\"plan\":\"%s\",\"region\":\"%s\","
            "\"timezone\":\"%s\",\"max_centers\":%s,\"max_candidates\":%s,"
            "\"deployment_model\":\"%s\",\"created_at\":%s}",
            PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
            PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "active",
            PQgetvalue(res, i, 4) ? PQgetvalue(res, i, 4) : "pilot",
            PQgetvalue(res, i, 5) ? PQgetvalue(res, i, 5) : "",
            PQgetvalue(res, i, 6) ? PQgetvalue(res, i, 6) : "",
            PQgetvalue(res, i, 7) ? PQgetvalue(res, i, 7) : "5",
            PQgetvalue(res, i, 8) ? PQgetvalue(res, i, 8) : "500",
            PQgetvalue(res, i, 9) ? PQgetvalue(res, i, 9) : "usb-boot",
            PQgetvalue(res, i, 10) ? PQgetvalue(res, i, 10) : "0");
    }
    snprintf(out + pos, out_len - pos, "]}");
}

static void inst_send_json(int fd, int code, const char *body,
                           const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

void institution_handle(int client_fd, const char *method, const char *path,
                        const char *body, const char *auth_header,
                        const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
        inst_send_json(client_fd, 401,
            "{\"error\":\"Admin credentials required\"}",
            origin, extra_headers, extra_len);
        return;
    }

    int is_owner = (sess.role == ROLE_PLATFORM_OWNER);

    /* List */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/institutions") == 0) {
        if (!is_owner) {
            inst_send_json(client_fd, 403,
                "{\"error\":\"Platform owner authorization required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PGconn *conn = db_acquire();
        PGresult *res = PQexec(conn,
            "SELECT id, name, code, status, plan, region, timezone, "
                    "max_centers, max_candidates, deployment_model, created_at "
            "FROM tenants ORDER BY created_at DESC");
        char json[65536] = {0};
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK)
            inst_list_json(res, json, sizeof(json));
        else
            snprintf(json, sizeof(json), "{\"institutions\":[]}");
        if (res) PQclear(res);
        db_release(conn, 0);
        inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        return;
    }

    /* Create */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/institutions") == 0) {
        if (!is_owner) {
            inst_send_json(client_fd, 403,
                "{\"error\":\"Platform owner required to create institutions\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char name[128] = {0}, code[32] = {0}, email[120] = {0};
        char phone[32] = {0}, region[64] = {0}, tz[40] = {0};
        char plan[40] = {0}, model[32] = {0};
        int max_c = 5, max_cd = 500, ret = 365;
        ctrl_json_string(body, "name", name, sizeof(name));
        ctrl_json_string(body, "code", code, sizeof(code));
        ctrl_json_string(body, "contact_email", email, sizeof(email));
        ctrl_json_string(body, "contact_phone", phone, sizeof(phone));
        ctrl_json_string(body, "region", region, sizeof(region));
        ctrl_json_string(body, "timezone", tz, sizeof(tz));
        ctrl_json_string(body, "plan", plan, sizeof(plan));
        ctrl_json_string(body, "deployment_model", model, sizeof(model));
        int rc = ctrl_json_int(body, "retention_days", &ret);
        (void)rc;
        ctrl_json_int(body, "max_centers", &max_c);
        ctrl_json_int(body, "max_candidates", &max_cd);

        if (!name[0] || !code[0]) {
            inst_send_json(client_fd, 400,
                "{\"error\":\"name and code are required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (ret < 1 || ret > 36500) {
            inst_send_json(client_fd, 400,
                "{\"error\":\"retention_days must be between 1 and 36500\"}",
                origin, extra_headers, extra_len);
            return;
        }

        PGconn *conn = db_acquire();
        char id[64]; snprintf(id, sizeof(id), "ins_%ld", (long)time(NULL));
        char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));

        /* Check duplicate */
        const char *chk[2] = { name, code };
        int clen[2] = { (int)strlen(name), (int)strlen(code) };
        PGresult *dup = db_simple(conn,
            "SELECT id FROM tenants WHERE name = $1 OR code = $2",
            2, chk, clen);
        int dup_found = dup && PQresultStatus(dup) == PGRES_TUPLES_OK && PQntuples(dup) > 0;
        if (dup) PQclear(dup);

        if (dup_found) {
            inst_send_json(client_fd, 409,
                "{\"error\":\"Institution name or code already exists\"}",
                origin, extra_headers, extra_len);
            db_release(conn, 0);
            return;
        }

        char max_c_str[16], max_cd_str[16];
        snprintf(max_c_str, sizeof(max_c_str), "%d", max_c);
        snprintf(max_cd_str, sizeof(max_cd_str), "%d", max_cd);

        const char *pvals[13] = {
            id, name, code, email, phone, region, tz,
            plan[0] ? plan : "pilot", max_c_str, max_cd_str,
            model[0] ? model : "usb-boot", now, sess.user_id
        };
        int plens[13];
        for (int i = 0; i < 13; i++) plens[i] = pvals[i] ? (int)strlen(pvals[i]) : 0;

        PGresult *ins = db_simple(conn,
            "INSERT INTO tenants (id, name, code, contact_email, contact_phone, "
             "region, timezone, plan, status, max_centers, max_candidates, "
             "deployment_model, created_at, created_by) "
             "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9::integer,$10::integer,$11,$12::bigint,$13)",
            13, pvals, plens);
        int ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
        if (ins) PQclear(ins);

        if (!ok) {
            inst_send_json(client_fd, 503,
                "{\"error\":\"Failed to create institution\"}",
                origin, extra_headers, extra_len);
            db_release(conn, 0);
            return;
        }

        char resp[256];
        snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"institution_id\":\"%s\"}", id);
        inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
        audit_log(sess.user_id, "TENANT_CREATED", name);
        db_release(conn, 0);
        return;
    }

    /* Get one: /api/v1/admin/institutions/:id */
    if (strcmp(method, "GET") == 0 && strncmp(path, "/api/v1/admin/institutions/", 27) == 0) {
        const char *id = path + 27;
        if (!id[0] || strpbrk(id, "/?&#")) {
            inst_send_json(client_fd, 400,
                "{\"error\":\"Invalid institution id\"}",
                origin, extra_headers, extra_len);
            return;
        }
        /* Scope check: non-owner can only read own institution */
        if (!is_owner && strcmp(sess.institution_id, id) != 0) {
            inst_send_json(client_fd, 403,
                "{\"error\":\"Institution scope denied\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PGconn *conn = db_acquire();
        const char *pvals[1] = { id };
        int lens[1] = { (int)strlen(id) };
        PGresult *res = db_simple(conn,
            "SELECT id, name, code, status, plan, region, timezone, "
                    "max_centers, max_candidates, deployment_model, created_at "
            "FROM tenants WHERE id = $1",
            1, pvals, lens);
        char json[8192] = {0};
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
            inst_list_json(res, json, sizeof(json));
        } else {
            snprintf(json, sizeof(json), "{\"error\":\"Institution not found\"}");
        }
        if (res) PQclear(res);
        db_release(conn, 0);
        int code = (json[0] == '{' && strstr(json, "\"error\"")) ? 404 : 200;
        inst_send_json(client_fd, code, json, origin, extra_headers, extra_len);
        return;
    }

    inst_send_json(client_fd, 404,
        "{\"error\":\"Not found\"}", origin, extra_headers, extra_len);
}
