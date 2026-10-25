/*
 * device_controller.c — Device fleet management + heartbeat.
 * Mirrors frontend modules/fleet/service.js and modules/devices/service.js.
 */

#include "device_controller.h"
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

static void dev_send_json(int fd, int code, const char *body,
                          const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

void device_handle(int client_fd, const char *method, const char *path,
                   const char *body, const char *auth_header,
                   const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
        dev_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                      origin, extra_headers, extra_len);
        return;
    }

    /* Fleet list */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/fleet") == 0) {
        PGconn *conn = db_acquire();
        const char *pvals[1] = { sess.institution_id };
        int lens[1] = { (int)strlen(sess.institution_id) };
        int is_owner = (sess.role == ROLE_PLATFORM_OWNER);
        PGresult *res;
        if (is_owner) {
            res = PQexec(conn,
                "SELECT id, tenant_id, hostname, serial, status, trust, "
                        "isolated, tampered, last_seen, profile FROM devices "
                "ORDER BY hostname");
        } else {
            res = db_simple(conn,
                "SELECT id, tenant_id, hostname, serial, status, trust, "
                        "isolated, tampered, last_seen, profile FROM devices "
                "WHERE tenant_id = $1 ORDER BY hostname",
                1, pvals, lens);
        }
        char json[262144] = {0};
        size_t pos = 0;
        pos += snprintf(json + pos, sizeof(json) - pos, "{\"devices\":[");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            int n = PQntuples(res);
            for (int i = 0; i < n; i++) {
                if (i > 0) pos += snprintf(json + pos, sizeof(json) - pos, ",");
                pos += snprintf(json + pos, sizeof(json) - pos,
                    "{\"id\":\"%s\",\"tenant_id\":\"%s\",\"hostname\":\"%s\","
                    "\"serial\":\"%s\",\"status\":\"%s\",\"trust\":\"%s\","
                    "\"isolated\":%s,\"tampered\":%s,\"last_seen\":%s,\"profile\":\"%s\"}",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
                    PQgetvalue(res, i, 2) ? PQgetvalue(res, i, 2) : "",
                    PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "",
                    PQgetvalue(res, i, 4) ? PQgetvalue(res, i, 4) : "enrolled",
                    PQgetvalue(res, i, 5) ? PQgetvalue(res, i, 5) : "unknown",
                    PQgetvalue(res, i, 6) && strcmp(PQgetvalue(res, i, 6), "1") == 0 ? "true" : "false",
                    PQgetvalue(res, i, 7) && strcmp(PQgetvalue(res, i, 7), "1") == 0 ? "true" : "false",
                    PQgetvalue(res, i, 8) ? PQgetvalue(res, i, 8) : "0",
                    PQgetvalue(res, i, 9) ? PQgetvalue(res, i, 9) : "standard-uefi");
            }
        }
        if (res) PQclear(res);
        snprintf(json + pos, sizeof(json) - pos, "]}");
        db_release(conn, 0);
        dev_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        return;
    }

    /* Compliance */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/fleet/compliance") == 0) {
        dev_send_json(client_fd, 200,
            "{\"compliant\":0,\"non_compliant\":0,\"isolated\":0,\"offline\":0}",
            origin, extra_headers, extra_len);
        return;
    }

    /* Bulk device action */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/fleet/bulk") == 0) {
        if (sess.role != ROLE_PLATFORM_OWNER && sess.role != ROLE_SECURITY_ADMIN &&
            sess.role != ROLE_TECH_OPERATOR) {
            dev_send_json(client_fd, 403,
                "{\"error\":\"Security admin permission required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char action[64] = {0};
        ctrl_json_string(body, "action_type", action, sizeof(action));
        if (!action[0]) {
            dev_send_json(client_fd, 400, "{\"error\":\"action_type required\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        dev_send_json(client_fd, 200, "{\"status\":\"ok\",\"action\":\"...\"}",
                      origin, extra_headers, extra_len);
        audit_log(sess.user_id, "FLEET_BULK_ACTION", action);
        return;
    }

    dev_send_json(client_fd, 404, "{\"error\":\"Not found\"}",
                  origin, extra_headers, extra_len);
}
