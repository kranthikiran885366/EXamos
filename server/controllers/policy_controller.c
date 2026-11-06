/*
 * policy_controller.c — Exam policies.
 * Mirrors frontend modules/policies/service.js.
 */

#include "policy_controller.h"
#include "../db/db.h"
#include "../security/security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void pol_send_json(int fd, int code, const char *body,
                          const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

void policy_handle(int client_fd, const char *method, const char *path,
                   const char *body, const char *auth_header,
                   const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
        pol_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                      origin, extra_headers, extra_len);
        return;
    }

    /* Policy catalog: provisioned browser policy names */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/policies/catalog") == 0) {
        pol_send_json(client_fd, 200,
            "{\"policies\":["
            "{\"name\":\"secure-exam\",\"config\":{\"requireTpm\":true,\"kioskLockdown\":true,\"allowUsb\":false,\"onViolation\":\"Warn candidate & log\",\"origins\":[\"https://exam.examos.example\"]}},"
            "{\"name\":\"standard-exam\",\"config\":{\"requireTpm\":false,\"kioskLockdown\":false,\"allowUsb\":true,\"onViolation\":\"Warn candidate & log\",\"origins\":[\"https://exam.examos.example\"]}}"
            "]}",
            origin, extra_headers, extra_len);
        return;
    }

    /* Policy list: GET /api/v1/admin/policies?exam_id= */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/policies") == 0) {
        PGconn *conn = db_acquire();
        PGresult *res = PQexec(conn,
            "SELECT id, tenant_id, name, version, status, created_at FROM policies "
            "ORDER BY created_at DESC");
        char json[131072] = {0};
        size_t pos = 0;
        pos += snprintf(json + pos, sizeof(json) - pos, "{\"policies\":[");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            int n = PQntuples(res);
            for (int i = 0; i < n; i++) {
                if (i > 0) pos += snprintf(json + pos, sizeof(json) - pos, ",");
                pos += snprintf(json + pos, sizeof(json) - pos,
                    "{\"id\":\"%s\",\"tenant_id\":\"%s\",\"name\":\"%s\","
                    "\"version\":%s,\"status\":\"%s\",\"created_at\":%s}",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
                    PQgetvalue(res, i, 2) ? PQgetvalue(res, i, 2) : "",
                    PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "1",
                    PQgetvalue(res, i, 4) ? PQgetvalue(res, i, 4) : "draft",
                    PQgetvalue(res, i, 5) ? PQgetvalue(res, i, 5) : "0");
            }
        }
        if (res) PQclear(res);
        snprintf(json + pos, sizeof(json) - pos, "]}");
        db_release(conn, 0);
        pol_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        return;
    }

    pol_send_json(client_fd, 404, "{\"error\":\"Not found\"}",
                  origin, extra_headers, extra_len);
}
