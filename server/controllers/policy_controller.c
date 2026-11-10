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
    if (ctrl_authorize(auth_header, AUTH_PERM_EXAM_READ, &sess) != 0) {
        pol_send_json(client_fd, 403, "{\"error\":\"Exam read permission required\"}",
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
        const char *params[2] = {
            sess.institution_id,
            sess.role == ROLE_PLATFORM_OWNER ? "true" : "false"
        };
        int lengths[2] = { (int)strlen(params[0]), (int)strlen(params[1]) };
        PGresult *res = db_simple(conn,
            "SELECT COALESCE(jsonb_agg(data ORDER BY updated_at DESC), '[]'::jsonb)::text "
            "FROM console_records WHERE collection='policies' "
            "AND ($2::boolean OR institution_id=$1)",
            2, params, lengths);
        if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
            const char *sqlstate = res ? PQresultErrorField(res, PG_DIAG_SQLSTATE) : NULL;
            fprintf(stderr, "[policies] list failed sqlstate=%s\n",
                    sqlstate ? sqlstate : "connection_error");
            if (res) PQclear(res);
            db_release(conn, 0);
            pol_send_json(client_fd, 500, "{\"error\":\"Policy records could not be loaded\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        char json[131072];
        int written = snprintf(json, sizeof(json), "{\"policies\":%s}", PQgetvalue(res, 0, 0));
        PQclear(res);
        db_release(conn, 0);
        if (written < 0 || (size_t)written >= sizeof(json)) {
            pol_send_json(client_fd, 500, "{\"error\":\"Policy response exceeds the supported size\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        pol_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        return;
    }

    pol_send_json(client_fd, 404, "{\"error\":\"Not found\"}",
                  origin, extra_headers, extra_len);
}
