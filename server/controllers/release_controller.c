/*
 * release_controller.c — Release revocation endpoints.
 * Mirrors frontend modules/releases/service.js (revoke parts).
 */

#include "release_controller.h"
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

static void rel_send_json(int fd, int code, const char *body,
                          const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

void release_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_SECURITY_ADMIN, &sess) != 0) {
        rel_send_json(client_fd, 401, "{\"error\":\"Security admin authorization required\"}",
                      origin, extra_headers, extra_len);
        return;
    }

    /* Revoke release: POST /api/v1/admin/revoke/release {release_id} */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/revoke/release") == 0) {
        char release_id[64] = {0};
        ctrl_json_string(body, "release_id", release_id, sizeof(release_id));
        if (!release_id[0]) {
            rel_send_json(client_fd, 400,
                "{\"error\":\"release_id required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PGconn *conn = db_acquire();
        const char *p[1] = { release_id };
        int l[1] = { (int)strlen(release_id) };
        PGresult *r = db_simple(conn, "UPDATE releases SET status = 'revoked' WHERE id = $1", 1, p, l);
        int ok = r && PQresultStatus(r) == PGRES_COMMAND_OK;
        if (r) PQclear(r);
        db_release(conn, 0);
        if (ok) {
            rel_send_json(client_fd, 200, "{\"status\":\"REVOKED\"}",
                          origin, extra_headers, extra_len);
            audit_log(sess.user_id, "RELEASE_REVOKED", release_id);
        } else {
            rel_send_json(client_fd, 503,
                "{\"status\":\"UNAVAILABLE\",\"error\":\"Release revocation failed\"}",
                origin, extra_headers, extra_len);
        }
        return;
    }

    /* Revoke device: POST /api/v1/admin/revoke/device {device_id} */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/revoke/device") == 0) {
        char device_id[64] = {0};
        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        if (!device_id[0]) {
            rel_send_json(client_fd, 400,
                "{\"error\":\"device_id required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PGconn *conn = db_acquire();
        const char *p[1] = { device_id };
        int l[1] = { (int)strlen(device_id) };
        PGresult *r = db_simple(conn, "UPDATE devices SET status = 'revoked' WHERE id = $1", 1, p, l);
        int ok = r && PQresultStatus(r) == PGRES_COMMAND_OK;
        if (r) PQclear(r);
        db_release(conn, 0);
        if (ok) {
            rel_send_json(client_fd, 200, "{\"status\":\"REVOKED\"}",
                          origin, extra_headers, extra_len);
            audit_log(sess.user_id, "DEVICE_REVOKED", device_id);
        } else {
            rel_send_json(client_fd, 503,
                "{\"status\":\"UNAVAILABLE\",\"error\":\"Device revocation failed\"}",
                origin, extra_headers, extra_len);
        }
        return;
    }

    rel_send_json(client_fd, 404, "{\"error\":\"Not found\"}",
                  origin, extra_headers, extra_len);
}
