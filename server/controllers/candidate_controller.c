/*
 * candidate_controller.c — Candidate roster management.
 * Mirrors frontend modules/candidates/service.js (roster parts).
 */

#include "candidate_controller.h"
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

static void cand_send_json(int fd, int code, const char *body,
                           const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

void candidate_handle(int client_fd, const char *method, const char *path,
                      const char *body, const char *auth_header,
                      const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
        cand_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                       origin, extra_headers, extra_len);
        return;
    }

    /* Roster list: GET /api/v1/admin/roster?exam_id= */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/roster") == 0) {
        PGconn *conn = db_acquire();
        PGresult *res = PQexec(conn,
            "SELECT id, tenant_id, roll_no, name, email, exam_id, seat, "
                    "identity, status FROM candidates ORDER BY id");
        char json[131072] = {0};
        size_t pos = 0;
        pos += snprintf(json + pos, sizeof(json) - pos, "{\"candidates\":[");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            int n = PQntuples(res);
            for (int i = 0; i < n; i++) {
                if (i > 0) pos += snprintf(json + pos, sizeof(json) - pos, ",");
                pos += snprintf(json + pos, sizeof(json) - pos,
                    "{\"id\":\"%s\",\"tenant_id\":\"%s\",\"roll_no\":\"%s\","
                    "\"name\":\"%s\",\"email\":\"%s\",\"exam_id\":\"%s\","
                    "\"seat\":\"%s\",\"identity\":\"%s\",\"status\":\"%s\"}",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1),
                    PQgetvalue(res, i, 2) ? PQgetvalue(res, i, 2) : "",
                    PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "",
                    PQgetvalue(res, i, 4) ? PQgetvalue(res, i, 4) : "",
                    PQgetvalue(res, i, 5) ? PQgetvalue(res, i, 5) : "",
                    PQgetvalue(res, i, 6) ? PQgetvalue(res, i, 6) : "",
                    PQgetvalue(res, i, 7) ? PQgetvalue(res, i, 7) : "pending",
                    PQgetvalue(res, i, 8) ? PQgetvalue(res, i, 8) : "registered");
            }
        }
        if (res) PQclear(res);
        snprintf(json + pos, sizeof(json) - pos, "]}");
        db_release(conn, 0);
        cand_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        return;
    }

    /* Add roster entry: POST /api/v1/platform/exams/:id/roster */
    if (strcmp(method, "POST") == 0 &&
        strncmp(path, "/api/v1/platform/exams/", 23) == 0 &&
        strstr(path, "/roster")) {
        char cid[64] = {0}, name[128] = {0}, email[120] = {0};
        char room[64] = {0}, seat[16] = {0}, device[64] = {0}, pin[64] = {0};
        int extra_time = 0;
        ctrl_json_string(body, "candidate_id", cid, sizeof(cid));
        ctrl_json_string(body, "full_name", name, sizeof(name));
        ctrl_json_string(body, "email", email, sizeof(email));
        ctrl_json_string(body, "room_id", room, sizeof(room));
        ctrl_json_string(body, "assigned_seat", seat, sizeof(seat));
        ctrl_json_string(body, "assigned_device_id", device, sizeof(device));
        ctrl_json_string(body, "pin", pin, sizeof(pin));
        ctrl_json_int(body, "accommodation_extra_time_mins", &extra_time);

        if (!cid[0] || !name[0] || !email[0] || !pin[0]) {
            cand_send_json(client_fd, 400,
                "{\"error\":\"candidate_id, full_name, email and pin required\"}",
                origin, extra_headers, extra_len);
            return;
        }

        PGconn *conn = db_acquire();
        char id[64]; snprintf(id, sizeof(id), "cnd_%ld", (long)time(NULL));
        char now[32]; snprintf(now, sizeof(now), "%ld", (long)time(NULL));

        /* Hash PIN with PBKDF2 */
        char pin_hash[256] = {0};
        security_pbkdf2_hash(pin, cid, pin_hash, sizeof(pin_hash));

        char extra_str[16];
        snprintf(extra_str, sizeof(extra_str), "%d", extra_time);

        const char *p[13] = { id, cid, name, email, room, seat, device,
                              pin_hash, extra_str, "ELIGIBLE", now, sess.user_id,
                              sess.institution_id };
        int lens[13];
        for (int i = 0; i < 13; i++) lens[i] = p[i] ? (int)strlen(p[i]) : 0;

        PGresult *r = db_simple(conn,
            "INSERT INTO candidates (id, tenant_id, roll_no, name, email, exam_id, "
             "center_id, seat, pin_hash, status, created_at, updated_at, "
             "identity, accommodation_extra_time_mins) "
             "VALUES ($1,$13,$1,$2,$3,$10,$11,$4,$7,'registered',to_timestamp($9),to_timestamp($9),'pending',$8)",
            13, p, lens);
        int ok = r && PQresultStatus(r) == PGRES_COMMAND_OK;
        if (r) PQclear(r);

        if (!ok) {
            cand_send_json(client_fd, 409,
                "{\"error\":\"Roster entry creation failed\"}",
                origin, extra_headers, extra_len);
            db_release(conn, 0);
            return;
        }
        char resp[256];
        snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"candidate_id\":\"%s\"}", id);
        cand_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        audit_log(sess.user_id, "CANDIDATE_ADDED", name);
        OPENSSL_cleanse(pin, sizeof(pin));
        OPENSSL_cleanse(pin_hash, sizeof(pin_hash));
        db_release(conn, 0);
        return;
    }

    cand_send_json(client_fd, 404, "{\"error\":\"Not found\"}",
                   origin, extra_headers, extra_len);
}
