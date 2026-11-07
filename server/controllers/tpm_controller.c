/*
 * tpm_controller.c — TPM attestation endpoints.
 * Mirrors frontend modules/tpm/service.js.
 */

#include "tpm_controller.h"
#include "../include/attestation_service.h"
#include "../security/security.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void tpm_send_json(int fd, int code, const char *body,
                          const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static int query_id(const char *path, const char *name, char *out, size_t out_len) {
    if (!path || !name || !out || out_len == 0) return -1;
    out[0] = '\0';
    const char *query = strchr(path, '?');
    if (!query) return -1;
    size_t name_len = strlen(name);
    for (const char *item = query + 1; *item;) {
        const char *end = strchr(item, '&');
        size_t item_len = end ? (size_t)(end - item) : strlen(item);
        if (item_len > name_len && memcmp(item, name, name_len) == 0 &&
            item[name_len] == '=') {
            size_t value_len = item_len - name_len - 1;
            if (value_len == 0 || value_len >= out_len) return -1;
            for (size_t i = 0; i < value_len; ++i) {
                unsigned char c = (unsigned char)item[name_len + 1 + i];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                      c == '.' || c == ':')) return -1;
                out[i] = (char)c;
            }
            out[value_len] = '\0';
            return 0;
        }
        if (!end) break;
        item = end + 1;
    }
    return -1;
}

/* Agent token check: EXAMOS_AGENT_API_TOKEN */
static int agent_authorized(const char *auth_header) {
    const char *env = getenv("EXAMOS_AGENT_API_TOKEN");
    if (!env || !env[0]) return 0;
    char token[128] = {0};
    if (!ctrl_extract_bearer(auth_header, token, sizeof(token))) return 0;
    int authorized = security_safe_equal(token, env);
    OPENSSL_cleanse(token, sizeof(token));
    return authorized;
}

void tpm_handle(int client_fd, const char *method, const char *path,
                const char *body, const char *auth_header,
                const char *origin, char *extra_headers, size_t extra_len) {
    int status_route = strcmp(method, "GET") == 0 &&
        strncmp(path, "/api/v1/attestation/status", 26) == 0 &&
        (path[26] == '\0' || path[26] == '?');
    int pending_exam_attestation = strcmp(method, "POST") == 0 &&
        strcmp(path, "/api/v1/agent/exam-attestation/pending") == 0;
    auth_session_t admin_session;
    if (status_route) {
        if (ctrl_authorize(auth_header, AUTH_PERM_READ, &admin_session) == 0)
            goto authorized;
    } else if (agent_authorized(auth_header)) {
        goto authorized;
    }
    if (!status_route) {
        tpm_send_json(client_fd, 401, "{\"error\":\"Valid agent token required\"}",
                      origin, extra_headers, extra_len);
    } else {
        tpm_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                      origin, extra_headers, extra_len);
    }
    return;

authorized:
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/attestation/nonce") == 0) {
        char dev_id[64] = {0}, sess_id[64] = {0}, rel_id[64] = {0};
        ctrl_json_string(body, "device_id", dev_id, sizeof(dev_id));
        ctrl_json_string(body, "session_id", sess_id, sizeof(sess_id));
        ctrl_json_string(body, "release_id", rel_id, sizeof(rel_id));

        if (!dev_id[0] || !sess_id[0] || !rel_id[0]) {
            tpm_send_json(client_fd, 400,
                "{\"error\":\"device_id, session_id, and release_id required\"}",
                origin, extra_headers, extra_len);
            return;
        }

        char nonce[128] = {0}, att_id[64] = {0}, error_code[64] = {0};
        if (attestation_create_challenge(dev_id, sess_id, rel_id,
                nonce, att_id, error_code) != 0) {
            OPENSSL_cleanse(nonce, sizeof(nonce));
            tpm_send_json(client_fd, 503,
                "{\"status\":\"REJECTED\",\"error_code\":\"ATTESTATION_CHALLENGE_FAILED\","
                "\"error\":\"A trusted device and approved release are required\"}",
                origin, extra_headers, extra_len);
            return;
        }

        char resp[640];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"CHALLENGE_ISSUED\",\"nonce\":\"%s\",\"session_id\":\"%s\",\"attestation_id\":\"%s\"}",
            nonce, sess_id, att_id);
        OPENSSL_cleanse(nonce, sizeof(nonce));
        tpm_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/attestation/verify") == 0) {
        char reason[64] = {0}, exam_key[EXAM_KEY_LEN + 1] = {0};
        if (attestation_verify_evidence(body, reason, exam_key) == 0) {
            OPENSSL_cleanse(exam_key, sizeof(exam_key));
            tpm_send_json(client_fd, 200,
                "{\"status\":\"TRUSTED\",\"verified\":true,\"key_release_required\":true}",
                origin, extra_headers, extra_len);
        } else {
            OPENSSL_cleanse(exam_key, sizeof(exam_key));
            char response[256];
            snprintf(response, sizeof(response),
                "{\"status\":\"FAILED\",\"verified\":false,\"error_code\":\"%s\"}",
                reason[0] ? reason : "ATTESTATION_VERIFICATION_FAILED");
            tpm_send_json(client_fd, 403, response, origin, extra_headers, extra_len);
        }
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/attestation/re-attest") == 0) {
        char session_id[64] = {0}, device_id[64] = {0}, nonce[128] = {0};
        ctrl_json_string(body, "session_id", session_id, sizeof(session_id));
        if (!session_id[0])
            ctrl_json_string(body, "attestation_id", session_id, sizeof(session_id));
        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        if (!session_id[0] || !device_id[0]) {
            tpm_send_json(client_fd, 400,
                "{\"error\":\"session_id and device_id are required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (attestation_re_attest_challenge(session_id, device_id, nonce) != 0) {
            OPENSSL_cleanse(nonce, sizeof(nonce));
            tpm_send_json(client_fd, 403,
                "{\"status\":\"FAILED\",\"error\":\"Session is not trusted or device binding is invalid\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char response[384];
        snprintf(response, sizeof(response),
            "{\"status\":\"RE_ATTESTATION_CHALLENGE\",\"nonce\":\"%s\",\"session_id\":\"%s\"}",
            nonce, session_id);
        OPENSSL_cleanse(nonce, sizeof(nonce));
        tpm_send_json(client_fd, 200, response, origin, extra_headers, extra_len);
        return;
    }

    if (status_route) {
        char attestation_id[64] = {0}, status[32] = {0};
        if (query_id(path, "attestation_id", attestation_id,
                     sizeof(attestation_id)) != 0 &&
            query_id(path, "session_id", attestation_id,
                     sizeof(attestation_id)) != 0) {
            tpm_send_json(client_fd, 400,
                "{\"error\":\"attestation_id or session_id is required\"}",
                origin, extra_headers, extra_len);
        } else if (attestation_get_status(attestation_id, status,
                                          sizeof(status)) != 0) {
            tpm_send_json(client_fd, 404, "{\"status\":\"NOT_FOUND\"}",
                          origin, extra_headers, extra_len);
        } else {
            char response[96];
            snprintf(response, sizeof(response), "{\"status\":\"%s\"}", status);
            tpm_send_json(client_fd, 200, response, origin, extra_headers, extra_len);
        }
        return;
    }

    if (pending_exam_attestation) {
        char device_id[64] = {0};
        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        if (!device_id[0]) {
            tpm_send_json(client_fd, 400, "{\"error\":\"device_id is required\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        PGconn *conn = db_acquire();
        if (!conn) {
            tpm_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        const char *params[1] = { device_id };
        int lengths[1] = { (int)strlen(device_id) };
        PGresult *result = db_simple(conn,
            "SELECT s.id FROM exam_sessions s "
            "JOIN candidate_exam_checkins ci ON ci.exam_session_id=s.id "
            "WHERE s.device_id=$1 AND s.status IN ('pending','authorized','active',"
            "'interrupted','resuming') "
            "AND ci.status IN ('attesting','consumed') "
            "AND (ci.status='consumed' OR "
            "ci.expires_at>EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000) "
            "AND NOT EXISTS (SELECT 1 FROM examos_attestation_challenges c "
            "JOIN examos_exam_key_releases k ON k.attestation_id=c.attestation_id "
            "WHERE c.session_id=s.id AND c.device_id=s.device_id "
            "AND c.state='TRUSTED' "
            "AND c.verified_at>clock_timestamp()-interval '10 minutes' "
            "AND k.revoked_at IS NULL "
            "AND NOT EXISTS (SELECT 1 FROM examos_attestation_challenges newer "
            "WHERE newer.session_id=c.session_id AND newer.created_at>c.created_at) "
            "AND NOT EXISTS (SELECT 1 FROM examos_attestation_revocations r "
            "WHERE (r.target_type='DEVICE' AND r.target_id=c.device_id) "
            "OR (r.target_type='RELEASE' AND r.target_id=c.release_id))) "
            "ORDER BY s.created_at ASC LIMIT 1",
            1, params, lengths);
        if (!result || PQresultStatus(result) != PGRES_TUPLES_OK) {
            if (result) PQclear(result);
            db_release(conn, 1);
            tpm_send_json(client_fd, 503,
                "{\"error\":\"Could not load a pending exam attestation\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (PQntuples(result) == 0) {
            PQclear(result);
            db_release(conn, 0);
            tpm_send_json(client_fd, 200, "{\"status\":\"IDLE\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        char session_id[64], release_id[64];
        snprintf(session_id, sizeof(session_id), "%s", PQgetvalue(result, 0, 0));
        PQclear(result);
        db_release(conn, 0);
        if (attestation_get_device_release(device_id, release_id,
                                           sizeof(release_id)) != 0) {
            tpm_send_json(client_fd, 503,
                "{\"error\":\"Assigned device has no approved attestation release\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char response[320];
        snprintf(response, sizeof(response),
            "{\"status\":\"CHALLENGE\",\"session_id\":\"%s\","
            "\"release_id\":\"%s\"}",
            session_id, release_id);
        tpm_send_json(client_fd, 200, response, origin, extra_headers, extra_len);
        return;
    }

    tpm_send_json(client_fd, 404, "{\"error\":\"Not found\"}",
                  origin, extra_headers, extra_len);
}
