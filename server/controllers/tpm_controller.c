/*
 * tpm_controller.c — TPM attestation endpoints.
 * Mirrors frontend modules/tpm/service.js.
 */

#include "tpm_controller.h"
#include "../include/attestation_service.h"
#include "../include/credential_activation.h"
#include "../security/security.h"
#include "../db/db.h"
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
                "", "re_attestation", "system",
                nonce, att_id, error_code) != 0) {
            OPENSSL_cleanse(nonce, sizeof(nonce));
            int status = strcmp(error_code, "P3_CHALLENGE_STORE_UNAVAILABLE") == 0 ||
                         strcmp(error_code, "P3_REVOCATION_STORE_UNAVAILABLE") == 0
                ? 503 : 403;
            char response[256];
            snprintf(response, sizeof(response),
                "{\"status\":\"REJECTED\",\"error_code\":\"%s\","
                "\"error\":\"A tenant-bound trusted device and approved release are required\"}",
                error_code[0] ? error_code : "P3_CHALLENGE_FAILED");
            tpm_send_json(client_fd, status, response, origin, extra_headers, extra_len);
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
        if (attestation_verify_evidence(body, "re_attestation", reason, exam_key) == 0) {
            int key_release_required = exam_key[0] != '\0';
            OPENSSL_cleanse(exam_key, sizeof(exam_key));
            tpm_send_json(client_fd, 200,
                key_release_required
                    ? "{\"status\":\"TRUSTED\",\"verified\":true,\"key_release_required\":true}"
                    : "{\"status\":\"TRUSTED\",\"verified\":true,\"key_release_required\":false}",
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

    /* Phase 2: Credential Activation Endpoint */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/attestation/activate") == 0) {
        char device_id[64] = {0}, ak_name_hex[68] = {0};
        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        ctrl_json_string(body, "ak_name_hex", ak_name_hex, sizeof(ak_name_hex));

        if (!device_id[0] || !ak_name_hex[0]) {
            tpm_send_json(client_fd, 400,
                "{\"error\":\"device_id and ak_name_hex required\"}",
                origin, extra_headers, extra_len);
            return;
        }

        PGconn *conn = db_acquire();
        if (!conn) {
            tpm_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                          origin, extra_headers, extra_len);
            return;
        }

        /* Get EK public key from device_ek_certificates */
        const char *ek_params[1] = { device_id };
        int ek_lengths[1] = { (int)strlen(device_id) };
        PGresult *ek_result = db_simple(conn,
            "SELECT ek_public_key_pem FROM device_ek_certificates "
            "WHERE device_id=$1 AND trust_status='verified' LIMIT 1",
            1, ek_params, ek_lengths);

        if (!ek_result || PQresultStatus(ek_result) != PGRES_TUPLES_OK || PQntuples(ek_result) != 1) {
            if (ek_result) PQclear(ek_result);
            db_release(conn, 0);
            tpm_send_json(client_fd, 404,
                "{\"error\":\"No verified EK certificate found for device\"}",
                origin, extra_headers, extra_len);
            return;
        }

        char ek_pem[2048] = {0};
        snprintf(ek_pem, sizeof(ek_pem), "%s", PQgetvalue(ek_result, 0, 0));
        PQclear(ek_result);
        db_release(conn, 0);

        /* Generate credential activation challenge */
        char activation_id[64] = {0};
        char credential_blob_hex[4096] = {0};
        char secret_hash[65] = {0};
        char error[256] = {0};

        /* Get institution_id from device record */
        const char *inst_params[1] = { device_id };
        int inst_lengths[1] = { (int)strlen(device_id) };
        PGresult *inst_result = db_simple(conn,
            "SELECT institution_id FROM devices WHERE id=$1 LIMIT 1",
            1, inst_params, inst_lengths);

        if (!inst_result || PQresultStatus(inst_result) != PGRES_TUPLES_OK || PQntuples(inst_result) != 1) {
            if (inst_result) PQclear(inst_result);
            db_release(conn, 0);
            tpm_send_json(client_fd, 404,
                "{\"error\":\"Device not found\"}",
                origin, extra_headers, extra_len);
            return;
        }

        char institution_id[64] = {0};
        snprintf(institution_id, sizeof(institution_id), "%s", PQgetvalue(inst_result, 0, 0));
        PQclear(inst_result);
        db_release(conn, 0);

        if (credential_activation_initiate(device_id, institution_id, ak_name_hex,
                                            activation_id, credential_blob_hex,
                                            secret_hash, error) != 0) {
            OPENSSL_cleanse(secret_hash, sizeof(secret_hash));
            OPENSSL_cleanse(credential_blob_hex, sizeof(credential_blob_hex));
            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"ACTIVATION_FAILED\",\"error\":\"%s\"}",
                error[0] ? error : "Failed to initiate credential activation");
            tpm_send_json(client_fd, 503, resp, origin, extra_headers, extra_len);
            return;
        }

        char resp[5120];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"ACTIVATION_CHALLENGE\",\"activation_id\":\"%s\","
            "\"credential_blob\":\"%s\"}",
            activation_id, credential_blob_hex);
        OPENSSL_cleanse(credential_blob_hex, sizeof(credential_blob_hex));
        tpm_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/attestation/activate/complete") == 0) {
        char activation_id[64] = {0}, activation_response_hex[4096] = {0};
        ctrl_json_string(body, "activation_id", activation_id, sizeof(activation_id));
        ctrl_json_string(body, "activation_response", activation_response_hex, sizeof(activation_response_hex));

        if (!activation_id[0] || !activation_response_hex[0]) {
            tpm_send_json(client_fd, 400,
                "{\"error\":\"activation_id and activation_response required\"}",
                origin, extra_headers, extra_len);
            return;
        }

        PGconn *conn = db_acquire();
        if (!conn) {
            tpm_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                          origin, extra_headers, extra_len);
            return;
        }

        /* Get the expected secret hash from the activation record */
        const char *act_params[1] = { activation_id };
        int act_lengths[1] = { (int)strlen(activation_id) };
        PGresult *act_result = db_simple(conn,
            "SELECT device_id, credential_secret_hash FROM device_credential_activations "
            "WHERE id=$1 AND status='pending' LIMIT 1",
            1, act_params, act_lengths);

        if (!act_result || PQresultStatus(act_result) != PGRES_TUPLES_OK || PQntuples(act_result) != 1) {
            if (act_result) PQclear(act_result);
            db_release(conn, 0);
            tpm_send_json(client_fd, 404,
                "{\"error\":\"Activation record not found or already used\"}",
                origin, extra_headers, extra_len);
            return;
        }

        char device_id[64] = {0};
        char expected_secret_hash[65] = {0};
        snprintf(device_id, sizeof(device_id), "%s", PQgetvalue(act_result, 0, 0));
        snprintf(expected_secret_hash, sizeof(expected_secret_hash), "%s", PQgetvalue(act_result, 0, 1));
        PQclear(act_result);
        db_release(conn, 0);

        char error[256] = {0};
        int verify_result = credential_activation_verify(activation_id, device_id,
                                                         activation_response_hex,
                                                         expected_secret_hash, error);

        if (verify_result == 0) {
            /* Update provenance status to verified on successful activation */
            PGconn *prov_conn = db_acquire();
            if (prov_conn) {
                const char *prov_params[1] = { device_id };
                PGresult *prov_update = PQexecParams(prov_conn,
                    "UPDATE device_attestation_keys "
                    "SET provenance_status='verified', provenance_details='Credential activation completed at ' || clock_timestamp()::text "
                    "WHERE device_id=$1 AND key_name='AK' AND status='active'",
                    1, NULL, prov_params, NULL, NULL, 0);
                if (prov_update) PQclear(prov_update);
                db_release(prov_conn, 0);
            }

            tpm_send_json(client_fd, 200,
                "{\"status\":\"ACTIVATION_SUCCESS\",\"verified\":true}",
                origin, extra_headers, extra_len);
        } else {
            /* Update provenance status to failed on failed activation */
            PGconn *prov_conn = db_acquire();
            if (prov_conn) {
                const char *prov_params[2] = { device_id, error };
                int prov_lengths[2] = { (int)strlen(device_id), (int)strlen(error) };
                PGresult *prov_update = PQexecParams(prov_conn,
                    "UPDATE device_attestation_keys "
                    "SET provenance_status='failed', provenance_details=$2 "
                    "WHERE device_id=$1 AND key_name='AK' AND status='active'",
                    2, NULL, prov_params, prov_lengths, NULL, 0);
                if (prov_update) PQclear(prov_update);
                db_release(prov_conn, 0);
            }

            char response[512];
            snprintf(response, sizeof(response),
                "{\"status\":\"ACTIVATION_FAILED\",\"verified\":false,\"error\":\"%s\"}",
                error[0] ? error : "Activation verification failed");
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
