/*
 * tpm_controller.c — TPM attestation endpoints.
 * Mirrors frontend modules/tpm/service.js.
 */

#include "tpm_controller.h"
#include "../include/attestation_service.h"
#include "../include/credential_activation.h"
#include "../include/ek_certificate.h"
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
        const char *begin_sql = "BEGIN";
        PGresult *result = PQexec(conn, begin_sql);
        int transaction_ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
        if (!transaction_ok) {
            db_release(conn, 0);
            tpm_send_json(client_fd, 503, "{\"error\":\"Activation transaction unavailable\"}",
                          origin, extra_headers, extra_len);
            return;
        }

        const char *lookup_params[] = {device_id, ak_name_hex};
        result = PQexecParams(conn,
            "SELECT d.institution_id,k.ak_name_hex,e.ek_public_key_pem,"
            "k.provenance_status,e.ek_certificate_pem,"
            "COALESCE(e.ek_certificate_chain,'') "
            "FROM devices d "
            "JOIN device_attestation_keys k ON k.device_id=d.id "
            "JOIN device_ek_certificates e ON e.device_id=d.id "
            "AND e.institution_id=d.institution_id AND e.trust_status='verified' "
            "WHERE d.id=$1 AND d.status IN ('registered','enrolled') "
            "AND d.tpm_present=TRUE "
            "AND k.key_name='AK' AND k.status='active' AND k.ak_name_hex=$2 "
            "AND EXISTS (SELECT 1 FROM device_registrations r "
            "WHERE r.device_id=d.id AND r.institution_id=d.institution_id "
            "AND r.decision='approved') "
            "AND EXISTS (SELECT 1 FROM device_trust_policies p "
            "WHERE p.institution_id=d.institution_id AND p.status='active' "
            "AND p.require_tpm=TRUE) "
            "ORDER BY e.updated_at DESC LIMIT 1 FOR SHARE OF d,k,e",
            2, NULL, lookup_params, NULL, NULL, 0);
        if (!result || PQresultStatus(result) != PGRES_TUPLES_OK ||
            PQntuples(result) != 1) {
            if (result) PQclear(result);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            tpm_send_json(client_fd, 409,
                "{\"error\":\"Approved device, trusted EK certificate, and matching TPM AK Name are required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char institution_id[64] = {0}, ek_pem[2048] = {0};
        char ek_cert_pem[4096] = {0}, ek_chain[4096] = {0};
        char stored_name[69] = {0}, provenance_status[32] = {0};
        int ek_fields_fit =
            PQgetlength(result, 0, 2) < (int)sizeof(ek_pem) &&
            PQgetlength(result, 0, 4) < (int)sizeof(ek_cert_pem) &&
            PQgetlength(result, 0, 5) < (int)sizeof(ek_chain);
        if (!ek_fields_fit) {
            PQclear(result);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            tpm_send_json(client_fd, 409,
                "{\"error\":\"Stored EK certificate data exceeds supported limits\"}",
                origin, extra_headers, extra_len);
            return;
        }
        snprintf(institution_id, sizeof(institution_id), "%s", PQgetvalue(result, 0, 0));
        snprintf(stored_name, sizeof(stored_name), "%s", PQgetvalue(result, 0, 1));
        snprintf(ek_pem, sizeof(ek_pem), "%s", PQgetvalue(result, 0, 2));
        snprintf(provenance_status, sizeof(provenance_status), "%s", PQgetvalue(result, 0, 3));
        snprintf(ek_cert_pem, sizeof(ek_cert_pem), "%s", PQgetvalue(result, 0, 4));
        snprintf(ek_chain, sizeof(ek_chain), "%s", PQgetvalue(result, 0, 5));
        PQclear(result);
        if (strcmp(provenance_status, "verified") == 0) {
            PQexec(conn, "COMMIT");
            db_release(conn, 0);
            tpm_send_json(client_fd, 200,
                "{\"status\":\"ALREADY_VERIFIED\",\"verified\":true}",
                origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(provenance_status, "template_valid") != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            tpm_send_json(client_fd, 409,
                "{\"error\":\"AK TPM public-area template must be validated before activation\"}",
                origin, extra_headers, extra_len);
            return;
        }

        char verified_ek_pem[2048] = {0}, anchor_id[64] = {0};
        char ek_error[256] = {0};
        if (ek_certificate_validate(ek_cert_pem, ek_chain, NULL, anchor_id,
                ek_error, verified_ek_pem, sizeof(verified_ek_pem)) != 0 ||
            strcmp(verified_ek_pem, ek_pem) != 0) {
            OPENSSL_cleanse(ek_pem, sizeof(ek_pem));
            OPENSSL_cleanse(verified_ek_pem, sizeof(verified_ek_pem));
            OPENSSL_cleanse(ek_cert_pem, sizeof(ek_cert_pem));
            OPENSSL_cleanse(ek_chain, sizeof(ek_chain));
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            tpm_send_json(client_fd, 409,
                "{\"error\":\"EK certificate is no longer valid under configured trust anchors\"}",
                origin, extra_headers, extra_len);
            return;
        }
        OPENSSL_cleanse(verified_ek_pem, sizeof(verified_ek_pem));
        OPENSSL_cleanse(ek_cert_pem, sizeof(ek_cert_pem));
        OPENSSL_cleanse(ek_chain, sizeof(ek_chain));

        const char *expire_params[] = {device_id};
        result = PQexecParams(conn,
            "UPDATE device_credential_activations SET status='expired' "
            "WHERE device_id=$1 AND status IN ('pending','verifying') "
            "AND expires_at<=EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000",
            1, NULL, expire_params, NULL, NULL, 0);
        int expiry_ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
        if (!expiry_ok) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            tpm_send_json(client_fd, 503, "{\"error\":\"Activation state could not be checked\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        result = PQexecParams(conn,
            "SELECT 1 FROM device_credential_activations "
            "WHERE device_id=$1 AND status IN ('pending','verifying') LIMIT 1",
            1, NULL, expire_params, NULL, NULL, 0);
        int activation_open = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
                              PQntuples(result) > 0;
        int activation_check_ok = result && PQresultStatus(result) == PGRES_TUPLES_OK;
        if (result) PQclear(result);
        if (!activation_check_ok || activation_open) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            tpm_send_json(client_fd, activation_open ? 409 : 503,
                activation_open ? "{\"error\":\"An activation challenge is already outstanding\"}"
                                : "{\"error\":\"Activation state could not be checked\"}",
                origin, extra_headers, extra_len);
            return;
        }

        char activation_id[64] = {0};
        char credential_blob_hex[8193] = {0};
        char secret_mac[65] = {0}, activation_error[256] = {0};
        if (credential_activation_initiate(
                device_id, institution_id, ek_pem, stored_name,
                activation_id, credential_blob_hex, sizeof(credential_blob_hex),
                secret_mac, activation_error) != 0) {
            OPENSSL_cleanse(ek_pem, sizeof(ek_pem));
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            OPENSSL_cleanse(secret_mac, sizeof(secret_mac));
            tpm_send_json(client_fd, 503,
                "{\"error\":\"TPM2 MakeCredential could not be completed\"}",
                origin, extra_headers, extra_len);
            return;
        }
        const char *insert_params[] = {
            activation_id, device_id, institution_id, stored_name,
            credential_blob_hex, secret_mac
        };
        result = PQexecParams(conn,
            "INSERT INTO device_credential_activations "
            "(id,device_id,institution_id,ak_name_hex,credential_blob_hex,"
            "credential_secret_hash,status,created_at,expires_at) "
            "VALUES ($1,$2,$3,$4,$5,$6,'pending',"
            "EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000,"
            "EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000+120000)",
            6, NULL, insert_params, NULL, NULL, 0);
        int inserted = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
        result = PQexec(conn, inserted ? "COMMIT" : "ROLLBACK");
        transaction_ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
        if (!inserted || !transaction_ok) {
            OPENSSL_cleanse(ek_pem, sizeof(ek_pem));
            OPENSSL_cleanse(credential_blob_hex, sizeof(credential_blob_hex));
            OPENSSL_cleanse(secret_mac, sizeof(secret_mac));
            db_release(conn, 0);
            tpm_send_json(client_fd, 409,
                "{\"error\":\"Could not persist a unique activation challenge\"}",
                origin, extra_headers, extra_len);
            return;
        }
        db_release(conn, 0);
        OPENSSL_cleanse(ek_pem, sizeof(ek_pem));
        OPENSSL_cleanse(secret_mac, sizeof(secret_mac));
        char response[12288];
        int response_len = snprintf(response, sizeof(response),
            "{\"status\":\"ACTIVATION_CHALLENGE\",\"activation_id\":\"%s\","
            "\"credential_blob\":\"%s\"}", activation_id, credential_blob_hex);
        OPENSSL_cleanse(credential_blob_hex, sizeof(credential_blob_hex));
        if (response_len < 0 || (size_t)response_len >= sizeof(response)) {
            tpm_send_json(client_fd, 500, "{\"error\":\"Activation response overflow\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        tpm_send_json(client_fd, 200, response, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/attestation/activate/complete") == 0) {
        char activation_id[64] = {0}, device_id[64] = {0};
        char activation_response_hex[65] = {0};
        ctrl_json_string(body, "activation_id", activation_id, sizeof(activation_id));
        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        ctrl_json_string(body, "activation_response", activation_response_hex, sizeof(activation_response_hex));

        if (!activation_id[0] || !device_id[0] || !activation_response_hex[0]) {
            OPENSSL_cleanse(activation_response_hex, sizeof(activation_response_hex));
            tpm_send_json(client_fd, 400,
                "{\"error\":\"activation_id, device_id, and activation_response required\"}",
                origin, extra_headers, extra_len);
            return;
        }

        PGconn *conn = db_acquire();
        if (!conn) {
            OPENSSL_cleanse(activation_response_hex, sizeof(activation_response_hex));
            tpm_send_json(client_fd, 503, "{\"error\":\"Database unavailable\"}",
                          origin, extra_headers, extra_len);
            return;
        }

        PGresult *result = PQexec(conn, "BEGIN");
        int transaction_ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
        if (!transaction_ok) {
            OPENSSL_cleanse(activation_response_hex, sizeof(activation_response_hex));
            db_release(conn, 0);
            tpm_send_json(client_fd, 503, "{\"error\":\"Activation store unavailable\"}",
                origin, extra_headers, extra_len);
            return;
        }
        const char *claim_params[] = {activation_id, device_id};
        result = PQexecParams(conn,
            "UPDATE device_credential_activations "
            "SET status='verifying' WHERE id=$1 AND device_id=$2 AND status='pending' "
            "AND expires_at>EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000 "
            "RETURNING institution_id,credential_secret_hash,ak_name_hex",
            2, NULL, claim_params, NULL, NULL, 0);
        int claimed = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
                      PQntuples(result) == 1;
        char institution_id[64] = {0}, expected_mac[65] = {0};
        char ak_name_hex[69] = {0};
        if (claimed) {
            snprintf(institution_id, sizeof(institution_id), "%s", PQgetvalue(result, 0, 0));
            snprintf(expected_mac, sizeof(expected_mac), "%s", PQgetvalue(result, 0, 1));
            snprintf(ak_name_hex, sizeof(ak_name_hex), "%s", PQgetvalue(result, 0, 2));
        }
        if (result) PQclear(result);
        result = PQexec(conn, claimed ? "COMMIT" : "ROLLBACK");
        transaction_ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
        if (!claimed || !transaction_ok) {
            OPENSSL_cleanse(activation_response_hex, sizeof(activation_response_hex));
            db_release(conn, 0);
            tpm_send_json(client_fd, 409,
                "{\"error\":\"Activation is unknown, expired, bound to another device, or already consumed\"}",
                origin, extra_headers, extra_len);
            return;
        }

        char error[256] = {0};
        int verified = credential_activation_verify(
            activation_id, device_id, institution_id, activation_response_hex,
            expected_mac, error) == 0;
        OPENSSL_cleanse(activation_response_hex, sizeof(activation_response_hex));
        OPENSSL_cleanse(expected_mac, sizeof(expected_mac));
        if (!verified) {
            const char *fail_params[] = {activation_id};
            PGresult *failed = PQexecParams(conn,
                "UPDATE device_credential_activations SET status='failed',"
                "activation_error='ACTIVATE_CREDENTIAL_MISMATCH' "
                "WHERE id=$1 AND status='verifying'",
                1, NULL, fail_params, NULL, NULL, 0);
            int failure_persisted = failed &&
                PQresultStatus(failed) == PGRES_COMMAND_OK &&
                strcmp(PQcmdTuples(failed), "1") == 0;
            if (failed) PQclear(failed);
            OPENSSL_cleanse(institution_id, sizeof(institution_id));
            db_release(conn, 0);
            if (!failure_persisted) {
                tpm_send_json(client_fd, 503,
                    "{\"error\":\"Activation failure could not be persisted\"}",
                    origin, extra_headers, extra_len);
                return;
            }
            tpm_send_json(client_fd, 403,
                "{\"status\":\"ACTIVATION_FAILED\",\"verified\":false}",
                origin, extra_headers, extra_len);
            return;
        }

        result = PQexec(conn, "BEGIN");
        transaction_ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
        const char *activate_params[] = {activation_id};
        if (transaction_ok) {
            result = PQexecParams(conn,
                "UPDATE device_credential_activations SET status='activated',"
                "activated_at=EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000 "
                "WHERE id=$1 AND status='verifying' "
                "AND expires_at>EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000",
                1, NULL, activate_params, NULL, NULL, 0);
            transaction_ok = result && PQresultStatus(result) == PGRES_COMMAND_OK &&
                   strcmp(PQcmdTuples(result), "1") == 0;
            if (result) PQclear(result);
        }
        if (transaction_ok) {
                const char *provenance_params[] = {device_id, institution_id, ak_name_hex, activation_id};
            result = PQexecParams(conn,
                "UPDATE device_attestation_keys k SET provenance_status='verified',"
                "provenance_details='TPM2_CREDENTIAL_ACTIVATION_V1:' || $4 "
                "FROM devices d WHERE k.device_id=d.id AND d.id=$1 "
                "AND d.institution_id=$2 AND k.ak_name_hex=$3 AND k.key_name='AK' "
                "AND k.status='active' AND k.provenance_status='template_valid' "
                "AND d.status IN ('registered','enrolled') "
                "AND d.tpm_present=TRUE "
                "AND EXISTS (SELECT 1 FROM device_registrations r "
                "WHERE r.device_id=d.id AND r.institution_id=d.institution_id "
                "AND r.decision='approved') "
                "AND EXISTS (SELECT 1 FROM device_trust_policies p "
                "WHERE p.institution_id=d.institution_id AND p.status='active' "
                "AND p.require_tpm=TRUE) "
                "AND EXISTS (SELECT 1 FROM device_ek_certificates e "
                "WHERE e.device_id=d.id AND e.institution_id=d.institution_id "
                "AND e.trust_status='verified')",
                4, NULL, provenance_params, NULL, NULL, 0);
            transaction_ok = result && PQresultStatus(result) == PGRES_COMMAND_OK &&
                   strcmp(PQcmdTuples(result), "1") == 0;
            if (result) PQclear(result);
        }
        result = PQexec(conn, transaction_ok ? "COMMIT" : "ROLLBACK");
        transaction_ok = transaction_ok && result &&
                         PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
        OPENSSL_cleanse(institution_id, sizeof(institution_id));
        OPENSSL_cleanse(ak_name_hex, sizeof(ak_name_hex));
        db_release(conn, 0);
        if (!transaction_ok) {
            tpm_send_json(client_fd, 503,
                "{\"error\":\"Could not persist the verified activation state\"}",
                origin, extra_headers, extra_len);
            return;
        }
        tpm_send_json(client_fd, 200,
            "{\"status\":\"ACTIVATION_SUCCESS\",\"verified\":true}",
            origin, extra_headers, extra_len);
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
