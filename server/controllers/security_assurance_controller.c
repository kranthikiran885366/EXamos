#include "security_assurance_controller.h"
#include "controller.h"
#include "../audit/audit.h"

#include <ctype.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int is_valid_sha256_hex(const char *s) {
    if (!s || strlen(s) != 64) return 0;
    for (int i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}

static void send_json_with_cors(int client_fd, int status, const char *json,
                                const char *origin, char *extra_headers,
                                size_t extra_len) {
    ctrl_set_cors(extra_headers, extra_len, origin,
                  ctrl_cors_origin_allowed(origin));
    ctrl_send_json(client_fd, status, json, extra_headers);
}

static void send_err_with_cors(int client_fd, int status, const char *msg,
                               const char *origin, char *extra_headers,
                               size_t extra_len) {
    ctrl_set_cors(extra_headers, extra_len, origin,
                  ctrl_cors_origin_allowed(origin));
    char esc[512];
    ctrl_json_escape(msg ? msg : "Error", esc, sizeof(esc));
    char body[640];
    snprintf(body, sizeof(body), "{\"error\":\"%s\"}", esc);
    ctrl_send_json(client_fd, status, body, extra_headers);
}

void security_assurance_handle(int client_fd, const char *method, const char *path,
                               const char *body, const char *auth_header,
                               const char *origin, char *extra_headers,
                               size_t extra_len) {
    auth_session_t sess;
    memset(&sess, 0, sizeof(sess));
    if (!ctrl_authorize(auth_header, PERM_VIEW_AUDIT, &sess)) {
        send_err_with_cors(client_fd, 401, "Authentication required",
                           origin, extra_headers, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        send_err_with_cors(client_fd, 503, "Database unavailable",
                           origin, extra_headers, extra_len);
        return;
    }

    /* ---------------- GET /api/v1/security/assurance-posture ---------------- */
    if (strcmp(method, "GET") == 0 &&
        strcmp(path, "/api/v1/security/assurance-posture") == 0) {
        PGresult *res = db_simple(conn,
            "SELECT "
            "  (SELECT COUNT(*) FROM devices) AS total_devices, "
            "  (SELECT COUNT(*) FROM device_defence_posture WHERE dm_verity_ok) AS verity_ok, "
            "  (SELECT COUNT(*) FROM device_defence_posture WHERE bpf_lsm_active) AS bpf_lsm_ok, "
            "  (SELECT COUNT(*) FROM device_defence_posture WHERE pfr_800_193_ok) AS pfr_ok, "
            "  (SELECT COUNT(*) FROM device_defence_posture WHERE selinux_mls_ok AND iommu_dma_ok) AS mls_dma_ok, "
            "  (SELECT COUNT(*) FROM device_defence_posture WHERE rust_ai_active) AS rust_ai_ok, "
            "  (SELECT COUNT(*) FROM ima_verification_logs WHERE verified = TRUE) AS ima_verified, "
            "  (SELECT COUNT(*) FROM pqc_signing_keys WHERE status = 'active') AS pqc_keys, "
            "  (SELECT COUNT(*) FROM tamper_zeroization_events) AS tamper_events",
            0, NULL, NULL);

        if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
            if (res) PQclear(res);
            db_release(conn, 0);
            send_err_with_cors(client_fd, 500, "Failed to query security assurance posture",
                               origin, extra_headers, extra_len);
            return;
        }

        char resp[1024];
        snprintf(resp, sizeof(resp),
            "{\"total_devices\":%s,\"dm_verity_ab_verified\":%s,"
            "\"bpf_lsm_enforced\":%s,\"pfr_800_193_verified\":%s,"
            "\"mls_dma_enforced\":%s,\"rust_behavioral_ai_active\":%s,"
            "\"keylime_ima_verified\":%s,\"active_pqc_keys\":%s,"
            "\"tamper_zeroization_events\":%s,"
            "\"pqc_standards\":[\"ML-KEM-768 (FIPS 203)\",\"ML-DSA-65 (FIPS 204)\"],"
            "\"common_criteria_target\":\"ISO/IEC 15408 STQC IC3S EAL4\"}",
            PQgetvalue(res, 0, 0), PQgetvalue(res, 0, 1),
            PQgetvalue(res, 0, 2), PQgetvalue(res, 0, 3),
            PQgetvalue(res, 0, 4), PQgetvalue(res, 0, 5),
            PQgetvalue(res, 0, 6), PQgetvalue(res, 0, 7),
            PQgetvalue(res, 0, 8));
        PQclear(res);
        db_release(conn, 0);
        send_json_with_cors(client_fd, 200, resp, origin, extra_headers, extra_len);
        return;
    }

    /* ---------------- POST /api/v1/security/ima-verify ---------------- */
    if (strcmp(method, "POST") == 0 &&
        strcmp(path, "/api/v1/security/ima-verify") == 0) {
        char device_id[64] = {0};
        char pcr10_replayed[128] = {0};
        char pcr10_expected[128] = {0};
        int entry_count = 0;

        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        ctrl_json_string(body, "pcr10_replayed", pcr10_replayed, sizeof(pcr10_replayed));
        ctrl_json_string(body, "pcr10_expected", pcr10_expected, sizeof(pcr10_expected));
        ctrl_json_int(body, "entry_count", &entry_count);

        if (!device_id[0] || !is_valid_sha256_hex(pcr10_replayed) ||
            !is_valid_sha256_hex(pcr10_expected)) {
            db_release(conn, 0);
            send_err_with_cors(client_fd, 400,
                               "device_id and 64-hex-char pcr10_replayed/pcr10_expected are required",
                               origin, extra_headers, extra_len);
            return;
        }

        int match = (CRYPTO_memcmp(pcr10_replayed, pcr10_expected, 64) == 0);
        char id_buf[64], count_buf[16];
        snprintf(id_buf, sizeof(id_buf), "ima_%lld_%u",
                 (long long)time(NULL), (unsigned int)(rand() % 10000));
        snprintf(count_buf, sizeof(count_buf), "%d", entry_count);
        const char *ver_str = match ? "true" : "false";
        const char *reason = match ? "" : "PCR-10 IMA measurement mismatch";

        const char *p[6] = { id_buf, device_id, pcr10_replayed, pcr10_expected, count_buf, ver_str };
        int l[6];
        for (int i = 0; i < 6; i++) l[i] = (int)strlen(p[i]);

        PGresult *ins = db_simple(conn,
            "INSERT INTO ima_verification_logs "
            "(id, device_id, pcr10_replayed, pcr10_expected, entry_count, verified) "
            "VALUES ($1, $2, $3, $4, $5::int, $6::boolean)",
            6, p, l);
        if (ins) PQclear(ins);
        db_release(conn, 0);

        audit_log(AUDIT_INFO, sess.username, "KEYLIME_IMA_VERIFY",
                  match ? "PCR10_MATCH" : reason);

        if (!match) {
            send_err_with_cors(client_fd, 403, reason, origin, extra_headers, extra_len);
            return;
        }

        char ok_resp[256];
        snprintf(ok_resp, sizeof(ok_resp),
                 "{\"verified\":true,\"id\":\"%s\",\"device_id\":\"%s\"}",
                 id_buf, device_id);
        send_json_with_cors(client_fd, 200, ok_resp, origin, extra_headers, extra_len);
        return;
    }

    /* ---------------- POST /api/v1/security/tamper-zeroize ---------------- */
    if (strcmp(method, "POST") == 0 &&
        strcmp(path, "/api/v1/security/tamper-zeroize") == 0) {
        char device_id[64] = {0};
        char trigger_type[64] = {0};
        int fde = 0, sess_scrub = 0, pqc = 0;

        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        ctrl_json_string(body, "trigger_type", trigger_type, sizeof(trigger_type));
        ctrl_json_bool(body, "fde_scrubbed", &fde);
        ctrl_json_bool(body, "session_scrubbed", &sess_scrub);
        ctrl_json_bool(body, "pqc_scrubbed", &pqc);

        if (!device_id[0] || !trigger_type[0]) {
            db_release(conn, 0);
            send_err_with_cors(client_fd, 400, "device_id and trigger_type are required",
                               origin, extra_headers, extra_len);
            return;
        }

        char id_buf[64];
        snprintf(id_buf, sizeof(id_buf), "tz_%lld_%u",
                 (long long)time(NULL), (unsigned int)(rand() % 10000));
        const char *p[6] = {
            id_buf, device_id, trigger_type,
            fde ? "true" : "false",
            sess_scrub ? "true" : "false",
            pqc ? "true" : "false"
        };
        int l[6];
        for (int i = 0; i < 6; i++) l[i] = (int)strlen(p[i]);

        PGresult *ins = db_simple(conn,
            "INSERT INTO tamper_zeroization_events "
            "(id, device_id, trigger_type, fde_scrubbed, session_scrubbed, pqc_scrubbed, lockdown_engaged) "
            "VALUES ($1, $2, $3, $4::boolean, $5::boolean, $6::boolean, TRUE)",
            6, p, l);
        if (ins) PQclear(ins);
        db_release(conn, 0);

        audit_log(AUDIT_CRITICAL, sess.username, "TAMPER_RAM_ZEROIZATION", trigger_type);

        char ok_resp[256];
        snprintf(ok_resp, sizeof(ok_resp),
                 "{\"recorded\":true,\"id\":\"%s\",\"lockdown_engaged\":true}",
                 id_buf);
        send_json_with_cors(client_fd, 200, ok_resp, origin, extra_headers, extra_len);
        return;
    }

    db_release(conn, 0);
    send_err_with_cors(client_fd, 404, "Security assurance endpoint not found",
                       origin, extra_headers, extra_len);
}
