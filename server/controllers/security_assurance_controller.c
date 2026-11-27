#include "security_assurance_controller.h"
#include "controller.h"
#include "../audit/audit.h"

#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
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

static int gen_assurance_id(char *out, size_t out_len, const char *prefix) {
    unsigned char rnd[12];
    static const char hex[] = "0123456789abcdef";
    size_t plen = strlen(prefix);
    if (out_len < plen + sizeof(rnd) * 2 + 1 || RAND_bytes(rnd, sizeof(rnd)) != 1)
        return -1;
    memcpy(out, prefix, plen);
    for (size_t i = 0; i < sizeof(rnd); i++) {
        out[plen + i * 2] = hex[rnd[i] >> 4];
        out[plen + i * 2 + 1] = hex[rnd[i] & 15];
    }
    out[plen + sizeof(rnd) * 2] = '\0';
    return 0;
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
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
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

    const char *is_owner = (sess.role == ROLE_PLATFORM_OWNER) ? "true" : "false";
    const char *tenant = sess.institution_id;

    /* ---------------- GET /api/v1/security/assurance-posture ---------------- */
    if (strcmp(method, "GET") == 0 &&
        strcmp(path, "/api/v1/security/assurance-posture") == 0) {
        /* Tenant-scoped and freshness-gated (15-minute live window) */
        const char *qp[2] = { is_owner, tenant };
        int ql[2] = { (int)strlen(qp[0]), (int)strlen(qp[1]) };
        PGresult *res = db_simple(conn,
            "SELECT "
            "  (SELECT COUNT(*) FROM devices d WHERE ($1::boolean OR d.institution_id = $2)) AS total_devices, "
            "  (SELECT COUNT(*) FROM device_defence_posture p JOIN devices d ON d.id = p.device_id "
            "     WHERE ($1::boolean OR d.institution_id = $2) "
            "       AND p.updated_at >= (EXTRACT(EPOCH FROM NOW())::BIGINT - 900) * 1000 "
            "       AND p.dm_verity_ok) AS verity_ok, "
            "  (SELECT COUNT(*) FROM device_defence_posture p JOIN devices d ON d.id = p.device_id "
            "     WHERE ($1::boolean OR d.institution_id = $2) "
            "       AND p.updated_at >= (EXTRACT(EPOCH FROM NOW())::BIGINT - 900) * 1000 "
            "       AND p.bpf_lsm_active) AS bpf_lsm_ok, "
            "  (SELECT COUNT(*) FROM device_defence_posture p JOIN devices d ON d.id = p.device_id "
            "     WHERE ($1::boolean OR d.institution_id = $2) "
            "       AND p.updated_at >= (EXTRACT(EPOCH FROM NOW())::BIGINT - 900) * 1000 "
            "       AND p.pfr_800_193_ok) AS pfr_ok, "
            "  (SELECT COUNT(*) FROM device_defence_posture p JOIN devices d ON d.id = p.device_id "
            "     WHERE ($1::boolean OR d.institution_id = $2) "
            "       AND p.updated_at >= (EXTRACT(EPOCH FROM NOW())::BIGINT - 900) * 1000 "
            "       AND p.selinux_mls_ok AND p.iommu_dma_ok) AS mls_dma_ok, "
            "  (SELECT COUNT(*) FROM device_defence_posture p JOIN devices d ON d.id = p.device_id "
            "     WHERE ($1::boolean OR d.institution_id = $2) "
            "       AND p.updated_at >= (EXTRACT(EPOCH FROM NOW())::BIGINT - 900) * 1000 "
            "       AND p.rust_ai_active) AS rust_ai_ok, "
            "  (SELECT COUNT(DISTINCT l.device_id) FROM ima_verification_logs l JOIN devices d ON d.id = l.device_id "
            "     WHERE ($1::boolean OR d.institution_id = $2) "
            "       AND l.verified_at >= (EXTRACT(EPOCH FROM NOW())::BIGINT - 900) * 1000 "
            "       AND l.verified = TRUE) AS ima_verified, "
            "  (SELECT COUNT(*) FROM pqc_signing_keys WHERE status = 'active') AS pqc_keys, "
            "  (SELECT COUNT(*) FROM tamper_zeroization_events t JOIN devices d ON d.id = t.device_id "
            "     WHERE ($1::boolean OR d.institution_id = $2) AND t.lockdown_engaged = TRUE) AS tamper_events",
            2, qp, ql);

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
            "\"freshness_window_seconds\":900,"
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
        if (!security_role_has_permission(sess.role, AUTH_PERM_SECURITY_ADMIN) &&
            !security_role_has_permission(sess.role, AUTH_PERM_FLEET_MUTATION)) {
            db_release(conn, 0);
            send_err_with_cors(client_fd, 403, "Security or fleet admin permission required",
                               origin, extra_headers, extra_len);
            return;
        }

        char device_id[64] = {0};
        char pcr10_replayed[128] = {0};
        char quote_nonce[128] = {0};
        int entry_count = 0;

        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        ctrl_json_string(body, "pcr10_replayed", pcr10_replayed, sizeof(pcr10_replayed));
        ctrl_json_string(body, "quote_nonce", quote_nonce, sizeof(quote_nonce));
        ctrl_json_int(body, "entry_count", &entry_count);

        if (!device_id[0] || !is_valid_sha256_hex(pcr10_replayed) || entry_count <= 0) {
            db_release(conn, 0);
            send_err_with_cors(client_fd, 400,
                               "device_id, 64-hex-char pcr10_replayed, and positive entry_count are required",
                               origin, extra_headers, extra_len);
            return;
        }

        /* Look up device in caller's institution and fetch server-controlled expected PCR-10 */
        const char *dp[3] = { device_id, is_owner, tenant };
        int dl[3] = { (int)strlen(dp[0]), (int)strlen(dp[1]), (int)strlen(dp[2]) };
        PGresult *dres = db_simple(conn,
            "SELECT COALESCE(NULLIF(p.expected_pcr10, ''), "
            "  (SELECT g.sha256_digest FROM ima_golden_allowlist g "
            "   WHERE g.release_version = d.os_version ORDER BY g.created_at DESC LIMIT 1), '') "
            "FROM devices d "
            "LEFT JOIN device_defence_posture p ON p.device_id = d.id "
            "WHERE d.id = $1 AND ($2::boolean OR d.institution_id = $3)",
            3, dp, dl);

        if (!dres || PQresultStatus(dres) != PGRES_TUPLES_OK) {
            if (dres) PQclear(dres);
            db_release(conn, 0);
            send_err_with_cors(client_fd, 503, "Failed to query device IMA baseline",
                               origin, extra_headers, extra_len);
            return;
        }
        if (PQntuples(dres) != 1) {
            PQclear(dres);
            db_release(conn, 0);
            send_err_with_cors(client_fd, 404, "Device not found in authenticated institution",
                               origin, extra_headers, extra_len);
            return;
        }

        char server_expected_pcr10[65] = {0};
        snprintf(server_expected_pcr10, sizeof(server_expected_pcr10), "%s", PQgetvalue(dres, 0, 0));
        PQclear(dres);

        if (!is_valid_sha256_hex(server_expected_pcr10)) {
            db_release(conn, 0);
            send_err_with_cors(client_fd, 409,
                               "No server-controlled IMA PCR-10 baseline is registered for this device",
                               origin, extra_headers, extra_len);
            return;
        }

        int match = (CRYPTO_memcmp(pcr10_replayed, server_expected_pcr10, 64) == 0);
        char id_buf[64], count_buf[16];
        if (gen_assurance_id(id_buf, sizeof(id_buf), "ima_") != 0) {
            db_release(conn, 0);
            send_err_with_cors(client_fd, 500, "Failed to generate verification ID",
                               origin, extra_headers, extra_len);
            return;
        }
        snprintf(count_buf, sizeof(count_buf), "%d", entry_count);
        const char *ver_str = match ? "true" : "false";
        const char *reason = match ? "" : "PCR-10 IMA measurement mismatch against server baseline";

        const char *p[7] = { id_buf, device_id, pcr10_replayed, server_expected_pcr10, count_buf, ver_str, reason };
        int l[7];
        for (int i = 0; i < 7; i++) l[i] = (int)strlen(p[i]);

        PGresult *ins = db_simple(conn,
            "INSERT INTO ima_verification_logs "
            "(id, device_id, pcr10_replayed, pcr10_expected, entry_count, verified, failure_reason) "
            "VALUES ($1, $2, $3, $4, $5::int, $6::boolean, $7)",
            7, p, l);
        if (!ins || PQresultStatus(ins) != PGRES_COMMAND_OK || strcmp(PQcmdTuples(ins), "1") != 0) {
            const char *sqlstate = ins ? PQresultErrorField(ins, PG_DIAG_SQLSTATE) : NULL;
            int dup = sqlstate && strcmp(sqlstate, "23505") == 0;
            if (ins) PQclear(ins);
            db_release(conn, 0);
            send_err_with_cors(client_fd, dup ? 409 : 503,
                               dup ? "Duplicate IMA verification record" : "Failed to persist IMA verification log",
                               origin, extra_headers, extra_len);
            return;
        }
        PQclear(ins);
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
        if (!security_role_has_permission(sess.role, AUTH_PERM_SECURITY_ADMIN) &&
            !security_role_has_permission(sess.role, AUTH_PERM_FLEET_MUTATION)) {
            db_release(conn, 0);
            send_err_with_cors(client_fd, 403, "Security or fleet admin permission required",
                               origin, extra_headers, extra_len);
            return;
        }

        char device_id[64] = {0};
        char trigger_type[64] = {0};
        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        ctrl_json_string(body, "trigger_type", trigger_type, sizeof(trigger_type));

        if (!device_id[0] || !trigger_type[0]) {
            db_release(conn, 0);
            send_err_with_cors(client_fd, 400, "device_id and trigger_type are required",
                               origin, extra_headers, extra_len);
            return;
        }

        const char *dp[3] = { device_id, is_owner, tenant };
        int dl[3] = { (int)strlen(dp[0]), (int)strlen(dp[1]), (int)strlen(dp[2]) };
        PGresult *dres = db_simple(conn,
            "SELECT id FROM devices WHERE id = $1 AND ($2::boolean OR institution_id = $3)",
            3, dp, dl);
        if (!dres || PQresultStatus(dres) != PGRES_TUPLES_OK) {
            if (dres) PQclear(dres);
            db_release(conn, 0);
            send_err_with_cors(client_fd, 503, "Failed to verify device ownership",
                               origin, extra_headers, extra_len);
            return;
        }
        if (PQntuples(dres) != 1) {
            PQclear(dres);
            db_release(conn, 0);
            send_err_with_cors(client_fd, 404, "Device not found in authenticated institution",
                               origin, extra_headers, extra_len);
            return;
        }
        PQclear(dres);

        char id_buf[64], evt_id[64];
        if (gen_assurance_id(id_buf, sizeof(id_buf), "tz_") != 0 ||
            gen_assurance_id(evt_id, sizeof(evt_id), "dse_") != 0) {
            db_release(conn, 0);
            send_err_with_cors(client_fd, 500, "Failed to generate tamper event ID",
                               origin, extra_headers, extra_len);
            return;
        }

        PGresult *beg = PQexec(conn, "BEGIN");
        if (!beg || PQresultStatus(beg) != PGRES_COMMAND_OK) {
            if (beg) PQclear(beg);
            db_release(conn, 0);
            send_err_with_cors(client_fd, 503, "Failed to start tamper dispatch transaction",
                               origin, extra_headers, extra_len);
            return;
        }
        PQclear(beg);

        /* Record pending zeroization order — lockdown_engaged remains FALSE until device ack */
        const char *p[3] = { id_buf, device_id, trigger_type };
        int l[3] = { (int)strlen(p[0]), (int)strlen(p[1]), (int)strlen(p[2]) };
        PGresult *ins = db_simple(conn,
            "INSERT INTO tamper_zeroization_events "
            "(id, device_id, trigger_type, fde_scrubbed, session_scrubbed, pqc_scrubbed, lockdown_engaged) "
            "VALUES ($1, $2, $3, FALSE, FALSE, FALSE, FALSE)",
            3, p, l);
        if (!ins || PQresultStatus(ins) != PGRES_COMMAND_OK || strcmp(PQcmdTuples(ins), "1") != 0) {
            const char *sqlstate = ins ? PQresultErrorField(ins, PG_DIAG_SQLSTATE) : NULL;
            int dup = sqlstate && strcmp(sqlstate, "23505") == 0;
            if (ins) PQclear(ins);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_err_with_cors(client_fd, dup ? 409 : 503,
                               dup ? "Duplicate tamper zeroization event" : "Failed to persist tamper zeroization order",
                               origin, extra_headers, extra_len);
            return;
        }
        PQclear(ins);

        /* Revoke device trust & dispatch lockdown command in device_security_events */
        const char *rev_p[1] = { device_id };
        int rev_l[1] = { (int)strlen(device_id) };
        PGresult *rev = db_simple(conn,
            "UPDATE devices SET status = 'revoked' WHERE id = $1", 1, rev_p, rev_l);
        if (!rev || PQresultStatus(rev) != PGRES_COMMAND_OK) {
            if (rev) PQclear(rev);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_err_with_cors(client_fd, 503, "Failed to revoke device trust on tamper",
                               origin, extra_headers, extra_len);
            return;
        }
        PQclear(rev);

        const char *dse_p[3] = { evt_id, device_id, trigger_type };
        int dse_l[3] = { (int)strlen(dse_p[0]), (int)strlen(dse_p[1]), (int)strlen(dse_p[2]) };
        PGresult *dse = db_simple(conn,
            "INSERT INTO device_security_events (id, device_id, event_type, severity, details_json) "
            "VALUES ($1, $2, 'TAMPER_LOCKDOWN_AND_ZEROIZE', 'CRITICAL', "
            "jsonb_build_object('trigger',$3,'status','DISPATCHED_PENDING_VERIFICATION')::text)",
            3, dse_p, dse_l);
        if (!dse || PQresultStatus(dse) != PGRES_COMMAND_OK) {
            if (dse) PQclear(dse);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_err_with_cors(client_fd, 503, "Failed to dispatch device lockdown command",
                               origin, extra_headers, extra_len);
            return;
        }
        PQclear(dse);

        PGresult *cmt = PQexec(conn, "COMMIT");
        if (!cmt || PQresultStatus(cmt) != PGRES_COMMAND_OK) {
            if (cmt) PQclear(cmt);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_err_with_cors(client_fd, 503, "Failed to commit tamper dispatch",
                               origin, extra_headers, extra_len);
            return;
        }
        PQclear(cmt);
        db_release(conn, 0);

        audit_log(AUDIT_CRITICAL, sess.username, "TAMPER_ZEROIZATION_DISPATCHED", trigger_type);

        char ok_resp[256];
        snprintf(ok_resp, sizeof(ok_resp),
                 "{\"recorded\":true,\"id\":\"%s\",\"status\":\"DISPATCHED_PENDING_VERIFICATION\",\"lockdown_engaged\":false}",
                 id_buf);
        send_json_with_cors(client_fd, 202, ok_resp, origin, extra_headers, extra_len);
        return;
    }

    /* ---------------- POST /api/v1/security/tamper-zeroize/ack ---------------- */
    if (strcmp(method, "POST") == 0 &&
        strcmp(path, "/api/v1/security/tamper-zeroize/ack") == 0) {
        char event_id[64] = {0};
        char device_id[64] = {0};
        char receipt_digest[128] = {0};
        int fde = 0, sess_scrub = 0, pqc = 0;

        ctrl_json_string(body, "event_id", event_id, sizeof(event_id));
        ctrl_json_string(body, "device_id", device_id, sizeof(device_id));
        ctrl_json_string(body, "receipt_digest", receipt_digest, sizeof(receipt_digest));
        ctrl_json_bool(body, "fde_scrubbed", &fde);
        ctrl_json_bool(body, "session_scrubbed", &sess_scrub);
        ctrl_json_bool(body, "pqc_scrubbed", &pqc);

        if (!event_id[0] || !device_id[0] || !is_valid_sha256_hex(receipt_digest) ||
            (!fde && !sess_scrub && !pqc)) {
            db_release(conn, 0);
            send_err_with_cors(client_fd, 400,
                               "event_id, device_id, 64-hex receipt_digest, and scrubbed flags are required",
                               origin, extra_headers, extra_len);
            return;
        }

        const char *up[6] = {
            event_id, device_id, receipt_digest,
            fde ? "true" : "false", sess_scrub ? "true" : "false", pqc ? "true" : "false"
        };
        int ul[6];
        for (int i = 0; i < 6; i++) ul[i] = (int)strlen(up[i]);

        PGresult *res = db_simple(conn,
            "UPDATE tamper_zeroization_events "
            "SET fde_scrubbed = $4::boolean, session_scrubbed = $5::boolean, "
            "    pqc_scrubbed = $6::boolean, lockdown_engaged = TRUE, "
            "    receipt_digest = $3, acknowledged_at = (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
            "WHERE id = $1 AND device_id = $2",
            6, up, ul);
        if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
            if (res) PQclear(res);
            db_release(conn, 0);
            send_err_with_cors(client_fd, 503, "Failed to record tamper zeroization acknowledgement",
                               origin, extra_headers, extra_len);
            return;
        }
        int updated = strcmp(PQcmdTuples(res), "1") == 0;
        PQclear(res);
        db_release(conn, 0);

        if (!updated) {
            send_err_with_cors(client_fd, 404, "Tamper zeroization event not found for device",
                               origin, extra_headers, extra_len);
            return;
        }

        audit_log(AUDIT_CRITICAL, sess.username, "TAMPER_ZEROIZATION_VERIFIED", event_id);
        char ok_resp[256];
        snprintf(ok_resp, sizeof(ok_resp),
                 "{\"verified\":true,\"id\":\"%s\",\"lockdown_engaged\":true}", event_id);
        send_json_with_cors(client_fd, 200, ok_resp, origin, extra_headers, extra_len);
        return;
    }

    db_release(conn, 0);
    send_err_with_cors(client_fd, 404, "Security assurance endpoint not found",
                       origin, extra_headers, extra_len);
}
