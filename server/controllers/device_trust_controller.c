/*
 * device_trust_controller.c — ExamOS Module 13: Device Trust, Registration & Attestation
 *
 * Implements:
 * - Enterprise device identity & registration lifecycle
 * - Boot environment & OS release integrity verification
 * - Hardware TPM 2.0 attestation challenge-response & quote verification
 * - Device trust policy engine (ALLOW, DENY, PENDING, REASSESS, QUARANTINE, UNSUPPORTED)
 * - Device assignments & student association
 * - Master Exam Launch Authorization integration (Modules 9, 10, 11, 12, 13)
 * - Security incidents, revocations, and durable audit trail
 */

#include "device_trust_controller.h"
#include "controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../include/attestation_service.h"
#include "../include/enterprise_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

static void dt_audit_log(const char *actor, const char *event, const char *detail) {
    audit_append(actor, event, detail);
}

static void dt_send_json(int fd, int code, const char *body,
                         const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void dt_send_error(int fd, int code, const char *msg,
                          const char *origin, char *extra, size_t extra_len) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "{\"error\":\"%.512s\"}", msg ? msg : "Unknown error");
    dt_send_json(fd, code, buf, origin, extra, extra_len);
}

static int record_device_audit(PGconn *conn, const char *device_id, const char *inst_id,
                               const char *actor_id, const char *action, const char *details) {
    char aid[64];
    snprintf(aid, sizeof(aid), "daud_%ld_%d", (long)time(NULL), rand() % 10000);
    const char *p[6] = { aid, device_id, inst_id, actor_id, action, details ? details : "" };
    int l[6];
    for (int i = 0; i < 6; i++) l[i] = p[i] ? (int)strlen(p[i]) : 0;

    PGresult *r = db_simple(conn,
        "INSERT INTO device_audit_events (id, device_id, institution_id, actor_id, action, details, created_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 6, p, l);
    int ok = r && PQresultStatus(r) == PGRES_COMMAND_OK;
    if (r) PQclear(r);
    return ok ? 0 : -1;
}

static int record_device_security_event(PGconn *conn, const char *device_id,
                                        const char *event_type, const char *severity, const char *details) {
    char sid[64];
    snprintf(sid, sizeof(sid), "dsec_%ld_%d", (long)time(NULL), rand() % 10000);
    const char *p[5] = { sid, device_id, event_type, severity, details ? details : "" };
    int l[5];
    for (int i = 0; i < 5; i++) l[i] = p[i] ? (int)strlen(p[i]) : 0;

    PGresult *r = db_simple(conn,
        "INSERT INTO device_security_events (id, device_id, event_type, severity, details, created_at) "
        "VALUES ($1, $2, $3, $4, $5, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, p, l);
    int ok = r && PQresultStatus(r) == PGRES_COMMAND_OK;
    if (r) PQclear(r);
    return ok ? 0 : -1;
}

static int update_device_status(PGconn *conn, const char *device_id,
                                const char *institution_id, const char *status,
                                const char *actor_id, const char *action,
                                const char *reason) {
    PGresult *begin = PQexec(conn, "BEGIN");
    if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
        if (begin) PQclear(begin);
        return -1;
    }
    PQclear(begin);

    const char *params[3] = { status, device_id, institution_id };
    const int lengths[3] = {
        (int)strlen(status), (int)strlen(device_id),
        (int)strlen(institution_id)
    };
    const char *query =
        "UPDATE devices SET status=$1,updated_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000 "
        "WHERE id=$2 AND institution_id=$3 AND "
        "(($1='suspended' AND status IN ('registered','enrolled')) OR "
        "($1='revoked' AND status NOT IN ('revoked','retired')) OR "
        "($1='retired' AND status<>'retired'))";
    PGresult *updated = db_simple(conn, query, 3, params, lengths);
    if (!updated || PQresultStatus(updated) != PGRES_COMMAND_OK) {
        if (updated) PQclear(updated);
        PQexec(conn, "ROLLBACK");
        return -1;
    }
    if (strcmp(PQcmdTuples(updated), "1") != 0) {
        PQclear(updated);
        PQexec(conn, "ROLLBACK");
        return 0;
    }
    PQclear(updated);

    if (strcmp(status, "revoked") == 0 || strcmp(status, "retired") == 0) {
        PGresult *keys = db_simple(conn,
            "UPDATE device_attestation_keys SET status='revoked' "
            "WHERE device_id=$1 AND status='active'",
            1, (const char *[]){ device_id },
            (const int []){ (int)strlen(device_id) });
        if (!keys || PQresultStatus(keys) != PGRES_COMMAND_OK) {
            if (keys) PQclear(keys);
            PQexec(conn, "ROLLBACK");
            return -1;
        }
        PQclear(keys);
    }

    if ((strcmp(status, "revoked") == 0 &&
         record_device_security_event(conn, device_id, "DEVICE_REVOKED",
                                      "CRITICAL", reason) != 0) ||
        record_device_audit(conn, device_id, institution_id, actor_id,
                            action, reason) != 0) {
        PQexec(conn, "ROLLBACK");
        return -1;
    }

    PGresult *commit = PQexec(conn, "COMMIT");
    if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
        if (commit) PQclear(commit);
        PQexec(conn, "ROLLBACK");
        return -1;
    }
    PQclear(commit);
    return 1;
}

static void sha256_hex_str(const unsigned char *data, size_t len, char *out_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(out_hex + (i * 2), "%02x", hash[i]);
    }
    out_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
}

static int device_ak_key_algorithm(const char *public_key_pem,
                                  char *algorithm, size_t algorithm_len) {
    if (!public_key_pem || !public_key_pem[0] || !algorithm || algorithm_len == 0)
        return 0;
    BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
    if (!bio) return 0;
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!key) return 0;

    int valid = 1;
    int key_type = EVP_PKEY_base_id(key);
    int key_bits = EVP_PKEY_bits(key);
    if (key_type == EVP_PKEY_RSA && key_bits == 2048) {
        snprintf(algorithm, algorithm_len, "RSA-2048");
    } else if (key_type == EVP_PKEY_RSA && key_bits == 3072) {
        snprintf(algorithm, algorithm_len, "RSA-3072");
    } else if (key_type == EVP_PKEY_EC && key_bits == 256) {
        snprintf(algorithm, algorithm_len, "ECC-P256");
    } else if (key_type == EVP_PKEY_EC && key_bits == 384) {
        snprintf(algorithm, algorithm_len, "ECC-P384");
    } else {
        valid = 0;
    }
    EVP_PKEY_free(key);
    return valid;
}

/*
 * Evaluates the full trust decision for a device against the active policy.
 * Populates outcome: ALLOW, DENY, PENDING, REASSESS, QUARANTINE, UNSUPPORTED.
 */
static void evaluate_device_trust(PGconn *conn, const char *device_id,
                                  char *out_outcome, size_t out_len,
                                  char *out_reason, size_t r_len,
                                  char *out_policy_id, size_t pol_len) {
    strncpy(out_outcome, "DENY", out_len - 1);
    out_reason[0] = '\0';
    if (out_policy_id && pol_len > 0) out_policy_id[0] = '\0';

    /* 1. Fetch Device Record */
    const char *dp[1] = { device_id };
    int dl[1] = { (int)strlen(device_id) };
    PGresult *d_res = db_simple(conn,
        "SELECT id, institution_id, hostname, device_name, device_category, "
        "boot_mode, secure_boot_state, tpm_present, tpm_version, os_release_id, "
        "status FROM devices WHERE id = $1", 1, dp, dl);

    if (!d_res || PQntuples(d_res) == 0) {
        if (d_res) PQclear(d_res);
        strncpy(out_outcome, "DENY", out_len - 1);
        snprintf(out_reason, r_len, "Device not registered in ExamOS inventory");
        return;
    }

    char d_inst[64] = {0}, d_status[32] = {0}, d_sb[32] = {0}, d_osrel[64] = {0};
    char d_tpmp[8] = {0};

    strncpy(d_inst, PQgetvalue(d_res, 0, 1), sizeof(d_inst) - 1);
    strncpy(d_sb, PQgetvalue(d_res, 0, 6), sizeof(d_sb) - 1);
    strncpy(d_tpmp, PQgetvalue(d_res, 0, 7), sizeof(d_tpmp) - 1);
    strncpy(d_osrel, PQgetvalue(d_res, 0, 9), sizeof(d_osrel) - 1);
    strncpy(d_status, PQgetvalue(d_res, 0, 10), sizeof(d_status) - 1);
    PQclear(d_res);

    /* 2. Check Device Status Lifecycle */
    if (strcmp(d_status, "quarantined") == 0) {
        strncpy(out_outcome, "QUARANTINE", out_len - 1);
        snprintf(out_reason, r_len, "Device is quarantined due to security violation or tampering");
        return;
    }
    if (strcmp(d_status, "pending_approval") == 0 || strcmp(d_status, "registration_requested") == 0) {
        strncpy(out_outcome, "PENDING", out_len - 1);
        snprintf(out_reason, r_len, "Device registration is pending administrative approval");
        return;
    }
    if (strcmp(d_status, "suspended") == 0) {
        strncpy(out_outcome, "DENY", out_len - 1);
        snprintf(out_reason, r_len, "Device has been administratively suspended");
        return;
    }
    if (strcmp(d_status, "revoked") == 0 || strcmp(d_status, "retired") == 0) {
        strncpy(out_outcome, "DENY", out_len - 1);
        snprintf(out_reason, r_len, "Device identity has been revoked or retired");
        return;
    }
    if (strcmp(d_status, "registered") != 0 && strcmp(d_status, "enrolled") != 0) {
        strncpy(out_outcome, "DENY", out_len - 1);
        snprintf(out_reason, r_len, "Device status is not registered (status: %s)", d_status);
        return;
    }

    /* 3. Fetch Active Trust Policy for Institution */
    const char *pp[1] = { d_inst };
    int pl[1] = { (int)strlen(d_inst) };
    PGresult *p_res = db_simple(conn,
        "SELECT id, require_tpm, require_secure_boot, require_approved_release "
        "FROM device_trust_policies WHERE institution_id = $1 AND status = 'active' "
        "ORDER BY version DESC", 1, pp, pl);

    if (!p_res || PQresultStatus(p_res) != PGRES_TUPLES_OK) {
        if (p_res) PQclear(p_res);
        strncpy(out_outcome, "DENY", out_len - 1);
        snprintf(out_reason, r_len, "Active device trust policy could not be verified");
        return;
    }
    if (PQntuples(p_res) != 1) {
        PQclear(p_res);
        strncpy(out_outcome, "DENY", out_len - 1);
        snprintf(out_reason, r_len, "A unique active device trust policy is required");
        return;
    }

    char pol_id[64] = {0};
    int req_tpm = (strcmp(PQgetvalue(p_res, 0, 1), "t") == 0);
    int req_sb = (strcmp(PQgetvalue(p_res, 0, 2), "t") == 0);
    int req_rel = (strcmp(PQgetvalue(p_res, 0, 3), "t") == 0);
    strncpy(pol_id, PQgetvalue(p_res, 0, 0), sizeof(pol_id) - 1);
    PQclear(p_res);

    if (out_policy_id && pol_len > 0) {
        snprintf(out_policy_id, pol_len, "%s", pol_id);
    }

    /* 4. Check Secure Boot */
    if (req_sb && strcmp(d_sb, "enabled") != 0) {
        strncpy(out_outcome, "DENY", out_len - 1);
        snprintf(out_reason, r_len, "Secure Boot verification failed (state: %s)", d_sb);
        return;
    }

    /* 5. Check TPM presence */
    if (req_tpm && strcmp(d_tpmp, "t") != 0) {
        strncpy(out_outcome, "UNSUPPORTED", out_len - 1);
        snprintf(out_reason, r_len, "TPM 2.0 cryptographic hardware missing or unsupported");
        return;
    }

    /* 6. Check OS Release Integrity */
    if (req_rel && d_osrel[0]) {
        const char *rel_p[1] = { d_osrel };
        int rel_l[1] = { (int)strlen(d_osrel) };
        PGresult *rel_res = db_simple(conn,
            "SELECT status FROM device_os_releases WHERE release_version = $1", 1, rel_p, rel_l);
        if (rel_res && PQntuples(rel_res) > 0) {
            const char *r_stat = PQgetvalue(rel_res, 0, 0);
            if (strcmp(r_stat, "revoked") == 0) {
                PQclear(rel_res);
                strncpy(out_outcome, "DENY", out_len - 1);
                snprintf(out_reason, r_len, "ExamOS release has been revoked due to security advisory: %s", d_osrel);
                return;
            }
            if (strcmp(r_stat, "active") != 0) {
                PQclear(rel_res);
                strncpy(out_outcome, "DENY", out_len - 1);
                snprintf(out_reason, r_len, "ExamOS release is not approved for examination use: %s", d_osrel);
                return;
            }
            PQclear(rel_res);
        } else {
            if (rel_res) PQclear(rel_res);
            strncpy(out_outcome, "DENY", out_len - 1);
            snprintf(out_reason, r_len, "Unrecognized ExamOS release: %s", d_osrel);
            return;
        }
    }

    /* All policy requirements satisfied: grant ALLOW */
    strncpy(out_outcome, "ALLOW", out_len - 1);
    snprintf(out_reason, r_len, "Device meets all policy security requirements (Secure Boot, TPM 2.0, verified OS release)");
}

void device_trust_handle(int client_fd, const char *method, const char *path,
                         const char *body, const char *auth_header,
                         const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    memset(&sess, 0, sizeof(sess));

    int auth_rc = ctrl_authorize(auth_header, AUTH_PERM_READ, &sess);
    int is_owner = auth_rc == 0 && sess.role == ROLE_PLATFORM_OWNER;

    PGconn *conn = db_acquire();
    if (!conn) {
        dt_send_error(client_fd, 503, "Database connection unavailable", origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 1. POST /api/v1/devices/register: Submit device registration
     * ========================================================================= */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/devices/register") == 0) {
        if (ctrl_authorize(auth_header, AUTH_PERM_FLEET_MUTATION, &sess) != 0) {
            db_release(conn, 0);
            dt_send_error(client_fd, 403, "Fleet mutation permission is required to register a device",
                          origin, extra_headers, extra_len);
            return;
        }
        char dev_id[64] = {0}, inst_id[64] = {0}, campus_id[64] = {0};
        char hostname[128] = {0}, dev_name[128] = {0}, dev_cat[32] = "unknown";
        char mfr[128] = "unknown", model[128] = "unknown", cpu_arch[64] = "unknown";
        char boot_mode[32] = "unknown", sb_state[32] = "unknown";
        char tpm_ver[32] = "unknown", os_rel[64] = "unknown", kernel_v[64] = "unknown";
        char ak_pem[2048] = {0};
        int tpm_present = 0;

        ctrl_json_string(body, "device_id", dev_id, sizeof(dev_id));
        ctrl_json_string(body, "institution_id", inst_id, sizeof(inst_id));
        ctrl_json_string(body, "campus_id", campus_id, sizeof(campus_id));
        ctrl_json_string(body, "hostname", hostname, sizeof(hostname));
        ctrl_json_string(body, "device_name", dev_name, sizeof(dev_name));
        ctrl_json_string(body, "device_category", dev_cat, sizeof(dev_cat));
        ctrl_json_string(body, "manufacturer", mfr, sizeof(mfr));
        ctrl_json_string(body, "model", model, sizeof(model));
        ctrl_json_string(body, "cpu_arch", cpu_arch, sizeof(cpu_arch));
        ctrl_json_string(body, "boot_mode", boot_mode, sizeof(boot_mode));
        ctrl_json_string(body, "secure_boot_state", sb_state, sizeof(sb_state));
        ctrl_json_bool(body, "tpm_present", &tpm_present);
        ctrl_json_string(body, "tpm_version", tpm_ver, sizeof(tpm_ver));
        ctrl_json_string(body, "os_release_id", os_rel, sizeof(os_rel));
        ctrl_json_string(body, "kernel_version", kernel_v, sizeof(kernel_v));
        ctrl_json_string(body, "ak_public_key_pem", ak_pem, sizeof(ak_pem));

        if (sess.role != ROLE_PLATFORM_OWNER) {
            if (!sess.institution_id[0] ||
                (inst_id[0] && strcmp(inst_id, sess.institution_id) != 0)) {
                db_release(conn, 0);
                dt_send_error(client_fd, 403, "Device registration is outside the authenticated institution",
                              origin, extra_headers, extra_len);
                return;
            }
            snprintf(inst_id, sizeof(inst_id), "%s", sess.institution_id);
        } else if (!inst_id[0]) {
            db_release(conn, 0);
            dt_send_error(client_fd, 400, "Platform owner must provide an institution_id",
                          origin, extra_headers, extra_len);
            return;
        }
        if (!dev_id[0]) {
            db_release(conn, 0);
            dt_send_error(client_fd, 400, "A provisioned device_id is required",
                          origin, extra_headers, extra_len);
            return;
        }
        char ak_algorithm[32] = {0};
        if (!device_ak_key_algorithm(ak_pem, ak_algorithm, sizeof(ak_algorithm))) {
            db_release(conn, 0);
            dt_send_error(client_fd, 400,
                          "A valid RSA-2048, RSA-3072, ECC-P256, or ECC-P384 attestation public key is required",
                          origin, extra_headers, extra_len);
            return;
        }
        const char *tpm_mode = getenv("EXAMOS_TPM_MODE");
        if (tpm_mode && strcmp(tpm_mode, "production") == 0 &&
            !attestation_device_identity_matches(dev_id, inst_id, ak_pem)) {
            db_release(conn, 0);
            dt_send_error(client_fd, 403,
                          "Device identity, institution, and AK must match the signed production registry",
                          origin, extra_headers, extra_len);
            return;
        }
        if (!dev_name[0]) {
            snprintf(dev_name, sizeof(dev_name), "ExamOS Terminal %s", dev_id);
        }
        if (!hostname[0]) {
            snprintf(hostname, sizeof(hostname), "%s.examos.local", dev_id);
        }

        /* Registration must never manufacture an institution or its trust policy. */
        const char *tchk_p[1] = { inst_id };
        int tchk_l[1] = { (int)strlen(inst_id) };
        PGresult *tchk = db_simple(conn, "SELECT id FROM tenants WHERE id = $1", 1, tchk_p, tchk_l);
        if (!tchk || PQresultStatus(tchk) != PGRES_TUPLES_OK) {
            if (tchk) PQclear(tchk);
            db_release(conn, 0);
            dt_send_error(client_fd, 503, "Institution registry could not be verified",
                          origin, extra_headers, extra_len);
            return;
        }
        if (PQntuples(tchk) != 1) {
            PQclear(tchk);
            db_release(conn, 0);
            dt_send_error(client_fd, 404, "Institution does not exist",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(tchk);

        PGresult *begin = PQexec(conn, "BEGIN");
        if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
            if (begin) PQclear(begin);
            db_release(conn, 0);
            dt_send_error(client_fd, 503, "Could not start device registration transaction",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(begin);

        /* Lock the active policy while the registration decision is persisted. */
        const char *pp[1] = { inst_id };
        int pl[1] = { (int)strlen(inst_id) };
        PGresult *pol_r = db_simple(conn,
            "SELECT require_admin_approval FROM device_trust_policies "
            "WHERE institution_id=$1 AND status='active' FOR SHARE",
            1, pp, pl);
        if (!pol_r || PQresultStatus(pol_r) != PGRES_TUPLES_OK) {
            if (pol_r) PQclear(pol_r);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            dt_send_error(client_fd, 503, "Device trust policy could not be verified",
                          origin, extra_headers, extra_len);
            return;
        }
        if (PQntuples(pol_r) != 1) {
            PQclear(pol_r);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            dt_send_error(client_fd, 409, "A unique active device trust policy is required",
                          origin, extra_headers, extra_len);
            return;
        }
        int req_approval = strcmp(PQgetvalue(pol_r, 0, 0), "t") == 0;
        PQclear(pol_r);

        const char *initial_status = req_approval ? "pending_approval" : "registered";

        const char *dp[16] = {
            dev_id, inst_id, campus_id, hostname, dev_name, dev_cat,
            mfr, model, cpu_arch, boot_mode, sb_state, tpm_present ? "t" : "f",
            tpm_ver, os_rel, kernel_v, initial_status
        };
        int dl[16];
        for (int i = 0; i < 16; i++) dl[i] = dp[i] ? (int)strlen(dp[i]) : 0;

        PGresult *ins_dev = db_simple(conn,
            "INSERT INTO devices (id, institution_id, campus_id, hostname, device_name, device_category, "
            "manufacturer, model, cpu_arch, boot_mode, secure_boot_state, tpm_present, tpm_version, "
            "os_release_id, kernel_version, status, last_contact_at, enrolled_at, tenant_id, "
            "created_at, updated_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, "
            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, $2, "
            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
            "ON CONFLICT (id) DO NOTHING RETURNING id",
            16, dp, dl);

        if (!ins_dev || PQresultStatus(ins_dev) != PGRES_TUPLES_OK) {
            char err[512];
            snprintf(err, sizeof(err), "Failed to register device: %s",
                     ins_dev ? PQresultErrorMessage(ins_dev) : "Database query failed");
            if (ins_dev) PQclear(ins_dev);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            dt_send_error(client_fd, 500, err, origin, extra_headers, extra_len);
            return;
        }
        if (PQntuples(ins_dev) != 1) {
            PQclear(ins_dev);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            dt_send_error(client_fd, 409, "Device identity is already registered",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(ins_dev);

        /* Record Registration Attempt */
        char reg_id[64];
        snprintf(reg_id, sizeof(reg_id), "dreg_%ld_%d", (long)time(NULL), rand() % 10000);
        const char *registration_decision = req_approval ? "pending" : "approved";
        const char *registration_actor = sess.user_id[0] ? sess.user_id : "installer";
        const char *decided_by = req_approval ? "" : "system";
        const char *rp[6] = {
            reg_id, dev_id, inst_id, registration_actor, registration_decision, decided_by
        };
        int rl[6];
        for (int i = 0; i < 6; i++) rl[i] = rp[i] ? (int)strlen(rp[i]) : 0;

        PGresult *ins_reg = db_simple(conn,
            "INSERT INTO device_registrations "
            "(id,device_id,institution_id,requested_by,decision,decided_by,created_at,updated_at) "
            "VALUES ($1,$2,$3,$4,$5,$6,EXTRACT(EPOCH FROM NOW())::BIGINT*1000,"
            "EXTRACT(EPOCH FROM NOW())::BIGINT*1000)",
            6, rp, rl);
        if (!ins_reg || PQresultStatus(ins_reg) != PGRES_COMMAND_OK) {
            if (ins_reg) PQclear(ins_reg);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            dt_send_error(client_fd, 503, "Device registration record could not be persisted",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(ins_reg);

        unsigned char ak_id_random[16];
        if (RAND_bytes(ak_id_random, sizeof(ak_id_random)) != 1) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            dt_send_error(client_fd, 503,
                          "Cryptographic randomness is unavailable for attestation key registration",
                          origin, extra_headers, extra_len);
            return;
        }
        char ak_id[37] = "ak_";
        for (int i = 0; i < 16; i++)
            sprintf(ak_id + 3 + (i * 2), "%02x", ak_id_random[i]);
        char fp[65];
        sha256_hex_str((const unsigned char *)ak_pem, strlen(ak_pem), fp);

        const char *ak_p[6] = { ak_id, dev_id, "AK", ak_algorithm, ak_pem, fp };
        int ak_l[6];
        for (int i = 0; i < 6; i++) ak_l[i] = (int)strlen(ak_p[i]);

        PGresult *ins_ak = db_simple(conn,
            "INSERT INTO device_attestation_keys "
            "(id,device_id,key_name,key_algorithm,public_key_pem,public_key_fingerprint,status,enrolled_at) "
            "VALUES ($1,$2,$3,$4,$5,$6,'active',EXTRACT(EPOCH FROM NOW())::BIGINT*1000)",
            6, ak_p, ak_l);
        if (!ins_ak || PQresultStatus(ins_ak) != PGRES_COMMAND_OK) {
            if (ins_ak) PQclear(ins_ak);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            dt_send_error(client_fd, 503, "Device attestation key could not be persisted",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(ins_ak);

        const char *registration_auditor = sess.user_id[0] ? sess.user_id : "system";
        if (record_device_audit(conn, dev_id, inst_id, registration_auditor,
                                "DEVICE_REGISTERED", initial_status) != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            dt_send_error(client_fd, 503, "Device registration audit record could not be persisted",
                          origin, extra_headers, extra_len);
            return;
        }
        PGresult *commit = PQexec(conn, "COMMIT");
        if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
            if (commit) PQclear(commit);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            dt_send_error(client_fd, 503, "Device registration transaction could not commit",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(commit);
        dt_audit_log(sess.user_id[0] ? sess.user_id : "system", "DEVICE_REGISTERED", dev_id);

        db_release(conn, 0);
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"%s\",\"device_id\":\"%s\",\"institution_id\":\"%s\",\"secure_boot\":\"%s\","
            "\"tpm_present\":%s,\"os_release\":\"%s\"}",
            initial_status, dev_id, inst_id, sb_state, tpm_present ? "true" : "false", os_rel);
        dt_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 2. GET /api/v1/devices: List devices
     * ========================================================================= */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/devices") == 0) {
        PGresult *res = NULL;
        if (is_owner) {
            res = PQexec(conn,
                "SELECT id, institution_id, campus_id, hostname, device_name, device_category, "
                "manufacturer, model, cpu_arch, boot_mode, secure_boot_state, tpm_present, "
                "tpm_version, os_release_id, status, last_contact_at, last_attestation_at "
                "FROM devices ORDER BY created_at DESC");
        } else {
            const char *pvals[1] = { sess.institution_id };
            int lens[1] = { (int)strlen(sess.institution_id) };
            res = db_simple(conn,
                "SELECT id, institution_id, campus_id, hostname, device_name, device_category, "
                "manufacturer, model, cpu_arch, boot_mode, secure_boot_state, tpm_present, "
                "tpm_version, os_release_id, status, last_contact_at, last_attestation_at "
                "FROM devices WHERE institution_id = $1 ORDER BY created_at DESC", 1, pvals, lens);
        }

        char *json = malloc(262144);
        if (!json) {
            if (res) PQclear(res);
            db_release(conn, 0);
            dt_send_error(client_fd, 500, "Out of memory", origin, extra_headers, extra_len);
            return;
        }

        size_t pos = 0;
        pos += snprintf(json + pos, 262144 - pos, "{\"devices\":[");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            int n = PQntuples(res);
            for (int i = 0; i < n; i++) {
                if (i > 0) pos += snprintf(json + pos, 262144 - pos, ",");
                const char *lc = PQgetvalue(res, i, 15);
                const char *la = PQgetvalue(res, i, 16);
                pos += snprintf(json + pos, 262144 - pos,
                    "{\"id\":\"%s\",\"institution_id\":\"%s\",\"campus_id\":\"%s\",\"hostname\":\"%s\","
                    "\"device_name\":\"%s\",\"device_category\":\"%s\",\"manufacturer\":\"%s\",\"model\":\"%s\","
                    "\"cpu_arch\":\"%s\",\"boot_mode\":\"%s\",\"secure_boot_state\":\"%s\",\"tpm_present\":%s,"
                    "\"tpm_version\":\"%s\",\"os_release_id\":\"%s\",\"status\":\"%s\","
                    "\"last_contact_at\":%s,\"last_attestation_at\":%s}",
                    PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                    PQgetvalue(res, i, 3), PQgetvalue(res, i, 4), PQgetvalue(res, i, 5),
                    PQgetvalue(res, i, 6), PQgetvalue(res, i, 7), PQgetvalue(res, i, 8),
                    PQgetvalue(res, i, 9), PQgetvalue(res, i, 10),
                    strcmp(PQgetvalue(res, i, 11), "t") == 0 ? "true" : "false",
                    PQgetvalue(res, i, 12), PQgetvalue(res, i, 13), PQgetvalue(res, i, 14),
                    lc[0] ? lc : "null", la[0] ? la : "null");
            }
        }
        if (res) PQclear(res);
        pos += snprintf(json + pos, 262144 - pos, "]}");

        db_release(conn, 0);
        dt_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        free(json);
        return;
    }

    /* =========================================================================
     * 3. Specific Device Sub-routes: /api/v1/devices/:id/...
     * ========================================================================= */
    const char *dev_pfx = "/api/v1/devices/";
    size_t dev_plen = strlen(dev_pfx);
    if (strncmp(path, dev_pfx, dev_plen) == 0) {
        if (strcmp(method, "POST") == 0) {
            if (ctrl_authorize(auth_header, AUTH_PERM_FLEET_MUTATION, &sess) != 0) {
                db_release(conn, 0);
                dt_send_error(client_fd, 403, "Fleet mutation permission is required for device state changes",
                              origin, extra_headers, extra_len);
                return;
            }
            is_owner = sess.role == ROLE_PLATFORM_OWNER;
        }
        const char *sub = path + dev_plen;
        char device_id[64] = {0};
        const char *slash = strchr(sub, '/');
        size_t id_len = slash ? (size_t)(slash - sub) : strlen(sub);
        if (id_len >= sizeof(device_id)) {
            db_release(conn, 0);
            dt_send_error(client_fd, 400, "Invalid device ID", origin, extra_headers, extra_len);
            return;
        }
        memcpy(device_id, sub, id_len);
        device_id[id_len] = '\0';
        const char *action = slash ? slash : "";

        /* Load Device and verify tenant */
        const char *sp[1] = { device_id };
        int sl[1] = { (int)strlen(device_id) };
        PGresult *d_res = db_simple(conn,
            "SELECT id, institution_id, hostname, device_name, device_category, "
            "boot_mode, secure_boot_state, tpm_present, tpm_version, os_release_id, status "
            "FROM devices WHERE id = $1", 1, sp, sl);

        if (!d_res || PQntuples(d_res) == 0) {
            if (d_res) PQclear(d_res);
            db_release(conn, 0);
            dt_send_error(client_fd, 404, "Device not found in system", origin, extra_headers, extra_len);
            return;
        }

        char d_inst[64] = {0}, d_host[128] = {0}, d_name[128] = {0}, d_cat[32] = {0};
        char d_sb[32] = {0}, d_tpmp[8] = {0}, d_osrel[64] = {0}, d_status[32] = {0};

        strncpy(d_inst, PQgetvalue(d_res, 0, 1), sizeof(d_inst) - 1);
        strncpy(d_host, PQgetvalue(d_res, 0, 2), sizeof(d_host) - 1);
        strncpy(d_name, PQgetvalue(d_res, 0, 3), sizeof(d_name) - 1);
        strncpy(d_cat, PQgetvalue(d_res, 0, 4), sizeof(d_cat) - 1);
        strncpy(d_sb, PQgetvalue(d_res, 0, 6), sizeof(d_sb) - 1);
        strncpy(d_tpmp, PQgetvalue(d_res, 0, 7), sizeof(d_tpmp) - 1);
        strncpy(d_osrel, PQgetvalue(d_res, 0, 9), sizeof(d_osrel) - 1);
        strncpy(d_status, PQgetvalue(d_res, 0, 10), sizeof(d_status) - 1);
        PQclear(d_res);

        if (!is_owner && strcmp(d_inst, sess.institution_id) != 0) {
            db_release(conn, 0);
            dt_send_error(client_fd, 403, "Access to other institution's device is prohibited", origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- GET /api/v1/devices/:id (Device Details) ---------------- */
        if (strcmp(method, "GET") == 0 && action[0] == '\0') {
            db_release(conn, 0);
            char resp[1024];
            snprintf(resp, sizeof(resp),
                "{\"device\":{\"id\":\"%s\",\"institution_id\":\"%s\",\"hostname\":\"%s\",\"device_name\":\"%s\","
                "\"device_category\":\"%s\",\"secure_boot_state\":\"%s\",\"tpm_present\":%s,\"os_release_id\":\"%s\","
                "\"status\":\"%s\"}}",
                device_id, d_inst, d_host, d_name, d_cat, d_sb,
                strcmp(d_tpmp, "t") == 0 ? "true" : "false", d_osrel, d_status);
            dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/devices/:id/approve (Admin Approval) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/approve") == 0) {
            auth_session_t approver;
            if (ctrl_authorize(auth_header, AUTH_PERM_FLEET_MUTATION, &approver) != 0) {
                db_release(conn, 0);
                dt_send_error(client_fd, 403, "Fleet mutation permission is required to approve device enrollment",
                              origin, extra_headers, extra_len);
                return;
            }
            if (approver.role != ROLE_PLATFORM_OWNER &&
                (!approver.institution_id[0] ||
                 strcmp(approver.institution_id, d_inst) != 0)) {
                db_release(conn, 0);
                dt_send_error(client_fd, 403, "Device enrollment approval is outside the authenticated institution",
                              origin, extra_headers, extra_len);
                return;
            }
            if (strcmp(d_status, "pending_approval") != 0 &&
                strcmp(d_status, "registration_requested") != 0) {
                db_release(conn, 0);
                dt_send_error(client_fd, 409, "Device is not awaiting enrollment approval",
                              origin, extra_headers, extra_len);
                return;
            }

            PGresult *begin = PQexec(conn, "BEGIN");
            if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
                if (begin) PQclear(begin);
                db_release(conn, 0);
                dt_send_error(client_fd, 503, "Could not start device approval transaction",
                              origin, extra_headers, extra_len);
                return;
            }
            PQclear(begin);

            const char *up_p[3] = { "registered", device_id, d_inst };
            const int up_l[3] = {
                (int)strlen(up_p[0]), (int)strlen(up_p[1]), (int)strlen(up_p[2])
            };
            PGresult *up_r = db_simple(conn,
                "UPDATE devices SET status=$1,updated_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000 "
                "WHERE id=$2 AND institution_id=$3 "
                "AND status IN ('pending_approval','registration_requested')",
                3, up_p, up_l);
            if (!up_r || PQresultStatus(up_r) != PGRES_COMMAND_OK ||
                strcmp(PQcmdTuples(up_r), "1") != 0) {
                if (up_r) PQclear(up_r);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                dt_send_error(client_fd, 409, "Device enrollment state changed; approval was not applied",
                              origin, extra_headers, extra_len);
                return;
            }
            PQclear(up_r);

            const char *reg_p[5] = {
                "approved", approver.user_id, device_id, d_inst, approver.user_id
            };
            const int reg_l[5] = {
                (int)strlen(reg_p[0]), (int)strlen(reg_p[1]), (int)strlen(reg_p[2]),
                (int)strlen(reg_p[3]), (int)strlen(reg_p[4])
            };
            PGresult *reg_r = db_simple(conn,
                "UPDATE device_registrations SET decision=$1,decided_by=$2,"
                "updated_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000 "
                "WHERE device_id=$3 AND institution_id=$4 AND decision='pending' "
                "AND requested_by<>$5",
                5, reg_p, reg_l);
            if (!reg_r || PQresultStatus(reg_r) != PGRES_COMMAND_OK ||
                strcmp(PQcmdTuples(reg_r), "1") != 0) {
                if (reg_r) PQclear(reg_r);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                dt_send_error(client_fd, 409, "A pending enrollment from a different requester was not found",
                              origin, extra_headers, extra_len);
                return;
            }
            PQclear(reg_r);

            if (record_device_audit(conn, device_id, d_inst, approver.user_id,
                                    "DEVICE_APPROVED", "Registration approved") != 0) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                dt_send_error(client_fd, 503, "Device approval audit record could not be persisted",
                              origin, extra_headers, extra_len);
                return;
            }
            PGresult *commit = PQexec(conn, "COMMIT");
            if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
                if (commit) PQclear(commit);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                dt_send_error(client_fd, 503, "Device approval transaction could not commit",
                              origin, extra_headers, extra_len);
                return;
            }
            PQclear(commit);
            dt_audit_log(approver.user_id, "DEVICE_APPROVED", device_id);

            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"approved\",\"device_id\":\"%s\"}", device_id);
            dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/devices/:id/suspend ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/suspend") == 0) {
            char reason[256] = {0};
            ctrl_json_string(body, "reason", reason, sizeof(reason));
            if (strlen(reason) < 8) {
                db_release(conn, 0);
                dt_send_error(client_fd, 400, "A suspension reason of at least 8 characters is required",
                              origin, extra_headers, extra_len);
                return;
            }
            int transition = update_device_status(conn, device_id, d_inst,
                "suspended", sess.user_id, "DEVICE_SUSPENDED", reason);
            if (transition != 1) {
                db_release(conn, 0);
                dt_send_error(client_fd, transition == 0 ? 409 : 503,
                              transition == 0 ? "Device state changed; suspension was not applied"
                                              : "Device suspension and audit could not be persisted",
                              origin, extra_headers, extra_len);
                return;
            }
            dt_audit_log(sess.user_id, "DEVICE_SUSPENDED", device_id);

            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"suspended\",\"device_id\":\"%s\"}", device_id);
            dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/devices/:id/revoke ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/revoke") == 0) {
            char reason[256] = {0};
            ctrl_json_string(body, "reason", reason, sizeof(reason));
            if (strlen(reason) < 8) {
                db_release(conn, 0);
                dt_send_error(client_fd, 400, "A revocation reason of at least 8 characters is required",
                              origin, extra_headers, extra_len);
                return;
            }
            int transition = update_device_status(conn, device_id, d_inst,
                "revoked", sess.user_id, "DEVICE_REVOKED", reason);
            if (transition != 1) {
                db_release(conn, 0);
                dt_send_error(client_fd, transition == 0 ? 409 : 503,
                              transition == 0 ? "Device state changed; revocation was not applied"
                                              : "Device revocation, key revocation, and audit could not be persisted",
                              origin, extra_headers, extra_len);
                return;
            }
            dt_audit_log(sess.user_id, "DEVICE_REVOKED", device_id);

            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"revoked\",\"device_id\":\"%s\"}", device_id);
            dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/devices/:id/retire ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/retire") == 0) {
            int transition = update_device_status(conn, device_id, d_inst,
                "retired", sess.user_id, "DEVICE_RETIRED", "Device retired");
            if (transition != 1) {
                db_release(conn, 0);
                dt_send_error(client_fd, transition == 0 ? 409 : 503,
                              transition == 0 ? "Device state changed; retirement was not applied"
                                              : "Device retirement and audit could not be persisted",
                              origin, extra_headers, extra_len);
                return;
            }
            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"retired\",\"device_id\":\"%s\"}", device_id);
            dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/devices/:id/assign (Device Assignment) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/assign") == 0) {
            char student_id[64] = {0}, exam_id[64] = {0}, asg_type[32] = "student";
            ctrl_json_string(body, "student_id", student_id, sizeof(student_id));
            ctrl_json_string(body, "exam_id", exam_id, sizeof(exam_id));
            ctrl_json_string(body, "assignment_type", asg_type, sizeof(asg_type));

            /* Check for active conflict */
            const char *chk_p[1] = { device_id };
            int chk_l[1] = { (int)strlen(device_id) };
            PGresult *chk_r = db_simple(conn,
                "SELECT id, assigned_student_id FROM device_assignments WHERE device_id = $1 AND status = 'active'", 1, chk_p, chk_l);
            if (chk_r) {
                if (PQntuples(chk_r) > 0) {
                    char cur_stu[64] = {0};
                    strncpy(cur_stu, PQgetvalue(chk_r, 0, 1), sizeof(cur_stu) - 1);
                    if (student_id[0] && strcmp(cur_stu, student_id) != 0) {
                        PQclear(chk_r);
                        db_release(conn, 0);
                        dt_send_error(client_fd, 409, "Device already actively assigned to another student", origin, extra_headers, extra_len);
                        return;
                    }
                }
                PQclear(chk_r);
            }

            char asg_id[64];
            snprintf(asg_id, sizeof(asg_id), "dasg_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *ap[7] = { asg_id, device_id, d_inst, asg_type, student_id, exam_id, sess.user_id[0] ? sess.user_id : "admin" };
            int al[7];
            for (int i = 0; i < 7; i++) al[i] = ap[i] ? (int)strlen(ap[i]) : 0;

            PGresult *ins_asg = db_simple(conn,
                "INSERT INTO device_assignments (id, device_id, institution_id, assignment_type, assigned_student_id, "
                "assigned_exam_id, status, start_time, assigned_by, created_at, assigned_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, 'active', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, $7, "
                "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 7, ap, al);
            if (!ins_asg || PQresultStatus(ins_asg) != PGRES_COMMAND_OK) {
                char err[512];
                snprintf(err, sizeof(err), "Failed to assign device: %s",
                         ins_asg ? PQresultErrorMessage(ins_asg) : "Database query failed");
                if (ins_asg) PQclear(ins_asg);
                db_release(conn, 0);
                dt_send_error(client_fd, 500, err, origin, extra_headers, extra_len);
                return;
            }
            PQclear(ins_asg);

            record_device_audit(conn, device_id, d_inst, sess.user_id, "DEVICE_ASSIGNED", student_id);

            db_release(conn, 0);
            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"assigned\",\"assignment_id\":\"%s\",\"device_id\":\"%s\",\"student_id\":\"%s\",\"exam_id\":\"%s\"}",
                asg_id, device_id, student_id, exam_id);
            dt_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/devices/:id/attestation/challenge (Fresh Nonce) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/attestation/challenge") == 0) {
            if (strcmp(d_status, "registered") != 0 &&
                strcmp(d_status, "enrolled") != 0) {
                db_release(conn, 0);
                dt_send_error(client_fd, 409,
                              "Only an active registered device can request an attestation challenge",
                              origin, extra_headers, extra_len);
                return;
            }
            unsigned char rand_buf[48];
            if (RAND_bytes(rand_buf, sizeof(rand_buf)) != 1) {
                db_release(conn, 0);
                dt_send_error(client_fd, 503,
                              "Cryptographic randomness is unavailable",
                              origin, extra_headers, extra_len);
                return;
            }
            char nonce[65];
            for (int i = 0; i < 32; i++) sprintf(nonce + (i * 2), "%02x", rand_buf[i]);
            nonce[64] = '\0';

            char ch_id[40] = "dch_";
            for (int i = 0; i < 16; i++)
                sprintf(ch_id + 4 + (i * 2), "%02x", rand_buf[32 + i]);

            const char *cp[3] = { ch_id, device_id, nonce };
            int cl[3] = { (int)strlen(ch_id), (int)strlen(device_id), (int)strlen(nonce) };

            PGresult *ins_ch = db_simple(conn,
                "INSERT INTO device_attestation_challenges (id, device_id, nonce, used, expires_at, created_at) "
                "VALUES ($1, $2, $3, FALSE, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 + 120000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
                3, cp, cl);
            if (!ins_ch || PQresultStatus(ins_ch) != PGRES_COMMAND_OK) {
                if (ins_ch) PQclear(ins_ch);
                db_release(conn, 0);
                dt_send_error(client_fd, 503,
                              "Attestation challenge could not be persisted",
                              origin, extra_headers, extra_len);
                return;
            }
            PQclear(ins_ch);

            db_release(conn, 0);
            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"CHALLENGE_ISSUED\",\"challenge_id\":\"%s\",\"device_id\":\"%s\",\"nonce\":\"%s\",\"expires_in_sec\":120}",
                ch_id, device_id, nonce);
            dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/devices/:id/attestation/verify (Verify Quote) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/attestation/verify") == 0) {
            if (strcmp(d_status, "registered") != 0 && strcmp(d_status, "enrolled") != 0) {
                db_release(conn, 0);
                dt_send_error(client_fd, 409,
                              "Only a registered or enrolled device can submit attestation evidence",
                              origin, extra_headers, extra_len);
                return;
            }

            /* Inject device_id into the evidence body so attestation_verify_evidence
             * can look up the AK and institution binding from the registry. */
            char augmented[8192];
            size_t body_len = body ? strlen(body) : 0;
            if (body_len == 0 || body_len > 7900) {
                db_release(conn, 0);
                dt_send_error(client_fd, 400, "Attestation evidence body is missing or too large",
                              origin, extra_headers, extra_len);
                return;
            }
            /* Strip trailing } and append device_id field */
            char trimmed[8192];
            strncpy(trimmed, body, sizeof(trimmed) - 1);
            trimmed[sizeof(trimmed) - 1] = '\0';
            size_t tlen = strlen(trimmed);
            while (tlen > 0 && (trimmed[tlen - 1] == '}' || trimmed[tlen - 1] == ' '))
                tlen--;
            trimmed[tlen] = '\0';
            snprintf(augmented, sizeof(augmented),
                     "%s,\"device_id\":\"%s\"}", trimmed, device_id);

            char reason[64] = {0}, exam_key[EXAM_KEY_LEN + 1] = {0};
            int verified = attestation_verify_evidence(augmented, reason, exam_key) == 0;
            OPENSSL_cleanse(exam_key, sizeof(exam_key));

            if (verified) {
                /* Update device last_attestation_at */
                const char *ua_p[1] = { device_id };
                int ua_l[1] = { (int)strlen(device_id) };
                PGresult *ua_r = db_simple(conn,
                    "UPDATE devices SET last_attestation_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000,"
                    "updated_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000 WHERE id=$1",
                    1, ua_p, ua_l);
                if (ua_r) PQclear(ua_r);
                record_device_audit(conn, device_id, d_inst, sess.user_id[0] ? sess.user_id : "agent",
                                    "ATTESTATION_VERIFIED", reason);
                dt_audit_log(sess.user_id[0] ? sess.user_id : "agent", "ATTESTATION_VERIFIED", device_id);
                db_release(conn, 0);
                char resp[256];
                snprintf(resp, sizeof(resp),
                    "{\"status\":\"VERIFIED\",\"device_id\":\"%s\",\"outcome\":\"TRUSTED\"}",
                    device_id);
                dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            } else {
                record_device_security_event(conn, device_id, "ATTESTATION_FAILED", "WARNING",
                                             reason[0] ? reason : "TPM quote verification failed");
                db_release(conn, 0);
                char resp[256];
                snprintf(resp, sizeof(resp),
                    "{\"status\":\"REJECTED\",\"device_id\":\"%s\",\"error_code\":\"%s\"}",
                    device_id, reason[0] ? reason : "VERIFICATION_ERROR");
                dt_send_json(client_fd, 403, resp, origin, extra_headers, extra_len);
            }
            return;
        }

        /* ---------------- GET /api/v1/devices/:id/trust-status ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(action, "/trust-status") == 0) {
            char outcome[32] = {0}, reason[512] = {0}, pol_id[64] = {0};
            evaluate_device_trust(conn, device_id, outcome, sizeof(outcome),
                                  reason, sizeof(reason), pol_id, sizeof(pol_id));

            db_release(conn, 0);
            char resp[1024];
            snprintf(resp, sizeof(resp),
                "{\"device_id\":\"%s\",\"institution_id\":\"%s\",\"outcome\":\"%s\",\"reason\":\"%s\","
                "\"policy_id\":\"%s\",\"secure_boot\":\"%s\",\"tpm_present\":%s,\"os_release\":\"%s\"}",
                device_id, d_inst, outcome, reason, pol_id, d_sb,
                strcmp(d_tpmp, "t") == 0 ? "true" : "false", d_osrel);
            dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/devices/:id/security-events ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/security-events") == 0) {
            char event_type[64] = "TAMPER_DETECTED", severity[32] = "WARNING", details[512] = {0};
            ctrl_json_string(body, "event_type", event_type, sizeof(event_type));
            ctrl_json_string(body, "severity", severity, sizeof(severity));
            ctrl_json_string(body, "details", details, sizeof(details));

            record_device_security_event(conn, device_id, event_type, severity, details);

            /* If CRITICAL, auto-quarantine device */
            if (strcmp(severity, "CRITICAL") == 0) {
                const char *qp[2] = { "quarantined", device_id };
                int ql[2] = { 11, (int)strlen(device_id) };
                PGresult *qr = db_simple(conn,
                    "UPDATE devices SET status = $1, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $2", 2, qp, ql);
                if (qr) PQclear(qr);
                record_device_audit(conn, device_id, d_inst, "security_monitor", "DEVICE_QUARANTINED", event_type);
            }

            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"recorded\",\"device_id\":\"%s\"}", device_id);
            dt_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        db_release(conn, 0);
        dt_send_error(client_fd, 404, "Endpoint not found", origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 4. Device Trust Policies: /api/v1/device-trust-policies/...
     * ========================================================================= */
    const char *pol_pfx = "/api/v1/device-trust-policies";
    if (strncmp(path, pol_pfx, strlen(pol_pfx)) == 0) {
        const char *sub = path + strlen(pol_pfx);

        /* POST /api/v1/device-trust-policies (Create Draft) */
        if (strcmp(method, "POST") == 0 && sub[0] == '\0') {
            auth_session_t policy_actor;
            if (ctrl_authorize(auth_header, AUTH_PERM_SECURITY_ADMIN, &policy_actor) != 0) {
                db_release(conn, 0);
                dt_send_error(client_fd, 403, "Security administration permission is required",
                              origin, extra_headers, extra_len);
                return;
            }
            char pol_name[128] = {0}, inst_id[64] = {0};
            int req_tpm = 1, req_sb = 1, req_rel = 1, req_admin = 1, max_age = 300;

            ctrl_json_string(body, "policy_name", pol_name, sizeof(pol_name));
            ctrl_json_string(body, "institution_id", inst_id, sizeof(inst_id));
            ctrl_json_bool(body, "require_tpm", &req_tpm);
            ctrl_json_bool(body, "require_secure_boot", &req_sb);
            ctrl_json_bool(body, "require_approved_release", &req_rel);
            ctrl_json_bool(body, "require_admin_approval", &req_admin);
            ctrl_json_int(body, "max_evidence_age_sec", &max_age);

            if (!pol_name[0] || max_age < 1 || max_age > 86400) {
                db_release(conn, 0);
                dt_send_error(client_fd, 400, "A policy name and evidence age between 1 and 86400 seconds are required",
                              origin, extra_headers, extra_len);
                return;
            }
            if (policy_actor.role != ROLE_PLATFORM_OWNER) {
                if (!policy_actor.institution_id[0] ||
                    (inst_id[0] && strcmp(inst_id, policy_actor.institution_id) != 0)) {
                    db_release(conn, 0);
                    dt_send_error(client_fd, 403, "Policy creation is outside the authenticated institution",
                                  origin, extra_headers, extra_len);
                    return;
                }
                snprintf(inst_id, sizeof(inst_id), "%s", policy_actor.institution_id);
            } else if (!inst_id[0]) {
                db_release(conn, 0);
                dt_send_error(client_fd, 400, "Platform owner must provide an institution_id",
                              origin, extra_headers, extra_len);
                return;
            }

            const char *tenant_params[1] = { inst_id };
            const int tenant_lengths[1] = { (int)strlen(inst_id) };
            PGresult *tenant = db_simple(conn, "SELECT id FROM tenants WHERE id=$1",
                                         1, tenant_params, tenant_lengths);
            if (!tenant || PQresultStatus(tenant) != PGRES_TUPLES_OK) {
                if (tenant) PQclear(tenant);
                db_release(conn, 0);
                dt_send_error(client_fd, 503, "Institution registry could not be verified",
                              origin, extra_headers, extra_len);
                return;
            }
            if (PQntuples(tenant) != 1) {
                PQclear(tenant);
                db_release(conn, 0);
                dt_send_error(client_fd, 404, "Institution does not exist",
                              origin, extra_headers, extra_len);
                return;
            }
            PQclear(tenant);

            char pid[64];
            snprintf(pid, sizeof(pid), "dtpol_%ld_%d", (long)time(NULL), rand() % 10000);

            char age_str[16];
            snprintf(age_str, sizeof(age_str), "%d", max_age);

            const char *pp[10] = {
                pid, inst_id, pol_name, req_tpm ? "t" : "f", req_sb ? "t" : "f",
                req_rel ? "t" : "f", req_admin ? "t" : "f", age_str, "draft",
                policy_actor.user_id
            };
            int pl[10];
            for (int i = 0; i < 10; i++) pl[i] = (int)strlen(pp[i]);

            PGresult *ins_p = db_simple(conn,
                "INSERT INTO device_trust_policies "
                "(id,institution_id,policy_name,require_tpm,require_secure_boot,"
                "require_approved_release,require_admin_approval,max_evidence_age_sec,"
                "status,created_by,created_at,updated_at) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,"
                "EXTRACT(EPOCH FROM NOW())::BIGINT*1000,"
                "EXTRACT(EPOCH FROM NOW())::BIGINT*1000) RETURNING id",
                10, pp, pl);
            if (!ins_p || PQresultStatus(ins_p) != PGRES_TUPLES_OK ||
                PQntuples(ins_p) != 1) {
                if (ins_p) PQclear(ins_p);
                db_release(conn, 0);
                dt_send_error(client_fd, 503, "Device trust policy draft could not be persisted",
                              origin, extra_headers, extra_len);
                return;
            }
            PQclear(ins_p);
            dt_audit_log(policy_actor.user_id, "DEVICE_TRUST_POLICY_DRAFT_CREATED", pid);

            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"draft_created\",\"policy_id\":\"%s\"}", pid);
            dt_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* Policy Actions: /:id/approve or /:id/activate */
        if (sub[0] == '/') {
            char pid[64] = {0};
            const char *slash = strchr(sub + 1, '/');
            size_t id_len = slash ? (size_t)(slash - (sub + 1)) : strlen(sub + 1);
            if (id_len < sizeof(pid)) {
                memcpy(pid, sub + 1, id_len);
                pid[id_len] = '\0';
                const char *act = slash ? slash : "";

                if (strcmp(method, "POST") == 0 && strcmp(act, "/approve") == 0) {
                    auth_session_t policy_actor;
                    if (ctrl_authorize(auth_header, AUTH_PERM_SECURITY_ADMIN, &policy_actor) != 0) {
                        db_release(conn, 0);
                        dt_send_error(client_fd, 403, "Security administration permission is required",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    const char *ap[4] = {
                        policy_actor.user_id, pid, policy_actor.institution_id,
                        policy_actor.role == ROLE_PLATFORM_OWNER ? "true" : "false"
                    };
                    const int al[4] = {
                        (int)strlen(ap[0]), (int)strlen(ap[1]),
                        (int)strlen(ap[2]), (int)strlen(ap[3])
                    };
                    PGresult *ar = db_simple(conn,
                        "UPDATE device_trust_policies SET status='approved',approved_by=$1,"
                        "approved_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000,"
                        "updated_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000 "
                        "WHERE id=$2 AND status='draft' AND created_by<>'' AND created_by<>$1 "
                        "AND ($4::boolean OR institution_id=$3) RETURNING id",
                        4, ap, al);
                    if (!ar || PQresultStatus(ar) != PGRES_TUPLES_OK) {
                        if (ar) PQclear(ar);
                        db_release(conn, 0);
                        dt_send_error(client_fd, 503, "Device trust policy approval could not be persisted",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    if (PQntuples(ar) != 1) {
                        PQclear(ar);
                        db_release(conn, 0);
                        dt_send_error(client_fd, 409, "Policy is not an eligible draft or requires an independent approver",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    PQclear(ar);
                    dt_audit_log(policy_actor.user_id, "DEVICE_TRUST_POLICY_APPROVED", pid);

                    db_release(conn, 0);
                    char resp[256];
                    snprintf(resp, sizeof(resp), "{\"status\":\"approved\",\"policy_id\":\"%s\"}", pid);
                    dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                    return;
                }

                if (strcmp(method, "POST") == 0 && strcmp(act, "/activate") == 0) {
                    auth_session_t policy_actor;
                    if (ctrl_authorize(auth_header, AUTH_PERM_SECURITY_ADMIN, &policy_actor) != 0) {
                        db_release(conn, 0);
                        dt_send_error(client_fd, 403, "Security administration permission is required",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    PGresult *begin = PQexec(conn, "BEGIN");
                    if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
                        if (begin) PQclear(begin);
                        db_release(conn, 0);
                        dt_send_error(client_fd, 503, "Could not start policy activation transaction",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    PQclear(begin);
                    const char *policy_params[1] = { pid };
                    const int policy_lengths[1] = { (int)strlen(policy_params[0]) };
                    PGresult *policy = db_simple(conn,
                        "SELECT institution_id,created_by,approved_by,status "
                        "FROM device_trust_policies WHERE id=$1 FOR UPDATE",
                        1, policy_params, policy_lengths);
                    if (!policy || PQresultStatus(policy) != PGRES_TUPLES_OK ||
                        PQntuples(policy) != 1) {
                        if (policy) PQclear(policy);
                        PQexec(conn, "ROLLBACK");
                        db_release(conn, 0);
                        dt_send_error(client_fd, 404, "Device trust policy was not found",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    char policy_inst[64], created_by[65], approved_by[65], policy_status[33];
                    snprintf(policy_inst, sizeof(policy_inst), "%s", PQgetvalue(policy, 0, 0));
                    snprintf(created_by, sizeof(created_by), "%s", PQgetvalue(policy, 0, 1));
                    snprintf(approved_by, sizeof(approved_by), "%s", PQgetvalue(policy, 0, 2));
                    snprintf(policy_status, sizeof(policy_status), "%s", PQgetvalue(policy, 0, 3));
                    PQclear(policy);
                    int is_platform_owner = policy_actor.role == ROLE_PLATFORM_OWNER;
                    if ((!is_platform_owner &&
                         strcmp(policy_inst, policy_actor.institution_id) != 0) ||
                        strcmp(policy_status, "approved") != 0 || !created_by[0] ||
                        !approved_by[0] || strcmp(created_by, approved_by) == 0 ||
                        strcmp(created_by, policy_actor.user_id) == 0) {
                        PQexec(conn, "ROLLBACK");
                        db_release(conn, 0);
                        dt_send_error(client_fd, 409, "Policy is not eligible for independent activation",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    const char *tenant_params[1] = { policy_inst };
                    const int tenant_lengths[1] = { (int)strlen(policy_inst) };
                    PGresult *tenant = db_simple(conn,
                        "SELECT id FROM tenants WHERE id=$1 FOR UPDATE",
                        1, tenant_params, tenant_lengths);
                    if (!tenant || PQresultStatus(tenant) != PGRES_TUPLES_OK ||
                        PQntuples(tenant) != 1) {
                        if (tenant) PQclear(tenant);
                        PQexec(conn, "ROLLBACK");
                        db_release(conn, 0);
                        dt_send_error(client_fd, 409, "Policy institution could not be locked for activation",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    PQclear(tenant);
                    PGresult *retire = db_simple(conn,
                        "UPDATE device_trust_policies SET status='retired',"
                        "updated_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000 "
                        "WHERE institution_id=$1 AND status='active'",
                        1, tenant_params, tenant_lengths);
                    if (!retire || PQresultStatus(retire) != PGRES_COMMAND_OK) {
                        if (retire) PQclear(retire);
                        PQexec(conn, "ROLLBACK");
                        db_release(conn, 0);
                        dt_send_error(client_fd, 503, "Existing active policy could not be retired",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    PQclear(retire);
                    const char *activate_params[3] = { pid, policy_inst, policy_actor.user_id };
                    const int activate_lengths[3] = {
                        (int)strlen(activate_params[0]), (int)strlen(activate_params[1]),
                        (int)strlen(activate_params[2])
                    };
                    PGresult *activate = db_simple(conn,
                        "UPDATE device_trust_policies SET status='active',"
                        "activated_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000,"
                        "updated_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000 "
                        "WHERE id=$1 AND institution_id=$2 AND status='approved' "
                        "AND approved_by<>'' AND created_by<>$3",
                        3, activate_params, activate_lengths);
                    if (!activate || PQresultStatus(activate) != PGRES_COMMAND_OK ||
                        strcmp(PQcmdTuples(activate), "1") != 0) {
                        if (activate) PQclear(activate);
                        PQexec(conn, "ROLLBACK");
                        db_release(conn, 0);
                        dt_send_error(client_fd, 409, "Policy activation failed revalidation",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    PQclear(activate);
                    PGresult *commit = PQexec(conn, "COMMIT");
                    if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
                        if (commit) PQclear(commit);
                        PQexec(conn, "ROLLBACK");
                        db_release(conn, 0);
                        dt_send_error(client_fd, 503, "Policy activation transaction could not commit",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    PQclear(commit);
                    dt_audit_log(policy_actor.user_id, "DEVICE_TRUST_POLICY_ACTIVATED", pid);
                    db_release(conn, 0);
                    char resp[256];
                    snprintf(resp, sizeof(resp), "{\"status\":\"activated\",\"policy_id\":\"%s\"}", pid);
                    dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                    return;
                }
            }
        }
    }

    /* =========================================================================
     * 5. POST /api/v1/exam-launch/authorize: Master Launch Authorization Gate
     * Integrates Modules 9, 10, 11, 12, 13
     * ========================================================================= */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/exam-launch/authorize") == 0) {
        /* This gate issues an exam URL and a one-time launch token. It must
         * never be reachable without an authenticated, institution-scoped
         * operator session. Otherwise any caller that knows a device, student
         * and examination identifier could obtain a launch credential. */
        if (auth_rc != 0) {
            db_release(conn, 0);
            dt_send_error(client_fd, 401,
                          "Authentication is required to authorize an exam launch",
                          origin, extra_headers, extra_len);
            return;
        }

        char dev_id[64] = {0}, stu_id[64] = {0}, exam_id[64] = {0};
        ctrl_json_string(body, "device_id", dev_id, sizeof(dev_id));
        ctrl_json_string(body, "student_id", stu_id, sizeof(stu_id));
        ctrl_json_string(body, "examination_id", exam_id, sizeof(exam_id));

        if (!dev_id[0] || !stu_id[0] || !exam_id[0]) {
            db_release(conn, 0);
            dt_send_error(client_fd, 400, "device_id, student_id, and examination_id are required", origin, extra_headers, extra_len);
            return;
        }

        /* Step 1: Device Trust Check */
        char dt_outcome[32] = {0}, dt_reason[512] = {0}, dt_pol_id[64] = {0};
        evaluate_device_trust(conn, dev_id, dt_outcome, sizeof(dt_outcome),
                              dt_reason, sizeof(dt_reason), dt_pol_id, sizeof(dt_pol_id));

        if (strcmp(dt_outcome, "ALLOW") != 0) {
            db_release(conn, 0);
            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"error\":\"DEVICE_TRUST_FAILED\",\"outcome\":\"%s\",\"device_id\":\"%s\",\"reason\":\"%s\"}",
                dt_outcome, dev_id, dt_reason);
            dt_send_json(client_fd, 403, resp, origin, extra_headers, extra_len);
            return;
        }

        /* Step 2: Student Assignment Check (Device Assignment Boundary) */
        const char *asg_p[1] = { dev_id };
        int asg_l[1] = { (int)strlen(dev_id) };
        PGresult *asg_r = db_simple(conn,
            "SELECT assigned_student_id FROM device_assignments WHERE device_id = $1 AND status = 'active' LIMIT 1", 1, asg_p, asg_l);
        if (asg_r) {
            if (PQntuples(asg_r) > 0) {
                const char *asg_stu = PQgetvalue(asg_r, 0, 0);
                if (asg_stu[0] && strcmp(asg_stu, stu_id) != 0) {
                    PQclear(asg_r);
                    db_release(conn, 0);
                    dt_send_error(client_fd, 403, "Device is actively assigned to another candidate (identity mismatch)", origin, extra_headers, extra_len);
                    return;
                }
            }
            PQclear(asg_r);
        }

        /* Step 3: Student Eligibility (Module 10) */
        const char *st_p[2] = { stu_id, exam_id };
        int st_l[2] = { (int)strlen(stu_id), (int)strlen(exam_id) };
        PGresult *st_r = db_simple(conn,
            "SELECT s.academic_status, s.administrative_hold, r.registration_status, r.eligibility_status, "
            "e.status, e.exam_url, e.allowed_origins, e.institution_id "
            "FROM students s "
            "JOIN exam_registrations r ON s.id = r.student_id AND r.examination_id = $2 "
            "JOIN examinations e ON e.id = $2 "
            "WHERE (s.id = $1 OR s.roll_no = $1)", 2, st_p, st_l);

        if (!st_r || PQntuples(st_r) == 0) {
            if (st_r) PQclear(st_r);
            db_release(conn, 0);
            dt_send_error(client_fd, 403, "Student is not registered or eligible for this examination", origin, extra_headers, extra_len);
            return;
        }

        const char *acad_stat = PQgetvalue(st_r, 0, 0);
        const char *adm_hold = PQgetvalue(st_r, 0, 1);
        const char *reg_stat = PQgetvalue(st_r, 0, 2);
        const char *elig_stat = PQgetvalue(st_r, 0, 3);
        const char *ex_stat = PQgetvalue(st_r, 0, 4);
        char ex_url[512] = {0}, ex_orgs[512] = {0}, ex_inst[64] = {0};
        strncpy(ex_url, PQgetvalue(st_r, 0, 5), sizeof(ex_url) - 1);
        strncpy(ex_orgs, PQgetvalue(st_r, 0, 6), sizeof(ex_orgs) - 1);
        strncpy(ex_inst, PQgetvalue(st_r, 0, 7), sizeof(ex_inst) - 1);
        PQclear(st_r);

        /* Institution scope: only the platform owner may authorize a launch
         * across tenants. Everyone else is confined to their own institution. */
        if (sess.role != ROLE_PLATFORM_OWNER &&
            (!sess.institution_id[0] || strcmp(ex_inst, sess.institution_id) != 0)) {
            db_release(conn, 0);
            dt_send_error(client_fd, 403,
                          "Examination is outside the authenticated institution",
                          origin, extra_headers, extra_len);
            return;
        }

        /* Step 3b: Check for individual candidate-assigned URL override.
         * If the administrator assigned a candidate-specific external exam URL
         * via exam_student_assignments.assigned_exam_url, that takes precedence
         * over the examination-level exam_url. The individual assignment must
         * be active and the URL must pass the same HTTPS validation. */
        {
            const char *aurl_p[2] = { exam_id, stu_id };
            int aurl_l[2] = { (int)strlen(exam_id), (int)strlen(stu_id) };
            PGresult *aurl_r = db_simple(conn,
                "SELECT assigned_exam_url FROM exam_student_assignments "
                "WHERE exam_id = $1 AND student_id = $2 "
                "AND assignment_status = 'active' "
                "AND assigned_exam_url <> '' LIMIT 1",
                2, aurl_p, aurl_l);
            if (aurl_r && PQresultStatus(aurl_r) == PGRES_TUPLES_OK &&
                PQntuples(aurl_r) > 0) {
                const char *candidate_url = PQgetvalue(aurl_r, 0, 0);
                if (candidate_url && candidate_url[0]) {
                    memset(ex_url, 0, sizeof(ex_url));
                    strncpy(ex_url, candidate_url, sizeof(ex_url) - 1);
                }
            }
            if (aurl_r) PQclear(aurl_r);
        }

        /* The URL that will be handed to the kiosk must still be an approved
         * HTTPS exam endpoint. Never deliver an unvalidated URL. */
        char url_error[192] = {0};
        if (platform_validate_exam_url(ex_url, url_error, sizeof(url_error)) != 0) {
            db_release(conn, 0);
            dt_send_error(client_fd, 403,
                          url_error[0] ? url_error : "Examination URL is not approved",
                          origin, extra_headers, extra_len);
            return;
        }

        if (strcmp(acad_stat, "active") != 0 || strcmp(adm_hold, "t") == 0) {
            db_release(conn, 0);
            dt_send_error(client_fd, 403, "Student is suspended or has an administrative hold", origin, extra_headers, extra_len);
            return;
        }

        if (strcmp(reg_stat, "approved") != 0 && strcmp(reg_stat, "exception_approved") != 0) {
            db_release(conn, 0);
            dt_send_error(client_fd, 403, "Student registration is not approved", origin, extra_headers, extra_len);
            return;
        }

        if (strcmp(elig_stat, "eligible") != 0) {
            db_release(conn, 0);
            dt_send_error(client_fd, 403, "Student is not marked eligible for this examination", origin, extra_headers, extra_len);
            return;
        }

        if (strcmp(ex_stat, "cancelled") == 0 || strcmp(ex_stat, "closed") == 0) {
            db_release(conn, 0);
            dt_send_error(client_fd, 403, "Examination is closed or cancelled", origin, extra_headers, extra_len);
            return;
        }

        /* Step 4: Issue One-Time Launch Token. Never fall back to a non-CSPRNG
         * for a launch credential: fail closed instead. */
        unsigned char rand_token[32];
        if (RAND_bytes(rand_token, sizeof(rand_token)) != 1) {
            db_release(conn, 0);
            dt_send_error(client_fd, 503,
                          "Secure launch token generation failed; launch was not authorized",
                          origin, extra_headers, extra_len);
            return;
        }
        char token_str[65];
        for (int i = 0; i < 32; i++) sprintf(token_str + (i * 2), "%02x", rand_token[i]);
        token_str[64] = '\0';

        char token_hash[65];
        sha256_hex_str((const unsigned char *)token_str, strlen(token_str), token_hash);

        char auth_id[64];
        snprintf(auth_id, sizeof(auth_id), "auth_%ld_%d", (long)time(NULL), rand() % 10000);

        char sess_id[64];
        snprintf(sess_id, sizeof(sess_id), "sess_lch_%ld_%d", (long)time(NULL), rand() % 10000);

        /* Create session record. Use the examination's real institution; never
         * substitute a hard-coded tenant identifier. */
        const char *ses_p[6] = { sess_id, ex_inst, exam_id, stu_id, dev_id, "launching" };
        int ses_l[6];
        for (int i = 0; i < 6; i++) ses_l[i] = (int)strlen(ses_p[i]);

        PGresult *ins_s = db_simple(conn,
            "INSERT INTO exam_sessions (id, institution_id, examination_id, student_id, device_id, status, "
            "authorized_at, launched_at, created_at, updated_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 6, ses_p, ses_l);
        int session_saved = ins_s && PQresultStatus(ins_s) == PGRES_COMMAND_OK;
        if (ins_s) PQclear(ins_s);
        if (!session_saved) {
            db_release(conn, 0);
            OPENSSL_cleanse(token_str, sizeof(token_str));
            dt_send_error(client_fd, 503,
                          "Could not persist the exam session; launch was not authorized",
                          origin, extra_headers, extra_len);
            return;
        }

        /* Insert launch authorization */
        const char *lp[5] = { auth_id, sess_id, token_hash, ex_url, ex_orgs };
        int ll[5];
        for (int i = 0; i < 5; i++) ll[i] = (int)strlen(lp[i]);

        PGresult *ins_l = db_simple(conn,
            "INSERT INTO exam_launch_authorizations (id, session_id, token_hash, exam_url, allowed_origins, expires_at, created_at) "
            "VALUES ($1, $2, $3, $4, $5, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 + 120000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
            5, lp, ll);
        int launch_saved = ins_l && PQresultStatus(ins_l) == PGRES_COMMAND_OK;
        if (ins_l) PQclear(ins_l);
        if (!launch_saved) {
            /* Do not leave an orphaned session that looks launchable. */
            const char *close_p[1] = { sess_id };
            int close_l[1] = { (int)strlen(sess_id) };
            PGresult *closed = db_simple(conn,
                "UPDATE exam_sessions SET status='closed',closure_reason='LAUNCH_TOKEN_PERSIST_FAILED',"
                "closed_at=EXTRACT(EPOCH FROM NOW())::BIGINT * 1000,"
                "updated_at=EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id=$1",
                1, close_p, close_l);
            if (closed) PQclear(closed);
            db_release(conn, 0);
            OPENSSL_cleanse(token_str, sizeof(token_str));
            dt_send_error(client_fd, 503,
                          "Could not persist the launch authorization; launch was not authorized",
                          origin, extra_headers, extra_len);
            return;
        }

        record_device_audit(conn, dev_id, ex_inst,
                            stu_id, "EXAM_LAUNCH_AUTHORIZED", exam_id);
        dt_audit_log(stu_id, "EXAM_LAUNCH_AUTHORIZED", dev_id);

        char ev_id[64];
        snprintf(ev_id, sizeof(ev_id), "ev_auth_%ld_%d", (long)time(NULL), rand() % 10000);
        const char *ev_p[4] = { ev_id, sess_id, exam_id, ex_inst };
        int ev_l[4];
        for (int i = 0; i < 4; i++) ev_l[i] = (int)strlen(ev_p[i]);
        PGresult *ins_ev = db_simple(conn,
            "INSERT INTO exam_session_events (id, session_id, examination_id, institution_id, event_type, payload_json, created_at) "
            "VALUES ($1, $2, $3, $4, 'authorized', '{}', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
            4, ev_p, ev_l);
        if (ins_ev) PQclear(ins_ev);

        db_release(conn, 0);
        char resp[2048];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"launch_authorized\",\"authorization_id\":\"%s\",\"session_id\":\"%s\","
            "\"device_id\":\"%s\",\"student_id\":\"%s\",\"examination_id\":\"%s\",\"exam_url\":\"%s\","
            "\"allowed_origins\":\"%s\",\"launch_token\":\"%s\",\"expires_in_sec\":120}",
            auth_id, sess_id, dev_id, stu_id, exam_id, ex_url, ex_orgs, token_str);
        dt_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
        return;
    }

    db_release(conn, 0);
    dt_send_error(client_fd, 404, "Device trust endpoint not found", origin, extra_headers, extra_len);
}
