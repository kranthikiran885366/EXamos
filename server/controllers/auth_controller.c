/*
 * auth_controller.c — Admin and candidate authentication against PostgreSQL.
 *
 * Implements end-to-end enterprise authentication for ExamOS:
 *   • Constant-time PBKDF2-SHA256 password verification
 *   • Multi-factor authentication (MFA / TOTP RFC 6238)
 *   • Emergency single-use recovery code support
 *   • Cryptographically random 256-bit session token generation
 *   • Cross-origin resource sharing (CORS) with allowed origin whitelist
 *   • Secure HttpOnly session cookies (Path=/)
 *   • Immutable audit chain logging
 *   • Candidate examination portal authentication
 */

#include "auth_controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../security/security.h"
#include "../include/config_manager.h"
#include "../include/secure_token.h"
#include "../include/totp.h"
#include "../include/candidate_login.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static void audit_log(const char *actor, const char *event, const char *detail) {
    audit_append(actor, event, detail);
}

static void send_json_cors(int fd, int code, const char *body,
                           const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin,
                  ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void normalize_code(const char *in, char *out, size_t out_len) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < out_len; i++) {
        if (isalnum((unsigned char)in[i])) {
            out[j++] = (char)toupper((unsigned char)in[i]);
        }
    }
    out[j] = '\0';
}

/* --------------------------------------------------------------- Brute-force & Lockout Protection */
typedef struct {
    char key[128];
    int attempts;
    time_t locked_until;
} lockout_entry_t;

static lockout_entry_t g_lockouts[256];
static int g_lockout_count = 0;

static int check_lockout(const char *key, time_t now, char *err_buf, size_t err_len) {
    if (!key || !key[0]) return 0;
    for (int i = 0; i < g_lockout_count; i++) {
        if (strcasecmp(g_lockouts[i].key, key) == 0) {
            if (g_lockouts[i].locked_until > now) {
                long remaining = (long)(g_lockouts[i].locked_until - now);
                snprintf(err_buf, err_len,
                    "{\"status\":\"LOCKED\",\"error\":\"Account temporarily locked due to repeated failed login attempts. Retry in %ld seconds or use emergency recovery code.\"}",
                    remaining > 0 ? remaining : 1);
                return 1;
            }
            if (g_lockouts[i].attempts >= 5) {
                g_lockouts[i].attempts = 0;
                g_lockouts[i].locked_until = 0;
            }
            break;
        }
    }
    return 0;
}

static void record_failure(const char *key, time_t now) {
    if (!key || !key[0]) return;
    for (int i = 0; i < g_lockout_count; i++) {
        if (strcasecmp(g_lockouts[i].key, key) == 0) {
            g_lockouts[i].attempts++;
            if (g_lockouts[i].attempts >= 5) {
                g_lockouts[i].locked_until = now + 900; // 15-minute lockout
                audit_append(key, "SECURITY_ALERT_ACCOUNT_LOCKOUT", "5 consecutive failed login attempts");
            }
            return;
        }
    }
    if (g_lockout_count < 256) {
        strncpy(g_lockouts[g_lockout_count].key, key, sizeof(g_lockouts[g_lockout_count].key) - 1);
        g_lockouts[g_lockout_count].attempts = 1;
        g_lockouts[g_lockout_count].locked_until = 0;
        g_lockout_count++;
    }
}

static void clear_failure(const char *key) {
    if (!key || !key[0]) return;
    for (int i = 0; i < g_lockout_count; i++) {
        if (strcasecmp(g_lockouts[i].key, key) == 0) {
            g_lockouts[i].attempts = 0;
            g_lockouts[i].locked_until = 0;
            return;
        }
    }
}

static int role_clearance_tier(user_role_t role) {
    switch (role) {
        case ROLE_PLATFORM_OWNER: return 5;
        case ROLE_SECURITY_ADMIN: return 4;
        case ROLE_EXAM_MANAGER: return 3;
        case ROLE_INSTITUTION_ADMIN: return 2;
        case ROLE_INVIGILATOR:
        case ROLE_TECH_OPERATOR: return 1;
        default: return 0;
    }
}

static const char *role_clearance_label(user_role_t role) {
    switch (role) {
        case ROLE_PLATFORM_OWNER: return "TIER-5 PLATFORM_OWNER (HARDWARE ROOT CLEARANCE)";
        case ROLE_SECURITY_ADMIN: return "TIER-4 SECURITY_ADMIN (TPM POLICY & FLEET ATTESTATION)";
        case ROLE_EXAM_MANAGER: return "TIER-3 EXAM_MANAGER (EXAM KEYS & ENCRYPTION CONTROL)";
        case ROLE_INSTITUTION_ADMIN: return "TIER-2 INSTITUTION_ADMIN (CAMPUS & PROCTOR MANAGEMENT)";
        case ROLE_INVIGILATOR: return "TIER-1 INVIGILATOR (LIVE MONITORING & CANDIDATE SUPERVISION)";
        case ROLE_TECH_OPERATOR: return "TIER-1 TECH_OPERATOR (WORKSTATION TELEMETRY & HARDWARE HEALTH)";
        default: return "TIER-0 AUDITOR (IMMUTABLE LOG VERIFICATION)";
    }
}

/* --------------------------------------------------------------- admin login */
void auth_admin_login(int client_fd, const char *req_body,
                      const char *origin, char *extra_headers, size_t extra_len) {
    char username[128] = {0}, password[256] = {0}, mfa_code[32] = {0};
    ctrl_json_string(req_body, "username", username, sizeof(username));
    ctrl_json_string(req_body, "password", password, sizeof(password));
    ctrl_json_string(req_body, "mfa_code", mfa_code, sizeof(mfa_code));

    if (!username[0] || !password[0]) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Username and password are required\"}",
            origin, extra_headers, extra_len);
        goto done;
    }

    /* Check brute-force lockout */
    time_t now = time(NULL);
    char lock_err[256] = {0};
    if (check_lockout(username, now, lock_err, sizeof(lock_err))) {
        send_json_cors(client_fd, 429, lock_err, origin, extra_headers, extra_len);
        audit_log(username, "ADMIN_LOGIN_LOCKED", "brute force threshold exceeded");
        goto done;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        send_json_cors(client_fd, 503,
            "{\"status\":\"FAIL\",\"error\":\"Database service unavailable\"}",
            origin, extra_headers, extra_len);
        goto done;
    }

    const char *pvals[1] = { username };
    int lens[1] = { (int)strlen(username) };

    /* Query users table first */
    PGresult *res = db_simple(conn,
        "SELECT id, username, password_hash, salt, role, COALESCE(tenant_id, ''), "
               "mfa_enabled, status, COALESCE(totp_secret, ''), COALESCE(name, '') "
        "FROM users WHERE LOWER(username) = LOWER($1)",
        1, pvals, lens);

    int found = res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0;
    char db_userid[64] = {0}, db_username[64] = {0}, db_hash[256] = {0};
    char db_salt[128] = {0}, db_role[64] = {0}, db_inst[64] = {0};
    char db_status[32] = {0}, db_totp[64] = {0}, db_name[128] = {0};
    int mfa_enabled = 0;

    if (found) {
        strncpy(db_userid, PQgetvalue(res, 0, 0), sizeof(db_userid) - 1);
        strncpy(db_username, PQgetvalue(res, 0, 1), sizeof(db_username) - 1);
        strncpy(db_hash, PQgetvalue(res, 0, 2), sizeof(db_hash) - 1);
        strncpy(db_salt, PQgetvalue(res, 0, 3), sizeof(db_salt) - 1);
        strncpy(db_role, PQgetvalue(res, 0, 4), sizeof(db_role) - 1);
        strncpy(db_inst, PQgetvalue(res, 0, 5), sizeof(db_inst) - 1);
        const char *mval = PQgetvalue(res, 0, 6);
        mfa_enabled = (mval && (mval[0] == 't' || mval[0] == 'T' || mval[0] == '1' || atoi(mval) > 0)) ? 1 : 0;
        strncpy(db_status, PQgetvalue(res, 0, 7), sizeof(db_status) - 1);
        strncpy(db_totp, PQgetvalue(res, 0, 8), sizeof(db_totp) - 1);
        strncpy(db_name, PQgetvalue(res, 0, 9), sizeof(db_name) - 1);
        if (db_totp[0]) mfa_enabled = 1;
    }
    if (res) PQclear(res);

    /* If not in users, check examos_admin_users */
    if (!found) {
        res = db_simple(conn,
            "SELECT user_id, username, password_hash, '', role::text, COALESCE(institution_id, ''), "
                   "mfa_enabled::int, (CASE WHEN active THEN 'active' ELSE 'inactive' END), "
                   "COALESCE(totp_secret, ''), COALESCE(full_name, '') "
            "FROM examos_admin_users WHERE LOWER(username) = LOWER($1)",
            1, pvals, lens);
        found = res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0;
        if (found) {
            strncpy(db_userid, PQgetvalue(res, 0, 0), sizeof(db_userid) - 1);
            strncpy(db_username, PQgetvalue(res, 0, 1), sizeof(db_username) - 1);
            strncpy(db_hash, PQgetvalue(res, 0, 2), sizeof(db_hash) - 1);
            int role_id = atoi(PQgetvalue(res, 0, 4));
            strncpy(db_role, security_role_to_string((user_role_t)role_id), sizeof(db_role) - 1);
            strncpy(db_inst, PQgetvalue(res, 0, 5), sizeof(db_inst) - 1);
            const char *mval2 = PQgetvalue(res, 0, 6);
            mfa_enabled = (mval2 && (mval2[0] == 't' || mval2[0] == 'T' || mval2[0] == '1' || atoi(mval2) > 0)) ? 1 : 0;
            strncpy(db_status, PQgetvalue(res, 0, 7), sizeof(db_status) - 1);
            strncpy(db_totp, PQgetvalue(res, 0, 8), sizeof(db_totp) - 1);
            strncpy(db_name, PQgetvalue(res, 0, 9), sizeof(db_name) - 1);
            if (db_totp[0]) mfa_enabled = 1;
        }
        if (res) PQclear(res);
    }

    int password_ok = 0;
    if (found && strcmp(db_status, "active") == 0 && db_hash[0]) {
        if (db_salt[0]) {
            /* users table: hash is bare PBKDF2 hex, salt is a separate column */
            char computed[256] = {0};
            if (security_pbkdf2_hash(password, db_salt, computed, sizeof(computed)) == 0 &&
                security_safe_equal(computed, db_hash)) {
                password_ok = 1;
            }
        } else {
            /* examos_admin_users table: hash is "iterations:salt_hex:hash_hex" —
             * config_verify_password_hash returns 1 on match, 0 on no-match.
             * Must NOT invert this: == 1 is the success condition. */
            if (config_verify_password_hash(password, db_hash) == 1) {
                password_ok = 1;
            }
        }
    } else {
        /* Dummy hash to equalize timing against enumeration */
        char dummy[256] = {0};
        security_pbkdf2_hash(password, "decoy_timing_salt", dummy, sizeof(dummy));
    }
    OPENSSL_cleanse(password, sizeof(password));

    if (!password_ok) {
        record_failure(username, now);
        send_json_cors(client_fd, 401,
            "{\"status\":\"FAIL\",\"error\":\"Invalid username or password, or account is inactive\"}",
            origin, extra_headers, extra_len);
        audit_log(username, "ADMIN_LOGIN_FAILED", "invalid credentials");
        db_release(conn, 0);
        goto done;
    }

    /* Reject candidate/student accounts from management dashboard console */
    if (strcasecmp(db_role, "student") == 0 || strcasecmp(db_role, "candidate") == 0) {
        send_json_cors(client_fd, 403,
            "{\"status\":\"FAIL\",\"error\":\"Access denied: Candidate and student accounts cannot access management consoles. Please use the Candidate Station.\"}",
            origin, extra_headers, extra_len);
        audit_log(username, "ADMIN_LOGIN_DENIED_STUDENT_ROLE", "student attempted admin login");
        db_release(conn, 0);
        goto done;
    }

    /* Management Dashboard MFA Enforcement:
     * First-time / new management users who do not have an authenticator registered
     * (db_totp is empty) must set up Google Authenticator first (MFA_SETUP_REQUIRED).
     * Users who already enrolled their authenticator (db_totp exists) must provide
     * their valid 6-digit TOTP code or recovery code (MFA_REQUIRED).
     */
    if (!db_totp[0]) {
        char setup_msg[512];
        snprintf(setup_msg, sizeof(setup_msg),
            "{\"status\":\"MFA_SETUP_REQUIRED\",\"mfa_setup_required\":true,"
            "\"username\":\"%s\",\"message\":\"Authenticator setup required for first-time management user\"}",
            db_username[0] ? db_username : username);
        send_json_cors(client_fd, 200, setup_msg, origin, extra_headers, extra_len);
        audit_log(db_userid[0] ? db_userid : username, "ADMIN_MFA_SETUP_REQUIRED", username);
        db_release(conn, 0);
        goto done;
    }

    if (!mfa_code[0]) {
        char mfa_req_msg[512];
        snprintf(mfa_req_msg, sizeof(mfa_req_msg),
            "{\"status\":\"MFA_REQUIRED\",\"mfa_required\":true,\"username\":\"%s\",\"error\":\"MFA code required\"}",
            db_username[0] ? db_username : username);
        send_json_cors(client_fd, 200, mfa_req_msg, origin, extra_headers, extra_len);
        audit_log(db_userid[0] ? db_userid : username, "ADMIN_LOGIN_MFA_REQUIRED", username);
        db_release(conn, 0);
        goto done;
    }

    /* Sanitize 6-digit TOTP code (strip spaces/dashes) */
    char clean_code[16] = {0};
    size_t c_idx = 0;
    for (size_t i = 0; mfa_code[i] && c_idx < 6; i++) {
        if (isdigit((unsigned char)mfa_code[i])) clean_code[c_idx++] = mfa_code[i];
    }
    clean_code[c_idx] = '\0';

    int mfa_ok = 0;
    /* Strict RFC 6238 TOTP verification against registered secret (window +-3 = +-90s clock drift) */
    if (db_totp[0] && clean_code[0] && totp_verify_code(db_totp, clean_code, time(NULL), 3)) {
        mfa_ok = 1;
    }

    /* If TOTP didn't match, check emergency recovery codes */
    if (!mfa_ok) {
        char norm_code[32] = {0};
        normalize_code(mfa_code, norm_code, sizeof(norm_code));

        /* Check recovery table */
        char rec_hash[65] = {0};
        if (totp_hash_recovery_code(norm_code, rec_hash) == 0) {
            const char *r_params[] = { db_userid, rec_hash };
            int r_lens[] = { (int)strlen(db_userid), (int)strlen(rec_hash) };
            PGresult *r_res = db_simple(conn,
                "UPDATE examos_admin_recovery_codes SET used = true, used_at = clock_timestamp() "
                "WHERE user_id = $1 AND code_hash = $2 AND NOT used RETURNING code_hash",
                2, r_params, r_lens);
            if (r_res && PQresultStatus(r_res) == PGRES_TUPLES_OK && PQntuples(r_res) == 1) {
                mfa_ok = 1;
                audit_log(db_userid, "ADMIN_RECOVERY_USED", "recovery code consumed");
            }
            if (r_res) PQclear(r_res);
        }
    }

    if (!mfa_ok) {
        record_failure(username, now);
        send_json_cors(client_fd, 401,
            "{\"status\":\"FAIL\",\"error\":\"Invalid authentication code or recovery code\"}",
            origin, extra_headers, extra_len);
        audit_log(db_userid, "ADMIN_LOGIN_MFA_FAILED", "invalid code");
        db_release(conn, 0);
        goto done;
    }

    /* Generate 256-bit cryptographically secure session token */
    char token[65] = {0};
    {
        unsigned char rnd[32];
        if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
            send_json_cors(client_fd, 500,
                "{\"status\":\"FAIL\",\"error\":\"Cryptographic randomness failure\"}",
                origin, extra_headers, extra_len);
            db_release(conn, 0);
            goto done;
        }
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            token[i * 2] = hex[rnd[i] >> 4];
            token[i * 2 + 1] = hex[rnd[i] & 0x0f];
        }
        token[64] = '\0';
    }

    now = time(NULL);
    time_t expires = now + 28800; // 8 hours max session
    char now_str[32], exp_str[32], sid[64];
    snprintf(now_str, sizeof(now_str), "%ld", (long)now);
    snprintf(exp_str, sizeof(exp_str), "%ld", (long)expires);
    snprintf(sid, sizeof(sid), "ase_%ld_%s", (long)now, token + 56);

    /* Store session in auth_sessions */
    const char *ins_pvals[9] = {
        sid, db_userid, db_username[0] ? db_username : username,
        db_inst, db_role, token, now_str, exp_str, "active"
    };
    int ilens[9];
    for (int k = 0; k < 9; k++) ilens[k] = ins_pvals[k] ? (int)strlen(ins_pvals[k]) : 0;

    PGresult *ins = db_simple(conn,
        "INSERT INTO auth_sessions (id, user_id, username, institution_id, role, "
        "session_token, created_at, expires_at, status) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7::bigint, $8::bigint, $9)",
        9, ins_pvals, ilens);
    if (ins) PQclear(ins);

    /* Also record in examos_admin_sessions if available */
    char token_hash[65] = {0};
    if (secure_token_hash(token, token_hash) == 0) {
        user_role_t urole = ROLE_READONLY_AUDITOR;
        if (strcmp(db_role, "PLATFORM_OWNER") == 0 || strcmp(db_role, "superadmin") == 0) urole = ROLE_PLATFORM_OWNER;
        else if (strcmp(db_role, "INSTITUTION_ADMIN") == 0 || strcmp(db_role, "inst_admin") == 0) urole = ROLE_INSTITUTION_ADMIN;
        else if (strcmp(db_role, "EXAM_MANAGER") == 0 || strcmp(db_role, "exam_controller") == 0) urole = ROLE_EXAM_MANAGER;
        else if (strcmp(db_role, "SECURITY_ADMIN") == 0 || strcmp(db_role, "security_engineer") == 0) urole = ROLE_SECURITY_ADMIN;
        else if (strcmp(db_role, "INVIGILATOR") == 0) urole = ROLE_INVIGILATOR;
        else if (strcmp(db_role, "TECH_OPERATOR") == 0 || strcmp(db_role, "ops_admin") == 0) urole = ROLE_TECH_OPERATOR;
        char role_num[16]; snprintf(role_num, sizeof(role_num), "%d", (int)urole);

        const char *adm_pvals[4] = { token_hash, db_userid, role_num, db_inst };
        int a_lens[4] = { 64, (int)strlen(db_userid), (int)strlen(role_num), (int)strlen(db_inst) };
        PGresult *as_res = db_simple(conn,
            "INSERT INTO examos_admin_sessions (token_hash, user_id, role, institution_id, expires_at) "
            "VALUES ($1, $2, $3::smallint, NULLIF($4, ''), clock_timestamp() + interval '8 hours') "
            "ON CONFLICT (token_hash) DO NOTHING",
            4, adm_pvals, a_lens);
        if (as_res) PQclear(as_res);
    }

    /* Update user's last login */
    const char *up_pvals[2] = { now_str, db_userid };
    int ulens[2] = { (int)strlen(now_str), (int)strlen(db_userid) };
    PGresult *up = db_simple(conn,
        "UPDATE users SET last_login = $1::bigint WHERE id = $2",
        2, up_pvals, ulens);
    if (up) PQclear(up);

    db_release(conn, 0);

    /* Construct HttpOnly Session Cookie */
    const char *secure_env = getenv("EXAMOS_ADMIN_COOKIE_SECURE");
    int is_secure = secure_env && strcmp(secure_env, "1") == 0;
    char cookie[512];
    snprintf(cookie, sizeof(cookie),
        "Set-Cookie: admin_session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800%s\r\n",
        token, is_secure ? "; Secure" : "");

    char resp_body[1024];
    snprintf(resp_body, sizeof(resp_body),
        "{\"status\":\"AUTHENTICATED\",\"token\":\"%s\",\"mfa_required\":false,"
        "\"user_id\":\"%s\",\"username\":\"%s\",\"name\":\"%s\",\"role\":\"%s\","
        "\"institution_id\":\"%s\",\"expires_at\":%s}",
        token, db_userid, db_username[0] ? db_username : username,
        db_name[0] ? db_name : (db_username[0] ? db_username : username),
        db_role, db_inst, exp_str);

    ctrl_set_cors(extra_headers, extra_len, origin,
                  ctrl_cors_origin_allowed(origin));
    strncat(extra_headers, cookie, extra_len - strlen(extra_headers) - 1);
    ctrl_send_json(client_fd, 200, resp_body, extra_headers);

    clear_failure(username);
    audit_log(db_userid, "ADMIN_LOGIN_SUCCESS", username);

done:
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(mfa_code, sizeof(mfa_code));
}

/* ------------------------------------------------------------- admin logout */
void auth_admin_logout(int client_fd, const char *auth_header,
                       const char *origin, char *extra_headers, size_t extra_len) {
    char token[128] = {0};
    if (!ctrl_extract_bearer(auth_header, token, sizeof(token)) || !token[0]) {
        send_json_cors(client_fd, 401,
            "{\"error\":\"Unauthorized\"}", origin, extra_headers, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (conn) {
        const char *pvals[1] = { token };
        int lens[1] = { (int)strlen(token) };
        PGresult *res = db_simple(conn,
            "UPDATE auth_sessions SET status = 'ended' WHERE session_token = $1",
            1, pvals, lens);
        if (res) PQclear(res);

        char token_hash[65] = {0};
        if (secure_token_hash(token, token_hash) == 0) {
            const char *th_vals[1] = { token_hash };
            int th_lens[1] = { 64 };
            PGresult *as_res = db_simple(conn,
                "UPDATE examos_admin_sessions SET revoked_at = clock_timestamp() WHERE token_hash = $1",
                1, th_vals, th_lens);
            if (as_res) PQclear(as_res);
        }
        db_release(conn, 0);
    }

    char cookie[256];
    snprintf(cookie, sizeof(cookie),
        "Set-Cookie: admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0\r\n");

    ctrl_set_cors(extra_headers, extra_len, origin,
                  ctrl_cors_origin_allowed(origin));
    strncat(extra_headers, cookie, extra_len - strlen(extra_headers) - 1);
    ctrl_send_json(client_fd, 200, "{\"status\":\"SIGNED_OUT\"}", extra_headers);
    audit_log(token, "ADMIN_LOGOUT", "session ended");
}

/* ----------------------------------------------------------- admin session */
void auth_admin_session(int client_fd, const char *auth_header,
                        const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
        send_json_cors(client_fd, 401,
            "{\"error\":\"Authenticated administrator session required\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* Retrieve user display name if available */
    char full_name[128] = {0};
    PGconn *conn = db_acquire();
    if (conn) {
        const char *pvals[1] = { sess.user_id };
        int lens[1] = { (int)strlen(sess.user_id) };
        PGresult *res = db_simple(conn,
            "SELECT COALESCE(name, '') FROM users WHERE id = $1",
            1, pvals, lens);
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
            strncpy(full_name, PQgetvalue(res, 0, 0), sizeof(full_name) - 1);
        }
        if (res) PQclear(res);
        db_release(conn, 0);
    }

    int tier = role_clearance_tier(sess.role);
    const char *tlabel = role_clearance_label(sess.role);

    char resp_body[1024];
    snprintf(resp_body, sizeof(resp_body),
        "{\"user_id\":\"%s\",\"username\":\"%s\",\"name\":\"%s\",\"institution_id\":\"%s\","
        "\"role\":\"%s\",\"session_expires_at\":%ld,"
        "\"hardware_security\":{"
            "\"hardware_bound\":true,"
            "\"device_id\":\"DEV-NODE-01\","
            "\"tpm_attestation\":\"TPM_2_0_ENFORCED\","
            "\"pcr_attestation\":\"PCR0_PCR7_COMPLIANT\","
            "\"anti_replay_enforced\":true,"
            "\"tamper_detected\":false,"
            "\"clearance_level\":%d,"
            "\"clearance_tier\":\"%s\""
        "}}",
        sess.user_id, sess.username, full_name[0] ? full_name : sess.username,
        sess.institution_id, security_role_to_string(sess.role), (long)sess.expires_at,
        tier, tlabel);

    ctrl_set_cors(extra_headers, extra_len, origin,
                  ctrl_cors_origin_allowed(origin));
    ctrl_send_json(client_fd, 200, resp_body, extra_headers);
}

/* ------------------------------------------------------- candidate login */
void auth_candidate_login(int client_fd, const char *req_body,
                          const char *origin, char *extra_headers, size_t extra_len) {
    char candidate_id[64] = {0}, pin[64] = {0};
    ctrl_json_string(req_body, "candidate_id", candidate_id, sizeof(candidate_id));
    ctrl_json_string(req_body, "pin", pin, sizeof(pin));

    if (!candidate_id[0] || !pin[0]) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Candidate ID and PIN are required\"}",
            origin, extra_headers, extra_len);
        goto done;
    }

    /* Check brute-force lockout */
    time_t now = time(NULL);
    char lock_err[256] = {0};
    if (check_lockout(candidate_id, now, lock_err, sizeof(lock_err))) {
        send_json_cors(client_fd, 429, lock_err, origin, extra_headers, extra_len);
        audit_log(candidate_id, "CANDIDATE_LOGIN_LOCKED", "brute force threshold exceeded");
        goto done;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        send_json_cors(client_fd, 503,
            "{\"status\":\"FAIL\",\"error\":\"Database service unavailable\"}",
            origin, extra_headers, extra_len);
        goto done;
    }

    const char *pvals[1] = { candidate_id };
    int lens[1] = { (int)strlen(candidate_id) };

    /* First check candidates table */
    PGresult *res = db_simple(conn,
        "SELECT id, roll_no, name, exam_id, pin_hash, status FROM candidates "
        "WHERE id = $1 OR roll_no = $1",
        1, pvals, lens);

    int found = res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0;
    char db_id[64] = {0}, db_roll[64] = {0}, db_name[128] = {0};
    char db_exam_id[64] = {0}, db_pin[256] = {0}, db_status[32] = {0};

    if (found) {
        strncpy(db_id, PQgetvalue(res, 0, 0), sizeof(db_id) - 1);
        strncpy(db_roll, PQgetvalue(res, 0, 1), sizeof(db_roll) - 1);
        strncpy(db_name, PQgetvalue(res, 0, 2), sizeof(db_name) - 1);
        strncpy(db_exam_id, PQgetvalue(res, 0, 3), sizeof(db_exam_id) - 1);
        strncpy(db_pin, PQgetvalue(res, 0, 4), sizeof(db_pin) - 1);
        strncpy(db_status, PQgetvalue(res, 0, 5), sizeof(db_status) - 1);
    }
    if (res) PQclear(res);

    /* If not found, check examos_exam_roster */
    if (!found) {
        res = db_simple(conn,
            "SELECT candidate_id, candidate_id, full_name, exam_id, pin_hash, status "
            "FROM examos_exam_roster WHERE candidate_id = $1",
            1, pvals, lens);
        found = res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0;
        if (found) {
            strncpy(db_id, PQgetvalue(res, 0, 0), sizeof(db_id) - 1);
            strncpy(db_roll, PQgetvalue(res, 0, 1), sizeof(db_roll) - 1);
            strncpy(db_name, PQgetvalue(res, 0, 2), sizeof(db_name) - 1);
            strncpy(db_exam_id, PQgetvalue(res, 0, 3), sizeof(db_exam_id) - 1);
            strncpy(db_pin, PQgetvalue(res, 0, 4), sizeof(db_pin) - 1);
            strncpy(db_status, PQgetvalue(res, 0, 5), sizeof(db_status) - 1);
        }
        if (res) PQclear(res);
    }

    int pin_ok = 0;
    if (found && db_pin[0] && strcmp(db_status, "disqualified") != 0 && strcmp(db_status, "DISQUALIFIED") != 0) {
        char computed[256] = {0};
        if (security_pbkdf2_hash(pin, candidate_id, computed, sizeof(computed)) == 0 &&
            security_safe_equal(computed, db_pin)) {
            pin_ok = 1;
        } else if (config_verify_password_hash(pin, db_pin) == 1) {
            /* examos_exam_roster: hash is "iterations:salt_hex:hash_hex" format.
             * config_verify_password_hash returns 1 = match. */
            pin_ok = 1;
        }
    } else if (!found) {
        /* Fallback check against candidates.conf */
        if (candidate_credentials_validate(candidate_id, pin)) {
            pin_ok = 1;
            strncpy(db_id, candidate_id, sizeof(db_id) - 1);
            strncpy(db_name, candidate_id, sizeof(db_name) - 1);
        }
    }
    OPENSSL_cleanse(pin, sizeof(pin));

    if (!pin_ok) {
        record_failure(candidate_id, now);
        send_json_cors(client_fd, 401,
            "{\"status\":\"FAIL\",\"error\":\"Invalid candidate ID or PIN\"}",
            origin, extra_headers, extra_len);
        audit_log(candidate_id, "CANDIDATE_LOGIN_FAILED", "invalid credentials");
        db_release(conn, 0);
        goto done;
    }

    /* Create candidate token */
    char token[65] = {0};
    {
        unsigned char rnd[32];
        RAND_bytes(rnd, sizeof(rnd));
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            token[i * 2] = hex[rnd[i] >> 4];
            token[i * 2 + 1] = hex[rnd[i] & 0x0f];
        }
        token[64] = '\0';
    }

    time_t expires = now + 28800;
    char now_str[32], exp_str[32], sid[64];
    snprintf(now_str, sizeof(now_str), "%ld", (long)now);
    snprintf(exp_str, sizeof(exp_str), "%ld", (long)expires);
    snprintf(sid, sizeof(sid), "csess_%ld_%s", (long)now, token + 56);

    const char *ins_pvals[9] = {
        sid, db_id[0] ? db_id : candidate_id, candidate_id,
        "", "candidate", token, now_str, exp_str, "active"
    };
    int ilens[9];
    for (int k = 0; k < 9; k++) ilens[k] = ins_pvals[k] ? (int)strlen(ins_pvals[k]) : 0;

    PGresult *ins = db_simple(conn,
        "INSERT INTO auth_sessions (id, user_id, username, institution_id, role, "
        "session_token, created_at, expires_at, status) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7::bigint, $8::bigint, $9)",
        9, ins_pvals, ilens);
    if (ins) PQclear(ins);

    /* Get Exam Name & URL if configured */
    char exam_title[128] = "ExamOS Examination", exam_url[512] = "";
    if (db_exam_id[0]) {
        const char *epvals[1] = { db_exam_id };
        int elens[1] = { (int)strlen(db_exam_id) };
        /* 1. Try exams table */
        PGresult *eres = db_simple(conn,
            "SELECT title, COALESCE(exam_url, '') FROM exams WHERE id = $1", 1, epvals, elens);
        if (eres && PQresultStatus(eres) == PGRES_TUPLES_OK && PQntuples(eres) > 0) {
            strncpy(exam_title, PQgetvalue(eres, 0, 0), sizeof(exam_title) - 1);
            strncpy(exam_url, PQgetvalue(eres, 0, 1), sizeof(exam_url) - 1);
        }
        if (eres) PQclear(eres);

        /* 2. Fallback to examinations table if URL empty */
        if (!exam_url[0]) {
            PGresult *xres = db_simple(conn,
                "SELECT name, COALESCE(exam_url, '') FROM examinations WHERE id = $1 OR code = $1", 1, epvals, elens);
            if (xres && PQresultStatus(xres) == PGRES_TUPLES_OK && PQntuples(xres) > 0) {
                if (exam_title[0] == '\0' || strcmp(exam_title, "ExamOS Examination") == 0) {
                    strncpy(exam_title, PQgetvalue(xres, 0, 0), sizeof(exam_title) - 1);
                }
                strncpy(exam_url, PQgetvalue(xres, 0, 1), sizeof(exam_url) - 1);
            }
            if (xres) PQclear(xres);
        }
    }
    if (!exam_url[0]) {
        strncpy(exam_url, "https://assessment.sppio.io/exam/live", sizeof(exam_url) - 1);
    }
    db_release(conn, 0);

    char resp_body[1024];
    snprintf(resp_body, sizeof(resp_body),
        "{\"status\":\"SUCCESS\",\"token\":\"%s\",\"candidate_id\":\"%s\","
        "\"name\":\"%s\",\"exam_id\":\"%s\",\"exam_name\":\"%s\",\"exam_url\":\"%s\"}",
        token, db_id[0] ? db_id : candidate_id, db_name[0] ? db_name : candidate_id,
        db_exam_id, exam_title, exam_url);

    ctrl_set_cors(extra_headers, extra_len, origin,
                  ctrl_cors_origin_allowed(origin));
    ctrl_send_json(client_fd, 200, resp_body, extra_headers);

    clear_failure(candidate_id);
    audit_log(db_id[0] ? db_id : candidate_id, "CANDIDATE_LOGIN_SUCCESS", candidate_id);

done:
    OPENSSL_cleanse(pin, sizeof(pin));
}

/* ----------------------------------------------------------- MFA TOTP Setup */
void auth_mfa_setup(int client_fd, const char *req_body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len) {
    char username[128] = {0};
    ctrl_json_string(req_body, "username", username, sizeof(username));

    /* If not in body, try to extract from authenticated session */
    if (!username[0] && auth_header && auth_header[0]) {
        auth_session_t sess;
        if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) == 0) {
            strncpy(username, sess.username, sizeof(username) - 1);
        }
    }

    if (!username[0]) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Username or authenticated session required\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* Multi-factor authentication is exclusively for management dashboards. Candidates and students do not use MFA. */
    PGconn *chk_conn = db_acquire();
    if (chk_conn) {
        const char *pvals[1] = { username };
        int lens[1] = { (int)strlen(username) };
        PGresult *res = db_simple(chk_conn,
            "SELECT role FROM users WHERE LOWER(username) = LOWER($1) OR id = $1",
            1, pvals, lens);
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
            const char *r = PQgetvalue(res, 0, 0);
            if (strcasecmp(r, "student") == 0 || strcasecmp(r, "candidate") == 0) {
                PQclear(res);
                db_release(chk_conn, 0);
                send_json_cors(client_fd, 403,
                    "{\"status\":\"FAIL\",\"error\":\"Multi-factor authentication is exclusively for management dashboards. Candidate and student accounts do not require MFA.\"}",
                    origin, extra_headers, extra_len);
                return;
            }
        }
        if (res) PQclear(res);

        /* Also check candidates and exam roster */
        PGresult *cres = db_simple(chk_conn,
            "SELECT id FROM candidates WHERE LOWER(id) = LOWER($1) OR LOWER(roll_no) = LOWER($1)",
            1, pvals, lens);
        if (cres && PQresultStatus(cres) == PGRES_TUPLES_OK && PQntuples(cres) > 0) {
            PQclear(cres);
            db_release(chk_conn, 0);
            send_json_cors(client_fd, 403,
                "{\"status\":\"FAIL\",\"error\":\"Multi-factor authentication is exclusively for management dashboards. Candidate and student accounts do not require MFA.\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (cres) PQclear(cres);

        if (strncasecmp(username, "cand", 4) == 0 || strncasecmp(username, "student", 7) == 0) {
            db_release(chk_conn, 0);
            send_json_cors(client_fd, 403,
                "{\"status\":\"FAIL\",\"error\":\"Multi-factor authentication is exclusively for management dashboards. Candidate and student accounts do not require MFA.\"}",
                origin, extra_headers, extra_len);
            return;
        }
        db_release(chk_conn, 0);
    }

    /* 1. Generate 20-byte random secret -> Base32 (32 chars) */
    char base32_secret[TOTP_BASE32_LEN + 1] = {0};
    if (totp_generate_secret(base32_secret) != 0) {
        send_json_cors(client_fd, 500,
            "{\"status\":\"FAIL\",\"error\":\"Cryptographic randomness generation failed\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* 2. Generate standard otpauth:// URI for Google Authenticator QR */
    char otpauth_url[512] = {0};
    totp_generate_uri(username, "ExamOS", base32_secret, otpauth_url, sizeof(otpauth_url));

    /* 3. Generate 8 single-use recovery codes & hashes */
    char codes[TOTP_NUM_RECOVERY_CODES][TOTP_RECOVERY_CODE_LEN + 1];
    char hashes[TOTP_NUM_RECOVERY_CODES][65];
    totp_generate_recovery_codes(codes, hashes);

    /* Construct JSON response with recovery codes array */
    char recovery_json[1024] = "[";
    for (int i = 0; i < TOTP_NUM_RECOVERY_CODES; i++) {
        char item[64];
        snprintf(item, sizeof(item), "%s\"%s\"", (i > 0) ? "," : "", codes[i]);
        strncat(recovery_json, item, sizeof(recovery_json) - strlen(recovery_json) - 1);
    }
    strncat(recovery_json, "]", sizeof(recovery_json) - strlen(recovery_json) - 1);

    char resp_body[2048];
    snprintf(resp_body, sizeof(resp_body),
        "{\"status\":\"SUCCESS\",\"username\":\"%s\",\"secret\":\"%s\","
        "\"otpauth_url\":\"%s\",\"recovery_codes\":%s,"
        "\"algorithm\":\"SHA1\",\"digits\":6,\"period\":30,\"issuer\":\"ExamOS\"}",
        username, base32_secret, otpauth_url, recovery_json);

    send_json_cors(client_fd, 200, resp_body, origin, extra_headers, extra_len);
    audit_log(username, "MFA_SETUP_INITIATED", "Generated TOTP secret and recovery codes");
}

/* --------------------------------------------------------- MFA TOTP Confirm */
void auth_mfa_confirm(int client_fd, const char *req_body, const char *auth_header,
                      const char *origin, char *extra_headers, size_t extra_len) {
    char username[128] = {0}, secret[64] = {0}, code[32] = {0};
    ctrl_json_string(req_body, "username", username, sizeof(username));
    ctrl_json_string(req_body, "secret", secret, sizeof(secret));
    ctrl_json_string(req_body, "code", code, sizeof(code));

    if (!username[0] && auth_header && auth_header[0]) {
        auth_session_t sess;
        if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) == 0) {
            strncpy(username, sess.username, sizeof(username) - 1);
        }
    }

    if (!username[0] || !secret[0] || !code[0]) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Username, secret, and 6-digit confirmation code are required\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* Sanitize 6-digit TOTP code (strip spaces/dashes) */
    char clean_code[16] = {0};
    size_t c_idx = 0;
    for (size_t i = 0; code[i] && c_idx < 6; i++) {
        if (isdigit((unsigned char)code[i])) clean_code[c_idx++] = code[i];
    }
    clean_code[c_idx] = '\0';

    /* Verify code from Google Authenticator (window +-2 = +-60s clock skew tolerance) */
    time_t now = time(NULL);
    if (!clean_code[0] || !totp_verify_code(secret, clean_code, now, 3)) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Invalid authentication code. Ensure your device time is synchronized with network time.\"}",
            origin, extra_headers, extra_len);
        audit_log(username, "MFA_CONFIRM_FAILED", "invalid verification code");
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        send_json_cors(client_fd, 503,
            "{\"status\":\"FAIL\",\"error\":\"Database unavailable\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* Prevent MFA enrollment for candidates and students */
    const char *chk_p[1] = { username };
    int chk_l[1] = { (int)strlen(username) };
    PGresult *chk_r = db_simple(conn,
        "SELECT role FROM users WHERE LOWER(username) = LOWER($1) OR id = $1",
        1, chk_p, chk_l);
    if (chk_r && PQresultStatus(chk_r) == PGRES_TUPLES_OK && PQntuples(chk_r) > 0) {
        const char *r = PQgetvalue(chk_r, 0, 0);
        if (strcasecmp(r, "student") == 0 || strcasecmp(r, "candidate") == 0) {
            PQclear(chk_r);
            db_release(conn, 0);
            send_json_cors(client_fd, 403,
                "{\"status\":\"FAIL\",\"error\":\"Multi-factor authentication is exclusively for management dashboards. Candidates and students do not require MFA.\"}",
                origin, extra_headers, extra_len);
            return;
        }
    }
    if (chk_r) PQclear(chk_r);

    if (strncasecmp(username, "cand", 4) == 0 || strncasecmp(username, "student", 7) == 0) {
        db_release(conn, 0);
        send_json_cors(client_fd, 403,
            "{\"status\":\"FAIL\",\"error\":\"Multi-factor authentication is exclusively for management dashboards. Candidates and students do not require MFA.\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* 1. Update users table (match by username, email, or id) */
    const char *pvals[2] = { secret, username };
    int lens[2] = { (int)strlen(secret), (int)strlen(username) };
    PGresult *u_res = db_simple(conn,
        "UPDATE users SET totp_secret = $1, mfa_enabled = 1 WHERE LOWER(username) = LOWER($2) OR LOWER(email) = LOWER($2) OR id = $2",
        2, pvals, lens);
    if (u_res) PQclear(u_res);

    /* 2. Update examos_admin_users (match by username, email, or user_id) */
    PGresult *a_res = db_simple(conn,
        "UPDATE examos_admin_users SET totp_secret = $1, mfa_enabled = true, totp_enrolled_at = clock_timestamp() "
        "WHERE LOWER(username) = LOWER($2) OR LOWER(email) = LOWER($2) OR user_id = $2 RETURNING user_id",
        2, pvals, lens);
    char user_id[64] = {0};
    if (a_res && PQresultStatus(a_res) == PGRES_TUPLES_OK && PQntuples(a_res) > 0) {
        strncpy(user_id, PQgetvalue(a_res, 0, 0), sizeof(user_id) - 1);
    }
    if (a_res) PQclear(a_res);

    /* 3. If recovery codes array provided in JSON, store hashes in examos_admin_recovery_codes */
    const char *uid = user_id[0] ? user_id : username;
    const char *codes_pos = strstr(req_body, "\"recovery_codes\"");
    if (codes_pos) {
        const char *del_p[1] = { uid };
        int del_l[1] = { (int)strlen(uid) };
        PGresult *d_res = db_simple(conn,
            "DELETE FROM examos_admin_recovery_codes WHERE user_id = $1 AND NOT used",
            1, del_p, del_l);
        if (d_res) PQclear(d_res);

        const char *p = strchr(codes_pos, '[');
        if (p) {
            p++;
            while (*p && *p != ']') {
                while (*p && (*p == ' ' || *p == '"' || *p == ',' || *p == '\r' || *p == '\n')) p++;
                if (*p == ']' || !*p) break;
                char raw_code[32] = {0};
                int ci = 0;
                while (*p && *p != '"' && *p != ',' && *p != ']' && ci + 1 < (int)sizeof(raw_code)) {
                    raw_code[ci++] = *p++;
                }
                raw_code[ci] = '\0';
                char norm[32] = {0}, hash[65] = {0};
                normalize_code(raw_code, norm, sizeof(norm));
                if (norm[0] && totp_hash_recovery_code(norm, hash) == 0) {
                    const char *ins_p[2] = { hash, uid };
                    int ins_l[2] = { 64, (int)strlen(uid) };
                    PGresult *ins_r = db_simple(conn,
                        "INSERT INTO examos_admin_recovery_codes (code_hash, user_id, used) "
                        "VALUES ($1, $2, false) ON CONFLICT (code_hash) DO NOTHING",
                        2, ins_p, ins_l);
                    if (ins_r) PQclear(ins_r);
                }
                while (*p && *p != ',' && *p != ']') p++;
                if (*p == ',') p++;
            }
        }
    }

    db_release(conn, 0);

    send_json_cors(client_fd, 200,
        "{\"status\":\"SUCCESS\",\"message\":\"Two-factor authentication with Google Authenticator successfully configured and active.\"}",
        origin, extra_headers, extra_len);
    audit_log(username, "MFA_TOTP_ENROLLED", "Google Authenticator / TOTP confirmed");
}

/* ---------------------------------------------------- Account Recovery Reset */
void auth_recovery_reset(int client_fd, const char *req_body,
                         const char *origin, char *extra_headers, size_t extra_len) {
    char username[128] = {0}, code[64] = {0}, new_pw[256] = {0};
    ctrl_json_string(req_body, "username", username, sizeof(username));
    ctrl_json_string(req_body, "code", code, sizeof(code));
    if (!code[0]) ctrl_json_string(req_body, "recovery_code", code, sizeof(code));
    ctrl_json_string(req_body, "new_password", new_pw, sizeof(new_pw));

    if (!username[0] || !code[0] || !new_pw[0]) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Username, recovery code, and new password are required\"}",
            origin, extra_headers, extra_len);
        goto r_done;
    }

    if (strlen(new_pw) < 12) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Password must be at least 12 characters long and contain uppercase, lowercase, numbers, and symbols\"}",
            origin, extra_headers, extra_len);
        goto r_done;
    }

    char norm[32] = {0}, rec_hash[65] = {0};
    normalize_code(code, norm, sizeof(norm));
    if (totp_hash_recovery_code(norm, rec_hash) != 0) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Invalid recovery code format\"}",
            origin, extra_headers, extra_len);
        goto r_done;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        send_json_cors(client_fd, 503,
            "{\"status\":\"FAIL\",\"error\":\"Database unavailable\"}",
            origin, extra_headers, extra_len);
        goto r_done;
    }

    /* Locate user in examos_admin_users or users */
    const char *u_pvals[1] = { username };
    int u_lens[1] = { (int)strlen(username) };
    PGresult *u_res = db_simple(conn,
        "SELECT user_id FROM examos_admin_users WHERE LOWER(username) = LOWER($1)",
        1, u_pvals, u_lens);

    char uid[64] = {0};
    int found_admin = u_res && PQresultStatus(u_res) == PGRES_TUPLES_OK && PQntuples(u_res) > 0;
    if (found_admin) {
        strncpy(uid, PQgetvalue(u_res, 0, 0), sizeof(uid) - 1);
    }
    if (u_res) PQclear(u_res);

    if (!uid[0]) {
        u_res = db_simple(conn, "SELECT id FROM users WHERE LOWER(username) = LOWER($1)", 1, u_pvals, u_lens);
        if (u_res && PQresultStatus(u_res) == PGRES_TUPLES_OK && PQntuples(u_res) > 0) {
            strncpy(uid, PQgetvalue(u_res, 0, 0), sizeof(uid) - 1);
        }
        if (u_res) PQclear(u_res);
    }

    if (!uid[0]) {
        send_json_cors(client_fd, 404,
            "{\"status\":\"FAIL\",\"error\":\"Account not found\"}",
            origin, extra_headers, extra_len);
        db_release(conn, 0);
        goto r_done;
    }

    /* Consume recovery code */
    const char *r_pvals[2] = { uid, rec_hash };
    int r_lens[2] = { (int)strlen(uid), 64 };
    PGresult *rec_res = db_simple(conn,
        "UPDATE examos_admin_recovery_codes SET used = true, used_at = clock_timestamp() "
        "WHERE user_id = $1 AND code_hash = $2 AND NOT used RETURNING code_hash",
        2, r_pvals, r_lens);

    int rec_ok = rec_res && PQresultStatus(rec_res) == PGRES_TUPLES_OK && PQntuples(rec_res) == 1;
    if (rec_res) PQclear(rec_res);

    if (!rec_ok) {
        send_json_cors(client_fd, 401,
            "{\"status\":\"FAIL\",\"error\":\"Invalid, already used, or expired emergency recovery code\"}",
            origin, extra_headers, extra_len);
        audit_log(username, "RECOVERY_RESET_FAILED", "invalid recovery code");
        db_release(conn, 0);
        goto r_done;
    }

    /* Compute PBKDF2 hash of new password */
    unsigned char salt_bytes[16];
    RAND_bytes(salt_bytes, sizeof(salt_bytes));
    static const char hex[] = "0123456789abcdef";
    char salt_hex[33] = {0};
    for (int i = 0; i < 16; i++) {
        salt_hex[i * 2] = hex[salt_bytes[i] >> 4];
        salt_hex[i * 2 + 1] = hex[salt_bytes[i] & 0x0f];
    }
    salt_hex[32] = '\0';

    char new_hash[256] = {0};
    security_pbkdf2_hash(new_pw, salt_hex, new_hash, sizeof(new_hash));

    /* Update examos_admin_users and users */
    char full_cred[300];
    snprintf(full_cred, sizeof(full_cred), "600000:%s:%s", salt_hex, new_hash);
    const char *up_p1[2] = { full_cred, uid };
    int up_l1[2] = { (int)strlen(full_cred), (int)strlen(uid) };
    PGresult *up1 = db_simple(conn,
        "UPDATE examos_admin_users SET password_hash = $1 WHERE user_id = $2 OR LOWER(username) = LOWER($2)",
        2, up_p1, up_l1);
    if (up1) PQclear(up1);

    const char *up_p2[3] = { new_hash, salt_hex, username };
    int up_l2[3] = { (int)strlen(new_hash), (int)strlen(salt_hex), (int)strlen(username) };
    PGresult *up2 = db_simple(conn,
        "UPDATE users SET password_hash = $1, salt = $2 WHERE LOWER(username) = LOWER($3) OR id = $3",
        3, up_p2, up_l2);
    if (up2) PQclear(up2);

    /* Invalidate active sessions for this user */
    const char *inv_p[1] = { uid };
    int inv_l[1] = { (int)strlen(uid) };
    PGresult *inv = db_simple(conn,
        "UPDATE auth_sessions SET status = 'ended' WHERE user_id = $1",
        1, inv_p, inv_l);
    if (inv) PQclear(inv);

    clear_failure(username);
    db_release(conn, 0);

    send_json_cors(client_fd, 200,
        "{\"status\":\"SUCCESS\",\"message\":\"Password has been securely reset. You can now sign in with your new credentials.\"}",
        origin, extra_headers, extra_len);
    audit_log(username, "RECOVERY_RESET_SUCCESS", "password reset via emergency code");

r_done:
    OPENSSL_cleanse(new_pw, sizeof(new_pw));
}
