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
#include "../include/admin_auth_store.h"
#include "../include/config_manager.h"
#include "../include/secure_token.h"
#include "../include/totp.h"
#include "../include/candidate_login.h"
#include "../include/session_store.h"
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

static int password_meets_policy(const char *pw) {
    if (!pw) return 0;
    size_t n = strlen(pw);
    if (n < 12 || n > 256) return 0;
    int upper = 0, lower = 0, digit = 0, symbol = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)pw[i];
        if (isupper(c)) upper = 1;
        else if (islower(c)) lower = 1;
        else if (isdigit(c)) digit = 1;
        else symbol = 1;
    }
    return upper && lower && digit && symbol;
}

/*
 * Lockout helpers — all state is durable in examos_admin_login_throttle.
 * The previous in-memory g_lockouts[] array was wiped on every server
 * restart, making the brute-force protection ineffective in production.
 */
static int check_lockout(const char *key, time_t now, char *err_buf, size_t err_len) {
    (void)now;
    if (!key || !key[0]) return 0;
    int locked = admin_auth_throttle_check(key);
    if (locked == 1) {
        snprintf(err_buf, err_len,
            "{\"status\":\"LOCKED\",\"error\":\"Account temporarily locked due to repeated failed login attempts. Retry in 900 seconds or use emergency recovery code.\"}");
        return 1;
    }
    return 0;
}

static void record_failure(const char *key, time_t now) {
    (void)now;
    if (!key || !key[0]) return;
    if (admin_auth_throttle_failure(key) != 0)
        fprintf(stderr, "[AUTH] WARN: could not record login failure for '%s'\n", key);
}

static void clear_failure(const char *key) {
    if (!key || !key[0]) return;
    (void)admin_auth_throttle_clear(key);
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
        case ROLE_PLATFORM_OWNER: return "TIER-5 PLATFORM_OWNER (FULL PLATFORM CLEARANCE)";
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
    (void)mfa_enabled; /* enrollment/MFA decisions below are driven by db_totp */

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
        /*
         * First-time management users must enrol an authenticator.  The
         * client receives a single-use, short-lived enrollment token that is
         * bound to this account; the TOTP secret itself is only released by
         * /admin/mfa/setup when that token (or an authenticated session) is
         * presented.  A caller who merely knows a username can therefore
         * never obtain or replace someone else's authenticator.
         */
        char enroll_token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        char enroll_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        char failure[256] = {0};
        if (secure_token_create(enroll_token, enroll_hash) != 0) {
            snprintf(failure, sizeof(failure),
                     "{\"status\":\"FAIL\",\"error\":\"Cryptographic randomness failure\"}");
            send_json_cors(client_fd, 500, failure, origin, extra_headers, extra_len);
            db_release(conn, 0);
            goto done;
        }

        const char *del_p[1] = { db_username[0] ? db_username : username };
        int del_l[1] = { (int)strlen(del_p[0]) };
        PGresult *del_r = db_simple(conn,
            "DELETE FROM examos_admin_mfa_enrollments WHERE LOWER(username) = LOWER($1)",
            1, del_p, del_l);
        if (del_r) PQclear(del_r);

        const char *en_p[4] = {
            enroll_hash, db_userid[0] ? db_userid : username,
            db_username[0] ? db_username : username, ""
        };
        int en_l[4] = { 64, (int)strlen(en_p[1]), (int)strlen(en_p[2]), 0 };
        PGresult *en_r = db_simple(conn,
            "INSERT INTO examos_admin_mfa_enrollments "
            "(token_hash, user_id, username, secret, recovery_hashes, expires_at) "
            "VALUES ($1, $2, $3, $4, '', clock_timestamp() + interval '10 minutes')",
            4, en_p, en_l);
        if (en_r) PQclear(en_r);

        char setup_msg[768];
        snprintf(setup_msg, sizeof(setup_msg),
            "{\"status\":\"MFA_SETUP_REQUIRED\",\"mfa_setup_required\":true,"
            "\"username\":\"%s\",\"enrollment_token\":\"%s\",\"expires_in\":600,"
            "\"message\":\"Authenticator setup required for first-time management user\"}",
            db_username[0] ? db_username : username, enroll_token);
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
    /* RFC 6238 TOTP verification: window=1 allows +-30s clock drift only.
     * The previous window=3 (+-90s) was too permissive for production. */
    if (db_totp[0] && clean_code[0] && totp_verify_code(db_totp, clean_code, time(NULL), 1)) {
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

    /* Generate 256-bit cryptographically secure session token via the
     * canonical path — secure_token_create() generates random bytes,
     * hex-encodes them, and produces the SHA-256 digest atomically. */
    char token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    if (secure_token_create(token, token_hash) != 0) {
        send_json_cors(client_fd, 500,
            "{\"status\":\"FAIL\",\"error\":\"Cryptographic randomness failure\"}",
            origin, extra_headers, extra_len);
        db_release(conn, 0);
        goto done;
    }

    now = time(NULL);
    time_t expires = now + 28800;
    char now_str[32], exp_str[32], sid[64];
    snprintf(now_str, sizeof(now_str), "%ld", (long)now);
    snprintf(exp_str, sizeof(exp_str), "%ld", (long)expires);
    snprintf(sid, sizeof(sid), "ase_%ld_%s", (long)now, token + (EXAMOS_TOKEN_HEX_LEN - 8));

    /* Store session in auth_sessions */
    const char *ins_pvals[9] = {
        sid, db_userid, db_username[0] ? db_username : username,
        db_inst, db_role, token_hash, now_str, exp_str, "active"
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
    {
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
    const char *tpm_mode = getenv("EXAMOS_TPM_MODE");
    int is_secure = (secure_env && strcmp(secure_env, "1") == 0) ||
                    (tpm_mode && strcmp(tpm_mode, "production") == 0);
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
        char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        const char *stored = token;
        if (secure_token_hash(token, token_hash) == 0) stored = token_hash;

        const char *pvals[1] = { stored };
        int lens[1] = { (int)strlen(stored) };
        PGresult *res = db_simple(conn,
            "UPDATE auth_sessions SET status = 'ended' WHERE session_token = $1 AND status = 'active'",
            1, pvals, lens);
        if (res) PQclear(res);

        char token_digest[65] = {0};
        if (secure_token_hash(token, token_digest) == 0) {
            const char *th_vals[1] = { token_digest };
            int th_lens[1] = { 64 };
            PGresult *as_res = db_simple(conn,
                "UPDATE examos_admin_sessions SET revoked_at = clock_timestamp() WHERE token_hash = $1",
                1, th_vals, th_lens);
            if (as_res) PQclear(as_res);
        }
        OPENSSL_cleanse(token_hash, sizeof(token_hash));
        db_release(conn, 0);
    }

    char cookie[256];
    snprintf(cookie, sizeof(cookie),
        "Set-Cookie: admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0\r\n");

    ctrl_set_cors(extra_headers, extra_len, origin,
                  ctrl_cors_origin_allowed(origin));
    strncat(extra_headers, cookie, extra_len - strlen(extra_headers) - 1);
    ctrl_send_json(client_fd, 200, "{\"status\":\"SIGNED_OUT\"}", extra_headers);
    /* Never write the bearer token itself to the audit trail: it is a live
     * credential.  The session row has already been terminated above. */
    audit_log("admin", "ADMIN_LOGOUT", "session ended");
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

    /*
     * Report only facts this server actually established.  The previous
     * implementation returned hard-coded "TPM_2_0_ENFORCED" and
     * "PCR0_PCR7_COMPLIANT" values for every session, which made an
     * unverified browser session look like an attested appliance.
     * Hardware attestation is established by the agent/attestation service,
     * not by the console session, so it is reported as unavailable here.
     */
    char resp_body[1024];
    snprintf(resp_body, sizeof(resp_body),
        "{\"user_id\":\"%s\",\"username\":\"%s\",\"name\":\"%s\",\"institution_id\":\"%s\","
        "\"role\":\"%s\",\"session_expires_at\":%ld,"
        "\"hardware_security\":{"
            "\"hardware_bound\":false,"
            "\"tpm_attestation\":\"NOT_ATTESTED\","
            "\"pcr_attestation\":\"NOT_ATTESTED\","
            "\"attestation_source\":\"none\","
            "\"anti_replay_enforced\":false,"
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

/* --------------------------------------------------- admin change password */
void auth_change_password(int client_fd, const char *req_body,
                          const char *auth_header,
                          const char *origin, char *extra_headers, size_t extra_len) {
    char current[256] = {0}, next[512] = {0};
    ctrl_json_string(req_body, "current_password", current, sizeof(current));
    ctrl_json_string(req_body, "new_password", next, sizeof(next));

    if (!current[0] || !next[0]) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Current and new passwords are required\"}",
            origin, extra_headers, extra_len);
        return;
    }
    if (!password_meets_policy(next)) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Password must be at least 12 characters long and contain uppercase, lowercase, numbers, and symbols\"}",
            origin, extra_headers, extra_len);
        goto done;
    }
    if (strcmp(current, next) == 0) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"The new password must differ from the current password\"}",
            origin, extra_headers, extra_len);
        goto done;
    }

    auth_session_t sess;
    memset(&sess, 0, sizeof(sess));
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
        send_json_cors(client_fd, 401,
            "{\"status\":\"FAIL\",\"error\":\"Authenticated management session required\"}",
            origin, extra_headers, extra_len);
        goto done;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        send_json_cors(client_fd, 503,
            "{\"status\":\"FAIL\",\"error\":\"Database unavailable\"}",
            origin, extra_headers, extra_len);
        goto done;
    }

    const char *id_p[1] = { sess.user_id };
    int id_l[1] = { (int)strlen(sess.user_id) };

    int current_ok = 0;
    int has_users_row = 0, has_admin_row = 0;

    PGresult *ur = db_simple(conn,
        "SELECT password_hash, COALESCE(salt, '') FROM users "
        "WHERE id = $1 OR LOWER(username) = LOWER($1)",
        1, id_p, id_l);
    if (ur && PQresultStatus(ur) == PGRES_TUPLES_OK && PQntuples(ur) > 0) {
        has_users_row = 1;
        const char *hash = PQgetvalue(ur, 0, 0);
        const char *salt = PQgetvalue(ur, 0, 1);
        if (hash && hash[0]) {
            if (salt && salt[0]) {
                char computed[256] = {0};
                if (security_pbkdf2_hash(current, salt, computed, sizeof(computed)) == 0 &&
                    security_safe_equal(computed, hash)) {
                    current_ok = 1;
                }
            } else if (config_verify_password_hash(current, hash) == 1) {
                current_ok = 1;
            }
        }
    }
    if (ur) PQclear(ur);

    PGresult *ar = db_simple(conn,
        "SELECT password_hash FROM examos_admin_users "
        "WHERE user_id = $1 OR LOWER(username) = LOWER($1)",
        1, id_p, id_l);
    if (ar && PQresultStatus(ar) == PGRES_TUPLES_OK && PQntuples(ar) > 0) {
        has_admin_row = 1;
        const char *hash = PQgetvalue(ar, 0, 0);
        if (!current_ok && hash && hash[0] &&
            config_verify_password_hash(current, hash) == 1) {
            current_ok = 1;
        }
    }
    if (ar) PQclear(ar);

    if (!current_ok) {
        record_failure(sess.username, time(NULL));
        send_json_cors(client_fd, 401,
            "{\"status\":\"FAIL\",\"error\":\"Current password is incorrect\"}",
            origin, extra_headers, extra_len);
        audit_log(sess.user_id, "ADMIN_PASSWORD_CHANGE_FAILED", "current password mismatch");
        db_release(conn, 0);
        goto done;
    }

    unsigned char salt_bytes[16];
    if (RAND_bytes(salt_bytes, sizeof(salt_bytes)) != 1) {
        send_json_cors(client_fd, 500,
            "{\"status\":\"FAIL\",\"error\":\"Cryptographic randomness failure\"}",
            origin, extra_headers, extra_len);
        db_release(conn, 0);
        goto done;
    }
    static const char hex[] = "0123456789abcdef";
    char salt_hex[33] = {0};
    for (int i = 0; i < 16; i++) {
        salt_hex[i * 2] = hex[salt_bytes[i] >> 4];
        salt_hex[i * 2 + 1] = hex[salt_bytes[i] & 0x0f];
    }
    salt_hex[32] = '\0';

    char new_hash[256] = {0};
    if (security_pbkdf2_hash(next, salt_hex, new_hash, sizeof(new_hash)) != 0) {
        send_json_cors(client_fd, 500,
            "{\"status\":\"FAIL\",\"error\":\"Password hashing failed\"}",
            origin, extra_headers, extra_len);
        db_release(conn, 0);
        goto done;
    }

    char full_cred[320];
    snprintf(full_cred, sizeof(full_cred), "210000:%s:%s", salt_hex, new_hash);
    const char *up_full[2] = { full_cred, sess.user_id };
    int up_full_l[2] = { (int)strlen(full_cred), (int)strlen(sess.user_id) };
    const char *up_bare[3] = { new_hash, salt_hex, sess.user_id };
    int up_bare_l[3] = { (int)strlen(new_hash), (int)strlen(salt_hex),
                         (int)strlen(sess.user_id) };

    if (has_admin_row) {
        PGresult *r = db_simple(conn,
            "UPDATE examos_admin_users SET password_hash = $1 "
            "WHERE user_id = $2 OR LOWER(username) = LOWER($2)",
            2, up_full, up_full_l);
        if (r) PQclear(r);
    }
    if (has_users_row) {
        PGresult *r = db_simple(conn,
            "UPDATE users SET password_hash = $1, salt = $2 "
            "WHERE id = $3 OR LOWER(username) = LOWER($3)",
            3, up_bare, up_bare_l);
        if (r) PQclear(r);
    }

    /* Invalidate every other session for this account; keep the caller's. */
    char current_token[128] = {0};
    char current_digest[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    if (ctrl_extract_bearer(auth_header, current_token, sizeof(current_token)) &&
        secure_token_hash(current_token, current_digest) == 0) {
        const char *inv_p[2] = { sess.user_id, current_digest };
        int inv_l[2] = { (int)strlen(sess.user_id), (int)strlen(current_digest) };
        PGresult *r = db_simple(conn,
            "UPDATE auth_sessions SET status = 'ended' "
            "WHERE user_id = $1 AND session_token <> $2 AND status = 'active'",
            2, inv_p, inv_l);
        if (r) PQclear(r);

        /* Admin sessions are additionally mirrored in examos_admin_sessions,
         * and session verification falls back to that table.  Revoke there as
         * well, otherwise the old bearer token would survive the password
         * change through the fallback path. */
        PGresult *ar2 = db_simple(conn,
            "UPDATE examos_admin_sessions SET revoked_at = clock_timestamp() "
            "WHERE user_id = $1 AND token_hash <> $2 AND revoked_at IS NULL",
            2, inv_p, inv_l);
        if (ar2) PQclear(ar2);
    }
    OPENSSL_cleanse(current_token, sizeof(current_token));
    OPENSSL_cleanse(current_digest, sizeof(current_digest));

    db_release(conn, 0);

    send_json_cors(client_fd, 200,
        "{\"status\":\"SUCCESS\",\"message\":\"Password changed successfully\"}",
        origin, extra_headers, extra_len);
    audit_log(sess.user_id, "ADMIN_PASSWORD_CHANGED", "self-service password change");

done:
    OPENSSL_cleanse(current, sizeof(current));
    OPENSSL_cleanse(next, sizeof(next));
}

/* ---------------------------------------------------------- helpers */

/*
 * A candidate may sign in only while their roster entry is in a usable state.
 * Previously only "disqualified" was rejected, so suspended, withdrawn,
 * cancelled and already-submitted candidates could still open an exam.
 */
static int candidate_status_permits_login(const char *status) {
    static const char *blocked[] = {
        "disqualified", "suspended", "withdrawn", "cancelled", "canceled",
        "expired", "completed", "submitted", "blocked", "inactive",
        "revoked", "ineligible", NULL
    };
    if (!status || !status[0]) return 1;
    for (int i = 0; blocked[i]; i++) {
        if (strcasecmp(status, blocked[i]) == 0) return 0;
    }
    return 1;
}

/*
 * Returns 0 when the candidate is eligible and within the sign-in lead window,
 * or 1 with a human-readable reason when they are not.  Missing schedule or
 * assignment rows are treated as "no constraint recorded" so an institution
 * that does not use scheduling/eligibility is not locked out.
 */
static int candidate_exam_window_reason(PGconn *conn, const char *exam_id,
                                        const char *candidate_id,
                                        const char *user_id, const char *roll_no,
                                        char *reason, size_t reason_len) {
    if (reason && reason_len) reason[0] = '\0';

    if (exam_id && exam_id[0]) {
        const char *exam_p[1] = { exam_id };
        int exam_l[1] = { (int)strlen(exam_id) };
        PGresult *exam = db_simple(conn,
            "SELECT status FROM examinations WHERE id = $1", 1, exam_p, exam_l);
        if (!exam || PQresultStatus(exam) != PGRES_TUPLES_OK || PQntuples(exam) == 0) {
            if (exam) PQclear(exam);
            if (reason && reason_len)
                snprintf(reason, reason_len, "The assigned examination is not available.");
            return 1;
        }
        const char *exam_status = PQgetvalue(exam, 0, 0);
        int available = strcmp(exam_status, "scheduled") == 0 ||
                        strcmp(exam_status, "ready") == 0 ||
                        strcmp(exam_status, "in_progress") == 0;
        PQclear(exam);
        if (!available) {
            if (reason && reason_len)
                snprintf(reason, reason_len, "The assigned examination is not open for candidates.");
            return 1;
        }

        char now_ms[32];
        snprintf(now_ms, sizeof(now_ms), "%lld",
                 (long long)time(NULL) * 1000LL);
        const char *sp[2] = { exam_id, now_ms };
        int sl[2] = { (int)strlen(exam_id), (int)strlen(now_ms) };
        PGresult *sr = db_simple(conn,
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE "
            "(CASE WHEN start_time < 10000000000 THEN start_time * 1000 ELSE start_time END) <= ($2::bigint + 1800000) "
            "AND (CASE WHEN end_time < 10000000000 THEN end_time * 1000 ELSE end_time END) >= $2::bigint) "
            "FROM exam_schedules WHERE exam_id = $1",
            2, sp, sl);
        if (sr && PQresultStatus(sr) == PGRES_TUPLES_OK && PQntuples(sr) == 1) {
            long total = atol(PQgetvalue(sr, 0, 0));
            long current = atol(PQgetvalue(sr, 0, 1));
            if (total > 0 && current == 0) {
                if (reason && reason_len)
                    snprintf(reason, reason_len,
                             "The examination is not open at this time. "
                             "Please sign in during your scheduled session.");
                if (sr) PQclear(sr);
                return 1;
            }
        }
        if (sr) PQclear(sr);

        const char *ep[3] = { exam_id, candidate_id, roll_no };
        int el[3] = { (int)strlen(exam_id), candidate_id ? (int)strlen(candidate_id) : 0,
                      roll_no ? (int)strlen(roll_no) : 0 };
        (void)user_id;
        PGresult *er = db_simple(conn,
            "SELECT eligibility_status FROM exam_student_assignments "
            "WHERE exam_id = $1 AND (student_id = $2 OR roll_no = $2 OR roll_no = $3) "
            "ORDER BY (student_id = $2) DESC LIMIT 1",
            3, ep, el);
        if (er && PQresultStatus(er) == PGRES_TUPLES_OK && PQntuples(er) == 1) {
            const char *elig = PQgetvalue(er, 0, 0);
            if (strcasecmp(elig, "ineligible") == 0) {
                if (reason && reason_len)
                    snprintf(reason, reason_len,
                             "You are not eligible for this examination. "
                             "Contact your examination controller.");
                PQclear(er);
                return 1;
            }
        }
        if (er) PQclear(er);
    }
    return 0;
}

static int candidate_auth_role_allowed(user_role_t role) {
    return role == ROLE_PLATFORM_OWNER || role == ROLE_INSTITUTION_ADMIN ||
           role == ROLE_EXAM_MANAGER || role == ROLE_INVIGILATOR;
}

static int candidate_session_persist(PGconn *conn, const char *candidate_id,
                                     const char *institution_id, time_t now,
                                     char token[EXAMOS_TOKEN_HEX_LEN + 1],
                                     char token_hash[EXAMOS_TOKEN_HEX_LEN + 1],
                                     time_t *expires_at) {
    if (!conn || !candidate_id || !candidate_id[0] || !token || !token_hash ||
        secure_token_create(token, token_hash) != 0) return -1;

    time_t expires = now + 28800;
    char now_str[32], exp_str[32], session_id[64];
    snprintf(now_str, sizeof(now_str), "%ld", (long)now);
    snprintf(exp_str, sizeof(exp_str), "%ld", (long)expires);
    snprintf(session_id, sizeof(session_id), "csess_%ld_%.8s",
             (long)now, token + EXAMOS_TOKEN_HEX_LEN - 8);

    const char *params[9] = {
        session_id, candidate_id, candidate_id, institution_id ? institution_id : "",
        "candidate", token_hash, now_str, exp_str, "active"
    };
    int lengths[9];
    for (int i = 0; i < 9; ++i) lengths[i] = (int)strlen(params[i]);
    PGresult *insert = db_simple(conn,
        "INSERT INTO auth_sessions (id, user_id, username, institution_id, role, "
        "session_token, created_at, expires_at, status) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7::bigint,$8::bigint,$9)",
        9, params, lengths);
    int ok = insert && PQresultStatus(insert) == PGRES_COMMAND_OK &&
             strcmp(PQcmdTuples(insert), "1") == 0;
    if (insert) PQclear(insert);
    if (!ok) {
        OPENSSL_cleanse(token, EXAMOS_TOKEN_HEX_LEN + 1);
        OPENSSL_cleanse(token_hash, EXAMOS_TOKEN_HEX_LEN + 1);
        return -1;
    }
    if (expires_at) *expires_at = expires;
    return 0;
}

static void candidate_session_activate(const char *token, const char *candidate_id,
                                       time_t now, time_t expires) {
    if (candidate_session_restore(token, candidate_id, now) != 0) {
        fprintf(stderr, "[AUTH] ERROR: could not activate persisted candidate session\n");
        return;
    }
    session_journal_record_t record;
    memset(&record, 0, sizeof(record));
    record.event_type = SESSION_EVENT_CREATE;
    snprintf(record.token, sizeof(record.token), "%s", token);
    snprintf(record.candidate_id, sizeof(record.candidate_id), "%s", candidate_id);
    record.created_at = now;
    record.expires_at = expires;
    if (session_store_record(&record) != 0)
        fprintf(stderr, "[AUTH] WARN: candidate session journal append failed\n");
}

static void candidate_success_response(int client_fd, const char *token,
                                       const char *candidate_id, const char *name,
                                       const char *exam_id, const char *exam_title,
                                       const char *exam_url, const char *origin,
                                       char *extra_headers, size_t extra_len) {
    char escaped_candidate[128], escaped_name[256], escaped_exam[128];
    char escaped_title[256], escaped_url[1024], response[2048];
    ctrl_json_escape(candidate_id, escaped_candidate, sizeof(escaped_candidate));
    ctrl_json_escape(name, escaped_name, sizeof(escaped_name));
    ctrl_json_escape(exam_id, escaped_exam, sizeof(escaped_exam));
    ctrl_json_escape(exam_title, escaped_title, sizeof(escaped_title));
    ctrl_json_escape(exam_url, escaped_url, sizeof(escaped_url));
    snprintf(response, sizeof(response),
        "{\"status\":\"SUCCESS\",\"token\":\"%s\",\"candidate_id\":\"%s\","
        "\"name\":\"%s\",\"exam_id\":\"%s\",\"exam_name\":\"%s\",\"exam_url\":\"%s\"}",
        token, escaped_candidate, escaped_name, escaped_exam, escaped_title, escaped_url);
    send_json_cors(client_fd, 200, response, origin, extra_headers, extra_len);
}

static int parse_candidate_workflow_path(const char *path, char *exam_id,
                                         size_t exam_id_len, char *action,
                                         size_t action_len, char *resource_id,
                                         size_t resource_id_len) {
    const char *prefix = "/api/v1/examinations/";
    if (!path || strncmp(path, prefix, strlen(prefix)) != 0) return 0;
    const char *rest = path + strlen(prefix);
    const char *slash = strchr(rest, '/');
    if (!slash) return 0;
    size_t id_len = (size_t)(slash - rest);
    if (id_len == 0 || id_len >= exam_id_len) return 0;
    memcpy(exam_id, rest, id_len);
    exam_id[id_len] = '\0';

    const char *tail = slash + 1;
    const char *next = strchr(tail, '/');
    size_t action_size = next ? (size_t)(next - tail) : strlen(tail);
    if (action_size == 0 || action_size >= action_len) return 0;
    memcpy(action, tail, action_size);
    action[action_size] = '\0';
    if (next) {
        size_t resource_size = strlen(next + 1);
        if (resource_size == 0 || resource_size >= resource_id_len ||
            strchr(next + 1, '/')) return 0;
        memcpy(resource_id, next + 1, resource_size);
        resource_id[resource_size] = '\0';
    }
    return 1;
}

void auth_candidate_workflow_handle(int client_fd, const char *method, const char *path,
                                    const char *body, const char *auth_header,
                                    const char *origin, char *extra_headers, size_t extra_len) {
    if (strcmp(path, "/api/v1/candidate/checkin/status") == 0 &&
        strcmp(method, "POST") == 0) {
        char poll_token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        char poll_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        ctrl_json_string(body, "poll_token", poll_token, sizeof(poll_token));
        if (!poll_token[0] || secure_token_hash(poll_token, poll_hash) != 0) {
            send_json_cors(client_fd, 400,
                "{\"status\":\"FAIL\",\"error\":\"A valid check-in reference is required\"}",
                origin, extra_headers, extra_len);
            OPENSSL_cleanse(poll_token, sizeof(poll_token));
            return;
        }
        OPENSSL_cleanse(poll_token, sizeof(poll_token));

        PGconn *conn = db_acquire();
        if (!conn) {
            send_json_cors(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Database service unavailable\"}",
                origin, extra_headers, extra_len);
            return;
        }
        const char *params[1] = { poll_hash };
        int lengths[1] = { (int)strlen(poll_hash) };
        PGresult *checkin = db_simple(conn,
            "SELECT ci.id, ci.examination_id, ci.institution_id, ci.candidate_id, ci.status, "
            "ci.expires_at, c.status, c.name, c.roll_no, e.name, COALESCE(e.exam_url,'') "
            "FROM candidate_exam_checkins ci "
            "JOIN candidates c ON c.id=ci.candidate_id "
            "JOIN examinations e ON e.id=ci.examination_id "
            "WHERE ci.poll_token_hash=$1",
            1, params, lengths);
        if (!checkin || PQresultStatus(checkin) != PGRES_TUPLES_OK || PQntuples(checkin) != 1) {
            if (checkin) PQclear(checkin);
            db_release(conn, 0);
            send_json_cors(client_fd, 404,
                "{\"status\":\"FAIL\",\"error\":\"Check-in request not found\"}",
                origin, extra_headers, extra_len);
            return;
        }

        char request_id[64], exam_id[64], institution_id[64], candidate_id[64];
        char checkin_status[24], candidate_status[32], candidate_name[128];
        char roll_no[64], exam_title[128], exam_url[512];
        snprintf(request_id, sizeof(request_id), "%s", PQgetvalue(checkin, 0, 0));
        snprintf(exam_id, sizeof(exam_id), "%s", PQgetvalue(checkin, 0, 1));
        snprintf(institution_id, sizeof(institution_id), "%s", PQgetvalue(checkin, 0, 2));
        snprintf(candidate_id, sizeof(candidate_id), "%s", PQgetvalue(checkin, 0, 3));
        snprintf(checkin_status, sizeof(checkin_status), "%s", PQgetvalue(checkin, 0, 4));
        long long expires = atoll(PQgetvalue(checkin, 0, 5));
        snprintf(candidate_status, sizeof(candidate_status), "%s", PQgetvalue(checkin, 0, 6));
        snprintf(candidate_name, sizeof(candidate_name), "%s", PQgetvalue(checkin, 0, 7));
        snprintf(roll_no, sizeof(roll_no), "%s", PQgetvalue(checkin, 0, 8));
        snprintf(exam_title, sizeof(exam_title), "%s", PQgetvalue(checkin, 0, 9));
        snprintf(exam_url, sizeof(exam_url), "%s", PQgetvalue(checkin, 0, 10));
        PQclear(checkin);

        long long now_ms = (long long)time(NULL) * 1000;
        if (expires <= now_ms && strcmp(checkin_status, "pending") == 0) {
            const char *expire_params[1] = { request_id };
            int expire_lengths[1] = { (int)strlen(request_id) };
            PGresult *expired = db_simple(conn,
                "UPDATE candidate_exam_checkins SET status='expired' "
                "WHERE id=$1 AND status='pending'", 1, expire_params, expire_lengths);
            if (expired) PQclear(expired);
            db_release(conn, 0);
            send_json_cors(client_fd, 410,
                "{\"status\":\"FAIL\",\"error\":\"Invigilator check-in request expired. Please sign in again.\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(checkin_status, "pending") == 0) {
            db_release(conn, 0);
            send_json_cors(client_fd, 200,
                "{\"status\":\"PENDING_VERIFICATION\",\"message\":\"Waiting for invigilator approval\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(checkin_status, "rejected") == 0) {
            db_release(conn, 0);
            send_json_cors(client_fd, 403,
                "{\"status\":\"FAIL\",\"error\":\"Invigilator did not approve this check-in. Contact the exam desk.\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(checkin_status, "consumed") == 0 || strcmp(checkin_status, "expired") == 0) {
            db_release(conn, 0);
            send_json_cors(client_fd, 409,
                "{\"status\":\"FAIL\",\"error\":\"Check-in request has already been used or expired\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char window_reason[256] = {0};
        if (!candidate_status_permits_login(candidate_status) ||
            candidate_exam_window_reason(conn, exam_id, candidate_id, candidate_id,
                                         roll_no, window_reason, sizeof(window_reason)) != 0 ||
            !exam_url[0]) {
            db_release(conn, 0);
            send_json_cors(client_fd, 403,
                "{\"status\":\"FAIL\",\"error\":\"Candidate, exam availability or schedule changed before approval could be completed\"}",
                origin, extra_headers, extra_len);
            return;
        }

        PGresult *begin = PQexec(conn, "BEGIN");
        if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
            if (begin) PQclear(begin);
            db_release(conn, 1);
            send_json_cors(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Could not start check-in session transaction\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PQclear(begin);
        char now_ms_text[32];
        snprintf(now_ms_text, sizeof(now_ms_text), "%lld", now_ms);
        const char *claim_params[3] = { request_id, poll_hash, now_ms_text };
        int claim_lengths[3] = { (int)strlen(request_id), (int)strlen(poll_hash),
                                 (int)strlen(now_ms_text) };
        PGresult *claim = db_simple(conn,
            "UPDATE candidate_exam_checkins SET status='consumed', consumed_at=$3::bigint "
            "WHERE id=$1 AND poll_token_hash=$2 AND status='approved' AND expires_at>$3::bigint "
            "RETURNING candidate_id",
            3, claim_params, claim_lengths);
        if (!claim || PQresultStatus(claim) != PGRES_TUPLES_OK || PQntuples(claim) != 1) {
            if (claim) PQclear(claim);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_json_cors(client_fd, 409,
                "{\"status\":\"FAIL\",\"error\":\"Check-in approval has changed or expired. Please check in again.\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PQclear(claim);

        char token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        time_t now = time(NULL), session_expires = 0;
        if (candidate_session_persist(conn, candidate_id, institution_id, now,
                                      token, token_hash, &session_expires) != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_json_cors(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Could not create candidate session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PGresult *commit = PQexec(conn, "COMMIT");
        if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
            if (commit) PQclear(commit);
            PQexec(conn, "ROLLBACK");
            OPENSSL_cleanse(token, sizeof(token));
            OPENSSL_cleanse(token_hash, sizeof(token_hash));
            db_release(conn, 1);
            send_json_cors(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Could not commit candidate session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PQclear(commit);
        db_release(conn, 0);
        candidate_session_activate(token, candidate_id, now, session_expires);
        candidate_success_response(client_fd, token, candidate_id, candidate_name,
                                   exam_id, exam_title, exam_url, origin,
                                   extra_headers, extra_len);
        audit_log(candidate_id, "CANDIDATE_CHECKIN_APPROVED", exam_id);
        OPENSSL_cleanse(token, sizeof(token));
        OPENSSL_cleanse(token_hash, sizeof(token_hash));
        (void)roll_no;
        return;
    }

    char exam_id[64] = {0}, action[32] = {0}, resource_id[64] = {0};
    if (!parse_candidate_workflow_path(path, exam_id, sizeof(exam_id),
                                       action, sizeof(action), resource_id,
                                       sizeof(resource_id)) ||
        (strcmp(action, "candidate-tokens") != 0 &&
         strcmp(action, "candidate-pins") != 0 &&
         strcmp(action, "candidate-checkins") != 0)) {
        send_json_cors(client_fd, 404, "{\"error\":\"Not found\"}",
                       origin, extra_headers, extra_len);
        return;
    }

    auth_session_t session;
    memset(&session, 0, sizeof(session));
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &session) != 0 ||
        !candidate_auth_role_allowed(session.role)) {
        send_json_cors(client_fd, 403,
            "{\"error\":\"An authenticated invigilator or exam administrator is required\"}",
            origin, extra_headers, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        send_json_cors(client_fd, 503, "{\"error\":\"Database service unavailable\"}",
                       origin, extra_headers, extra_len);
        return;
    }
    const char *exam_params[1] = { exam_id };
    int exam_lengths[1] = { (int)strlen(exam_id) };
    PGresult *exam = db_simple(conn,
        "SELECT institution_id, COALESCE(exam_config->>'authMode',''), status "
        "FROM examinations WHERE id=$1",
        1, exam_params, exam_lengths);
    if (!exam || PQresultStatus(exam) != PGRES_TUPLES_OK || PQntuples(exam) != 1) {
        if (exam) PQclear(exam);
        db_release(conn, 0);
        send_json_cors(client_fd, 404, "{\"error\":\"Examination not found\"}",
                       origin, extra_headers, extra_len);
        return;
    }
    char institution_id[64], exam_auth_mode[32], exam_status[32];
    snprintf(institution_id, sizeof(institution_id), "%s", PQgetvalue(exam, 0, 0));
    snprintf(exam_auth_mode, sizeof(exam_auth_mode), "%s", PQgetvalue(exam, 0, 1));
    snprintf(exam_status, sizeof(exam_status), "%s", PQgetvalue(exam, 0, 2));
    PQclear(exam);
    if (session.role != ROLE_PLATFORM_OWNER &&
        strcmp(session.institution_id, institution_id) != 0) {
        db_release(conn, 0);
        send_json_cors(client_fd, 403, "{\"error\":\"Exam belongs to another institution\"}",
                       origin, extra_headers, extra_len);
        return;
    }
    if (strcmp(exam_status, "scheduled") != 0 &&
        strcmp(exam_status, "ready") != 0 &&
        strcmp(exam_status, "in_progress") != 0) {
        db_release(conn, 0);
        send_json_cors(client_fd, 409,
            "{\"error\":\"Candidate authentication operations are available only for scheduled or live exams\"}",
            origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(action, "candidate-pins") == 0 &&
        strcmp(method, "POST") == 0 && !resource_id[0]) {
        if (strcmp(exam_auth_mode, "candidate-login") != 0 &&
            strcmp(exam_auth_mode, "proctor-verify") != 0) {
            db_release(conn, 0);
            send_json_cors(client_fd, 409,
                "{\"error\":\"Candidate PINs are not used by this examination authentication mode\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char requested_candidate[64] = {0};
        ctrl_json_string(body, "candidate_id", requested_candidate, sizeof(requested_candidate));
        if (!requested_candidate[0]) {
            db_release(conn, 0);
            send_json_cors(client_fd, 400, "{\"error\":\"candidate_id is required\"}",
                           origin, extra_headers, extra_len);
            return;
        }
        const char *candidate_params[3] = { exam_id, institution_id, requested_candidate };
        int candidate_lengths[3] = { (int)strlen(exam_id), (int)strlen(institution_id),
                                     (int)strlen(requested_candidate) };
        PGresult *candidate = db_simple(conn,
            "SELECT id, status, roll_no FROM candidates WHERE exam_id=$1 AND tenant_id=$2 "
            "AND (id=$3 OR roll_no=$3) ORDER BY (id=$3) DESC LIMIT 1",
            3, candidate_params, candidate_lengths);
        if (!candidate || PQresultStatus(candidate) != PGRES_TUPLES_OK ||
            PQntuples(candidate) != 1 ||
            !candidate_status_permits_login(PQntuples(candidate) == 1 ? PQgetvalue(candidate, 0, 1) : "")) {
            if (candidate) PQclear(candidate);
            db_release(conn, 0);
            send_json_cors(client_fd, 404,
                "{\"error\":\"No active candidate assignment exists for this exam and institution\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char candidate_id[64], roll_no[64];
        snprintf(candidate_id, sizeof(candidate_id), "%s", PQgetvalue(candidate, 0, 0));
        snprintf(roll_no, sizeof(roll_no), "%s", PQgetvalue(candidate, 0, 2));
        PQclear(candidate);

        char random_token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        char unused_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        if (secure_token_create(random_token, unused_hash) != 0) {
            db_release(conn, 0);
            send_json_cors(client_fd, 500, "{\"error\":\"Secure PIN generation failed\"}",
                           origin, extra_headers, extra_len);
            return;
        }
        char candidate_pin[13] = {0}, pin_hash[256] = {0};
        memcpy(candidate_pin, random_token, 12);
        if (security_pbkdf2_hash(candidate_pin, roll_no, pin_hash, sizeof(pin_hash)) != 0) {
            OPENSSL_cleanse(random_token, sizeof(random_token));
            OPENSSL_cleanse(unused_hash, sizeof(unused_hash));
            OPENSSL_cleanse(candidate_pin, sizeof(candidate_pin));
            db_release(conn, 0);
            send_json_cors(client_fd, 500, "{\"error\":\"Candidate PIN hashing failed\"}",
                           origin, extra_headers, extra_len);
            return;
        }
        const char *update_params[4] = { pin_hash, candidate_id, exam_id, institution_id };
        int update_lengths[4] = { (int)strlen(pin_hash), (int)strlen(candidate_id),
                                  (int)strlen(exam_id), (int)strlen(institution_id) };
        PGresult *updated = db_simple(conn,
            "UPDATE candidates SET pin_hash=$1 WHERE id=$2 AND exam_id=$3 AND tenant_id=$4 "
            "RETURNING id",
            4, update_params, update_lengths);
        int update_ok = updated && PQresultStatus(updated) == PGRES_TUPLES_OK &&
                        PQntuples(updated) == 1;
        if (updated) PQclear(updated);
        db_release(conn, 0);
        OPENSSL_cleanse(random_token, sizeof(random_token));
        OPENSSL_cleanse(unused_hash, sizeof(unused_hash));
        OPENSSL_cleanse(pin_hash, sizeof(pin_hash));
        if (!update_ok) {
            OPENSSL_cleanse(candidate_pin, sizeof(candidate_pin));
            send_json_cors(client_fd, 500, "{\"error\":\"Candidate PIN could not be persisted\"}",
                           origin, extra_headers, extra_len);
            return;
        }
        char escaped_candidate[128], response[256];
        ctrl_json_escape(candidate_id, escaped_candidate, sizeof(escaped_candidate));
        snprintf(response, sizeof(response),
            "{\"status\":\"created\",\"candidate_id\":\"%s\",\"pin\":\"%s\"}",
            escaped_candidate, candidate_pin);
        send_json_cors(client_fd, 201, response, origin, extra_headers, extra_len);
        audit_log(session.user_id, "CANDIDATE_EXAM_PIN_ISSUED", exam_id);
        OPENSSL_cleanse(candidate_pin, sizeof(candidate_pin));
        return;
    }

    if (strcmp(action, "candidate-tokens") == 0 &&
        strcmp(method, "POST") == 0 && !resource_id[0]) {
        if (strcmp(exam_auth_mode, "exam-token") != 0) {
            db_release(conn, 0);
            send_json_cors(client_fd, 409,
                "{\"error\":\"This examination is not configured for exam-token authentication\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char requested_candidate[64] = {0};
        ctrl_json_string(body, "candidate_id", requested_candidate, sizeof(requested_candidate));
        if (!requested_candidate[0]) {
            db_release(conn, 0);
            send_json_cors(client_fd, 400, "{\"error\":\"candidate_id is required\"}",
                           origin, extra_headers, extra_len);
            return;
        }
        const char *candidate_params[3] = { exam_id, institution_id, requested_candidate };
        int candidate_lengths[3] = { (int)strlen(exam_id), (int)strlen(institution_id),
                                     (int)strlen(requested_candidate) };
        PGresult *candidate = db_simple(conn,
            "SELECT id, status FROM candidates WHERE exam_id=$1 AND tenant_id=$2 "
            "AND (id=$3 OR roll_no=$3) ORDER BY (id=$3) DESC LIMIT 1",
            3, candidate_params, candidate_lengths);
        if (!candidate || PQresultStatus(candidate) != PGRES_TUPLES_OK ||
            PQntuples(candidate) != 1 ||
            !candidate_status_permits_login(PQntuples(candidate) == 1 ? PQgetvalue(candidate, 0, 1) : "")) {
            if (candidate) PQclear(candidate);
            db_release(conn, 0);
            send_json_cors(client_fd, 404,
                "{\"error\":\"No active candidate assignment exists for this exam and institution\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char candidate_id[64];
        snprintf(candidate_id, sizeof(candidate_id), "%s", PQgetvalue(candidate, 0, 0));
        PQclear(candidate);

        char token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        if (secure_token_create(token, token_hash) != 0) {
            db_release(conn, 0);
            send_json_cors(client_fd, 500, "{\"error\":\"Secure token generation failed\"}",
                           origin, extra_headers, extra_len);
            return;
        }
        long long now_ms = (long long)time(NULL) * 1000;
        long long expires_ms = now_ms + 12LL * 60 * 60 * 1000;
        char now_text[32], expires_text[32], token_id[64];
        snprintf(now_text, sizeof(now_text), "%lld", now_ms);
        snprintf(expires_text, sizeof(expires_text), "%lld", expires_ms);
        snprintf(token_id, sizeof(token_id), "cat_%s", token + EXAMOS_TOKEN_HEX_LEN - 16);
        PGresult *begin = PQexec(conn, "BEGIN");
        if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
            if (begin) PQclear(begin);
            db_release(conn, 1);
            OPENSSL_cleanse(token, sizeof(token));
            OPENSSL_cleanse(token_hash, sizeof(token_hash));
            send_json_cors(client_fd, 503, "{\"error\":\"Could not start token issuance transaction\"}",
                           origin, extra_headers, extra_len);
            return;
        }
        PQclear(begin);
        const char *revoke_params[3] = { exam_id, candidate_id, now_text };
        int revoke_lengths[3] = { (int)strlen(exam_id), (int)strlen(candidate_id),
                                  (int)strlen(now_text) };
        PGresult *revoke = db_simple(conn,
            "UPDATE candidate_exam_auth_tokens SET revoked_at=$3::bigint "
            "WHERE examination_id=$1 AND candidate_id=$2 AND used_at IS NULL AND revoked_at IS NULL",
            3, revoke_params, revoke_lengths);
        int revoke_ok = revoke && PQresultStatus(revoke) == PGRES_COMMAND_OK;
        if (revoke) PQclear(revoke);
        const char *insert_params[8] = { token_id, exam_id, institution_id, candidate_id,
                                         token_hash, session.user_id, expires_text, now_text };
        int insert_lengths[8];
        for (int i = 0; i < 8; ++i) insert_lengths[i] = (int)strlen(insert_params[i]);
        PGresult *insert = revoke_ok ? db_simple(conn,
            "INSERT INTO candidate_exam_auth_tokens "
            "(id,examination_id,institution_id,candidate_id,token_hash,issued_by,expires_at,created_at) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7::bigint,$8::bigint)",
            8, insert_params, insert_lengths) : NULL;
        int insert_ok = insert && PQresultStatus(insert) == PGRES_COMMAND_OK;
        if (insert) PQclear(insert);
        PGresult *commit = (revoke_ok && insert_ok) ? PQexec(conn, "COMMIT") : NULL;
        int commit_ok = commit && PQresultStatus(commit) == PGRES_COMMAND_OK;
        if (commit) PQclear(commit);
        if (!commit_ok) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            OPENSSL_cleanse(token, sizeof(token));
            OPENSSL_cleanse(token_hash, sizeof(token_hash));
            send_json_cors(client_fd, 500, "{\"error\":\"Candidate token could not be persisted\"}",
                           origin, extra_headers, extra_len);
            return;
        }
        db_release(conn, 0);
        char escaped_candidate[128], response[512];
        ctrl_json_escape(candidate_id, escaped_candidate, sizeof(escaped_candidate));
        snprintf(response, sizeof(response),
            "{\"status\":\"created\",\"candidate_id\":\"%s\",\"token\":\"%s\",\"expires_at\":%s}",
            escaped_candidate, token, expires_text);
        send_json_cors(client_fd, 201, response, origin, extra_headers, extra_len);
        audit_log(session.user_id, "CANDIDATE_EXAM_TOKEN_ISSUED", exam_id);
        OPENSSL_cleanse(token, sizeof(token));
        OPENSSL_cleanse(token_hash, sizeof(token_hash));
        (void)now_text;
        return;
    }

    if (strcmp(action, "candidate-checkins") == 0 && strcmp(method, "GET") == 0 &&
        !resource_id[0]) {
        if (strcmp(exam_auth_mode, "proctor-verify") != 0) {
            db_release(conn, 0);
            send_json_cors(client_fd, 409,
                "{\"error\":\"This examination is not configured for invigilator verification\"}",
                origin, extra_headers, extra_len);
            return;
        }
        const char *queue_params[2] = { exam_id, institution_id };
        int queue_lengths[2] = { (int)strlen(exam_id), (int)strlen(institution_id) };
        PGresult *queue = db_simple(conn,
            "SELECT ci.id, ci.candidate_id, c.roll_no, c.name, ci.created_at, c.seat "
            "FROM candidate_exam_checkins ci JOIN candidates c ON c.id=ci.candidate_id "
            "WHERE ci.examination_id=$1 AND ci.institution_id=$2 AND ci.status='pending' "
            "AND ci.expires_at > EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 ORDER BY ci.created_at",
            2, queue_params, queue_lengths);
        if (!queue || PQresultStatus(queue) != PGRES_TUPLES_OK) {
            if (queue) PQclear(queue);
            db_release(conn, 0);
            send_json_cors(client_fd, 500, "{\"error\":\"Could not load check-in queue\"}",
                           origin, extra_headers, extra_len);
            return;
        }
        char response[32768];
        size_t used = (size_t)snprintf(response, sizeof(response), "{\"checkins\":[");
        int count = PQntuples(queue);
        for (int i = 0; i < count; ++i) {
            char id_json[128], candidate_json[128], roll_json[128], name_json[256], seat_json[128];
            ctrl_json_escape(PQgetvalue(queue, i, 0), id_json, sizeof(id_json));
            ctrl_json_escape(PQgetvalue(queue, i, 1), candidate_json, sizeof(candidate_json));
            ctrl_json_escape(PQgetvalue(queue, i, 2), roll_json, sizeof(roll_json));
            ctrl_json_escape(PQgetvalue(queue, i, 3), name_json, sizeof(name_json));
            ctrl_json_escape(PQgetvalue(queue, i, 5), seat_json, sizeof(seat_json));
            int written = snprintf(response + used, sizeof(response) - used,
                "%s{\"id\":\"%s\",\"candidate_id\":\"%s\",\"roll_no\":\"%s\","
                "\"name\":\"%s\",\"created_at\":%s,\"seat\":\"%s\"}",
                i ? "," : "", id_json, candidate_json, roll_json, name_json,
                PQgetvalue(queue, i, 4), seat_json);
            if (written < 0 || (size_t)written >= sizeof(response) - used) {
                PQclear(queue);
                db_release(conn, 0);
                send_json_cors(client_fd, 500, "{\"error\":\"Check-in queue exceeds response limit\"}",
                               origin, extra_headers, extra_len);
                return;
            }
            used += (size_t)written;
        }
        if (used + 3 >= sizeof(response)) {
            PQclear(queue);
            db_release(conn, 0);
            send_json_cors(client_fd, 500, "{\"error\":\"Check-in queue exceeds response limit\"}",
                           origin, extra_headers, extra_len);
            return;
        }
        snprintf(response + used, sizeof(response) - used, "]}");
        PQclear(queue);
        db_release(conn, 0);
        send_json_cors(client_fd, 200, response, origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(action, "candidate-checkins") == 0 && strcmp(method, "POST") == 0 &&
        resource_id[0]) {
        if (strcmp(exam_auth_mode, "proctor-verify") != 0) {
            db_release(conn, 0);
            send_json_cors(client_fd, 409,
                "{\"error\":\"This examination is not configured for invigilator verification\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char decision[16] = {0}, reason[256] = {0};
        ctrl_json_string(body, "decision", decision, sizeof(decision));
        ctrl_json_string(body, "reason", reason, sizeof(reason));
        int approve = strcmp(decision, "approve") == 0;
        if ((!approve && strcmp(decision, "reject") != 0) ||
            (!approve && strlen(reason) < 3)) {
            db_release(conn, 0);
            send_json_cors(client_fd, 400,
                "{\"error\":\"decision must be approve or reject; rejection requires a reason\"}",
                origin, extra_headers, extra_len);
            return;
        }
        const char *decision_params[6] = {
            approve ? "approved" : "rejected", session.user_id, reason, resource_id, exam_id,
            institution_id
        };
        int decision_lengths[6];
        for (int i = 0; i < 6; ++i) decision_lengths[i] = (int)strlen(decision_params[i]);
        PGresult *update = db_simple(conn,
            "UPDATE candidate_exam_checkins SET status=$1, verified_by=$2, decision_reason=$3, "
            "verified_at=EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
            "WHERE id=$4 AND examination_id=$5 AND institution_id=$6 AND status='pending' "
            "AND expires_at > EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 RETURNING candidate_id",
            6, decision_params, decision_lengths);
        int updated = update && PQresultStatus(update) == PGRES_TUPLES_OK && PQntuples(update) == 1;
        char decided_candidate[64] = {0};
        if (updated) snprintf(decided_candidate, sizeof(decided_candidate), "%s", PQgetvalue(update, 0, 0));
        if (update) PQclear(update);
        db_release(conn, 0);
        if (!updated) {
            send_json_cors(client_fd, 409,
                "{\"error\":\"Check-in request is no longer pending or has expired\"}",
                origin, extra_headers, extra_len);
            return;
        }
        audit_log(session.user_id, approve ? "CANDIDATE_IDENTITY_APPROVED" : "CANDIDATE_IDENTITY_REJECTED",
                  decided_candidate);
        send_json_cors(client_fd, 200,
            approve ? "{\"status\":\"approved\"}" : "{\"status\":\"rejected\"}",
            origin, extra_headers, extra_len);
        return;
    }

    db_release(conn, 0);
    send_json_cors(client_fd, 404, "{\"error\":\"Not found\"}",
                   origin, extra_headers, extra_len);
}

/* ------------------------------------------------------- candidate login */
void auth_candidate_login(int client_fd, const char *req_body,
                          const char *origin, char *extra_headers, size_t extra_len) {
    char candidate_id[64] = {0}, pin[64] = {0};
    char exam_token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    ctrl_json_string(req_body, "candidate_id", candidate_id, sizeof(candidate_id));
    ctrl_json_string(req_body, "pin", pin, sizeof(pin));
    ctrl_json_string(req_body, "exam_token", exam_token, sizeof(exam_token));

    if (!candidate_id[0]) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Candidate ID is required\"}",
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
    char exam_auth_mode[32] = "candidate-login";
    char exam_institution_id[64] = {0};

    if (found) {
        strncpy(db_id, PQgetvalue(res, 0, 0), sizeof(db_id) - 1);
        strncpy(db_roll, PQgetvalue(res, 0, 1), sizeof(db_roll) - 1);
        strncpy(db_name, PQgetvalue(res, 0, 2), sizeof(db_name) - 1);
        strncpy(db_exam_id, PQgetvalue(res, 0, 3), sizeof(db_exam_id) - 1);
        strncpy(db_pin, PQgetvalue(res, 0, 4), sizeof(db_pin) - 1);
        strncpy(db_status, PQgetvalue(res, 0, 5), sizeof(db_status) - 1);
    }
    if (res) PQclear(res);

    if (found && db_exam_id[0]) {
        const char *auth_params[1] = { db_exam_id };
        int auth_lengths[1] = { (int)strlen(db_exam_id) };
        PGresult *auth_mode_res = db_simple(conn,
            "SELECT COALESCE(exam_config->>'authMode',''), institution_id "
            "FROM examinations WHERE id=$1",
            1, auth_params, auth_lengths);
        if (auth_mode_res && PQresultStatus(auth_mode_res) == PGRES_TUPLES_OK &&
            PQntuples(auth_mode_res) == 1) {
            snprintf(exam_auth_mode, sizeof(exam_auth_mode), "%s",
                     PQgetvalue(auth_mode_res, 0, 0));
            snprintf(exam_institution_id, sizeof(exam_institution_id), "%s",
                     PQgetvalue(auth_mode_res, 0, 1));
        } else {
            if (auth_mode_res) PQclear(auth_mode_res);
            send_json_cors(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"The assigned examination authentication configuration is unavailable\"}",
                origin, extra_headers, extra_len);
            db_release(conn, 0);
            goto done;
        }
        if (auth_mode_res) PQclear(auth_mode_res);
    }

    if (strcmp(exam_auth_mode, "candidate-login") != 0 &&
        strcmp(exam_auth_mode, "exam-token") != 0 &&
        strcmp(exam_auth_mode, "proctor-verify") != 0) {
        send_json_cors(client_fd, 503,
            "{\"status\":\"FAIL\",\"error\":\"The examination has an unsupported authentication configuration\"}",
            origin, extra_headers, extra_len);
        db_release(conn, 0);
        goto done;
    }

    if (strcmp(exam_auth_mode, "exam-token") == 0 && !exam_token[0]) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"This examination requires the single-use token issued at the exam desk\"}",
            origin, extra_headers, extra_len);
        db_release(conn, 0);
        goto done;
    }
    if (strcmp(exam_auth_mode, "exam-token") != 0 && !pin[0]) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Candidate ID and PIN are required for this examination\"}",
            origin, extra_headers, extra_len);
        db_release(conn, 0);
        goto done;
    }

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

    int pin_ok = strcmp(exam_auth_mode, "exam-token") == 0 && found;
    if (strcmp(exam_auth_mode, "exam-token") != 0 && found && db_pin[0]) {
        /*
         * candidates.pin_hash is a bare PBKDF2 digest whose salt is the roster
         * roll number, but the sign-in form may be filled with either the
         * roll number or the internal candidate id.  Try every identifier that
         * identifies this row so a valid candidate is not rejected just
         * because they used the other accepted form.
         */
        static const char *no_salt = "";
        const char *salts[3] = { candidate_id, db_roll, db_id };
        for (int s = 0; s < 3 && !pin_ok; s++) {
            const char *salt = (salts[s] && salts[s][0]) ? salts[s] : no_salt;
            char computed[256] = {0};
            if (security_pbkdf2_hash(pin, salt, computed, sizeof(computed)) == 0 &&
                security_safe_equal(computed, db_pin)) {
                pin_ok = 1;
            }
            OPENSSL_cleanse(computed, sizeof(computed));
        }
        if (!pin_ok && config_verify_password_hash(pin, db_pin) == 1) {
            /* examos_exam_roster: hash is "iterations:salt_hex:hash_hex" format.
             * config_verify_password_hash returns 1 = match. */
            pin_ok = 1;
        }
    } else if (strcmp(exam_auth_mode, "exam-token") != 0 && !found) {
        /* Fallback check against candidates.conf */
        if (candidate_credentials_validate(candidate_id, pin)) {
            pin_ok = 1;
            snprintf(db_id, sizeof(db_id), "%s", candidate_id);
            strncpy(db_name, candidate_id, sizeof(db_name) - 1);
        }
    }
    OPENSSL_cleanse(pin, sizeof(pin));

    if (!pin_ok) {
        record_failure(candidate_id, now);
        send_json_cors(client_fd, 401,
            strcmp(exam_auth_mode, "exam-token") == 0
                ? "{\"status\":\"FAIL\",\"error\":\"Candidate is not assigned to an examination\"}"
                : "{\"status\":\"FAIL\",\"error\":\"Invalid candidate ID or PIN\"}",
            origin, extra_headers, extra_len);
        audit_log(candidate_id, "CANDIDATE_LOGIN_FAILED", "invalid credentials");
        db_release(conn, 0);
        goto done;
    }

    /*
     * Credentials are valid.  Only now enforce account state and eligibility,
     * so a rejected sign-in cannot be used to enumerate roster statuses.  The
     * previous implementation only rejected "disqualified", which let
     * suspended, withdrawn, cancelled and already-submitted candidates open an
     * examination, and never checked schedule windows or eligibility rules.
     */
    if (found && !candidate_status_permits_login(db_status)) {
        send_json_cors(client_fd, 403,
            "{\"status\":\"FAIL\",\"error\":\"This candidate record is not permitted to sign in. Contact your examination controller.\"}",
            origin, extra_headers, extra_len);
        audit_log(db_id[0] ? db_id : candidate_id, "CANDIDATE_LOGIN_DENIED",
                  db_status[0] ? db_status : "inactive status");
        db_release(conn, 0);
        goto done;
    }

    if (!found || !db_exam_id[0]) {
        send_json_cors(client_fd, 403,
            "{\"status\":\"FAIL\",\"error\":\"No assigned institution assessment is configured for this candidate. Contact your examination controller.\"}",
            origin, extra_headers, extra_len);
        audit_log(db_id[0] ? db_id : candidate_id, "CANDIDATE_LOGIN_DENIED",
                  "candidate has no assigned examination");
        db_release(conn, 0);
        goto done;
    }

    {
        char window_reason[256] = {0};
        if (candidate_exam_window_reason(conn, db_exam_id, db_id,
                                         db_id, db_roll,
                                         window_reason, sizeof(window_reason)) != 0) {
            char body[512];
            snprintf(body, sizeof(body),
                "{\"status\":\"FAIL\",\"error\":\"%s\"}",
                window_reason[0] ? window_reason : "You are not permitted to sit this examination.");
            send_json_cors(client_fd, 403, body, origin, extra_headers, extra_len);
            audit_log(db_id[0] ? db_id : candidate_id, "CANDIDATE_LOGIN_DENIED",
                      "not eligible or outside scheduled window");
            db_release(conn, 0);
            goto done;
        }
    }

    char exam_title[128] = "ExamOS Examination", exam_url[512] = "";
    const char *epvals[1] = { db_exam_id };
    int elens[1] = { (int)strlen(db_exam_id) };
    PGresult *eres = db_simple(conn,
        "SELECT title, COALESCE(exam_url, '') FROM exams WHERE id = $1", 1, epvals, elens);
    if (eres && PQresultStatus(eres) == PGRES_TUPLES_OK && PQntuples(eres) > 0) {
        strncpy(exam_title, PQgetvalue(eres, 0, 0), sizeof(exam_title) - 1);
        strncpy(exam_url, PQgetvalue(eres, 0, 1), sizeof(exam_url) - 1);
    }
    if (eres) PQclear(eres);

    if (!exam_url[0]) {
        PGresult *xres = db_simple(conn,
            "SELECT name, COALESCE(exam_url, '') FROM examinations WHERE id = $1 OR code = $1", 1, epvals, elens);
        if (xres && PQresultStatus(xres) == PGRES_TUPLES_OK && PQntuples(xres) > 0) {
            strncpy(exam_title, PQgetvalue(xres, 0, 0), sizeof(exam_title) - 1);
            strncpy(exam_url, PQgetvalue(xres, 0, 1), sizeof(exam_url) - 1);
        }
        if (xres) PQclear(xres);
    }

    if (!exam_url[0]) {
        send_json_cors(client_fd, 503,
            "{\"status\":\"FAIL\",\"error\":\"The assigned institution assessment portal URL is not configured.\"}",
            origin, extra_headers, extra_len);
        audit_log(db_id[0] ? db_id : candidate_id, "CANDIDATE_LOGIN_DENIED",
                  "assigned exam portal URL is not configured");
        db_release(conn, 0);
        goto done;
    }

    if (strcmp(exam_auth_mode, "proctor-verify") == 0) {
        char poll_token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        char poll_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        if (secure_token_create(poll_token, poll_hash) != 0) {
            send_json_cors(client_fd, 500,
                "{\"status\":\"FAIL\",\"error\":\"Secure check-in reference generation failed\"}",
                origin, extra_headers, extra_len);
            db_release(conn, 0);
            goto done;
        }
        long long now_ms = (long long)now * 1000;
        long long expires_ms = now_ms + 15LL * 60 * 1000;
        char now_text[32], expires_text[32], checkin_id[64], escaped_poll[128], response[256];
        snprintf(now_text, sizeof(now_text), "%lld", now_ms);
        snprintf(expires_text, sizeof(expires_text), "%lld", expires_ms);
        snprintf(checkin_id, sizeof(checkin_id), "chk_%s",
                 poll_token + EXAMOS_TOKEN_HEX_LEN - 16);
        const char *checkin_params[7] = {
            checkin_id, db_exam_id, exam_institution_id, db_id, poll_hash, now_text, expires_text
        };
        int checkin_lengths[7];
        for (int i = 0; i < 7; ++i) checkin_lengths[i] = (int)strlen(checkin_params[i]);
        PGresult *begin = PQexec(conn, "BEGIN");
        int transaction_ok = begin && PQresultStatus(begin) == PGRES_COMMAND_OK;
        if (begin) PQclear(begin);
        const char *expire_params[2] = { db_exam_id, db_id };
        int expire_lengths[2] = { (int)strlen(db_exam_id), (int)strlen(db_id) };
        PGresult *expire_old = transaction_ok ? db_simple(conn,
            "UPDATE candidate_exam_checkins SET status='expired' "
            "WHERE examination_id=$1 AND candidate_id=$2 AND status IN ('pending','approved')",
            2, expire_params, expire_lengths) : NULL;
        transaction_ok = transaction_ok && expire_old &&
                         PQresultStatus(expire_old) == PGRES_COMMAND_OK;
        if (expire_old) PQclear(expire_old);
        PGresult *checkin_insert = transaction_ok ? db_simple(conn,
            "INSERT INTO candidate_exam_checkins "
            "(id,examination_id,institution_id,candidate_id,poll_token_hash,status,created_at,expires_at) "
            "VALUES ($1,$2,$3,$4,$5,'pending',$6::bigint,$7::bigint)",
            7, checkin_params, checkin_lengths) : NULL;
        int checkin_ok = checkin_insert &&
                         PQresultStatus(checkin_insert) == PGRES_COMMAND_OK;
        if (checkin_insert) PQclear(checkin_insert);
        PGresult *checkin_commit = (transaction_ok && checkin_ok) ? PQexec(conn, "COMMIT") : NULL;
        int checkin_committed = checkin_commit &&
                                PQresultStatus(checkin_commit) == PGRES_COMMAND_OK;
        if (checkin_commit) PQclear(checkin_commit);
        if (!checkin_committed) PQexec(conn, "ROLLBACK");
        if (!checkin_committed) {
            OPENSSL_cleanse(poll_token, sizeof(poll_token));
            OPENSSL_cleanse(poll_hash, sizeof(poll_hash));
            db_release(conn, 0);
            send_json_cors(client_fd, 500,
                "{\"status\":\"FAIL\",\"error\":\"Could not persist invigilator check-in request\"}",
                origin, extra_headers, extra_len);
            goto done;
        }
        db_release(conn, 0);
        ctrl_json_escape(poll_token, escaped_poll, sizeof(escaped_poll));
        snprintf(response, sizeof(response),
            "{\"status\":\"PENDING_VERIFICATION\",\"poll_token\":\"%s\",\"expires_at\":%s}",
            escaped_poll, expires_text);
        send_json_cors(client_fd, 200, response, origin, extra_headers, extra_len);
        audit_log(db_id, "CANDIDATE_CHECKIN_REQUESTED", db_exam_id);
        OPENSSL_cleanse(poll_token, sizeof(poll_token));
        OPENSSL_cleanse(poll_hash, sizeof(poll_hash));
        clear_failure(candidate_id);
        goto done;
    }

    char token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    char candidate_token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    time_t session_expires = 0;
    int token_transaction = strcmp(exam_auth_mode, "exam-token") == 0;
    if (token_transaction) {
        PGresult *begin = PQexec(conn, "BEGIN");
        if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
            if (begin) PQclear(begin);
            db_release(conn, 1);
            send_json_cors(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Could not start one-time token redemption\"}",
                origin, extra_headers, extra_len);
            goto done;
        }
        PQclear(begin);
        char supplied_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        if (secure_token_hash(exam_token, supplied_hash) != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_json_cors(client_fd, 401,
                "{\"status\":\"FAIL\",\"error\":\"Invalid or expired exam token\"}",
                origin, extra_headers, extra_len);
            OPENSSL_cleanse(supplied_hash, sizeof(supplied_hash));
            goto done;
        }
        char now_ms_text[32];
        snprintf(now_ms_text, sizeof(now_ms_text), "%lld", (long long)now * 1000);
        const char *redeem_params[4] = { supplied_hash, db_exam_id, db_id, now_ms_text };
        int redeem_lengths[4] = {
            (int)strlen(supplied_hash), (int)strlen(db_exam_id),
            (int)strlen(db_id), (int)strlen(now_ms_text)
        };
        PGresult *redeemed = db_simple(conn,
            "UPDATE candidate_exam_auth_tokens SET used_at=$4::bigint "
            "WHERE token_hash=$1 AND examination_id=$2 AND candidate_id=$3 "
            "AND used_at IS NULL AND revoked_at IS NULL AND expires_at>$4::bigint "
            "RETURNING id",
            4, redeem_params, redeem_lengths);
        int redeem_ok = redeemed && PQresultStatus(redeemed) == PGRES_TUPLES_OK &&
                        PQntuples(redeemed) == 1;
        if (redeemed) PQclear(redeemed);
        OPENSSL_cleanse(supplied_hash, sizeof(supplied_hash));
        if (!redeem_ok) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_json_cors(client_fd, 401,
                "{\"status\":\"FAIL\",\"error\":\"Invalid, expired, revoked or already-used exam token\"}",
                origin, extra_headers, extra_len);
            record_failure(candidate_id, now);
            goto done;
        }
    }

    const char *session_candidate_id = db_id[0] ? db_id : candidate_id;
    if (candidate_session_persist(conn, session_candidate_id, exam_institution_id, now,
                                  token, candidate_token_hash, &session_expires) != 0) {
        if (token_transaction) PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        send_json_cors(client_fd, 503,
            "{\"status\":\"FAIL\",\"error\":\"Candidate session could not be persisted\"}",
            origin, extra_headers, extra_len);
        goto done;
    }
    if (token_transaction) {
        PGresult *commit = PQexec(conn, "COMMIT");
        if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
            if (commit) PQclear(commit);
            PQexec(conn, "ROLLBACK");
            OPENSSL_cleanse(token, sizeof(token));
            OPENSSL_cleanse(candidate_token_hash, sizeof(candidate_token_hash));
            db_release(conn, 1);
            send_json_cors(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Could not commit one-time exam token redemption\"}",
                origin, extra_headers, extra_len);
            goto done;
        }
        PQclear(commit);
    }
    db_release(conn, 0);
    candidate_session_activate(token, session_candidate_id, now, session_expires);
    candidate_success_response(client_fd, token, session_candidate_id,
                               db_name[0] ? db_name : candidate_id, db_exam_id,
                               exam_title, exam_url, origin, extra_headers, extra_len);
    OPENSSL_cleanse(token, sizeof(token));
    OPENSSL_cleanse(candidate_token_hash, sizeof(candidate_token_hash));
    clear_failure(candidate_id);
    audit_log(session_candidate_id, "CANDIDATE_LOGIN_SUCCESS", candidate_id);

done:
    OPENSSL_cleanse(pin, sizeof(pin));
    OPENSSL_cleanse(exam_token, sizeof(exam_token));
}

/* --------------------------------------------------------- candidate logout */
void auth_candidate_logout(int client_fd, const char *auth_header,
                           const char *origin, char *extra_headers, size_t extra_len) {
    char token[128] = {0};
    ctrl_extract_bearer(auth_header, token, sizeof(token));

    if (token[0]) {
        char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
        if (secure_token_hash(token, token_hash) == 0) {
            PGconn *conn = db_acquire();
            if (conn) {
                const char *p[1] = { token_hash };
                int l[1] = { (int)strlen(token_hash) };
                PGresult *r = db_simple(conn,
                    "UPDATE auth_sessions SET status = 'ended' "
                    "WHERE session_token = $1 AND role = 'candidate' AND status = 'active'",
                    1, p, l);
                if (r) PQclear(r);
                db_release(conn, 0);
            }
        }

        /* Drop the in-process session immediately and journal the change so a
         * restart cannot resurrect a logged-out candidate. */
        candidate_session_invalidate(token);
        {
            session_journal_record_t rec;
            memset(&rec, 0, sizeof(rec));
            rec.event_type = SESSION_EVENT_INVALIDATE;
            snprintf(rec.token, sizeof(rec.token), "%s", token);
            rec.created_at = time(NULL);
            rec.expires_at = rec.created_at + 28800;
            if (session_store_record(&rec) != 0) {
                fprintf(stderr, "[AUTH] WARN: candidate logout journal append failed\n");
            }
        }

        OPENSSL_cleanse(token_hash, sizeof(token_hash));
        audit_log("candidate", "CANDIDATE_LOGOUT", "session ended");
    }
    OPENSSL_cleanse(token, sizeof(token));

    send_json_cors(client_fd, 200, "{\"status\":\"SIGNED_OUT\"}",
                   origin, extra_headers, extra_len);
}

/* ----------------------------------------------------------- MFA TOTP Setup */
/*
 * Enrollment challenge model
 * --------------------------
 * The client never supplies the account it is enrolling or the TOTP secret.
 * A challenge row is created by /admin/login after a successful password
 * check; this handler only accepts either
 *
 *   • the single-use enrollment token issued by that login, or
 *   • an authenticated management session (MFA rotation),
 *
 * and generates the secret plus recovery codes server-side.  The secret is
 * persisted on the challenge row and is only promoted to the account by
 * /admin/mfa/confirm after a valid TOTP code proves possession.
 */
void auth_mfa_setup(int client_fd, const char *req_body, const char *auth_header,
                    const char *enrollment_token,
                    const char *origin, char *extra_headers, size_t extra_len) {
    (void)req_body;

    char user_id[64] = {0}, username[128] = {0};
    char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    char response_token[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    int have_challenge = 0;

    PGconn *conn = db_acquire();
    if (!conn) {
        send_json_cors(client_fd, 503,
            "{\"status\":\"FAIL\",\"error\":\"Database service unavailable\"}",
            origin, extra_headers, extra_len);
        return;
    }

    if (enrollment_token && enrollment_token[0] &&
        secure_token_hash(enrollment_token, token_hash) == 0) {
        const char *p[1] = { token_hash };
        int l[1] = { (int)strlen(token_hash) };
        PGresult *r = db_simple(conn,
            "SELECT user_id, username FROM examos_admin_mfa_enrollments "
            "WHERE token_hash = $1 AND expires_at > clock_timestamp()",
            1, p, l);
        if (r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
            strncpy(user_id, PQgetvalue(r, 0, 0), sizeof(user_id) - 1);
            strncpy(username, PQgetvalue(r, 0, 1), sizeof(username) - 1);
            strncpy(response_token, enrollment_token, sizeof(response_token) - 1);
            have_challenge = 1;
        }
        if (r) PQclear(r);
    }

    if (!have_challenge) {
        /* Re-enrollment by an already authenticated management user. */
        auth_session_t sess;
        if (auth_header && auth_header[0] &&
            ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) == 0) {
            snprintf(user_id, sizeof(user_id), "%s", sess.user_id);
            strncpy(username, sess.username, sizeof(username) - 1);
            if (secure_token_create(response_token, token_hash) != 0) {
                db_release(conn, 0);
                send_json_cors(client_fd, 500,
                    "{\"status\":\"FAIL\",\"error\":\"Cryptographic randomness failure\"}",
                    origin, extra_headers, extra_len);
                return;
            }
            have_challenge = 1;
        }
    }

    if (!have_challenge) {
        db_release(conn, 0);
        send_json_cors(client_fd, 401,
            "{\"status\":\"FAIL\",\"error\":\"A valid enrollment token or authenticated management session is required\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* 1. Generate 20-byte random secret -> Base32 (32 chars). */
    char base32_secret[TOTP_BASE32_LEN + 1] = {0};
    if (totp_generate_secret(base32_secret) != 0) {
        db_release(conn, 0);
        send_json_cors(client_fd, 500,
            "{\"status\":\"FAIL\",\"error\":\"Cryptographic randomness generation failed\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* 2. Build the standard otpauth:// URI for the authenticator app. */
    char otpauth_url[512] = {0};
    totp_generate_uri(username, "ExamOS", base32_secret, otpauth_url, sizeof(otpauth_url));

    /* 3. Generate 8 single-use recovery codes and their hashes. */
    char codes[TOTP_NUM_RECOVERY_CODES][TOTP_RECOVERY_CODE_LEN + 1];
    char hashes[TOTP_NUM_RECOVERY_CODES][65];
    if (totp_generate_recovery_codes(codes, hashes) != 0) {
        db_release(conn, 0);
        send_json_cors(client_fd, 500,
            "{\"status\":\"FAIL\",\"error\":\"Recovery code generation failed\"}",
            origin, extra_headers, extra_len);
        return;
    }

    char recovery_hashes[sizeof(hashes) + 16] = {0};
    for (int i = 0; i < TOTP_NUM_RECOVERY_CODES; i++) {
        if (i) strncat(recovery_hashes, ",", sizeof(recovery_hashes) - strlen(recovery_hashes) - 1);
        strncat(recovery_hashes, hashes[i], sizeof(recovery_hashes) - strlen(recovery_hashes) - 1);
    }

    /* 4. Persist the challenge (secret stays server-side until confirm). */
    const char *up[4] = { base32_secret, recovery_hashes, token_hash, "" };
    int ul[4] = { (int)strlen(base32_secret), (int)strlen(recovery_hashes),
                  (int)strlen(token_hash), 0 };
    PGresult *upd = db_simple(conn,
        "UPDATE examos_admin_mfa_enrollments "
        "SET secret = $1, recovery_hashes = $2, attempts = 0 "
        "WHERE token_hash = $3",
        3, up, ul);
    int updated = upd && PQresultStatus(upd) == PGRES_COMMAND_OK &&
                  atoi(PQcmdTuples(upd)) > 0;
    if (upd) PQclear(upd);

    if (!updated) {
        /* Session-driven rotation: create a fresh challenge row. */
        const char *del_p[1] = { user_id[0] ? user_id : username };
        int del_l[1] = { (int)strlen(del_p[0]) };
        PGresult *del_r = db_simple(conn,
            "DELETE FROM examos_admin_mfa_enrollments WHERE user_id = $1",
            1, del_p, del_l);
        if (del_r) PQclear(del_r);

        const char *ins_p[5] = { token_hash, user_id[0] ? user_id : username,
                                 username, base32_secret, recovery_hashes };
        int ins_l[5] = { (int)strlen(ins_p[0]), (int)strlen(ins_p[1]),
                         (int)strlen(ins_p[2]), (int)strlen(ins_p[3]),
                         (int)strlen(ins_p[4]) };
        PGresult *ins_r = db_simple(conn,
            "INSERT INTO examos_admin_mfa_enrollments "
            "(token_hash, user_id, username, secret, recovery_hashes, expires_at) "
            "VALUES ($1, $2, $3, $4, $5, clock_timestamp() + interval '10 minutes')",
            5, ins_p, ins_l);
        int inserted = ins_r && PQresultStatus(ins_r) == PGRES_COMMAND_OK;
        if (ins_r) PQclear(ins_r);
        if (!inserted) {
            db_release(conn, 0);
            send_json_cors(client_fd, 500,
                "{\"status\":\"FAIL\",\"error\":\"Could not persist the MFA enrollment challenge\"}",
                origin, extra_headers, extra_len);
            return;
        }
    }

    /* Construct JSON response with recovery codes array. */
    char recovery_json[1024] = "[";
    for (int i = 0; i < TOTP_NUM_RECOVERY_CODES; i++) {
        char item[128];
        snprintf(item, sizeof(item), "%s\"%s\"", (i > 0) ? "," : "", codes[i]);
        strncat(recovery_json, item, sizeof(recovery_json) - strlen(recovery_json) - 1);
    }
    strncat(recovery_json, "]", sizeof(recovery_json) - strlen(recovery_json) - 1);

    db_release(conn, 0);

    char resp_body[2048];
    snprintf(resp_body, sizeof(resp_body),
        "{\"status\":\"SUCCESS\",\"username\":\"%s\",\"secret\":\"%s\","
        "\"otpauth_url\":\"%s\",\"recovery_codes\":%s,"
        "\"enrollment_token\":\"%s\",\"expires_in\":600,"
        "\"algorithm\":\"SHA1\",\"digits\":6,\"period\":30,\"issuer\":\"ExamOS\"}",
        username, base32_secret, otpauth_url, recovery_json, response_token);

    OPENSSL_cleanse(base32_secret, sizeof(base32_secret));
    OPENSSL_cleanse(hashes, sizeof(hashes));
    send_json_cors(client_fd, 200, resp_body, origin, extra_headers, extra_len);
    audit_log(username, "MFA_SETUP_INITIATED", "Generated server-side TOTP secret and recovery codes");
}

/* --------------------------------------------------------- MFA TOTP Confirm */
void auth_mfa_confirm(int client_fd, const char *req_body, const char *auth_header,
                      const char *enrollment_token,
                      const char *origin, char *extra_headers, size_t extra_len) {
    (void)auth_header;

    char code[32] = {0};
    ctrl_json_string(req_body, "code", code, sizeof(code));
    /* The client no longer supplies a secret or a username; both come from the
     * server-side challenge row created before the QR code was displayed. */
    if (!code[0]) ctrl_json_string(req_body, "mfa_code", code, sizeof(code));

    if (!enrollment_token || !enrollment_token[0] || !code[0]) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Enrollment token and 6-digit confirmation code are required\"}",
            origin, extra_headers, extra_len);
        return;
    }

    char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    if (secure_token_hash(enrollment_token, token_hash) != 0) {
        send_json_cors(client_fd, 500,
            "{\"status\":\"FAIL\",\"error\":\"Enrollment token could not be processed\"}",
            origin, extra_headers, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        send_json_cors(client_fd, 503,
            "{\"status\":\"FAIL\",\"error\":\"Database unavailable\"}",
            origin, extra_headers, extra_len);
        return;
    }

    const char *p[1] = { token_hash };
    int l[1] = { (int)strlen(token_hash) };
    PGresult *r = db_simple(conn,
        "SELECT user_id, username, secret, recovery_hashes, attempts "
        "FROM examos_admin_mfa_enrollments "
        "WHERE token_hash = $1 AND expires_at > clock_timestamp()",
        1, p, l);

    if (!r || PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) == 0) {
        if (r) PQclear(r);
        db_release(conn, 0);
        send_json_cors(client_fd, 401,
            "{\"status\":\"FAIL\",\"error\":\"Enrollment token is invalid or has expired. Sign in again to restart setup.\"}",
            origin, extra_headers, extra_len);
        return;
    }

    char user_id[64] = {0}, username[128] = {0}, secret[64] = {0};
    char recovery_hashes[TOTP_NUM_RECOVERY_CODES * 65 + 16] = {0};
    strncpy(user_id, PQgetvalue(r, 0, 0), sizeof(user_id) - 1);
    strncpy(username, PQgetvalue(r, 0, 1), sizeof(username) - 1);
    strncpy(secret, PQgetvalue(r, 0, 2), sizeof(secret) - 1);
    {
        const char *rh = PQgetvalue(r, 0, 3);
        if (rh) strncpy(recovery_hashes, rh, sizeof(recovery_hashes) - 1);
    }
    int attempts = atoi(PQgetvalue(r, 0, 4));
    PQclear(r);

    if (!secret[0]) {
        db_release(conn, 0);
        send_json_cors(client_fd, 409,
            "{\"status\":\"FAIL\",\"error\":\"No authenticator secret exists for this enrollment. Request a new setup QR code.\"}",
            origin, extra_headers, extra_len);
        return;
    }

    if (attempts >= 10) {
        const char *dp[1] = { token_hash };
        int dl[1] = { (int)strlen(token_hash) };
        PGresult *dr = db_simple(conn,
            "DELETE FROM examos_admin_mfa_enrollments WHERE token_hash = $1", 1, dp, dl);
        if (dr) PQclear(dr);
        db_release(conn, 0);
        audit_log(username, "MFA_CONFIRM_LOCKED", "too many invalid confirmation attempts");
        send_json_cors(client_fd, 429,
            "{\"status\":\"FAIL\",\"error\":\"Too many invalid codes. Sign in again to restart authenticator setup.\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* Sanitize 6-digit TOTP code (strip spaces/dashes). */
    char clean_code[16] = {0};
    size_t c_idx = 0;
    for (size_t i = 0; code[i] && c_idx < 6; i++) {
        if (isdigit((unsigned char)code[i])) clean_code[c_idx++] = code[i];
    }
    clean_code[c_idx] = '\0';

    /* Verify code from the authenticator (window +-3 = +-90s clock skew). */
    time_t now = time(NULL);
    if (!clean_code[0] || !totp_verify_code(secret, clean_code, now, 3)) {
        const char *ap[1] = { token_hash };
        int al[1] = { (int)strlen(token_hash) };
        PGresult *ar = db_simple(conn,
            "UPDATE examos_admin_mfa_enrollments SET attempts = attempts + 1 "
            "WHERE token_hash = $1", 1, ap, al);
        if (ar) PQclear(ar);
        db_release(conn, 0);
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Invalid authentication code. Ensure your device time is synchronized with network time.\"}",
            origin, extra_headers, extra_len);
        audit_log(username, "MFA_CONFIRM_FAILED", "invalid verification code");
        return;
    }

    /* 1. Promote the secret to the account directory row. */
    const char *u_p[2] = { secret, user_id[0] ? user_id : username };
    int u_l[2] = { (int)strlen(secret), (int)strlen(u_p[1]) };
    PGresult *u_res = db_simple(conn,
        "UPDATE users SET totp_secret = $1, mfa_enabled = 1 "
        "WHERE id = $2 OR LOWER(username) = LOWER($2)",
        2, u_p, u_l);
    if (u_res) PQclear(u_res);

    /* 2. Promote to examos_admin_users and obtain the canonical user id. */
    PGresult *a_res = db_simple(conn,
        "UPDATE examos_admin_users SET totp_secret = $1, mfa_enabled = true, "
        "totp_enrolled_at = clock_timestamp() "
        "WHERE user_id = $2 OR LOWER(username) = LOWER($2) RETURNING user_id",
        2, u_p, u_l);
    char admin_user_id[64] = {0};
    if (a_res && PQresultStatus(a_res) == PGRES_TUPLES_OK && PQntuples(a_res) > 0) {
        strncpy(admin_user_id, PQgetvalue(a_res, 0, 0), sizeof(admin_user_id) - 1);
    }
    if (a_res) PQclear(a_res);

    /* 3. Install the recovery code hashes generated during setup. */
    const char *uid = admin_user_id[0] ? admin_user_id : (user_id[0] ? user_id : username);
    if (recovery_hashes[0]) {
        const char *del_p[1] = { uid };
        int del_l[1] = { (int)strlen(uid) };
        PGresult *d_res = db_simple(conn,
            "DELETE FROM examos_admin_recovery_codes WHERE user_id = $1 AND NOT used",
            1, del_p, del_l);
        if (d_res) PQclear(d_res);

        char work[sizeof(recovery_hashes)];
        strncpy(work, recovery_hashes, sizeof(work) - 1);
        work[sizeof(work) - 1] = '\0';
        char *cursor = work;
        while (cursor && *cursor) {
            char *comma = strchr(cursor, ',');
            if (comma) *comma = '\0';
            if (strlen(cursor) == 64) {
                const char *ins_p[2] = { cursor, uid };
                int ins_l[2] = { 64, (int)strlen(uid) };
                PGresult *ins_r = db_simple(conn,
                    "INSERT INTO examos_admin_recovery_codes (code_hash, user_id, used) "
                    "VALUES ($1, $2, false) ON CONFLICT (code_hash) DO NOTHING",
                    2, ins_p, ins_l);
                if (ins_r) PQclear(ins_r);
            }
            if (!comma) break;
            cursor = comma + 1;
        }
        OPENSSL_cleanse(work, sizeof(work));
    }

    /* 4. Burn the single-use challenge. */
    const char *del_p[1] = { token_hash };
    int del_l[1] = { (int)strlen(token_hash) };
    PGresult *del_r = db_simple(conn,
        "DELETE FROM examos_admin_mfa_enrollments WHERE token_hash = $1",
        1, del_p, del_l);
    if (del_r) PQclear(del_r);

    db_release(conn, 0);

    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(recovery_hashes, sizeof(recovery_hashes));

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

    if (!password_meets_policy(new_pw)) {
        send_json_cors(client_fd, 400,
            "{\"status\":\"FAIL\",\"error\":\"Password must be at least 12 characters long and contain uppercase, lowercase, numbers, and symbols\"}",
            origin, extra_headers, extra_len);
        goto r_done;
    }

    /* Recovery attempts are rate-limited with the same lockout accounting as
     * password login, otherwise the 8-code space can be ground down. */
    time_t r_now = time(NULL);
    {
        char lock_err[256] = {0};
        if (check_lockout(username, r_now, lock_err, sizeof(lock_err))) {
            send_json_cors(client_fd, 429, lock_err, origin, extra_headers, extra_len);
            audit_log(username, "RECOVERY_RESET_LOCKED", "brute force threshold exceeded");
            goto r_done;
        }
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
        record_failure(username, r_now);
        send_json_cors(client_fd, 401,
            "{\"status\":\"FAIL\",\"error\":\"Invalid recovery details\"}",
            origin, extra_headers, extra_len);
        audit_log(username, "RECOVERY_RESET_FAILED", "unknown account or invalid code");
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
        record_failure(username, r_now);
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
    /*
     * security_pbkdf2_hash() derives with 210,000 iterations.  The prefix must
     * match that number: a mismatched prefix produced a credential that could
     * never verify (config_verify_password_hash recomputes with the stated
     * count).
     */
    snprintf(full_cred, sizeof(full_cred), "210000:%s:%s", salt_hex, new_hash);
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

    /* Also revoke the mirrored admin session rows, which are the fallback
     * lookup path in security_verify_session(). */
    PGresult *inv2 = db_simple(conn,
        "UPDATE examos_admin_sessions SET revoked_at = clock_timestamp() "
        "WHERE user_id = $1 AND revoked_at IS NULL",
        1, inv_p, inv_l);
    if (inv2) PQclear(inv2);

    clear_failure(username);
    db_release(conn, 0);

    send_json_cors(client_fd, 200,
        "{\"status\":\"SUCCESS\",\"message\":\"Password has been securely reset. You can now sign in with your new credentials.\"}",
        origin, extra_headers, extra_len);
    audit_log(username, "RECOVERY_RESET_SUCCESS", "password reset via emergency code");

r_done:
    OPENSSL_cleanse(new_pw, sizeof(new_pw));
}
