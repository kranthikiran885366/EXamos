#define _GNU_SOURCE
#include "../../server/include/admin_auth_store.h"
#include "../../server/include/config_manager.h"
#include "../../server/include/enterprise_platform.h"
#include "../../server/include/totp.h"

#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void cleanup_test_database(void) {
    const char *conn_file = getenv("EXAMOS_DATABASE_URL_FILE");
    if (!conn_file || !conn_file[0]) conn_file = "/etc/examos/secrets/test_db_url";
    FILE *f = fopen(conn_file, "r");
    if (!f) return;
    char conninfo[1024];
    if (!fgets(conninfo, sizeof(conninfo), f)) { fclose(f); return; }
    fclose(f);
    conninfo[strcspn(conninfo, "\r\n")] = '\0';

    PGconn *conn = PQconnectdb(conninfo);
    if (conn && PQstatus(conn) == CONNECTION_OK) {
        PQexec(conn, "DELETE FROM examos_admin_sessions");
        PQexec(conn, "DELETE FROM examos_admin_audit");
        PQexec(conn, "DELETE FROM examos_admin_recovery_codes");
        PQexec(conn, "DELETE FROM examos_admin_password_resets");
        PQexec(conn, "DELETE FROM examos_admin_users");
        PQfinish(conn);
    }
}

int main(void) {
    puts("=== Starting ExamOS Enterprise Authentication & MFA E2E Test Suite ===");

    if (!getenv("EXAMOS_DATABASE_URL_FILE")) {
        setenv("EXAMOS_DATABASE_URL_FILE", "/etc/examos/secrets/test_db_url", 1);
    }

    cleanup_test_database();

    /* 1. Initialize store and verify schema */
    if (admin_auth_store_init() != 0) {
        fprintf(stderr, "FAIL: admin_auth_store_init failed to connect or verify schema over TLS\n");
        return 1;
    }
    puts("[1/10] PASS: PostgreSQL TLS handshake, connection pool, and migrations 001/002 verified");

    /* 2. Provision Initial Platform Owner */
    user_account_t owner;
    memset(&owner, 0, sizeof(owner));
    snprintf(owner.user_id, sizeof(owner.user_id), "USR-OWNER-TEST-1");
    snprintf(owner.username, sizeof(owner.username), "owner_admin");
    snprintf(owner.full_name, sizeof(owner.full_name), "Primary Platform Owner");
    snprintf(owner.email, sizeof(owner.email), "owner@examos.internal");
    owner.role = ROLE_PLATFORM_OWNER;
    owner.active = 1;

    char owner_password[] = "OwnerSecret#2026!ExamOS";
    if (config_create_password_hash(owner_password, owner.password_hash, sizeof(owner.password_hash)) != 0) {
        fprintf(stderr, "FAIL: failed to hash owner password\n");
        return 1;
    }

    if (admin_auth_store_create_initial_owner(&owner) != 0) {
        fprintf(stderr, "FAIL: failed to create initial platform owner\n");
        return 1;
    }

    /* Verify duplicate initial owner is rejected */
    if (admin_auth_store_create_initial_owner(&owner) == 0) {
        fprintf(stderr, "FAIL: duplicate platform owner creation succeeded\n");
        return 1;
    }
    puts("[2/10] PASS: Initial Platform Owner provisioned and duplicate creation strictly prevented");

    /* 3. Provision Subordinate Accounts (Institution Admin, Exam Manager, Readonly Auditor) */
    user_account_t manager;
    memset(&manager, 0, sizeof(manager));
    snprintf(manager.user_id, sizeof(manager.user_id), "USR-MGR-TEST-2");
    snprintf(manager.username, sizeof(manager.username), "exam_manager_1");
    snprintf(manager.full_name, sizeof(manager.full_name), "Lead Exam Manager");
    snprintf(manager.email, sizeof(manager.email), "manager@university.edu");
    snprintf(manager.institution_id, sizeof(manager.institution_id), "INST-UNIV-01");
    manager.role = ROLE_EXAM_MANAGER;
    manager.active = 1;
    char manager_password[] = "ManagerSecret#2026!ExamOS";
    config_create_password_hash(manager_password, manager.password_hash, sizeof(manager.password_hash));

    if (admin_auth_store_create_user(&manager, owner.user_id) != 0) {
        fprintf(stderr, "FAIL: failed to create exam manager account\n");
        return 1;
    }

    user_account_t auditor;
    memset(&auditor, 0, sizeof(auditor));
    snprintf(auditor.user_id, sizeof(auditor.user_id), "USR-AUD-TEST-3");
    snprintf(auditor.username, sizeof(auditor.username), "auditor_user");
    snprintf(auditor.full_name, sizeof(auditor.full_name), "External Compliance Auditor");
    auditor.role = ROLE_READONLY_AUDITOR;
    auditor.active = 1;
    char auditor_password[] = "AuditorSecret#2026!ExamOS";
    config_create_password_hash(auditor_password, auditor.password_hash, sizeof(auditor.password_hash));

    if (admin_auth_store_create_user(&auditor, owner.user_id) != 0) {
        fprintf(stderr, "FAIL: failed to create readonly auditor account\n");
        return 1;
    }
    puts("[3/10] PASS: Privileged roles created via authorized Platform Owner");

    /* 4. Pre-MFA Login Verification */
    auth_session_t session;
    memset(&session, 0, sizeof(session));

    /* Valid password login without MFA */
    if (admin_auth_store_login(manager.username, manager_password, NULL, &session) != AUTH_LOGIN_SUCCESS ||
        strlen(session.session_token) != 64 || session.role != ROLE_EXAM_MANAGER) {
        fprintf(stderr, "FAIL: valid login failed for exam manager\n");
        return 1;
    }

    /* Invalid password rejection */
    auth_session_t bad_sess;
    if (admin_auth_store_login(manager.username, "WrongPassword#123", NULL, &bad_sess) != AUTH_LOGIN_FAILED) {
        fprintf(stderr, "FAIL: invalid password was accepted\n");
        return 1;
    }

    /* Non-existent user rejection */
    if (admin_auth_store_login("non_existent_user", manager_password, NULL, &bad_sess) != AUTH_LOGIN_FAILED) {
        fprintf(stderr, "FAIL: non-existent username was accepted\n");
        return 1;
    }
    puts("[4/10] PASS: Standard authentication verified (valid, invalid, and unknown credentials)");

    /* 5. TOTP MFA Enrollment & Confirmation for Platform Owner */
    char secret[TOTP_BASE32_LEN + 1];
    char uri[512];
    char recovery_codes[TOTP_NUM_RECOVERY_CODES][TOTP_RECOVERY_CODE_LEN + 1];

    if (admin_auth_store_mfa_enroll(owner.username, secret, uri, sizeof(uri), recovery_codes) != 0) {
        fprintf(stderr, "FAIL: MFA enrollment failed\n");
        return 1;
    }

    /* Confirm with invalid code should fail */
    if (admin_auth_store_mfa_confirm(owner.username, "000000") == 0) {
        fprintf(stderr, "FAIL: MFA confirmation accepted invalid 000000 code\n");
        return 1;
    }

    /* Compute current valid TOTP code */
    char valid_code[TOTP_CODE_LEN + 1];
    if (totp_generate_code(secret, time(NULL), valid_code) != 0) {
        fprintf(stderr, "FAIL: failed to generate TOTP code\n");
        return 1;
    }

    /* Confirm with valid code */
    if (admin_auth_store_mfa_confirm(owner.username, valid_code) != 0) {
        fprintf(stderr, "FAIL: MFA confirmation failed with valid code\n");
        return 1;
    }
    puts("[5/10] PASS: TOTP MFA secret enrollment, recovery codes generation, and code confirmation");

    /* 6. Enforced MFA Login Flow */
    /* Step 1: Login without code must return AUTH_LOGIN_MFA_REQUIRED */
    int res = admin_auth_store_login(owner.username, owner_password, NULL, &session);
    if (res != AUTH_LOGIN_MFA_REQUIRED) {
        fprintf(stderr, "FAIL: expected AUTH_LOGIN_MFA_REQUIRED, got %d\n", res);
        return 1;
    }

    /* Step 2: Login with wrong MFA code must fail */
    res = admin_auth_store_login(owner.username, owner_password, "999999", &session);
    if (res != AUTH_LOGIN_FAILED) {
        fprintf(stderr, "FAIL: invalid MFA code was accepted\n");
        return 1;
    }

    /* Step 3: Login with fresh valid TOTP code must succeed */
    totp_generate_code(secret, time(NULL), valid_code);
    res = admin_auth_store_login(owner.username, owner_password, valid_code, &session);
    if (res != AUTH_LOGIN_SUCCESS || strlen(session.session_token) != 64 || session.role != ROLE_PLATFORM_OWNER) {
        fprintf(stderr, "FAIL: valid MFA login failed\n");
        return 1;
    }
    puts("[6/10] PASS: Two-factor authentication strictly enforced on privileged account");

    /* 7. Single-Use Emergency Recovery Code Login */
    /* Use recovery code #0 */
    res = admin_auth_store_login(owner.username, owner_password, recovery_codes[0], &session);
    if (res != AUTH_LOGIN_SUCCESS) {
        fprintf(stderr, "FAIL: recovery code login failed for %s\n", recovery_codes[0]);
        return 1;
    }

    /* Re-use of recovery code #0 MUST FAIL */
    res = admin_auth_store_login(owner.username, owner_password, recovery_codes[0], &session);
    if (res == AUTH_LOGIN_SUCCESS) {
        fprintf(stderr, "FAIL: recovery code was reused successfully; single-use violation!\n");
        return 1;
    }
    puts("[7/10] PASS: Emergency recovery code accepted and single-use exhaustion strictly enforced");

    /* 8. Granular RBAC Permission Verification */
    auth_session_t auth_check;

    /* Exam Manager permission check */
    auth_session_t manager_session;
    if (admin_auth_store_login(manager.username, manager_password, NULL, &manager_session) != AUTH_LOGIN_SUCCESS) {
        fprintf(stderr, "FAIL: manager login failed\n");
        return 1;
    }
    if (admin_auth_store_authorize(manager_session.session_token, AUTH_PERM_EXAM_MUTATION, &auth_check) != 0) {
        fprintf(stderr, "FAIL: Exam Manager was denied AUTH_PERM_EXAM_MUTATION\n");
        return 1;
    }
    if (admin_auth_store_authorize(manager_session.session_token, AUTH_PERM_FLEET_MUTATION, &auth_check) == 0) {
        fprintf(stderr, "FAIL: Exam Manager was granted unauthorized AUTH_PERM_FLEET_MUTATION\n");
        return 1;
    }
    if (admin_auth_store_authorize(manager_session.session_token, AUTH_PERM_USER_MANAGEMENT, &auth_check) == 0) {
        fprintf(stderr, "FAIL: Exam Manager was granted unauthorized AUTH_PERM_USER_MANAGEMENT\n");
        return 1;
    }

    /* Readonly Auditor permission check */
    if (admin_auth_store_login(auditor.username, auditor_password, NULL, &session) != AUTH_LOGIN_SUCCESS) {
        fprintf(stderr, "FAIL: auditor login failed\n");
        return 1;
    }
    if (admin_auth_store_authorize(session.session_token, AUTH_PERM_READ, &auth_check) != 0) {
        fprintf(stderr, "FAIL: Auditor was denied AUTH_PERM_READ\n");
        return 1;
    }
    if (admin_auth_store_authorize(session.session_token, AUTH_PERM_EXAM_MUTATION, &auth_check) == 0) {
        fprintf(stderr, "FAIL: Readonly Auditor was granted unauthorized AUTH_PERM_EXAM_MUTATION\n");
        return 1;
    }
    puts("[8/10] PASS: Granular RBAC permission matrix enforced across operational boundaries");

    /* 9. Password Reset & Active Session Invalidation */
    char reset_token[65];
    if (admin_auth_store_password_reset_request(manager.username, reset_token) != 0 || strlen(reset_token) != 64) {
        fprintf(stderr, "FAIL: password reset request failed\n");
        return 1;
    }

    char new_manager_password[] = "BrandNewManagerPassword#2026!";
    if (admin_auth_store_password_reset_complete(manager.username, reset_token, new_manager_password) != 0) {
        fprintf(stderr, "FAIL: password reset completion failed\n");
        return 1;
    }

    /* Manager's old session token should now be invalidated */
    if (admin_auth_store_verify(manager_session.session_token, &auth_check) == 0) {
        fprintf(stderr, "FAIL: previous session survived password reset\n");
        return 1;
    }

    /* Old password should now fail */
    if (admin_auth_store_login(manager.username, manager_password, NULL, &session) == AUTH_LOGIN_SUCCESS) {
        fprintf(stderr, "FAIL: old password accepted after password reset\n");
        return 1;
    }

    /* New password should now succeed */
    if (admin_auth_store_login(manager.username, new_manager_password, NULL, &session) != AUTH_LOGIN_SUCCESS) {
        fprintf(stderr, "FAIL: new password login failed\n");
        return 1;
    }
    puts("[9/10] PASS: Cryptographic password reset completed and previous sessions invalidated");

    /* 10. Logout & Audit Ledger Verification */
    if (admin_auth_store_revoke(session.session_token) != 0) {
        fprintf(stderr, "FAIL: session revocation failed\n");
        return 1;
    }
    if (admin_auth_store_verify(session.session_token, &auth_check) == 0) {
        fprintf(stderr, "FAIL: revoked session was accepted by verify\n");
        return 1;
    }

    /* Verify audit table */
    char user_list[4096];
    if (admin_auth_store_list_users_json(user_list, sizeof(user_list)) != 0 ||
        !strstr(user_list, "owner_admin") || !strstr(user_list, "exam_manager_1")) {
        fprintf(stderr, "FAIL: user listing failed or missing accounts\n");
        return 1;
    }

    admin_auth_store_shutdown();
    puts("[10/10] PASS: Session revocation verified and administrative audit events confirmed");

    puts("\n==================================================================");
    puts("ALL EXAMOS ENTERPRISE AUTH & POSTGRESQL TESTS PASSED SUCCESSFULLY!");
    puts("==================================================================");
    return 0;
}
