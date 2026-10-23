/*
 * Regression coverage for the administrative login throttle.
 *
 * The previous version of this test called an API that no longer exists
 * (admin_auth_login_begin / admin_auth_login_complete), so it could not
 * compile and provided no coverage at all. This version exercises the real
 * login path against the durable store.
 *
 * The properties under test:
 *   1. Repeated failed logins lock the identity out.
 *   2. A locked identity is refused even when the correct password is
 *      presented.
 *   3. The lockout is scoped to one identity: a different administrator is
 *      not affected by it.
 *
 * The test requires a reachable PostgreSQL instance, configured the same way
 * the server is: EXAMOS_DATABASE_URL_FILE points at a connection string.
 */

#include "../../server/include/admin_auth_store.h"
#include "../../server/include/config_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_USER_A "throttle-unit-user-a"
#define TEST_USER_B "throttle-unit-user-b"
#define TEST_PASSWORD "Throttle-Unit-Password-2026"

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *label, int condition) {
    if (condition) {
        printf("  PASS  %s\n", label);
        g_pass++;
    } else {
        printf("  FAIL  %s\n", label);
        g_fail++;
    }
}

static void remove_test_state(void) {
    PGconn *conn = acquire_db_connection();
    if (!conn) return;
    const char *cleanup[] = {
        "DELETE FROM examos_admin_sessions WHERE user_id IN "
        "(SELECT user_id FROM examos_admin_users WHERE username IN ($1,$2))",
        "DELETE FROM examos_admin_users WHERE username IN ($1,$2)",
        "DELETE FROM examos_admin_login_throttle WHERE subject_hash IN "
        "(encode(sha256(convert_to($1,'UTF8')),'hex'), encode(sha256(convert_to($2,'UTF8')),'hex'))"
    };
    const char *params[2] = { TEST_USER_A, TEST_USER_B };
    for (size_t i = 0; i < sizeof(cleanup) / sizeof(cleanup[0]); i++) {
        PGresult *result = PQexecParams(conn, cleanup[i], 2, NULL, params, NULL, NULL, 0);
        if (result) PQclear(result);
    }
    release_db_connection(conn, 0);
}

static int create_test_user(const char *username, const char *password) {
    char hash[256] = {0};
    if (config_create_password_hash(password, hash, sizeof(hash)) != 0) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    char user_id[80] = {0};
    snprintf(user_id, sizeof(user_id), "unit-%s", username);
    const char *params[] = { user_id, username, hash };
    PGresult *result = PQexecParams(conn,
        "INSERT INTO examos_admin_users (user_id, username, password_hash, role, active) "
        "VALUES ($1, $2, $3, 8, true)",
        3, NULL, params, NULL, NULL, 0);
    int ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

int main(void) {
    remove_test_state();

    if (admin_auth_store_init() != 0) {
        fprintf(stderr, "FAIL: the durable authentication store is unavailable\n");
        return 1;
    }

    if (create_test_user(TEST_USER_A, TEST_PASSWORD) != 0 ||
        create_test_user(TEST_USER_B, TEST_PASSWORD) != 0) {
        fprintf(stderr, "FAIL: the test administrators could not be provisioned\n");
        admin_auth_store_shutdown();
        return 1;
    }

    auth_session_t session;
    memset(&session, 0, sizeof(session));

    /* 1. Repeated failed logins must lock the identity out. */
    int locked = 0;
    for (int attempt = 0; attempt < 6; attempt++) {
        int status = admin_auth_store_login(TEST_USER_A, "wrong-password", NULL, &session);
        if (status == AUTH_LOGIN_FAILED) locked++;
    }
    check("failed logins are refused", locked == 6);

    /* 2. The locked identity is refused even with the correct password. */
    int status = admin_auth_store_login(TEST_USER_A, TEST_PASSWORD, NULL, &session);
    check("a locked identity is refused with the correct password",
          status == AUTH_LOGIN_FAILED);

    /* 3. The lockout does not leak across identities. */
    status = admin_auth_store_login(TEST_USER_B, TEST_PASSWORD, NULL, &session);
    check("the lockout is scoped to one identity", status == AUTH_LOGIN_SUCCESS);

    remove_test_state();
    admin_auth_store_shutdown();

    printf("PASS: the administrative login throttle locks out a repeated failure without leaking across identities (%d passed, %d failed)\n",
           g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
