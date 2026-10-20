#include "../../server/include/admin_dashboard.h"

#include <stdio.h>

int main(void) {
    const char *username = "rate-limit-unit-user";

    for (int attempt = 0; attempt < 5; ++attempt) {
        if (!admin_auth_login_begin(username)) {
            fprintf(stderr, "FAIL: valid initial attempt was throttled\n");
            return 1;
        }
        admin_auth_login_complete(username, 0);
    }

    if (admin_auth_login_begin(username)) {
        fprintf(stderr, "FAIL: failed-login lockout was not enforced\n");
        return 1;
    }

    admin_auth_login_complete(username, 1);
    if (!admin_auth_login_begin(username)) {
        fprintf(stderr, "FAIL: successful authentication did not clear failure lockout\n");
        return 1;
    }
    admin_auth_login_complete(username, 1);

    if (!admin_auth_login_begin("another-unit-user")) {
        fprintf(stderr, "FAIL: rate limiting leaked across administrator identities\n");
        return 1;
    }
    admin_auth_login_complete("another-unit-user", 1);

    puts("PASS: shared administrator rate limit enforces lockout and identity scope");
    return 0;
}
