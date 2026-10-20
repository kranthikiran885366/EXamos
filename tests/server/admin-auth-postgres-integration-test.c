#include "../../server/include/admin_auth_store.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    auth_session_t session = {0};
    if (admin_auth_store_init() != 0) {
        fprintf(stderr, "FAIL: PostgreSQL TLS connection or admin_auth migration verification failed\n");
        return 1;
    }
    if (admin_auth_store_login("not-a-provisioned-account",
                              "not-a-valid-password", &session) == 0) {
        fprintf(stderr, "FAIL: authentication succeeded for an absent database identity\n");
        admin_auth_store_shutdown();
        return 1;
    }
    admin_auth_store_shutdown();
    puts("PASS: real PostgreSQL TLS connection, schema verification, and unknown-account rejection");
    return 0;
}
