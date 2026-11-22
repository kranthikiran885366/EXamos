#include "../../server/include/key_release.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    char key[65] = "must-not-be-populated";
    char error[64] = {0};
    if (key_release_get_session_key("sess_test", key, sizeof(key),
                                    "dev_test", error) != -1 ||
        strcmp(error, "P3_DEVICE_BOUND_TRANSPORT_UNAVAILABLE") != 0 ||
        key[0] != '\0') {
        fprintf(stderr, "FAIL: plaintext key transport is not fail-closed\n");
        return 1;
    }

    char reason[64] = {0};
    if (key_release_check_eligibility("sess_test", "dev_test", reason) != -1 ||
        strcmp(reason, "P3_DEVICE_BOUND_TRANSPORT_UNAVAILABLE") != 0) {
        fprintf(stderr, "FAIL: key-release eligibility is not transport-safe\n");
        return 1;
    }

    puts("PASS: plaintext and unwrapped key release remain disabled");
    return 0;
}
