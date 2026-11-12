#define _GNU_SOURCE
#include "../../server/include/credential_activation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    unsetenv("EXAMOS_CREDENTIAL_ACTIVATION_KEY");
    char activation_id[64] = "must-be-cleared";
    char credential_blob[8193] = "must-be-cleared";
    char secret_mac[65] = "must-be-cleared";
    char error[256] = {0};
    int failures = 0;

    if (credential_activation_initiate(
            "device-test", "institution-test",
            "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n",
            "000b0000000000000000000000000000000000000000000000000000000000000000",
            activation_id, credential_blob, sizeof(credential_blob),
            secret_mac, error) == 0 ||
        activation_id[0] || credential_blob[0] || secret_mac[0] ||
        !strstr(error, "EXAMOS_CREDENTIAL_ACTIVATION_KEY")) {
        fputs("FAIL: activation initiation did not fail closed without its HMAC key\n", stderr);
        failures++;
    }

    memset(error, 0, sizeof(error));
    if (credential_activation_verify(
            "activation-test", "device-test", "institution-test",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            error) == 0 ||
        !strstr(error, "Activation verification key is unavailable")) {
        fputs("FAIL: activation verification succeeded without the HMAC key\n", stderr);
        failures++;
    }

    if (failures) return 1;
    puts("PASS: activation fails closed when the server HMAC key is unavailable");
    return 0;
}
