#include "../../server/include/totp.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    char secret[TOTP_BASE32_LEN + 1];
    if (totp_generate_secret(secret) != 0 || strlen(secret) != TOTP_BASE32_LEN) {
        fprintf(stderr, "FAIL: secret generation failed\n");
        return 1;
    }

    time_t now = time(NULL);
    char code[TOTP_CODE_LEN + 1];
    if (totp_generate_code(secret, now, code) != 0 || strlen(code) != TOTP_CODE_LEN) {
        fprintf(stderr, "FAIL: code generation failed\n");
        return 1;
    }

    /* Valid verification at current time */
    if (!totp_verify_code(secret, code, now, 1)) {
        fprintf(stderr, "FAIL: valid code failed verification at current time\n");
        return 1;
    }

    /* Clock drift verification (+25 seconds in same or adjacent window) */
    if (!totp_verify_code(secret, code, now + 25, 1)) {
        fprintf(stderr, "FAIL: valid code failed within drift tolerance window\n");
        return 1;
    }

    /* Invalid code rejection */
    if (totp_verify_code(secret, "000000", now, 1) && strcmp(code, "000000") != 0) {
        fprintf(stderr, "FAIL: invalid code accepted\n");
        return 1;
    }

    /* Out of window rejection (+120 seconds) */
    if (totp_verify_code(secret, code, now + 120, 1)) {
        fprintf(stderr, "FAIL: expired code accepted outside window\n");
        return 1;
    }

    /* Recovery codes generation and verification */
    char codes[TOTP_NUM_RECOVERY_CODES][TOTP_RECOVERY_CODE_LEN + 1];
    char hashes[TOTP_NUM_RECOVERY_CODES][65];
    if (totp_generate_recovery_codes(codes, hashes) != 0) {
        fprintf(stderr, "FAIL: recovery codes generation failed\n");
        return 1;
    }

    for (int i = 0; i < TOTP_NUM_RECOVERY_CODES; ++i) {
        char verify_hash[65];
        if (totp_hash_recovery_code(codes[i], verify_hash) != 0 ||
            strcmp(hashes[i], verify_hash) != 0) {
            fprintf(stderr, "FAIL: recovery code hash mismatch for index %d\n", i);
            return 1;
        }
    }

    /* OTP provisioning URI format */
    char uri[256];
    if (totp_generate_uri("admin_test", "ExamOS", secret, uri, sizeof(uri)) != 0 ||
        !strstr(uri, "otpauth://totp/ExamOS:admin_test") ||
        !strstr(uri, secret)) {
        fprintf(stderr, "FAIL: otpauth URI formatting failed\n");
        return 1;
    }

    puts("PASS: RFC 6238 TOTP generation, clock-drift tolerance, and recovery codes verified");
    return 0;
}
