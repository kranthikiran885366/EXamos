#define _GNU_SOURCE
#include "../../server/include/config_manager.h"
#include "../../server/include/admin_dashboard.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

static void bytes_to_hex(const unsigned char *bytes, size_t length, char *hex) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        hex[i * 2] = digits[bytes[i] >> 4];
        hex[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    hex[length * 2] = '\0';
}

int main(void) {
    const char password[] = "test-only-password-not-for-deployment";
    unsigned char salt[16];
    unsigned char hash[32];
    char salt_hex[sizeof(salt) * 2 + 1];
    char hash_hex[sizeof(hash) * 2 + 1];
    char credential[160];
    char config_path[] = "/tmp/examos-admin-config-test-XXXXXX";

    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, sizeof(salt),
                          600000, EVP_sha256(), sizeof(hash), hash) != 1) {
        fprintf(stderr, "FAIL: could not create an ephemeral unit-test credential\n");
        return 1;
    }

    bytes_to_hex(salt, sizeof(salt), salt_hex);
    bytes_to_hex(hash, sizeof(hash), hash_hex);
    snprintf(credential, sizeof(credential), "600000:%s:%s", salt_hex, hash_hex);

    if (!config_verify_password_hash(password, credential) ||
        config_verify_password_hash("incorrect-test-password", credential) ||
        config_verify_password_hash(password, "1:00:00") ||
        config_verify_password_hash(password, NULL)) {
        fprintf(stderr, "FAIL: PBKDF2 password hash verification contract failed\n");
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(hash, sizeof(hash));
        OPENSSL_cleanse(credential, sizeof(credential));
        return 1;
    }

    int config_fd = mkstemp(config_path);
    if (config_fd < 0) {
        fprintf(stderr, "FAIL: unable to create isolated config test file\n");
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(hash, sizeof(hash));
        OPENSSL_cleanse(credential, sizeof(credential));
        return 1;
    }
    FILE *config_file = fdopen(config_fd, "w");
    if (!config_file) {
        close(config_fd);
        unlink(config_path);
        fprintf(stderr, "FAIL: unable to open isolated config test file\n");
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(hash, sizeof(hash));
        OPENSSL_cleanse(credential, sizeof(credential));
        return 1;
    }
    int write_ok = fprintf(config_file, "ADMIN_USERNAME=test-admin\n"
                                        "ADMIN_PASSWORD_PBKDF2=%s\n", credential) >= 0;
    int close_ok = fclose(config_file) == 0;
    if (!write_ok || !close_ok || chmod(config_path, 0600) != 0 ||
        setenv("EXAMOS_ADMIN_CONFIG", config_path, 1) != 0 ||
        setenv("EXAMOS_ALLOW_UNPROVISIONED_DEV", "1", 1) != 0) {
        fprintf(stderr, "FAIL: unable to provision isolated config test file\n");
        unlink(config_path);
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(hash, sizeof(hash));
        OPENSSL_cleanse(credential, sizeof(credential));
        return 1;
    }
    if (!config_verify_admin_credentials("test-admin", password) ||
        config_verify_admin_credentials("wrong-user", password) ||
        config_verify_admin_credentials("test-admin", "incorrect-test-password")) {
        fprintf(stderr, "FAIL: configured admin identity verification failed\n");
        unlink(config_path);
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(hash, sizeof(hash));
        OPENSSL_cleanse(credential, sizeof(credential));
        return 1;
    }
    char basic_payload[256] = {0};
    char basic_encoded[344] = {0};
    char basic_header[352] = {0};
    int payload_length = snprintf(basic_payload, sizeof(basic_payload),
                                  "test-admin:%s", password);
    int encoded_length = payload_length > 0 &&
        (size_t)payload_length < sizeof(basic_payload)
        ? EVP_EncodeBlock((unsigned char *)basic_encoded,
                          (const unsigned char *)basic_payload, payload_length)
        : -1;
    if (encoded_length > 0 && (size_t)encoded_length < sizeof(basic_encoded))
        basic_encoded[encoded_length] = '\0';
    int header_length = encoded_length > 0
        ? snprintf(basic_header, sizeof(basic_header), "Basic %s", basic_encoded)
        : -1;
    if (header_length <= 0 || (size_t)header_length + 2 > sizeof(basic_header) ||
        !admin_check_auth(basic_header)) {
        fprintf(stderr, "FAIL: valid configured Basic authentication was rejected\n");
        unlink(config_path);
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(hash, sizeof(hash));
        OPENSSL_cleanse(credential, sizeof(credential));
        OPENSSL_cleanse(basic_payload, sizeof(basic_payload));
        OPENSSL_cleanse(basic_encoded, sizeof(basic_encoded));
        OPENSSL_cleanse(basic_header, sizeof(basic_header));
        return 1;
    }
    // Note: Bearer token path requires database connection (admin_auth_store_verify)
    // This test focuses on Basic auth which uses local config file only
    // Bearer token path is tested separately with full server initialization

    config_file = fopen(config_path, "w");
    int legacy_written = config_file &&
        fprintf(config_file, "ADMIN_USERNAME=test-admin\n"
                             "ADMIN_PASSWORD_SHA256=%064d\n", 0) >= 0;
    int legacy_closed = config_file && fclose(config_file) == 0;
    if (!legacy_written || !legacy_closed || chmod(config_path, 0600) != 0 ||
        config_verify_admin_credentials("test-admin", password)) {
        fprintf(stderr, "FAIL: legacy fast-hash credentials were accepted\n");
        unlink(config_path);
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(hash, sizeof(hash));
        OPENSSL_cleanse(credential, sizeof(credential));
        OPENSSL_cleanse(basic_payload, sizeof(basic_payload));
        OPENSSL_cleanse(basic_encoded, sizeof(basic_encoded));
        OPENSSL_cleanse(basic_header, sizeof(basic_header));
        return 1;
    }

    config_file = fopen(config_path, "w");
    int unprovisioned_written = config_file &&
        fprintf(config_file, "ADMIN_USERNAME=NOT_PROVISIONED\n"
                             "ADMIN_PASSWORD_PBKDF2=NOT_PROVISIONED\n") >= 0;
    int unprovisioned_closed = config_file && fclose(config_file) == 0;
    if (!unprovisioned_written || !unprovisioned_closed ||
        chmod(config_path, 0600) != 0 ||
        config_verify_admin_credentials("NOT_PROVISIONED", password)) {
        fprintf(stderr, "FAIL: unprovisioned credentials were accepted\n");
        unlink(config_path);
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(hash, sizeof(hash));
        OPENSSL_cleanse(credential, sizeof(credential));
        OPENSSL_cleanse(basic_payload, sizeof(basic_payload));
        OPENSSL_cleanse(basic_encoded, sizeof(basic_encoded));
        OPENSSL_cleanse(basic_header, sizeof(basic_header));
        return 1;
    }

    config_file = fopen(config_path, "w");
    int insecure_written = config_file &&
        fprintf(config_file, "ADMIN_USERNAME=test-admin\n"
                             "ADMIN_PASSWORD_PBKDF2=%s\n", credential) >= 0;
    int insecure_closed = config_file && fclose(config_file) == 0;
    if (!insecure_written || !insecure_closed || chmod(config_path, 0644) != 0 ||
        config_verify_admin_credentials("test-admin", password)) {
        fprintf(stderr, "FAIL: group/world-readable admin credential file was accepted\n");
        unlink(config_path);
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(hash, sizeof(hash));
        OPENSSL_cleanse(credential, sizeof(credential));
        OPENSSL_cleanse(basic_payload, sizeof(basic_payload));
        OPENSSL_cleanse(basic_encoded, sizeof(basic_encoded));
        OPENSSL_cleanse(basic_header, sizeof(basic_header));
        return 1;
    }
    unlink(config_path);
    if (config_verify_admin_credentials("test-admin", password)) {
        fprintf(stderr, "FAIL: missing admin config did not fail closed\n");
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(hash, sizeof(hash));
        OPENSSL_cleanse(credential, sizeof(credential));
        OPENSSL_cleanse(basic_payload, sizeof(basic_payload));
        OPENSSL_cleanse(basic_encoded, sizeof(basic_encoded));
        OPENSSL_cleanse(basic_header, sizeof(basic_header));
        return 1;
    }

    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(hash, sizeof(hash));
    OPENSSL_cleanse(credential, sizeof(credential));
    OPENSSL_cleanse(basic_payload, sizeof(basic_payload));
    OPENSSL_cleanse(basic_encoded, sizeof(basic_encoded));
    OPENSSL_cleanse(basic_header, sizeof(basic_header));
    puts("PASS: PBKDF2 admin auth, strict Basic parsing, and fail-closed config checks");
    return 0;
}
