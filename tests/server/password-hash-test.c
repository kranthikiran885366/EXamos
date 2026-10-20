#define _GNU_SOURCE
#include "../../server/include/config_manager.h"

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
        setenv("EXAMOS_ADMIN_CONFIG", config_path, 1) != 0) {
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
    unlink(config_path);

    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(hash, sizeof(hash));
    OPENSSL_cleanse(credential, sizeof(credential));
    puts("PASS: PBKDF2 hashes and configured admin identity reject invalid credentials");
    return 0;
}
