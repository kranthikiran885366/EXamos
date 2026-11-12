#define _GNU_SOURCE
#include "../include/credential_activation.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define ACTIVATION_SECRET_BYTES 32
#define ACTIVATION_KEY_BYTES 32
#define ACTIVATION_BLOB_MAX 4096

static void set_error(char *out_error, const char *message) {
    if (out_error) snprintf(out_error, 256, "%s", message);
}

static int decode_hex(const char *input, unsigned char *output, size_t output_len) {
    if (!input || strlen(input) != output_len * 2) return -1;
    for (size_t i = 0; i < output_len; ++i) {
        unsigned int byte = 0;
        if (sscanf(input + i * 2, "%2x", &byte) != 1) return -1;
        output[i] = (unsigned char)byte;
        if (input[i * 2] == '\0' || input[i * 2 + 1] == '\0') return -1;
        if (!((input[i * 2] >= '0' && input[i * 2] <= '9') ||
              (input[i * 2] >= 'a' && input[i * 2] <= 'f') ||
              (input[i * 2] >= 'A' && input[i * 2] <= 'F')) ||
            !((input[i * 2 + 1] >= '0' && input[i * 2 + 1] <= '9') ||
              (input[i * 2 + 1] >= 'a' && input[i * 2 + 1] <= 'f') ||
              (input[i * 2 + 1] >= 'A' && input[i * 2 + 1] <= 'F')))
            return -1;
    }
    return 0;
}

static void encode_hex(const unsigned char *input, size_t input_len, char *output) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < input_len; ++i) {
        output[i * 2] = digits[input[i] >> 4];
        output[i * 2 + 1] = digits[input[i] & 15];
    }
    output[input_len * 2] = '\0';
}

static int load_activation_key(unsigned char key[ACTIVATION_KEY_BYTES]) {
    const char *encoded = getenv("EXAMOS_CREDENTIAL_ACTIVATION_KEY");
    if (!encoded || decode_hex(encoded, key, ACTIVATION_KEY_BYTES) != 0)
        return -1;
    return 0;
}

static int activation_mac(const unsigned char secret[ACTIVATION_SECRET_BYTES],
                          const unsigned char key[ACTIVATION_KEY_BYTES],
                          const char *activation_id, const char *device_id,
                          const char *institution_id, char out_mac[65]) {
    unsigned char input[512], digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    int input_len = snprintf((char *)input, sizeof(input),
        "EXAMOS-TPM-ACTIVATION-V1\n%s\n%s\n%s",
        activation_id, device_id, institution_id);
    if (input_len < 0 || (size_t)input_len >= sizeof(input) ||
        !HMAC(EVP_sha256(), key, ACTIVATION_KEY_BYTES,
              input, (size_t)input_len, digest, &digest_len) ||
        digest_len != 32) {
        OPENSSL_cleanse(input, sizeof(input));
        OPENSSL_cleanse(digest, sizeof(digest));
        return -1;
    }
    unsigned char combined[ACTIVATION_SECRET_BYTES + 32];
    memcpy(combined, secret, ACTIVATION_SECRET_BYTES);
    memcpy(combined + ACTIVATION_SECRET_BYTES, digest, 32);
    if (!HMAC(EVP_sha256(), key, ACTIVATION_KEY_BYTES,
              combined, sizeof(combined), digest, &digest_len) ||
        digest_len != 32) {
        OPENSSL_cleanse(input, sizeof(input));
        OPENSSL_cleanse(digest, sizeof(digest));
        OPENSSL_cleanse(combined, sizeof(combined));
        return -1;
    }
    encode_hex(digest, 32, out_mac);
    OPENSSL_cleanse(input, sizeof(input));
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(combined, sizeof(combined));
    return 0;
}

static int write_private_file(const char *path, const void *data, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    const unsigned char *bytes = data;
    size_t written = 0;
    while (written < length) {
        ssize_t result = write(fd, bytes + written, length - written);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) {
            close(fd);
            return -1;
        }
        written += (size_t)result;
    }
    return close(fd);
}

static int read_private_file(const char *path, unsigned char *buffer,
                             size_t capacity, size_t *out_length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat status;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size <= 0 || (uintmax_t)status.st_size > capacity) {
        close(fd);
        return -1;
    }
    size_t length = 0;
    while (length < (size_t)status.st_size) {
        ssize_t result = read(fd, buffer + length, (size_t)status.st_size - length);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) {
            close(fd);
            return -1;
        }
        length += (size_t)result;
    }
    if (close(fd) != 0) return -1;
    *out_length = length;
    return 0;
}

static int run_makecredential(const char *ek_path, const char *secret_path,
                              const char *name_hex, const char *blob_path) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        if (setenv("TPM2TOOLS_TCTI", "none", 1) != 0) _exit(126);
        char *const arguments[] = {
            "tpm2_makecredential", "-Q", "-G", "rsa",
            "-u", (char *)ek_path, "-s", (char *)secret_path,
            "-n", (char *)name_hex, "-o", (char *)blob_path, NULL
        };
        execvp(arguments[0], arguments);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int valid_identifier(const char *value) {
    if (!value || !value[0] || strlen(value) > 63) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!( (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
               (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' ||
               *p == ':' || *p == '-')) return 0;
    return 1;
}

int credential_activation_initiate(const char *device_id,
                                   const char *institution_id,
                                   const char *ek_public_key_pem,
                                   const char *ak_name_hex,
                                   char *out_activation_id,
                                   char *out_credential_blob_hex,
                                   size_t out_blob_size,
                                   char *out_secret_mac,
                                   char *out_error) {
    unsigned char key[ACTIVATION_KEY_BYTES] = {0};
    unsigned char secret[ACTIVATION_SECRET_BYTES] = {0};
    unsigned char blob[ACTIVATION_BLOB_MAX] = {0};
    char work_dir[] = "/tmp/examos-makecredential.XXXXXX";
    char ek_path[128] = {0}, secret_path[128] = {0}, blob_path[128] = {0};
    size_t blob_len = 0;
    int result = -1;

    if (out_activation_id) out_activation_id[0] = '\0';
    if (out_credential_blob_hex && out_blob_size) out_credential_blob_hex[0] = '\0';
    if (out_secret_mac) out_secret_mac[0] = '\0';
    if (out_error) out_error[0] = '\0';
    if (!valid_identifier(device_id) || !valid_identifier(institution_id) ||
        !ek_public_key_pem || !ek_public_key_pem[0] || strlen(ek_public_key_pem) > 4096 ||
        !ak_name_hex || strlen(ak_name_hex) != 68 ||
        strncasecmp(ak_name_hex, "000b", 4) != 0 ||
        !out_activation_id || !out_credential_blob_hex || out_blob_size < 3 ||
        !out_secret_mac) {
        set_error(out_error, "Invalid EK/AK activation input");
        goto cleanup;
    }
    if (load_activation_key(key) != 0) {
        set_error(out_error, "EXAMOS_CREDENTIAL_ACTIVATION_KEY must be 32 bytes encoded as 64 hex characters");
        goto cleanup;
    }
    if (RAND_bytes(secret, sizeof(secret)) != 1) {
        set_error(out_error, "Cryptographic randomness is unavailable");
        goto cleanup;
    }
    unsigned char id[16];
    if (RAND_bytes(id, sizeof(id)) != 1) {
        set_error(out_error, "Cryptographic randomness is unavailable");
        OPENSSL_cleanse(id, sizeof(id));
        goto cleanup;
    }
    encode_hex(id, sizeof(id), out_activation_id);
    OPENSSL_cleanse(id, sizeof(id));

    if (!mkdtemp(work_dir) || chmod(work_dir, 0700) != 0) {
        set_error(out_error, "Could not create a private MakeCredential workspace");
        goto cleanup;
    }
    int path_ok =
        snprintf(ek_path, sizeof(ek_path), "%s/ek.pem", work_dir) > 0 &&
        snprintf(secret_path, sizeof(secret_path), "%s/secret.bin", work_dir) > 0 &&
        snprintf(blob_path, sizeof(blob_path), "%s/credential.blob", work_dir) > 0;
    if (!path_ok ||
        write_private_file(ek_path, ek_public_key_pem, strlen(ek_public_key_pem)) != 0 ||
        write_private_file(secret_path, secret, sizeof(secret)) != 0 ||
        run_makecredential(ek_path, secret_path, ak_name_hex, blob_path) != 0 ||
        read_private_file(blob_path, blob, sizeof(blob), &blob_len) != 0 ||
        blob_len * 2 + 1 > out_blob_size) {
        set_error(out_error, "TPM2 MakeCredential failed or returned an invalid blob");
        goto cleanup;
    }
    if (activation_mac(secret, key, out_activation_id, device_id,
                       institution_id, out_secret_mac) != 0) {
        set_error(out_error, "Could not authenticate the activation secret");
        goto cleanup;
    }
    encode_hex(blob, blob_len, out_credential_blob_hex);
    result = 0;

cleanup:
    if (ek_path[0]) unlink(ek_path);
    if (secret_path[0]) unlink(secret_path);
    if (blob_path[0]) unlink(blob_path);
    if (work_dir[0] && strstr(work_dir, "examos-makecredential.") == work_dir)
        rmdir(work_dir);
    if (result != 0) {
        if (out_activation_id) OPENSSL_cleanse(out_activation_id, 64);
        if (out_credential_blob_hex && out_blob_size)
            OPENSSL_cleanse(out_credential_blob_hex, out_blob_size);
        if (out_secret_mac) OPENSSL_cleanse(out_secret_mac, 65);
    }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(blob, sizeof(blob));
    return result;
}

int credential_activation_verify(const char *activation_id,
                                 const char *device_id,
                                 const char *institution_id,
                                 const char *activation_response_hex,
                                 const char *expected_secret_mac,
                                 char *out_error) {
    unsigned char key[ACTIVATION_KEY_BYTES] = {0};
    unsigned char secret[ACTIVATION_SECRET_BYTES] = {0};
    unsigned char expected[32] = {0}, actual[32] = {0};
    char actual_hex[65] = {0};
    int result = -1;
    if (out_error) out_error[0] = '\0';
    if (!valid_identifier(activation_id) || !valid_identifier(device_id) ||
        !valid_identifier(institution_id) || !activation_response_hex ||
        decode_hex(activation_response_hex, secret, sizeof(secret)) != 0 ||
        !expected_secret_mac || decode_hex(expected_secret_mac, expected, sizeof(expected)) != 0) {
        set_error(out_error, "Invalid activation response");
        goto cleanup;
    }
    if (load_activation_key(key) != 0 ||
        activation_mac(secret, key, activation_id, device_id,
                       institution_id, actual_hex) != 0 ||
        decode_hex(actual_hex, actual, sizeof(actual)) != 0) {
        set_error(out_error, "Activation verification key is unavailable");
        goto cleanup;
    }
    if (CRYPTO_memcmp(actual, expected, sizeof(actual)) != 0) {
        set_error(out_error, "ActivateCredential response did not match the issued credential");
        goto cleanup;
    }
    result = 0;

cleanup:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(actual_hex, sizeof(actual_hex));
    return result;
}
