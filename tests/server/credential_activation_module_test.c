#define _GNU_SOURCE
#include "../../server/include/credential_activation.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_text(const char *path, char *buffer, size_t capacity)
{
    FILE *file = fopen(path, "rb");
    if (!file) return -1;
    size_t length = fread(buffer, 1, capacity - 1, file);
    int read_error = ferror(file);
    int extra = fgetc(file);
    read_error |= ferror(file);
    int failed = read_error || extra != EOF;
    if (fclose(file) != 0) failed = 1;
    if (failed || length == 0) return -1;
    buffer[length] = '\0';
    return 0;
}

static int write_text(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");
    if (!file) return -1;
    size_t length = strlen(text);
    int failed = fwrite(text, 1, length, file) != length;
    if (fclose(file) != 0) failed = 1;
    return failed ? -1 : 0;
}

int main(int argc, char **argv)
{
    if (argc == 6 && strcmp(argv[1], "issue") == 0) {
        char ek_pem[4096], activation_id[64], blob_hex[8193], secret_mac[65];
        char error[256] = {0}, activation_record[160];
        if (read_text(argv[2], ek_pem, sizeof(ek_pem)) != 0 ||
            credential_activation_initiate(
                "dev-test", "inst-test", ek_pem, argv[3],
                activation_id, blob_hex, sizeof(blob_hex),
                secret_mac, error) != 0) {
            fprintf(stderr, "MakeCredential failed: %s\n", error);
            return 1;
        }
        int record_length = snprintf(activation_record, sizeof(activation_record),
                                     "%s\n%s\n", activation_id, secret_mac);
        int ok = record_length > 0 &&
                 (size_t)record_length < sizeof(activation_record) &&
                 write_text(argv[4], blob_hex) == 0 &&
                 write_text(argv[5], activation_record) == 0;
        OPENSSL_cleanse(ek_pem, sizeof(ek_pem));
        OPENSSL_cleanse(blob_hex, sizeof(blob_hex));
        OPENSSL_cleanse(secret_mac, sizeof(secret_mac));
        if (!ok) {
            fputs("Could not save simulator test output.\n", stderr);
            return 1;
        }
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "verify") == 0) {
        char error[256] = {0};
        if (credential_activation_verify(argv[2], "dev-test", "inst-test",
                argv[3], argv[4], error) != 0) {
            fprintf(stderr, "Activation response rejected: %s\n", error);
            return 1;
        }
        puts("PASS: issued activation response verified");
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "reject-device") == 0) {
        char error[256] = {0};
        if (credential_activation_verify(argv[2], "other-device", "inst-test",
                argv[3], argv[4], error) == 0) {
            fputs("Activation response was accepted for another device.\n", stderr);
            return 1;
        }
        puts("PASS: activation response is bound to the enrolled device");
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "reject-institution") == 0) {
        char error[256] = {0};
        if (credential_activation_verify(argv[2], "dev-test", "other-institution",
                argv[3], argv[4], error) == 0) {
            fputs("Activation response was accepted for another institution.\n", stderr);
            return 1;
        }
        puts("PASS: activation response is bound to the enrolled institution");
        return 0;
    }
    return 2;
}
