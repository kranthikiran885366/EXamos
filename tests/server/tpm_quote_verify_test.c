#include "../../server/include/tpm_quote.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, unsigned char **out, size_t *out_len)
{
    FILE *file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END) != 0) return -1;
    long size = ftell(file);
    if (size <= 0 || size > 8192 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    unsigned char *data = malloc((size_t)size);
    if (!data) { fclose(file); return -1; }
    if (fread(data, 1, (size_t)size, file) != (size_t)size || fclose(file) != 0) {
        free(data);
        return -1;
    }
    *out = data;
    *out_len = (size_t)size;
    return 0;
}

static void bytes_to_hex(const unsigned char *data, size_t length, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 15];
    }
    out[length * 2] = '\0';
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s attest signature ak-public.pem ak-name\n", argv[0]);
        return 2;
    }
    unsigned char *attest = NULL, *signature = NULL, *name = NULL;
    size_t attest_len = 0, signature_len = 0, name_len = 0;
    if (read_file(argv[1], &attest, &attest_len) != 0 ||
        read_file(argv[2], &signature, &signature_len) != 0 ||
        read_file(argv[4], &name, &name_len) != 0 || name_len != 34) {
        fputs("FAIL: invalid TPM quote test inputs\n", stderr);
        free(attest); free(signature); free(name);
        return 1;
    }
    FILE *key_file = fopen(argv[3], "rb");
    char public_pem[4096] = {0};
    size_t pem_len = key_file ? fread(public_pem, 1, sizeof(public_pem) - 1, key_file) : 0;
    if (!key_file || ferror(key_file) || fclose(key_file) != 0 || pem_len == 0) {
        fputs("FAIL: invalid enrolled AK test key\n", stderr);
        free(attest); free(signature); free(name);
        return 1;
    }

    char name_hex[69];
    bytes_to_hex(name, name_len, name_hex);
    const char *nonce = getenv("EXAMOS_TEST_TPM_NONCE");
    const char *zero_pcr = "0000000000000000000000000000000000000000000000000000000000000000";
    if (!nonce || strlen(nonce) != 64 ||
        tpm_quote_verify_sha256_rsa(attest, attest_len, signature, signature_len,
                                    public_pem, name_hex, nonce,
                                    zero_pcr, zero_pcr, zero_pcr, zero_pcr) != 0) {
        fputs("FAIL: valid TPM quote was rejected\n", stderr);
        free(attest); free(signature); free(name);
        return 1;
    }

    char wrong_nonce[65];
    snprintf(wrong_nonce, sizeof(wrong_nonce), "%s", nonce);
    wrong_nonce[0] = wrong_nonce[0] == '0' ? '1' : '0';
    if (tpm_quote_verify_sha256_rsa(attest, attest_len, signature, signature_len,
                                    public_pem, name_hex, wrong_nonce,
                                    zero_pcr, zero_pcr, zero_pcr, zero_pcr) == 0 ||
        tpm_quote_verify_sha256_rsa(attest, attest_len, signature, signature_len,
                                    public_pem, name_hex, nonce,
                                    "1111111111111111111111111111111111111111111111111111111111111111",
                                    zero_pcr, zero_pcr, zero_pcr) == 0) {
        fputs("FAIL: TPM quote accepted an invalid nonce or PCR set\n", stderr);
        free(attest); free(signature); free(name);
        return 1;
    }

    signature[signature_len - 1] ^= 1;
    if (tpm_quote_verify_sha256_rsa(attest, attest_len, signature, signature_len,
                                    public_pem, name_hex, nonce,
                                    zero_pcr, zero_pcr, zero_pcr, zero_pcr) == 0) {
        fputs("FAIL: TPM quote accepted a modified signature\n", stderr);
        free(attest); free(signature); free(name);
        return 1;
    }

    puts("PASS: TPM quote signature, enrolled AK Name, nonce, and selected PCR digest verified; tampered evidence rejected");
    free(attest); free(signature); free(name);
    return 0;
}
