#include "tpm_public.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, unsigned char *buffer, size_t capacity,
                     size_t *out_length)
{
    FILE *file = fopen(path, "rb");
    if (!file) return -1;
    size_t length = fread(buffer, 1, capacity, file);
    int extra = fgetc(file);
    int read_error = ferror(file);
    int close_error = fclose(file) != 0;
    if (read_error || extra != EOF || close_error || length == 0) return -1;
    *out_length = length;
    return 0;
}

static void to_hex(const unsigned char *bytes, size_t length, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 15];
    }
    out[length * 2] = '\0';
}

static int make_pem_with_wrong_exponent(const unsigned char *modulus,
                                        size_t modulus_length,
                                        char *out_pem, size_t out_size)
{
    RSA *rsa = RSA_new();
    BIGNUM *n = BN_bin2bn(modulus, (int)modulus_length, NULL);
    BIGNUM *e = BN_new();
    EVP_PKEY *key = EVP_PKEY_new();
    BIO *bio = BIO_new(BIO_s_mem());
    int ok = rsa && n && e && key && bio && BN_set_word(e, 3) == 1 &&
             RSA_set0_key(rsa, n, e, NULL) == 1;
    if (!ok) {
        BN_free(n);
        BN_free(e);
        RSA_free(rsa);
        EVP_PKEY_free(key);
        BIO_free(bio);
        return -1;
    }
    n = NULL;
    e = NULL;
    if (EVP_PKEY_assign_RSA(key, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(key);
        BIO_free(bio);
        return -1;
    }
    if (PEM_write_bio_PUBKEY(bio, key) != 1) {
        EVP_PKEY_free(key);
        BIO_free(bio);
        return -1;
    }
    BUF_MEM *memory = NULL;
    BIO_get_mem_ptr(bio, &memory);
    ok = memory && memory->length < out_size;
    if (ok) {
        memcpy(out_pem, memory->data, memory->length);
        out_pem[memory->length] = '\0';
    }
    EVP_PKEY_free(key);
    BIO_free(bio);
    return ok ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc != 4) return 2;
    unsigned char public_area[1024], name[64], pem_bytes[4096];
    size_t public_area_length = 0, name_length = 0, pem_length = 0;
    if (read_file(argv[1], public_area, sizeof(public_area), &public_area_length) != 0 ||
        read_file(argv[3], name, sizeof(name), &name_length) != 0 ||
        read_file(argv[2], pem_bytes, sizeof(pem_bytes) - 1, &pem_length) != 0 ||
        public_area_length > (sizeof(public_area) - 1) / 2 ||
        name_length != 34 || pem_length >= sizeof(pem_bytes)) return 1;

    char public_area_hex[2049], name_hex[69], calculated_name[69];
    pem_bytes[pem_length] = '\0';
    to_hex(public_area, public_area_length, public_area_hex);
    to_hex(name, name_length, name_hex);
    int key_bits = 0;
    if (tpm_public_validate_rsa_ak(public_area_hex, (char *)pem_bytes, name_hex,
            calculated_name, sizeof(calculated_name), &key_bits) != 0 ||
        strcmp(calculated_name, name_hex) != 0 ||
        (key_bits != 2048 && key_bits != 3072)) {
        fprintf(stderr, "TPM public area did not match the AK template and PEM.\n");
        return 1;
    }

    size_t area_start = public_area_length >= 2 &&
        (((size_t)public_area[0] << 8) | public_area[1]) ==
            public_area_length - 2 ? 2 : 0;
    size_t modulus_length = key_bits / 8;
    size_t modulus_start = area_start + 24;
    char wrong_exponent_pem[4096] = {0};
    if (modulus_start + modulus_length > public_area_length ||
        make_pem_with_wrong_exponent(public_area + modulus_start,
            modulus_length, wrong_exponent_pem, sizeof(wrong_exponent_pem)) != 0 ||
        tpm_public_validate_rsa_ak(public_area_hex, wrong_exponent_pem, name_hex,
            calculated_name, sizeof(calculated_name), NULL) == 0) {
        fprintf(stderr, "PEM exponent mismatch was accepted.\n");
        return 1;
    }

    name_hex[4] = name_hex[4] == '0' ? '1' : '0';
    if (tpm_public_validate_rsa_ak(public_area_hex, (char *)pem_bytes, name_hex,
            calculated_name, sizeof(calculated_name), NULL) == 0) {
        fprintf(stderr, "Tampered TPM Name was accepted.\n");
        return 1;
    }
    unsigned char tampered_public[sizeof(public_area)];
    memcpy(tampered_public, public_area, public_area_length);
    tampered_public[public_area_length - 1] ^= 1;
    area_start = public_area_length >= 2 &&
        (((size_t)tampered_public[0] << 8) | tampered_public[1]) ==
            public_area_length - 2 ? 2 : 0;
    unsigned char tampered_name[34] = {0, 0x0b};
    unsigned int digest_length = 0;
    if (EVP_Digest(tampered_public + area_start,
            public_area_length - area_start, tampered_name + 2,
            &digest_length, EVP_sha256(), NULL) != 1 || digest_length != 32)
        return 1;
    char tampered_area_hex[2049], tampered_name_hex[69];
    to_hex(tampered_public, public_area_length, tampered_area_hex);
    to_hex(tampered_name, sizeof(tampered_name), tampered_name_hex);
    if (tpm_public_validate_rsa_ak(tampered_area_hex, (char *)pem_bytes,
            tampered_name_hex, calculated_name, sizeof(calculated_name), NULL) == 0) {
        fprintf(stderr, "Tampered TPM modulus was accepted with a recomputed Name.\n");
        return 1;
    }
    puts("PASS: TPM public area, AK Name, modulus, and tamper rejection");
    return 0;
}
