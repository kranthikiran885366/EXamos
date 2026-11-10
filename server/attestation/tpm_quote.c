#define _GNU_SOURCE
#include "../include/tpm_quote.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <string.h>

#define TPM_GENERATED_VALUE 0xff544347U
#define TPM_ST_ATTEST_QUOTE 0x8018U
#define TPM_ALG_SHA256      0x000bU
#define TPM_ALG_RSASSA      0x0014U

typedef struct {
    const unsigned char *data;
    size_t length;
    size_t offset;
} cursor_t;

static int take(cursor_t *cursor, size_t length, const unsigned char **out)
{
    if (!cursor || cursor->offset > cursor->length ||
        length > cursor->length - cursor->offset) return -1;
    *out = cursor->data + cursor->offset;
    cursor->offset += length;
    return 0;
}

static int take_u8(cursor_t *cursor, uint8_t *out)
{
    const unsigned char *p;
    if (take(cursor, 1, &p) != 0) return -1;
    *out = p[0];
    return 0;
}

static int take_u16(cursor_t *cursor, uint16_t *out)
{
    const unsigned char *p;
    if (take(cursor, 2, &p) != 0) return -1;
    *out = (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
    return 0;
}

static int take_u32(cursor_t *cursor, uint32_t *out)
{
    const unsigned char *p;
    if (take(cursor, 4, &p) != 0) return -1;
    *out = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return 0;
}

static int take_tpm2b(cursor_t *cursor, const unsigned char **out, size_t *out_len)
{
    uint16_t length;
    if (take_u16(cursor, &length) != 0 || take(cursor, length, out) != 0)
        return -1;
    *out_len = length;
    return 0;
}

static int decode_hex(const char *hex, unsigned char *out, size_t bytes)
{
    if (!hex || strlen(hex) != bytes * 2) return -1;
    for (size_t i = 0; i < bytes; ++i) {
        unsigned char value = 0;
        for (size_t nibble = 0; nibble < 2; ++nibble) {
            const unsigned char c = (unsigned char)hex[i * 2 + nibble];
            unsigned char part;
            if (c >= '0' && c <= '9') part = (unsigned char)(c - '0');
            else if (c >= 'a' && c <= 'f') part = (unsigned char)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') part = (unsigned char)(c - 'A' + 10);
            else return -1;
            value = (unsigned char)((value << 4) | part);
        }
        out[i] = value;
    }
    return 0;
}

static int verify_quote_signature(const unsigned char *attest, size_t attest_len,
                                  const unsigned char *signature, size_t signature_len,
                                  const char *public_pem)
{
    cursor_t cursor = {signature, signature_len, 0};
    uint16_t signature_alg, hash_alg;
    const unsigned char *signature_bytes;
    size_t signature_bytes_len;
    if (take_u16(&cursor, &signature_alg) != 0 ||
        take_u16(&cursor, &hash_alg) != 0 ||
        take_tpm2b(&cursor, &signature_bytes, &signature_bytes_len) != 0 ||
        cursor.offset != cursor.length || signature_alg != TPM_ALG_RSASSA ||
        hash_alg != TPM_ALG_SHA256 || signature_bytes_len < 256 ||
        signature_bytes_len > 512) return -1;

    BIO *bio = BIO_new_mem_buf(public_pem, -1);
    EVP_PKEY *key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA ||
        EVP_PKEY_bits(key) < 2048 ||
        (size_t)EVP_PKEY_size(key) != signature_bytes_len) {
        EVP_PKEY_free(key);
        return -1;
    }

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int valid = context &&
        EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, key) == 1 &&
        EVP_DigestVerifyUpdate(context, attest, attest_len) == 1 &&
        EVP_DigestVerifyFinal(context, signature_bytes, signature_bytes_len) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return valid ? 0 : -1;
}

int tpm_quote_verify_sha256_rsa_with_pcr_digest(
                                const unsigned char *attest, size_t attest_len,
                                const unsigned char *signature, size_t signature_len,
                                const char *ak_public_pem,
                                const char *ak_qualified_name_hex,
                                const char *nonce_hex,
                                const char *pcr0_hex, const char *pcr4_hex,
                                const char *pcr7_hex, const char *pcr11_hex,
                                char *out_pcr_digest_hex, size_t out_digest_size)
{
    if (out_pcr_digest_hex && out_digest_size) out_pcr_digest_hex[0] = '\0';
    if (!attest || !signature || !ak_public_pem || !ak_qualified_name_hex || !nonce_hex ||
        !pcr0_hex || !pcr4_hex || !pcr7_hex || !pcr11_hex ||
        (out_pcr_digest_hex && out_digest_size < 65) ||
        attest_len < 100 || attest_len > 4096 ||
        signature_len < 8 || signature_len > 1024) return -1;

    unsigned char expected_name[34], expected_nonce[32], pcrs[128], expected_digest[32];
    const char *pcr_hex[] = {pcr0_hex, pcr4_hex, pcr7_hex, pcr11_hex};
    if (decode_hex(ak_qualified_name_hex, expected_name, sizeof(expected_name)) != 0 ||
        expected_name[0] != 0x00 || expected_name[1] != 0x0b ||
        decode_hex(nonce_hex, expected_nonce, sizeof(expected_nonce)) != 0) return -1;
    for (size_t i = 0; i < 4; ++i) {
        if (decode_hex(pcr_hex[i], pcrs + i * 32, 32) != 0) return -1;
    }
    unsigned int digest_len = 0;
    if (EVP_Digest(pcrs, sizeof(pcrs), expected_digest, &digest_len,
                   EVP_sha256(), NULL) != 1 || digest_len != sizeof(expected_digest))
        return -1;

    cursor_t cursor = {attest, attest_len, 0};
    uint32_t magic, selection_count;
    uint16_t type, name_len, nonce_len;
    const unsigned char *name, *nonce, *ignored, *selection, *pcr_digest;
    size_t pcr_digest_len;
    if (take_u32(&cursor, &magic) != 0 || take_u16(&cursor, &type) != 0 ||
        take_u16(&cursor, &name_len) != 0 || name_len != sizeof(expected_name) ||
        take(&cursor, name_len, &name) != 0) return -1;
    if (take_u16(&cursor, &nonce_len) != 0 || nonce_len != sizeof(expected_nonce) ||
        take(&cursor, nonce_len, &nonce) != 0) return -1;
    if (magic != TPM_GENERATED_VALUE || type != TPM_ST_ATTEST_QUOTE ||
        CRYPTO_memcmp(name, expected_name, sizeof(expected_name)) != 0 ||
        CRYPTO_memcmp(nonce, expected_nonce, sizeof(expected_nonce)) != 0) return -1;

    /* clockInfo plus firmwareVersion are fixed-size TPM wire fields. */
    uint8_t selection_size = 0;
    if (take(&cursor, 17 + 8, &ignored) != 0 ||
        take_u32(&cursor, &selection_count) != 0 || selection_count != 1 ||
        take_u16(&cursor, &type) != 0 || type != TPM_ALG_SHA256 ||
        take_u8(&cursor, &selection_size) != 0 || selection_size != 3 ||
        take(&cursor, 3, &selection) != 0 ||
        selection[0] != 0x91 || selection[1] != 0x08 || selection[2] != 0x00 ||
        take_tpm2b(&cursor, &pcr_digest, &pcr_digest_len) != 0 ||
        pcr_digest_len != sizeof(expected_digest) || cursor.offset != cursor.length ||
        CRYPTO_memcmp(pcr_digest, expected_digest, sizeof(expected_digest)) != 0) return -1;

    OPENSSL_cleanse(pcrs, sizeof(pcrs));
    OPENSSL_cleanse(expected_digest, sizeof(expected_digest));
    if (verify_quote_signature(attest, attest_len, signature, signature_len,
                               ak_public_pem) != 0) return -1;
    if (out_pcr_digest_hex) {
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < pcr_digest_len; ++i) {
            out_pcr_digest_hex[i * 2] = hex[pcr_digest[i] >> 4];
            out_pcr_digest_hex[i * 2 + 1] = hex[pcr_digest[i] & 15];
        }
        out_pcr_digest_hex[64] = '\0';
    }
    return 0;
}

int tpm_quote_verify_sha256_rsa(const unsigned char *attest, size_t attest_len,
                                const unsigned char *signature, size_t signature_len,
                                const char *ak_public_pem,
                                const char *ak_qualified_name_hex,
                                const char *nonce_hex,
                                const char *pcr0_hex, const char *pcr4_hex,
                                const char *pcr7_hex, const char *pcr11_hex)
{
    return tpm_quote_verify_sha256_rsa_with_pcr_digest(
        attest, attest_len, signature, signature_len, ak_public_pem,
        ak_qualified_name_hex, nonce_hex, pcr0_hex, pcr4_hex, pcr7_hex,
        pcr11_hex, NULL, 0);
}
