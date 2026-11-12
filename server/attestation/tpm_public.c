#include "../include/tpm_public.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <string.h>
#include <strings.h>

#define TPM_ALG_RSA 0x0001U
#define TPM_ALG_SHA256 0x000bU
#define TPM_ALG_NULL 0x0010U
#define TPM_ALG_RSASSA 0x0014U
#define TPM_AK_ATTRIBUTES 0x00050072U
#define TPM_PUBLIC_MAX_BYTES 1024U

typedef struct {
    const unsigned char *data;
    size_t length;
    size_t offset;
} reader_t;

static int take(reader_t *reader, size_t length, const unsigned char **out) {
    if (!reader || !out || reader->offset > reader->length ||
        length > reader->length - reader->offset) return -1;
    *out = reader->data + reader->offset;
    reader->offset += length;
    return 0;
}

static int take_u16(reader_t *reader, unsigned int *out) {
    const unsigned char *bytes;
    if (take(reader, 2, &bytes) != 0) return -1;
    *out = ((unsigned int)bytes[0] << 8) | bytes[1];
    return 0;
}

static int take_u32(reader_t *reader, unsigned int *out) {
    const unsigned char *bytes;
    if (take(reader, 4, &bytes) != 0) return -1;
    *out = ((unsigned int)bytes[0] << 24) |
           ((unsigned int)bytes[1] << 16) |
           ((unsigned int)bytes[2] << 8) | bytes[3];
    return 0;
}

static int hex_value(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int decode_public_area(const char *hex, unsigned char *output,
                              size_t *out_length) {
    if (!hex || !output || !out_length) return -1;
    size_t hex_length = strlen(hex);
    if (hex_length < 2 || (hex_length & 1) ||
        hex_length / 2 > TPM_PUBLIC_MAX_BYTES) return -1;
    size_t length = hex_length / 2;
    for (size_t i = 0; i < length; ++i) {
        int high = hex_value((unsigned char)hex[i * 2]);
        int low = hex_value((unsigned char)hex[i * 2 + 1]);
        if (high < 0 || low < 0) return -1;
        output[i] = (unsigned char)((high << 4) | low);
    }
    if (length >= 2 &&
        (((size_t)output[0] << 8) | output[1]) == length - 2) {
        memmove(output, output + 2, length - 2);
        length -= 2;
    }
    *out_length = length;
    return 0;
}

static void encode_hex(const unsigned char *input, size_t length, char *output) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        output[i * 2] = digits[input[i] >> 4];
        output[i * 2 + 1] = digits[input[i] & 15];
    }
    output[length * 2] = '\0';
}

int tpm_public_validate_rsa_ak(const char *public_area_hex,
                               const char *public_key_pem,
                               const char *submitted_name_hex,
                               char *out_name_hex,
                               size_t out_name_size,
                               int *out_key_bits) {
    unsigned char encoded[TPM_PUBLIC_MAX_BYTES] = {0};
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned char calculated_name[34] = {0};
    size_t encoded_length = 0;
    unsigned int type = 0, name_algorithm = 0, attributes = 0;
    unsigned int policy_length = 0, symmetric_algorithm = 0;
    unsigned int signing_scheme = 0, scheme_hash = 0, key_bits = 0;
    unsigned int exponent = 0, modulus_length = 0, digest_length = 0;
    const unsigned char *policy = NULL, *modulus = NULL;
    int valid = 0;

    if (out_name_hex && out_name_size) out_name_hex[0] = '\0';
    if (out_key_bits) *out_key_bits = 0;
    if (!public_key_pem || !submitted_name_hex || !out_name_hex ||
        out_name_size < 69 || decode_public_area(public_area_hex, encoded,
                                                  &encoded_length) != 0)
        goto cleanup;

    reader_t reader = {encoded, encoded_length, 0};
    if (take_u16(&reader, &type) != 0 || take_u16(&reader, &name_algorithm) != 0 ||
        take_u32(&reader, &attributes) != 0 || take_u16(&reader, &policy_length) != 0 ||
        take(&reader, policy_length, &policy) != 0 ||
        type != TPM_ALG_RSA || name_algorithm != TPM_ALG_SHA256 ||
        attributes != TPM_AK_ATTRIBUTES || policy_length != 0)
        goto cleanup;

    if (take_u16(&reader, &symmetric_algorithm) != 0 ||
        symmetric_algorithm != TPM_ALG_NULL ||
        take_u16(&reader, &signing_scheme) != 0 ||
        signing_scheme != TPM_ALG_RSASSA ||
        take_u16(&reader, &scheme_hash) != 0 ||
        scheme_hash != TPM_ALG_SHA256 ||
        take_u16(&reader, &key_bits) != 0 ||
        (key_bits != 2048 && key_bits != 3072) ||
        take_u32(&reader, &exponent) != 0 ||
        (exponent != 0 && exponent != 65537) ||
        take_u16(&reader, &modulus_length) != 0 ||
        modulus_length != key_bits / 8 ||
        take(&reader, modulus_length, &modulus) != 0 ||
        reader.offset != reader.length) {
        goto cleanup;
    }

    calculated_name[0] = 0;
    calculated_name[1] = TPM_ALG_SHA256;
    if (EVP_Digest(encoded, encoded_length, digest, &digest_length,
                   EVP_sha256(), NULL) != 1 || digest_length != 32)
        goto cleanup;
    memcpy(calculated_name + 2, digest, 32);
    char name_hex[69];
    encode_hex(calculated_name, sizeof(calculated_name), name_hex);
    if (strlen(submitted_name_hex) != 68 ||
        strcasecmp(name_hex, submitted_name_hex) != 0)
        goto cleanup;

    BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
    EVP_PKEY *key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA ||
        (unsigned int)EVP_PKEY_bits(key) != key_bits) {
        EVP_PKEY_free(key);
        goto cleanup;
    }
    BIGNUM *public_modulus = NULL, *public_exponent = NULL;
    int got_rsa_parameters =
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &public_modulus) == 1 &&
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &public_exponent) == 1;
    unsigned char pem_modulus[TPM_PUBLIC_MAX_BYTES] = {0};
    int pem_modulus_length = got_rsa_parameters
        ? BN_bn2bin(public_modulus, pem_modulus) : -1;
    unsigned long effective_exponent = exponent ? exponent : 65537UL;
    valid = pem_modulus_length == (int)modulus_length &&
        BN_is_word(public_exponent, effective_exponent) &&
        CRYPTO_memcmp(pem_modulus, modulus, modulus_length) == 0;
    BN_free(public_modulus);
    BN_free(public_exponent);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(pem_modulus, sizeof(pem_modulus));
    if (valid) {
        memcpy(out_name_hex, name_hex, sizeof(name_hex));
        if (out_key_bits) *out_key_bits = (int)key_bits;
    }

cleanup:
    OPENSSL_cleanse(encoded, sizeof(encoded));
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(calculated_name, sizeof(calculated_name));
    if (!valid && out_name_hex && out_name_size)
        OPENSSL_cleanse(out_name_hex, out_name_size);
    return valid ? 0 : -1;
}
