#include "release_signature.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>

#define RELEASE_DIGEST_LENGTH 71
#define RELEASE_SIGNATURE_MAX_BASE64 8192

static int valid_digest(const char *digest) {
    if (!digest || strlen(digest) != RELEASE_DIGEST_LENGTH ||
        strncmp(digest, "sha256:", 7) != 0)
        return 0;
    for (size_t i = 7; i < RELEASE_DIGEST_LENGTH; i++) {
        unsigned char c = (unsigned char)digest[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

static int decode_signature(const char *encoded, unsigned char **decoded,
                            size_t *decoded_len) {
    size_t encoded_len = encoded ? strlen(encoded) : 0;
    if (!encoded_len || encoded_len > RELEASE_SIGNATURE_MAX_BASE64 ||
        encoded_len % 4 != 0)
        return 0;
    size_t padding = encoded[encoded_len - 1] == '=' ? 1 : 0;
    if (encoded[encoded_len - 2] == '=') {
        if (!padding) return 0;
        padding++;
    }
    for (size_t i = 0; i < encoded_len - padding; i++) {
        unsigned char c = (unsigned char)encoded[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/'))
            return 0;
    }
    for (size_t i = encoded_len - padding; i < encoded_len; i++) {
        if (encoded[i] != '=') return 0;
    }

    size_t capacity = (encoded_len / 4) * 3;
    unsigned char *buffer = malloc(capacity ? capacity : 1);
    if (!buffer) return -1;
    int result_len = EVP_DecodeBlock(buffer, (const unsigned char *)encoded,
                                     (int)encoded_len);
    if (result_len < 0) {
        free(buffer);
        return 0;
    }
    size_t actual_len = (size_t)result_len - padding;

    char *canonical = malloc(encoded_len + 1);
    if (!canonical) {
        free(buffer);
        return -1;
    }
    int canonical_len = EVP_EncodeBlock((unsigned char *)canonical, buffer,
                                        (int)actual_len);
    if (canonical_len < 0) {
        free(canonical);
        free(buffer);
        return -1;
    }
    canonical[(size_t)canonical_len] = '\0';
    int canonical_match =
                          (size_t)canonical_len == encoded_len &&
                          memcmp(canonical, encoded, encoded_len) == 0;
    free(canonical);
    if (!canonical_match || actual_len == 0) {
        free(buffer);
        return 0;
    }

    *decoded = buffer;
    *decoded_len = actual_len;
    return 1;
}

static int key_fingerprint_matches(EVP_PKEY *key, const char *fingerprint) {
    if (!fingerprint || strlen(fingerprint) != RELEASE_DIGEST_LENGTH ||
        strncasecmp(fingerprint, "sha256:", 7) != 0)
        return 0;

    int der_len = i2d_PUBKEY(key, NULL);
    if (der_len <= 0) return -1;
    unsigned char *der = malloc((size_t)der_len);
    if (!der) return -1;
    unsigned char *der_cursor = der;
    if (i2d_PUBKEY(key, &der_cursor) != der_len) {
        free(der);
        return -1;
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_len = 0;
    int ok = EVP_Digest(der, (size_t)der_len, digest, &digest_len,
                        EVP_sha256(), NULL) == 1 &&
             digest_len == SHA256_DIGEST_LENGTH;
    free(der);
    if (!ok) return -1;

    char expected[RELEASE_DIGEST_LENGTH + 1] = "sha256:";
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        static const char hex[] = "0123456789abcdef";
        expected[7 + i * 2] = hex[digest[i] >> 4];
        expected[8 + i * 2] = hex[digest[i] & 0x0f];
    }
    expected[RELEASE_DIGEST_LENGTH] = '\0';
    return strcasecmp(expected, fingerprint) == 0;
}

static int verify_signature(EVP_PKEY *key, const char *algorithm,
                           const unsigned char *signature, size_t signature_len,
                           const char *message, size_t message_len) {
    int key_type = EVP_PKEY_base_id(key);
    const EVP_MD *digest = NULL;
    int rsa_padding = 0;
    if (strcmp(algorithm, "ed25519") == 0) {
        if (key_type != EVP_PKEY_ED25519 || signature_len != 64) return 0;
    } else if (strcmp(algorithm, "ml-dsa-65") == 0) {
        /* Pure ML-DSA signs the exact manifest, without an external digest.
         * EVP provider discovery fails closed on OpenSSL without ML-DSA. */
        if (!EVP_PKEY_is_a(key, "ML-DSA-65") || signature_len != 3309) return 0;
    } else if (strcmp(algorithm, "rsa-sha256") == 0) {
        if ((key_type != EVP_PKEY_RSA && key_type != EVP_PKEY_RSA_PSS) ||
            (EVP_PKEY_get_bits(key) != 2048 && EVP_PKEY_get_bits(key) != 3072))
            return 0;
        digest = EVP_sha256();
        rsa_padding = RSA_PKCS1_PADDING;
    } else if (strcmp(algorithm, "rsa-pss-sha256") == 0 ||
               strcmp(algorithm, "rsa-pss-sha384") == 0) {
        if ((key_type != EVP_PKEY_RSA && key_type != EVP_PKEY_RSA_PSS) ||
            (EVP_PKEY_get_bits(key) != 2048 && EVP_PKEY_get_bits(key) != 3072))
            return 0;
        digest = strcmp(algorithm, "rsa-pss-sha384") == 0
                     ? EVP_sha384() : EVP_sha256();
        rsa_padding = RSA_PKCS1_PSS_PADDING;
    } else if (strcmp(algorithm, "ecdsa-p256-sha256") == 0 ||
               strcmp(algorithm, "ecdsa-p384-sha384") == 0) {
        char group_name[80] = {0};
        size_t group_name_len = 0;
        const char *expected_group =
            strcmp(algorithm, "ecdsa-p384-sha384") == 0
                ? "secp384r1" : "prime256v1";
        int expected_bits =
            strcmp(algorithm, "ecdsa-p384-sha384") == 0 ? 384 : 256;
        if (key_type != EVP_PKEY_EC ||
            EVP_PKEY_get_bits(key) != expected_bits ||
            EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                                           group_name, sizeof(group_name),
                                           &group_name_len) != 1 ||
            strcmp(group_name, expected_group) != 0)
            return 0;
        digest = expected_bits == 384 ? EVP_sha384() : EVP_sha256();
    } else {
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    EVP_PKEY_CTX *key_ctx = NULL;
    if (EVP_DigestVerifyInit(ctx, &key_ctx, digest, NULL, key) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    if (rsa_padding) {
        int configured = key_ctx &&
            EVP_PKEY_CTX_set_rsa_padding(key_ctx, rsa_padding) > 0;
        if (configured && rsa_padding == RSA_PKCS1_PSS_PADDING) {
            configured =
                EVP_PKEY_CTX_set_rsa_mgf1_md(key_ctx, digest) > 0 &&
                EVP_PKEY_CTX_set_rsa_pss_saltlen(
                    key_ctx, EVP_MD_get_size(digest)) > 0;
        }
        if (!configured) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
    }
    int ok = EVP_DigestVerify(ctx, signature, signature_len,
                              (const unsigned char *)message, message_len);
    EVP_MD_CTX_free(ctx);
    return ok < 0 ? -1 : ok == 1;
}

int release_signature_verify(const char *manifest_json, size_t manifest_len,
                             const char *release_digest,
                             const char *manifest_digest,
                             const char *signed_digest,
                             const char *signature_algorithm,
                             const char *key_algorithm,
                             const char *signature_base64,
                             const char *public_key_pem,
                             const char *key_fingerprint) {
    if (!manifest_json || manifest_len == 0 || !valid_digest(release_digest) ||
        !valid_digest(manifest_digest) || !valid_digest(signed_digest) ||
        !signature_algorithm || !key_algorithm ||
        strcmp(signature_algorithm, key_algorithm) != 0 ||
        strcmp(release_digest, manifest_digest) != 0 ||
        strcmp(release_digest, signed_digest) != 0 ||
        !public_key_pem || !public_key_pem[0])
        return 0;

    unsigned char manifest_hash[SHA256_DIGEST_LENGTH];
    unsigned int manifest_hash_len = 0;
    if (EVP_Digest(manifest_json, manifest_len, manifest_hash,
                   &manifest_hash_len, EVP_sha256(), NULL) != 1 ||
        manifest_hash_len != SHA256_DIGEST_LENGTH)
        return -1;

    char computed_digest[RELEASE_DIGEST_LENGTH + 1] = "sha256:";
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        computed_digest[7 + i * 2] = hex[manifest_hash[i] >> 4];
        computed_digest[8 + i * 2] = hex[manifest_hash[i] & 0x0f];
    }
    computed_digest[RELEASE_DIGEST_LENGTH] = '\0';
    if (strcmp(computed_digest, release_digest) != 0) return 0;

    BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
    if (!bio) return -1;
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!key) return 0;

    int fingerprint_result = key_fingerprint_matches(key, key_fingerprint);
    if (fingerprint_result < 0) {
        EVP_PKEY_free(key);
        return -1;
    }
    if (!fingerprint_result) {
        EVP_PKEY_free(key);
        return 0;
    }

    unsigned char *signature = NULL;
    size_t signature_len = 0;
    int decode_result = decode_signature(signature_base64, &signature,
                                         &signature_len);
    if (decode_result <= 0) {
        EVP_PKEY_free(key);
        return decode_result;
    }
    int result = verify_signature(key, signature_algorithm, signature,
                                  signature_len, manifest_json,
                                  manifest_len);
    free(signature);
    EVP_PKEY_free(key);
    return result;
}
