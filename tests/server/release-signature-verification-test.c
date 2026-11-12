#include "../../server/security/release_signature.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static EVP_PKEY *generate_key(int type, int bits, const char *curve_name) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(type, NULL);
    EVP_PKEY *key = NULL;
    int setup_ok = ctx && EVP_PKEY_keygen_init(ctx) > 0;
    if (setup_ok && type == EVP_PKEY_RSA)
        setup_ok = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) > 0;
    if (setup_ok && type == EVP_PKEY_EC)
        setup_ok = curve_name &&
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                ctx, OBJ_sn2nid(curve_name)) > 0;
    if (!setup_ok || EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        fail("could not generate disposable test key");
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static void public_key_material(EVP_PKEY *key, char **pem_out,
                                char fingerprint[72]) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio || PEM_write_bio_PUBKEY(bio, key) != 1)
        fail("could not serialize test public key");
    BUF_MEM *memory = NULL;
    BIO_get_mem_ptr(bio, &memory);
    *pem_out = malloc(memory->length + 1);
    if (!*pem_out) fail("out of memory");
    memcpy(*pem_out, memory->data, memory->length);
    (*pem_out)[memory->length] = '\0';
    BIO_free(bio);

    int der_len = i2d_PUBKEY(key, NULL);
    if (der_len <= 0) fail("could not encode test public key");
    unsigned char *der = malloc((size_t)der_len);
    if (!der) fail("out of memory");
    unsigned char *cursor = der;
    if (i2d_PUBKEY(key, &cursor) != der_len) fail("could not encode test public key");
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_len = 0;
    if (EVP_Digest(der, (size_t)der_len, digest, &digest_len,
                   EVP_sha256(), NULL) != 1 ||
        digest_len != SHA256_DIGEST_LENGTH)
        fail("could not fingerprint test public key");
    free(der);

    memcpy(fingerprint, "sha256:", 7);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(fingerprint + 7 + i * 2, 3, "%02x", digest[i]);
}

static char *sign_payload(EVP_PKEY *key, const char *algorithm,
                          const char *payload, size_t *signature_len) {
    const EVP_MD *md = NULL;
    int rsa_padding = 0;
    if (strcmp(algorithm, "rsa-sha256") == 0) {
        md = EVP_sha256();
        rsa_padding = RSA_PKCS1_PADDING;
    } else if (strcmp(algorithm, "rsa-pss-sha256") == 0) {
        md = EVP_sha256();
        rsa_padding = RSA_PKCS1_PSS_PADDING;
    } else if (strcmp(algorithm, "rsa-pss-sha384") == 0 ||
               strcmp(algorithm, "ecdsa-p384-sha384") == 0) {
        md = EVP_sha384();
        if (strcmp(algorithm, "rsa-pss-sha384") == 0)
            rsa_padding = RSA_PKCS1_PSS_PADDING;
    } else if (strcmp(algorithm, "ecdsa-p256-sha256") == 0) {
        md = EVP_sha256();
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *key_ctx = NULL;
    size_t required = 0;
    if (!ctx || EVP_DigestSignInit(ctx, &key_ctx, md, NULL, key) != 1) {
        EVP_MD_CTX_free(ctx);
        fail("could not initialize test signature");
    }
    if (rsa_padding &&
        (EVP_PKEY_CTX_set_rsa_padding(key_ctx, rsa_padding) <= 0 ||
         (rsa_padding == RSA_PKCS1_PSS_PADDING &&
          (EVP_PKEY_CTX_set_rsa_mgf1_md(key_ctx, md) <= 0 ||
           EVP_PKEY_CTX_set_rsa_pss_saltlen(key_ctx, EVP_MD_get_size(md)) <= 0)))) {
        EVP_MD_CTX_free(ctx);
        fail("could not configure test RSA signature");
    }
    if (EVP_DigestSign(ctx, NULL, &required, (const unsigned char *)payload,
                       strlen(payload)) != 1) {
        EVP_MD_CTX_free(ctx);
        fail("could not initialize test signature");
    }
    unsigned char *signature = malloc(required);
    if (!signature) fail("out of memory");
    if (EVP_DigestSign(ctx, signature, &required,
                       (const unsigned char *)payload, strlen(payload)) != 1) {
        EVP_MD_CTX_free(ctx);
        free(signature);
        fail("could not create test signature");
    }
    EVP_MD_CTX_free(ctx);

    size_t encoded_capacity = 4 * ((required + 2) / 3) + 1;
    char *encoded = malloc(encoded_capacity);
    if (!encoded) fail("out of memory");
    int encoded_len = EVP_EncodeBlock((unsigned char *)encoded, signature,
                                      (int)required);
    free(signature);
    if (encoded_len <= 0 || (size_t)encoded_len >= encoded_capacity)
        fail("could not encode test signature");
    encoded[encoded_len] = '\0';
    *signature_len = required;
    return encoded;
}

static void digest_manifest(const char *manifest, char digest[72]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len = 0;
    if (EVP_Digest(manifest, strlen(manifest), hash, &hash_len,
                   EVP_sha256(), NULL) != 1 ||
        hash_len != SHA256_DIGEST_LENGTH)
        fail("could not hash test manifest");
    memcpy(digest, "sha256:", 7);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(digest + 7 + i * 2, 3, "%02x", hash[i]);
}

static void check_algorithm(int key_type, int bits, const char *curve_name,
                            const char *algorithm) {
    const char manifest[] = "{\"release_id\":\"qa-1\",\"version\":\"2.19.0\"}";
    char digest[72], fingerprint[72], *pem = NULL;
    digest_manifest(manifest, digest);
    EVP_PKEY *key = generate_key(key_type, bits, curve_name);
    public_key_material(key, &pem, fingerprint);
    size_t signature_len = 0;
    char *signature = sign_payload(key, algorithm, manifest, &signature_len);
    int valid_result = release_signature_verify(
        manifest, strlen(manifest), digest, digest, digest, algorithm, algorithm,
        signature, pem, fingerprint);
    if ((strcmp(algorithm, "ed25519") == 0 && signature_len != 64) ||
        valid_result != 1)
        fail("valid signature was rejected");

    char altered_manifest[] = "{\"release_id\":\"qa-2\",\"version\":\"2.19.0\"}";
    if (release_signature_verify(altered_manifest, strlen(altered_manifest),
                                 digest, digest, digest, algorithm, algorithm,
                                 signature, pem, fingerprint) == 1)
        fail("altered manifest was accepted");
    char altered_digest[72];
    digest_manifest(altered_manifest, altered_digest);
    if (release_signature_verify(altered_manifest, strlen(altered_manifest),
                                 altered_digest, altered_digest, altered_digest,
                                 algorithm, algorithm, signature, pem,
                                 fingerprint) == 1)
        fail("signature was not bound to the exact manifest bytes");
    if (release_signature_verify(manifest, strlen(manifest), digest, digest,
                                 digest, "unsupported", algorithm, signature,
                                 pem, fingerprint) == 1)
        fail("unsupported algorithm was accepted");
    if (release_signature_verify(manifest, strlen(manifest), digest, digest,
                                 digest, algorithm, algorithm, "!!!!", pem,
                                 fingerprint) == 1)
        fail("malformed signature encoding was accepted");

    char *tampered_signature = strdup(signature);
    if (!tampered_signature) fail("out of memory");
    tampered_signature[0] = tampered_signature[0] == 'A' ? 'B' : 'A';
    if (release_signature_verify(manifest, strlen(manifest), digest, digest,
                                 digest, algorithm, algorithm,
                                 tampered_signature, pem, fingerprint) == 1)
        fail("cryptographically invalid signature was accepted");
    free(tampered_signature);

    char *noncanonical_signature = strdup(signature);
    if (!noncanonical_signature) fail("out of memory");
    noncanonical_signature[1] = '=';
    if (release_signature_verify(manifest, strlen(manifest), digest, digest,
                                 digest, algorithm, algorithm,
                                 noncanonical_signature, pem, fingerprint) == 1)
        fail("noncanonical signature encoding was accepted");
    free(noncanonical_signature);

    char wrong_fingerprint[72];
    memcpy(wrong_fingerprint, fingerprint, sizeof(wrong_fingerprint));
    wrong_fingerprint[7] = wrong_fingerprint[7] == '0' ? '1' : '0';
    if (release_signature_verify(manifest, strlen(manifest), digest, digest,
                                 digest, algorithm, algorithm, signature, pem,
                                 wrong_fingerprint) == 1)
        fail("public key fingerprint mismatch was accepted");
    if (release_signature_verify(manifest, strlen(manifest), digest, digest,
                                 digest, algorithm, "mismatched-key-algorithm",
                                 signature, pem, fingerprint) == 1)
        fail("signing-key algorithm mismatch was accepted");

    char wrong_digest[72];
    memcpy(wrong_digest, digest, sizeof(wrong_digest));
    wrong_digest[7] = wrong_digest[7] == '0' ? '1' : '0';
    if (release_signature_verify(manifest, strlen(manifest), wrong_digest,
                                 digest, digest, algorithm, algorithm,
                                 signature, pem, fingerprint) == 1)
        fail("manifest digest mismatch was accepted");

    free(signature);
    free(pem);
    EVP_PKEY_free(key);
}

int main(void) {
    check_algorithm(EVP_PKEY_ED25519, 0, NULL, "ed25519");
    check_algorithm(EVP_PKEY_RSA, 2048, NULL, "rsa-sha256");
    check_algorithm(EVP_PKEY_RSA, 2048, NULL, "rsa-pss-sha256");
    check_algorithm(EVP_PKEY_RSA, 3072, NULL, "rsa-pss-sha384");
    check_algorithm(EVP_PKEY_EC, 256, "prime256v1", "ecdsa-p256-sha256");
    check_algorithm(EVP_PKEY_EC, 384, "secp384r1", "ecdsa-p384-sha384");
    puts("Release signature verification tests passed (Ed25519, RSA-2048/3072 PSS, ECDSA P-256/P-384).");
    return 0;
}
