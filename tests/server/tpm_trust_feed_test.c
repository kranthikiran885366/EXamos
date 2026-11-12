#include "tpm_trust_feed.h"
#include "ek_certificate.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(condition, label) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s\n", label); \
        goto cleanup; \
    } \
} while (0)

static int make_rsa_key(EVP_PKEY **out_key) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!context) return -1;
    int ok = EVP_PKEY_keygen_init(context) > 0 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(context, 3072) > 0 &&
        EVP_PKEY_keygen(context, out_key) > 0;
    EVP_PKEY_CTX_free(context);
    return ok ? 0 : -1;
}

static int public_key_pem(EVP_PKEY *key, char **out_pem) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return -1;
    int ok = PEM_write_bio_PUBKEY(bio, key) == 1;
    BUF_MEM *memory = NULL;
    BIO_get_mem_ptr(bio, &memory);
    if (!ok || !memory || memory->length == 0) {
        BIO_free(bio);
        return -1;
    }
    *out_pem = malloc(memory->length + 1);
    if (!*out_pem) {
        BIO_free(bio);
        return -1;
    }
    memcpy(*out_pem, memory->data, memory->length);
    (*out_pem)[memory->length] = '\0';
    BIO_free(bio);
    return 0;
}

static int public_key_fingerprint(EVP_PKEY *key, char out[65]) {
    int length = i2d_PUBKEY(key, NULL);
    unsigned char *der = length > 0 ? malloc((size_t)length) : NULL;
    if (!der) return -1;
    unsigned char *cursor = der;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    int ok = i2d_PUBKEY(key, &cursor) == length &&
        EVP_Digest(der, (size_t)length, digest, &digest_length,
                   EVP_sha256(), NULL) == 1 && digest_length == 32;
    free(der);
    if (!ok) return -1;
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out[2 * i] = digits[digest[i] >> 4];
        out[2 * i + 1] = digits[digest[i] & 15];
    }
    out[64] = '\0';
    return 0;
}

static int make_ca_certificate(EVP_PKEY *key, X509 **out_certificate,
                               char **out_pem, char fingerprint[65]) {
    X509 *certificate = X509_new();
    X509_NAME *subject = certificate ? X509_get_subject_name(certificate) : NULL;
    X509V3_CTX extension_context;
    X509_EXTENSION *basic_constraints = NULL;
    int ok = certificate && subject &&
        X509_set_version(certificate, 2) == 1 &&
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), 7) == 1 &&
        X509_gmtime_adj(X509_getm_notBefore(certificate), -60) != NULL &&
        X509_gmtime_adj(X509_getm_notAfter(certificate), 86400) != NULL &&
        X509_set_pubkey(certificate, key) == 1 &&
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
            (const unsigned char *)"SPPIO temporary unit-test CA", -1, -1, 0) == 1 &&
        X509_set_issuer_name(certificate, subject) == 1;
    if (ok) {
        X509V3_set_ctx(&extension_context, certificate, certificate, NULL, NULL, 0);
        basic_constraints = X509V3_EXT_conf_nid(NULL, &extension_context,
                                                NID_basic_constraints,
                                                "critical,CA:TRUE");
        ok = basic_constraints &&
             X509_add_ext(certificate, basic_constraints, -1) == 1 &&
             X509_sign(certificate, key, EVP_sha256()) > 0;
    }
    X509_EXTENSION_free(basic_constraints);
    if (!ok) {
        X509_free(certificate);
        return -1;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    if (X509_digest(certificate, EVP_sha256(), digest, &digest_length) != 1 ||
        digest_length != 32) {
        X509_free(certificate);
        return -1;
    }
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        fingerprint[2 * i] = digits[digest[i] >> 4];
        fingerprint[2 * i + 1] = digits[digest[i] & 15];
    }
    fingerprint[64] = '\0';

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio || PEM_write_bio_X509(bio, certificate) != 1) {
        BIO_free(bio);
        X509_free(certificate);
        return -1;
    }
    BUF_MEM *memory = NULL;
    BIO_get_mem_ptr(bio, &memory);
    *out_pem = memory ? malloc(memory->length + 1) : NULL;
    if (!*out_pem) {
        BIO_free(bio);
        X509_free(certificate);
        return -1;
    }
    memcpy(*out_pem, memory->data, memory->length);
    (*out_pem)[memory->length] = '\0';
    BIO_free(bio);
    *out_certificate = certificate;
    return 0;
}

static int sign_feed(EVP_PKEY *key, const unsigned char *feed, size_t feed_len,
                     unsigned char **out_signature, size_t *out_signature_len) {
    static const unsigned char domain[] = "SPPIO-TPM-TRUST-FEED-V1\n";
    unsigned char *signed_feed = malloc(sizeof(domain) - 1 + feed_len);
    if (!signed_feed) return -1;
    memcpy(signed_feed, domain, sizeof(domain) - 1);
    memcpy(signed_feed + sizeof(domain) - 1, feed, feed_len);
    size_t signed_feed_len = sizeof(domain) - 1 + feed_len;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    EVP_PKEY_CTX *key_context = NULL;
    if (!context ||
        EVP_DigestSignInit(context, &key_context, EVP_sha256(), NULL, key) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(key_context, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(key_context, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(key_context, 32) <= 0 ||
        EVP_DigestSignUpdate(context, signed_feed, signed_feed_len) != 1) {
        EVP_MD_CTX_free(context);
        free(signed_feed);
        return -1;
    }
    size_t signature_len = 0;
    int ok = EVP_DigestSignFinal(context, NULL, &signature_len) == 1;
    unsigned char *signature = ok ? malloc(signature_len) : NULL;
    if (!signature || EVP_DigestSignFinal(context, signature, &signature_len) != 1) {
        free(signature);
        EVP_MD_CTX_free(context);
        free(signed_feed);
        return -1;
    }
    EVP_MD_CTX_free(context);
    free(signed_feed);
    *out_signature = signature;
    *out_signature_len = signature_len;
    return 0;
}

static char *json_escape(const char *input) {
    size_t length = strlen(input);
    char *output = malloc(length * 2 + 1);
    if (!output) return NULL;
    size_t used = 0;
    for (size_t i = 0; i < length; ++i) {
        if (input[i] == '\n') {
            output[used++] = '\\';
            output[used++] = 'n';
        } else {
            output[used++] = input[i];
        }
    }
    output[used] = '\0';
    return output;
}

static char *make_feed(const char *authority, const char *root_pem,
                       const char *root_fingerprint, uint64_t sequence,
                       uint64_t issued_at, uint64_t expires_at,
                       int duplicate_authority, int unknown_field) {
    char *escaped_pem = json_escape(root_pem);
    if (!escaped_pem) return NULL;
    size_t capacity = strlen(escaped_pem) + 2048;
    char *json = malloc(capacity);
    if (!json) {
        free(escaped_pem);
        return NULL;
    }
    int count = snprintf(json, capacity,
        "{\"schema\":\"sppio-tpm-trust-feed-v1\","
        "\"authority_id\":\"%s\",%s"
        "\"sequence\":%llu,\"issued_at\":%llu,\"expires_at\":%llu,"
        "\"ek_roots\":[{\"id\":\"test-root\",\"pem\":\"%s\",\"sha256\":\"%s\"}],"
        "\"revoked_device_ids\":[\"test-device\"],"
        "\"revoked_ek_fingerprints\":[\"%064x\"]%s}",
        authority, duplicate_authority ? "\"authority_id\":\"other\"," : "",
        (unsigned long long)sequence, (unsigned long long)issued_at,
        (unsigned long long)expires_at, escaped_pem, root_fingerprint,
        0x1234, unknown_field ? ",\"unexpected\":true" : "");
    free(escaped_pem);
    if (count < 0 || (size_t)count >= capacity) {
        free(json);
        return NULL;
    }
    return json;
}

static int verify_result(const unsigned char *json, size_t json_len,
                         const unsigned char *signature, size_t signature_len,
                         const tpm_trust_feed_policy_t *policy, uint64_t now,
                         tpm_trust_feed_result_t expected, const char *label) {
    tpm_trust_feed_t feed;
    tpm_trust_feed_result_t actual = tpm_trust_feed_verify(
        json, json_len, signature, signature_len, policy, now, &feed);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %s, got %s\n", label,
                tpm_trust_feed_result_name(expected),
                tpm_trust_feed_result_name(actual));
        return -1;
    }
    return 0;
}

int main(void) {
    EVP_PKEY *signing_key = NULL;
    X509 *root_certificate = NULL;
    char *public_pem = NULL, *root_pem = NULL;
    char public_fingerprint[65] = {0}, root_fingerprint[65] = {0};
    char *json = NULL, *other_json = NULL;
    unsigned char *signature = NULL, *other_signature = NULL;
    size_t signature_len = 0, other_signature_len = 0;
    int exit_code = 1;
    uint64_t now = (uint64_t)time(NULL);

    CHECK(make_rsa_key(&signing_key) == 0, "generate ephemeral verifier key");
    CHECK(public_key_pem(signing_key, &public_pem) == 0,
          "serialize ephemeral public key");
    CHECK(public_key_fingerprint(signing_key, public_fingerprint) == 0,
          "fingerprint ephemeral public key");
    CHECK(make_ca_certificate(signing_key, &root_certificate, &root_pem,
                              root_fingerprint) == 0,
          "create ephemeral test CA");

    json = make_feed("authority-test", root_pem, root_fingerprint, 1,
                     now - 20, now + 120, 0, 0);
    CHECK(json != NULL, "create valid feed");
    CHECK(sign_feed(signing_key, (const unsigned char *)json, strlen(json),
                    &signature, &signature_len) == 0,
          "sign valid feed");

    tpm_trust_feed_policy_t policy = {
        "authority-test", public_pem, public_fingerprint, "rsa-pss-sha256",
        300, 0, 1
    };
    tpm_trust_feed_t parsed;
    CHECK(tpm_trust_feed_verify((const unsigned char *)json, strlen(json),
            signature, signature_len, &policy, now, &parsed) ==
            TPM_TRUST_FEED_VALID, "accept valid signed feed");
    CHECK(parsed.sequence == 1 && parsed.ek_root_count == 1 &&
          parsed.revoked_device_count == 1 && parsed.revoked_ek_count == 1,
          "return validated feed fields");

    tpm_trust_feed_policy_t mismatched_pin = policy;
    mismatched_pin.trust_anchor_sha256 =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    CHECK(verify_result((const unsigned char *)json, strlen(json), signature,
            signature_len, &mismatched_pin, now,
            TPM_TRUST_FEED_INVALID_SIGNATURE,
            "incorrect external trust-anchor pin") == 0,
          "incorrect trust-anchor pin result");

    tpm_trust_feed_policy_t missing = policy;
    missing.trust_anchor_public_key_pem = NULL;
    CHECK(verify_result((const unsigned char *)json, strlen(json), signature,
            signature_len, &missing, now, TPM_TRUST_FEED_BLOCKED_CONFIGURATION,
            "missing trust anchor") == 0, "missing trust anchor result");
    missing = policy;
    missing.authority_id = NULL;
    CHECK(verify_result((const unsigned char *)json, strlen(json), signature,
            signature_len, &missing, now, TPM_TRUST_FEED_BLOCKED_CONFIGURATION,
            "missing authority") == 0, "missing authority result");
    missing = policy;
    missing.max_evidence_age_seconds = 0;
    CHECK(verify_result((const unsigned char *)json, strlen(json), signature,
            signature_len, &missing, now, TPM_TRUST_FEED_BLOCKED_CONFIGURATION,
            "missing maximum age") == 0, "missing maximum age result");
    missing = policy;
    missing.trust_anchor_sha256 = NULL;
    CHECK(verify_result((const unsigned char *)json, strlen(json), signature,
            signature_len, &missing, now, TPM_TRUST_FEED_BLOCKED_CONFIGURATION,
            "missing independently provisioned trust pin") == 0,
          "missing trust pin result");
    missing = policy;
    missing.replay_state_available = 0;
    CHECK(verify_result((const unsigned char *)json, strlen(json), signature,
            signature_len, &missing, now, TPM_TRUST_FEED_BLOCKED_CONFIGURATION,
            "missing replay state") == 0, "missing replay state result");

    CHECK(setenv("EXAMOS_TPM_MODE", "production", 1) == 0,
            "set production TPM mode for startup guard");
    CHECK(ek_certificate_load_trust_anchors() != 0,
            "block production startup without an installed signed feed");
    unsetenv("EXAMOS_TPM_MODE");

    tpm_trust_feed_policy_t replay = policy;
    replay.highest_persisted_sequence = 1;
    CHECK(verify_result((const unsigned char *)json, strlen(json), signature,
            signature_len, &replay, now, TPM_TRUST_FEED_REPLAYED,
            "replayed sequence") == 0, "replay result");

    tpm_trust_feed_policy_t unknown = policy;
    unknown.authority_id = "different-authority";
    CHECK(verify_result((const unsigned char *)json, strlen(json), signature,
            signature_len, &unknown, now, TPM_TRUST_FEED_UNKNOWN_AUTHORITY,
            "unknown authority") == 0, "unknown authority result");

    unsigned char *tampered_signature = malloc(signature_len);
    CHECK(tampered_signature != NULL, "allocate tamper test signature");
    memcpy(tampered_signature, signature, signature_len);
    tampered_signature[0] ^= 0x01;
    CHECK(verify_result((const unsigned char *)json, strlen(json),
            tampered_signature, signature_len, &policy, now,
            TPM_TRUST_FEED_INVALID_SIGNATURE, "invalid signature") == 0,
          "invalid signature result");
    free(tampered_signature);

    other_json = strdup(json);
    CHECK(other_json != NULL, "copy feed for modification test");
    char *device = strstr(other_json, "test-device");
    CHECK(device != NULL, "locate feed field for modification");
    device[0] = 'x';
    CHECK(verify_result((const unsigned char *)other_json, strlen(other_json),
            signature, signature_len, &policy, now,
            TPM_TRUST_FEED_INVALID_SIGNATURE, "modified feed") == 0,
          "modified feed result");
    free(other_json);
    other_json = NULL;

    other_json = make_feed("authority-test", root_pem, root_fingerprint, 2,
                           now - 600, now + 120, 0, 0);
    CHECK(other_json != NULL, "create expired feed");
    CHECK(sign_feed(signing_key, (const unsigned char *)other_json,
                    strlen(other_json), &other_signature,
                    &other_signature_len) == 0, "sign expired feed");
    CHECK(verify_result((const unsigned char *)other_json, strlen(other_json),
            other_signature, other_signature_len, &policy, now,
            TPM_TRUST_FEED_EXPIRED, "expired evidence") == 0,
          "expired evidence result");
    free(other_signature);
    other_signature = NULL;
    free(other_json);
    other_json = NULL;

    CHECK(verify_result((const unsigned char *)json, strlen(json), NULL, 0,
            &policy, now, TPM_TRUST_FEED_INVALID_SIGNATURE,
            "unsigned feed") == 0, "unsigned feed result");
    memset(&parsed, 0xa5, sizeof(parsed));
    CHECK(tpm_trust_feed_verify((const unsigned char *)json, strlen(json),
            NULL, 0, &policy, now, &parsed) ==
            TPM_TRUST_FEED_INVALID_SIGNATURE &&
          parsed.sequence == 0 && parsed.ek_root_count == 0,
          "clear output when verification rejects input");

    static const char malformed[] = "{\"schema\":\"sppio-tpm-trust-feed-v1\",";
    unsigned char *malformed_signature = NULL;
    size_t malformed_signature_len = 0;
    CHECK(sign_feed(signing_key, (const unsigned char *)malformed,
                    sizeof(malformed) - 1, &malformed_signature,
                    &malformed_signature_len) == 0,
          "sign malformed JSON test bytes");
    CHECK(verify_result((const unsigned char *)malformed, sizeof(malformed) - 1,
            malformed_signature, malformed_signature_len, &policy, now,
            TPM_TRUST_FEED_INVALID_JSON,
            "malformed JSON") == 0, "malformed JSON result");
    free(malformed_signature);

    other_json = make_feed("authority-test", root_pem, root_fingerprint, 2,
                           now - 10, now + 120, 1, 0);
    CHECK(other_json != NULL, "create duplicate-key feed");
    CHECK(sign_feed(signing_key, (const unsigned char *)other_json,
                    strlen(other_json), &other_signature,
                    &other_signature_len) == 0, "sign duplicate-key feed");
    CHECK(verify_result((const unsigned char *)other_json, strlen(other_json),
            other_signature, other_signature_len, &policy, now,
            TPM_TRUST_FEED_INVALID_JSON,
            "duplicate JSON key") == 0, "duplicate-key result");
    free(other_signature);
    other_signature = NULL;
    free(other_json);
    other_json = make_feed("authority-test", root_pem, root_fingerprint, 2,
                           now - 10, now + 120, 0, 1);
    CHECK(other_json != NULL, "create unknown-field feed");
    CHECK(sign_feed(signing_key, (const unsigned char *)other_json,
                    strlen(other_json), &other_signature,
                    &other_signature_len) == 0, "sign unknown-field feed");
    CHECK(verify_result((const unsigned char *)other_json, strlen(other_json),
            other_signature, other_signature_len, &policy, now,
            TPM_TRUST_FEED_INVALID_SCHEMA, "unknown schema field") == 0,
          "unknown-field result");
    free(other_signature);
    other_signature = NULL;

    puts("PASS: TPM trust-feed schema, authority pin, signature, freshness, and replay checks");
    exit_code = 0;

cleanup:
    free(other_json);
    free(other_signature);
    free(json);
    free(signature);
    free(public_pem);
    free(root_pem);
    X509_free(root_certificate);
    EVP_PKEY_free(signing_key);
    return exit_code;
}
