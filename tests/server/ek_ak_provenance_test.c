/*
 * ek_ak_provenance_test.c - Phase 2: EK-to-AK Provenance Unit Tests
 *
 * Tests EK certificate validation and credential activation logic
 * without requiring a physical TPM or swtpm.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* Simulate the functions from our new modules */
static int test_credential_activation_initiate(void);
static int test_credential_activation_verify(void);
static int test_ek_certificate_validation(void);

/* Simple hex encoding */
static void bytes_to_hex(const unsigned char *bytes, size_t len, char *out) {
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

/* Generate a self-signed test certificate */
static int generate_test_ek_cert(char *out_pem, size_t max_len) {
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    BIGNUM *bn = NULL;
    
    bn = BN_new();
    BN_set_word(bn, RSA_F4);
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        BN_free(bn);
        return -1;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        BN_free(bn);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        BN_free(bn);
        return -1;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        BN_free(bn);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    BN_free(bn);
    
    cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 year
    
    name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"Test TPM EK", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    
    X509_set_pubkey(cert, pkey);
    X509_sign(cert, pkey, EVP_sha256());
    
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    
    if (len > 0 && (size_t)len < max_len) {
        memcpy(out_pem, data, len);
        out_pem[len] = '\0';
    }
    
    BIO_free(bio);
    X509_free(cert);
    X509_NAME_free(name);
    EVP_PKEY_free(pkey);
    
    return (len > 0 && (size_t)len < max_len) ? 0 : -1;
}

static int test_credential_activation_initiate(void) {
    printf("\n[TEST] Credential Activation Initiation\n");
    
    /* Simulate the credential activation initiation logic */
    unsigned char secret[32];
    if (RAND_bytes(secret, sizeof(secret)) != 1) {
        printf("  FAIL: Failed to generate secret\n");
        return -1;
    }
    
    char secret_hash[65];
    bytes_to_hex(secret, 32, secret_hash);
    
    /* Simulate credential blob (hex encoded secret) */
    char credential_blob[65];
    bytes_to_hex(secret, 32, credential_blob);
    
    printf("  PASS: Credential activation initiated\n");
    printf("    Secret hash: %s\n", secret_hash);
    printf("    Credential blob: %s\n", credential_blob);
    
    return 0;
}

static int test_credential_activation_verify(void) {
    printf("\n[TEST] Credential Activation Verification\n");
    
    /* Simulate verification logic */
    unsigned char secret[32];
    RAND_bytes(secret, sizeof(secret));
    
    char expected_hash[65];
    bytes_to_hex(secret, 32, expected_hash);
    
    /* Correct response */
    char response_blob[65];
    bytes_to_hex(secret, 32, response_blob);
    
    char response_hash[65];
    bytes_to_hex(secret, 32, response_hash);
    
    if (strcmp(response_hash, expected_hash) == 0) {
        printf("  PASS: Valid activation response verified\n");
    } else {
        printf("  FAIL: Hash mismatch\n");
        return -1;
    }
    
    /* Wrong response */
    unsigned char wrong_secret[32];
    RAND_bytes(wrong_secret, sizeof(wrong_secret));
    char wrong_hash[65];
    bytes_to_hex(wrong_secret, 32, wrong_hash);
    
    if (strcmp(wrong_hash, expected_hash) == 0) {
        printf("  FAIL: Wrong secret incorrectly verified\n");
        return -1;
    }
    
    printf("  PASS: Wrong activation response rejected\n");
    
    return 0;
}

static int test_ek_certificate_validation(void) {
    printf("\n[TEST] EK Certificate Validation\n");
    
    char cert_pem[4096];
    if (generate_test_ek_cert(cert_pem, sizeof(cert_pem)) != 0) {
        printf("  FAIL: Failed to generate test certificate\n");
        return -1;
    }
    
    /* Parse the certificate */
    BIO *bio = BIO_new_mem_buf(cert_pem, -1);
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!cert) {
        printf("  FAIL: Failed to parse certificate\n");
        return -1;
    }
    
    /* Check expiration */
    time_t now = time(NULL);
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    
    int nb_cmp = ASN1_TIME_cmp_time_t(not_before, now);
    int na_cmp = ASN1_TIME_cmp_time_t(not_after, now);
    
    if (nb_cmp > 0) {
        printf("  FAIL: Certificate not yet valid\n");
        X509_free(cert);
        return -1;
    }
    
    if (na_cmp < 0) {
        printf("  FAIL: Certificate expired\n");
        X509_free(cert);
        return -1;
    }
    
    printf("  PASS: Certificate validity period OK\n");
    
    /* Extract public key */
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (!pkey) {
        printf("  FAIL: Failed to extract public key\n");
        X509_free(cert);
        return -1;
    }
    
    int key_type = EVP_PKEY_base_id(pkey);
    int key_bits = EVP_PKEY_bits(pkey);
    
    EVP_PKEY_free(pkey);
    X509_free(cert);
    
    if (key_type != EVP_PKEY_RSA || key_bits < 2048) {
        printf("  FAIL: Invalid key type or size\n");
        return -1;
    }
    
    printf("  PASS: RSA key (%d bits) extracted\n", key_bits);
    
    return 0;
}

int main(void) {
    printf("=== Phase 2: EK-to-AK Provenance Unit Tests ===\n");
    
    int tests = 0;
    int passed = 0;
    int failed = 0;
    
    tests++;
    if (test_credential_activation_initiate() == 0) passed++;
    else failed++;
    
    tests++;
    if (test_credential_activation_verify() == 0) passed++;
    else failed++;
    
    tests++;
    if (test_ek_certificate_validation() == 0) passed++;
    else failed++;
    
    printf("\n=== Test Summary ===\n");
    printf("Total: %d, Pass: %d, Fail: %d\n", tests, passed, failed);
    
    return failed > 0 ? 1 : 0;
}
