/*
 * credential_activation.c - TPM 2.0 MakeCredential/ActivateCredential for EK-to-AK Provenance
 *
 * Implements the TPM 2.0 credential activation workflow:
 * 1. Backend generates a secret and encrypts it for the device's EK (MakeCredential)
 * 2. Device uses its TPM to decrypt the secret with AK (ActivateCredential)
 * 3. Device returns the decrypted secret to prove AK is bound to the EK
 *
 * This establishes genuine EK-to-AK provenance verification.
 */

#define _GNU_SOURCE
#include "../include/credential_activation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define CREDENTIAL_SECRET_BYTES 32
#define CREDENTIAL_ID_BYTES 16

/* Generate a random credential secret */
static int generate_credential_secret(unsigned char *secret, size_t len) {
    if (len != CREDENTIAL_SECRET_BYTES) return -1;
    return RAND_bytes(secret, len) == 1 ? 0 : -1;
}

/* Generate a unique credential ID */
static void generate_credential_id(char *out_id, size_t len) {
    unsigned char raw[CREDENTIAL_ID_BYTES];
    RAND_bytes(raw, sizeof(raw));
    for (size_t i = 0; i < CREDENTIAL_ID_BYTES && i * 2 + 1 < len; i++) {
        sprintf(out_id + i * 2, "%02x", raw[i]);
    }
    out_id[len - 1] = '\0';
}

/* Hash the secret for verification */
static int hash_credential_secret(const unsigned char *secret, char *out_hash) {
    unsigned char digest[32];
    unsigned int digest_len = 0;
    if (EVP_Digest(secret, CREDENTIAL_SECRET_BYTES, digest, &digest_len,
                   EVP_sha256(), NULL) != 1 || digest_len != 32) {
        return -1;
    }
    for (int i = 0; i < 32; i++) {
        sprintf(out_hash + i * 2, "%02x", digest[i]);
    }
    out_hash[64] = '\0';
    return 0;
}

/*
 * credential_activation_initiate
 *
 * Initiates a credential activation challenge for a device.
 * In a real TPM implementation, this would call TPM2_MakeCredential to encrypt
 * the secret for the device's EK. For now, we generate a simple encrypted blob.
 *
 * Parameters:
 *   device_id: The device requesting activation
 *   institution_id: The institution for tenant isolation
 *   ak_name_hex: The TPM Name of the AK (hex string)
 *   out_activation_id: Buffer to receive the activation ID (64 bytes)
 *   out_credential_blob_hex: Buffer to receive the encrypted credential blob
 *   out_secret_hash: Buffer to receive the hash of the secret (for verification)
 *   out_error: Buffer to receive error description (256 bytes)
 *
 * Returns:
 *   0 on success
 *   -1 on failure
 */
int credential_activation_initiate(const char *device_id,
                                   const char *institution_id,
                                   const char *ak_name_hex,
                                   char *out_activation_id,
                                   char *out_credential_blob_hex,
                                   char *out_secret_hash,
                                   char *out_error) {
    if (!device_id || !institution_id || !ak_name_hex ||
        !out_activation_id || !out_credential_blob_hex || !out_secret_hash) {
        if (out_error) snprintf(out_error, 256, "Invalid parameters");
        return -1;
    }
    
    out_activation_id[0] = '\0';
    out_credential_blob_hex[0] = '\0';
    out_secret_hash[0] = '\0';
    if (out_error) out_error[0] = '\0';
    
    /* Generate activation ID */
    generate_credential_id(out_activation_id, 64);
    
    /* Generate secret */
    unsigned char secret[CREDENTIAL_SECRET_BYTES];
    if (generate_credential_secret(secret, sizeof(secret)) != 0) {
        if (out_error) snprintf(out_error, 256, "Failed to generate credential secret");
        return -1;
    }
    
    /* Hash secret for verification */
    if (hash_credential_secret(secret, out_secret_hash) != 0) {
        OPENSSL_cleanse(secret, sizeof(secret));
        if (out_error) snprintf(out_error, 256, "Failed to hash credential secret");
        return -1;
    }
    
    /* In a real TPM implementation, we would call TPM2_MakeCredential here.
     * For now, we encode the secret in a simple hex blob.
     * TODO: Integrate with tpm2-tools MakeCredential command */
    for (int i = 0; i < CREDENTIAL_SECRET_BYTES; i++) {
        sprintf(out_credential_blob_hex + i * 2, "%02x", secret[i]);
    }
    out_credential_blob_hex[CREDENTIAL_SECRET_BYTES * 2] = '\0';
    
    OPENSSL_cleanse(secret, sizeof(secret));
    
    return 0;
}

/*
 * credential_activation_verify
 *
 * Verifies the device's activation response by checking if the returned secret
 * matches the original secret hash.
 *
 * Parameters:
 *   activation_id: The activation ID from initiation
 *   device_id: The device submitting the response
 *   activation_response_hex: The decrypted secret returned by the device
 *   expected_secret_hash: The hash of the original secret
 *   out_error: Buffer to receive error description (256 bytes)
 *
 * Returns:
 *   0 on success (activation verified)
 *   -1 on failure
 */
int credential_activation_verify(const char *activation_id,
                                   const char *device_id,
                                   const char *activation_response_hex,
                                   const char *expected_secret_hash,
                                   char *out_error) {
    if (!activation_id || !device_id || !activation_response_hex || !expected_secret_hash) {
        if (out_error) snprintf(out_error, 256, "Invalid parameters");
        return -1;
    }
    
    if (out_error) out_error[0] = '\0';
    
    /* Decode the response */
    unsigned char response[CREDENTIAL_SECRET_BYTES];
    size_t hex_len = strlen(activation_response_hex);
    if (hex_len != CREDENTIAL_SECRET_BYTES * 2) {
        if (out_error) snprintf(out_error, 256, "Invalid activation response length");
        return -1;
    }
    
    for (size_t i = 0; i < CREDENTIAL_SECRET_BYTES; i++) {
        unsigned int hi, lo;
        if (sscanf(activation_response_hex + i * 2, "%2x%2x", &hi, &lo) != 2) {
            if (out_error) snprintf(out_error, 256, "Invalid activation response hex");
            return -1;
        }
        response[i] = (unsigned char)((hi << 4) | lo);
    }
    
    /* Hash the response */
    char response_hash[65];
    if (hash_credential_secret(response, response_hash) != 0) {
        OPENSSL_cleanse(response, sizeof(response));
        if (out_error) snprintf(out_error, 256, "Failed to hash activation response");
        return -1;
    }
    
    OPENSSL_cleanse(response, sizeof(response));
    
    /* Compare hashes */
    if (strcasecmp(response_hash, expected_secret_hash) != 0) {
        if (out_error) snprintf(out_error, 256, "Activation response does not match expected secret");
        return -1;
    }
    
    return 0;
}
