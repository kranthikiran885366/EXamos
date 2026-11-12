#ifndef EXAMOS_CREDENTIAL_ACTIVATION_H
#define EXAMOS_CREDENTIAL_ACTIVATION_H

#include <stddef.h>

/*
 * credential_activation_initiate
 *
 * Initiates a TPM 2.0 credential activation challenge.
 * Creates a TPM 2.0 MakeCredential blob and a context-bound HMAC of its
 * random 32-byte activation secret. The secret itself is never persisted.
 *
 * Parameters:
 *   device_id: The device requesting activation
 *   institution_id: The institution for tenant isolation
 *   ak_name_hex: The TPM Name of the AK (hex string, 68 chars for SHA-256)
 *   out_activation_id: Buffer to receive the activation ID (64 bytes)
 *   out_credential_blob_hex: Buffer to receive the encrypted credential blob
 *   out_secret_mac: Buffer to receive the context-bound HMAC (65 bytes)
 *   out_error: Buffer to receive error description (256 bytes)
 *
 * Returns:
 *   0 on success
 *   -1 on failure
 */
int credential_activation_initiate(const char *device_id,
                                   const char *institution_id,
                                   const char *ek_public_key_pem,
                                   const char *ak_name_hex,
                                   char *out_activation_id,
                                   char *out_credential_blob_hex,
                                   size_t out_blob_size,
                                   char *out_secret_mac,
                                   char *out_error);

/*
 * credential_activation_verify
 *
 * Verifies the device's activation response from ActivateCredential.
 * Checks the ActivateCredential response against the issued secret MAC.
 *
 * Parameters:
 *   activation_id: The activation ID from initiation
 *   device_id: The device submitting the response
 *   activation_response_hex: The decrypted secret returned by the device
 *   expected_secret_mac: The context-bound HMAC stored with the challenge
 *   out_error: Buffer to receive error description (256 bytes)
 *
 * Returns:
 *   0 on success (activation verified - EK-to-AK provenance established)
 *   -1 on failure
 */
int credential_activation_verify(const char *activation_id,
                                   const char *device_id,
                                   const char *institution_id,
                                   const char *activation_response_hex,
                                   const char *expected_secret_mac,
                                   char *out_error);

#endif /* EXAMOS_CREDENTIAL_ACTIVATION_H */
