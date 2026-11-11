#ifndef EXAMOS_CREDENTIAL_ACTIVATION_H
#define EXAMOS_CREDENTIAL_ACTIVATION_H

#include <stddef.h>

/*
 * credential_activation_initiate
 *
 * Initiates a TPM 2.0 credential activation challenge.
 * This implements the MakeCredential portion of the EK-to-AK provenance workflow.
 *
 * Parameters:
 *   device_id: The device requesting activation
 *   institution_id: The institution for tenant isolation
 *   ak_name_hex: The TPM Name of the AK (hex string, 68 chars for SHA-256)
 *   out_activation_id: Buffer to receive the activation ID (64 bytes)
 *   out_credential_blob_hex: Buffer to receive the encrypted credential blob
 *   out_secret_hash: Buffer to receive the hash of the secret (65 bytes)
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
                                   char *out_error);

/*
 * credential_activation_verify
 *
 * Verifies the device's activation response from ActivateCredential.
 * This proves the AK is bound to the EK.
 *
 * Parameters:
 *   activation_id: The activation ID from initiation
 *   device_id: The device submitting the response
 *   activation_response_hex: The decrypted secret returned by the device
 *   expected_secret_hash: The hash of the original secret
 *   out_error: Buffer to receive error description (256 bytes)
 *
 * Returns:
 *   0 on success (activation verified - EK-to-AK provenance established)
 *   -1 on failure
 */
int credential_activation_verify(const char *activation_id,
                                   const char *device_id,
                                   const char *activation_response_hex,
                                   const char *expected_secret_hash,
                                   char *out_error);

#endif /* EXAMOS_CREDENTIAL_ACTIVATION_H */
