#ifndef EXAMOS_EK_CERTIFICATE_H
#define EXAMOS_EK_CERTIFICATE_H

#include <stddef.h>

/*
 * ek_certificate_validate
 *
 * Validates an EK certificate chain against configured trust anchors.
 *
 * Parameters:
 *   ek_certificate_pem: The device's EK certificate in PEM format
 *   ek_certificate_chain: Optional intermediate CA chain in PEM format
 *   ek_fingerprint: Expected SHA-256 fingerprint of the EK public key (can be NULL to skip check)
 *   out_anchor_id: Buffer to receive the trust anchor ID that validated the chain (64 bytes)
 *   out_error: Buffer to receive error description (256 bytes)
 *   out_public_key_pem: Buffer to receive the extracted public key PEM
 *   max_pem_len: Maximum size of out_public_key_pem buffer
 *
 * Returns:
 *   0 on success (certificate is valid and trusted)
 *   -1 on failure (error in out_error)
 */
int ek_certificate_validate(const char *ek_certificate_pem,
                            const char *ek_certificate_chain,
                            const char *ek_fingerprint,
                            char *out_anchor_id,
                            char *out_error,
                            char *out_public_key_pem,
                            size_t max_pem_len);

/*
 * ek_certificate_load_trust_anchors
 *
 * Loads development trust anchors from the configured directory.
 * Production is refused until the separately provisioned, signed SPPIO TPM
 * trust-feed adapter is configured and integrated.
 *
 * Returns:
 *   0 on success
 *   -1 on failure
 */
int ek_certificate_load_trust_anchors(void);

/*
 * ek_certificate_add_trust_anchor
 *
 * Adds a trust anchor for EK certificate validation (for testing/dev mode).
 *
 * Parameters:
 *   anchor_id: Unique identifier for the trust anchor
 *   anchor_name: Human-readable name
 *   certificate_pem: The CA certificate in PEM format
 *   parent_anchor_id: ID of parent anchor (NULL for root CA)
 *
 * Returns:
 *   0 on success
 *   -1 on failure
 */
int ek_certificate_add_trust_anchor(const char *anchor_id,
                                    const char *anchor_name,
                                    const char *certificate_pem,
                                    const char *parent_anchor_id);

#endif /* EXAMOS_EK_CERTIFICATE_H */
