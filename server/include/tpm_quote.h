#ifndef EXAMOS_TPM_QUOTE_H
#define EXAMOS_TPM_QUOTE_H

#include <stddef.h>

/* Verify a TPM2 Quote (TPMS_ATTEST + TPMT_SIGNATURE) against an enrolled RSA
 * Attestation Key, a fresh 32-byte server nonce, and the release PCR values. */
int tpm_quote_verify_sha256_rsa(const unsigned char *attest, size_t attest_len,
                                const unsigned char *signature, size_t signature_len,
                                const char *ak_public_pem,
                                const char *ak_qualified_name_hex,
                                const char *nonce_hex,
                                const char *pcr0_hex, const char *pcr4_hex,
                                const char *pcr7_hex, const char *pcr11_hex);

#endif
