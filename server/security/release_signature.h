#ifndef EXAMOS_RELEASE_SIGNATURE_H
#define EXAMOS_RELEASE_SIGNATURE_H

#include <stddef.h>

/* Supported: ML-DSA-65 (OpenSSL 3.5+ provider), Ed25519,
 * RSA-PSS/SHA-256 or SHA-384, and ECDSA P-256/SHA-256 or
 * P-384/SHA-384. rsa-sha256 remains for legacy PKCS#1 v1.5 verification. */
/* Signatures cover the exact manifest bytes supplied by the caller. */
/* This primitive does not canonicalize JSON; production callers must supply RFC 8785 bytes. */
/* Returns 1 for valid, 0 for rejected evidence, and -1 for verifier failure. */
int release_signature_verify(const char *manifest_json, size_t manifest_len,
                             const char *release_digest,
                             const char *manifest_digest,
                             const char *signed_digest,
                             const char *signature_algorithm,
                             const char *key_algorithm,
                             const char *signature_base64,
                             const char *public_key_pem,
                             const char *key_fingerprint);

#endif
