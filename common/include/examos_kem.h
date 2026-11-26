#ifndef EXAMOS_KEM_H
#define EXAMOS_KEM_H
#include <stddef.h>

/* ML-KEM-768 primitives through the OpenSSL 3.5+ provider. No fallback.
 * Caller must authenticate the recipient key and bind protocol context before
 * using the shared secret. These functions do not replace TPM enrollment.
 * The caller owns and must cleanse the 32-byte secret after use. */
#define EXAMOS_KEM_CIPHERTEXT_BYTES 1088
#define EXAMOS_KEM_SECRET_BYTES 32
int examos_kem_encapsulate(const char *public_pem,
                          unsigned char ciphertext[EXAMOS_KEM_CIPHERTEXT_BYTES],
                          unsigned char secret[EXAMOS_KEM_SECRET_BYTES]);
int examos_kem_decapsulate(const char *private_pem,
                          const unsigned char *ciphertext, size_t ciphertext_len,
                          unsigned char secret[EXAMOS_KEM_SECRET_BYTES]);
#endif
