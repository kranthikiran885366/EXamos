#ifndef EXAMOS_TOTP_H
#define EXAMOS_TOTP_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define TOTP_SECRET_BYTES 20
#define TOTP_BASE32_LEN   32
#define TOTP_CODE_LEN     6
#define TOTP_PERIOD       30
#define TOTP_RECOVERY_CODE_LEN 9   /* e.g., "ABCD-1234" */
#define TOTP_NUM_RECOVERY_CODES 8

/* Generates a cryptographically secure 20-byte random secret encoded as 32-char Base32 string */
int totp_generate_secret(char out_base32[TOTP_BASE32_LEN + 1]);

/* Computes 6-digit TOTP code for given base32 secret and timestamp */
int totp_generate_code(const char *base32_secret, time_t timestamp, char out_code[TOTP_CODE_LEN + 1]);

/* Verifies supplied 6-digit code with window tolerance (window_steps=1 checks now-30s, now, now+30s) */
int totp_verify_code(const char *base32_secret, const char *code, time_t now, int window_steps);

/* Generates standard otpauth:// URI for QR code enrollment */
int totp_generate_uri(const char *username, const char *issuer, const char *base32_secret,
                      char *out_uri, size_t max_len);

/* Generates random recovery codes and their SHA-256 hashes */
int totp_generate_recovery_codes(char out_codes[TOTP_NUM_RECOVERY_CODES][TOTP_RECOVERY_CODE_LEN + 1],
                                 char out_hashes[TOTP_NUM_RECOVERY_CODES][65]);

/* Hashes a recovery code with SHA-256 for database lookup */
int totp_hash_recovery_code(const char *code, char out_hash[65]);

#endif
