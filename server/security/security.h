#ifndef EXAMOS_SECURITY_H
#define EXAMOS_SECURITY_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* user_role_t and auth_session_t are defined in include/enterprise_platform.h */
#include "../include/enterprise_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * RBAC permission flags (mirrors admin_auth_store.h)
 * ========================================================================= */
#define AUTH_PERM_READ            (1U << 0)
#define AUTH_PERM_EXAM_MUTATION   (1U << 1)
#define AUTH_PERM_FLEET_MUTATION  (1U << 2)
#define AUTH_PERM_SECURITY_ADMIN  (1U << 3)
#define AUTH_PERM_USER_MANAGEMENT (1U << 4)
#define AUTH_PERM_INSTITUTION_ADMIN (1U << 5)
#define AUTH_PERM_EXAM_READ         (1U << 6)
#define AUTH_PERM_INCIDENT_READ     (1U << 7)
#define AUTH_PERM_MFA_ADMIN         (1U << 8)
#define AUTH_PERM_LOCATION_ADMIN    (1U << 9)
#define AUTH_PERM_INCIDENT_MUTATION (1U << 10)

/* Verify a session token against the database. Returns 0 on success. */
int security_verify_session(const char *token, auth_session_t *out);

/* Check if a role has a permission. */
int security_role_has_permission(user_role_t role, uint32_t permission);

/* Compute permissions bitmask from a role. */
uint32_t security_role_compute_permissions(user_role_t role);

/* Convert role enum to string. */
const char *security_role_to_string(user_role_t role);

/* =========================================================================
 * Password hashing (PBKDF2-SHA256, 210000 iterations)
 * ========================================================================= */
/* Hash a password with a salt. Output must be at least 256 bytes. */
int security_pbkdf2_hash(const char *password, const char *salt, char *out, size_t out_len);

/* Constant-time comparison. */
int security_safe_equal(const char *a, const char *b);

/* =========================================================================
 * TOTP (RFC 6238)
 * ========================================================================= */
/* Generate a new base32 TOTP secret. Returns length written. */
int security_totp_generate_secret(char *out, size_t out_len);

/* Verify a 6-digit TOTP code against a secret. Returns 1 if valid. */
int security_totp_verify(const char *secret, const char *code);

/* =========================================================================
 * ECDSA P-256 signing / verification
 * ========================================================================= */
/* Sign a message with a PEM-encoded private key. Returns signature hex. */
int security_ecdsa_sign_pem(const char *pem_private_key, const unsigned char *data,
                            size_t data_len, char *out_sig_hex, size_t out_len);

/* Verify a signature with a PEM-encoded public key. Returns 1 if valid. */
int security_ecdsa_verify_pem(const char *pem_public_key, const unsigned char *data,
                              size_t data_len, const char *sig_hex);

/* Generate a fresh ECDSA P-256 keypair. Writes PEM private + public keys. */
int security_ecdsa_generate_keypair(char *priv_pem, size_t priv_len,
                                    char *pub_pem, size_t pub_len);

/* =========================================================================
 * Request signing verification (console ECDSA signatures)
 * ========================================================================= */
/* Verify an ExamOS console request signature.
 * canonical = method + "\n" + url + "\n" + headers + "\n" + body_hash
 * Returns 1 if signature is valid. */
int security_verify_request_signature(const char *public_key_pem,
                                      const char *canonical,
                                      const char *signature_hex);

/* Compute SHA-256 hex digest of a string. */
void security_sha256_hex(const char *input, char *out, size_t out_len);

/* =========================================================================
 * mTLS / certificate helpers
 * ========================================================================= */
/* Load a CA bundle for client certificate verification. */
int security_load_ca_bundle(const char *ca_path);

/* =========================================================================
 * Rate limiting (token bucket per IP)
 * ========================================================================= */
#define RATE_LIMIT_WINDOW_SEC 60
#define RATE_LIMIT_MAX_REQUESTS 120

typedef struct {
    char ip[64];
    int count;
    time_t window_start;
} rate_bucket_t;

extern rate_bucket_t g_rate_buckets[256];
extern int g_rate_bucket_count;

/* Check and increment rate limit for an IP. Returns 1 if allowed, 0 if limited. */
int security_rate_check(const char *ip);

/* =========================================================================
 * Input sanitization
 * ========================================================================= */
/* Sanitize a string: strip control chars, truncate to max_len. Returns out length. */
int security_sanitize(const char *input, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_SECURITY_H */
