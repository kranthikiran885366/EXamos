#ifndef EXAMOS_ATTESTATION_SERVICE_H
#define EXAMOS_ATTESTATION_SERVICE_H

#include <stddef.h>
#include <time.h>

/* -----------------------------------------------------------------------
 * ExamOS Phase 3 — Attestation Service
 * Implements the 16-step deterministic trust chain:
 *   UEFI -> Secure Boot -> Signed UKI -> TPM measured boot ->
 *   PCR values -> Remote attestation -> Server verification ->
 *   Trusted session -> Exam-key release
 *
 * TEST ONLY configuration — production enrolls real devices with real EKs.
 * ----------------------------------------------------------------------- */

#define MAX_DEVICES              256
#define MAX_RELEASES             64
#define MAX_ATTESTATION_SESSIONS 512
#define NONCE_LEN                64
#define EXAM_KEY_LEN             64

/* Device lifecycle states — must match source-defined state machine */
typedef enum {
    DEVICE_STATUS_UNREGISTERED = 0,
    DEVICE_STATUS_ENROLLED,
    DEVICE_STATUS_TRUSTED,
    DEVICE_STATUS_SUSPENDED,
    DEVICE_STATUS_REVOKED,
    DEVICE_STATUS_RETIRED
} device_status_t;

typedef struct {
    char              device_id[64];
    char              ek_fingerprint[65];   /* SHA-256 hex of EK public key */
    char              ak_qualified_name[69]; /* TPM2B_NAME from TPMS_ATTEST */
    char              ak_public_pem[2048];   /* pinned RSA signing key */
    device_status_t   status;
    char              allowed_release[64];
    time_t            created_at;
    time_t            updated_at;
} enrolled_device_t;

typedef struct {
    char    release_id[64];
    char    uki_hash[65];       /* SHA-256 hex of Unified Kernel Image */
    char    pcr0[65];           /* CRTM / BIOS firmware measurement */
    char    pcr4[65];           /* Boot manager / UKI payload */
    char    pcr7[65];           /* Secure Boot policy state */
    char    pcr11[65];          /* Root filesystem dm-verity roothash */
    int     revoked;
    time_t  created_at;
} golden_release_t;

/* Attestation session state machine */
typedef enum {
    ATTESTATION_STATE_PENDING = 0,
    ATTESTATION_STATE_TRUSTED,
    ATTESTATION_STATE_FAILED,
    ATTESTATION_STATE_REVOKED
} attestation_state_t;

typedef struct {
    char                attestation_id[64];
    char                session_id[64];
    char                device_id[64];
    char                release_id[64];
    char                nonce[128];
    int                 nonce_used;
    time_t              created_at;
    time_t              last_re_attestation;
    attestation_state_t state;
    char                failure_reason[64];
    int                 exam_key_released;
    char                exam_key[EXAM_KEY_LEN + 1];
} attestation_session_t;

/* --- Service Lifecycle --- */
int  attestation_service_init(void);
int  attestation_store_init(void);

/* --- Device & Release Registry --- */
int  attestation_register_device(const char *device_id, const char *ek_fingerprint,
                                  const char *allowed_release);
int  attestation_register_device_identity(const char *device_id,
                                           const char *ek_fingerprint,
                                           const char *ak_qualified_name,
                                           const char *ak_public_pem,
                                           const char *ak_public_sha256,
                                           const char *allowed_release);
int  attestation_register_release(const char *release_id, const char *uki_hash,
                                   const char *pcr0, const char *pcr4,
                                   const char *pcr7, const char *pcr11);

/* --- Challenge / Verify Flow ---
 * attestation_create_challenge:
 *   - Checks device exists and is not revoked
 *   - Generates cryptographically random nonce
 *   - Writes nonce to out_nonce (128 bytes), session ID to out_attestation_id (64 bytes)
 *   - On failure writes structured error code to out_error_code (64 bytes)
 *   Returns 0 on success, -1 on failure.
 */
int  attestation_create_challenge(const char *device_id, const char *session_id,
                                   const char *release_id,
                                   char *out_nonce, char *out_attestation_id,
                                   char *out_error_code);

/*
 * attestation_verify_evidence:
 *   Verifies TPM quote evidence against the enrolled AK and approved release
 *   PCR measurements. Production challenge and revocation state are durably
 *   recorded in PostgreSQL. Exam-key release is a separate lifecycle.
 *   On failure: records the error in out_reason (64 bytes).
 */
int  attestation_verify_evidence(const char *evidence_json,
                                  char *out_reason, char *out_exam_key);

/*
 * attestation_re_attest_challenge:
 *   Issues a fresh nonce for periodic re-attestation of an active session.
 *   Looks up session by session_id OR attestation_id.
 *   Session must already be TRUSTED.
 *   Returns 0 and writes new nonce to out_new_nonce on success, -1 on failure.
 */
int  attestation_re_attest_challenge(const char *session_id, const char *device_id,
                                      char *out_new_nonce);

/* Legacy re-attest with full evidence re-verification (used for heartbeat) */
int  attestation_re_attest(const char *attestation_id, const char *evidence_json,
                            char *out_reason);

/* --- Revocation --- */
int  attestation_revoke_release(const char *release_id);
int  attestation_revoke_device(const char *device_id);

/* --- Status & Key Release --- */
int  attestation_get_status(const char *attestation_id, char *out_status, size_t max_len);

/*
 * attestation_get_exam_key:
 *   Releases the session-bound exam key to a TRUSTED session.
 *   Searches by session_id OR attestation_id.
 *   Returns 0 and writes key to out_key on success; -1 if untrusted or not found.
 */
int  attestation_get_exam_key(const char *session_id, const char *device_id,
                               char *out_key, size_t max_len);

#endif /* EXAMOS_ATTESTATION_SERVICE_H */
