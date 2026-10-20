#ifndef EXAMOS_KEY_RELEASE_H
#define EXAMOS_KEY_RELEASE_H

#include <stddef.h>

/*
 * key_release_get_session_key
 *
 * Releases the session-bound exam decryption key after verifying:
 *   - session is TRUSTED
 *   - device_id matches the session binding
 *   - exam key has been generated and is ready
 *   - release has not been revoked since attestation
 *
 * Returns 0 and writes 64-char hex key to out_exam_key on success.
 * Returns -1 and writes P3_xxx error code to out_error_code on failure.
 */
int key_release_get_session_key(const char *session_id,
                                 char *out_exam_key,
                                 size_t max_len,
                                 const char *device_id,
                                 char *out_error_code);

/*
 * key_release_check_eligibility
 *
 * Non-destructive check — answers whether this session is eligible for
 * key release without actually releasing the key.
 * Returns 0 if eligible, -1 if not (writes reason to out_reason).
 */
int key_release_check_eligibility(const char *session_id,
                                   const char *device_id,
                                   char *out_reason);

#endif /* EXAMOS_KEY_RELEASE_H */
