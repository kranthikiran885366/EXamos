#ifndef EXAMOS_KEY_RELEASE_H
#define EXAMOS_KEY_RELEASE_H

#include <stddef.h>

/*
 * key_release_get_session_key
 *
 * Plaintext key delivery is disabled. This function must not be used until a
 * TPM-resident recipient transport and authenticated agent-to-kiosk unwrap
 * flow are implemented.
 *
 * It always returns -1 with P3_DEVICE_BOUND_TRANSPORT_UNAVAILABLE.
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

/*
 * Creates an RSA-OAEP/SHA-256 envelope for the EK public key registered for
 * the device. The exam key never appears in the returned envelope or route.
 */
int key_release_wrap_session_key(const char *candidate_id,
                                 const char *session_id,
                                 const char *device_id,
                                 char *out_envelope,
                                 size_t envelope_len,
                                 char *out_error_code);

#endif /* EXAMOS_KEY_RELEASE_H */
