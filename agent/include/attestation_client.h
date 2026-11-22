#ifndef EXAMOS_ATTESTATION_CLIENT_H
#define EXAMOS_ATTESTATION_CLIENT_H

#include <stddef.h>

/* purpose is re_attestation for boot/active sessions and exam_launch for a
 * fresh, pending candidate check-in. */
int attestation_client_issue_challenge(const char *heartbeat_url,
                                       const char *device_id,
                                       const char *release_id,
                                       const char *session_id,
                                       const char *purpose,
                                       char *out_nonce, size_t nonce_size);
int attestation_client_verify(const char *heartbeat_url,
                              const char *evidence_json);
int attestation_client_activate(const char *heartbeat_url,
                                const char *device_id);
int attestation_client_rechallenge(const char *heartbeat_url,
                                   const char *device_id,
                                   const char *session_id,
                                   char *out_nonce, size_t nonce_size);
int attestation_client_poll_exam_session(const char *heartbeat_url,
                                         const char *device_id,
                                         char *out_session_id, size_t session_size,
                                         char *out_release_id, size_t release_size,
                                         char *out_purpose, size_t purpose_size);
int attestation_client_request_exam_key(const char *heartbeat_url,
                                        const char *session_id,
                                        const char *device_id,
                                        char *out_wrapped_key,
                                        size_t wrapped_key_size);

#endif
