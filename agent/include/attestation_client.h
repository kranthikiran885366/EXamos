#ifndef EXAMOS_ATTESTATION_CLIENT_H
#define EXAMOS_ATTESTATION_CLIENT_H

#include <stddef.h>

int attestation_client_issue_challenge(const char *heartbeat_url,
                                       const char *device_id,
                                       const char *release_id,
                                       const char *session_id,
                                       char *out_nonce, size_t nonce_size);
int attestation_client_verify(const char *heartbeat_url,
                              const char *evidence_json);
int attestation_client_rechallenge(const char *heartbeat_url,
                                   const char *device_id,
                                   const char *session_id,
                                   char *out_nonce, size_t nonce_size);

#endif
