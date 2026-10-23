#ifndef EXAMOS_APPLIANCE_H
#define EXAMOS_APPLIANCE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ExamOS appliance identity.
 *
 * The examination components only have meaning on an ExamOS appliance.
 * Running the server, the security agent or the proctoring worker on a
 * general-purpose host would place examination evidence, attestation state
 * and sealed secrets on a machine that was never measured, never had its
 * Secure Boot policy verified, and never had its root filesystem sealed.
 *
 * The components therefore refuse to start unless the host is an ExamOS
 * image whose security posture is active.
 *
 * examos_appliance_verify() returns 0 when the host is a valid ExamOS
 * appliance, and -1 otherwise, writing the reason into out_reason.
 */
int examos_appliance_verify(char *out_reason, size_t reason_len);

/* Reads the provisioned appliance identifier, or an empty string. */
int examos_appliance_identity(char *out_id, size_t id_len);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_APPLIANCE_H */
