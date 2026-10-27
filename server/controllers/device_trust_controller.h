/*
 * device_trust_controller.h — ExamOS Module 13: Device Trust, Registration & Attestation
 *
 * Implements:
 * - Enterprise device identity & registration lifecycle
 * - Boot environment & OS release integrity verification
 * - Hardware TPM 2.0 attestation challenge-response & quote verification
 * - Device trust policy engine (ALLOW, DENY, PENDING, REASSESS, QUARANTINE, UNSUPPORTED)
 * - Device assignments & student association
 * - Master Exam Launch Authorization integration (Modules 9, 10, 11, 12, 13)
 * - Security incidents, revocations, and durable audit trail
 */

#ifndef EXAMOS_DEVICE_TRUST_CONTROLLER_H
#define EXAMOS_DEVICE_TRUST_CONTROLLER_H

#include <stddef.h>

void device_trust_handle(int client_fd, const char *method, const char *path,
                         const char *body, const char *auth_header,
                         const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_DEVICE_TRUST_CONTROLLER_H */
