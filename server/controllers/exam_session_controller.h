/*
 * exam_session_controller.h — ExamOS Module 11: Exam Session Management
 *
 * Session lifecycle and runtime control:
 * - Session authorization & pre-flight verification
 * - Dynamic session creation & device binding
 * - Secure launch token generation & URL authorization
 * - Heartbeat tracking & stale detection
 * - Interruption handling & recovery policy evaluation
 * - Reconnection and session resumption
 * - Session termination and closure
 * - Multi-tenant isolation & immutable audit logging
 */

#ifndef EXAMOS_EXAM_SESSION_CONTROLLER_H
#define EXAMOS_EXAM_SESSION_CONTROLLER_H

#include <stddef.h>

void exam_session_handle(int client_fd, const char *method, const char *path,
                         const char *body, const char *auth_header,
                         const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_EXAM_SESSION_CONTROLLER_H */
