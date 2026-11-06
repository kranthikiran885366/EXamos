#ifndef EXAMOS_SUPPORT_CONTROLLER_H
#define EXAMOS_SUPPORT_CONTROLLER_H

#include "controller.h"

/* Dispatcher for the SPPIO / ExamOS Support platform.
 *
 * Routes (all under /api/v1/support):
 *   GET    /requests                       list requests (tenant-scoped)
 *   POST   /requests                       create a request
 *   GET    /requests/{id}                  request detail (comments + events)
 *   POST   /requests/{id}/comments         add a public reply or internal note
 *   POST   /requests/{id}/assign           assign to a support agent
 *   POST   /requests/{id}/status            validated status transition
 *   POST   /requests/{id}/escalate         escalate into a security incident
 *   POST   /requests/{id}/rate             record a satisfaction rating
 *   GET    /stats                           dashboard metrics from real records
 *   POST   /recovery                        open a recovery case + approval
 *   GET    /recovery                        list recovery cases (tenant-scoped)
 *   GET    /diagnostics                     real, read-only health diagnostics
 *   GET    /status                          service status from real records
 *
 * All authorization, validation, SLA, ticket numbering, tenant isolation and
 * audit are enforced server-side. Recovery integrates with the centralized
 * approval governance (approval_requests) for high-risk operations.
 */
void support_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_SUPPORT_CONTROLLER_H */
