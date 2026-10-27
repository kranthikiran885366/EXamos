#ifndef EXAMOS_CAMPUS_CONTROLLER_H
#define EXAMOS_CAMPUS_CONTROLLER_H

#include "../controllers/controller.h"

/* Campus Management Module 4 - Full Lifecycle
 *
 * GET    /api/v1/admin/campuses                                    -> list (tenant-scoped)
 * POST   /api/v1/admin/campuses                                    -> create (submits for approval)
 * GET    /api/v1/admin/campuses/:id                                -> view campus detail
 * POST   /api/v1/admin/campuses/:id/submit-for-approval            -> submit for approval
 * POST   /api/v1/admin/campuses/:id/activate                       -> activate campus
 * POST   /api/v1/admin/campuses/:id/suspend                        -> suspend campus
 * POST   /api/v1/admin/campuses/:id/close                          -> close campus
 * GET    /api/v1/admin/campus-approvals                            -> list pending approvals
 * POST   /api/v1/admin/campus-approvals/:id/decide                 -> approve/reject
 * GET    /api/v1/admin/campus-user-assignments                     -> list assignments
 * POST   /api/v1/admin/campus-user-assignments                     -> assign user to campus
 * POST   /api/v1/admin/campus-user-assignments/:id                 -> revoke assignment
 * GET    /api/v1/admin/campus-os-policies                          -> list OS policies
 * POST   /api/v1/admin/campus-os-policies                          -> create OS policy assignment
 * GET    /api/v1/admin/campus-capacity                             -> list capacity allocations
 * POST   /api/v1/admin/campus-capacity                             -> create capacity allocation
 * GET    /api/v1/admin/org/change-history                          -> organization change history
 */
void campus_handle(int client_fd, const char *method, const char *path,
                   const char *body, const char *auth_header,
                   const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_CAMPUS_CONTROLLER_H */
