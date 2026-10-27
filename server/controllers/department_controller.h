#ifndef EXAMOS_DEPARTMENT_CONTROLLER_H
#define EXAMOS_DEPARTMENT_CONTROLLER_H

#include "../controllers/controller.h"

/* Department Management Module 4 - Full Lifecycle
 *
 * GET    /api/v1/admin/departments                                    -> list (tenant-scoped)
 * POST   /api/v1/admin/departments                                    -> create (submits for approval)
 * GET    /api/v1/admin/departments/:id                                -> view department detail
 * POST   /api/v1/admin/departments/:id/submit-for-approval            -> submit for approval
 * POST   /api/v1/admin/departments/:id/activate                       -> activate department
 * POST   /api/v1/admin/departments/:id/suspend                        -> suspend department
 * POST   /api/v1/admin/departments/:id/archive                        -> archive department
 * POST   /api/v1/admin/departments/:id/transfer                       -> transfer to another campus
 * GET    /api/v1/admin/department-approvals                            -> list pending approvals
 * POST   /api/v1/admin/department-approvals/:id/decide                 -> approve/reject
 * GET    /api/v1/admin/department-user-assignments                     -> list assignments
 * POST   /api/v1/admin/department-user-assignments                     -> assign user to department
 * POST   /api/v1/admin/department-user-assignments/:id                 -> revoke assignment
 * GET    /api/v1/admin/academic-programs                             -> list programs
 * POST   /api/v1/admin/academic-programs                             -> create program
 * GET    /api/v1/admin/org/change-history                            -> organization change history
 */
void department_handle(int client_fd, const char *method, const char *path,
                       const char *body, const char *auth_header,
                       const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_DEPARTMENT_CONTROLLER_H */
