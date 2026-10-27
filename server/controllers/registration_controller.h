#ifndef EXAMOS_REGISTRATION_CONTROLLER_H
#define EXAMOS_REGISTRATION_CONTROLLER_H

#include "../controllers/controller.h"

/* Module 10: Examination Registration & Eligibility Management routes:
 * POST   /api/v1/admin/students                                      -> create/upsert student
 * GET    /api/v1/admin/students                                      -> list students
 * POST   /api/v1/examinations/:id/rules                              -> configure eligibility rule
 * GET    /api/v1/examinations/:id/rules                              -> list rules
 * POST   /api/v1/examinations/:id/registrations                      -> register student
 * GET    /api/v1/examinations/:id/registrations                      -> list registrations
 * GET    /api/v1/registrations/:id                                   -> view registration
 * POST   /api/v1/registrations/:id/evaluate                          -> evaluate eligibility
 * POST   /api/v1/registrations/:id/approve                           -> approve registration
 * POST   /api/v1/registrations/:id/reject                            -> reject registration
 * POST   /api/v1/registrations/:id/exception                         -> grant exception
 * POST   /api/v1/examinations/:id/registrations/import               -> bulk import
 * GET    /api/v1/registration-imports/:id                            -> check import progress
 * POST   /api/v1/examinations/:id/roster/publish                     -> publish approved roster
 * GET    /api/v1/examinations/:id/eligibility/:studentId             -> real-time exam access check
 */
void registration_handle(int client_fd, const char *method, const char *path,
                         const char *body, const char *auth_header,
                         const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_REGISTRATION_CONTROLLER_H */
