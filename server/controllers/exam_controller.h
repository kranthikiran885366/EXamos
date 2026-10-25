#ifndef EXAMOS_EXAM_CONTROLLER_H
#define EXAMOS_EXAM_CONTROLLER_H

#include "../controllers/controller.h"

/* Exam lifecycle routes:
 * GET    /api/v1/admin/exams                              -> list
 * POST   /api/v1/platform/exams/create                    -> create draft
 * POST   /api/v1/platform/exams/:id/validate              -> validate
 * POST   /api/v1/platform/exams/:id/approve               -> approve
 * POST   /api/v1/platform/exams/:id/state                 -> transition
 * POST   /api/v1/platform/exams/:id/url                   -> update url
 * POST   /api/v1/platform/exams/:id/schedule              -> schedule
 * POST   /api/v1/platform/exams/:id/policy/rollback       -> rollback
 * POST   /api/v1/platform/exams/:id/roster                -> add roster entry
 * POST   /api/v1/platform/exams/:id/checkin               -> checkin candidate
 * POST   /api/v1/platform/exams/:id/submissions           -> record submission
 * GET    /api/v1/platform/exams/:id/readiness             -> readiness
 * POST   /api/v1/platform/exams/purge                     -> purge expired
 * POST   /api/v1/platform/exams/sessions                  -> create session
 * POST   /api/v1/platform/exams/sessions/:id/state        -> update session state
 */
void exam_handle(int client_fd, const char *method, const char *path,
                 const char *body, const char *auth_header,
                 const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_EXAM_CONTROLLER_H */
