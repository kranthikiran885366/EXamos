#ifndef EXAMOS_SESSION_CONTROLLER_H
#define EXAMOS_SESSION_CONTROLLER_H

#include "../controllers/controller.h"

/* Candidate workbench routes:
 * GET    /api/v1/exam/paper                     -> question battery
 * POST   /api/v1/exam/save_answer               -> save answer
 * POST   /api/v1/exam/submit                    -> final submission
 * GET    /api/v1/exam/announcements             -> announcements
 * GET    /api/v1/exam/terminals                 -> terminals (admin)
 * POST   /api/v1/exam/command                   -> command (admin)
 * POST   /api/v1/exam/key-release               -> release session key
 * GET    /api/v1/exam/key-release/eligibility   -> eligibility check
 * POST   /api/v1/consent                        -> record consent
 * POST   /api/v1/proctoring/events              -> proctoring event
 * GET    /api/v1/proctoring/events              -> list events
 * POST   /api/v1/proctoring/checkpoint          -> checkpoint
 * POST   /api/v1/proctoring/verify              -> verify chain
 * POST   /api/v1/second-camera/request          -> pairing token
 * POST   /api/v1/second-camera/pair             -> validate pairing
 */
void session_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_SESSION_CONTROLLER_H */
