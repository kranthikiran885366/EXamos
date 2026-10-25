#ifndef EXAMOS_CANDIDATE_CONTROLLER_H
#define EXAMOS_CANDIDATE_CONTROLLER_H

#include "../controllers/controller.h"

/* POST /api/v1/admin/roster                  -> roster list/filters */
/* POST   candidate login handled in auth     */
void candidate_handle(int client_fd, const char *method, const char *path,
                      const char *body, const char *auth_header,
                      const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_CANDIDATE_CONTROLLER_H */
