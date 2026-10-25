#ifndef EXAMOS_POLICY_CONTROLLER_H
#define EXAMOS_POLICY_CONTROLLER_H

#include "../controllers/controller.h"

/* GET    /api/v1/admin/policies              -> list */
/* GET    /api/v1/admin/policies/catalog      -> browser policy catalog */
void policy_handle(int client_fd, const char *method, const char *path,
                   const char *body, const char *auth_header,
                   const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_POLICY_CONTROLLER_H */
