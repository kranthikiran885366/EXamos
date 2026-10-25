#ifndef EXAMOS_MODULES_CONTROLLER_H
#define EXAMOS_MODULES_CONTROLLER_H

#include "../controllers/controller.h"

/* Consolidated handler for all remaining module routes.
 * Routes dispatched by path prefix within this module group. */
void modules_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_MODULES_CONTROLLER_H */
