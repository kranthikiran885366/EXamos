#ifndef EXAMOS_RELEASE_CONTROLLER_H
#define EXAMOS_RELEASE_CONTROLLER_H

#include "../controllers/controller.h"

/* POST /api/v1/admin/revoke/release  -> revoke a release */
/* POST /api/v1/admin/revoke/device   -> revoke a device */
void release_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_RELEASE_CONTROLLER_H */
