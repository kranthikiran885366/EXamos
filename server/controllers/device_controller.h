#ifndef EXAMOS_DEVICE_CONTROLLER_H
#define EXAMOS_DEVICE_CONTROLLER_H

#include "../controllers/controller.h"

/* GET    /api/v1/admin/fleet                    -> device fleet list */
/* GET    /api/v1/admin/fleet/compliance         -> compliance summary */
/* POST   /api/v1/admin/fleet/bulk               -> bulk device action */
/* POST   /api/v1/heartbeat                      -> agent heartbeat */
void device_handle(int client_fd, const char *method, const char *path,
                   const char *body, const char *auth_header,
                   const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_DEVICE_CONTROLLER_H */
