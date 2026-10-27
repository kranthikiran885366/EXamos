#ifndef EXAMOS_INSTITUTION_CONTROLLER_H
#define EXAMOS_INSTITUTION_CONTROLLER_H

#include "../controllers/controller.h"

/* GET    /api/v1/admin/institutions            -> list (platform owner) */
/* POST   /api/v1/admin/institutions            -> create (platform owner) */
/* GET    /api/v1/admin/institutions/:id        -> get one */
/* POST   /api/v1/admin/institutions/:id/status -> set status */
void institution_handle(int client_fd, const char *method, const char *path,
                        const char *body, const char *auth_header,
                        const char *origin, char *extra_headers, size_t extra_len);

void kiosk_broadcast_os_update(const char *release_id, const char *channel, const char *security_profile);
int kiosk_get_active_count(void);

#endif /* EXAMOS_INSTITUTION_CONTROLLER_H */
