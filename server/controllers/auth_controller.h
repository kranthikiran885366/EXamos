#ifndef EXAMOS_AUTH_CONTROLLER_H
#define EXAMOS_AUTH_CONTROLLER_H

#include "../controllers/controller.h"

/* POST /api/v1/admin/login */
void auth_admin_login(int client_fd, const char *body,
                      const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/admin/logout */
void auth_admin_logout(int client_fd, const char *auth_header,
                       const char *origin, char *extra_headers, size_t extra_len);

/* GET /api/v1/admin/session */
void auth_admin_session(int client_fd, const char *auth_header,
                        const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/candidate/login */
void auth_candidate_login(int client_fd, const char *body,
                          const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/admin/mfa/setup */
void auth_mfa_setup(int client_fd, const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/admin/mfa/confirm */
void auth_mfa_confirm(int client_fd, const char *body, const char *auth_header,
                      const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/admin/recovery/reset */
void auth_recovery_reset(int client_fd, const char *body,
                         const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_AUTH_CONTROLLER_H */
