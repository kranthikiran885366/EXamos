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

/* POST /api/v1/candidate/logout */
void auth_candidate_logout(int client_fd, const char *auth_header,
                           const char *origin, char *extra_headers, size_t extra_len);

/* Candidate exam-token issuance and invigilator check-in workflow routes. */
void auth_candidate_workflow_handle(int client_fd, const char *method, const char *path,
                                    const char *body, const char *auth_header,
                                    const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/admin/mfa/setup */
void auth_mfa_setup(int client_fd, const char *body, const char *auth_header,
                    const char *enrollment_token,
                    const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/admin/mfa/confirm */
void auth_mfa_confirm(int client_fd, const char *body, const char *auth_header,
                      const char *enrollment_token,
                      const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/admin/recovery/reset */
void auth_recovery_reset(int client_fd, const char *body,
                         const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/admin/password/change */
void auth_change_password(int client_fd, const char *body, const char *auth_header,
                          const char *origin, char *extra_headers, size_t extra_len);

/* GET /api/v1/admin/sessions */
void auth_admin_sessions_list(int client_fd, const char *auth_header,
                              const char *origin, char *extra_headers, size_t extra_len);

/* DELETE /api/v1/admin/sessions/:id */
void auth_admin_session_revoke(int client_fd, const char *sid, const char *auth_header,
                               const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/admin/sessions/others */
void auth_admin_sessions_revoke_others(int client_fd, const char *auth_header,
                                      const char *origin, char *extra_headers, size_t extra_len);

/* POST /api/v1/admin/recovery/regenerate */
void auth_recovery_regenerate(int client_fd, const char *auth_header,
                              const char *origin, char *extra_headers, size_t extra_len);

/* PATCH or PUT /api/v1/admin/profile */
void auth_update_profile(int client_fd, const char *body, const char *auth_header,
                         const char *origin, char *extra_headers, size_t extra_len);

/* Dispatcher for /api/v1/admin/users/:sub */
void auth_admin_user_dispatch(int client_fd, const char *method, const char *sub_path,
                              const char *body, const char *auth_header,
                              const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_AUTH_CONTROLLER_H */
