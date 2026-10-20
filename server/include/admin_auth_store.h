#ifndef EXAMOS_ADMIN_AUTH_STORE_H
#define EXAMOS_ADMIN_AUTH_STORE_H

#include "enterprise_platform.h"
#include "totp.h"
#include <stdint.h>

#include <libpq-fe.h>

#define AUTH_LOGIN_SUCCESS       0
#define AUTH_LOGIN_FAILED        -1
#define AUTH_LOGIN_MFA_REQUIRED   2

/* Granular RBAC Permission Flags */
#define AUTH_PERM_READ            (1U << 0)
#define AUTH_PERM_EXAM_MUTATION   (1U << 1)
#define AUTH_PERM_FLEET_MUTATION  (1U << 2)
#define AUTH_PERM_SECURITY_ADMIN  (1U << 3)
#define AUTH_PERM_USER_MANAGEMENT (1U << 4)

#define MAX_POOL_CONNECTIONS 8

int admin_auth_store_init(void);
void admin_auth_store_shutdown(void);

/* Database Connection Pool access */
PGconn *acquire_db_connection(void);
void release_db_connection(PGconn *conn, int broken);

/* Multi-step or single-step login. If mfa_code is NULL and user has MFA, returns AUTH_LOGIN_MFA_REQUIRED */
int admin_auth_store_login(const char *username, const char *password,
                           const char *mfa_code, auth_session_t *out_session);

/* Verify active session token */
int admin_auth_store_verify(const char *token, auth_session_t *out_session);

/* Authorize session token with granular RBAC permissions */
int admin_auth_store_authorize(const char *token, uint32_t required_perm,
                               auth_session_t *out_session);

/* Check if a given role possesses a required permission flag */
int admin_role_has_permission(user_role_t role, uint32_t permission);
const char *admin_role_to_string(user_role_t role);

/* Revoke active session (logout) */
int admin_auth_store_revoke(const char *token);

/* User provisioning */
int admin_auth_store_create_initial_owner(const user_account_t *user);
int admin_auth_store_create_user(const user_account_t *user, const char *actor_user_id);
int admin_auth_store_list_users_json(char *out_buf, size_t max_len);

/* MFA Enrollment & Confirmation */
int admin_auth_store_mfa_enroll(const char *username, char out_secret[TOTP_BASE32_LEN + 1],
                                char *out_uri, size_t uri_len,
                                char out_recovery_codes[TOTP_NUM_RECOVERY_CODES][TOTP_RECOVERY_CODE_LEN + 1]);
int admin_auth_store_mfa_confirm(const char *username, const char *code);

/* Password Reset */
int admin_auth_store_password_reset_request(const char *username, char out_token[65]);
int admin_auth_store_password_reset_complete(const char *username, const char *reset_token,
                                             const char *new_password);

#endif
