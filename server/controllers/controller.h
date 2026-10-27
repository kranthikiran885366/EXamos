#ifndef EXAMOS_CONTROLLER_H
#define EXAMOS_CONTROLLER_H

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "../security/security.h"
#include "../db/db.h"

/* Send a JSON response with optional extra headers. */
void ctrl_send_json(int client_fd, int status_code, const char *body,
                    const char *extra_headers);

/* Send an error JSON response. */
void ctrl_send_error(int client_fd, int status_code, const char *error);

/* Extract Bearer token from Authorization header. Returns 1 if found. */
int ctrl_extract_bearer(const char *auth_header, char *out, size_t out_len);

/* Extract JSON string field from request body. */
int ctrl_json_string(const char *body, const char *key, char *out, size_t out_len);

/* Extract JSON int field from request body. Returns 0 if missing. */
int ctrl_json_int(const char *body, const char *key, int *out);

/* Extract JSON bool field from request body. Returns 0 if missing. */
int ctrl_json_bool(const char *body, const char *key, int *out);

/* Extract Origin header from request. */
int ctrl_extract_origin(const char *buffer, char *out, size_t out_len);

/* Authorize a Bearer token with required permission. Fills session. */
int ctrl_authorize(const char *auth_header, uint32_t required_perm,
                   auth_session_t *out);

/* Set CORS headers on the response for the given origin. */
void ctrl_set_cors(char *extra_headers, size_t extra_len,
                   const char *origin, int cors_ok);

/* Check that the origin is allowed (CORS). Returns 1 if allowed. */
int ctrl_cors_origin_allowed(const char *origin);

#endif /* EXAMOS_CONTROLLER_H */
