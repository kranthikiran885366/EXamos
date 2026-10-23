#ifndef EXAMOS_CANDIDATE_LOGIN_H
#define EXAMOS_CANDIDATE_LOGIN_H

#include <stddef.h>
#include <time.h>

#define SESSION_TOKEN_LEN 64   /* 32 random bytes = 64 hex chars */
#define MAX_CANDIDATE_ID_LEN 64
#define MAX_SESSIONS 256

typedef struct {
    char token[SESSION_TOKEN_LEN + 1];
    char candidate_id[MAX_CANDIDATE_ID_LEN];
    time_t created_at;
    int   active;
} candidate_session_t;

/* Initialize session store. */
void candidate_session_init(void);

/* Create a new session for the given candidate_id. Writes token into out_token (SESSION_TOKEN_LEN+1 bytes). Returns 0 on success. */
int candidate_session_create(const char *candidate_id, char *out_token);

/* Validate candidate credentials against the PBKDF2 credential store. */
int candidate_credentials_validate(const char *candidate_id, const char *pin);

/* Validate a session token. Returns 1 if valid and active, 0 if not. */
int candidate_session_validate(const char *token);

/* Resolve a valid token to its candidate ID. */
int candidate_session_identity(const char *token, char *out_candidate_id, size_t max_len);

/* Invalidate (logout) a session token. */
void candidate_session_invalidate(const char *token);

/* Restore a session from the durable journal (called during replay). */
int candidate_session_restore(const char *token, const char *candidate_id, time_t created_at);

/* Returns the HTML for the candidate login page (static string). */
const char *candidate_login_html(void);

#endif
