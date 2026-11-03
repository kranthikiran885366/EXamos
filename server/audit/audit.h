#ifndef EXAMOS_AUDIT_H
#define EXAMOS_AUDIT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Append an audit entry to the hash chain.
 * Returns 0 on success, -1 on failure. */
int audit_append(const char *actor, const char *event, const char *detail);

/* Append every entry in a {"events":[{actor,event,detail},...]} payload to
 * the durable hash chain. When actor_override is non-empty it is used for
 * every entry instead of the client-supplied actor, preventing spoofing.
 * Returns 0 only when every entry was persisted; -1 otherwise. The number of
 * entries actually appended is written to out_appended, and a human-readable
 * failure reason to out_error. */
int audit_append_batch_json(const char *body, const char *actor_override,
                            int *out_appended, char *out_error,
                            size_t error_len);

/* Verify the integrity of the entire chain.
 * Returns 1 if valid, 0 if tampered. */
int audit_verify(void);

/* Get total block count. */
long audit_block_count(void);

/* Initialize: load existing chain from DB, ensure seq counter. */
int audit_init(void);

/* Shutdown. */
void audit_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_AUDIT_H */
