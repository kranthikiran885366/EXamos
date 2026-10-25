#ifndef EXAMOS_AUDIT_H
#define EXAMOS_AUDIT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Append an audit entry to the hash chain.
 * Returns 0 on success, -1 on failure. */
int audit_append(const char *actor, const char *event, const char *detail);

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
