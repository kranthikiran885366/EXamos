/*
 * session_store.h — ExamOS Durable Session Persistence (C8 fix)
 *
 * Provides a write-ahead journal for candidate sessions so that a server
 * restart does not lose active exam sessions, attestation state, or
 * revocations registered only in memory.
 *
 * Design
 * ──────
 * Every session state change (create, invalidate, expire) is appended to a
 * journal file as a JSON record with an HMAC-SHA256 signature.  On startup
 * the journal is replayed to restore in-process state.
 *
 * The journal is NOT a substitute for a transactional database — it is a
 * crash-safe write-ahead log that survives clean restarts and covers the gap
 * before a full database backend is introduced.  It does NOT handle:
 *   • Multi-node coordination
 *   • Concurrent writers
 *   • Log compaction (journal grows unboundedly — rotate with logrotate)
 *
 * Journal file path: EXAMOS_SESSION_JOURNAL env var, or
 *                   /var/log/examos/session_journal.log
 * HMAC key:         EXAMOS_LEDGER_HMAC_KEY (shared with ledger — same TPM key)
 *
 * C8 status: this provides durable single-node session survival across
 * restarts. Multi-node HA and a full transactional database are out of scope
 * for this fix but are documented as the next step.
 */
#ifndef EXAMOS_SESSION_STORE_H
#define EXAMOS_SESSION_STORE_H

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SESSION_EVENT_CREATE     = 1,
    SESSION_EVENT_INVALIDATE = 2,
    SESSION_EVENT_EXPIRE     = 3
} session_event_type_t;

typedef struct {
    session_event_type_t event_type;
    char token[65];
    char candidate_id[64];
    time_t created_at;
    time_t expires_at;     /* created_at + 28800 (8 hours) */
} session_journal_record_t;

/*
 * session_store_init — open the journal file, replay existing records to
 * restore in-process session state. Call candidate_session_init() first;
 * it clears the in-memory table populated by journal replay.
 *
 * Returns 0 on success, -1 on I/O or integrity failure.
 */
int session_store_init(void);

/*
 * session_store_record — append a session event to the journal.
 * Thread-safe; fsync before returning.
 * Returns 0 on success, -1 on failure.
 */
int session_store_record(const session_journal_record_t *rec);

/*
 * session_store_close — flush and close the journal file cleanly.
 */
void session_store_close(void);

/*
 * session_store_replay — called by session_store_init to replay the journal
 * and rebuild the in-memory session table.  Can also be called explicitly
 * to detect gaps.  Returns number of sessions restored, -1 on error.
 */
int session_store_replay(void);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_SESSION_STORE_H */
