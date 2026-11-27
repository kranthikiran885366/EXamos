#ifndef EXAMOS_OFFLINE_BUFFER_H
#define EXAMOS_OFFLINE_BUFFER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Encrypted, HMAC-signed offline-first event WAL buffer.
 * Queues proctoring, ledger, and health events locally when lab Wi-Fi drops
 * mid-exam, then flushes them in FIFO order once connectivity returns.
 */

int offline_buffer_init(const char *wal_path, const unsigned char key32[32]);

int offline_buffer_enqueue(const char *event_type, const char *payload_json);

typedef int (*offline_buffer_flush_cb)(const char *event_type,
                                       const char *payload_json,
                                       void *user_ctx);

/*
 * Decrypts and verifies each queued record in FIFO order, invoking `cb`.
 * Records for which `cb` returns 0 are removed from the WAL; on the first
 * non-zero return (e.g. network drop), flushing stops cleanly and remaining
 * records stay encrypted on disk.
 * Returns the number of flushed records, or -1 on fatal error.
 */
int offline_buffer_flush(offline_buffer_flush_cb cb, void *user_ctx);

size_t offline_buffer_pending_count(void);
void offline_buffer_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_OFFLINE_BUFFER_H */
