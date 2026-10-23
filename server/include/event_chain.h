#ifndef EXAMOS_EVENT_CHAIN_H
#define EXAMOS_EVENT_CHAIN_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The maximum length of an event-chain session identifier, including the
   terminating null. Every component that records session-scoped evidence
   uses this bound so that identifiers are stored in a uniform shape. */
#define EVENT_SESSION_ID_LEN 128

#define EVENT_CHAIN_GENESIS_HASH "0000000000000000000000000000000000000000000000000000000000000000"
#define MAX_EVENT_TYPE_LEN 64
#define MAX_SOURCE_TYPE_LEN 32
#define MAX_PAYLOAD_LEN 1024
#define MAX_MODEL_LEN 64
#define HASH_HEX_LEN 65
#define SIG_HEX_LEN 129

/* Normalized Proctoring Event Structure */
typedef struct {
    char     session_id[EVENT_SESSION_ID_LEN];
    uint64_t sequence;
    char     server_timestamp[32];   /* ISO 8601 UTC (e.g. 2026-10-08T22:30:00.000Z) */
    char     source_timestamp[32];   /* ISO 8601 UTC */
    char     source_type[MAX_SOURCE_TYPE_LEN]; /* PRIMARY_CAMERA, SECONDARY_ROOM_CAMERA, etc. */
    char     event_type[MAX_EVENT_TYPE_LEN];   /* FACE_PRESENT, MULTIPLE_FACES, NO_FACE, etc. */
    char     payload_json[MAX_PAYLOAD_LEN];   /* Structured detection payload */
    char     model_name[MAX_MODEL_LEN];
    char     model_version[MAX_MODEL_LEN];
    char     previous_hash[HASH_HEX_LEN];
    char     event_hash[HASH_HEX_LEN];
} proctoring_event_t;

/* Checkpoint Signature Record */
typedef struct {
    char     session_id[EVENT_SESSION_ID_LEN];
    uint64_t checkpoint_sequence;
    char     latest_event_hash[HASH_HEX_LEN];
    char     signing_key_id[64];
    char     signature_hex[SIG_HEX_LEN];
    char     server_timestamp[32];
} event_checkpoint_t;

/* --- Lifecycle & Operations --- */
int  event_chain_init(const char *storage_file_path);
void event_chain_close(void);

/* Format event into strict deterministic canonical JSON string */
int  event_chain_canonicalize(const proctoring_event_t *ev, char *out_canonical, size_t max_out);

/* Append event to session chain (enforces sequence continuity, computes SHA-256 hash) */
int  event_chain_append(const char *session_id, const char *source_type,
                        const char *event_type, const char *payload_json,
                        const char *model_name, const char *model_version,
                        proctoring_event_t *out_event);

/* Create cryptographic checkpoint signature for a session's current latest hash */
int  event_chain_sign_checkpoint(const char *session_id, event_checkpoint_t *out_checkpoint);

/* Verify the entire hash chain for a specific session */
int  event_chain_verify_session(const char *session_id, uint64_t *out_total_events,
                                uint64_t *out_corrupt_sequence, char *out_error_reason,
                                size_t max_reason_len);

/* Export events for a session in JSON array format */
int  event_chain_export_json(const char *session_id, char *out_buf, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_EVENT_CHAIN_H */
