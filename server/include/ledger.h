#ifndef EXAMOS_LEDGER_H
#define EXAMOS_LEDGER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ExamOS tamper-evident ledger.
 *
 * Every block is authenticated with HMAC-SHA256 under a key that is supplied
 * out of band (EXAMOS_LEDGER_HMAC_KEY). A bare SHA-256 chain is not
 * tamper-evident: anyone able to rewrite the file can recompute every
 * downstream hash. The HMAC key is therefore mandatory, and the ledger
 * refuses to open without it.
 *
 * On-disk format (V2):
 *
 *   EXAMOS-LEDGER-V2 HMAC-SHA256            <- mandatory header line
 *   <idx>|<ts>|<type>|<device>|<details>|<prev_hash>|<hmac>   (repeated)
 *
 * <hmac> = HMAC-SHA256(mac_key, "<idx>:<ts>:<type>:<device>:<details>:<prev_hash>")
 *
 * A companion anchor file ("<ledger>.anchor") records the last block index
 * and hash that were durably committed. The anchor is what makes truncation
 * detectable: removing trailing blocks from the ledger no longer produces a
 * shorter but "valid" chain.
 */

typedef struct {
    long block_index;
    long timestamp;
    char event_type[32];
    char device_id[64];
    char details[256];
    char prev_hash[65];
    char block_hash[65];   /* HMAC-SHA256 hex of the block payload */
} ledger_block_t;

/*
 * Opens (or creates) the ledger at ledger_file_path.
 *
 * hmac_key must be a non-empty secret of at least 32 characters. Passing
 * NULL or an empty string fails closed: the ledger is never opened
 * unauthenticated.
 *
 * Returns 0 on success, -1 on any failure (missing key, unreadable file,
 * tampered chain, truncated chain, mismatched anchor).
 */
int ledger_init(const char *ledger_file_path, const char *hmac_key);

/* Appends an authenticated block. Returns 0 on success, -1 on failure. */
int ledger_append_event(const char *event_type, const char *device_id,
                        const char *details, ledger_block_t *out_block);

/*
 * Re-verifies every block and the truncation anchor.
 * Returns 1 when the ledger is intact, 0 when it is not.
 */
int ledger_verify_integrity(void);

/* Number of blocks currently committed to the ledger. */
long ledger_get_block_count(void);

/* Hex hash of the most recent block, or the genesis hash when empty. */
int ledger_get_last_hash(char *out_hex, size_t max_len);

/*
 * True when the ledger is open with a usable authentication key.
 * Always false before a successful ledger_init().
 */
int ledger_is_authenticated(void);

#ifdef __cplusplus
}
#endif

#endif // EXAMOS_LEDGER_H
