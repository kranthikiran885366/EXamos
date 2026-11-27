#ifndef EXAMOS_IMA_KEYLIME_H
#define EXAMOS_IMA_KEYLIME_H

#include <stddef.h>

#define EXAMOS_IMA_ASCII_PATH "/sys/kernel/security/ima/ascii_runtime_measurements"
#define EXAMOS_SHA256_HEX_LEN 64

typedef struct {
    size_t entry_count;
    char replayed_pcr10_hex[EXAMOS_SHA256_HEX_LEN + 1];
    int pcr10_valid;
} examos_ima_summary_t;

/**
 * Reads a Linux IMA ascii_runtime_measurements file, replays SHA-256 PCR 10
 * extensions across all PCR-10 entries, and outputs the summary.
 * Returns 0 on success, -1 on I/O or malformed log failure.
 */
int examos_ima_replay_pcr10(const char *ascii_path, examos_ima_summary_t *out);

#endif /* EXAMOS_IMA_KEYLIME_H */
