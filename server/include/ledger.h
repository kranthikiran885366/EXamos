#ifndef EXAMOS_LEDGER_H
#define EXAMOS_LEDGER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    long block_index;
    long timestamp;
    char event_type[32];
    char device_id[64];
    char details[256];
    char prev_hash[65];
    char block_hash[65];
} ledger_block_t;

int ledger_init(const char *ledger_file_path);
int ledger_append_event(const char *event_type, const char *device_id, const char *details, ledger_block_t *out_block);
int ledger_verify_integrity(void);
long ledger_get_block_count(void);

#ifdef __cplusplus
}
#endif

#endif // EXAMOS_LEDGER_H
