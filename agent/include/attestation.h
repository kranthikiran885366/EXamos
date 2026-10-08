#ifndef EXAMOS_ATTESTATION_H
#define EXAMOS_ATTESTATION_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int pcr_index;
    char pcr_value[65]; // 64 hex chars + null terminator for SHA256
} pcr_entry_t;

typedef struct {
    long timestamp;
    char nonce[128];
    int tpm_hardware_detected;
    pcr_entry_t pcrs[16];
    int pcr_count;
    char composite_digest[65];
} attestation_report_t;

int tpm_attestation_init(void);
int tpm_attestation_generate_report(const char *nonce, attestation_report_t *report);
int tpm_attestation_format_json(const attestation_report_t *report, char *out_buf, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif // EXAMOS_ATTESTATION_H
