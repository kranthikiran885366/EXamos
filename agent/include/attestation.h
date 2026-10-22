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
    char device_id[64];
    char release_id[64];
    char nonce[128];
    int  tpm_hardware_detected;
    char ek_fingerprint[65];
    char ak_pub_hex[512];
    char quote_message_hex[8193];
    char quote_signature_hex[2049];
    char event_log_hash[65];
    pcr_entry_t pcrs[16];
    int  pcr_count;
    char composite_digest[65];
} attestation_report_t;

int tpm_attestation_init(void);
/* Generates a real TPM 2.0 Quote with the provisioned persistent AK. */
int tpm_attestation_generate_report(const char *device_id, const char *release_id, const char *nonce, attestation_report_t *report);
int tpm_attestation_format_json(const attestation_report_t *report, char *out_buf, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif // EXAMOS_ATTESTATION_H
