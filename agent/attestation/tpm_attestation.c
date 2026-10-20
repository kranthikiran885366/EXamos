#define _GNU_SOURCE
#include "../include/attestation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

static int g_tpm_detected = 0;

int tpm_attestation_init(void) {
    if (access("/dev/tpmrm0", F_OK) == 0 || access("/dev/tpm0", F_OK) == 0) {
        g_tpm_detected = 1;
    } else {
        g_tpm_detected = 0;
    }
    return g_tpm_detected ? 0 : -1;
}

static int compute_event_log_hash(char *out_hash) {
    const char *paths[] = {
        "/sys/kernel/security/tpm0/binary_bios_measurements",
        "/sys/kernel/security/tpm/binary_bios_measurements",
        NULL
    };

    FILE *f = NULL;
    for (int i = 0; paths[i] != NULL; i++) {
        f = fopen(paths[i], "rb");
        if (f) break;
    }

    if (!f) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    unsigned char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(f);
            return -1;
        }
    }
    if (ferror(f)) { EVP_MD_CTX_free(ctx); fclose(f); return -1; }
    fclose(f);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    int digest_ok = EVP_DigestFinal_ex(ctx, hash, &hash_len) == 1 && hash_len == SHA256_DIGEST_LENGTH;
    EVP_MD_CTX_free(ctx);
    if (!digest_ok) return -1;

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(out_hash + (i * 2), "%02x", hash[i]);
    }
    out_hash[64] = '\0';
    return 0;
}

int tpm_attestation_generate_report(const char *device_id, const char *release_id, const char *nonce, attestation_report_t *report) {
    if (!report || !device_id || !*device_id || !release_id || !*release_id || !nonce || !*nonce) return -1;
    if (!g_tpm_detected) return -1;
    memset(report, 0, sizeof(attestation_report_t));

    report->timestamp = (long)time(NULL);
    if (strlen(device_id) >= sizeof(report->device_id) || strlen(release_id) >= sizeof(report->release_id) || strlen(nonce) >= sizeof(report->nonce)) return -1;
    snprintf(report->device_id, sizeof(report->device_id), "%s", device_id);
    snprintf(report->release_id, sizeof(report->release_id), "%s", release_id);
    snprintf(report->nonce, sizeof(report->nonce), "%s", nonce);
    report->tpm_hardware_detected = g_tpm_detected;

    /* TPM key provisioning and quote verification are not implemented here.
     * Never synthesize identity material or claim this digest is a quote. */
    if (compute_event_log_hash(report->event_log_hash) != 0) return -1;
    return -1;
}

int tpm_attestation_format_json(const attestation_report_t *report, char *out_buf, size_t max_len) {
    if (!report || !out_buf || max_len == 0) return -1;

    char pcrs_json[2048] = {0};
    strcat(pcrs_json, "{");
    for (int i = 0; i < report->pcr_count; i++) {
        char item[128];
        snprintf(item, sizeof(item), "\"%d\":\"%s\"%s",
                 report->pcrs[i].pcr_index,
                 report->pcrs[i].pcr_value,
                 (i < report->pcr_count - 1) ? "," : "");
        strcat(pcrs_json, item);
    }
    strcat(pcrs_json, "}");

    snprintf(out_buf, max_len,
             "{"
             "\"timestamp\":%ld,"
             "\"device_id\":\"%s\","
             "\"release_id\":\"%s\","
             "\"nonce\":\"%s\","
             "\"tpm_hardware\":%s,"
             "\"ek_fingerprint\":\"%s\","
             "\"ak_pub\":\"%s\","
             "\"quote_signature\":\"%s\","
             "\"event_log_hash\":\"%s\","
             "\"pcrs\":%s,"
             "\"composite_digest\":\"%s\""
             "}",
             report->timestamp,
             report->device_id,
             report->release_id,
             report->nonce,
             report->tpm_hardware_detected ? "true" : "false",
             report->ek_fingerprint,
             report->ak_pub_hex,
             report->quote_signature_hex,
             report->event_log_hash,
             pcrs_json,
             report->composite_digest);

    return 0;
}
