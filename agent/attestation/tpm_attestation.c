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

static int g_tpm_detected = 0;

int tpm_attestation_init(void) {
    if (access("/dev/tpmrm0", F_OK) == 0 || access("/dev/tpm0", F_OK) == 0) {
        g_tpm_detected = 1;
    } else {
        g_tpm_detected = 0;
    }
    return g_tpm_detected ? 0 : -1;
}

int tpm_attestation_generate_report(const char *nonce, attestation_report_t *report) {
    if (!report || !nonce || !*nonce || !g_tpm_detected) return -1;
    memset(report, 0, sizeof(attestation_report_t));

    report->timestamp = (long)time(NULL);
    if (snprintf(report->nonce, sizeof(report->nonce), "%s", nonce) >= (int)sizeof(report->nonce)) return -1;
    report->tpm_hardware_detected = g_tpm_detected;

    FILE *fp = popen("tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9,14 2>/dev/null", "r");
    if (!fp) return -1;

    char line[256];
    int seen[16] = {0};
    while (fgets(line, sizeof(line), fp)) {
        int idx = -1;
        char value[65] = {0};
        int parsed = sscanf(line, " %d : 0x%64[0-9a-fA-F]", &idx, value);
        if (parsed != 2) continue;
        if (idx < 0 || idx >= 16 || strlen(value) != 64 || seen[idx] || report->pcr_count >= 16) {
            pclose(fp);
            return -1;
        }
        seen[idx] = 1;
        report->pcrs[report->pcr_count].pcr_index = idx;
        memcpy(report->pcrs[report->pcr_count].pcr_value, value, sizeof(value));
        report->pcr_count++;
    }

    int command_status = pclose(fp);
    if (!WIFEXITED(command_status) || WEXITSTATUS(command_status) != 0 ||
        report->pcr_count != 11) {
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    int digest_ok = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1 &&
                    EVP_DigestUpdate(mdctx, report->nonce, strlen(report->nonce)) == 1 &&
                    EVP_DigestUpdate(mdctx, &report->timestamp, sizeof(report->timestamp)) == 1;
    for (int i = 0; digest_ok && i < report->pcr_count; i++) {
        digest_ok = EVP_DigestUpdate(mdctx, report->pcrs[i].pcr_value, 64) == 1;
    }
    digest_ok = digest_ok && EVP_DigestFinal_ex(mdctx, md_value, &md_len) == 1 && md_len == 32;
    EVP_MD_CTX_free(mdctx);
    if (!digest_ok) return -1;

    for (unsigned int i = 0; i < md_len; i++) {
        snprintf(report->composite_digest + i * 2, 3, "%02x", md_value[i]);
    }
    report->composite_digest[64] = '\0';

    return 0;
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
             "\"nonce\":\"%s\","
             "\"tpm_hardware\":%s,"
             "\"pcrs\":%s,"
             "\"composite_digest\":\"%s\""
             "}",
             report->timestamp,
             report->nonce,
             report->tpm_hardware_detected ? "true" : "false",
             pcrs_json,
             report->composite_digest);

    return 0;
}
