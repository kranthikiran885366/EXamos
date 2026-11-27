#include "../include/ima_keylime.h"

#include <ctype.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_to_bytes32(const char *hex, unsigned char out[32]) {
    if (!hex || strlen(hex) < 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned int byte = 0;
        if (!isxdigit((unsigned char)hex[i * 2]) ||
            !isxdigit((unsigned char)hex[i * 2 + 1])) {
            return -1;
        }
        if (sscanf(&hex[i * 2], "%2x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

int examos_ima_replay_pcr10(const char *ascii_path, examos_ima_summary_t *out) {
    if (!ascii_path || !out) return -1;
    memset(out, 0, sizeof(*out));

    FILE *fp = fopen(ascii_path, "r");
    if (!fp) return -1;

    unsigned char pcr10[SHA256_DIGEST_LENGTH];
    memset(pcr10, 0, sizeof(pcr10));

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0') continue;

        unsigned long pcr_idx = 0;
        char template_hex[128] = {0};
        if (sscanf(p, "%lu %127s", &pcr_idx, template_hex) != 2) {
            fclose(fp);
            return -1;
        }
        unsigned char template_hash[32];
        if (hex_to_bytes32(template_hex, template_hash) != 0) {
            fclose(fp);
            return -1;
        }
        if (pcr_idx == 10) {
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, pcr10, sizeof(pcr10));
            SHA256_Update(&ctx, template_hash, sizeof(template_hash));
            SHA256_Final(pcr10, &ctx);
        }
        out->entry_count++;
    }
    fclose(fp);

    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out->replayed_pcr10_hex[i * 2] = hexchars[(pcr10[i] >> 4) & 0x0f];
        out->replayed_pcr10_hex[i * 2 + 1] = hexchars[pcr10[i] & 0x0f];
    }
    out->replayed_pcr10_hex[64] = '\0';
    out->pcr10_valid = 1;
    return 0;
}
