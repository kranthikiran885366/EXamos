#define _GNU_SOURCE
#include "../include/config_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>

int config_load(exam_config_t *cfg) {
    if (!cfg) return -1;
    memset(cfg, 0, sizeof(exam_config_t));
    cfg->exam_duration_minutes = 120;

    FILE *f = fopen(EXAM_CONF_PATH, "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\r');
        if (nl) *nl = '\0';
        nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strncmp(line, "EXAM_URL=", 9) == 0) {
            char *v = line + 9;
            while (*v == ' ' || *v == '\t') v++;
            strncpy(cfg->exam_url, v, sizeof(cfg->exam_url) - 1);
        } else if (strncmp(line, "EXAM_NAME=", 10) == 0) {
            char *v = line + 10;
            while (*v == ' ' || *v == '\t') v++;
            strncpy(cfg->exam_name, v, sizeof(cfg->exam_name) - 1);
        } else if (strncmp(line, "EXAM_DURATION_MINUTES=", 22) == 0) {
            char *v = line + 22;
            cfg->exam_duration_minutes = atoi(v);
        }
    }
    fclose(f);

    if (strlen(cfg->exam_url) > 0 && strcmp(cfg->exam_url, "NOT_CONFIGURED") != 0) {
        if (strncmp(cfg->exam_url, "http://", 7) == 0 || strncmp(cfg->exam_url, "https://", 8) == 0) {
            cfg->configured = 1;
        }
    }
    return 0;
}

int config_save(const exam_config_t *cfg) {
    if (!cfg) return -1;

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", EXAM_CONF_PATH, getpid());

    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;

    fprintf(f, "# ExamOS Examination Configuration\n");
    fprintf(f, "# Managed automatically by ExamOS Admin Dashboard\n");
    fprintf(f, "EXAM_URL=%s\n", cfg->exam_url[0] ? cfg->exam_url : "NOT_CONFIGURED");
    fprintf(f, "EXAM_NAME=%s\n", cfg->exam_name[0] ? cfg->exam_name : "ExamOS Secure Exam");
    fprintf(f, "EXAM_DURATION_MINUTES=%d\n", cfg->exam_duration_minutes > 0 ? cfg->exam_duration_minutes : 120);

    if (fflush(f) != 0 || fsync(fileno(f)) != 0 || fclose(f) != 0) {
        unlink(tmp_path);
        return -1;
    }

    chmod(tmp_path, 0644);
    if (rename(tmp_path, EXAM_CONF_PATH) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

int config_load_admin_hash(char *out_hash, size_t max_len) {
    if (!out_hash || max_len < ADMIN_HASH_LEN) return -1;
    out_hash[0] = '\0';

    FILE *f = fopen(ADMIN_CONF_PATH, "r");
    if (!f) {
        /* Default fallback hash for ExamOS@Admin2025! if file not present:
           echo -n 'ExamOS@Admin2025!' | sha256sum */
        strncpy(out_hash, "c06497f5f9038234604db03ea13ba8100ff68652c7fe352467d1d28343729ee9", max_len - 1);
        out_hash[max_len - 1] = '\0';
        return 0;
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "ADMIN_PASSWORD_SHA256=", 22) == 0) {
            char *v = line + 22;
            char *nl = strchr(v, '\r');
            if (nl) *nl = '\0';
            nl = strchr(v, '\n');
            if (nl) *nl = '\0';
            while (*v == ' ' || *v == '\t') v++;

            if (strlen(v) == 64 && strcmp(v, "REPLACE_AT_BUILD_TIME") != 0) {
                strncpy(out_hash, v, max_len - 1);
                out_hash[max_len - 1] = '\0';
                found = 1;
                break;
            }
        }
    }
    fclose(f);

    if (!found) {
        /* Default fallback hash for ExamOS@Admin2025! */
        strncpy(out_hash, "c06497f5f9038234604db03ea13ba8100ff68652c7fe352467d1d28343729ee9", max_len - 1);
        out_hash[max_len - 1] = '\0';
    }
    return 0;
}

int config_verify_admin_password(const char *plaintext_password) {
    if (!plaintext_password || strlen(plaintext_password) == 0) return 0;

    char stored_hash[ADMIN_HASH_LEN];
    if (config_load_admin_hash(stored_hash, sizeof(stored_hash)) != 0) {
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    unsigned char md_val[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
             EVP_DigestUpdate(ctx, plaintext_password, strlen(plaintext_password)) &&
             EVP_DigestFinal_ex(ctx, md_val, &md_len);
    EVP_MD_CTX_free(ctx);

    if (!ok || md_len != 32) return 0;

    char hex[65];
    for (unsigned int i = 0; i < md_len; i++) {
        sprintf(hex + (i * 2), "%02x", md_val[i]);
    }
    hex[64] = '\0';

    /* Constant-time memory compare */
    return (CRYPTO_memcmp(hex, stored_hash, 64) == 0) ? 1 : 0;
}
