#define _GNU_SOURCE
#include "../include/ledger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

static pthread_mutex_t g_ledger_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_ledger_file[256] = "/tmp/examos_event_ledger.log";
static char g_latest_hash[65] = "0000000000000000000000000000000000000000000000000000000000000000";
static long g_block_count = 0;

static void compute_sha256(const char *input, char *hex_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_out + (i * 2), "%02x", hash[i]);
    }
    hex_out[64] = '\0';
}

int ledger_init(const char *ledger_file_path) {
    if (ledger_file_path && strlen(ledger_file_path) >= sizeof(g_ledger_file)) {
        return -1;
    }
    pthread_mutex_lock(&g_ledger_lock);
    if (ledger_file_path && strlen(ledger_file_path) > 0) {
        strncpy(g_ledger_file, ledger_file_path, sizeof(g_ledger_file) - 1);
        g_ledger_file[sizeof(g_ledger_file) - 1] = '\0';
    }
    g_block_count = 0;
    strcpy(g_latest_hash, "0000000000000000000000000000000000000000000000000000000000000000");

    FILE *f = fopen(g_ledger_file, "r");
    if (!f && errno != ENOENT) {
        pthread_mutex_unlock(&g_ledger_lock);
        return -1;
    }
    if (f) {
        char line[1024];
        char expected_prev[65] = "0000000000000000000000000000000000000000000000000000000000000000";
        long verified_count = 0;
        int valid = 1;

        while (fgets(line, sizeof(line), f)) {
            size_t line_len = strlen(line);
            if (line_len == 0 || line[line_len - 1] != '\n') {
                valid = 0;
                break;
            }

            long idx = 0, ts = 0;
            char type[32] = {0}, dev[64] = {0}, details[256] = {0};
            char prev[65] = {0}, hash[65] = {0}, trailing = '\0';
            if (sscanf(line, "%ld|%ld|%31[^|]|%63[^|]|%255[^|]|%64[^|]|%64s%c",
                       &idx, &ts, type, dev, details, prev, hash, &trailing) != 8 ||
                trailing != '\n' ||
                idx != verified_count + 1 || ts <= 0 ||
                strlen(prev) != 64 || strlen(hash) != 64 ||
                strcmp(prev, expected_prev) != 0) {
                valid = 0;
                break;
            }

            char payload[1024], computed[65];
            snprintf(payload, sizeof(payload), "%ld:%ld:%s:%s:%s:%s",
                     idx, ts, type, dev, details, prev);
            compute_sha256(payload, computed);
            if (strcmp(computed, hash) != 0) {
                valid = 0;
                break;
            }
            memcpy(expected_prev, hash, sizeof(expected_prev));
            verified_count = idx;
        }

        if (ferror(f)) valid = 0;
        if (fclose(f) != 0) valid = 0;
        if (!valid) {
            pthread_mutex_unlock(&g_ledger_lock);
            return -1;
        }
        g_block_count = verified_count;
        memcpy(g_latest_hash, expected_prev, sizeof(g_latest_hash));
    }
    pthread_mutex_unlock(&g_ledger_lock);
    return 0;
}

int ledger_append_event(const char *event_type, const char *device_id, const char *details, ledger_block_t *out_block) {
    pthread_mutex_lock(&g_ledger_lock);

    ledger_block_t block;
    memset(&block, 0, sizeof(block));
    block.block_index = g_block_count + 1;
    block.timestamp = (long)time(NULL);
    strncpy(block.event_type, event_type ? event_type : "GENERIC", sizeof(block.event_type) - 1);
    strncpy(block.device_id, device_id ? device_id : "UNKNOWN_DEV", sizeof(block.device_id) - 1);
    strncpy(block.details, details ? details : "", sizeof(block.details) - 1);
    memcpy(block.prev_hash, g_latest_hash, 64);
    block.prev_hash[64] = '\0';

    // Compute block hash: SHA256(index + timestamp + type + dev + details + prev_hash)
    char payload_to_hash[1024];
    snprintf(payload_to_hash, sizeof(payload_to_hash), "%ld:%ld:%s:%s:%s:%s",
             block.block_index, block.timestamp, block.event_type, block.device_id, block.details, block.prev_hash);

    compute_sha256(payload_to_hash, block.block_hash);

    FILE *f = fopen(g_ledger_file, "a");
    if (!f) {
        pthread_mutex_unlock(&g_ledger_lock);
        return -1;
    }

    int write_failed = fprintf(f, "%ld|%ld|%s|%s|%s|%s|%s\n",
                               block.block_index, block.timestamp, block.event_type,
                               block.device_id, block.details, block.prev_hash, block.block_hash) < 0;
    if (!write_failed && fflush(f) != 0) write_failed = 1;
    if (!write_failed && fsync(fileno(f)) != 0) write_failed = 1;
    if (fclose(f) != 0) write_failed = 1;
    if (write_failed) {
        pthread_mutex_unlock(&g_ledger_lock);
        return -1;
    }

    memcpy(g_latest_hash, block.block_hash, 65);
    g_block_count++;

    if (out_block) {
        *out_block = block;
    }

    pthread_mutex_unlock(&g_ledger_lock);
    return 0;
}

int ledger_verify_integrity(void) {
    pthread_mutex_lock(&g_ledger_lock);
    FILE *f = fopen(g_ledger_file, "r");
    if (!f) {
        int empty = errno == ENOENT && g_block_count == 0;
        pthread_mutex_unlock(&g_ledger_lock);
        return empty;
    }

    char line[1024];
    char expected_prev[65] = "0000000000000000000000000000000000000000000000000000000000000000";
    int valid = 1;
    long verified_count = 0;

    while (fgets(line, sizeof(line), f)) {
        long idx = 0, ts = 0;
        char type[32] = {0}, dev[64] = {0}, details[256] = {0}, prev[65] = {0}, hash[65] = {0};

        if (sscanf(line, "%ld|%ld|%31[^|]|%63[^|]|%255[^|]|%64[^|]|%64s",
                   &idx, &ts, type, dev, details, prev, hash) != 7 ||
            idx != verified_count + 1 || strcmp(prev, expected_prev) != 0) {
            valid = 0;
            break;
        }
        char payload[1024];
        snprintf(payload, sizeof(payload), "%ld:%ld:%s:%s:%s:%s", idx, ts, type, dev, details, prev);
        char computed[65];
        compute_sha256(payload, computed);
        if (strcmp(computed, hash) != 0) {
            valid = 0;
            break;
        }
        strcpy(expected_prev, hash);
        verified_count = idx;
    }

    if (ferror(f)) valid = 0;
    if (verified_count != g_block_count) valid = 0;
    fclose(f);
    pthread_mutex_unlock(&g_ledger_lock);
    return valid;
}

long ledger_get_block_count(void) {
    pthread_mutex_lock(&g_ledger_lock);
    long count = g_block_count;
    pthread_mutex_unlock(&g_ledger_lock);
    return count;
}
