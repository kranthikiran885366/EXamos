#define _GNU_SOURCE
#include "../include/ledger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define LEDGER_FORMAT_HEADER "EXAMOS-LEDGER-V2 HMAC-SHA256"
#define LEDGER_PATH_MAX       256
#define LEDGER_LINE_MAX       1024
#define LEDGER_MAC_KEY_LEN    32
#define LEDGER_MIN_SECRET_LEN 32
#define LEDGER_GENESIS_HASH \
    "0000000000000000000000000000000000000000000000000000000000000000"

static pthread_mutex_t g_ledger_lock = PTHREAD_MUTEX_INITIALIZER;
static char     g_ledger_file[LEDGER_PATH_MAX] = "/var/lib/examos/ledger.log";
static char     g_anchor_file[LEDGER_PATH_MAX + 16];
static unsigned char g_mac_key[LEDGER_MAC_KEY_LEN];
static int      g_key_loaded = 0;
static char     g_latest_hash[65] = LEDGER_GENESIS_HASH;
static long     g_block_count = 0;

/* -------------------------------------------------------------------------
 * Key handling
 * ------------------------------------------------------------------------- */

/*
 * Derives the block-authentication key from the operator-supplied secret.
 * The secret itself is never used directly as a MAC key: it is run through
 * HMAC with a fixed domain-separation label so that the same secret cannot
 * be reused across subsystems by accident.
 */
static int derive_mac_key(const char *secret) {
    if (!secret || !secret[0]) return -1;
    size_t secret_len = strlen(secret);
    if (secret_len < LEDGER_MIN_SECRET_LEN) return -1;

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    if (!HMAC(EVP_sha256(), secret, (int)secret_len,
              (const unsigned char *)"examos-ledger-v2-mac", 19,
              mac, &mac_len)) {
        return -1;
    }
    if (mac_len != sizeof(g_mac_key)) return -1;
    memcpy(g_mac_key, mac, sizeof(g_mac_key));
    OPENSSL_cleanse(mac, sizeof(mac));
    g_key_loaded = 1;
    return 0;
}

/* -------------------------------------------------------------------------
 * Hashing helpers
 * ------------------------------------------------------------------------- */

static void compute_block_mac(const char *payload, char *hex_out) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    if (!HMAC(EVP_sha256(), g_mac_key, sizeof(g_mac_key),
              (const unsigned char *)payload, strlen(payload),
              mac, &mac_len)) {
        /* HMAC over a fixed key cannot fail in practice; fail closed. */
        memset(mac, 0, sizeof(mac));
        mac_len = 0;
    }
    for (unsigned int i = 0; i < mac_len && i < 32; i++) {
        sprintf(hex_out + (i * 2), "%02x", mac[i]);
    }
    hex_out[64] = '\0';
    OPENSSL_cleanse(mac, sizeof(mac));
}

/*
 * Fields are pipe-delimited and one record per line. Untrusted content
 * (candidate identifiers, device identifiers, error text) must never be
 * able to inject a delimiter or a line break, otherwise the on-disk record
 * boundary can be forged.
 */
static void sanitize_field(char *s) {
    if (!s) return;
    for (; *s; s++) {
        if (*s == '|')      *s = '/';
        else if (*s == '\n') *s = ' ';
        else if (*s == '\r') *s = ' ';
        else if ((unsigned char)*s < 0x20) *s = ' ';
    }
}

/* -------------------------------------------------------------------------
 * Truncation anchor
 * ------------------------------------------------------------------------- */

static int anchor_path_for(const char *ledger_path) {
    size_t len = strlen(ledger_path);
    if (len + 7 >= sizeof(g_anchor_file)) return -1;
    snprintf(g_anchor_file, sizeof(g_anchor_file), "%s.anchor", ledger_path);
    return 0;
}

static int write_anchor_locked(long count, const char *last_hash) {
    char payload[256];
    char mac_hex[65];
    snprintf(payload, sizeof(payload), "%ld:%s", count, last_hash);
    compute_block_mac(payload, mac_hex);

    int fd = open(g_anchor_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    char line[400];
    int written = snprintf(line, sizeof(line), "%ld|%s|%s\n", count, last_hash, mac_hex);
    ssize_t n = written > 0 ? write(fd, line, (size_t)written) : -1;
    if (n != written || fsync(fd) != 0) { close(fd); return -1; }
    if (close(fd) != 0) return -1;
    return 0;
}

static int read_anchor(long *out_count, char out_hash[65]) {
    FILE *f = fopen(g_anchor_file, "r");
    if (!f) return -1;
    char line[400];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);

    long count = 0;
    char hash[65] = {0}, mac_hex[65] = {0};
    if (sscanf(line, "%ld|%64[^|]|%64s", &count, hash, mac_hex) != 3) return -1;
    if (count < 0 || strlen(hash) != 64) return -1;

    char payload[256];
    snprintf(payload, sizeof(payload), "%ld:%s", count, hash);
    char expected[65];
    compute_block_mac(payload, expected);
    if (strcmp(expected, mac_hex) != 0) return -1;

    *out_count = count;
    memcpy(out_hash, hash, 64);
    out_hash[64] = '\0';
    return 0;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

int ledger_is_authenticated(void) {
    pthread_mutex_lock(&g_ledger_lock);
    int ok = g_key_loaded;
    pthread_mutex_unlock(&g_ledger_lock);
    return ok;
}

int ledger_init(const char *ledger_file_path, const char *hmac_key) {
    if (!ledger_file_path || !ledger_file_path[0]) return -1;
    if (strlen(ledger_file_path) >= LEDGER_PATH_MAX) return -1;

    pthread_mutex_lock(&g_ledger_lock);

    memset(g_mac_key, 0, sizeof(g_mac_key));
    g_key_loaded = 0;
    if (derive_mac_key(hmac_key) != 0) {
        fprintf(stderr,
                "[ExamOS-Ledger] FATAL: ledger authentication key is missing or shorter than %d characters.\n",
                LEDGER_MIN_SECRET_LEN);
        pthread_mutex_unlock(&g_ledger_lock);
        return -1;
    }

    if (anchor_path_for(ledger_file_path) != 0) {
        pthread_mutex_unlock(&g_ledger_lock);
        return -1;
    }
    snprintf(g_ledger_file, sizeof(g_ledger_file), "%s", ledger_file_path);
    g_block_count = 0;
    memcpy(g_latest_hash, LEDGER_GENESIS_HASH, sizeof(g_latest_hash));

    FILE *f = fopen(g_ledger_file, "r");
    if (!f && errno != ENOENT) {
        pthread_mutex_unlock(&g_ledger_lock);
        return -1;
    }

    if (f) {
        char header[256];
        if (!fgets(header, sizeof(header), f) ||
            strncmp(header, LEDGER_FORMAT_HEADER, strlen(LEDGER_FORMAT_HEADER)) != 0) {
            /* An unauthenticated (V1) ledger is rejected outright rather
               than being silently trusted or silently overwritten. */
            fprintf(stderr,
                    "[ExamOS-Ledger] FATAL: ledger '%s' is not in the authenticated V2 format; refusing to open it.\n",
                    g_ledger_file);
            fclose(f);
            pthread_mutex_unlock(&g_ledger_lock);
            return -1;
        }

        char line[LEDGER_LINE_MAX];
        char expected_prev[65] = LEDGER_GENESIS_HASH;
        long verified_count = 0;
        int valid = 1;

        while (fgets(line, sizeof(line), f)) {
            size_t line_len = strlen(line);
            if (line_len == 0 || line[line_len - 1] != '\n') { valid = 0; break; }

            long idx = 0, ts = 0;
            char type[32] = {0}, dev[64] = {0}, details[LEDGER_LINE_MAX] = {0};
            char prev[65] = {0}, mac_hex[65] = {0};
            if (sscanf(line, "%ld|%ld|%31[^|]|%63[^|]|%1023[^|]|%64[^|]|%64s",
                       &idx, &ts, type, dev, details, prev, mac_hex) != 7 ||
                idx != verified_count + 1 || ts <= 0 ||
                strlen(prev) != 64 || strlen(mac_hex) != 64 ||
                strcmp(prev, expected_prev) != 0) {
                valid = 0;
                break;
            }

            char payload[LEDGER_LINE_MAX * 2];
            snprintf(payload, sizeof(payload), "%ld:%ld:%s:%s:%s:%s",
                     idx, ts, type, dev, details, prev);
            char computed[65];
            compute_block_mac(payload, computed);
            if (strcmp(computed, mac_hex) != 0) { valid = 0; break; }

            memcpy(expected_prev, mac_hex, sizeof(expected_prev));
            verified_count = idx;
        }

        if (ferror(f)) valid = 0;
        if (fclose(f) != 0) valid = 0;

        if (!valid) {
            fprintf(stderr,
                    "[ExamOS-Ledger] FATAL: ledger '%s' failed authentication (tampered or malformed); refusing to start.\n",
                    g_ledger_file);
            pthread_mutex_unlock(&g_ledger_lock);
            return -1;
        }

        g_block_count = verified_count;
        memcpy(g_latest_hash, expected_prev, sizeof(g_latest_hash));

        /* Truncation detection: the anchored tail must still be present. */
        long anchor_count = 0;
        char anchor_hash[65] = {0};
        if (read_anchor(&anchor_count, anchor_hash) == 0) {
            if (g_block_count < anchor_count) {
                fprintf(stderr,
                        "[ExamOS-Ledger] FATAL: ledger '%s' is shorter than its committed anchor (%ld < %ld); truncation detected.\n",
                        g_ledger_file, g_block_count, anchor_count);
                pthread_mutex_unlock(&g_ledger_lock);
                return -1;
            }
            if (anchor_count > 0) {
                /* Re-read the anchored block and confirm its hash. */
                FILE *af = fopen(g_ledger_file, "r");
                int matched = 0;
                if (af) {
                    char hline[LEDGER_LINE_MAX];
                    if (fgets(hline, sizeof(hline), af)) {
                        long idx = 0, ts = 0;
                        char type[32] = {0}, dev[64] = {0}, details[LEDGER_LINE_MAX] = {0};
                        char prev[65] = {0}, mac_hex[65] = {0};
                        while (fgets(hline, sizeof(hline), af)) {
                            if (sscanf(hline, "%ld|%ld|%31[^|]|%63[^|]|%1023[^|]|%64[^|]|%64s",
                                       &idx, &ts, type, dev, details, prev, mac_hex) != 7) break;
                            if (idx == anchor_count) {
                                matched = (strcmp(mac_hex, anchor_hash) == 0);
                                break;
                            }
                        }
                    }
                    fclose(af);
                }
                if (!matched) {
                    fprintf(stderr,
                            "[ExamOS-Ledger] FATAL: ledger '%s' no longer matches its committed anchor; the anchored block was rewritten.\n",
                            g_ledger_file);
                    pthread_mutex_unlock(&g_ledger_lock);
                    return -1;
                }
            }
        } else {
            /* First initialization of the anchor for an existing ledger. */
            if (write_anchor_locked(g_block_count, g_latest_hash) != 0) {
                pthread_mutex_unlock(&g_ledger_lock);
                return -1;
            }
        }
    } else {
        /* Fresh ledger: create it with the mandatory format header. */
        int fd = open(g_ledger_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) { pthread_mutex_unlock(&g_ledger_lock); return -1; }
        const char *header = LEDGER_FORMAT_HEADER "\n";
        ssize_t n = write(fd, header, strlen(header));
        if (n != (ssize_t)strlen(header) || fsync(fd) != 0) {
            close(fd);
            pthread_mutex_unlock(&g_ledger_lock);
            return -1;
        }
        if (close(fd) != 0) { pthread_mutex_unlock(&g_ledger_lock); return -1; }
        if (write_anchor_locked(0, g_latest_hash) != 0) {
            pthread_mutex_unlock(&g_ledger_lock);
            return -1;
        }
    }

    pthread_mutex_unlock(&g_ledger_lock);
    return 0;
}

int ledger_append_event(const char *event_type, const char *device_id,
                        const char *details, ledger_block_t *out_block) {
    pthread_mutex_lock(&g_ledger_lock);

    if (!g_key_loaded) {
        pthread_mutex_unlock(&g_ledger_lock);
        return -1;
    }

    ledger_block_t block;
    memset(&block, 0, sizeof(block));
    block.block_index = g_block_count + 1;
    block.timestamp = (long)time(NULL);
    snprintf(block.event_type, sizeof(block.event_type), "%s",
             event_type && event_type[0] ? event_type : "GENERIC");
    snprintf(block.device_id, sizeof(block.device_id), "%s",
             device_id && device_id[0] ? device_id : "UNKNOWN_DEV");
    snprintf(block.details, sizeof(block.details), "%s",
             details && details[0] ? details : "");
    sanitize_field(block.event_type);
    sanitize_field(block.device_id);
    sanitize_field(block.details);
    memcpy(block.prev_hash, g_latest_hash, 64);
    block.prev_hash[64] = '\0';

    char payload_to_hash[LEDGER_LINE_MAX];
    snprintf(payload_to_hash, sizeof(payload_to_hash), "%ld:%ld:%s:%s:%s:%s",
             block.block_index, block.timestamp, block.event_type,
             block.device_id, block.details, block.prev_hash);
    compute_block_mac(payload_to_hash, block.block_hash);

    int fd = open(g_ledger_file, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) { pthread_mutex_unlock(&g_ledger_lock); return -1; }

    char line[LEDGER_LINE_MAX];
    int written = snprintf(line, sizeof(line), "%ld|%ld|%s|%s|%s|%s|%s\n",
                           block.block_index, block.timestamp, block.event_type,
                           block.device_id, block.details, block.prev_hash,
                           block.block_hash);
    int failed = 0;
    if (written <= 0 || written >= (int)sizeof(line)) {
        failed = 1;
    } else {
        ssize_t n = write(fd, line, (size_t)written);
        if (n != written) failed = 1;
        else if (fsync(fd) != 0) failed = 1;
    }
    if (close(fd) != 0) failed = 1;

    if (failed) { pthread_mutex_unlock(&g_ledger_lock); return -1; }

    memcpy(g_latest_hash, block.block_hash, 65);
    g_block_count++;

    /* Commit the truncation anchor before reporting success. */
    if (write_anchor_locked(g_block_count, g_latest_hash) != 0) {
        pthread_mutex_unlock(&g_ledger_lock);
        return -1;
    }

    if (out_block) *out_block = block;
    pthread_mutex_unlock(&g_ledger_lock);
    return 0;
}

int ledger_verify_integrity(void) {
    pthread_mutex_lock(&g_ledger_lock);

    if (!g_key_loaded) { pthread_mutex_unlock(&g_ledger_lock); return 0; }

    FILE *f = fopen(g_ledger_file, "r");
    if (!f) {
        int empty = (errno == ENOENT && g_block_count == 0);
        pthread_mutex_unlock(&g_ledger_lock);
        return empty;
    }

    char header[256];
    if (!fgets(header, sizeof(header), f) ||
        strncmp(header, LEDGER_FORMAT_HEADER, strlen(LEDGER_FORMAT_HEADER)) != 0) {
        fclose(f);
        pthread_mutex_unlock(&g_ledger_lock);
        return 0;
    }

    char line[LEDGER_LINE_MAX];
    char expected_prev[65] = LEDGER_GENESIS_HASH;
    long verified_count = 0;
    int valid = 1;

    while (fgets(line, sizeof(line), f)) {
        size_t line_len = strlen(line);
        if (line_len == 0 || line[line_len - 1] != '\n') { valid = 0; break; }

        long idx = 0, ts = 0;
        char type[32] = {0}, dev[64] = {0}, details[256] = {0};
        char prev[65] = {0}, mac_hex[65] = {0};
        if (sscanf(line, "%ld|%ld|%31[^|]|%63[^|]|%255[^|]|%64[^|]|%64s",
                   &idx, &ts, type, dev, details, prev, mac_hex) != 7 ||
            idx != verified_count + 1 || ts <= 0 ||
            strlen(prev) != 64 || strlen(mac_hex) != 64 ||
            strcmp(prev, expected_prev) != 0) {
            valid = 0;
            break;
        }
        char payload[LEDGER_LINE_MAX];
        snprintf(payload, sizeof(payload), "%ld:%ld:%s:%s:%s:%s",
                 idx, ts, type, dev, details, prev);
        char computed[65];
        compute_block_mac(payload, computed);
        if (strcmp(computed, mac_hex) != 0) { valid = 0; break; }
        memcpy(expected_prev, mac_hex, sizeof(expected_prev));
        verified_count = idx;
    }

    if (ferror(f)) valid = 0;
    if (verified_count != g_block_count) valid = 0;
    fclose(f);

    if (valid) {
        long anchor_count = 0;
        char anchor_hash[65] = {0};
        if (read_anchor(&anchor_count, anchor_hash) == 0 && anchor_count > verified_count) {
            valid = 0;   /* truncated below the committed anchor */
        }
    }

    pthread_mutex_unlock(&g_ledger_lock);
    return valid;
}

long ledger_get_block_count(void) {
    pthread_mutex_lock(&g_ledger_lock);
    long count = g_block_count;
    pthread_mutex_unlock(&g_ledger_lock);
    return count;
}

int ledger_get_last_hash(char *out_hex, size_t max_len) {
    if (!out_hex || max_len < 65) return -1;
    pthread_mutex_lock(&g_ledger_lock);
    memcpy(out_hex, g_latest_hash, 64);
    out_hex[64] = '\0';
    pthread_mutex_unlock(&g_ledger_lock);
    return 0;
}
