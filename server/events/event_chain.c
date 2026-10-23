#define _GNU_SOURCE
#include "../include/event_chain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define MAX_ACTIVE_SESSION_CHAINS 256

typedef struct {
    char     session_id[EVENT_SESSION_ID_LEN];
    uint64_t last_sequence;
    char     latest_hash[HASH_HEX_LEN];
    time_t   last_event_time;
    int      active;
} session_chain_state_t;

static session_chain_state_t g_chains[MAX_ACTIVE_SESSION_CHAINS];
static int                   g_chain_count = 0;
static char                  g_storage_path[512] = "/var/log/examos/proctoring_events.log";
static pthread_mutex_t       g_event_lock = PTHREAD_MUTEX_INITIALIZER;

static void sha256_hex(const unsigned char *data, size_t len, char *out_hex) {
    unsigned char hash[32];
    unsigned int hash_len = 0;
    EVP_Digest(data, len, hash, &hash_len, EVP_sha256(), NULL);
    for (int i = 0; i < 32; i++)
        sprintf(out_hex + (i * 2), "%02x", hash[i]);
    out_hex[64] = '\0';
    OPENSSL_cleanse(hash, sizeof(hash));
}

static int hmac_sha256_hex(const char *key, const unsigned char *data, size_t len, char *out_hex) {
    unsigned char digest[32];
    unsigned int digest_len = 0;
    if (!HMAC(EVP_sha256(), key, (int)strlen(key), data, len, digest, &digest_len) ||
        digest_len != 32) return -1;
    for (unsigned int i = 0; i < digest_len; i++)
        sprintf(out_hex + (i * 2), "%02x", digest[i]);
    out_hex[digest_len * 2] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static void get_iso8601_utc(char *out, size_t max_len) {
    struct timeval tv;
    if (!out || max_len == 0 || gettimeofday(&tv, NULL) != 0) return;
    struct tm tm_utc;
    if (!gmtime_r(&tv.tv_sec, &tm_utc)) return;
    char base[24];
    if (strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm_utc) == 0) return;
    int written = snprintf(out, max_len, "%s.%03uZ", base,
                           (unsigned)(tv.tv_usec / 1000));
    if (written < 0 || (size_t)written >= max_len) out[0] = '\0';
}

static int safe_event_label(const char *value, size_t max_len) {
    if (!value || !value[0] || strnlen(value, max_len) >= max_len) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')) return 0;
    }
    return 1;
}

int event_chain_init(const char *storage_file_path) {
    pthread_mutex_lock(&g_event_lock);
    if (storage_file_path && storage_file_path[0]) {
        strncpy(g_storage_path, storage_file_path, sizeof(g_storage_path) - 1);
        g_storage_path[sizeof(g_storage_path) - 1] = '\0';
    }

    memset(g_chains, 0, sizeof(g_chains));
    g_chain_count = 0;

    /* Create directory structure if needed */
    char dir_path[512];
    memcpy(dir_path, g_storage_path, sizeof(dir_path));
    dir_path[sizeof(dir_path) - 1] = '\0';
    char *slash = strrchr(dir_path, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir_path, 0750);
    }

    pthread_mutex_unlock(&g_event_lock);
    return 0;
}

void event_chain_close(void) {
    /* No persistent handles to clean */
}

int event_chain_canonicalize(const proctoring_event_t *ev, char *out_canonical, size_t max_out) {
    if (!ev || !out_canonical) return -1;

    /* Canonical JSON format: deterministic key order, no extraneous spaces outside strings */
    int len = snprintf(out_canonical, max_out,
             "{\"event_type\":\"%s\",\"model_name\":\"%s\",\"model_version\":\"%s\",\"payload\":%s,"
             "\"previous_hash\":\"%s\",\"sequence\":%lu,\"server_timestamp\":\"%s\","
             "\"session_id\":\"%s\",\"source_timestamp\":\"%s\",\"source_type\":\"%s\"}",
             ev->event_type,
             ev->model_name,
             ev->model_version,
             (ev->payload_json[0] == '{' || ev->payload_json[0] == '[') ? ev->payload_json : "{}",
             ev->previous_hash,
             (unsigned long)ev->sequence,
             ev->server_timestamp,
             ev->session_id,
             ev->source_timestamp,
             ev->source_type);

    if (len < 0 || (size_t)len >= max_out) return -1;
    return 0;
}

int event_chain_append(const char *session_id, const char *source_type,
                        const char *event_type, const char *payload_json,
                        const char *model_name, const char *model_version,
                        proctoring_event_t *out_event) {
    if (!safe_event_label(session_id, sizeof(((proctoring_event_t *)0)->session_id)) ||
        !safe_event_label(source_type, MAX_SOURCE_TYPE_LEN) ||
        !safe_event_label(event_type, MAX_EVENT_TYPE_LEN) ||
        !payload_json || !payload_json[0] || strnlen(payload_json, MAX_PAYLOAD_LEN) >= MAX_PAYLOAD_LEN ||
        (payload_json[0] != '{' && payload_json[0] != '[') ||
        !safe_event_label(model_name, MAX_MODEL_LEN) ||
        !safe_event_label(model_version, MAX_MODEL_LEN)) return -1;

    pthread_mutex_lock(&g_event_lock);

    /* 1. Find or allocate session chain */
    session_chain_state_t *st = NULL;
    for (int i = 0; i < g_chain_count; i++) {
        if (strcmp(g_chains[i].session_id, session_id) == 0 && g_chains[i].active) {
            st = &g_chains[i];
            break;
        }
    }

    if (!st) {
        if (g_chain_count >= MAX_ACTIVE_SESSION_CHAINS) {
            pthread_mutex_unlock(&g_event_lock);
            return -1; /* Session capacity reached */
        }
        st = &g_chains[g_chain_count++];
        memset(st, 0, sizeof(*st));
        strncpy(st->session_id, session_id, sizeof(st->session_id) - 1);
        st->last_sequence = 0;
        strcpy(st->latest_hash, EVENT_CHAIN_GENESIS_HASH);
        st->active = 1;
    }

    /* 2. Construct event */
    proctoring_event_t ev;
    memset(&ev, 0, sizeof(ev));
    strncpy(ev.session_id, session_id, sizeof(ev.session_id) - 1);
    ev.sequence = st->last_sequence + 1;
    get_iso8601_utc(ev.server_timestamp, sizeof(ev.server_timestamp));
    memcpy(ev.source_timestamp, ev.server_timestamp, sizeof(ev.source_timestamp));
    strncpy(ev.source_type, source_type, sizeof(ev.source_type) - 1);
    strncpy(ev.event_type, event_type, sizeof(ev.event_type) - 1);
    strncpy(ev.payload_json, payload_json, sizeof(ev.payload_json) - 1);
    strncpy(ev.model_name, model_name, sizeof(ev.model_name) - 1);
    strncpy(ev.model_version, model_version, sizeof(ev.model_version) - 1);
    strcpy(ev.previous_hash, st->latest_hash);

    /* 3. Compute Canonical JSON representation */
    char canonical_json[4096];
    if (event_chain_canonicalize(&ev, canonical_json, sizeof(canonical_json)) != 0) {
        pthread_mutex_unlock(&g_event_lock);
        return -1;
    }

    /* 4. Compute Hash: SHA256(previousHash || canonicalJSON) */
    char hash_input[8192];
    snprintf(hash_input, sizeof(hash_input), "%s%s", ev.previous_hash, canonical_json);
    sha256_hex((const unsigned char *)hash_input, strlen(hash_input), ev.event_hash);

    /* 5. Append durably before publishing the new in-memory chain head. */
    int fd = open(g_storage_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if (fd < 0) {
        pthread_mutex_unlock(&g_event_lock);
        return -1;
    }
    FILE *fp = fdopen(fd, "a");
    if (!fp) {
        close(fd);
        pthread_mutex_unlock(&g_event_lock);
        return -1;
    }
    int write_ok = fprintf(fp, "{\"session_id\":\"%s\",\"sequence\":%lu,\"server_timestamp\":\"%s\"," 
                    "\"source_timestamp\":\"%s\",\"source_type\":\"%s\",\"event_type\":\"%s\","
                    "\"payload\":%s,\"model_name\":\"%s\",\"model_version\":\"%s\","
                    "\"previous_hash\":\"%s\",\"event_hash\":\"%s\"}\n",
                ev.session_id, (unsigned long)ev.sequence, ev.server_timestamp,
                ev.source_timestamp, ev.source_type, ev.event_type,
                ev.payload_json, ev.model_name, ev.model_version,
                ev.previous_hash, ev.event_hash);
    if (write_ok < 0 || fflush(fp) != 0 || fsync(fd) != 0 || fclose(fp) != 0) {
        pthread_mutex_unlock(&g_event_lock);
        return -1;
    }

    /* 6. Publish only evidence known to have reached stable storage. */
    st->last_sequence = ev.sequence;
    strcpy(st->latest_hash, ev.event_hash);
    st->last_event_time = time(NULL);

    if (out_event) {
        memcpy(out_event, &ev, sizeof(proctoring_event_t));
    }

    pthread_mutex_unlock(&g_event_lock);
    return 0;
}

int event_chain_sign_checkpoint(const char *session_id, event_checkpoint_t *out_checkpoint) {
    if (!session_id || !out_checkpoint) return -1;

    const char *signing_key = getenv("EXAMOS_EVENT_SIGNING_KEY");
    const char *signing_key_id = getenv("EXAMOS_EVENT_SIGNING_KEY_ID");
    if (!signing_key || strlen(signing_key) < 32 ||
        !safe_event_label(signing_key_id, sizeof(out_checkpoint->signing_key_id))) return -1;

    pthread_mutex_lock(&g_event_lock);

    session_chain_state_t *st = NULL;
    for (int i = 0; i < g_chain_count; i++) {
        if (strcmp(g_chains[i].session_id, session_id) == 0 && g_chains[i].active) {
            st = &g_chains[i];
            break;
        }
    }

    if (!st || st->last_sequence == 0) {
        pthread_mutex_unlock(&g_event_lock);
        return -1;
    }

    memset(out_checkpoint, 0, sizeof(*out_checkpoint));
    strncpy(out_checkpoint->session_id, session_id, sizeof(out_checkpoint->session_id) - 1);
    out_checkpoint->checkpoint_sequence = st->last_sequence;
    strcpy(out_checkpoint->latest_event_hash, st->latest_hash);
    snprintf(out_checkpoint->signing_key_id, sizeof(out_checkpoint->signing_key_id), "%s", signing_key_id);
    get_iso8601_utc(out_checkpoint->server_timestamp, sizeof(out_checkpoint->server_timestamp));

    /* A deployment-provisioned key signs the checkpoint; no key is compiled in. */
    char sign_input[512];
    int sign_len = snprintf(sign_input, sizeof(sign_input), "%s:%s:%lu:%s:%s",
             out_checkpoint->signing_key_id,
             out_checkpoint->session_id,
             (unsigned long)out_checkpoint->checkpoint_sequence,
             out_checkpoint->latest_event_hash,
             out_checkpoint->server_timestamp);
    if (sign_len < 0 || (size_t)sign_len >= sizeof(sign_input) ||
        hmac_sha256_hex(signing_key, (const unsigned char *)sign_input, (size_t)sign_len,
                        out_checkpoint->signature_hex) != 0) {
        pthread_mutex_unlock(&g_event_lock);
        return -1;
    }

    pthread_mutex_unlock(&g_event_lock);
    return 0;
}

int event_chain_verify_session(const char *session_id, uint64_t *out_total_events,
                                uint64_t *out_corrupt_sequence, char *out_error_reason,
                                size_t max_reason_len) {
    if (!session_id || !out_total_events) return -1;
    *out_total_events = 0;
    if (out_corrupt_sequence) *out_corrupt_sequence = 0;
    if (out_error_reason) out_error_reason[0] = '\0';

    pthread_mutex_lock(&g_event_lock);

    FILE *fp = fopen(g_storage_path, "r");
    if (!fp) {
        if (out_error_reason) snprintf(out_error_reason, max_reason_len, "STORAGE_FILE_MISSING");
        pthread_mutex_unlock(&g_event_lock);
        return -1;
    }

    char line[8192];
    uint64_t expected_sequence = 1;
    char expected_prev_hash[HASH_HEX_LEN];
    strcpy(expected_prev_hash, EVENT_CHAIN_GENESIS_HASH);

    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, session_id)) continue;

        proctoring_event_t ev;
        memset(&ev, 0, sizeof(ev));

        /* Parse event fields from log line */
        char *p_sess = strstr(line, "\"session_id\":\"");
        if (!p_sess) continue;
        p_sess += 14;
        char *end_sess = strchr(p_sess, '"');
        if (!end_sess) continue;
        *end_sess = '\0';
        if (strcmp(p_sess, session_id) != 0) continue;
        strcpy(ev.session_id, p_sess);
        *end_sess = '"';

        char *p_seq = strstr(line, "\"sequence\":");
        if (p_seq) ev.sequence = strtoull(p_seq + 11, NULL, 10);

        char *p_st = strstr(line, "\"server_timestamp\":\"");
        if (p_st) {
            p_st += 20;
            char *e = strchr(p_st, '"');
            if (e) { *e = '\0'; strncpy(ev.server_timestamp, p_st, 31); *e = '"'; }
        }

        char *p_src_t = strstr(line, "\"source_timestamp\":\"");
        if (p_src_t) {
            p_src_t += 20;
            char *e = strchr(p_src_t, '"');
            if (e) { *e = '\0'; strncpy(ev.source_timestamp, p_src_t, 31); *e = '"'; }
        }

        char *p_src = strstr(line, "\"source_type\":\"");
        if (p_src) {
            p_src += 15;
            char *e = strchr(p_src, '"');
            if (e) { *e = '\0'; strncpy(ev.source_type, p_src, 31); *e = '"'; }
        }

        char *p_type = strstr(line, "\"event_type\":\"");
        if (p_type) {
            p_type += 14;
            char *e = strchr(p_type, '"');
            if (e) { *e = '\0'; strncpy(ev.event_type, p_type, 63); *e = '"'; }
        }

        char *p_payload = strstr(line, "\"payload\":");
        if (p_payload) {
            p_payload += 10;
            char *p_end = strstr(p_payload, ",\"model_name\":");
            if (p_end) {
                *p_end = '\0';
                strncpy(ev.payload_json, p_payload, sizeof(ev.payload_json) - 1);
                *p_end = ',';
            }
        }

        char *p_mname = strstr(line, "\"model_name\":\"");
        if (p_mname) {
            p_mname += 14;
            char *e = strchr(p_mname, '"');
            if (e) { *e = '\0'; strncpy(ev.model_name, p_mname, 63); *e = '"'; }
        }

        char *p_mver = strstr(line, "\"model_version\":\"");
        if (p_mver) {
            p_mver += 17;
            char *e = strchr(p_mver, '"');
            if (e) { *e = '\0'; strncpy(ev.model_version, p_mver, 63); *e = '"'; }
        }

        char *p_prev = strstr(line, "\"previous_hash\":\"");
        if (p_prev) {
            p_prev += 17;
            char *e = strchr(p_prev, '"');
            if (e) { *e = '\0'; strncpy(ev.previous_hash, p_prev, 64); *e = '"'; }
        }

        char *p_hash = strstr(line, "\"event_hash\":\"");
        if (p_hash) {
            p_hash += 14;
            char *e = strchr(p_hash, '"');
            if (e) { *e = '\0'; strncpy(ev.event_hash, p_hash, 64); *e = '"'; }
        }

        /* Verification Rule 1: Sequence Continuity */
        if (ev.sequence != expected_sequence) {
            if (out_corrupt_sequence) *out_corrupt_sequence = ev.sequence;
            if (out_error_reason) snprintf(out_error_reason, max_reason_len, "SEQUENCE_GAP_OR_REORDER");
            fclose(fp);
            pthread_mutex_unlock(&g_event_lock);
            return -1;
        }

        /* Verification Rule 2: Previous Hash Continuity */
        if (strcmp(ev.previous_hash, expected_prev_hash) != 0) {
            if (out_corrupt_sequence) *out_corrupt_sequence = ev.sequence;
            if (out_error_reason) snprintf(out_error_reason, max_reason_len, "PREVIOUS_HASH_MISMATCH");
            fclose(fp);
            pthread_mutex_unlock(&g_event_lock);
            return -1;
        }

        /* Verification Rule 3: Recompute Canonical Hash */
        char canonical_json[4096];
        if (event_chain_canonicalize(&ev, canonical_json, sizeof(canonical_json)) != 0) {
            if (out_corrupt_sequence) *out_corrupt_sequence = ev.sequence;
            if (out_error_reason) snprintf(out_error_reason, max_reason_len, "CANONICALIZATION_FAIL");
            fclose(fp);
            pthread_mutex_unlock(&g_event_lock);
            return -1;
        }

        char hash_input[8192];
        snprintf(hash_input, sizeof(hash_input), "%s%s", ev.previous_hash, canonical_json);
        char calculated_hash[HASH_HEX_LEN];
        sha256_hex((const unsigned char *)hash_input, strlen(hash_input), calculated_hash);

        if (strcmp(calculated_hash, ev.event_hash) != 0) {
            if (out_corrupt_sequence) *out_corrupt_sequence = ev.sequence;
            if (out_error_reason) snprintf(out_error_reason, max_reason_len, "EVENT_HASH_MISMATCH");
            fclose(fp);
            pthread_mutex_unlock(&g_event_lock);
            return -1;
        }

        strcpy(expected_prev_hash, ev.event_hash);
        expected_sequence++;
        (*out_total_events)++;
    }

    fclose(fp);
    pthread_mutex_unlock(&g_event_lock);

    if (*out_total_events == 0) {
        if (out_error_reason) snprintf(out_error_reason, max_reason_len, "NO_EVENTS_FOUND");
        return -1;
    }

    return 0;
}

int event_chain_export_json(const char *session_id, char *out_buf, size_t max_len) {
    if (!session_id || !out_buf || max_len < 16) return -1;

    pthread_mutex_lock(&g_event_lock);
    FILE *fp = fopen(g_storage_path, "r");
    if (!fp) {
        strcpy(out_buf, "[]");
        pthread_mutex_unlock(&g_event_lock);
        return 0;
    }

    size_t offset = 0;
    offset += snprintf(out_buf + offset, max_len - offset, "[");

    char line[8192];
    int first = 1;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, session_id)) continue;
        size_t line_len = strlen(line);
        while (line_len > 0 && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r')) {
            line[--line_len] = '\0';
        }

        if (offset + line_len + 4 >= max_len) break;
        if (!first) {
            offset += snprintf(out_buf + offset, max_len - offset, ",");
        }
        offset += snprintf(out_buf + offset, max_len - offset, "%s", line);
        first = 0;
    }

    fclose(fp);
    snprintf(out_buf + offset, max_len - offset, "]");
    pthread_mutex_unlock(&g_event_lock);
    return 0;
}
