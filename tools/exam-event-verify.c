#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#define EVENT_CHAIN_GENESIS_HASH "0000000000000000000000000000000000000000000000000000000000000000"
#define HASH_HEX_LEN 65
#define SIG_HEX_LEN 129

#define EVENT_SESSION_ID_LEN 128

typedef struct {
    char     session_id[EVENT_SESSION_ID_LEN];
    uint64_t sequence;
    char     server_timestamp[32];
    char     source_timestamp[32];
    char     source_type[32];
    char     event_type[64];
    char     payload_json[1024];
    char     model_name[64];
    char     model_version[64];
    char     previous_hash[HASH_HEX_LEN];
    char     event_hash[HASH_HEX_LEN];
} parsed_event_t;

static void sha256_hex(const unsigned char *data, size_t len, char *out_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(out_hex + (i * 2), "%02x", hash[i]);
    }
    out_hex[64] = '\0';
}

static int hmac_sha256_hex(const char *key, const unsigned char *data, size_t len,
                           char out_hex[HASH_HEX_LEN]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (!key || !data || !out_hex ||
        !HMAC(EVP_sha256(), key, (int)strlen(key), data, len, digest, &digest_len) ||
        digest_len != SHA256_DIGEST_LENGTH) {
        return -1;
    }
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(out_hex + (i * 2), "%02x", digest[i]);
    }
    out_hex[HASH_HEX_LEN - 1] = '\0';
    return 0;
}

static const char *json_string_field(const char *json, const char *key,
                                     char *out, size_t out_size) {
    if (!json || !key || !out || out_size == 0) return NULL;
    out[0] = '\0';
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return NULL;
    p += strlen(pattern);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '"') return NULL;
    p++;
    const char *end = strchr(p, '"');
    if (!end || (size_t)(end - p) >= out_size) return NULL;
    memcpy(out, p, (size_t)(end - p));
    out[end - p] = '\0';
    return out;
}

static int verify_checkpoint(const char *checkpoint_path) {
    const char *signing_key = getenv("EXAMOS_EVENT_SIGNING_KEY");
    if (!signing_key || strlen(signing_key) < 32) {
        printf("CHECKPOINT: UNVERIFIABLE\n");
        printf("FAILURE_TYPE: SIGNING_KEY_UNAVAILABLE\n");
        printf("RESULT: BLOCKED\n");
        return 2;
    }

    FILE *fp = fopen(checkpoint_path, "r");
    if (!fp) {
        printf("CHECKPOINT: INVALID\n");
        printf("FAILURE_TYPE: CHECKPOINT_UNAVAILABLE\n");
        printf("RESULT: FAIL\n");
        return 1;
    }
    char json[8192];
    size_t used = fread(json, 1, sizeof(json) - 1, fp);
    fclose(fp);
    json[used] = '\0';

    char key_id[128] = {0}, session_id[EVENT_SESSION_ID_LEN] = {0};
    char latest_hash[HASH_HEX_LEN] = {0}, server_timestamp[64] = {0};
    char signature[SIG_HEX_LEN] = {0};
    if (!json_string_field(json, "key_id", key_id, sizeof(key_id)) ||
        !json_string_field(json, "session_id", session_id, sizeof(session_id)) ||
        !json_string_field(json, "latest_hash", latest_hash, sizeof(latest_hash)) ||
        !json_string_field(json, "server_timestamp", server_timestamp, sizeof(server_timestamp)) ||
        !json_string_field(json, "signature", signature, sizeof(signature))) {
        printf("CHECKPOINT: INVALID\n");
        printf("FAILURE_TYPE: CHECKPOINT_FIELDS_MISSING\n");
        printf("RESULT: FAIL\n");
        return 1;
    }

    const char *p_seq = strstr(json, "\"sequence\"");
    if (!p_seq) {
        printf("CHECKPOINT: INVALID\n");
        printf("FAILURE_TYPE: CHECKPOINT_FIELDS_MISSING\n");
        printf("RESULT: FAIL\n");
        return 1;
    }
    p_seq += strlen("\"sequence\"");
    while (*p_seq == ' ' || *p_seq == '\t' || *p_seq == '\r' || *p_seq == '\n') p_seq++;
    if (*p_seq != ':') {
        printf("CHECKPOINT: INVALID\n");
        printf("FAILURE_TYPE: CHECKPOINT_FIELDS_MISSING\n");
        printf("RESULT: FAIL\n");
        return 1;
    }
    p_seq++;
    while (*p_seq == ' ' || *p_seq == '\t' || *p_seq == '\r' || *p_seq == '\n') p_seq++;
    unsigned long long sequence = strtoull(p_seq, NULL, 10);

    char sign_input[512];
    int sign_len = snprintf(sign_input, sizeof(sign_input), "%s:%s:%llu:%s:%s",
                            key_id, session_id, sequence, latest_hash,
                            server_timestamp);
    char expected[SIG_HEX_LEN] = {0};
    if (sign_len < 0 || (size_t)sign_len >= sizeof(sign_input) ||
        hmac_sha256_hex(signing_key, (const unsigned char *)sign_input,
                        (size_t)sign_len, expected) != 0) {
        printf("CHECKPOINT: INVALID\n");
        printf("FAILURE_TYPE: CHECKPOINT_CANONICALIZATION_FAIL\n");
        printf("RESULT: FAIL\n");
        return 1;
    }

    if (strlen(signature) != 64 ||
        CRYPTO_memcmp(signature, expected, 64) != 0) {
        printf("CHECKPOINT: INVALID\n");
        printf("FAILURE_TYPE: SIGNATURE_INVALID\n");
        printf("RESULT: FAIL\n");
        return 1;
    }

    printf("CHECKPOINT: VALID\n");
    printf("SEQUENCE: %llu\n", sequence);
    printf("RESULT: PASS\n");
    return 0;
}

static int canonicalize_event(const parsed_event_t *ev, char *out_canonical, size_t max_out) {
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

static void print_usage(const char *prog) {
    fprintf(stderr, "ExamOS Phase 4 — Independent Event Chain Verifier\n");
    fprintf(stderr,
            "Usage: %s --session <SESSION_ID> --store <PATH_TO_LOG_FILE>\n"
            "       %s --checkpoint <CHECKPOINT_JSON_FILE>\n"
            "Checkpoint verification reads EXAMOS_EVENT_SIGNING_KEY from the environment.\n",
            prog, prog);
}

int main(int argc, char *argv[]) {
    const char *session_id = NULL;
    const char *store_path = "/var/log/examos/proctoring_events.log";
    const char *checkpoint_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--session") == 0 && i + 1 < argc) {
            session_id = argv[++i];
        } else if (strcmp(argv[i], "--store") == 0 && i + 1 < argc) {
            store_path = argv[++i];
        } else if (strcmp(argv[i], "--checkpoint") == 0 && i + 1 < argc) {
            checkpoint_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (checkpoint_path) {
        return verify_checkpoint(checkpoint_path);
    }

    if (!session_id) {
        fprintf(stderr, "[ERROR] Missing required --session argument\n");
        print_usage(argv[0]);
        return 1;
    }

    FILE *fp = fopen(store_path, "r");
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open event store: %s\n", store_path);
        printf("SESSION: %s\n", session_id);
        printf("CHAIN: INVALID\n");
        printf("FAILURE_TYPE: STORE_UNAVAILABLE\n");
        printf("RESULT: FAIL\n");
        return 1;
    }

    char line[8192];
    uint64_t expected_sequence = 1;
    char expected_prev_hash[HASH_HEX_LEN];
    strcpy(expected_prev_hash, EVENT_CHAIN_GENESIS_HASH);
    uint64_t total_events = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, session_id)) continue;

        parsed_event_t ev;
        memset(&ev, 0, sizeof(ev));

        char *p_sess = strstr(line, "\"session_id\":\"");
        if (!p_sess) continue;
        p_sess += 14;
        char *end_sess = strchr(p_sess, '"');
        if (!end_sess) continue;
        *end_sess = '\0';
        if (strcmp(p_sess, session_id) != 0) continue;
        strncpy(ev.session_id, p_sess, sizeof(ev.session_id) - 1);
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

        /* 1. Sequence Continuity */
        if (ev.sequence != expected_sequence) {
            printf("SESSION: %s\n", session_id);
            printf("CHAIN: INVALID\n");
            printf("FAILURE_SEQUENCE: %lu\n", (unsigned long)ev.sequence);
            printf("FAILURE_TYPE: SEQUENCE_GAP_OR_REORDER (expected %lu)\n", (unsigned long)expected_sequence);
            printf("RESULT: FAIL\n");
            fclose(fp);
            return 1;
        }

        /* 2. Previous Hash Linkage */
        if (strcmp(ev.previous_hash, expected_prev_hash) != 0) {
            printf("SESSION: %s\n", session_id);
            printf("CHAIN: INVALID\n");
            printf("FAILURE_SEQUENCE: %lu\n", (unsigned long)ev.sequence);
            printf("FAILURE_TYPE: PREVIOUS_HASH_MISMATCH\n");
            printf("RESULT: FAIL\n");
            fclose(fp);
            return 1;
        }

        /* 3. Canonical Hash Verification */
        char canonical_json[4096];
        if (canonicalize_event(&ev, canonical_json, sizeof(canonical_json)) != 0) {
            printf("SESSION: %s\n", session_id);
            printf("CHAIN: INVALID\n");
            printf("FAILURE_SEQUENCE: %lu\n", (unsigned long)ev.sequence);
            printf("FAILURE_TYPE: CANONICALIZATION_FAIL\n");
            printf("RESULT: FAIL\n");
            fclose(fp);
            return 1;
        }

        char hash_input[8192];
        snprintf(hash_input, sizeof(hash_input), "%s%s", ev.previous_hash, canonical_json);
        char calculated_hash[HASH_HEX_LEN];
        sha256_hex((const unsigned char *)hash_input, strlen(hash_input), calculated_hash);

        if (strcmp(calculated_hash, ev.event_hash) != 0) {
            printf("SESSION: %s\n", session_id);
            printf("CHAIN: INVALID\n");
            printf("FAILURE_SEQUENCE: %lu\n", (unsigned long)ev.sequence);
            printf("FAILURE_TYPE: EVENT_HASH_MISMATCH\n");
            printf("RESULT: FAIL\n");
            fclose(fp);
            return 1;
        }

        strcpy(expected_prev_hash, ev.event_hash);
        expected_sequence++;
        total_events++;
    }

    fclose(fp);

    if (total_events == 0) {
        printf("SESSION: %s\n", session_id);
        printf("CHAIN: INVALID\n");
        printf("FAILURE_TYPE: NO_EVENTS_FOUND\n");
        printf("RESULT: FAIL\n");
        return 1;
    }

    printf("SESSION: %s\n", session_id);
    printf("EVENTS: %lu\n", (unsigned long)total_events);
    printf("CHAIN: VALID\n");
    printf("RESULT: PASS\n");
    return 0;
}
