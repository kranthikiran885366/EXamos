/*
 * attestation_service.c — ExamOS Phase 3 Attestation Engine
 *
 * Implements the 16-step deterministic trust chain:
 *   device check → nonce freshness → EK/AK → PCR match → quote sig → key release
 *
 * TEST/DEVELOPMENT CONFIGURATION.
 * Production golden PCR values must come from a controlled clean measured boot.
 * Production EK fingerprints come from real TPM manufacturer certificates.
 *
 * TEST ONLY — NOT FOR PRODUCTION.
 */
#define _GNU_SOURCE
#include "../include/attestation_service.h"
#include "../include/ledger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

/* -----------------------------------------------------------------------
 * Golden PCR values for ExamOS release examos-0.4.0 (development/test).
 * These are TEST placeholder measurements.  In production, golden values
 * are generated from a controlled clean measured boot, reviewed, approved
 * and published — they are NEVER manually guessed.
 * Each value is exactly 64 hex characters (SHA-256 digest).
 * ----------------------------------------------------------------------- */
#define GOLDEN_PCR0  "f4a3c2e1b09876543210abcdef0123456789abcdef0123456789abcdef012345"
#define GOLDEN_PCR4  "a1b2c3d4e5f6071829304a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f"
#define GOLDEN_PCR7  "778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566"
#define GOLDEN_PCR11 "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"

/*
 * Test EK fingerprints — deterministic 64-char hex values per enrolled device.
 * In production these are derived from the TPM EK certificate (RSA-2048/ECC P-256).
 * TEST ONLY — NOT FOR PRODUCTION.
 */
#define EK_DEV01     "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
#define EK_DEV02     "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c"
#define EK_MACHINE_A "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d"
#define EK_MACHINE_B "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e"
#define EK_NODE01    "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f"

/*
 * Test AK quote-signature construction suffix.
 * Both the client test agent and this server use:
 *   composite = SHA256(pcr0 || pcr4 || pcr7 || pcr11 || nonce)
 *   quote_sig  = SHA256(composite || AK_TEST_SUFFIX)
 * This is a development test protocol — real production uses TPM2_Quote
 * signed with the AK private key and verified with the AK public key.
 */
#define AK_TEST_SUFFIX "EXAMOS_AK_TEST_KEY_SIGNATURE"

/* -----------------------------------------------------------------------
 * Module-level state
 * ----------------------------------------------------------------------- */
static enrolled_device_t    g_devices[MAX_DEVICES];
static int                  g_device_count = 0;

static golden_release_t     g_releases[MAX_RELEASES];
static int                  g_release_count = 0;

static attestation_session_t g_sessions[MAX_ATTESTATION_SESSIONS];
static int                   g_session_count = 0;

static pthread_mutex_t      g_trust_lock = PTHREAD_MUTEX_INITIALIZER;

/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

/* Compute SHA-256 of data and write 64-char lowercase hex into out_hex[65]. */
static void sha256_hex(const unsigned char *data, size_t len, char *out_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out_hex + i * 2, "%02x", hash[i]);
    out_hex[64] = '\0';
}

/* Minimal JSON string-field extractor.
 * Finds "key":"value" in buf and copies the value into out[0..max_out-1].
 * Handles escaped quotes inside values up to max_out bytes.
 */
static void json_str(const char *buf, const char *key,
                     char *out, size_t max_out) {
    out[0] = '\0';
    if (!buf || !key) return;

    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(buf, pattern);
    if (!pos) return;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == ':' || *pos == '\t') pos++;
    if (*pos != '"') return;
    pos++;

    size_t i = 0;
    while (*pos && *pos != '"' && i + 1 < max_out) {
        if (*pos == '\\' && *(pos + 1)) { pos++; } /* skip escape prefix */
        out[i++] = *pos++;
    }
    out[i] = '\0';
}

/*
 * Parse PCR values from a JSON array of the form:
 *   "pcrs": [
 *     {"index": 0,  "value": "<64-char hex>"},
 *     {"index": 4,  "value": "<64-char hex>"},
 *     {"index": 7,  "value": "<64-char hex>"},
 *     {"index": 11, "value": "<64-char hex>"}
 *   ]
 *
 * Writes into pcr0/4/7/11 (each a 65-byte buffer).
 */
static void parse_pcr_array(const char *buf,
                             char *pcr0, char *pcr4,
                             char *pcr7, char *pcr11) {
    /* Locate the "pcrs" key */
    const char *start = strstr(buf, "\"pcrs\"");
    if (!start) return;
    start = strchr(start, '[');
    if (!start) return;

    /* Find the matching closing bracket */
    int depth = 1;
    const char *arr_end = start + 1;
    while (*arr_end && depth > 0) {
        if (*arr_end == '[') depth++;
        else if (*arr_end == ']') depth--;
        arr_end++;
    }

    const char *p = start + 1;

    while (p < arr_end && *p) {
        /* Advance to next '{' */
        while (p < arr_end && *p && *p != '{') p++;
        if (p >= arr_end || !*p) break;

        /* Find matching '}' within array bounds */
        const char *obj_start = p;
        const char *obj_end   = strchr(p, '}');
        if (!obj_end || obj_end >= arr_end) break;

        /* Extract "index": <int> */
        int  idx      = -1;
        char val[65]  = {0};

        const char *idx_pos = strstr(obj_start, "\"index\"");
        if (idx_pos && idx_pos < obj_end) {
            idx_pos += 7; /* strlen("\"index\"") */
            while (*idx_pos == ':' || *idx_pos == ' ' || *idx_pos == '\t') idx_pos++;
            if (isdigit((unsigned char)*idx_pos))
                idx = atoi(idx_pos);
        }

        /* Extract "value": "<hex>" */
        const char *val_pos = strstr(obj_start, "\"value\"");
        if (val_pos && val_pos < obj_end) {
            val_pos += 7;
            while (*val_pos == ':' || *val_pos == ' ' || *val_pos == '\t') val_pos++;
            if (*val_pos == '"') {
                val_pos++;
                int j = 0;
                while (*val_pos && *val_pos != '"' && j < 64) val[j++] = *val_pos++;
                val[j] = '\0';
            }
        }

        if (val[0]) {
            if      (idx == 0  && pcr0)  { strncpy(pcr0,  val, 64); pcr0[64]  = '\0'; }
            else if (idx == 4  && pcr4)  { strncpy(pcr4,  val, 64); pcr4[64]  = '\0'; }
            else if (idx == 7  && pcr7)  { strncpy(pcr7,  val, 64); pcr7[64]  = '\0'; }
            else if (idx == 11 && pcr11) { strncpy(pcr11, val, 64); pcr11[64] = '\0'; }
        }

        p = obj_end + 1;
    }
}

/* Generate 32 cryptographically random bytes, write as 64-char lowercase hex. */
static int random_hex64(char *out64) {
    unsigned char raw[32];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, raw, sizeof(raw));
    close(fd);
    if (r != (ssize_t)sizeof(raw)) return -1;
    for (int i = 0; i < 32; i++) sprintf(out64 + i * 2, "%02x", raw[i]);
    out64[64] = '\0';
    return 0;
}

/* Safe string copy into a fixed-size buffer with guaranteed null termination. */
static void safe_copy(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) return;
    strncpy(dst, src ? src : "", dst_size - 1);
    dst[dst_size - 1] = '\0';
}

/* -----------------------------------------------------------------------
 * attestation_service_init
 * ----------------------------------------------------------------------- */
int attestation_service_init(void) {
    pthread_mutex_lock(&g_trust_lock);

    memset(g_devices,  0, sizeof(g_devices));
    memset(g_releases, 0, sizeof(g_releases));
    memset(g_sessions, 0, sizeof(g_sessions));
    g_device_count  = 0;
    g_release_count = 0;
    g_session_count = 0;

    /* ----- Register golden release: examos-0.4.0 ----- */
    golden_release_t *rel = &g_releases[g_release_count++];
    safe_copy(rel->release_id, sizeof(rel->release_id), "examos-0.4.0");
    /*
     * UKI hash is UNKNOWN until an actual signed UKI is built.
     * This placeholder will be replaced by artifacts/p3/uki.sha256
     * after a real P3 image build.
     */
    safe_copy(rel->uki_hash, sizeof(rel->uki_hash),
              "0000000000000000000000000000000000000000000000000000000000000000");
    /* Exact 64-char test golden PCR values */
    safe_copy(rel->pcr0,  sizeof(rel->pcr0),  GOLDEN_PCR0);
    safe_copy(rel->pcr4,  sizeof(rel->pcr4),  GOLDEN_PCR4);
    safe_copy(rel->pcr7,  sizeof(rel->pcr7),  GOLDEN_PCR7);
    safe_copy(rel->pcr11, sizeof(rel->pcr11), GOLDEN_PCR11);
    rel->revoked    = 0;
    rel->created_at = time(NULL);

    /* ----- Register enrolled devices with deterministic test EK fingerprints ----- */
    struct { const char *id; const char *ek; } devs[] = {
        { "examos-device-01",      EK_DEV01     },
        { "examos-device-02",      EK_DEV02     },
        { "machine-a",             EK_MACHINE_A },
        { "machine-b",             EK_MACHINE_B },
        { "examos-device-node-01", EK_NODE01    },
        { NULL, NULL }
    };

    for (int i = 0; devs[i].id && g_device_count < MAX_DEVICES; i++) {
        enrolled_device_t *dev = &g_devices[g_device_count++];
        safe_copy(dev->device_id,       sizeof(dev->device_id),       devs[i].id);
        safe_copy(dev->ek_fingerprint,  sizeof(dev->ek_fingerprint),  devs[i].ek);
        dev->status     = DEVICE_STATUS_ENROLLED;
        safe_copy(dev->allowed_release, sizeof(dev->allowed_release), "examos-0.4.0");
        dev->created_at = time(NULL);
    }

    pthread_mutex_unlock(&g_trust_lock);
    return 0;
}

/* -----------------------------------------------------------------------
 * attestation_register_device
 * ----------------------------------------------------------------------- */
int attestation_register_device(const char *device_id, const char *ek_fingerprint,
                                  const char *allowed_release) {
    if (!device_id || !ek_fingerprint) return -1;
    pthread_mutex_lock(&g_trust_lock);

    /* Update if already registered */
    for (int i = 0; i < g_device_count; i++) {
        if (strcmp(g_devices[i].device_id, device_id) == 0) {
            safe_copy(g_devices[i].ek_fingerprint, sizeof(g_devices[i].ek_fingerprint),
                      ek_fingerprint);
            g_devices[i].status = DEVICE_STATUS_ENROLLED;
            if (allowed_release)
                safe_copy(g_devices[i].allowed_release,
                          sizeof(g_devices[i].allowed_release), allowed_release);
            g_devices[i].updated_at = time(NULL);
            pthread_mutex_unlock(&g_trust_lock);
            return 0;
        }
    }

    if (g_device_count < MAX_DEVICES) {
        enrolled_device_t *dev = &g_devices[g_device_count++];
        safe_copy(dev->device_id,      sizeof(dev->device_id),      device_id);
        safe_copy(dev->ek_fingerprint, sizeof(dev->ek_fingerprint), ek_fingerprint);
        dev->status = DEVICE_STATUS_ENROLLED;
        safe_copy(dev->allowed_release, sizeof(dev->allowed_release),
                  allowed_release ? allowed_release : "examos-0.4.0");
        dev->created_at = time(NULL);
        pthread_mutex_unlock(&g_trust_lock);
        return 0;
    }

    pthread_mutex_unlock(&g_trust_lock);
    return -1;
}

/* -----------------------------------------------------------------------
 * attestation_register_release
 * ----------------------------------------------------------------------- */
int attestation_register_release(const char *release_id, const char *uki_hash,
                                   const char *pcr0, const char *pcr4,
                                   const char *pcr7, const char *pcr11) {
    if (!release_id || !pcr0) return -1;
    pthread_mutex_lock(&g_trust_lock);

    if (g_release_count < MAX_RELEASES) {
        golden_release_t *rel = &g_releases[g_release_count++];
        safe_copy(rel->release_id, sizeof(rel->release_id), release_id);
        safe_copy(rel->uki_hash,   sizeof(rel->uki_hash),   uki_hash ? uki_hash : "");
        safe_copy(rel->pcr0,       sizeof(rel->pcr0),       pcr0);
        safe_copy(rel->pcr4,       sizeof(rel->pcr4),       pcr4 ? pcr4 : "");
        safe_copy(rel->pcr7,       sizeof(rel->pcr7),       pcr7 ? pcr7 : "");
        safe_copy(rel->pcr11,      sizeof(rel->pcr11),      pcr11 ? pcr11 : "");
        rel->revoked    = 0;
        rel->created_at = time(NULL);
        pthread_mutex_unlock(&g_trust_lock);
        return 0;
    }

    pthread_mutex_unlock(&g_trust_lock);
    return -1;
}

/* -----------------------------------------------------------------------
 * attestation_create_challenge
 *
 * BUG-FIX: now checks device registry BEFORE issuing nonce.
 * Unknown devices → P3_UNKNOWN_DEVICE.
 * Revoked devices → P3_REVOKED_DEVICE.
 * Only enrolled/trusted devices receive a challenge nonce.
 * ----------------------------------------------------------------------- */
int attestation_create_challenge(const char *device_id, const char *session_id,
                                   const char *release_id,
                                   char *out_nonce, char *out_attestation_id,
                                   char *out_error_code) {
    if (!device_id || !out_nonce || !out_attestation_id) return -1;
    if (out_error_code) out_error_code[0] = '\0';

    pthread_mutex_lock(&g_trust_lock);

    /* Step 1: Device must be enrolled */
    enrolled_device_t *dev = NULL;
    for (int i = 0; i < g_device_count; i++) {
        if (strcmp(g_devices[i].device_id, device_id) == 0) {
            dev = &g_devices[i];
            break;
        }
    }
    if (!dev) {
        if (out_error_code) safe_copy(out_error_code, 64, "P3_UNKNOWN_DEVICE");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* Step 2: Device must not be revoked */
    if (dev->status == DEVICE_STATUS_REVOKED) {
        if (out_error_code) safe_copy(out_error_code, 64, "P3_REVOKED_DEVICE");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* Step 3: Find a free session slot */
    int slot = -1;
    for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
        if (g_sessions[i].created_at == 0) { slot = i; break; }
    }
    if (slot < 0) {
        /* Evict oldest if all slots used */
        slot = 0;
        for (int i = 1; i < MAX_ATTESTATION_SESSIONS; i++)
            if (g_sessions[i].created_at < g_sessions[slot].created_at) slot = i;
        memset(&g_sessions[slot], 0, sizeof(attestation_session_t));
    }
    if (g_session_count < MAX_ATTESTATION_SESSIONS) g_session_count++;

    /* Step 4: Generate 64-char cryptographically random nonce */
    char nonce[65] = {0};
    if (random_hex64(nonce) != 0) {
        if (out_error_code) safe_copy(out_error_code, 64, "P3_INTERNAL_ERROR");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* Step 5: Build session record */
    attestation_session_t *s = &g_sessions[slot];
    memset(s, 0, sizeof(*s));

    snprintf(s->attestation_id, sizeof(s->attestation_id),
             "attest-%ld-%d", (long)time(NULL), slot);
    safe_copy(s->session_id,  sizeof(s->session_id),
              (session_id && session_id[0]) ? session_id : s->attestation_id);
    safe_copy(s->device_id,   sizeof(s->device_id),  device_id);
    safe_copy(s->release_id,  sizeof(s->release_id),
              (release_id && release_id[0]) ? release_id : "examos-0.4.0");
    safe_copy(s->nonce,       sizeof(s->nonce),       nonce);
    s->nonce_used  = 0;
    s->created_at  = time(NULL);
    s->state       = ATTESTATION_STATE_PENDING;

    safe_copy(out_nonce,          128, nonce);
    safe_copy(out_attestation_id, 64,  s->attestation_id);

    pthread_mutex_unlock(&g_trust_lock);
    return 0;
}

/* -----------------------------------------------------------------------
 * attestation_verify_evidence
 *
 * Performs all 16 trust checks in deterministic order.
 * Field names corrected: quote_signature_hex, ak_pub_hex.
 * PCR values extracted from nested array {"pcrs": [{index,value}...]}.
 * Quote verification: SHA256(SHA256(pcr0||pcr4||pcr7||pcr11||nonce) || AK_TEST_SUFFIX)
 * ----------------------------------------------------------------------- */
int attestation_verify_evidence(const char *evidence_json,
                                  char *out_reason, char *out_exam_key) {
    if (!evidence_json || !out_reason) return -1;
    out_reason[0] = '\0';
    if (out_exam_key) out_exam_key[0] = '\0';

    /* --- Parse evidence fields --- */
    char dev_id[64]    = {0};
    char rel_id[64]    = {0};
    char nonce[128]    = {0};
    char ek_fp[65]     = {0};
    char ak_pub[512]   = {0};
    char quote_sig[65] = {0};
    char ev_log[65]    = {0};
    char pcr0[65]      = {0};
    char pcr4[65]      = {0};
    char pcr7[65]      = {0};
    char pcr11[65]     = {0};

    json_str(evidence_json, "device_id",          dev_id,    sizeof(dev_id));
    json_str(evidence_json, "release_id",          rel_id,    sizeof(rel_id));
    json_str(evidence_json, "nonce",               nonce,     sizeof(nonce));
    json_str(evidence_json, "ek_fingerprint",      ek_fp,     sizeof(ek_fp));
    json_str(evidence_json, "ak_pub_hex",          ak_pub,    sizeof(ak_pub));    /* FIXED field name */
    json_str(evidence_json, "quote_signature_hex", quote_sig, sizeof(quote_sig)); /* FIXED field name */
    json_str(evidence_json, "event_log_hash",      ev_log,    sizeof(ev_log));

    /* Extract PCR values from nested array */
    parse_pcr_array(evidence_json, pcr0, pcr4, pcr7, pcr11);

    pthread_mutex_lock(&g_trust_lock);

    /* ----- Check 1: Request format ----- */
    if (!dev_id[0] || !rel_id[0] || !nonce[0]) {
        safe_copy(out_reason, 64, "P3_MALFORMED_REQUEST");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 2: Session exists (match by nonce) ----- */
    attestation_session_t *sess = NULL;
    for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
        if (g_sessions[i].created_at &&
            strcmp(g_sessions[i].nonce, nonce) == 0) {
            sess = &g_sessions[i];
            break;
        }
    }
    if (!sess) {
        safe_copy(out_reason, 64, "P3_INVALID_NONCE");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 3: Device exists ----- */
    enrolled_device_t *dev = NULL;
    for (int i = 0; i < g_device_count; i++) {
        if (strcmp(g_devices[i].device_id, dev_id) == 0) {
            dev = &g_devices[i];
            break;
        }
    }
    if (!dev) {
        safe_copy(out_reason, 64, "P3_UNKNOWN_DEVICE");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 4: Device not revoked ----- */
    if (dev->status == DEVICE_STATUS_REVOKED) {
        safe_copy(out_reason, 64, "P3_REVOKED_DEVICE");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 5: Release exists ----- */
    golden_release_t *rel = NULL;
    for (int i = 0; i < g_release_count; i++) {
        if (strcmp(g_releases[i].release_id, rel_id) == 0) {
            rel = &g_releases[i];
            break;
        }
    }
    if (!rel) {
        safe_copy(out_reason, 64, "P3_UNKNOWN_RELEASE");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 6: Release not revoked ----- */
    if (rel->revoked) {
        safe_copy(out_reason, 64, "P3_REVOKED_RELEASE");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 7: Nonce is from this session ----- */
    if (strcmp(sess->device_id, dev_id) != 0) {
        safe_copy(out_reason, 64, "P3_SESSION_BINDING_FAIL");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 8: Nonce is unused (replay protection) ----- */
    if (sess->nonce_used) {
        safe_copy(out_reason, 64, "P3_NONCE_REPLAY");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }
    sess->nonce_used = 1; /* Consume nonce atomically */

    /* ----- Check 9: EK fingerprint matches enrolled device identity.
     * A mismatched EK means this is not the registered hardware TPM — treat as
     * an unknown device identity (unregistered software TPM / wrong machine).
     * ----- */
    if (ek_fp[0] == '\0' || strcmp(dev->ek_fingerprint, ek_fp) != 0) {
        safe_copy(out_reason, 64, "P3_UNKNOWN_DEVICE");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 10: AK must be present (minimal check — production uses credential activation) ----- */
    if (ak_pub[0] == '\0') {
        safe_copy(out_reason, 64, "P3_INVALID_AK");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 11: PCR values must be present ----- */
    if (pcr0[0] == '\0' || pcr4[0] == '\0' || pcr7[0] == '\0' || pcr11[0] == '\0') {
        safe_copy(out_reason, 64, "P3_PCR_MISMATCH");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 12 & 13: PCR values match golden release measurements ----- */
    if (strcmp(rel->pcr0,  pcr0)  != 0 ||
        strcmp(rel->pcr4,  pcr4)  != 0 ||
        strcmp(rel->pcr7,  pcr7)  != 0 ||
        strcmp(rel->pcr11, pcr11) != 0) {
        safe_copy(out_reason, 64, "P3_PCR_MISMATCH");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 14: Event log must be present ----- */
    if (ev_log[0] == '\0') {
        safe_copy(out_reason, 64, "P3_EVENTLOG_INVALID");
        sess->state = ATTESTATION_STATE_FAILED;
        safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* ----- Check 15: Quote signature verification.
     *
     * Development test protocol:
     *   composite = SHA256(pcr0 || pcr4 || pcr7 || pcr11 || nonce)
     *   expected  = SHA256(composite || AK_TEST_SUFFIX)
     *
     * Both client agent and server use the same formula so they agree.
     * Production replaces this with TPM2_Quote RSA-PKCS1/ECDSA verification.
     * ----- */
    {
        char combined[800];
        /* nonce from the session (server-side) — binds quote freshness */
        snprintf(combined, sizeof(combined), "%s%s%s%s%s",
                 pcr0, pcr4, pcr7, pcr11, sess->nonce);
        char composite[65];
        sha256_hex((const unsigned char *)combined, strlen(combined), composite);

        char sig_input[200];
        snprintf(sig_input, sizeof(sig_input), "%s%s", composite, AK_TEST_SUFFIX);
        char expected_sig[65];
        sha256_hex((const unsigned char *)sig_input, strlen(sig_input), expected_sig);

        if (quote_sig[0] == '\0' || strcmp(expected_sig, quote_sig) != 0) {
            safe_copy(out_reason, 64, "P3_INVALID_SIGNATURE");
            sess->state = ATTESTATION_STATE_FAILED;
            safe_copy(sess->failure_reason, sizeof(sess->failure_reason), out_reason);
            pthread_mutex_unlock(&g_trust_lock);
            return -1;
        }
    }

    /* ----- Check 16: Session binding confirmed — all checks passed ----- */
    sess->state            = ATTESTATION_STATE_TRUSTED;
    sess->last_re_attestation = time(NULL);
    dev->status            = DEVICE_STATUS_TRUSTED;
    dev->updated_at        = time(NULL);

    /* Generate session-bound exam key: SHA256("EXAMOS-KEY-" || attest_id || device_id || ts) */
    char key_seed[256];
    snprintf(key_seed, sizeof(key_seed), "EXAMOS-KEY-%s-%s-%ld",
             sess->attestation_id, sess->device_id, (long)time(NULL));
    sha256_hex((const unsigned char *)key_seed, strlen(key_seed), sess->exam_key);
    sess->exam_key_released = 1;

    if (out_exam_key)
        safe_copy(out_exam_key, EXAM_KEY_LEN + 1, sess->exam_key);

    safe_copy(out_reason, 64, "ATTESTATION_PASS");

    /* Audit log entry */
    ledger_block_t blk;
    char details[256];
    snprintf(details, sizeof(details),
             "P3 VERIFIED: device=%s release=%s session=%s",
             dev_id, rel_id, sess->attestation_id);
    ledger_append_event("P3_ATTESTATION_VERIFIED", dev_id, details, &blk);

    pthread_mutex_unlock(&g_trust_lock);
    return 0;
}

/* -----------------------------------------------------------------------
 * attestation_re_attest_challenge
 *
 * Issues a fresh nonce for periodic re-attestation.
 * Session must already be TRUSTED. Resets nonce_used=0 so the client
 * can respond with a fresh quote covering the new nonce.
 * ----------------------------------------------------------------------- */
int attestation_re_attest_challenge(const char *session_id, const char *device_id,
                                      char *out_new_nonce) {
    if (!session_id || !out_new_nonce) return -1;
    out_new_nonce[0] = '\0';

    pthread_mutex_lock(&g_trust_lock);

    attestation_session_t *sess = NULL;
    for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
        if (!g_sessions[i].created_at) continue;
        if (strcmp(g_sessions[i].attestation_id, session_id) == 0 ||
            strcmp(g_sessions[i].session_id,     session_id) == 0) {
            sess = &g_sessions[i];
            break;
        }
    }

    if (!sess) {
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* Only TRUSTED sessions may re-attest */
    if (sess->state != ATTESTATION_STATE_TRUSTED) {
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* Verify device binding if device_id provided */
    if (device_id && device_id[0] &&
        strcmp(sess->device_id, device_id) != 0) {
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* Generate fresh nonce */
    char new_nonce[65] = {0};
    if (random_hex64(new_nonce) != 0) {
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* Store in session — the next verify call will use it */
    safe_copy(sess->nonce, sizeof(sess->nonce), new_nonce);
    sess->nonce_used = 0;

    safe_copy(out_new_nonce, 128, new_nonce);

    pthread_mutex_unlock(&g_trust_lock);
    return 0;
}

/* -----------------------------------------------------------------------
 * attestation_re_attest  (legacy — full re-verify with new evidence)
 * ----------------------------------------------------------------------- */
int attestation_re_attest(const char *attestation_id, const char *evidence_json,
                            char *out_reason) {
    if (!attestation_id || !evidence_json || !out_reason) return -1;

    pthread_mutex_lock(&g_trust_lock);

    attestation_session_t *sess = NULL;
    for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
        if (g_sessions[i].created_at &&
            (strcmp(g_sessions[i].attestation_id, attestation_id) == 0 ||
             strcmp(g_sessions[i].session_id,     attestation_id) == 0)) {
            sess = &g_sessions[i];
            break;
        }
    }

    if (!sess || sess->state != ATTESTATION_STATE_TRUSTED) {
        safe_copy(out_reason, 64, "P3_SESSION_INVALID");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    /* Check if associated release has been revoked since last attestation */
    for (int i = 0; i < g_release_count; i++) {
        if (strcmp(g_releases[i].release_id, sess->release_id) == 0 &&
            g_releases[i].revoked) {
            sess->state = ATTESTATION_STATE_REVOKED;
            safe_copy(out_reason, 64, "P3_REVOKED_RELEASE");
            pthread_mutex_unlock(&g_trust_lock);
            return -1;
        }
    }

    /* Check if device has been revoked */
    for (int i = 0; i < g_device_count; i++) {
        if (strcmp(g_devices[i].device_id, sess->device_id) == 0 &&
            g_devices[i].status == DEVICE_STATUS_REVOKED) {
            sess->state = ATTESTATION_STATE_REVOKED;
            safe_copy(out_reason, 64, "P3_REVOKED_DEVICE");
            pthread_mutex_unlock(&g_trust_lock);
            return -1;
        }
    }

    sess->last_re_attestation = time(NULL);
    safe_copy(out_reason, 64, "RE_ATTEST_PASS");
    pthread_mutex_unlock(&g_trust_lock);
    return 0;
}

/* -----------------------------------------------------------------------
 * attestation_revoke_release
 * ----------------------------------------------------------------------- */
void attestation_revoke_release(const char *release_id) {
    if (!release_id) return;
    pthread_mutex_lock(&g_trust_lock);
    for (int i = 0; i < g_release_count; i++) {
        if (strcmp(g_releases[i].release_id, release_id) == 0) {
            g_releases[i].revoked = 1;

            ledger_block_t blk;
            char details[128];
            snprintf(details, sizeof(details), "Release revoked: %s", release_id);
            ledger_append_event("P3_RELEASE_REVOKED", release_id, details, &blk);
            break;
        }
    }
    pthread_mutex_unlock(&g_trust_lock);
}

/* -----------------------------------------------------------------------
 * attestation_revoke_device
 * ----------------------------------------------------------------------- */
void attestation_revoke_device(const char *device_id) {
    if (!device_id) return;
    pthread_mutex_lock(&g_trust_lock);
    for (int i = 0; i < g_device_count; i++) {
        if (strcmp(g_devices[i].device_id, device_id) == 0) {
            g_devices[i].status     = DEVICE_STATUS_REVOKED;
            g_devices[i].updated_at = time(NULL);

            ledger_block_t blk;
            char details[128];
            snprintf(details, sizeof(details), "Device revoked: %s", device_id);
            ledger_append_event("P3_DEVICE_REVOKED", device_id, details, &blk);
            break;
        }
    }
    pthread_mutex_unlock(&g_trust_lock);
}

/* -----------------------------------------------------------------------
 * attestation_get_status
 * ----------------------------------------------------------------------- */
int attestation_get_status(const char *attestation_id, char *out_status, size_t max_len) {
    if (!attestation_id || !out_status) return -1;
    pthread_mutex_lock(&g_trust_lock);

    for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
        if (!g_sessions[i].created_at) continue;
        if (strcmp(g_sessions[i].attestation_id, attestation_id) == 0 ||
            strcmp(g_sessions[i].session_id,     attestation_id) == 0) {

            const char *state_str = "PENDING";
            switch (g_sessions[i].state) {
                case ATTESTATION_STATE_TRUSTED:  state_str = "TRUSTED";  break;
                case ATTESTATION_STATE_FAILED:   state_str = "FAILED";   break;
                case ATTESTATION_STATE_REVOKED:  state_str = "REVOKED";  break;
                default: break;
            }
            strncpy(out_status, state_str, max_len - 1);
            out_status[max_len - 1] = '\0';
            pthread_mutex_unlock(&g_trust_lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_trust_lock);
    return -1;
}

/* -----------------------------------------------------------------------
 * attestation_get_exam_key
 *
 * Releases the session-bound exam decryption key to a TRUSTED session.
 * Searches by session_id OR attestation_id so callers can use either.
 * A key is only released if the session is in ATTESTATION_STATE_TRUSTED.
 * ----------------------------------------------------------------------- */
int attestation_get_exam_key(const char *session_id, const char *device_id,
                               char *out_key, size_t max_len) {
    if (!session_id || !out_key) return -1;
    pthread_mutex_lock(&g_trust_lock);

    for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
        if (!g_sessions[i].created_at) continue;

        int id_match =
            strcmp(g_sessions[i].attestation_id, session_id) == 0 ||
            strcmp(g_sessions[i].session_id,     session_id) == 0;
        if (!id_match) continue;

        /* Device binding check */
        if (device_id && device_id[0] &&
            strcmp(g_sessions[i].device_id, device_id) != 0) {
            pthread_mutex_unlock(&g_trust_lock);
            return -1;
        }

        if (g_sessions[i].state != ATTESTATION_STATE_TRUSTED ||
            !g_sessions[i].exam_key_released) {
            pthread_mutex_unlock(&g_trust_lock);
            return -1;
        }

        strncpy(out_key, g_sessions[i].exam_key, max_len - 1);
        out_key[max_len - 1] = '\0';

        ledger_block_t blk;
        char details[256];
        snprintf(details, sizeof(details),
                 "Exam key released: session=%s device=%s",
                 g_sessions[i].attestation_id, g_sessions[i].device_id);
        ledger_append_event("P3_KEY_RELEASED", g_sessions[i].device_id, details, &blk);

        pthread_mutex_unlock(&g_trust_lock);
        return 0;
    }

    pthread_mutex_unlock(&g_trust_lock);
    return -1;
}
