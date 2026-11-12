/*
 * attestation_service.c — ExamOS Phase 3 Attestation Engine
 *
 * Production attestation requires authenticated device/release registries,
 * the TPM quote verifier, and PostgreSQL-backed replay-safe state.
 *
 * No default devices or release measurements are trusted at startup.
 */
#define _GNU_SOURCE
#include "../include/attestation_service.h"
#include "../include/ledger.h"
#include "../include/tpm_quote.h"
#include "../include/admin_auth_store.h"
#include "../include/enterprise_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* -----------------------------------------------------------------------
 * Exam-key sealing
 *
 * The exam decryption key must survive a server restart, so it is stored
 * durably. It is never stored in the clear: it is sealed with AES-256-GCM
 * under a key-encryption key derived from EXAMOS_EXAM_KEY_KEK. A release
 * is only ever unsealed for a challenge that is TRUSTED, unrevoked, and
 * bound to the requesting device.
 * ----------------------------------------------------------------------- */
#define EXAM_KEY_KEK_BYTES   32
#define EXAM_KEY_KEK_LABEL   "examos-exam-key-kek-v1"
#define EXAM_KEY_SEAL_ID     "aes-256-gcm/v1"
#define EXAM_KEY_NONCE_BYTES 12
#define EXAM_KEY_TAG_BYTES   16

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

typedef struct {
    char attestation_id[64];
    char device_id[64];
    char institution_id[64];
    char nonce[128];
    char ak_public_pem[2048];
    char quote_signature_hex[2049];
    char pcr_digest_hex[65];
    char pcr_values_json[384];
} institution_attestation_evidence_t;

/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------
 * Exam-key sealing helpers
 * ------------------------------------------------------------------------- */

/*
 * Derives the key-encryption key from the provisioned secret. The raw secret
 * is never used directly as a key: it is run through HMAC with a fixed
 * domain-separation label so it cannot collide with any other subsystem.
 */
static int derive_exam_key_kek(unsigned char kek[EXAM_KEY_KEK_BYTES]) {
    const char *secret = getenv("EXAMOS_EXAM_KEY_KEK");
    if (!secret || !secret[0]) return -1;
    size_t secret_len = strlen(secret);
    if (secret_len < 32 || secret_len > 256) return -1;

    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), secret, (int)secret_len,
              (const unsigned char *)EXAM_KEY_KEK_LABEL, strlen(EXAM_KEY_KEK_LABEL),
              kek, &out_len)) {
        return -1;
    }
    if (out_len != EXAM_KEY_KEK_BYTES) return -1;
    return 0;
}

static int seal_exam_key(const unsigned char plain[32], const unsigned char kek[32],
                         unsigned char ciphertext[32],
                         unsigned char nonce[EXAM_KEY_NONCE_BYTES],
                         unsigned char tag[EXAM_KEY_TAG_BYTES]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int out_len = 0, final_len = 0;
    int ok = (RAND_bytes(nonce, EXAM_KEY_NONCE_BYTES) == 1) &&
             (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1) &&
             (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                  EXAM_KEY_NONCE_BYTES, NULL) == 1) &&
             (EVP_EncryptInit_ex(ctx, NULL, NULL, kek, nonce) == 1) &&
             (EVP_EncryptUpdate(ctx, ciphertext, &out_len, plain, 32) == 1) &&
             (out_len == 32) &&
             (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) == 1) &&
             (final_len == 0) &&
             (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                  EXAM_KEY_TAG_BYTES, tag) == 1);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int open_exam_key(const unsigned char ciphertext[32],
                         const unsigned char nonce[EXAM_KEY_NONCE_BYTES],
                         const unsigned char tag[EXAM_KEY_TAG_BYTES],
                         const unsigned char kek[32],
                         unsigned char plain[32]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int out_len = 0, final_len = 0;
    int ok = (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1) &&
             (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                  EXAM_KEY_NONCE_BYTES, NULL) == 1) &&
             (EVP_DecryptInit_ex(ctx, NULL, NULL, kek, nonce) == 1) &&
             (EVP_DecryptUpdate(ctx, plain, &out_len, ciphertext, 32) == 1) &&
             (out_len == 32) &&
             (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                  EXAM_KEY_TAG_BYTES, (void *)tag) == 1) &&
             (EVP_DecryptFinal_ex(ctx, plain + out_len, &final_len) == 1) &&
             (final_len == 0);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int is_sha256_hex(const char *value) {
    if (!value || strlen(value) != 64) return 0;
    for (size_t i = 0; i < 64; i++) {
        const char c = value[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) return 0;
    }
    return 1;
}

static int decode_hex_bytes(const char *hex, unsigned char **out, size_t *out_len,
                            size_t maximum_bytes) {
    if (!hex || !out || !out_len) return -1;
    size_t hex_len = strlen(hex);
    if (hex_len == 0 || (hex_len & 1) != 0 || hex_len / 2 > maximum_bytes)
        return -1;
    size_t bytes = hex_len / 2;
    unsigned char *decoded = malloc(bytes);
    if (!decoded) return -1;
    for (size_t i = 0; i < bytes; ++i) {
        unsigned char a = (unsigned char)hex[i * 2];
        unsigned char b = (unsigned char)hex[i * 2 + 1];
        int hi = isdigit(a) ? a - '0' :
            (tolower(a) >= 'a' && tolower(a) <= 'f' ? tolower(a) - 'a' + 10 : -1);
        int lo = isdigit(b) ? b - '0' :
            (tolower(b) >= 'a' && tolower(b) <= 'f' ? tolower(b) - 'a' + 10 : -1);
        if (hi < 0 || lo < 0) {
            OPENSSL_clear_free(decoded, bytes);
            return -1;
        }
        decoded[i] = (unsigned char)((hi << 4) | lo);
    }
    *out = decoded;
    *out_len = bytes;
    return 0;
}

static int production_attestation_mode(void) {
    const char *mode = getenv("EXAMOS_TPM_MODE");
    return mode && strcmp(mode, "production") == 0;
}

static int hash_nonce_hex(const char *nonce, char out_hash[65]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (!nonce || strlen(nonce) != 64 ||
        EVP_Digest(nonce, strlen(nonce), digest, &digest_len,
                   EVP_sha256(), NULL) != 1 || digest_len != 32) return -1;
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out_hash[i * 2] = digits[digest[i] >> 4];
        out_hash[i * 2 + 1] = digits[digest[i] & 15];
    }
    out_hash[64] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static int valid_identifier(const char *value) {
    if (!value || !value[0] || strlen(value) > 63) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' ||
              *p == ':' || *p == '-')) return 0;
    return 1;
}

static int persist_revocation(const char *type, const char *identifier,
                              const char *reason) {
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    const char *params[] = {type, identifier, reason};
    PGresult *result = PQexecParams(conn,
        "INSERT INTO examos_attestation_revocations(target_type,target_id,reason) "
        "VALUES($1,$2,$3) ON CONFLICT(target_type,target_id) DO UPDATE "
        "SET reason=EXCLUDED.reason,revoked_at=clock_timestamp()",
        3, NULL, params, NULL, NULL, 0);
    int ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (ok) {
        const char *state_params[] = {type, identifier, reason};
        result = PQexecParams(conn,
            "UPDATE examos_attestation_challenges SET state='REVOKED',failure_code=$3 "
            "WHERE (($1='DEVICE' AND device_id=$2) OR "
            "($1='RELEASE' AND release_id=$2)) "
            "AND state IN ('PENDING','VERIFYING','TRUSTED')",
            3, NULL, state_params, NULL, NULL, 0);
        ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
    }
    release_db_connection(conn, 0);
    return ok ? 0 : -1;
}

static int persistently_revoked(const char *type, const char *identifier) {
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    const char *params[] = {type, identifier};
    PGresult *result = PQexecParams(conn,
        "SELECT 1 FROM examos_attestation_revocations "
        "WHERE target_type=$1 AND target_id=$2",
        2, NULL, params, NULL, NULL, 0);
    int status = result && PQresultStatus(result) == PGRES_TUPLES_OK
        ? (PQntuples(result) == 1 ? 1 : 0) : -1;
    if (result) PQclear(result);
    release_db_connection(conn, 0);
    return status;
}

static int persist_challenge(const attestation_session_t *session) {
    char nonce_hash[65];
    if (!session || !session->session_id[0] || !session->device_id[0] ||
        !session->release_id[0] || !session->institution_id[0] ||
        !session->purpose[0] || !session->created_by[0] ||
        hash_nonce_hex(session->nonce, nonce_hash) != 0) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    PGresult *result = PQexec(conn, "BEGIN");
    int ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (ok) {
        const char *params[] = {
            session->session_id, session->device_id, session->institution_id
        };
        result = PQexecParams(conn,
            "UPDATE examos_attestation_challenges SET state='STALE', "
            "failure_code='RE_ATTESTATION_STARTED' "
            "WHERE session_id=$1 AND device_id=$2 AND institution_id=$3 "
            "AND state='TRUSTED'",
            3, NULL, params, NULL, NULL, 0);
        ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
    }
    if (ok) {
        char created[32];
        snprintf(created, sizeof(created), "%lld", (long long)session->created_at);
        const char *params[] = {session->attestation_id, session->session_id,
            session->device_id, session->release_id, session->institution_id,
            session->purpose, session->created_by, nonce_hash, created};
        result = PQexecParams(conn,
            "INSERT INTO examos_attestation_challenges "
            "(attestation_id,session_id,device_id,release_id,institution_id,purpose,created_by,nonce_sha256,state,created_at,expires_at) "
            "SELECT $1::varchar(63),$2::varchar(63),$3::varchar(63),$4::varchar(63),"
            "d.institution_id,$6::varchar(32),$7::varchar(64),$8,'PENDING',"
            "to_timestamp($9::double precision), "
            "to_timestamp($9::double precision)+interval '120 seconds' "
            "FROM devices d "
            "JOIN device_registrations r ON r.device_id=d.id "
            "AND r.institution_id=d.institution_id AND r.decision='approved' "
            "JOIN device_trust_policies p ON p.institution_id=d.institution_id "
            "AND p.status='active' "
            "WHERE d.id=$3 AND d.institution_id=$5 "
            "AND d.institution_id<>'' AND d.status IN ('registered','enrolled') "
            "AND (NOT EXISTS (SELECT 1 FROM exam_sessions s WHERE s.id=$2) "
            "OR EXISTS (SELECT 1 FROM exam_sessions s "
            "WHERE s.id=$2 AND s.device_id=d.id "
            "AND s.institution_id=d.institution_id "
            "AND s.status IN ('pending','authorized','launching','active','interrupted','resuming') "
            "AND EXISTS (SELECT 1 FROM candidate_exam_checkins ci "
            "WHERE ci.exam_session_id=$2 AND ci.institution_id=d.institution_id "
            "AND ci.status IN ('attesting','consumed') "
            "AND (ci.status='consumed' OR "
            "ci.expires_at>EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000)))) "
            "AND NOT EXISTS (SELECT 1 FROM examos_attestation_revocations "
            "WHERE (target_type='DEVICE' AND target_id=$3) OR "
            "(target_type='RELEASE' AND target_id=$4))",
            9, NULL, params, NULL, NULL, 0);
        ok = result && PQresultStatus(result) == PGRES_COMMAND_OK &&
             strcmp(PQcmdTuples(result), "1") == 0;
        if (result) PQclear(result);
    }
    result = PQexec(conn, ok ? "COMMIT" : "ROLLBACK");
    if (!result || PQresultStatus(result) != PGRES_COMMAND_OK) ok = 0;
    if (result) PQclear(result);
    release_db_connection(conn, ok ? 0 : 0);
    OPENSSL_cleanse(nonce_hash, sizeof(nonce_hash));
    return ok ? 0 : -1;
}

static int claim_persisted_challenge(const char *nonce, const char *device_id,
                                     const char *release_id,
                                     const char *institution_id,
                                     const char *purpose,
                                     char out_attestation_id[64],
                                     char out_session_id[64],
                                     int *out_exam_session_bound) {
    char nonce_hash[65];
    if (!institution_id || !institution_id[0] || !purpose || !purpose[0] ||
        hash_nonce_hex(nonce, nonce_hash) != 0) return -1;
    if (out_exam_session_bound) *out_exam_session_bound = 0;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    const char *params[] = {
        nonce_hash, device_id, release_id, institution_id, purpose
    };
    PGresult *result = PQexecParams(conn,
        "UPDATE examos_attestation_challenges AS c "
        "SET state='VERIFYING',claimed_at=clock_timestamp() "
        "WHERE c.nonce_sha256=$1 AND c.device_id=$2 AND c.release_id=$3 "
        "AND c.institution_id=$4 AND c.purpose=$5 "
        "AND c.state='PENDING' AND c.expires_at>clock_timestamp() "
        "AND (NOT EXISTS (SELECT 1 FROM exam_sessions s WHERE s.id=c.session_id) "
        "OR EXISTS (SELECT 1 FROM exam_sessions s "
        "WHERE s.id=c.session_id AND s.device_id=c.device_id "
        "AND s.institution_id=c.institution_id "
        "AND s.status IN ('pending','authorized','launching','active','interrupted','resuming') "
        "AND EXISTS (SELECT 1 FROM candidate_exam_checkins ci "
        "WHERE ci.exam_session_id=c.session_id AND ci.institution_id=c.institution_id "
        "AND ci.status IN ('attesting','consumed') "
        "AND (ci.status='consumed' OR "
        "ci.expires_at>EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000)))) "
        "AND NOT EXISTS (SELECT 1 FROM examos_attestation_revocations r "
        "WHERE (r.target_type='DEVICE' AND r.target_id=c.device_id) OR "
        "(r.target_type='RELEASE' AND r.target_id=c.release_id)) "
        "RETURNING c.attestation_id, c.session_id, "
        "EXISTS (SELECT 1 FROM exam_sessions s "
        "JOIN candidate_exam_checkins ci ON ci.exam_session_id=s.id "
        "AND ci.institution_id=s.institution_id "
        "WHERE s.id=c.session_id AND s.device_id=c.device_id "
        "AND s.institution_id=c.institution_id "
        "AND s.status IN ('pending','authorized','launching','active','interrupted','resuming') "
        "AND ci.status IN ('attesting','consumed') "
        "AND (ci.status='consumed' OR "
        "ci.expires_at>EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000))",
        5, NULL, params, NULL, NULL, 0);
    int claimed = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
                  PQntuples(result) == 1;
    if (claimed) {
        snprintf(out_attestation_id, 64, "%s", PQgetvalue(result, 0, 0));
        snprintf(out_session_id, 64, "%s", PQgetvalue(result, 0, 1));
        if (out_exam_session_bound)
            *out_exam_session_bound = strcmp(PQgetvalue(result, 0, 2), "t") == 0;
    }
    if (result) PQclear(result);
    release_db_connection(conn, 0);
    OPENSSL_cleanse(nonce_hash, sizeof(nonce_hash));
    return claimed ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Durable exam-key release records
 * ------------------------------------------------------------------------- */

/*
 * Seals the exam key and stores it against the attestation challenge that
 * produced it. The record is written in the same transaction as the release
 * decision so a key can never exist without a bound, TRUSTED challenge.
 */
static int persist_exam_key_release(const char *attestation_id,
                                    const char *session_id,
                                    const char *device_id,
                                    const char *release_id,
                                    const unsigned char plain_key[32]) {
    unsigned char kek[EXAM_KEY_KEK_BYTES];
    unsigned char ciphertext[32];
    unsigned char nonce[EXAM_KEY_NONCE_BYTES];
    unsigned char tag[EXAM_KEY_TAG_BYTES];
    int rc = -1;

    if (derive_exam_key_kek(kek) != 0) {
        fprintf(stderr, "[Attestation] FATAL: EXAMOS_EXAM_KEY_KEK is not provisioned; exam keys cannot be sealed.\n");
        return -1;
    }
    if (seal_exam_key(plain_key, kek, ciphertext, nonce, tag) != 0) {
        OPENSSL_cleanse(kek, sizeof(kek));
        return -1;
    }

    PGconn *conn = acquire_db_connection();
    if (!conn) { OPENSSL_cleanse(kek, sizeof(kek)); return -1; }

    const char *params[8];
    int param_lengths[8] = {0, 0, 0, 0, 32, EXAM_KEY_NONCE_BYTES, EXAM_KEY_TAG_BYTES, 0};
    int param_formats[8] = {0, 0, 0, 0, 1, 1, 1, 0};
    Oid param_types[8] = {0, 0, 0, 0, 17, 17, 17, 0};
    params[0] = attestation_id;
    params[1] = session_id;
    params[2] = device_id;
    params[3] = release_id;
    params[4] = (const char *)ciphertext;
    params[5] = (const char *)nonce;
    params[6] = (const char *)tag;
    params[7] = EXAM_KEY_SEAL_ID;

    PGresult *result = PQexecParams(conn,
        "INSERT INTO examos_exam_key_releases "
        "(attestation_id, session_id, device_id, release_id, "
        " key_ciphertext, key_nonce, key_tag, kek_id) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8) "
        "ON CONFLICT (attestation_id) DO UPDATE SET "
        " key_ciphertext=EXCLUDED.key_ciphertext, "
        " key_nonce=EXCLUDED.key_nonce, "
        " key_tag=EXCLUDED.key_tag, "
        " kek_id=EXCLUDED.kek_id, "
        " released_at=clock_timestamp(), revoked_at=NULL",
        8, param_types, params, param_lengths, param_formats, 0);
    rc = (result && PQresultStatus(result) == PGRES_COMMAND_OK) ? 0 : -1;
    if (result) PQclear(result);
    release_db_connection(conn, rc == 0 ? 0 : 1);

    OPENSSL_cleanse(kek, sizeof(kek));
    OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(tag, sizeof(tag));
    return rc;
}

/*
 * Loads and unseals the exam key for a trusted session. The key is released
 * only when the bound challenge is still TRUSTED, has not been revoked, and
 * the requesting device matches the device that produced the quote.
 */
static int load_exam_key_release(const char *identifier, const char *device_id,
                                 char *out_key_hex, size_t max_len) {
    if (!identifier || !identifier[0] || !out_key_hex || max_len < EXAM_KEY_LEN + 1)
        return -1;
    out_key_hex[0] = '\0';

    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;

    const char *params[2];
    params[0] = identifier;
    params[1] = device_id && device_id[0] ? device_id : "";
    PGresult *result = PQexecParams(conn,
        "SELECT k.attestation_id, k.device_id, k.key_ciphertext, k.key_nonce, k.key_tag "
        "FROM examos_exam_key_releases k "
        "JOIN examos_attestation_challenges c ON c.attestation_id = k.attestation_id "
        "JOIN exam_sessions s ON s.id=k.session_id AND s.device_id=k.device_id "
        "AND s.institution_id=c.institution_id "
        "AND s.status IN ('pending','authorized','launching','active','interrupted','resuming') "
        "JOIN candidate_exam_checkins ci ON ci.exam_session_id=s.id "
        "AND ci.institution_id=s.institution_id "
        "AND ci.status IN ('attesting','consumed') "
        "AND (ci.status='consumed' OR "
        "ci.expires_at>EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000) "
        "WHERE (k.session_id=$1 OR k.attestation_id=$1) "
        "AND k.device_id=$2 "
        "AND k.revoked_at IS NULL "
        "AND c.state='TRUSTED' "
        "AND c.verified_at > clock_timestamp() - interval '10 minutes' "
        "AND NOT EXISTS (SELECT 1 FROM examos_attestation_challenges newer "
        "WHERE newer.session_id=c.session_id AND newer.created_at>c.created_at) "
        "AND NOT EXISTS (SELECT 1 FROM examos_attestation_revocations r "
        "WHERE (r.target_type='DEVICE' AND r.target_id=k.device_id) OR "
        "(r.target_type='RELEASE' AND r.target_id=k.release_id)) "
        "ORDER BY k.released_at DESC LIMIT 1",
        2, NULL, params, NULL, NULL, 0);

    int rc = -1;
    unsigned char kek[EXAM_KEY_KEK_BYTES];
    unsigned char plain[32];

    if (result && PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1) {
        const char *ct_hex = PQgetvalue(result, 0, 2);
        const char *nonce_hex = PQgetvalue(result, 0, 3);
        const char *tag_hex = PQgetvalue(result, 0, 4);
        size_t ct_len = strlen(ct_hex), nonce_len = strlen(nonce_hex), tag_len = strlen(tag_hex);
        if (ct_len == 64 && nonce_len == 24 && tag_len == 32 &&
            derive_exam_key_kek(kek) == 0) {
            unsigned char ciphertext[32], nonce[12], tag[16];
            int decoded = 1;
            for (size_t i = 0; i < 32; i++) {
                unsigned int v = 0;
                if (sscanf(ct_hex + i * 2, "%2x", &v) != 1) { decoded = 0; break; }
                ciphertext[i] = (unsigned char)v;
            }
            for (size_t i = 0; i < 12 && decoded; i++) {
                unsigned int v = 0;
                if (sscanf(nonce_hex + i * 2, "%2x", &v) != 1) { decoded = 0; break; }
                nonce[i] = (unsigned char)v;
            }
            for (size_t i = 0; i < 16 && decoded; i++) {
                unsigned int v = 0;
                if (sscanf(tag_hex + i * 2, "%2x", &v) != 1) { decoded = 0; break; }
                tag[i] = (unsigned char)v;
            }
            if (decoded && open_exam_key(ciphertext, nonce, tag, kek, plain) == 0) {
                for (int i = 0; i < 32; i++)
                    sprintf(out_key_hex + i * 2, "%02x", plain[i]);
                out_key_hex[64] = '\0';
                rc = 0;
            }
            OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
            OPENSSL_cleanse(nonce, sizeof(nonce));
            OPENSSL_cleanse(tag, sizeof(tag));
        }
    }
    if (result) PQclear(result);
    release_db_connection(conn, 0);

    OPENSSL_cleanse(kek, sizeof(kek));
    OPENSSL_cleanse(plain, sizeof(plain));
    return rc;
}

static int persist_institution_attestation_evidence(
    PGconn *conn, const institution_attestation_evidence_t *evidence) {
    if (!conn || !evidence || !evidence->attestation_id[0] ||
        !evidence->device_id[0] || !evidence->institution_id[0] ||
        !evidence->nonce[0] || !evidence->ak_public_pem[0] ||
        !evidence->quote_signature_hex[0] || !evidence->pcr_digest_hex[0] ||
        !evidence->pcr_values_json[0]) return -1;

    const char *lookup_params[] = {
        evidence->device_id, evidence->institution_id, evidence->ak_public_pem
    };
    PGresult *lookup = PQexecParams(conn,
        "SELECT k.id FROM devices d "
        "JOIN device_attestation_keys k ON k.device_id=d.id AND k.status='active' "
        " AND k.public_key_pem=$3 "
        "JOIN device_registrations r ON r.device_id=d.id "
        " AND r.institution_id=d.institution_id AND r.decision='approved' "
        "JOIN device_trust_policies p ON p.institution_id=d.institution_id "
        " AND p.status='active' "
        "WHERE d.id=$1 AND d.institution_id=$2 "
        " AND d.status IN ('registered','enrolled') "
        "GROUP BY k.id HAVING COUNT(DISTINCT p.id)=1 "
        " AND COUNT(DISTINCT r.id)=1",
        3, NULL, lookup_params, NULL, NULL, 0);
    if (!lookup || PQresultStatus(lookup) != PGRES_TUPLES_OK) {
        if (lookup) PQclear(lookup);
        return -1;
    }
    if (PQntuples(lookup) == 0) {
        fprintf(stderr,
                "[Attestation] Institution readiness evidence was not persisted: "
                "device registration, AK, approval, or active-policy binding is incomplete.\n");
        PQclear(lookup);
        return -1;
    }
    if (PQntuples(lookup) != 1) {
        PQclear(lookup);
        return -1;
    }

    char key_id[64];
    snprintf(key_id, sizeof(key_id), "%s", PQgetvalue(lookup, 0, 0));
    PQclear(lookup);

    char evidence_id[64];
    snprintf(evidence_id, sizeof(evidence_id), "ev_%.58s",
             evidence->attestation_id);
    const char *challenge_params[] = {
        evidence->attestation_id, evidence->device_id, evidence->nonce
    };
    PGresult *insert_challenge = PQexecParams(conn,
        "INSERT INTO device_attestation_challenges "
        "(id,device_id,nonce,used,expires_at,created_at) "
        "VALUES ($1,$2,$3,TRUE,"
        "EXTRACT(EPOCH FROM clock_timestamp())::BIGINT*1000,"
        "EXTRACT(EPOCH FROM clock_timestamp())::BIGINT*1000)",
        3, NULL, challenge_params, NULL, NULL, 0);
    if (!insert_challenge ||
        PQresultStatus(insert_challenge) != PGRES_COMMAND_OK ||
        strcmp(PQcmdTuples(insert_challenge), "1") != 0) {
        if (insert_challenge) PQclear(insert_challenge);
        return -1;
    }
    PQclear(insert_challenge);

    char verified_at[32];
    snprintf(verified_at, sizeof(verified_at), "%lld",
             (long long)time(NULL) * 1000);
    const char *evidence_params[] = {
        evidence_id, evidence->device_id, evidence->attestation_id, key_id,
        evidence->quote_signature_hex, evidence->pcr_digest_hex,
        evidence->pcr_values_json, verified_at
    };
    PGresult *insert_evidence = PQexecParams(conn,
        "INSERT INTO device_attestation_evidence "
        "(id,device_id,challenge_id,ak_key_id,quote_signature,pcr_digest,"
        "pcr_values_json,verification_result,verified_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,'TRUSTED',$8::bigint)",
        8, NULL, evidence_params, NULL, NULL, 0);
    if (!insert_evidence ||
        PQresultStatus(insert_evidence) != PGRES_COMMAND_OK ||
        strcmp(PQcmdTuples(insert_evidence), "1") != 0) {
        if (insert_evidence) PQclear(insert_evidence);
        return -1;
    }
    PQclear(insert_evidence);

    const char *device_params[] = {
        evidence->device_id, verified_at, evidence->institution_id
    };
    PGresult *update_device = PQexecParams(conn,
        "UPDATE devices SET last_attestation_at=$2::bigint,"
        "updated_at=EXTRACT(EPOCH FROM NOW())::BIGINT*1000 "
        "WHERE id=$1 AND institution_id=$3",
        3, NULL, device_params, NULL, NULL, 0);
    if (!update_device || PQresultStatus(update_device) != PGRES_COMMAND_OK ||
        strcmp(PQcmdTuples(update_device), "1") != 0) {
        if (update_device) PQclear(update_device);
        return -1;
    }
    PQclear(update_device);
    return 0;
}

static int complete_persisted_challenge(
    const char *nonce, int verified, const char *failure_code,
    const institution_attestation_evidence_t *institution_evidence) {
    char nonce_hash[65];
    if (hash_nonce_hex(nonce, nonce_hash) != 0) return -1;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    PGresult *begin = PQexec(conn, "BEGIN");
    int ok = begin && PQresultStatus(begin) == PGRES_COMMAND_OK;
    if (begin) PQclear(begin);
    if (!ok) {
        release_db_connection(conn, 0);
        OPENSSL_cleanse(nonce_hash, sizeof(nonce_hash));
        return -1;
    }
    const char *state = verified ? "TRUSTED" : "FAILED";
    const char *reason = verified ? "" : failure_code;
    const char *params[] = {nonce_hash, state, reason};
    PGresult *result = PQexecParams(conn,
        "UPDATE examos_attestation_challenges SET state=$2,failure_code=$3, "
        "verified_at=CASE WHEN $2='TRUSTED' THEN clock_timestamp() ELSE NULL END "
        "WHERE nonce_sha256=$1 AND state='VERIFYING'",
        3, NULL, params, NULL, NULL, 0);
    int updated = result && PQresultStatus(result) == PGRES_COMMAND_OK &&
                  strcmp(PQcmdTuples(result), "1") == 0;
    if (result) PQclear(result);
    if (updated && verified && institution_evidence &&
        persist_institution_attestation_evidence(conn, institution_evidence) != 0)
        updated = 0;
    PGresult *finish = PQexec(conn, updated ? "COMMIT" : "ROLLBACK");
    if (!finish || PQresultStatus(finish) != PGRES_COMMAND_OK) updated = 0;
    if (finish) PQclear(finish);
    release_db_connection(conn, 0);
    OPENSSL_cleanse(nonce_hash, sizeof(nonce_hash));
    return updated ? 0 : -1;
}

static int persisted_attestation_status(const char *identifier,
                                        char *out_status, size_t max_len) {
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    PGresult *expire = PQexec(conn,
        "UPDATE examos_attestation_challenges SET state='STALE', "
        "failure_code='ATTESTATION_EXPIRED' "
        "WHERE state='TRUSTED' AND verified_at<=clock_timestamp()-interval '10 minutes'");
    int expiry_ok = expire && PQresultStatus(expire) == PGRES_COMMAND_OK;
    if (expire) PQclear(expire);
    if (!expiry_ok) { release_db_connection(conn, 0); return -1; }
    const char *params[] = {identifier};
    PGresult *result = PQexecParams(conn,
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM examos_attestation_revocations r "
        "WHERE (r.target_type='DEVICE' AND r.target_id=examos_attestation_challenges.device_id) "
        "OR (r.target_type='RELEASE' AND r.target_id=examos_attestation_challenges.release_id)) "
        "THEN 'REVOKED' ELSE state END FROM examos_attestation_challenges "
        "WHERE attestation_id=$1 OR session_id=$1 ORDER BY created_at DESC LIMIT 1",
        1, NULL, params, NULL, NULL, 0);
    int found = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
                PQntuples(result) == 1;
    if (found && max_len > 0)
        snprintf(out_status, max_len, "%s", PQgetvalue(result, 0, 0));
    if (result) PQclear(result);
    release_db_connection(conn, 0);
    return found ? 0 : -1;
}

static int persisted_re_attestation_source(const char *identifier,
                                            const char *requested_device,
                                            char out_device[64],
                                            char out_session[64],
                                            char out_release[64]) {
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    const char *params[] = {identifier};
    PGresult *result = PQexecParams(conn,
        "SELECT device_id,session_id,release_id,state FROM examos_attestation_challenges "
        "WHERE (attestation_id=$1 OR session_id=$1) "
        "AND NOT EXISTS (SELECT 1 FROM examos_attestation_revocations r "
        "WHERE (r.target_type='DEVICE' AND r.target_id=examos_attestation_challenges.device_id) "
        "OR (r.target_type='RELEASE' AND r.target_id=examos_attestation_challenges.release_id)) "
        "AND (state<>'TRUSTED' OR verified_at>clock_timestamp()-interval '10 minutes') "
        "ORDER BY created_at DESC LIMIT 1",
        1, NULL, params, NULL, NULL, 0);
    int valid = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
                PQntuples(result) == 1 &&
                strcmp(PQgetvalue(result, 0, 3), "TRUSTED") == 0 &&
                (!requested_device || !requested_device[0] ||
                 strcmp(PQgetvalue(result, 0, 0), requested_device) == 0);
    if (valid) {
        snprintf(out_device, 64, "%s", PQgetvalue(result, 0, 0));
        snprintf(out_session, 64, "%s", PQgetvalue(result, 0, 1));
        snprintf(out_release, 64, "%s", PQgetvalue(result, 0, 2));
    }
    if (result) PQclear(result);
    release_db_connection(conn, 0);
    return valid ? 0 : -1;
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

    pthread_mutex_unlock(&g_trust_lock);
    return 0;
}

/*
 * Read-only health probe for the attestation store. Unlike
 * attestation_store_init() it never mutates challenge state, so it is safe
 * to call on every readiness or health check.
 */
int attestation_store_health(void) {
    if (!production_attestation_mode()) return 0;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    PGresult *result = PQexec(conn,
        "SELECT to_regclass('public.examos_attestation_challenges') IS NOT NULL "
        "AND to_regclass('public.examos_attestation_revocations') IS NOT NULL "
        "AND to_regclass('public.examos_exam_key_releases') IS NOT NULL "
        "AND to_regclass('public.exam_sessions') IS NOT NULL "
        "AND to_regclass('public.candidate_exam_checkins') IS NOT NULL "
        "AND (SELECT COUNT(*)=3 FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='examos_attestation_challenges' "
        "AND column_name IN ('institution_id','purpose','created_by')) "
        "AND (SELECT COUNT(*)=4 FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='exam_sessions' "
        "AND column_name IN ('id','institution_id','device_id','status')) "
        "AND (SELECT COUNT(*)=4 FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='candidate_exam_checkins' "
        "AND column_name IN ('exam_session_id','institution_id','status','expires_at')) "
        "AND EXISTS (SELECT 1 FROM pg_constraint "
        "WHERE conrelid=to_regclass('public.examos_attestation_challenges') "
        "AND conname='examos_attestation_institution_nonempty_check') "
        "AND EXISTS (SELECT 1 FROM pg_constraint "
        "WHERE conrelid=to_regclass('public.examos_attestation_challenges') "
        "AND conname='examos_attestation_purpose_check')");
    int healthy = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
                  PQntuples(result) == 1 &&
                  strcmp(PQgetvalue(result, 0, 0), "t") == 0;
    if (result) PQclear(result);
    release_db_connection(conn, 0);
    return healthy ? 0 : -1;
}

int attestation_store_init(void) {    if (!production_attestation_mode()) return 0;
    PGconn *conn = acquire_db_connection();
    if (!conn) return -1;
    PGresult *result = PQexec(conn,
        "SELECT to_regclass('public.examos_attestation_challenges') IS NOT NULL "
        "AND to_regclass('public.examos_attestation_revocations') IS NOT NULL "
        "AND to_regclass('public.examos_exam_key_releases') IS NOT NULL "
        "AND to_regclass('public.exam_sessions') IS NOT NULL "
        "AND to_regclass('public.candidate_exam_checkins') IS NOT NULL "
        "AND (SELECT COUNT(*)=3 FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='examos_attestation_challenges' "
        "AND column_name IN ('institution_id','purpose','created_by')) "
        "AND (SELECT COUNT(*)=4 FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='exam_sessions' "
        "AND column_name IN ('id','institution_id','device_id','status')) "
        "AND (SELECT COUNT(*)=4 FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='candidate_exam_checkins' "
        "AND column_name IN ('exam_session_id','institution_id','status','expires_at')) "
        "AND EXISTS (SELECT 1 FROM pg_constraint "
        "WHERE conrelid=to_regclass('public.examos_attestation_challenges') "
        "AND conname='examos_attestation_institution_nonempty_check') "
        "AND EXISTS (SELECT 1 FROM pg_constraint "
        "WHERE conrelid=to_regclass('public.examos_attestation_challenges') "
        "AND conname='examos_attestation_purpose_check')");
    int ready = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
                PQntuples(result) == 1 && strcmp(PQgetvalue(result, 0, 0), "t") == 0;
    if (result) PQclear(result);
    if (ready) {
        result = PQexec(conn,
            "UPDATE examos_attestation_challenges SET state='FAILED', "
            "failure_code='SERVER_RESTARTED_DURING_VERIFICATION' "
            "WHERE state='VERIFYING'; "
            "UPDATE examos_attestation_challenges SET state='STALE', "
            "failure_code='CHALLENGE_EXPIRED' "
            "WHERE state='PENDING' AND expires_at<=clock_timestamp(); "
            "UPDATE examos_attestation_challenges SET state='STALE', "
            "failure_code='ATTESTATION_EXPIRED' "
            "WHERE state='TRUSTED' AND verified_at<=clock_timestamp()-interval '10 minutes'");
        ready = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
    }
    release_db_connection(conn, 0);
    if (!ready)
        fprintf(stderr, "[Attestation] Required PostgreSQL challenge-state schema is unavailable.\n");
    return ready ? 0 : -1;
}
/* -----------------------------------------------------------------------
 * attestation_register_device
 * ----------------------------------------------------------------------- */
int attestation_register_device(const char *device_id, const char *ek_fingerprint,
                                  const char *allowed_release) {
    return attestation_register_device_identity(device_id, ek_fingerprint,
                                                "", "", "", allowed_release);
}

int attestation_register_device_identity(const char *device_id,
                                          const char *ek_fingerprint,
                                          const char *ak_qualified_name,
                                          const char *ak_public_pem,
                                          const char *ak_public_sha256,
                                          const char *allowed_release) {
    return attestation_register_device_identity_for_institution(
        device_id, "", ek_fingerprint, ak_qualified_name, ak_public_pem,
        ak_public_sha256, allowed_release);
}

int attestation_register_device_identity_for_institution(
                                          const char *device_id,
                                          const char *institution_id,
                                          const char *ek_fingerprint,
                                          const char *ak_qualified_name,
                                          const char *ak_public_pem,
                                          const char *ak_public_sha256,
                                          const char *allowed_release) {
    if (!device_id || !device_id[0] || strlen(device_id) >= sizeof(g_devices[0].device_id) ||
        (institution_id && strlen(institution_id) >= sizeof(g_devices[0].institution_id) &&
         institution_id[0]) ||
        !is_sha256_hex(ek_fingerprint) || !allowed_release || !allowed_release[0] ||
        strlen(allowed_release) >= sizeof(g_devices[0].allowed_release)) return -1;

    const int has_ak_identity = ak_qualified_name && ak_qualified_name[0] &&
                                ak_public_pem && ak_public_pem[0] &&
                                ak_public_sha256 && ak_public_sha256[0];
    if ((ak_qualified_name && ak_qualified_name[0]) ||
        (ak_public_pem && ak_public_pem[0]) ||
        (ak_public_sha256 && ak_public_sha256[0])) {
        if (!has_ak_identity || strlen(ak_qualified_name) != 68 ||
            strncmp(ak_qualified_name, "000b", 4) != 0 ||
            !is_sha256_hex(ak_qualified_name + 4) ||
            !is_sha256_hex(ak_public_sha256) || strlen(ak_public_pem) >= 2048)
            return -1;

        BIO *bio = BIO_new_mem_buf(ak_public_pem, (int)strlen(ak_public_pem));
        EVP_PKEY *key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
        BIO_free(bio);
        unsigned char *der = NULL;
        int der_len = key ? i2d_PUBKEY(key, &der) : -1;
        unsigned char digest[EVP_MAX_MD_SIZE] = {0};
        unsigned int digest_len = 0;
        int valid = key && EVP_PKEY_base_id(key) == EVP_PKEY_RSA &&
            EVP_PKEY_bits(key) >= 2048 && der_len > 0 && der &&
            EVP_Digest(der, (size_t)der_len, digest, &digest_len,
                       EVP_sha256(), NULL) == 1 && digest_len == 32;
        char actual_hash[65] = {0};
        static const char hex[] = "0123456789abcdef";
        if (valid) {
            for (size_t i = 0; i < 32; ++i) {
                actual_hash[i * 2] = hex[digest[i] >> 4];
                actual_hash[i * 2 + 1] = hex[digest[i] & 15];
            }
        }
        for (size_t i = 0; valid && i < 64; ++i) {
            if ((unsigned char)tolower((unsigned char)ak_public_sha256[i]) !=
                (unsigned char)actual_hash[i]) valid = 0;
        }
        if (der) OPENSSL_clear_free(der, (size_t)der_len);
        if (key) EVP_PKEY_free(key);
        OPENSSL_cleanse(digest, sizeof(digest));
        if (!valid) return -1;
    }

    pthread_mutex_lock(&g_trust_lock);

    /* Update if already registered */
    for (int i = 0; i < g_device_count; i++) {
        if (strcmp(g_devices[i].device_id, device_id) == 0) {
            safe_copy(g_devices[i].ek_fingerprint, sizeof(g_devices[i].ek_fingerprint),
                      ek_fingerprint);
            safe_copy(g_devices[i].institution_id,
                      sizeof(g_devices[i].institution_id),
                      institution_id ? institution_id : "");
            g_devices[i].status = DEVICE_STATUS_ENROLLED;
            safe_copy(g_devices[i].allowed_release,
                      sizeof(g_devices[i].allowed_release), allowed_release);
            safe_copy(g_devices[i].ak_qualified_name,
                      sizeof(g_devices[i].ak_qualified_name),
                      has_ak_identity ? ak_qualified_name : "");
            safe_copy(g_devices[i].ak_public_pem,
                      sizeof(g_devices[i].ak_public_pem),
                      has_ak_identity ? ak_public_pem : "");
            g_devices[i].updated_at = time(NULL);
            pthread_mutex_unlock(&g_trust_lock);
            return 0;
        }
    }

    if (g_device_count < MAX_DEVICES) {
        enrolled_device_t *dev = &g_devices[g_device_count++];
        safe_copy(dev->device_id,      sizeof(dev->device_id),      device_id);
        safe_copy(dev->institution_id, sizeof(dev->institution_id),
                  institution_id ? institution_id : "");
        safe_copy(dev->ek_fingerprint, sizeof(dev->ek_fingerprint), ek_fingerprint);
        dev->status = DEVICE_STATUS_ENROLLED;
        safe_copy(dev->allowed_release, sizeof(dev->allowed_release),
                  allowed_release);
        safe_copy(dev->ak_qualified_name, sizeof(dev->ak_qualified_name),
                  has_ak_identity ? ak_qualified_name : "");
        safe_copy(dev->ak_public_pem, sizeof(dev->ak_public_pem),
                  has_ak_identity ? ak_public_pem : "");
        dev->created_at = time(NULL);
        pthread_mutex_unlock(&g_trust_lock);
        return 0;
    }

    pthread_mutex_unlock(&g_trust_lock);
    return -1;
}

int attestation_device_identity_matches(const char *device_id,
                                         const char *institution_id,
                                         const char *ak_public_pem) {
    if (!device_id || !device_id[0] || !institution_id || !institution_id[0] ||
        !ak_public_pem || !ak_public_pem[0]) return 0;
    int matches = 0;
    pthread_mutex_lock(&g_trust_lock);
    for (int i = 0; i < g_device_count; ++i) {
        const enrolled_device_t *device = &g_devices[i];
        if (strcmp(device->device_id, device_id) == 0 &&
            strcmp(device->institution_id, institution_id) == 0 &&
            strcmp(device->ak_public_pem, ak_public_pem) == 0 &&
            device->status != DEVICE_STATUS_SUSPENDED &&
            device->status != DEVICE_STATUS_REVOKED &&
            device->status != DEVICE_STATUS_RETIRED) {
            matches = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_trust_lock);
    return matches;
}

/* -----------------------------------------------------------------------
 * attestation_register_release
 * ----------------------------------------------------------------------- */
int attestation_register_release(const char *release_id, const char *uki_hash,
                                   const char *pcr0, const char *pcr4,
                                   const char *pcr7, const char *pcr11) {
    if (!release_id || !release_id[0] || strlen(release_id) >= sizeof(g_releases[0].release_id) ||
        !is_sha256_hex(uki_hash) || !is_sha256_hex(pcr0) || !is_sha256_hex(pcr4) ||
        !is_sha256_hex(pcr7) || !is_sha256_hex(pcr11)) return -1;
    pthread_mutex_lock(&g_trust_lock);

    for (int i = 0; i < g_release_count; i++) {
        if (strcmp(g_releases[i].release_id, release_id) == 0) {
            pthread_mutex_unlock(&g_trust_lock);
            return -1;
        }
    }

    if (g_release_count < MAX_RELEASES) {
        golden_release_t *rel = &g_releases[g_release_count++];
        safe_copy(rel->release_id, sizeof(rel->release_id), release_id);
        safe_copy(rel->uki_hash,   sizeof(rel->uki_hash),   uki_hash);
        safe_copy(rel->pcr0,       sizeof(rel->pcr0),       pcr0);
        safe_copy(rel->pcr4,       sizeof(rel->pcr4),       pcr4);
        safe_copy(rel->pcr7,       sizeof(rel->pcr7),       pcr7);
        safe_copy(rel->pcr11,      sizeof(rel->pcr11),      pcr11);
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
 *
 * The institution is derived from the trusted device registry. A caller may
 * provide the tenant as an additional consistency check, but cannot supply it.
 * ----------------------------------------------------------------------- */
int attestation_create_challenge(const char *device_id, const char *session_id,
                                   const char *release_id,
                                   const char *institution_id,
                                   const char *purpose,
                                   const char *created_by,
                                   char *out_nonce, char *out_attestation_id,
                                   char *out_error_code) {
    if (!device_id || !device_id[0] || strlen(device_id) >= sizeof(g_devices[0].device_id) ||
        !session_id || !session_id[0] || strlen(session_id) >= sizeof(g_sessions[0].session_id) ||
        !release_id || !release_id[0] || strlen(release_id) >= sizeof(g_sessions[0].release_id) ||
        !out_nonce || !out_attestation_id) return -1;
    if (out_error_code) out_error_code[0] = '\0';

    /* Set defaults for optional parameters */
    const char *requested_inst_id =
        (institution_id && institution_id[0]) ? institution_id : "";
    const char *inst_id = "";
    const char *ch_purpose = (purpose && purpose[0]) ? purpose : "re_attestation";
    const char *actor = (created_by && created_by[0]) ? created_by : "system";

    /* Validate purpose against allowed values */
    if (strcmp(ch_purpose, "enrollment") != 0 &&
        strcmp(ch_purpose, "re_attestation") != 0 &&
        strcmp(ch_purpose, "exam_launch") != 0) {
        if (out_error_code) safe_copy(out_error_code, 64, "P3_INVALID_PURPOSE");
        return -1;
    }

    if (production_attestation_mode()) {
        int device_revoked = persistently_revoked("DEVICE", device_id);
        int release_revoked = persistently_revoked("RELEASE", release_id);
        if (device_revoked < 0 || release_revoked < 0) {
            if (out_error_code) safe_copy(out_error_code, 64, "P3_REVOCATION_STORE_UNAVAILABLE");
            return -1;
        }
        if (device_revoked || release_revoked) {
            if (out_error_code) safe_copy(out_error_code, 64,
                device_revoked ? "P3_REVOKED_DEVICE" : "P3_REVOKED_RELEASE");
            return -1;
        }
    }

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

    if (!dev->institution_id[0]) {
        if (out_error_code) safe_copy(out_error_code, 64, "P3_DEVICE_TENANT_UNBOUND");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }
    if (requested_inst_id[0] &&
        strcmp(requested_inst_id, dev->institution_id) != 0) {
        if (out_error_code) safe_copy(out_error_code, 64, "P3_INSTITUTION_MISMATCH");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }
    inst_id = dev->institution_id;

    /* Step 2: Device must not be revoked */
    if (dev->status == DEVICE_STATUS_REVOKED) {
        if (out_error_code) safe_copy(out_error_code, 64, "P3_REVOKED_DEVICE");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    if (dev->status != DEVICE_STATUS_ENROLLED && dev->status != DEVICE_STATUS_TRUSTED) {
        if (out_error_code) safe_copy(out_error_code, 64, "P3_DEVICE_NOT_ENROLLED");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }
    if (strcmp(dev->allowed_release, release_id) != 0) {
        if (out_error_code) safe_copy(out_error_code, 64, "P3_RELEASE_NOT_ALLOWED");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }
    int release_found = 0;
    for (int i = 0; i < g_release_count; i++) {
        if (strcmp(g_releases[i].release_id, release_id) == 0 && !g_releases[i].revoked) {
            release_found = 1;
            break;
        }
    }
    if (!release_found) {
        if (out_error_code) safe_copy(out_error_code, 64, "P3_RELEASE_UNKNOWN_OR_REVOKED");
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
             "attest-%.32s", nonce);
    safe_copy(s->session_id,  sizeof(s->session_id), session_id);
    safe_copy(s->device_id,   sizeof(s->device_id),  device_id);
    safe_copy(s->release_id,  sizeof(s->release_id), release_id);
    safe_copy(s->institution_id, sizeof(s->institution_id), inst_id);
    safe_copy(s->nonce,       sizeof(s->nonce),       nonce);
    safe_copy(s->purpose,     sizeof(s->purpose),     ch_purpose);
    safe_copy(s->created_by,  sizeof(s->created_by),  actor);
    s->nonce_used  = 0;
    s->created_at  = time(NULL);
    s->state       = ATTESTATION_STATE_PENDING;

    safe_copy(out_nonce,          128, nonce);
    safe_copy(out_attestation_id, 64,  s->attestation_id);

    attestation_session_t persisted_copy = *s;

    pthread_mutex_unlock(&g_trust_lock);
    if (production_attestation_mode() && persist_challenge(&persisted_copy) != 0) {
        pthread_mutex_lock(&g_trust_lock);
        for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
            if (g_sessions[i].created_at &&
                strcmp(g_sessions[i].attestation_id, persisted_copy.attestation_id) == 0) {
                OPENSSL_cleanse(&g_sessions[i], sizeof(g_sessions[i]));
                break;
            }
        }
        pthread_mutex_unlock(&g_trust_lock);
        OPENSSL_cleanse(&persisted_copy, sizeof(persisted_copy));
        OPENSSL_cleanse(out_nonce, 128);
        OPENSSL_cleanse(out_attestation_id, 64);
        safe_copy(out_error_code, 64, "P3_CHALLENGE_STORE_UNAVAILABLE");
        return -1;
    }
    OPENSSL_cleanse(&persisted_copy, sizeof(persisted_copy));
    return 0;
}

/* -----------------------------------------------------------------------
 * attestation_verify_evidence
 *
 * TPM quote verification validates the TPM2 wire format, signature, nonce,
 * AK identity, and approved release PCR measurements. Production challenge
 * and revocation state are backed by PostgreSQL; key release is separate.
 * ----------------------------------------------------------------------- */
int attestation_verify_evidence(const char *evidence_json,
                                  const char *expected_purpose,
                                  char *out_reason, char *out_exam_key) {
    if (!out_reason) return -1;
    out_reason[0] = '\0';
    if (out_exam_key) out_exam_key[0] = '\0';
    if (!evidence_json) {
        safe_copy(out_reason, 64, "P3_MALFORMED_REQUEST");
        return -1;
    }
    if (!expected_purpose ||
        (strcmp(expected_purpose, "enrollment") != 0 &&
         strcmp(expected_purpose, "re_attestation") != 0 &&
         strcmp(expected_purpose, "exam_launch") != 0)) {
        safe_copy(out_reason, 64, "P3_INVALID_PURPOSE");
        return -1;
    }

    char nonce[128] = {0}, device_id[64] = {0}, release_id[64] = {0};
    char quote_message_hex[8193] = {0}, quote_signature_hex[2049] = {0};
    json_str(evidence_json, "device_id", device_id, sizeof(device_id));
    json_str(evidence_json, "release_id", release_id, sizeof(release_id));
    json_str(evidence_json, "nonce", nonce, sizeof(nonce));
    json_str(evidence_json, "quote_message_hex", quote_message_hex,
             sizeof(quote_message_hex));
    json_str(evidence_json, "quote_signature_hex", quote_signature_hex,
             sizeof(quote_signature_hex));
    if (!nonce[0] || !device_id[0] || !release_id[0] ||
        !quote_message_hex[0] || !quote_signature_hex[0]) {
        safe_copy(out_reason, 64, "P3_MALFORMED_REQUEST");
        return -1;
    }

    if (production_attestation_mode()) {
        enrolled_device_t production_device;
        golden_release_t production_release;
        int found_device = 0, found_release = 0;
        pthread_mutex_lock(&g_trust_lock);
        for (int i = 0; i < g_device_count; ++i) {
            if (strcmp(g_devices[i].device_id, device_id) == 0 &&
                (g_devices[i].status == DEVICE_STATUS_ENROLLED ||
                 g_devices[i].status == DEVICE_STATUS_TRUSTED)) {
                production_device = g_devices[i];
                found_device = 1;
                break;
            }
        }
        for (int i = 0; i < g_release_count; ++i) {
            if (strcmp(g_releases[i].release_id, release_id) == 0 &&
                !g_releases[i].revoked) {
                production_release = g_releases[i];
                found_release = 1;
                break;
            }
        }
        pthread_mutex_unlock(&g_trust_lock);
        if (!found_device || !found_release ||
            strcmp(production_device.allowed_release, release_id) != 0 ||
            !production_device.ak_qualified_name[0] ||
            !production_device.ak_public_pem[0]) {
            safe_copy(out_reason, 64, "P3_DEVICE_OR_RELEASE_NOT_TRUSTED");
            return -1;
        }

        char persisted_id[64] = {0};
        char persisted_session[64] = {0};
        int exam_session_bound = 0;
        if (claim_persisted_challenge(nonce, device_id, release_id,
                                      production_device.institution_id,
                                      expected_purpose,
                                      persisted_id, persisted_session,
                                      &exam_session_bound) != 0) {
            safe_copy(out_reason, 64, "P3_INVALID_OR_EXPIRED_NONCE");
            return -1;
        }

        /* Production attestation requires completed TPM credential activation. */
        PGconn *prov_conn = acquire_db_connection();
        if (!prov_conn) {
            if (complete_persisted_challenge(
                    nonce, 0, "P3_PROVENANCE_STORE_UNAVAILABLE", NULL) != 0) {
                safe_copy(out_reason, 64, "P3_ATTESTATION_STATE_STORE_FAILED");
                return -1;
            }
            safe_copy(out_reason, 64, "P3_PROVENANCE_STORE_UNAVAILABLE");
            return -1;
        }
        const char *prov_params[3] = {
            device_id, production_device.institution_id,
            production_device.ak_public_pem
        };
        PGresult *prov_result = PQexecParams(prov_conn,
            "SELECT 1 FROM device_attestation_keys k "
            "JOIN devices d ON d.id=k.device_id "
            "WHERE k.device_id=$1 AND d.institution_id=$2 "
            "AND k.public_key_pem=$3 AND k.key_name='AK' AND k.status='active' "
            "AND k.provenance_status='verified' "
            "AND k.provenance_details LIKE 'TPM2_CREDENTIAL_ACTIVATION_V1:%' "
            "LIMIT 1",
            3, NULL, prov_params, NULL, NULL, 0);
        int provenance_store_available = prov_result &&
            PQresultStatus(prov_result) == PGRES_TUPLES_OK;
        int provenance_verified = provenance_store_available &&
            PQntuples(prov_result) == 1;
        if (prov_result) PQclear(prov_result);
        release_db_connection(prov_conn, 0);
        if (!provenance_verified) {
            const char *provenance_failure = provenance_store_available
                ? "P3_PROVENANCE_NOT_VERIFIED"
                : "P3_PROVENANCE_STORE_UNAVAILABLE";
            if (complete_persisted_challenge(
                    nonce, 0, provenance_failure, NULL) != 0) {
                safe_copy(out_reason, 64, "P3_ATTESTATION_STATE_STORE_FAILED");
                return -1;
            }
            safe_copy(out_reason, 64, provenance_failure);
            return -1;
        }
        unsigned char *attest = NULL, *signature = NULL;
        size_t attest_len = 0, signature_len = 0;
        char pcr_digest_hex[65] = {0};
        int decoded = decode_hex_bytes(quote_message_hex, &attest,
                                       &attest_len, 4096) == 0 &&
                      decode_hex_bytes(quote_signature_hex, &signature,
                                       &signature_len, 1024) == 0;
        int verified = decoded && tpm_quote_verify_sha256_rsa_with_pcr_digest(
            attest, attest_len, signature, signature_len,
            production_device.ak_public_pem,
            production_device.ak_qualified_name, nonce,
            production_release.pcr0, production_release.pcr4,
            production_release.pcr7, production_release.pcr11,
            pcr_digest_hex, sizeof(pcr_digest_hex)) == 0;
        if (attest) OPENSSL_clear_free(attest, attest_len);
        if (signature) OPENSSL_clear_free(signature, signature_len);
        const char *failure = decoded ? "P3_INVALID_TPM_QUOTE"
                                      : "P3_MALFORMED_TPM_QUOTE";
        institution_attestation_evidence_t institution_evidence;
        institution_attestation_evidence_t *institution_evidence_ptr = NULL;
        memset(&institution_evidence, 0, sizeof(institution_evidence));
        if (verified && production_device.institution_id[0]) {
            safe_copy(institution_evidence.attestation_id,
                      sizeof(institution_evidence.attestation_id), persisted_id);
            safe_copy(institution_evidence.device_id,
                      sizeof(institution_evidence.device_id), device_id);
            safe_copy(institution_evidence.institution_id,
                      sizeof(institution_evidence.institution_id),
                      production_device.institution_id);
            safe_copy(institution_evidence.nonce,
                      sizeof(institution_evidence.nonce), nonce);
            safe_copy(institution_evidence.ak_public_pem,
                      sizeof(institution_evidence.ak_public_pem),
                      production_device.ak_public_pem);
            safe_copy(institution_evidence.quote_signature_hex,
                      sizeof(institution_evidence.quote_signature_hex),
                      quote_signature_hex);
            safe_copy(institution_evidence.pcr_digest_hex,
                      sizeof(institution_evidence.pcr_digest_hex),
                      pcr_digest_hex);
            snprintf(institution_evidence.pcr_values_json,
                     sizeof(institution_evidence.pcr_values_json),
                     "{\"pcr0\":\"%s\",\"pcr4\":\"%s\",\"pcr7\":\"%s\",\"pcr11\":\"%s\"}",
                     production_release.pcr0, production_release.pcr4,
                     production_release.pcr7, production_release.pcr11);
            institution_evidence_ptr = &institution_evidence;
        }
        if (complete_persisted_challenge(nonce, verified, failure,
                                         institution_evidence_ptr) != 0) {
            safe_copy(out_reason, 64, "P3_ATTESTATION_STATE_STORE_FAILED");
            return -1;
        }
        if (!verified) {
            safe_copy(out_reason, 64, failure);
            return -1;
        }

        if (!exam_session_bound) {
            platform_update_device_attestation(device_id, "TRUSTED", NULL);
            safe_copy(out_reason, 64, "TPM_QUOTE_VERIFIED");
            return 0;
        }

        /*
         * The challenge is TRUSTED. Generate the exam key, seal it, and bind
         * it durably to this challenge so that it can be released later
         * through the audited key-release path, including after a restart.
         */
        char prod_key[EXAM_KEY_LEN + 1] = {0};
        if (random_hex64(prod_key) != 0) {
            safe_copy(out_reason, 64, "P3_EXAM_KEY_GENERATION_FAILED");
            return -1;
        }
        unsigned char raw_key[32];
        int key_decoded = 1;
        for (int i = 0; i < 32; i++) {
            unsigned int v = 0;
            if (sscanf(prod_key + i * 2, "%2x", &v) != 1) { key_decoded = 0; break; }
            raw_key[i] = (unsigned char)v;
        }
        if (!key_decoded) {
            OPENSSL_cleanse(prod_key, sizeof(prod_key));
            safe_copy(out_reason, 64, "P3_EXAM_KEY_GENERATION_FAILED");
            return -1;
        }
        if (persist_exam_key_release(persisted_id, persisted_session,
                                     device_id, release_id, raw_key) != 0) {
            OPENSSL_cleanse(raw_key, sizeof(raw_key));
            OPENSSL_cleanse(prod_key, sizeof(prod_key));
            safe_copy(out_reason, 64, "P3_EXAM_KEY_RELEASE_PERSIST_FAILED");
            return -1;
        }
        OPENSSL_cleanse(raw_key, sizeof(raw_key));

        /* Mirror the trusted session into the in-process session table so
           that in-process status and re-attestation see the same state. */
        pthread_mutex_lock(&g_trust_lock);
        for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
            attestation_session_t *sess = &g_sessions[i];
            if (sess->created_at && strcmp(sess->attestation_id, persisted_id) == 0) {
                sess->state = ATTESTATION_STATE_TRUSTED;
                sess->last_re_attestation = time(NULL);
                safe_copy(sess->exam_key, sizeof(sess->exam_key), prod_key);
                sess->exam_key_released = 1;
                break;
            }
        }
        pthread_mutex_unlock(&g_trust_lock);

        {
            ledger_block_t blk;
            char details[256];
            snprintf(details, sizeof(details),
                     "Exam key bound to session=%s device=%s release=%s",
                     persisted_session, device_id, release_id);
            ledger_append_event("P3_KEY_BOUND", device_id, details, &blk);
        }

        /*
         * Publish the verified attestation state to the device fleet so that
         * exam readiness and policy eligibility reflect it. The fleet row is
         * only updated when the device is registered; an unknown device
         * still gets a valid attestation, it simply is not in the fleet.
         */
        platform_update_device_attestation(device_id, "TRUSTED", NULL);

        if (out_exam_key) safe_copy(out_exam_key, EXAM_KEY_LEN + 1, prod_key);
        OPENSSL_cleanse(prod_key, sizeof(prod_key));
        safe_copy(out_reason, 64, "TPM_QUOTE_VERIFIED");
        return 0;
    }

    enrolled_device_t device_copy;
    golden_release_t release_copy;
    char selected_attestation_id[64] = {0};
    pthread_mutex_lock(&g_trust_lock);
    enrolled_device_t *device = NULL;
    golden_release_t *release = NULL;
    for (int i = 0; i < g_device_count; ++i)
        if (strcmp(g_devices[i].device_id, device_id) == 0) device = &g_devices[i];
    for (int i = 0; i < g_release_count; ++i)
        if (strcmp(g_releases[i].release_id, release_id) == 0 &&
            !g_releases[i].revoked) release = &g_releases[i];
    if (!device || !release || strcmp(device->allowed_release, release_id) != 0 ||
        device->status == DEVICE_STATUS_REVOKED ||
        device->status == DEVICE_STATUS_SUSPENDED ||
        !device->ak_qualified_name[0] || !device->ak_public_pem[0]) {
        safe_copy(out_reason, 64, "P3_DEVICE_OR_RELEASE_NOT_TRUSTED");
        pthread_mutex_unlock(&g_trust_lock);
        return -1;
    }

    for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
        attestation_session_t *sess = &g_sessions[i];
        if (sess->created_at && strcmp(sess->nonce, nonce) == 0) {
            if (sess->nonce_used || sess->state != ATTESTATION_STATE_PENDING ||
                strcmp(sess->device_id, device_id) != 0 ||
                strcmp(sess->release_id, release_id) != 0 ||
                strcmp(sess->institution_id, device->institution_id) != 0 ||
                strcmp(sess->purpose, expected_purpose) != 0 ||
                time(NULL) - sess->created_at > 120) {
                safe_copy(out_reason, 64, "P3_INVALID_OR_EXPIRED_NONCE");
                pthread_mutex_unlock(&g_trust_lock);
                return -1;
            }
            sess->nonce_used = 1;
            safe_copy(selected_attestation_id, sizeof(selected_attestation_id),
                      sess->attestation_id);
            device_copy = *device;
            release_copy = *release;
            pthread_mutex_unlock(&g_trust_lock);

            unsigned char *attest = NULL, *signature = NULL;
            size_t attest_len = 0, signature_len = 0;
            int decoded = decode_hex_bytes(quote_message_hex, &attest,
                                           &attest_len, 4096) == 0 &&
                          decode_hex_bytes(quote_signature_hex, &signature,
                                           &signature_len, 1024) == 0;
            int verified = decoded && tpm_quote_verify_sha256_rsa(
                attest, attest_len, signature, signature_len,
                device_copy.ak_public_pem, device_copy.ak_qualified_name,
                nonce, release_copy.pcr0, release_copy.pcr4,
                release_copy.pcr7, release_copy.pcr11) == 0;
            if (attest) OPENSSL_clear_free(attest, attest_len);
            if (signature) OPENSSL_clear_free(signature, signature_len);

            pthread_mutex_lock(&g_trust_lock);
            for (int j = 0; j < MAX_ATTESTATION_SESSIONS; ++j) {
                attestation_session_t *current = &g_sessions[j];
                if (current->created_at &&
                    strcmp(current->attestation_id, selected_attestation_id) == 0 &&
                    strcmp(current->nonce, nonce) == 0 && current->nonce_used &&
                    current->state == ATTESTATION_STATE_PENDING) {
                    current->state = verified ? ATTESTATION_STATE_TRUSTED
                                               : ATTESTATION_STATE_FAILED;
                    current->last_re_attestation = verified ? time(NULL) : 0;
                    safe_copy(current->failure_reason,
                              sizeof(current->failure_reason),
                              verified ? "" : "P3_INVALID_TPM_QUOTE");
                    break;
                }
            }
            pthread_mutex_unlock(&g_trust_lock);
            if (!verified) {
                safe_copy(out_reason, 64, decoded ? "P3_INVALID_TPM_QUOTE"
                                                  : "P3_MALFORMED_TPM_QUOTE");
                return -1;
            }

            /* Generate and bind exam key to the now-trusted session */
            char exam_key[EXAM_KEY_LEN + 1] = {0};
            if (random_hex64(exam_key) != 0) {
                safe_copy(out_reason, 64, "P3_EXAM_KEY_GENERATION_FAILED");
                return -1;
            }
            pthread_mutex_lock(&g_trust_lock);
            for (int j = 0; j < MAX_ATTESTATION_SESSIONS; ++j) {
                attestation_session_t *cur = &g_sessions[j];
                if (cur->created_at &&
                    strcmp(cur->attestation_id, selected_attestation_id) == 0) {
                    safe_copy(cur->exam_key, sizeof(cur->exam_key), exam_key);
                    cur->exam_key_released = 1;
                    break;
                }
            }
            pthread_mutex_unlock(&g_trust_lock);
            if (out_exam_key) safe_copy(out_exam_key, EXAM_KEY_LEN + 1, exam_key);
            OPENSSL_cleanse(exam_key, sizeof(exam_key));
            safe_copy(out_reason, 64, "TPM_QUOTE_VERIFIED");
            return 0;
        }
    }
    pthread_mutex_unlock(&g_trust_lock);
    safe_copy(out_reason, 64, "P3_INVALID_NONCE");
    return -1;
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

    if (production_attestation_mode()) {
        char persisted_device[64] = {0}, persisted_session[64] = {0};
        char persisted_release[64] = {0}, new_attestation_id[64] = {0};
        char error_code[64] = {0};
        if (persisted_re_attestation_source(session_id, device_id,
                                            persisted_device, persisted_session,
                                            persisted_release) != 0 ||
            attestation_create_challenge(persisted_device, persisted_session,
                                         persisted_release, "", "re_attestation",
                                         "system", out_new_nonce,
                                         new_attestation_id, error_code) != 0)
            return -1;
        return 0;
    }

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
int attestation_revoke_release(const char *release_id) {
    if (!valid_identifier(release_id)) return -1;
    if (production_attestation_mode() &&
        persist_revocation("RELEASE", release_id, "RELEASE_REVOKED") != 0)
        return -1;
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
    return 0;
}

/* -----------------------------------------------------------------------
 * attestation_revoke_device
 * ----------------------------------------------------------------------- */
int attestation_revoke_device(const char *device_id) {
    if (!valid_identifier(device_id)) return -1;
    if (production_attestation_mode() &&
        persist_revocation("DEVICE", device_id, "DEVICE_REVOKED") != 0)
        return -1;
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
    return 0;
}

/* -----------------------------------------------------------------------
 * attestation_get_status
 * ----------------------------------------------------------------------- */
int attestation_get_status(const char *attestation_id, char *out_status, size_t max_len) {
    if (!attestation_id || !out_status || max_len == 0) return -1;
    if (production_attestation_mode())
        return persisted_attestation_status(attestation_id, out_status, max_len);
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

int attestation_check_device_binding(const char *attestation_id,
                                     const char *device_id) {
    if (!attestation_id || !attestation_id[0] || !device_id || !device_id[0])
        return -1;

    if (production_attestation_mode()) {
        char bound_device[64] = {0}, session_id[64] = {0}, release_id[64] = {0};
        return persisted_re_attestation_source(attestation_id, device_id,
                                               bound_device, session_id,
                                               release_id);
    }

    pthread_mutex_lock(&g_trust_lock);
    for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
        if (!g_sessions[i].created_at) continue;
        if (strcmp(g_sessions[i].attestation_id, attestation_id) != 0 &&
            strcmp(g_sessions[i].session_id, attestation_id) != 0)
            continue;
        int trusted = g_sessions[i].state == ATTESTATION_STATE_TRUSTED &&
                      strcmp(g_sessions[i].device_id, device_id) == 0;
        pthread_mutex_unlock(&g_trust_lock);
        return trusted ? 0 : -1;
    }
    pthread_mutex_unlock(&g_trust_lock);
    return -1;
}

int attestation_check_exam_key_ready(const char *attestation_id,
                                     const char *device_id) {
    if (!attestation_id || !attestation_id[0] || !device_id || !device_id[0])
        return -1;

    if (production_attestation_mode()) {
        PGconn *conn = acquire_db_connection();
        if (!conn) return -1;
        const char *params[] = {attestation_id, device_id};
        PGresult *result = PQexecParams(conn,
            "SELECT 1 FROM examos_attestation_challenges c "
            "JOIN examos_exam_key_releases k ON k.attestation_id=c.attestation_id "
            "WHERE (c.attestation_id=$1 OR c.session_id=$1) "
            "AND c.device_id=$2 AND k.device_id=$2 "
            "AND c.state='TRUSTED' "
            "AND c.verified_at>clock_timestamp()-interval '10 minutes' "
            "AND k.revoked_at IS NULL "
            "AND NOT EXISTS (SELECT 1 FROM examos_attestation_challenges newer "
            "WHERE newer.session_id=c.session_id AND newer.created_at>c.created_at) "
            "AND NOT EXISTS (SELECT 1 FROM examos_attestation_revocations r "
            "WHERE (r.target_type='DEVICE' AND r.target_id=c.device_id) "
            "OR (r.target_type='RELEASE' AND r.target_id=c.release_id)) "
            "ORDER BY c.created_at DESC LIMIT 1",
            2, NULL, params, NULL, NULL, 0);
        int ready = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
                    PQntuples(result) == 1;
        if (result) PQclear(result);
        release_db_connection(conn, 0);
        return ready ? 0 : -1;
    }

    pthread_mutex_lock(&g_trust_lock);
    for (int i = 0; i < MAX_ATTESTATION_SESSIONS; i++) {
        if (!g_sessions[i].created_at) continue;
        if (strcmp(g_sessions[i].attestation_id, attestation_id) != 0 &&
            strcmp(g_sessions[i].session_id, attestation_id) != 0)
            continue;
        int ready = g_sessions[i].state == ATTESTATION_STATE_TRUSTED &&
                    g_sessions[i].exam_key_released &&
                    strcmp(g_sessions[i].device_id, device_id) == 0;
        pthread_mutex_unlock(&g_trust_lock);
        return ready ? 0 : -1;
    }
    pthread_mutex_unlock(&g_trust_lock);
    return -1;
}

int attestation_get_device_release(const char *device_id, char *out_release_id,
                                   size_t out_len) {
    if (!device_id || !device_id[0] || !out_release_id || out_len == 0) return -1;
    out_release_id[0] = '\0';
    pthread_mutex_lock(&g_trust_lock);
    for (int i = 0; i < g_device_count; ++i) {
        const enrolled_device_t *device = &g_devices[i];
        if (strcmp(device->device_id, device_id) != 0) continue;
        if ((device->status != DEVICE_STATUS_ENROLLED &&
             device->status != DEVICE_STATUS_TRUSTED) ||
            !device->allowed_release[0] ||
            strlen(device->allowed_release) >= out_len) {
            pthread_mutex_unlock(&g_trust_lock);
            return -1;
        }
        safe_copy(out_release_id, out_len, device->allowed_release);
        pthread_mutex_unlock(&g_trust_lock);
        return 0;
    }
    pthread_mutex_unlock(&g_trust_lock);
    return -1;
}

/* -----------------------------------------------------------------------
 * attestation_get_exam_key
 *
 * Releases the session-bound exam decryption key to a TRUSTED session.
 * Searches by session_id OR attestation_id so callers can use either.
 *
 * In production the key is unsealed from the durable release record, so a
 * restart does not strand a trusted session. The release is refused when the
 * bound challenge is no longer TRUSTED, when it has been revoked, or when
 * the requesting device does not match the device that produced the quote.
 * ----------------------------------------------------------------------- */
int attestation_get_exam_key(const char *session_id, const char *device_id,
                               char *out_key, size_t max_len) {
    if (!session_id || !session_id[0] || !device_id || !device_id[0] ||
        !out_key || max_len < EXAM_KEY_LEN + 1) return -1;
    out_key[0] = '\0';

    if (production_attestation_mode()) {
        char released[EXAM_KEY_LEN + 1] = {0};
        if (load_exam_key_release(session_id, device_id, released,
                                  sizeof(released)) != 0) {
            OPENSSL_cleanse(released, sizeof(released));
            return -1;
        }

        ledger_block_t blk;
        char details[256];
        snprintf(details, sizeof(details),
                 "Exam key released: session=%.63s device=%.63s",
                 session_id, device_id);
        if (ledger_append_event("P3_KEY_RELEASED", device_id, details, &blk) != 0) {
            OPENSSL_cleanse(released, sizeof(released));
            return -1;
        }
        memcpy(out_key, released, EXAM_KEY_LEN);
        out_key[EXAM_KEY_LEN] = '\0';
        OPENSSL_cleanse(released, sizeof(released));
        return 0;
    }

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

        ledger_block_t blk;
        char details[256];
        snprintf(details, sizeof(details),
                 "Exam key released: session=%.63s device=%.63s",
                 g_sessions[i].attestation_id, g_sessions[i].device_id);
        if (ledger_append_event("P3_KEY_RELEASED", g_sessions[i].device_id,
                                details, &blk) != 0) {
            pthread_mutex_unlock(&g_trust_lock);
            return -1;
        }
        strncpy(out_key, g_sessions[i].exam_key, max_len - 1);
        out_key[max_len - 1] = '\0';

        pthread_mutex_unlock(&g_trust_lock);
        return 0;
    }

    pthread_mutex_unlock(&g_trust_lock);
    return -1;
}
