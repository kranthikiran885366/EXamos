/*
 * session_store.c — ExamOS Durable Session Journal (C8 fix)
 *
 * Write-ahead log for candidate sessions.  Every state transition is
 * appended atomically with an HMAC-SHA256 signature (same key as the
 * event ledger — EXAMOS_LEDGER_HMAC_KEY).
 *
 * Journal record format (one JSON line per record):
 *   {"v":1,"event":"CREATE|INVALIDATE|EXPIRE","token":"<64hex>",
 *    "candidate_id":"<id>","created_at":<epoch>,"expires_at":<epoch>,
 *    "hmac":"<64hex>"}
 *
 * Replay on startup:
 *   • CREATE records populate the in-memory session table.
 *   • INVALIDATE/EXPIRE records remove sessions.
 *   • Records whose HMAC does not verify are skipped with a warning —
 *     the in-memory state reflects only verified records.
 *   • Sessions whose expires_at is in the past are not restored.
 */
#define _GNU_SOURCE
#include "../include/session_store.h"
#include "../include/candidate_login.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#define JOURNAL_DEFAULT_PATH "/var/log/examos/session_journal.log"
#define SESSION_LIFETIME_SECONDS 28800   /* 8 hours */

static pthread_mutex_t g_store_lock  = PTHREAD_MUTEX_INITIALIZER;
static FILE           *g_journal_fp  = NULL;
static char            g_journal_path[512];
static unsigned char   g_hmac_key[64];
static size_t          g_hmac_key_len = 0;
static int             g_hmac_ok      = 0;

static int is_production_mode(void)
{
    const char *mode = getenv("EXAMOS_TPM_MODE");
    return mode && strcmp(mode, "production") == 0;
}

/* -----------------------------------------------------------------------
 * HMAC helper — same key as ledger.c
 * ----------------------------------------------------------------------- */
static void compute_record_hmac(const char *payload, char *out_hex65)
{
    if (!g_hmac_ok) {
        memset(out_hex65, '0', 64);
        out_hex65[64] = '\0';
        return;
    }
    unsigned char raw[EVP_MAX_MD_SIZE];
    unsigned int  rawlen = 0;
    HMAC(EVP_sha256(), g_hmac_key, (int)g_hmac_key_len,
         (const unsigned char *)payload, strlen(payload),
         raw, &rawlen);
    for (unsigned int i = 0; i < rawlen; i++)
        sprintf(out_hex65 + i * 2, "%02x", raw[i]);
    out_hex65[rawlen * 2] = '\0';
}

static int verify_record_hmac(const char *payload, const char *stored_hmac)
{
    if (!g_hmac_ok) return 0;  /* unsigned records are never authenticated */
    char expected[65];
    compute_record_hmac(payload, expected);
    if (strlen(stored_hmac) != 64) return 0;
    unsigned char a[32], b[32];
    for (int i = 0; i < 32; i++) {
        unsigned int va = 0, vb = 0;
        sscanf(expected    + i * 2, "%2x", &va);
        sscanf(stored_hmac + i * 2, "%2x", &vb);
        a[i] = (unsigned char)va;
        b[i] = (unsigned char)vb;
    }
    return CRYPTO_memcmp(a, b, 32) == 0;
}

/* Build the canonical payload string for HMAC */
static void build_record_payload(char *buf, size_t bufsz,
                                  const char *event,
                                  const char *token,
                                  const char *candidate_id,
                                  time_t created_at,
                                  time_t expires_at)
{
    snprintf(buf, bufsz,
             "event=%s:token=%s:cid=%s:created=%ld:expires=%ld",
             event, token, candidate_id,
             (long)created_at, (long)expires_at);
}

static const char *event_name(session_event_type_t t)
{
    switch (t) {
    case SESSION_EVENT_CREATE:     return "CREATE";
    case SESSION_EVENT_INVALIDATE: return "INVALIDATE";
    case SESSION_EVENT_EXPIRE:     return "EXPIRE";
    default:                        return "UNKNOWN";
    }
}

/* -----------------------------------------------------------------------
 * session_store_init
 * ----------------------------------------------------------------------- */
int session_store_init(void)
{
    pthread_mutex_lock(&g_store_lock);

    /* Determine journal path */
    const char *path_env = getenv("EXAMOS_SESSION_JOURNAL");
    const char *path = (path_env && *path_env) ? path_env : JOURNAL_DEFAULT_PATH;
    if (strlen(path) >= sizeof(g_journal_path)) {
        pthread_mutex_unlock(&g_store_lock);
        return -1;
    }
    strncpy(g_journal_path, path, sizeof(g_journal_path) - 1);
    g_journal_path[sizeof(g_journal_path) - 1] = '\0';

    /* Ensure parent directory exists */
    {
        char dir[512];
        strncpy(dir, g_journal_path, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
        char *slash = strrchr(dir, '/');
        if (slash && slash != dir) {
            *slash = '\0';
            (void)mkdir(dir, 0750);
        }
    }

    /* Load HMAC key (same env var as ledger) */
    const char *key_env = getenv("EXAMOS_LEDGER_HMAC_KEY");
    g_hmac_ok = 0;
    if (key_env && strlen(key_env) >= 32) {
        size_t klen = strlen(key_env);
        if (klen > sizeof(g_hmac_key)) klen = sizeof(g_hmac_key);
        memcpy(g_hmac_key, key_env, klen);
        g_hmac_key_len = klen;
        g_hmac_ok = 1;
    } else {
        fprintf(stderr, "[SessionStore] %s: EXAMOS_LEDGER_HMAC_KEY not set — "
                        "session journal HMAC disabled.%s\n",
                is_production_mode() ? "FATAL" : "WARNING",
                is_production_mode()
                    ? " Production refuses unauthenticated session records."
                    : " Development mode only.");
        if (is_production_mode()) {
            pthread_mutex_unlock(&g_store_lock);
            return -1;
        }
    }

    pthread_mutex_unlock(&g_store_lock);

    /* Replay existing journal to restore sessions */
    int restored = session_store_replay();
    if (restored < 0) {
        fprintf(stderr, "[SessionStore] %s: journal replay encountered errors — "
                        "some sessions may not be restored.\n",
                is_production_mode() ? "FATAL" : "WARNING");
        if (is_production_mode())
            return -1;
    } else if (restored > 0) {
        fprintf(stdout, "[SessionStore] Restored %d active session(s) from journal.\n",
                restored);
    }

    pthread_mutex_lock(&g_store_lock);
    /* Open journal for appending */
    g_journal_fp = fopen(g_journal_path, "a");
    if (!g_journal_fp) {
        fprintf(stderr, "[SessionStore] %s: cannot open session journal at %s: %s\n",
                is_production_mode() ? "FATAL" : "WARNING",
                g_journal_path, strerror(errno));
        if (is_production_mode()) {
            pthread_mutex_unlock(&g_store_lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&g_store_lock);

    return 0;
}

/* -----------------------------------------------------------------------
 * session_store_replay
 * ----------------------------------------------------------------------- */
int session_store_replay(void)
{
    FILE *f = fopen(g_journal_path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;   /* new journal — OK */
        fprintf(stderr, "[SessionStore] Cannot open journal for replay: %s\n",
                strerror(errno));
        return -1;
    }

    time_t now = time(NULL);
    char line[2048];
    int restored = 0;
    int skipped  = 0;

    while (fgets(line, sizeof(line), f)) {
        /* Minimal JSON field extraction */
        char event[16]       = {0};
        char token[65]       = {0};
        char candidate_id[64]= {0};
        char hmac_field[65]  = {0};
        long created_at      = 0;
        long expires_at      = 0;

        /* Extract fields using strstr — no JSON library dependency */
        {
            const char *p;
#define EXTRACT_STR(key, out, sz) do { \
    p = strstr(line, "\"" key "\":\""); \
    if (p) { p += strlen("\"" key "\":\""); \
      size_t _i=0; \
      while (*p && *p != '"' && _i+1 < (sz)) (out)[_i++]=*p++; \
      (out)[_i]='\0'; } } while(0)
#define EXTRACT_LONG(key, out) do { \
    p = strstr(line, "\"" key "\":"); \
    if (p) { p += strlen("\"" key "\":"); out = strtol(p,NULL,10); } } while(0)

            EXTRACT_STR("event",        event,        sizeof(event));
            EXTRACT_STR("token",        token,        sizeof(token));
            EXTRACT_STR("candidate_id", candidate_id, sizeof(candidate_id));
            EXTRACT_STR("hmac",         hmac_field,   sizeof(hmac_field));
            EXTRACT_LONG("created_at",  created_at);
            EXTRACT_LONG("expires_at",  expires_at);
#undef EXTRACT_STR
#undef EXTRACT_LONG
        }

        if (!token[0] || !event[0]) continue;

        /* Verify HMAC */
        char payload[512];
        build_record_payload(payload, sizeof(payload),
                             event, token, candidate_id,
                             (time_t)created_at, (time_t)expires_at);
        if (!verify_record_hmac(payload, hmac_field)) {
            fprintf(stderr, "[SessionStore] HMAC mismatch on journal record "
                            "(token=%.8s...) — skipping.\n", token);
            skipped++;
            if (is_production_mode()) {
                fclose(f);
                return -1;
            }
            continue;
        }

        if (strcmp(event, "CREATE") == 0) {
            /* Only restore if not yet expired */
            if (expires_at > 0 && (time_t)expires_at <= now) {
                continue;   /* expired — don't restore */
            }
            /* Inject into the candidate session table directly */
            /* We call the internal create variant that takes an existing token */
            if (candidate_session_restore(token, candidate_id,
                                           (time_t)created_at) == 0) {
                restored++;
            }
        } else if (strcmp(event, "INVALIDATE") == 0 ||
                   strcmp(event, "EXPIRE")     == 0) {
            candidate_session_invalidate(token);
        }
    }

    if (skipped > 0)
        fprintf(stderr, "[SessionStore] %d record(s) skipped due to HMAC failures.\n",
                skipped);

    fclose(f);
    return restored;
}

/* -----------------------------------------------------------------------
 * session_store_record
 * ----------------------------------------------------------------------- */
int session_store_record(const session_journal_record_t *rec)
{
    if (!rec) return -1;

    const char *event = event_name(rec->event_type);
    if (strcmp(event, "UNKNOWN") == 0 || !rec->token[0] ||
        (rec->event_type == SESSION_EVENT_CREATE && !rec->candidate_id[0])) {
        fprintf(stderr, "[SessionStore] Refusing invalid session journal record.\n");
        return -1;
    }
    char payload[512];
    build_record_payload(payload, sizeof(payload),
                         event, rec->token, rec->candidate_id,
                         rec->created_at, rec->expires_at);

    pthread_mutex_lock(&g_store_lock);

    if (!g_journal_fp || !g_hmac_ok) {
        fprintf(stderr, "[SessionStore] Refusing session record without an open authenticated journal.\n");
        pthread_mutex_unlock(&g_store_lock);
        return -1;
    }

    char hmac[65];
    compute_record_hmac(payload, hmac);
    int ok = fprintf(g_journal_fp,
        "{\"v\":1,\"event\":\"%s\","
        "\"token\":\"%s\","
        "\"candidate_id\":\"%s\","
        "\"created_at\":%ld,"
        "\"expires_at\":%ld,"
        "\"hmac\":\"%s\"}\n",
        event,
        rec->token,
        rec->candidate_id,
        (long)rec->created_at,
        (long)rec->expires_at,
        hmac) > 0;

    if (ok) ok = (fflush(g_journal_fp) == 0);
    if (ok) ok = (fsync(fileno(g_journal_fp)) == 0);
    if (!ok)
        fprintf(stderr, "[SessionStore] Failed to append and sync session journal record.\n");

    pthread_mutex_unlock(&g_store_lock);
    return ok ? 0 : -1;
}

/* -----------------------------------------------------------------------
 * session_store_close
 * ----------------------------------------------------------------------- */
void session_store_close(void)
{
    pthread_mutex_lock(&g_store_lock);
    if (g_journal_fp) {
        fflush(g_journal_fp);
        fsync(fileno(g_journal_fp));
        fclose(g_journal_fp);
        g_journal_fp = NULL;
    }
    OPENSSL_cleanse(g_hmac_key, sizeof(g_hmac_key));
    g_hmac_key_len = 0;
    g_hmac_ok = 0;
    pthread_mutex_unlock(&g_store_lock);
}
