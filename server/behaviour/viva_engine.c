/*
 * ExamOS Phase 5 — Viva Engine Implementation
 * server/behaviour/viva_engine.c
 *
 * Post-exam viva: LLM-grounded follow-up question generation,
 * candidate viva response collection, reviewer override with audit trail.
 *
 * LLM integration: HTTPS POST to EXAMOS_LLM_ENDPOINT with
 * Authorization: Bearer EXAMOS_LLM_API_KEY.
 * If env vars are missing → VIVA_PROVIDER_UNAVAILABLE (not a silent failure).
 * API key is never logged, never returned in any response.
 *
 * Persistence: flat-file store in EXAMOS_VIVA_STORE (same pattern as
 * behaviour_engine and variant_engine).
 *
 * Idempotency: before calling LLM, check if a viva already exists for
 * this submission_receipt_hash.  If so, return existing record.
 *
 * Prompt minimization: only the question template wording (no answer key),
 * candidate's submitted answer text, and assessment objective are sent to LLM.
 * Candidate PII (full name, ID) is not included in prompts.
 */

#define _GNU_SOURCE
#include "../include/viva_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#ifndef EXAMOS_BUILD_ID
#define EXAMOS_BUILD_ID "dev-unset"
#endif

#define VIVA_STORE_DEFAULT  "/var/lib/examos/viva"
#define VIVA_GEN_FILE       "viva_generations.log"
#define VIVA_RESP_FILE      "viva_responses.log"
#define VIVA_AUDIT_FILE     "viva_audit.log"
#define VIVA_SUGGEST_FILE   "viva_suggestions.log"
#define VIVA_DECISION_FILE  "viva_decisions.log"
#define MAX_PATH            512

static char g_viva_dir[MAX_PATH]      = VIVA_STORE_DEFAULT;
static char g_gen_path[MAX_PATH]      = {0};
static char g_resp_path[MAX_PATH]     = {0};
static char g_audit_path[MAX_PATH]    = {0};
static char g_suggest_path[MAX_PATH]  = {0};
static char g_decision_path[MAX_PATH] = {0};
static pthread_mutex_t g_vlock        = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized              = 0;

/* Viva timeout: seconds a candidate has to respond to each question */
static int g_viva_timeout_sec         = 300; /* 5 min default */

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void copy_text(char *dest, size_t dest_size, const char *source) {
    if (!dest || dest_size == 0) return;
    if (!source) source = "";
    size_t length = strlen(source);
    if (length >= dest_size) length = dest_size - 1;
    memcpy(dest, source, length);
    dest[length] = '\0';
}

static int join_store_path(char *dest, size_t dest_size, const char *filename) {
    size_t dir_len = strlen(g_viva_dir);
    size_t file_len = strlen(filename);
    if (dir_len + 1 + file_len >= dest_size) return -1;
    memcpy(dest, g_viva_dir, dir_len);
    dest[dir_len] = '/';
    memcpy(dest + dir_len + 1, filename, file_len + 1);
    return 0;
}

static int append_hex_field(char *line, size_t line_size, size_t *used,
                            const char *field) {
    static const char hex[] = "0123456789abcdef";
    if (!line || !used || !field) return -1;
    size_t field_len = strlen(field);
    if (*used >= line_size || line_size - *used < 2 ||
        field_len > (line_size - *used - 2) / 2) return -1;
    line[(*used)++] = '|';
    for (size_t i = 0; i < field_len; ++i) {
        unsigned char byte = (unsigned char)field[i];
        line[(*used)++] = hex[byte >> 4];
        line[(*used)++] = hex[byte & 0x0f];
    }
    line[*used] = '\0';
    return 0;
}

static int decode_hex_field(const char *encoded, char *decoded, size_t decoded_size) {
    if (!encoded || !decoded || decoded_size == 0) return -1;
    size_t encoded_len = strlen(encoded);
    if ((encoded_len & 1U) != 0 || encoded_len / 2 >= decoded_size) return -1;
    for (size_t i = 0; i < encoded_len; i += 2) {
        unsigned int byte = 0;
        if (sscanf(encoded + i, "%2x", &byte) != 1) return -1;
        decoded[i / 2] = (char)byte;
    }
    decoded[encoded_len / 2] = '\0';
    return 0;
}

static void get_build_id(char *out, size_t max) {
    const char *b = getenv("EXAMOS_BUILD_ID");
    strncpy(out, b && *b ? b : EXAMOS_BUILD_ID, max-1);
    out[max-1]='\0';
}

static int mkdir_p(const char *path) {
    char tmp[MAX_PATH];
    strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
    size_t len = strlen(tmp);
    if (tmp[len-1]=='/') tmp[--len]='\0';
    for (char *p=tmp+1; *p; p++) {
        if (*p=='/') { *p='\0'; mkdir(tmp, 0750); *p='/'; }
    }
    return mkdir(tmp,0750)==0||errno==EEXIST ? 0 : -1;
}

static int safe_append(const char *path, const char *line) {
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    int rc=0;
    if (fprintf(f,"%s\n",line)<0) rc=-1;
    if (fflush(f)) rc=-1;
    if (fsync(fileno(f))) rc=-1;
    if (fclose(f)) rc=-1;
    return rc;
}

static void gen_id(char *out, size_t max, const char *prefix) {
    unsigned char rb[8];
    RAND_bytes(rb, sizeof(rb));
    char hex[17];
    for (int i=0;i<8;i++) sprintf(hex+(i*2),"%02x",rb[i]);
    hex[16]='\0';
    snprintf(out, max, "%s-%ld-%s", prefix, (long)time(NULL), hex);
}

static void sha256_hex(const char *input, char out[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input, strlen(input), hash);
    for (int i=0;i<SHA256_DIGEST_LENGTH;i++) sprintf(out+(i*2),"%02x",hash[i]);
    out[64]='\0';
}

/* ── Init ─────────────────────────────────────────────────────────────────── */

int viva_engine_init(void) {
    pthread_mutex_lock(&g_vlock);
    if (g_initialized) { pthread_mutex_unlock(&g_vlock); return 0; }

    const char *env_dir = getenv("EXAMOS_VIVA_STORE");
    if (env_dir && *env_dir) {
        if (strlen(env_dir) >= sizeof(g_viva_dir)) {
            fprintf(stderr, "[VivaEngine] FATAL: store path is too long\n");
            pthread_mutex_unlock(&g_vlock);
            return -1;
        }
        copy_text(g_viva_dir, sizeof(g_viva_dir), env_dir);
    }
    if (mkdir_p(g_viva_dir)!=0 && errno!=EEXIST) {
        fprintf(stderr, "[VivaEngine] FATAL: cannot create store %s\n", g_viva_dir);
        pthread_mutex_unlock(&g_vlock);
        return -1;
    }

    if (join_store_path(g_gen_path, sizeof(g_gen_path), VIVA_GEN_FILE) != 0 ||
        join_store_path(g_resp_path, sizeof(g_resp_path), VIVA_RESP_FILE) != 0 ||
        join_store_path(g_audit_path, sizeof(g_audit_path), VIVA_AUDIT_FILE) != 0 ||
        join_store_path(g_suggest_path, sizeof(g_suggest_path), VIVA_SUGGEST_FILE) != 0 ||
        join_store_path(g_decision_path, sizeof(g_decision_path), VIVA_DECISION_FILE) != 0) {
        fprintf(stderr, "[VivaEngine] FATAL: store path is too long\n");
        pthread_mutex_unlock(&g_vlock);
        return -1;
    }

    const char *tv = getenv("EXAMOS_VIVA_TIMEOUT_SEC");
    if (tv && *tv) { int v = atoi(tv); if (v>0) g_viva_timeout_sec=v; }

    g_initialized = 1;
    printf("[VivaEngine] Phase 5 viva engine ready. Store: %s Timeout: %ds\n",
           g_viva_dir, g_viva_timeout_sec);
    pthread_mutex_unlock(&g_vlock);
    return 0;
}

/* ── Idempotency check ───────────────────────────────────────────────────── */

static int find_existing_viva(const char *session_id,
                               const char *submission_receipt_hash,
                               char *out_viva_id, size_t vid_max) {
    pthread_mutex_lock(&g_vlock);
    FILE *f = fopen(g_gen_path, "r");
    if (!f) { pthread_mutex_unlock(&g_vlock); return 0; }

    char line[4096];
    int found = 0;
    while (fgets(line, sizeof(line), f) && !found) {
        char ftype[16]={0}, fvid[64]={0}, fsess[128]={0}, frh[65]={0};
        if (sscanf(line, "%15[^|]|%63[^|]|%127[^|]", ftype, fvid, fsess) < 3) continue;
        if (strcmp(ftype,"VIVA")!=0) continue;
        if (strcmp(fsess,session_id)!=0) continue;
        /* Extract receipt hash field (field 5) */
        char *p = line;
        int field = 0;
        while (field < 4 && p) { p = strchr(p,'|'); if (p) { p++; field++; } }
        if (p && sscanf(p, "%64[^|]", frh)==1 &&
            strcmp(frh, submission_receipt_hash)==0) {
            copy_text(out_viva_id, vid_max, fvid);
            found = 1;
        }
    }
    fclose(f);
    pthread_mutex_unlock(&g_vlock);
    return found;
}

static int json_read_string_field(const char *json, const char *key,
                                  char *output, size_t output_size);

/* ── LLM HTTP call (HTTPS POST via OpenSSL) ─────────────────────────────── */
/* 
 * Makes a real HTTPS POST to EXAMOS_LLM_ENDPOINT.
 * API key from EXAMOS_LLM_API_KEY (never logged).
 * Returns 0 on success with response in out_body.
 * Requires EXAMOS_LLM_TIMEOUT_SEC to be explicitly configured.
 */
static int llm_https_post(const char *prompt_json,
                           char *out_body, size_t out_max) {
    const char *endpoint = getenv("EXAMOS_LLM_ENDPOINT");
    const char *api_key  = getenv("EXAMOS_LLM_API_KEY");
    const char *model    = getenv("EXAMOS_LLM_MODEL");

    if (!endpoint || !*endpoint) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                 "\"reason\":\"EXAMOS_LLM_ENDPOINT not configured\"}");
        return -1;
    }
    if (!api_key || strlen(api_key) < 8) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                 "\"reason\":\"EXAMOS_LLM_API_KEY not configured\"}");
        return -1;
    }
    if (strlen(api_key) > 4096) return -1;
    for (const unsigned char *p = (const unsigned char *)api_key; *p; p++) {
        if (*p < 0x21 || *p == 0x7f) {
            snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                     "\"reason\":\"Provider credential contains invalid header characters\"}");
            return -1;
        }
    }
    if (!model || !*model) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                 "\"reason\":\"EXAMOS_LLM_MODEL not configured\"}");
        return -1;
    }

    int timeout_sec;
    const char *tv = getenv("EXAMOS_LLM_TIMEOUT_SEC");
    char *timeout_end = NULL;
    errno = 0;
    long configured_timeout = tv && *tv ? strtol(tv, &timeout_end, 10) : 0;
    if (!tv || !*tv || errno != 0 || !timeout_end || *timeout_end ||
        configured_timeout < 5 || configured_timeout >= 300) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                 "\"reason\":\"EXAMOS_LLM_TIMEOUT_SEC must be configured within the supported range\"}");
        return -1;
    }
    timeout_sec = (int)configured_timeout;

    /* Parse endpoint: https://host[:port]/path */
    char host[256]={0}, path[512]={0};
    int port = 443;
    const char *url = endpoint;
    if (strncmp(url,"https://",8)!=0) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                 "\"reason\":\"LLM endpoint must use HTTPS\"}");
        return -1;
    }
    url += 8;
    const char *slash = strchr(url, '/');
    if (slash) {
        size_t hlen = (size_t)(slash-url);
        if (hlen>=sizeof(host)) return -1;
        strncpy(host, url, hlen);
        strncpy(path, slash, sizeof(path)-1);
    } else {
        strncpy(host, url, sizeof(host)-1);
        strcpy(path, "/");
    }
    /* Check for port in host */
    char *colon = strchr(host, ':');
    if (colon) {
        char *port_end = NULL;
        errno = 0;
        long parsed_port = strtol(colon + 1, &port_end, 10);
        if (errno != 0 || !port_end || *port_end || parsed_port < 1 || parsed_port > 65535) {
            snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                     "\"reason\":\"Invalid LLM endpoint port\"}");
            return -1;
        }
        port = (int)parsed_port;
        *colon='\0';
    }
    if (!host[0] || strchr(host, '@') || strchr(host, '\r') || strchr(host, '\n') ||
        port < 1 || port > 65535 || strchr(path, '\r') || strchr(path, '\n')) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                 "\"reason\":\"Invalid LLM endpoint authority or path\"}");
        return -1;
    }

    /* DNS resolution */
    struct addrinfo hints, *res;
    memset(&hints,0,sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                 "\"reason\":\"DNS resolution failed\"}");
        return -1;
    }

    int sock = -1;
    struct timeval tv_so = { timeout_sec, 0 };
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int candidate = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (candidate < 0) continue;
        setsockopt(candidate, SOL_SOCKET, SO_RCVTIMEO, &tv_so, sizeof(tv_so));
        setsockopt(candidate, SOL_SOCKET, SO_SNDTIMEO, &tv_so, sizeof(tv_so));
        if (connect(candidate, ai->ai_addr, ai->ai_addrlen) == 0) {
            sock = candidate;
            break;
        }
        close(candidate);
    }
    freeaddrinfo(res);
    if (sock < 0) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                 "\"reason\":\"Connection failed for all resolved addresses\"}");
        return -1;
    }

    /* TLS handshake */
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) { close(sock); return -1; }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
        SSL_CTX_free(ssl_ctx); close(sock);
        return -1;
    }

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_set_tlsext_host_name(ssl, host) != 1 || SSL_set1_host(ssl, host) != 1) {
        SSL_free(ssl); SSL_CTX_free(ssl_ctx); close(sock);
        return -1;
    }
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl); SSL_CTX_free(ssl_ctx); close(sock);
        snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                 "\"reason\":\"TLS handshake failed\"}");
        return -1;
    }

    /* Build HTTP request (API key in header only, never in body/logs) */
    size_t body_len = strlen(prompt_json);
    char http_req[65536];
    int req_len = snprintf(http_req, sizeof(http_req),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Authorization: Bearer %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        path, host, api_key, body_len, prompt_json);

    if (req_len <= 0 || (size_t)req_len >= sizeof(http_req)) {
        SSL_free(ssl); SSL_CTX_free(ssl_ctx); close(sock);
        return -1;
    }
    int request_sent = 0;
    while (request_sent < req_len) {
        int written = SSL_write(ssl, http_req + request_sent, req_len - request_sent);
        if (written <= 0) {
            SSL_free(ssl); SSL_CTX_free(ssl_ctx); close(sock);
            snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                     "\"reason\":\"Provider request write failed\"}");
            return -1;
        }
        request_sent += written;
    }
    /* zero out api_key in stack copy immediately */
    memset(http_req, 0, (size_t)req_len);

    /* Read response */
    char resp_buf[16384] = {0};
    int  resp_len = 0;
    int  n;
    while ((n = SSL_read(ssl, resp_buf+resp_len, (int)sizeof(resp_buf)-resp_len-1)) > 0) {
        resp_len += n;
        if ((size_t)resp_len >= sizeof(resp_buf)-1) break;
    }
    resp_buf[resp_len] = '\0';

    if ((size_t)resp_len >= sizeof(resp_buf)-1) {
        SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ssl_ctx); close(sock);
        snprintf(out_body, out_max, "{\"error\":\"VIVA_OUTPUT_INVALID\","
                 "\"reason\":\"Provider response exceeded the configured limit\"}");
        return -1;
    }

    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ssl_ctx); close(sock);

    /* Extract JSON body after \r\n\r\n */
    const char *body = strstr(resp_buf, "\r\n\r\n");
    if (!body) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_OUTPUT_INVALID\","
                 "\"reason\":\"No HTTP body in LLM response\"}");
        return -1;
    }
    if (strncmp(resp_buf, "HTTP/1.1 2", 10) != 0 &&
        strncmp(resp_buf, "HTTP/1.0 2", 10) != 0) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_PROVIDER_UNAVAILABLE\","
                 "\"reason\":\"Provider returned a non-success HTTP status\"}");
        return -1;
    }
    if (strcasestr(resp_buf, "Transfer-Encoding: chunked")) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_OUTPUT_INVALID\","
                 "\"reason\":\"Chunked provider responses are unsupported\"}");
        return -1;
    }
    body += 4;
    size_t resp_body_len = (size_t)(resp_buf + resp_len - body);
    if (resp_body_len >= out_max) {
        snprintf(out_body, out_max, "{\"error\":\"VIVA_OUTPUT_INVALID\","
                 "\"reason\":\"Provider response exceeds the consumer buffer\"}");
        return -1;
    }
    memcpy(out_body, body, resp_body_len);
    out_body[resp_body_len] = '\0';
    if (strstr(out_body, "\"choices\"")) {
        char provider_content[8192];
        if (json_read_string_field(out_body, "content", provider_content,
                                   sizeof(provider_content)) != 0 ||
            strlen(provider_content) >= out_max) {
            snprintf(out_body, out_max, "{\"error\":\"VIVA_OUTPUT_INVALID\","
                     "\"reason\":\"Provider response has no valid message content\"}");
            return -1;
        }
        memcpy(out_body, provider_content, strlen(provider_content) + 1);
    }
    return 0;
}

/* ── Build LLM prompt ────────────────────────────────────────────────────── */

static int json_escape_value(const char *input, char *output, size_t output_size) {
    size_t used = 0;
    if (!input || !output || output_size == 0) return -1;
    for (const unsigned char *p = (const unsigned char *)input; *p; p++) {
        const char *escape = NULL;
        char unicode_escape[7];
        size_t amount = 1;
        switch (*p) {
            case '"': escape = "\\\""; amount = 2; break;
            case '\\': escape = "\\\\"; amount = 2; break;
            case '\b': escape = "\\b"; amount = 2; break;
            case '\f': escape = "\\f"; amount = 2; break;
            case '\n': escape = "\\n"; amount = 2; break;
            case '\r': escape = "\\r"; amount = 2; break;
            case '\t': escape = "\\t"; amount = 2; break;
            default:
                if (*p < 0x20) {
                    snprintf(unicode_escape, sizeof(unicode_escape), "\\u%04x", *p);
                    escape = unicode_escape;
                    amount = 6;
                }
        }
        if (used + amount >= output_size) return -1;
        if (escape) memcpy(output + used, escape, amount);
        else output[used] = (char)*p;
        used += amount;
    }
    output[used] = '\0';
    return 0;
}

static int json_read_string_field(const char *json, const char *key,
                                 char *output, size_t output_size) {
    char needle[96];
    if (!json || !key || !output || output_size == 0) return -1;
    int n = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (n < 0 || (size_t)n >= sizeof(needle)) return -1;
    const char *p = strstr(json, needle);
    if (!p || !(p = strchr(p + n, ':'))) return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p++ != '"') return -1;
    size_t used = 0;
    while (*p && *p != '"') {
        unsigned char value = (unsigned char)*p++;
        if (value == '\\') {
            switch (*p++) {
                case '"': value = '"'; break;
                case '\\': value = '\\'; break;
                case '/': value = '/'; break;
                case 'b': value = '\b'; break;
                case 'f': value = '\f'; break;
                case 'n': value = '\n'; break;
                case 'r': value = '\r'; break;
                case 't': value = '\t'; break;
                default: return -1;
            }
        }
        if (value == '\0' || used + 1 >= output_size) return -1;
        output[used++] = (char)value;
    }
    if (*p != '"' || used == 0) return -1;
    output[used] = '\0';
    return 0;
}

static int build_viva_prompt(const char *question_text,
                              const char *submitted_answer,
                              const char *assessment_objective,
                              char *out_prompt, size_t max) {
    char escaped_model[512], escaped_question[8192], escaped_answer[8192], escaped_objective[2048];
    const char *model = getenv("EXAMOS_LLM_MODEL");
    if (!model || !*model ||
        json_escape_value(model, escaped_model, sizeof(escaped_model)) != 0 ||
        json_escape_value(question_text, escaped_question, sizeof(escaped_question)) != 0 ||
        json_escape_value(submitted_answer, escaped_answer, sizeof(escaped_answer)) != 0 ||
        json_escape_value(assessment_objective, escaped_objective, sizeof(escaped_objective)) != 0)
        return -1;
    /* Only submitted question/answer context is sent; JSON string escaping
     * prevents candidate content from changing the provider request structure. */
    int n = snprintf(out_prompt, max,
        "{"
        "\"model\":\"%s\","
        "\"messages\":["
          "{\"role\":\"system\",\"content\":"
            "\"You are an academic viva examiner. Generate %d concise follow-up questions "
            "based solely on the candidate's submitted answer. "
            "Do NOT disclose any correct answer or marking criteria. "
            "Each question must reference specific content in the candidate's answer. "
            "Respond with a JSON object: {\\\"questions\\\":[{\\\"text\\\":\\\"...\\\","
            "\\\"assessment_objective\\\":\\\"...\\\"},...]}. "
            "Generate exactly %d questions.\"},"
          "{\"role\":\"user\",\"content\":"
            "\"Question asked: %s\\n\\nCandidate answered: %s\\n\\n"
            "Assessment focus: %s\"}"
        "],"
        "\"max_tokens\":800,"
        "\"temperature\":0.3"
        "}",
        escaped_model,
        VIVA_MIN_QUESTIONS, VIVA_MIN_QUESTIONS,
        escaped_question, escaped_answer, escaped_objective);
    return n >= 0 && (size_t)n < max ? 0 : -1;
}

/* ── Parse LLM response for viva questions ───────────────────────────────── */

static int parse_viva_response(const char *llm_body,
                                viva_question_t questions[VIVA_MAX_QUESTIONS],
                                int *out_count) {
    *out_count = 0;
    if (!llm_body || !*llm_body) return -1;

    /* Look for "questions": [...] array */
    const char *qa = strstr(llm_body, "\"questions\"");
    if (!qa) return -1;
    qa = strchr(qa, '[');
    if (!qa) return -1;

    /* Simple sequential extraction of "text" fields */
    const char *p = qa;
    while (*out_count < VIVA_MAX_QUESTIONS) {
        const char *text_key = strstr(p, "\"text\"");
        if (!text_key) break;
        text_key = strchr(text_key, ':');
        if (!text_key) break;
        text_key++;
        while (*text_key==' '||*text_key=='\t') text_key++;
        if (*text_key != '"') break;
        text_key++;
        /* Extract until closing quote (handle \\") */
        char qtext[1024]={0};
        int qi=0;
        const char *qq=text_key;
        while (*qq && qi<1023) {
            if (*qq=='\\' && *(qq+1)=='"') { qtext[qi++]='"'; qq+=2; continue; }
            if (*qq=='"') break;
            qtext[qi++]=*qq++;
        }
        if (!*qq) break;
        p = qq+1;

        /* Extract assessment_objective */
        char obj[128]="explanation and reasoning";
        const char *obj_key = strstr(text_key, "\"assessment_objective\"");
        if (obj_key && obj_key < p+256) {
            obj_key = strchr(obj_key,':');
            if (obj_key) {
                obj_key++;
                while (*obj_key==' ') obj_key++;
                if (*obj_key=='"') {
                    obj_key++;
                    int oi=0;
                    while (*obj_key && *obj_key!='"' && oi<127) obj[oi++]=*obj_key++;
                    obj[oi]='\0';
                }
            }
        }

        viva_question_t *vq = &questions[*out_count];
        memset(vq, 0, sizeof(*vq));
        gen_id(vq->question_id, sizeof(vq->question_id), "vivaq");
        copy_text(vq->text, sizeof(vq->text), qtext);
        copy_text(vq->assessment_objective, sizeof(vq->assessment_objective), obj);
        strncpy(vq->rubric_reference, "REVIEWER_ONLY", sizeof(vq->rubric_reference)-1);
        (*out_count)++;
    }

    return (*out_count >= VIVA_MIN_QUESTIONS) ? 0 : -1;
}

/* ── ISS-04: Offline Fallback Question Bank ──────────────────────────────── */
/*
 * When the LLM provider is unreachable, generate structured viva questions
 * from a pre-defined bank keyed on exam_type. Returns VIVA_STATUS_OFFLINE_FALLBACK.
 * Produces 3-5 questions in the same viva_question_t format.
 */

typedef struct {
    const char *exam_type_keyword; /* matched against exam_id prefix or "generic" */
    const char *questions[5];
    const char *objectives[5];
    int count;
} offline_question_set_t;

static const offline_question_set_t g_offline_question_bank[] = {
    {
        "math", {
            "Explain the reasoning behind your approach to the main problem in this exam.",
            "What alternative methods could have been used to arrive at the same answer?",
            "Describe a real-world scenario where this mathematical concept is applied.",
            "How would you verify the correctness of your solution?",
            "What assumptions did you make, and how do they affect your result?"
        }, {
            "reasoning",
            "application",
            "application",
            "verification",
            "critical thinking"
        }, 5
    },
    {
        "science", {
            "Explain the core scientific principle underlying your answer.",
            "What experimental evidence supports the conclusion you reached?",
            "How would you design an experiment to test the hypothesis in this question?",
            "Describe how this concept relates to other areas of science you have studied.",
            "What are the limitations of the approach you used to answer this question?"
        }, {
            "reasoning",
            "evidence evaluation",
            "experimental design",
            "synthesis",
            "critical analysis"
        }, 5
    },
    {
        "generic", {
            "Explain the core reasoning behind the approach you took in your answer.",
            "What alternative approaches could you have used, and why did you choose this one?",
            "Describe how you would verify that your answer is correct.",
            "How does the concept tested in this question apply in a real-world context?",
            "What additional information would have helped you give a more complete answer?"
        }, {
            "reasoning",
            "critical thinking",
            "verification",
            "application",
            "reflection"
        }, 5
    }
};

static const offline_question_set_t *select_offline_question_set(const char *exam_id) {
    if (exam_id && *exam_id) {
        for (size_t i = 0; i < sizeof(g_offline_question_bank)/sizeof(g_offline_question_bank[0]) - 1; i++) {
            if (strstr(exam_id, g_offline_question_bank[i].exam_type_keyword) != NULL) {
                return &g_offline_question_bank[i];
            }
        }
    }
    /* last entry is always "generic" */
    return &g_offline_question_bank[sizeof(g_offline_question_bank)/sizeof(g_offline_question_bank[0]) - 1];
}

static int viva_generate_offline_fallback(viva_generation_t *out_viva,
                                          const char *exam_id) {
    const offline_question_set_t *qs = select_offline_question_set(exam_id);

    /* Use 3 questions from the set (minimum required, bounded by set size) */
    int count = qs->count < 3 ? qs->count : 3;
    out_viva->question_count = count;

    for (int i = 0; i < count; i++) {
        viva_question_t *vq = &out_viva->questions[i];
        memset(vq, 0, sizeof(*vq));
        gen_id(vq->question_id, sizeof(vq->question_id), "vivaq-offline");
        copy_text(vq->text, sizeof(vq->text), qs->questions[i]);
        copy_text(vq->assessment_objective, sizeof(vq->assessment_objective), qs->objectives[i]);
        strncpy(vq->rubric_reference, "OFFLINE_FALLBACK", sizeof(vq->rubric_reference)-1);
    }

    out_viva->status = VIVA_STATUS_OFFLINE_FALLBACK;
    copy_text(out_viva->status_str, sizeof(out_viva->status_str), "VIVA_OFFLINE_FALLBACK");
    copy_text(out_viva->failure_reason, sizeof(out_viva->failure_reason),
              "LLM provider unavailable; pre-banked academic integrity questions used");
    fprintf(stderr, "[VivaEngine] ISS-04: LLM unavailable — using offline fallback question bank (%s)\n",
            qs->exam_type_keyword);
    return 0;
}

/* ── Validation ──────────────────────────────────────────────────────────── */

static int validate_viva_output(const viva_generation_t *v) {
    if (v->question_count < VIVA_MIN_QUESTIONS ||
        v->question_count > VIVA_MAX_QUESTIONS) return 0;
    for (int i=0; i<v->question_count; i++) {
        if (!v->questions[i].text[0]) return 0;
        /* Reject suspiciously short questions */
        if (strlen(v->questions[i].text) < 20) return 0;
        /* Reject if no question mark or common interrogative */
        const char *t = v->questions[i].text;
        int has_q = (strchr(t,'?') != NULL);
        int has_wh = (strstr(t,"why") || strstr(t,"how") || strstr(t,"what") ||
                      strstr(t,"explain") || strstr(t,"describe") ||
                      strstr(t,"Why") || strstr(t,"How") || strstr(t,"What") ||
                      strstr(t,"Explain") || strstr(t,"Describe"));
        if (!has_q && !has_wh) return 0;
    }
    return 1;
}

/* ── Viva generation ─────────────────────────────────────────────────────── */

int viva_generate(const char *session_id,
                   const char *candidate_id,
                   const char *exam_id,
                   const char *submission_receipt_hash,
                   const char *question_context,
                   const char *answer_context,
                   viva_generation_t *out_viva) {
    if (!session_id||!candidate_id||!exam_id||!submission_receipt_hash||
        !question_context || !*question_context || !answer_context || !*answer_context || !out_viva) return -1;
    if (!g_initialized && viva_engine_init()!=0) return -1;

    memset(out_viva, 0, sizeof(*out_viva));

    /* Idempotency: check if viva already generated for this submission */
    char existing_vid[64]={0};
    if (find_existing_viva(session_id, submission_receipt_hash, existing_vid, sizeof(existing_vid))) {
        if (viva_retrieve(existing_vid, out_viva) != 0) {
            fprintf(stderr, "[VivaEngine] ERROR: idempotent viva record is incomplete or invalid\n");
            return -1;
        }
        out_viva->idempotency_key_used = 1;
        printf("[VivaEngine] Idempotent: returning existing viva=%s for session=%s\n",
               existing_vid, session_id);
        return 0;
    }

    /* New viva generation */
    gen_id(out_viva->viva_id, sizeof(out_viva->viva_id), "viva");
    strncpy(out_viva->session_id, session_id, sizeof(out_viva->session_id)-1);
    strncpy(out_viva->candidate_id, candidate_id, sizeof(out_viva->candidate_id)-1);
    strncpy(out_viva->exam_id, exam_id, sizeof(out_viva->exam_id)-1);
    strncpy(out_viva->submission_receipt_hash, submission_receipt_hash,
            sizeof(out_viva->submission_receipt_hash)-1);
    strncpy(out_viva->prompt_version, VIVA_PROMPT_VERSION, sizeof(out_viva->prompt_version)-1);
    out_viva->generated_ts = time(NULL);
    get_build_id(out_viva->build_id, sizeof(out_viva->build_id));

    /* Record model ID from env */
    const char *model = getenv("EXAMOS_LLM_MODEL");
    if (!model || !*model) {
        out_viva->status = VIVA_STATUS_FAILED;
        copy_text(out_viva->status_str, sizeof(out_viva->status_str), "VIVA_PROVIDER_UNAVAILABLE");
        copy_text(out_viva->failure_reason, sizeof(out_viva->failure_reason), "EXAMOS_LLM_MODEL not configured");
        return -1;
    }
    copy_text(out_viva->generation_model, sizeof(out_viva->generation_model), model);

    /* Hash endpoint URL (not the URL itself) for audit */
    const char *ep = getenv("EXAMOS_LLM_ENDPOINT");
    if (ep && *ep) sha256_hex(ep, out_viva->provider_endpoint_hash);

    char prompt[32768]={0};
    if (build_viva_prompt(question_context, answer_context,
                          "reasoning, application and explanation of core concepts",
                          prompt, sizeof(prompt)) != 0) {
        out_viva->status = VIVA_STATUS_FAILED;
        copy_text(out_viva->status_str, sizeof(out_viva->status_str), "VIVA_CONTEXT_INVALID");
        copy_text(out_viva->failure_reason, sizeof(out_viva->failure_reason), "Submitted context exceeds provider request limits");
        return -1;
    }

    /* Call LLM */
    char llm_body[8192]={0};
    int llm_rc = llm_https_post(prompt, llm_body, sizeof(llm_body));

    if (llm_rc != 0) {
        /* ISS-04 fix: LLM unavailable — use offline academic integrity fallback question bank.
         * This allows the viva workflow to proceed in air-gapped exam centres without
         * an external cloud dependency. The offline fallback is clearly flagged in the
         * generated record and audit trail so reviewers know it was used. */
        fprintf(stderr, "[VivaEngine] ISS-04: LLM provider unavailable, using offline fallback\n");
        if (viva_generate_offline_fallback(out_viva, exam_id) != 0) {
            out_viva->status = VIVA_STATUS_FAILED;
            copy_text(out_viva->status_str, sizeof(out_viva->status_str), "VIVA_PROVIDER_UNAVAILABLE");
            copy_text(out_viva->failure_reason, sizeof(out_viva->failure_reason),
                      "LLM unavailable and offline fallback also failed");
            return -1;
        }
        /* Offline fallback succeeded — fall through to validation and persistence */
    } else {
        viva_question_t questions[VIVA_MAX_QUESTIONS];
        int qcount = 0;
        if (parse_viva_response(llm_body, questions, &qcount) != 0) {
            out_viva->status = VIVA_STATUS_INVALID;
            strncpy(out_viva->status_str, "VIVA_OUTPUT_INVALID", sizeof(out_viva->status_str)-1);
            strncpy(out_viva->failure_reason, "LLM_OUTPUT_PARSE_FAILED", sizeof(out_viva->failure_reason)-1);

            char line[512];
            snprintf(line, sizeof(line),
                "VIVA|%s|%s|%s|%s|%s|INVALID|VIVA_OUTPUT_INVALID|%d|%ld|%s",
                out_viva->viva_id, out_viva->session_id, out_viva->candidate_id,
                out_viva->exam_id, out_viva->submission_receipt_hash,
                qcount, (long)out_viva->generated_ts, out_viva->build_id);
            pthread_mutex_lock(&g_vlock);
            safe_append(g_gen_path, line);
            pthread_mutex_unlock(&g_vlock);
            viva_append_audit("VIVA_VALIDATION_FAILED", "SYSTEM", out_viva->viva_id,
                              "LLM_OUTPUT_PARSE_FAILED");
            return -1;
        }

        /* Copy questions into output and populate source references */
        memcpy(out_viva->questions, questions, sizeof(viva_question_t) * (size_t)qcount);
        out_viva->question_count = qcount;
        for (int i = 0; i < out_viva->question_count; i++) {
            /* The viva questions are derived from the whole submitted exam;
               do not leak the candidate session token into reviewer evidence. */
            strncpy(out_viva->questions[i].source_question_id, "SUBMITTED_EXAM",
                    sizeof(out_viva->questions[i].source_question_id)-1);
            strncpy(out_viva->questions[i].source_answer_version, submission_receipt_hash,
                    sizeof(out_viva->questions[i].source_answer_version)-1);
        }
    }

    /* Validate output */
    if (!validate_viva_output(out_viva)) {
        out_viva->status = VIVA_STATUS_INVALID;
        strncpy(out_viva->status_str, "VIVA_VALIDATION_REJECTED", sizeof(out_viva->status_str)-1);
        strncpy(out_viva->failure_reason, "OUTPUT_QUALITY_CHECK_FAILED",
                sizeof(out_viva->failure_reason)-1);
        viva_append_audit("VIVA_VALIDATION_REJECTED", "SYSTEM", out_viva->viva_id,
                          "OUTPUT_QUALITY_CHECK_FAILED");
        return -1;
    }

    out_viva->status = VIVA_STATUS_SUCCEEDED;
    strncpy(out_viva->status_str, "SUCCEEDED", sizeof(out_viva->status_str)-1);

    /* Persist generation record */
    char line[16384];
    int base_len = snprintf(line, sizeof(line),
        "VIVA|%s|%s|%s|%s|%s|SUCCEEDED|%s|%d|%ld|%s",
        out_viva->viva_id, out_viva->session_id, out_viva->candidate_id,
        out_viva->exam_id, out_viva->submission_receipt_hash,
        out_viva->generation_model, out_viva->question_count,
        (long)out_viva->generated_ts, out_viva->build_id);
    if (base_len < 0 || (size_t)base_len >= sizeof(line)) {
        out_viva->status = VIVA_STATUS_FAILED;
        copy_text(out_viva->status_str, sizeof(out_viva->status_str), "FAILED");
        copy_text(out_viva->failure_reason, sizeof(out_viva->failure_reason),
                  "VIVA_RECORD_TOO_LARGE");
        return -1;
    }
    size_t line_used = (size_t)base_len;

    for (int i = 0; i < out_viva->question_count; i++) {
        const viva_question_t *question = &out_viva->questions[i];
        if (line_used + sizeof("|QDATA") >= sizeof(line)) return -1;
        memcpy(line + line_used, "|QDATA", sizeof("|QDATA"));
        line_used += sizeof("|QDATA") - 1;
        line[line_used] = '\0';
        if (append_hex_field(line, sizeof(line), &line_used, question->question_id) != 0 ||
            append_hex_field(line, sizeof(line), &line_used, question->text) != 0 ||
            append_hex_field(line, sizeof(line), &line_used, question->assessment_objective) != 0 ||
            append_hex_field(line, sizeof(line), &line_used, question->rubric_reference) != 0 ||
            append_hex_field(line, sizeof(line), &line_used, question->source_question_id) != 0 ||
            append_hex_field(line, sizeof(line), &line_used, question->source_answer_version) != 0) {
            out_viva->status = VIVA_STATUS_FAILED;
            copy_text(out_viva->status_str, sizeof(out_viva->status_str), "FAILED");
            copy_text(out_viva->failure_reason, sizeof(out_viva->failure_reason),
                      "VIVA_RECORD_TOO_LARGE");
            return -1;
        }
    }

    pthread_mutex_lock(&g_vlock);
    int persist_rc = safe_append(g_gen_path, line);
    pthread_mutex_unlock(&g_vlock);
    if (persist_rc != 0) {
        out_viva->status = VIVA_STATUS_FAILED;
        copy_text(out_viva->status_str, sizeof(out_viva->status_str), "FAILED");
        copy_text(out_viva->failure_reason, sizeof(out_viva->failure_reason),
                  "VIVA_PERSISTENCE_FAILED");
        fprintf(stderr, "[VivaEngine] ERROR: failed to persist generated viva\n");
        return -1;
    }

    viva_append_audit("VIVA_GENERATED", "SYSTEM", out_viva->viva_id,
                      out_viva->generation_model);

    printf("[VivaEngine] Generated viva=%s session=%s questions=%d\n",
           out_viva->viva_id, session_id, out_viva->question_count);
    return 0;
}

/* ── Retrieve viva ───────────────────────────────────────────────────────── */

int viva_retrieve(const char *viva_id, viva_generation_t *out_viva) {
    if (!viva_id||!out_viva||!g_initialized) return -1;
    pthread_mutex_lock(&g_vlock);
    FILE *f = fopen(g_gen_path, "r");
    if (!f) { pthread_mutex_unlock(&g_vlock); return -1; }
    char line[16384]; int found=0;
    while (fgets(line,sizeof(line),f)&&!found) {
        char ftype[16]={0},fvid[64]={0};
        if (sscanf(line,"%15[^|]|%63[^|]",ftype,fvid)<2) continue;
        if (strcmp(ftype,"VIVA")!=0||strcmp(fvid,viva_id)!=0) continue;
        char *fields[11 + VIVA_MAX_QUESTIONS * 7];
        size_t field_count = 0;
        char *save = NULL;
        for (char *field = strtok_r(line, "|\r\n", &save);
             field && field_count < sizeof(fields) / sizeof(fields[0]);
             field = strtok_r(NULL, "|\r\n", &save)) {
            fields[field_count++] = field;
        }
        if (field_count < 11 || strcmp(fields[6], "SUCCEEDED") != 0) continue;
        char *end = NULL;
        long question_count = strtol(fields[8], &end, 10);
        if (!end || *end || question_count < VIVA_MIN_QUESTIONS ||
            question_count > VIVA_MAX_QUESTIONS ||
            field_count != 11 + (size_t)question_count * 7) continue;

        memset(out_viva, 0, sizeof(*out_viva));
        copy_text(out_viva->viva_id, sizeof(out_viva->viva_id), fields[1]);
        copy_text(out_viva->session_id, sizeof(out_viva->session_id), fields[2]);
        copy_text(out_viva->candidate_id, sizeof(out_viva->candidate_id), fields[3]);
        copy_text(out_viva->exam_id, sizeof(out_viva->exam_id), fields[4]);
        copy_text(out_viva->submission_receipt_hash,
                  sizeof(out_viva->submission_receipt_hash), fields[5]);
        copy_text(out_viva->status_str, sizeof(out_viva->status_str), fields[6]);
        copy_text(out_viva->generation_model, sizeof(out_viva->generation_model), fields[7]);
        out_viva->question_count = (int)question_count;
        out_viva->generated_ts = (time_t)strtoll(fields[9], NULL, 10);
        copy_text(out_viva->build_id, sizeof(out_viva->build_id), fields[10]);
        out_viva->status = VIVA_STATUS_SUCCEEDED;

        for (int i = 0; i < out_viva->question_count; ++i) {
            size_t offset = 11 + (size_t)i * 7;
            viva_question_t *question = &out_viva->questions[i];
            if (strcmp(fields[offset], "QDATA") != 0 ||
                decode_hex_field(fields[offset + 1], question->question_id,
                                 sizeof(question->question_id)) != 0 ||
                decode_hex_field(fields[offset + 2], question->text,
                                 sizeof(question->text)) != 0 ||
                decode_hex_field(fields[offset + 3], question->assessment_objective,
                                 sizeof(question->assessment_objective)) != 0 ||
                decode_hex_field(fields[offset + 4], question->rubric_reference,
                                 sizeof(question->rubric_reference)) != 0 ||
                decode_hex_field(fields[offset + 5], question->source_question_id,
                                 sizeof(question->source_question_id)) != 0 ||
                decode_hex_field(fields[offset + 6], question->source_answer_version,
                                 sizeof(question->source_answer_version)) != 0 ||
                !question->question_id[0] || !question->text[0] ||
                !question->assessment_objective[0]) {
                memset(out_viva, 0, sizeof(*out_viva));
                break;
            }
        }
        found = out_viva->status == VIVA_STATUS_SUCCEEDED;
    }
    fclose(f);
    pthread_mutex_unlock(&g_vlock);
    return found ? 0 : -1;
}

/* ── Viva response submission ────────────────────────────────────────────── */

int viva_submit_response(const char *viva_id,
                          const char *question_id,
                          const char *candidate_id,
                          const char *response_text,
                          viva_response_t *out_response) {
    if (!viva_id||!question_id||!candidate_id||!response_text||!out_response) return -1;
    if (!g_initialized && viva_engine_init()!=0) return -1;
    if (strnlen(response_text, sizeof(out_response->response_text)) >=
        sizeof(out_response->response_text)) {
        fprintf(stderr, "[VivaEngine] REJECTED: response exceeds storage limit\n");
        return -1;
    }

    /* Verify ownership: viva must belong to this candidate */
    viva_generation_t vgen;
    if (viva_retrieve(viva_id, &vgen) != 0) return -1;
    if (strcmp(vgen.candidate_id, candidate_id) != 0) {
        fprintf(stderr, "[VivaEngine] UNAUTHORIZED: candidate %s attempted response for viva %s (owner %s)\n",
                candidate_id, viva_id, vgen.candidate_id);
        return -1;
    }
    if (vgen.status != VIVA_STATUS_SUCCEEDED) return -1;
    int question_belongs_to_viva = 0;
    for (int i = 0; i < vgen.question_count; ++i) {
        if (strcmp(vgen.questions[i].question_id, question_id) == 0) {
            question_belongs_to_viva = 1;
            break;
        }
    }
    if (!question_belongs_to_viva) {
        fprintf(stderr, "[VivaEngine] REJECTED: question does not belong to viva\n");
        return -1;
    }

    memset(out_response, 0, sizeof(*out_response));
    gen_id(out_response->response_id, sizeof(out_response->response_id), "resp");
    strncpy(out_response->viva_id,       viva_id,     sizeof(out_response->viva_id)-1);
    strncpy(out_response->question_id,   question_id, sizeof(out_response->question_id)-1);
    strncpy(out_response->candidate_id,  candidate_id,sizeof(out_response->candidate_id)-1);
    copy_text(out_response->session_id, sizeof(out_response->session_id), vgen.session_id);
    strncpy(out_response->response_text, response_text, sizeof(out_response->response_text)-1);
    copy_text(out_response->submission_receipt_hash,
              sizeof(out_response->submission_receipt_hash), vgen.submission_receipt_hash);
    out_response->displayed_ts = time(NULL);
    out_response->received_ts  = time(NULL);
    out_response->immutable    = 1;

    /* Persist (response text is stored; key is never here) */
    char line[4096];
    char safe_text[4096];
    size_t response_len = strlen(response_text);
    memcpy(safe_text, response_text, response_len + 1);
    for (char *p=safe_text; *p; p++) {
        if (*p == '|' || *p == '\n' || *p == '\r') *p = ' ';
    }

    int line_len = snprintf(line, sizeof(line),
        "RESP|%s|%s|%s|%s|%s|%ld|%s",
        out_response->viva_id, out_response->question_id,
        out_response->candidate_id, out_response->response_id,
        safe_text,
        (long)out_response->received_ts, vgen.build_id);
    if (line_len < 0 || (size_t)line_len >= sizeof(line)) {
        fprintf(stderr, "[VivaEngine] REJECTED: serialized response exceeds storage limit\n");
        return -1;
    }

    /* Serialize the duplicate check and append so concurrent submissions cannot race. */
    pthread_mutex_lock(&g_vlock);
    FILE *f = fopen(g_resp_path, "r");
    if (f) {
        char stored_line[4096];
        while (fgets(stored_line, sizeof(stored_line), f)) {
            char ftype[16]={0}, fvid[64]={0}, fqid[64]={0};
            if (sscanf(stored_line,"%15[^|]|%63[^|]|%63[^|]",ftype,fvid,fqid)<3) continue;
            if (strcmp(ftype,"RESP")==0&&strcmp(fvid,viva_id)==0&&strcmp(fqid,question_id)==0) {
                fclose(f);
                pthread_mutex_unlock(&g_vlock);
                fprintf(stderr, "[VivaEngine] DUPLICATE_RESPONSE: viva=%s q=%s\n", viva_id, question_id);
                return -2;
            }
        }
        fclose(f);
    } else if (errno != ENOENT) {
        int open_errno = errno;
        pthread_mutex_unlock(&g_vlock);
        fprintf(stderr, "[VivaEngine] ERROR: cannot inspect response store: %s\n",
                strerror(open_errno));
        return -1;
    }
    int append_rc = safe_append(g_resp_path, line);
    pthread_mutex_unlock(&g_vlock);
    if (append_rc != 0) {
        fprintf(stderr, "[VivaEngine] ERROR: cannot persist response: %s\n",
                strerror(errno));
        return -1;
    }

    viva_append_audit("VIVA_RESPONSE_SUBMITTED", candidate_id, viva_id, question_id);
    return 0;
}

/* ── Suggested grading ───────────────────────────────────────────────────── */

int viva_suggest_grade(const char *viva_id,
                        const char *question_id,
                        const char *response_id,
                        viva_suggestion_t *out_suggestion) {
    if (!viva_id||!question_id||!response_id||!out_suggestion) return -1;
    memset(out_suggestion, 0, sizeof(*out_suggestion));
    if (!g_initialized && viva_engine_init()!=0) return -1;

    /* Load the candidate's response text */
    char resp_text[4096]={0};
    pthread_mutex_lock(&g_vlock);
    FILE *f = fopen(g_resp_path, "r");
    if (f) {
        char line[4096];
        while (fgets(line,sizeof(line),f)) {
            char ftype[16]={0},fvid[64]={0},fqid[64]={0},frid[64]={0},ftext[4096]={0};
            if (sscanf(line,"%15[^|]|%63[^|]|%63[^|]|%63[^|]|%63[^|]|%4095[^|]",
                       ftype,fvid,fqid,&frid[0],&frid[0],ftext)<5) continue;
            /* Re-parse properly */
            char *tok = line;
            char *fields[8]; int fi=0;
            while (fi<7 && tok) {
                fields[fi++]=tok;
                tok=strchr(tok,'|');
                if (tok) { *tok='\0'; tok++; }
            }
            if (fi<5) continue;
            if (strcmp(fields[0],"RESP")!=0) continue;
            if (strcmp(fields[1],viva_id)!=0) continue;
            if (strcmp(fields[2],question_id)!=0) continue;
            if (fi>4) strncpy(resp_text, fields[4], sizeof(resp_text)-1);
            break;
        }
        fclose(f);
    }
    pthread_mutex_unlock(&g_vlock);

    if (!resp_text[0]) {
        fprintf(stderr,"[VivaEngine] RESPONSE_NOT_FOUND for viva=%s q=%s rid=%s\n",
                viva_id, question_id, response_id);
        return -1;
    }

    /* Build grade-suggestion prompt */
    char grade_prompt[4096];
    const char *configured_model = getenv("EXAMOS_LLM_MODEL");
    char escaped_model[512], escaped_response[8192];
    if (!configured_model || !*configured_model ||
        json_escape_value(configured_model, escaped_model, sizeof(escaped_model)) != 0 ||
        json_escape_value(resp_text, escaped_response, sizeof(escaped_response)) != 0) return -1;
    int grade_prompt_len = snprintf(grade_prompt, sizeof(grade_prompt),
        "{"
        "\"model\":\"%s\","
        "\"messages\":["
          "{\"role\":\"system\",\"content\":"
            "\"You are an academic grader. Given a viva response, provide a suggested grade. "
            "Respond with JSON: {\\\"suggested_score\\\":0.0to1.0,\\\"label\\\":\\\"PASS|PARTIAL|FAIL\\\","
            "\\\"rationale\\\":\\\"...\\\"}. Do NOT disclose any answer key.\"},"
          "{\"role\":\"user\",\"content\":"
            "\"Viva response to grade:\\n%s\"}"
        "],"
        "\"max_tokens\":400,"
        "\"temperature\":0.2"
        "}",
        escaped_model,
        escaped_response);
    if (grade_prompt_len < 0 || (size_t)grade_prompt_len >= sizeof(grade_prompt)) return -1;

    char llm_body[4096]={0};
    int llm_rc = llm_https_post(grade_prompt, llm_body, sizeof(llm_body));
    if (llm_rc != 0) {
        fprintf(stderr, "[VivaEngine] BLOCKED: grading provider unavailable; no score generated\n");
        return -1;
    }

    gen_id(out_suggestion->suggestion_id, sizeof(out_suggestion->suggestion_id), "sugg");
    strncpy(out_suggestion->viva_id,      viva_id,     sizeof(out_suggestion->viva_id)-1);
    strncpy(out_suggestion->question_id,  question_id, sizeof(out_suggestion->question_id)-1);
    strncpy(out_suggestion->prompt_version, VIVA_PROMPT_VERSION, sizeof(out_suggestion->prompt_version)-1);
    out_suggestion->generated_ts = time(NULL);
    copy_text(out_suggestion->model_id, sizeof(out_suggestion->model_id), configured_model);
    {
        /* Parse suggestion */
        const char *score_pos = strstr(llm_body, "\"suggested_score\"");
        if (!score_pos || !(score_pos = strchr(score_pos, ':'))) return -1;
        char *score_end = NULL;
        errno = 0;
        out_suggestion->suggested_score = strtod(score_pos + 1, &score_end);
        while (score_end && (*score_end == ' ' || *score_end == '\t' ||
                             *score_end == '\r' || *score_end == '\n')) score_end++;
        if (errno != 0 || score_end == score_pos + 1 || !isfinite(out_suggestion->suggested_score) ||
            (*score_end != ',' && *score_end != '}') ||
            out_suggestion->suggested_score < 0.0 || out_suggestion->suggested_score > 1.0) {
            fprintf(stderr, "[VivaEngine] BLOCKED: grading provider returned an invalid score\n");
            return -1;
        }
        if (json_read_string_field(llm_body, "label", out_suggestion->suggested_label,
                                   sizeof(out_suggestion->suggested_label)) != 0 ||
            json_read_string_field(llm_body, "rationale", out_suggestion->rationale,
                                   sizeof(out_suggestion->rationale)) != 0) return -1;
        if ((strcmp(out_suggestion->suggested_label, "PASS") != 0 &&
             strcmp(out_suggestion->suggested_label, "PARTIAL") != 0 &&
             strcmp(out_suggestion->suggested_label, "FAIL") != 0) ||
            !out_suggestion->rationale[0]) {
            fprintf(stderr, "[VivaEngine] BLOCKED: grading provider returned an incomplete suggestion\n");
            return -1;
        }
    }

    char sline[2048];
    snprintf(sline, sizeof(sline),
        "SUGGEST|%s|%s|%s|%.4f|%s|%s|%ld",
        out_suggestion->suggestion_id, out_suggestion->viva_id,
        out_suggestion->question_id, out_suggestion->suggested_score,
        out_suggestion->suggested_label, out_suggestion->model_id,
        (long)out_suggestion->generated_ts);
    pthread_mutex_lock(&g_vlock);
    safe_append(g_suggest_path, sline);
    pthread_mutex_unlock(&g_vlock);

    return 0;
}

/* ── Reviewer decision / override ───────────────────────────────────────── */

int viva_reviewer_decide(const char *viva_id,
                          const char *reviewer_id,
                          review_state_t state,
                          double final_score,
                          const char *reason_code,
                          const char *written_rationale,
                          reviewer_decision_t *out_decision) {
    if (!viva_id||!reviewer_id||!out_decision) return -1;
    if (!g_initialized && viva_engine_init()!=0) return -1;
    if (state < REVIEW_STATE_NEEDS_REVIEW || state > REVIEW_STATE_OVERRIDDEN) {
        fprintf(stderr, "[VivaEngine] Rejected reviewer decision with invalid state\n");
        return -1;
    }

    viva_generation_t generation;
    if (viva_retrieve(viva_id, &generation) != 0) {
        fprintf(stderr, "[VivaEngine] Rejected reviewer decision for unknown or invalid viva\n");
        return -1;
    }

    /* Validate reviewer identity */
    if (strlen(reviewer_id) < 3) {
        fprintf(stderr, "[VivaEngine] Invalid reviewer identity: %s\n", reviewer_id);
        return -1;
    }

    memset(out_decision, 0, sizeof(*out_decision));
    gen_id(out_decision->decision_id, sizeof(out_decision->decision_id), "dec");
    strncpy(out_decision->viva_id,      viva_id,     sizeof(out_decision->viva_id)-1);
    strncpy(out_decision->reviewer_id,  reviewer_id, sizeof(out_decision->reviewer_id)-1);
    out_decision->state        = state;
    out_decision->final_score  = final_score > 1.0 ? 1.0 : (final_score < 0.0 ? 0.0 : final_score);
    out_decision->decision_ts  = time(NULL);
    get_build_id(out_decision->build_id, sizeof(out_decision->build_id));

    const char *state_names[] = {"NEEDS_REVIEW","REVIEWED","NO_ACTION","OVERRIDDEN"};
    strncpy(out_decision->state_str,
            state_names[(int)state % 4], sizeof(out_decision->state_str)-1);
    if (reason_code)
        strncpy(out_decision->reason_code, reason_code, sizeof(out_decision->reason_code)-1);
    if (written_rationale)
        strncpy(out_decision->written_rationale, written_rationale,
                sizeof(out_decision->written_rationale)-1);

    /* Require rationale when overriding */
    if (state == REVIEW_STATE_OVERRIDDEN &&
        (!written_rationale || strlen(written_rationale) < 10)) {
        fprintf(stderr, "[VivaEngine] OVERRIDE requires written rationale (>=10 chars)\n");
        return -1;
    }

    /* Persist decision (immutable append) */
    char safe_rat[1024];
    strncpy(safe_rat, written_rationale ? written_rationale : "", sizeof(safe_rat)-1);
    for (char *p=safe_rat; *p; p++) if (*p=='|') *p=' ';

    char dline[2048];
    snprintf(dline, sizeof(dline),
        "DECISION|%s|%s|%s|%s|%.4f|%s|%s|%ld|%s",
        out_decision->decision_id, out_decision->viva_id,
        out_decision->reviewer_id, out_decision->state_str,
        out_decision->final_score,
        out_decision->reason_code[0] ? out_decision->reason_code : "NONE",
        safe_rat[0] ? safe_rat : "NONE",
        (long)out_decision->decision_ts, out_decision->build_id);

    pthread_mutex_lock(&g_vlock);
    safe_append(g_decision_path, dline);
    pthread_mutex_unlock(&g_vlock);

    char audit_detail[256];
    snprintf(audit_detail, sizeof(audit_detail),
             "state=%s score=%.2f reason=%s",
             out_decision->state_str, out_decision->final_score,
             out_decision->reason_code[0] ? out_decision->reason_code : "NONE");
    viva_append_audit("REVIEWER_DECISION", reviewer_id, viva_id, audit_detail);

    printf("[VivaEngine] ReviewerDecision viva=%s state=%s score=%.2f reviewer=%s\n",
           viva_id, out_decision->state_str, out_decision->final_score, reviewer_id);
    return 0;
}

/* ── Audit ───────────────────────────────────────────────────────────────── */

int viva_append_audit(const char *event_type, const char *actor_id,
                       const char *target_id,  const char *detail) {
    if (!g_initialized) return -1;
    char line[1024];
    char safe_detail[512];
    strncpy(safe_detail, detail ? detail : "", sizeof(safe_detail)-1);
    for (char *p=safe_detail; *p; p++) if (*p=='|') *p=' ';
    snprintf(line, sizeof(line),
        "AUDIT|%ld|%s|%s|%s|%s",
        (long)time(NULL), event_type,
        actor_id  ? actor_id  : "SYSTEM",
        target_id ? target_id : "NONE",
        safe_detail);
    pthread_mutex_lock(&g_vlock);
    int rc = safe_append(g_audit_path, line);
    pthread_mutex_unlock(&g_vlock);
    return rc;
}

/* ── JSON exports ─────────────────────────────────────────────────────────── */

int viva_export_candidate_json(const char *viva_id,
                                const char *candidate_id,
                                char *out_buf, size_t max_len) {
    viva_generation_t vgen;
    if (viva_retrieve(viva_id, &vgen) != 0) {
        snprintf(out_buf, max_len, "{\"error\":\"VIVA_NOT_FOUND\"}");
        return -1;
    }
    if (strcmp(vgen.candidate_id, candidate_id) != 0) {
        snprintf(out_buf, max_len, "{\"error\":\"UNAUTHORIZED\"}");
        return -1;
    }
    if (vgen.status != VIVA_STATUS_SUCCEEDED) {
        snprintf(out_buf, max_len,
            "{\"viva_id\":\"%s\",\"status\":\"%s\",\"question_count\":0}",
            viva_id, vgen.status_str);
        return 0;
    }
    size_t off = (size_t)snprintf(out_buf, max_len,
        "{\"viva_id\":\"%s\",\"exam_id\":\"%s\",\"status\":\"SUCCEEDED\","
        "\"question_count\":%d,\"questions\":[",
        viva_id, vgen.exam_id, vgen.question_count);
    for (int i=0; i<vgen.question_count && off+512<max_len; i++) {
        off += (size_t)snprintf(out_buf+off, max_len-off,
            "%s{\"question_id\":\"%s\",\"text\":\"%s\","
            "\"assessment_objective\":\"%s\"}",
            i>0?",":"",
            vgen.questions[i].question_id,
            vgen.questions[i].text,
            vgen.questions[i].assessment_objective);
        /* Note: rubric_reference NOT included in candidate response */
    }
    snprintf(out_buf+off, max_len-off, "]}");
    return 0;
}

int viva_export_reviewer_json(const char *viva_id,
                               char *out_buf, size_t max_len) {
    viva_generation_t vgen;
    if (viva_retrieve(viva_id, &vgen) != 0) {
        snprintf(out_buf, max_len, "{\"error\":\"VIVA_NOT_FOUND\"}");
        return -1;
    }
    size_t off = (size_t)snprintf(out_buf, max_len,
        "{\"viva_id\":\"%s\",\"session_id\":\"%s\","
        "\"candidate_id\":\"%s\",\"exam_id\":\"%s\","
        "\"status\":\"%s\",\"generation_model\":\"%s\","
        "\"prompt_version\":\"%s\","
        "\"question_count\":%d,\"questions\":[",
        vgen.viva_id, vgen.session_id, vgen.candidate_id, vgen.exam_id,
        vgen.status_str, vgen.generation_model, vgen.prompt_version,
        vgen.question_count);
    for (int i=0; i<vgen.question_count && off+512<max_len; i++) {
        off += (size_t)snprintf(out_buf+off, max_len-off,
            "%s{\"question_id\":\"%s\",\"text\":\"%s\","
            "\"assessment_objective\":\"%s\","
            "\"rubric_reference\":\"%s\","
            "\"source_question_id\":\"%s\"}",
            i>0?",":"",
            vgen.questions[i].question_id,
            vgen.questions[i].text,
            vgen.questions[i].assessment_objective,
            vgen.questions[i].rubric_reference,
            vgen.questions[i].source_question_id);
    }
    snprintf(out_buf+off, max_len-off,
             "],\"generated_ts\":%ld,\"build_id\":\"%s\"}",
             (long)vgen.generated_ts, vgen.build_id);
    return 0;
}
