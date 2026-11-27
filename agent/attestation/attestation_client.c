#define _GNU_SOURCE
#include "../include/attestation_client.h"
#include "../include/attestation.h"

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t capacity;
    size_t length;
} response_buffer_t;

static size_t receive_response(char *data, size_t size, size_t count, void *opaque)
{
    response_buffer_t *response = opaque;
    size_t bytes = size * count;
    if (!response || bytes >= response->capacity - response->length) return 0;
    memcpy(response->data + response->length, data, bytes);
    response->length += bytes;
    response->data[response->length] = '\0';
    return bytes;
}

static int safe_identifier(const char *value, size_t max_length)
{
    if (!value || !value[0] || strlen(value) >= max_length) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!( (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
               (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' ||
               *p == ':' || *p == '-')) return 0;
    return 1;
}

static int make_endpoint(const char *heartbeat_url, const char *suffix,
                         char *out, size_t out_size)
{
    static const char heartbeat_path[] = "/api/v1/heartbeat";
    if (!heartbeat_url || strncmp(heartbeat_url, "https://", 8) != 0) return -1;
    size_t url_len = strlen(heartbeat_url);
    size_t path_len = sizeof(heartbeat_path) - 1;
    if (url_len < path_len || strcmp(heartbeat_url + url_len - path_len,
                                    heartbeat_path) != 0) return -1;
    size_t prefix_len = url_len - path_len;
    int written = snprintf(out, out_size, "%.*s/api/v1/attestation/%s",
                           (int)prefix_len, heartbeat_url, suffix);
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}

#define JSON_DEPTH_LIMIT 32
#define JSON_DOCUMENT_LIMIT (1024 * 1024)

typedef struct {
    const char *p;
    const char *end;
    unsigned int depth;
} json_cursor_t;

static void json_skip_ws(json_cursor_t *cursor)
{
    while (cursor->p < cursor->end &&
           (*cursor->p == ' ' || *cursor->p == '\t' ||
            *cursor->p == '\r' || *cursor->p == '\n'))
        cursor->p++;
}

static int json_skip_string(json_cursor_t *cursor)
{
    if (cursor->p >= cursor->end || *cursor->p++ != '"') return -1;
    while (cursor->p < cursor->end) {
        unsigned char c = (unsigned char)*cursor->p++;
        if (c == '"') return 0;
        if (c < 0x20) return -1;
        if (c != '\\') continue;
        if (cursor->p >= cursor->end) return -1;
        unsigned char escaped = (unsigned char)*cursor->p++;
        switch (escaped) {
            case '"': case '\\': case '/': case 'b':
            case 'f': case 'n': case 'r': case 't':
                break;
            case 'u':
                if (cursor->end - cursor->p < 4) return -1;
                for (int i = 0; i < 4; i++) {
                    if (!isxdigit((unsigned char)cursor->p[i])) return -1;
                }
                cursor->p += 4;
                break;
            default:
                return -1;
        }
    }
    return -1;
}

static int json_skip_number(json_cursor_t *cursor)
{
    if (cursor->p < cursor->end && *cursor->p == '-') cursor->p++;
    if (cursor->p >= cursor->end) return -1;
    if (*cursor->p == '0') {
        cursor->p++;
    } else if (*cursor->p >= '1' && *cursor->p <= '9') {
        while (cursor->p < cursor->end && isdigit((unsigned char)*cursor->p)) cursor->p++;
    } else {
        return -1;
    }
    if (cursor->p < cursor->end && *cursor->p == '.') {
        cursor->p++;
        if (cursor->p >= cursor->end || !isdigit((unsigned char)*cursor->p)) return -1;
        while (cursor->p < cursor->end && isdigit((unsigned char)*cursor->p)) cursor->p++;
    }
    if (cursor->p < cursor->end && (*cursor->p == 'e' || *cursor->p == 'E')) {
        cursor->p++;
        if (cursor->p < cursor->end && (*cursor->p == '+' || *cursor->p == '-')) cursor->p++;
        if (cursor->p >= cursor->end || !isdigit((unsigned char)*cursor->p)) return -1;
        while (cursor->p < cursor->end && isdigit((unsigned char)*cursor->p)) cursor->p++;
    }
    return 0;
}

static int json_skip_value(json_cursor_t *cursor);

static int json_skip_container(json_cursor_t *cursor, char open, char close)
{
    if (cursor->p >= cursor->end || *cursor->p++ != open) return -1;
    json_skip_ws(cursor);
    if (cursor->p < cursor->end && *cursor->p == close) {
        cursor->p++;
        return 0;
    }
    for (;;) {
        json_skip_ws(cursor);
        if (open == '{') {
            if (json_skip_string(cursor) != 0) return -1;
            json_skip_ws(cursor);
            if (cursor->p >= cursor->end || *cursor->p++ != ':') return -1;
            json_skip_ws(cursor);
        }
        if (json_skip_value(cursor) != 0) return -1;
        json_skip_ws(cursor);
        if (cursor->p >= cursor->end) return -1;
        char separator = *cursor->p++;
        if (separator == close) return 0;
        if (separator != ',') return -1;
    }
}

static int json_skip_value(json_cursor_t *cursor)
{
    if (++cursor->depth > JSON_DEPTH_LIMIT) return -1;
    json_skip_ws(cursor);
    if (cursor->p >= cursor->end) return -1;

    int result;
    char c = *cursor->p;
    if (c == '"') {
        result = json_skip_string(cursor);
    } else if (c == '{') {
        result = json_skip_container(cursor, '{', '}');
    } else if (c == '[') {
        result = json_skip_container(cursor, '[', ']');
    } else if (c == '-' || isdigit((unsigned char)c)) {
        result = json_skip_number(cursor);
    } else if ((size_t)(cursor->end - cursor->p) >= 4 &&
               memcmp(cursor->p, "true", 4) == 0) {
        cursor->p += 4;
        result = 0;
    } else if ((size_t)(cursor->end - cursor->p) >= 5 &&
               memcmp(cursor->p, "false", 5) == 0) {
        cursor->p += 5;
        result = 0;
    } else if ((size_t)(cursor->end - cursor->p) >= 4 &&
               memcmp(cursor->p, "null", 4) == 0) {
        cursor->p += 4;
        result = 0;
    } else {
        result = -1;
    }
    cursor->depth--;
    return result;
}

static int json_decode_string(const char *start, const char *end,
                              char *out, size_t size)
{
    if (!start || !end || !out || size == 0 || end <= start || *start != '"')
        return -1;
    const char *p = start + 1;
    const char *closing = end - 1;
    size_t used = 0;
    while (p < closing) {
        unsigned char c = (unsigned char)*p++;
        if (c == '\\') {
            if (p >= closing) return -1;
            unsigned char escaped = (unsigned char)*p++;
            switch (escaped) {
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case '/': c = '/'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'u': {
                    if (closing - p < 4) return -1;
                    unsigned int codepoint = 0;
                    for (int digit = 0; digit < 4; digit++) {
                        unsigned char hex = (unsigned char)*p++;
                        if (!isxdigit(hex)) return -1;
                        codepoint = (codepoint << 4) |
                            (unsigned int)(isdigit(hex) ? hex - '0' :
                                           (tolower(hex) - 'a' + 10));
                    }
                    if (codepoint == 0 || codepoint >= 0x80) return -1;
                    c = (unsigned char)codepoint;
                    break;
                }
                default:
                    return -1;
            }
        }
        if (c == '\0' || used + 1 >= size) return -1;
        out[used++] = (char)c;
    }
    out[used] = '\0';
    return 0;
}

/* Validates the whole document and returns the value position for a top-level key. */
static int json_find_member(const char *json, const char *key, json_cursor_t *value)
{
    size_t length = strlen(json);
    if (length == 0 || length > JSON_DOCUMENT_LIMIT) return -1;

    json_cursor_t document = { json, json + length, 0 };
    json_cursor_t validated = document;
    if (json_skip_value(&validated) != 0) return -1;
    json_skip_ws(&validated);
    if (validated.p != validated.end) return -1;

    json_cursor_t cursor = document;
    json_skip_ws(&cursor);
    if (cursor.p >= cursor.end || *cursor.p++ != '{') return -1;
    json_skip_ws(&cursor);
    if (cursor.p < cursor.end && *cursor.p == '}') return -1;

    for (;;) {
        json_skip_ws(&cursor);
        const char *key_start = cursor.p;
        if (json_skip_string(&cursor) != 0) return -1;
        char decoded_key[128];
        if (json_decode_string(key_start, cursor.p, decoded_key,
                               sizeof(decoded_key)) != 0)
            return -1;
        json_skip_ws(&cursor);
        if (cursor.p >= cursor.end || *cursor.p++ != ':') return -1;
        json_skip_ws(&cursor);

        if (strcmp(decoded_key, key) == 0) {
            *value = cursor;
            return 0;
        }
        if (json_skip_value(&cursor) != 0) return -1;
        json_skip_ws(&cursor);
        if (cursor.p >= cursor.end) return -1;
        char separator = *cursor.p++;
        if (separator == '}') return -1;
        if (separator != ',') return -1;
    }
}

static int json_string(const char *json, const char *key, char *out, size_t size)
{
    if (!json || !key || !out || size == 0 || strlen(key) >= 128) return -1;
    out[0] = '\0';

    json_cursor_t value;
    if (json_find_member(json, key, &value) != 0) return -1;
    if (value.p >= value.end || *value.p != '"') return -1;

    json_cursor_t end = value;
    if (json_skip_string(&end) != 0) return -1;
    return json_decode_string(value.p, end.p, out, size);
}

/* Returns 1 for true, 0 for false, -1 when the key is absent or not a boolean. */
static int json_bool(const char *json, const char *key, int *out)
{
    if (!json || !key || !out || strlen(key) >= 128) return -1;

    json_cursor_t value;
    if (json_find_member(json, key, &value) != 0) return -1;
    size_t remaining = (size_t)(value.end - value.p);
    if (remaining >= 4 && memcmp(value.p, "true", 4) == 0) {
        *out = 1;
        return 0;
    }
    if (remaining >= 5 && memcmp(value.p, "false", 5) == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int post_json(const char *url, const char *body,
                     char *response_data, size_t response_capacity,
                     long *http_status)
{
    const char *token = getenv("EXAMOS_AGENT_API_TOKEN");
    if (!url || !body || !token || strlen(token) < 32 ||
        !response_data || response_capacity < 2) return -1;
    char authorization[512];
    if (snprintf(authorization, sizeof(authorization), "Authorization: Bearer %s", token) >=
        (int)sizeof(authorization)) return -1;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, authorization);
    if (!headers) return -1;

    response_data[0] = '\0';
    response_buffer_t response = {response_data, response_capacity, 0};
    CURL *curl = curl_easy_init();
    if (!curl) { curl_slist_free_all(headers); return -1; }
    CURLcode rc = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_response);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    const char *mtls_cert = getenv("EXAMOS_MTLS_CLIENT_CERT");
    const char *mtls_key  = getenv("EXAMOS_MTLS_CLIENT_KEY");
    const char *mtls_ca   = getenv("EXAMOS_MTLS_CA_CERT");
    if (rc == CURLE_OK && mtls_ca && mtls_ca[0]) {
        rc = curl_easy_setopt(curl, CURLOPT_CAINFO, mtls_ca);
    }
    if (rc == CURLE_OK && mtls_cert && mtls_cert[0] && mtls_key && mtls_key[0]) {
        rc = curl_easy_setopt(curl, CURLOPT_SSLCERT, mtls_cert);
        if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_SSLKEY, mtls_key);
    }
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (rc == CURLE_OK) rc = curl_easy_perform(curl);
    long status = 0;
    if (rc == CURLE_OK) rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    if (http_status) *http_status = status;
    return rc == CURLE_OK ? 0 : -1;
}

int attestation_client_issue_challenge(const char *heartbeat_url,
                                       const char *device_id,
                                       const char *release_id,
                                       const char *session_id,
                                       const char *purpose,
                                       char *out_nonce, size_t nonce_size)
{
    if (!safe_identifier(device_id, 64) || !safe_identifier(release_id, 64) ||
        !safe_identifier(session_id, 64) || !purpose ||
        (strcmp(purpose, "re_attestation") != 0 &&
         strcmp(purpose, "exam_launch") != 0) ||
        !out_nonce || nonce_size < 65) return -1;
    char endpoint[1024], body[512], response[2048];
    if (make_endpoint(heartbeat_url, "nonce", endpoint, sizeof(endpoint)) != 0 ||
        snprintf(body, sizeof(body),
            "{\"device_id\":\"%s\",\"release_id\":\"%s\","
            "\"session_id\":\"%s\",\"purpose\":\"%s\"}",
            device_id, release_id, session_id, purpose) >= (int)sizeof(body))
        return -1;
    long status = 0;
    if (post_json(endpoint, body, response, sizeof(response), &status) != 0 || status != 200 ||
        json_string(response, "nonce", out_nonce, nonce_size) != 0 ||
        strlen(out_nonce) != 64) return -1;
    return 0;
}

int attestation_client_verify(const char *heartbeat_url, const char *evidence_json)
{
    char endpoint[1024], response[2048];
    if (make_endpoint(heartbeat_url, "verify", endpoint, sizeof(endpoint)) != 0)
        return -1;
    long status = 0;
    if (post_json(endpoint, evidence_json, response, sizeof(response), &status) != 0 ||
        status != 200) return -1;
    char result[32] = {0};
    return json_string(response, "status", result, sizeof(result)) == 0 &&
           strcmp(result, "TRUSTED") == 0 ? 0 : -1;
}

int attestation_client_activate(const char *heartbeat_url, const char *device_id)
{
    if (!safe_identifier(device_id, 64)) return -1;
    char ak_name_hex[69] = {0}, endpoint[1024], body[256];
    char response[16384], activation_id[64] = {0};
    char credential_blob_hex[8193] = {0}, activation_response_hex[65] = {0};
    char status_text[40] = {0};
    int result = -1;
    if (tpm_attestation_get_ak_name(ak_name_hex, sizeof(ak_name_hex)) != 0 ||
        make_endpoint(heartbeat_url, "activate", endpoint, sizeof(endpoint)) != 0 ||
        snprintf(body, sizeof(body),
            "{\"device_id\":\"%s\",\"ak_name_hex\":\"%s\"}",
            device_id, ak_name_hex) >= (int)sizeof(body)) goto cleanup;

    long http_status = 0;
    if (post_json(endpoint, body, response, sizeof(response), &http_status) != 0 ||
        http_status != 200 ||
        json_string(response, "status", status_text, sizeof(status_text)) != 0)
        goto cleanup;
    if (strcmp(status_text, "ALREADY_VERIFIED") == 0) {
        result = 0;
        goto cleanup;
    }
    if (strcmp(status_text, "ACTIVATION_CHALLENGE") != 0 ||
        json_string(response, "activation_id", activation_id, sizeof(activation_id)) != 0 ||
        strlen(activation_id) != 32 ||
        json_string(response, "credential_blob", credential_blob_hex,
                    sizeof(credential_blob_hex)) != 0 ||
        !credential_blob_hex[0] ||
        tpm_attestation_activate_credential(credential_blob_hex,
            activation_response_hex, sizeof(activation_response_hex)) != 0)
        goto cleanup;

    if (make_endpoint(heartbeat_url, "activate/complete", endpoint,
                      sizeof(endpoint)) != 0 ||
        snprintf(body, sizeof(body),
            "{\"activation_id\":\"%s\",\"device_id\":\"%s\","
            "\"activation_response\":\"%s\"}",
            activation_id, device_id, activation_response_hex) >= (int)sizeof(body))
        goto cleanup;
    int verified = 0;
    if (post_json(endpoint, body, response, sizeof(response), &http_status) != 0 ||
        http_status != 200 ||
        json_string(response, "status", status_text, sizeof(status_text)) != 0 ||
        strcmp(status_text, "ACTIVATION_SUCCESS") != 0 ||
        json_bool(response, "verified", &verified) != 0 ||
        verified != 1) goto cleanup;
    result = 0;

cleanup:
    OPENSSL_cleanse(ak_name_hex, sizeof(ak_name_hex));
    OPENSSL_cleanse(body, sizeof(body));
    OPENSSL_cleanse(response, sizeof(response));
    OPENSSL_cleanse(credential_blob_hex, sizeof(credential_blob_hex));
    OPENSSL_cleanse(activation_response_hex, sizeof(activation_response_hex));
    return result;
}

int attestation_client_rechallenge(const char *heartbeat_url,
                                   const char *device_id,
                                   const char *session_id,
                                   char *out_nonce, size_t nonce_size)
{
    if (!safe_identifier(device_id, 64) || !safe_identifier(session_id, 64) ||
        !out_nonce || nonce_size < 65) return -1;
    char endpoint[1024], body[512], response[2048];
    if (make_endpoint(heartbeat_url, "re-attest", endpoint, sizeof(endpoint)) != 0 ||
        snprintf(body, sizeof(body), "{\"device_id\":\"%s\",\"session_id\":\"%s\"}",
                 device_id, session_id) >= (int)sizeof(body)) return -1;
    long status = 0;
    if (post_json(endpoint, body, response, sizeof(response), &status) != 0 || status != 200 ||
        json_string(response, "nonce", out_nonce, nonce_size) != 0 ||
        strlen(out_nonce) != 64) return -1;
    return 0;
}

int attestation_client_poll_exam_session(const char *heartbeat_url,
                                         const char *device_id,
                                         char *out_session_id, size_t session_size,
                                         char *out_release_id, size_t release_size,
                                         char *out_purpose, size_t purpose_size)
{
    static const char heartbeat_path[] = "/api/v1/heartbeat";
    static const char pending_path[] = "/api/v1/agent/exam-attestation/pending";
    if (!safe_identifier(device_id, 64) || !out_session_id || session_size < 2 ||
        !out_release_id || release_size < 2 || !out_purpose || purpose_size < 2 ||
        !heartbeat_url ||
        strncmp(heartbeat_url, "https://", 8) != 0) return -1;
    size_t url_len = strlen(heartbeat_url);
    size_t heartbeat_path_len = sizeof(heartbeat_path) - 1;
    if (url_len < heartbeat_path_len ||
        strcmp(heartbeat_url + url_len - heartbeat_path_len, heartbeat_path) != 0)
        return -1;

    char endpoint[1024], body[256], response[2048], status_text[32];
    char purpose_text[32] = {0};
    int endpoint_len = snprintf(endpoint, sizeof(endpoint), "%.*s%s",
        (int)(url_len - heartbeat_path_len), heartbeat_url, pending_path);
    if (endpoint_len < 0 || (size_t)endpoint_len >= sizeof(endpoint) ||
        snprintf(body, sizeof(body), "{\"device_id\":\"%s\"}", device_id) >=
            (int)sizeof(body)) return -1;
    out_session_id[0] = '\0';
    out_release_id[0] = '\0';
    out_purpose[0] = '\0';

    long http_status = 0;
    if (post_json(endpoint, body, response, sizeof(response), &http_status) != 0 ||
        http_status != 200 ||
        json_string(response, "status", status_text, sizeof(status_text)) != 0)
        return -1;
    if (strcmp(status_text, "IDLE") == 0) return 0;
    if (strcmp(status_text, "CHALLENGE") != 0 ||
        json_string(response, "session_id", out_session_id, session_size) != 0 ||
        json_string(response, "release_id", out_release_id, release_size) != 0 ||
        json_string(response, "purpose", purpose_text, sizeof(purpose_text)) != 0 ||
        strlen(purpose_text) >= purpose_size ||
        (strcmp(purpose_text, "exam_launch") != 0 &&
         strcmp(purpose_text, "re_attestation") != 0) ||
        !safe_identifier(out_session_id, session_size) ||
        !safe_identifier(out_release_id, release_size)) {
        out_session_id[0] = '\0';
        out_release_id[0] = '\0';
        out_purpose[0] = '\0';
        return -1;
    }
    snprintf(out_purpose, purpose_size, "%s", purpose_text);
    return 1;
}

int attestation_client_request_exam_key(const char *heartbeat_url,
                                        const char *session_id,
                                        const char *device_id,
                                        char *out_wrapped_key,
                                        size_t wrapped_key_size) {
    static const char heartbeat_path[] = "/api/v1/heartbeat";
    if (!heartbeat_url || strncmp(heartbeat_url, "https://", 8) != 0 ||
        !safe_identifier(session_id, 64) || !safe_identifier(device_id, 64) ||
        !out_wrapped_key || wrapped_key_size < 512)
        return -1;
    size_t url_len = strlen(heartbeat_url);
    size_t heartbeat_path_len = sizeof(heartbeat_path) - 1;
    if (url_len < heartbeat_path_len ||
        strcmp(heartbeat_url + url_len - heartbeat_path_len, heartbeat_path) != 0)
        return -1;
    char endpoint[1024], body[512], response[8192];
    int endpoint_len = snprintf(endpoint, sizeof(endpoint), "%.*s/api/v1/exam/key-release",
                                (int)(url_len - heartbeat_path_len), heartbeat_url);
    int body_len = snprintf(body, sizeof(body),
                            "{\"session_id\":\"%s\",\"device_id\":\"%s\"}",
                            session_id, device_id);
    if (endpoint_len < 0 || (size_t)endpoint_len >= sizeof(endpoint) ||
        body_len < 0 || (size_t)body_len >= sizeof(body))
        return -1;
    long http_status = 0;
    if (post_json(endpoint, body, response, sizeof(response),
                  &http_status) != 0 || http_status != 200)
        return -1;
    char status[32] = {0};
    if (json_string(response, "status", status, sizeof(status)) != 0 ||
        strcmp(status, "WRAPPED") != 0 ||
        json_string(response, "wrapped_key", out_wrapped_key,
                    wrapped_key_size) != 0 ||
        strlen(out_wrapped_key) < 340)
        return -1;
    return 0;
}
