#define _GNU_SOURCE
#include "../include/attestation_client.h"

#include <curl/curl.h>
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

static int json_string(const char *json, const char *key, char *out, size_t size)
{
    if (!json || !key || !out || size == 0) return -1;
    out[0] = '\0';
    char pattern[96];
    int n = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (n < 0 || (size_t)n >= sizeof(pattern)) return -1;
    const char *p = strstr(json, pattern);
    if (!p) return -1;
    p += (size_t)n;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (*p++ != ':') return -1;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (*p++ != '"') return -1;
    size_t used = 0;
    while (*p && *p != '"') {
        if (*p == '\\' || used + 1 >= size) return -1;
        out[used++] = *p++;
    }
    if (*p != '"') return -1;
    out[used] = '\0';
    return 0;
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
                                       char *out_nonce, size_t nonce_size)
{
    if (!safe_identifier(device_id, 64) || !safe_identifier(release_id, 64) ||
        !safe_identifier(session_id, 64) || !out_nonce || nonce_size < 65) return -1;
    char endpoint[1024], body[512], response[2048];
    if (make_endpoint(heartbeat_url, "nonce", endpoint, sizeof(endpoint)) != 0 ||
        snprintf(body, sizeof(body),
            "{\"device_id\":\"%s\",\"release_id\":\"%s\",\"session_id\":\"%s\"}",
            device_id, release_id, session_id) >= (int)sizeof(body)) return -1;
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
