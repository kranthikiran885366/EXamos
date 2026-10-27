/*
 * controller.c — Shared helpers for all ExamOS controllers.
 * JSON response formatting, auth extraction, CORS, parameter parsing.
 */

#include "controller.h"
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 413: return "Payload Too Large";
        case 415: return "Unsupported Media Type";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        default: return "Internal Server Error";
    }
}

void ctrl_send_json(int client_fd, int status_code, const char *body,
                    const char *extra_headers) {
    char header[2400];
    size_t body_len = body ? strlen(body) : 0;
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store, no-cache, must-revalidate\r\n"
        "Pragma: no-cache\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Cross-Origin-Opener-Policy: same-origin\r\n"
        "Content-Security-Policy: default-src 'none'; connect-src 'self'; frame-ancestors 'none'\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text(status_code), body_len,
        extra_headers ? extra_headers : "");
    if (hlen < 0 || (size_t)hlen >= sizeof(header)) return;
    send(client_fd, header, (size_t)hlen, 0);
    if (body_len > 0) send(client_fd, body, body_len, 0);
}

void ctrl_send_error(int client_fd, int status_code, const char *error) {
    char body[512];
    int blen = snprintf(body, sizeof(body), "{\"error\":\"%s\"}", error ? error : "error");
    if (blen < 0) blen = 0;
    ctrl_send_json(client_fd, status_code, body, NULL);
}

int ctrl_extract_bearer(const char *auth_header, char *out, size_t out_len) {
    if (!auth_header || !out || out_len == 0) return 0;
    out[0] = '\0';
    if (strncasecmp(auth_header, "Bearer ", 7) == 0) {
        const char *t = auth_header + 7;
        while (*t == ' ' || *t == '\t') t++;
        size_t len = strlen(t);
        if (len > 0 && len < out_len) {
            memcpy(out, t, len);
            out[len] = '\0';
            return 1;
        }
    }
    return 0;
}

int ctrl_json_string(const char *body, const char *key, char *out, size_t out_len) {
    if (!body || !key || !out || out_len == 0) return 0;
    out[0] = '\0';
    /* Search for "key":"value" or "key": "value" */
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(body, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_len) {
        if (*p == '\\' && p[1]) { p++; out[i++] = *p; }
        else out[i++] = *p;
        p++;
    }
    out[i] = '\0';
    return i > 0;
}

int ctrl_json_int(const char *body, const char *key, int *out) {
    if (!body || !key || !out) return 0;
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(body, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p == '"') p++;
    char tmp[32] = {0};
    size_t i = 0;
    if (*p == '-') { tmp[i++] = *p++; }
    while (*p >= '0' && *p <= '9' && i + 1 < sizeof(tmp)) {
        tmp[i++] = *p++;
    }
    if (i == 0) return 0;
    *out = atoi(tmp);
    return 1;
}

int ctrl_json_bool(const char *body, const char *key, int *out) {
    if (!body || !key || !out) return 0;
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(body, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (strncmp(p, "true", 4) == 0 || strncmp(p, "\"true\"", 6) == 0 || *p == '1') {
        *out = 1;
        return 1;
    }
    if (strncmp(p, "false", 5) == 0 || strncmp(p, "\"false\"", 7) == 0 || *p == '0') {
        *out = 0;
        return 1;
    }
    return 0;
}

int ctrl_extract_origin(const char *buffer, char *out, size_t out_len) {
    if (!buffer || !out || out_len == 0) return 0;
    const char *line = strstr(buffer, "\r\n");
    if (!line) return 0;
    line += 2;
    const char *headers_end = strstr(buffer, "\r\n\r\n");
    while (line < headers_end) {
        const char *le = strstr(line, "\r\n");
        if (!le || le > headers_end) break;
        const char *colon = memchr(line, ':', (size_t)(le - line));
        if (colon && (size_t)(colon - line) == sizeof("Origin") - 1 &&
            strncasecmp(line, "Origin", sizeof("Origin") - 1) == 0) {
            const char *v = colon + 1;
            while (v < le && (*v == ' ' || *v == '\t')) v++;
            size_t vlen = (size_t)(le - v);
            if (vlen > 0 && vlen < out_len) {
                memcpy(out, v, vlen);
                out[vlen] = '\0';
                return 1;
            }
        }
        line = le + 2;
    }
    return 0;
}

int ctrl_authorize(const char *auth_header, uint32_t required_perm,
                   auth_session_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    char token[128] = {0};
    if (!ctrl_extract_bearer(auth_header, token, sizeof(token))) return -1;
    if (security_verify_session(token, out) != 0) return -1;
    if (required_perm && !security_role_has_permission(out->role, required_perm)) {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    return 0;
}

void ctrl_set_cors(char *extra_headers, size_t extra_len,
                   const char *origin, int cors_ok) {
    if (!cors_ok || !origin || !origin[0]) return;
    int n = snprintf(extra_headers, extra_len,
        "Access-Control-Allow-Origin: %s\r\n"
        "Vary: Origin\r\n"
        "Access-Control-Allow-Credentials: true\r\n",
        origin);
    if (n < 0 || (size_t)n >= extra_len) extra_headers[0] = '\0';
}

int ctrl_cors_origin_allowed(const char *origin) {
    if (!origin || !origin[0]) return 0;
    const char *env = getenv("EXAMOS_CORS_ALLOWED_ORIGINS");
    if (!env || !env[0]) {
        return strcmp(origin, "http://localhost:5173") == 0 ||
               strcmp(origin, "http://127.0.0.1:5173") == 0;
    }
    char buf[1024];
    size_t n = strlen(env);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    memcpy(buf, env, n); buf[n] = '\0';
    char *save = NULL;
    char *tok = strtok_r(buf, ",", &save);
    while (tok) {
        while (*tok == ' ' || *tok == '\t') tok++;
        if (strcmp(tok, origin) == 0) return 1;
        tok = strtok_r(NULL, ",", &save);
    }
    return 0;
}
