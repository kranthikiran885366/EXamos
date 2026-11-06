/*
 * controller.c — Shared helpers for all ExamOS controllers.
 * JSON response formatting, auth extraction, CORS, parameter parsing.
 */

#include "controller.h"
#include "../include/candidate_login.h"
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
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
        case 501: return "Not Implemented";
        case 503: return "Service Unavailable";
        default: return "Internal Server Error";
    }
}

void ctrl_json_escape(const char *input, char *output, size_t output_len) {
    if (!output || output_len == 0) return;
    if (!input) input = "error";
    size_t out = 0;
    for (size_t in = 0; input[in] && out + 2 < output_len; ++in) {
        unsigned char c = (unsigned char)input[in];
        switch (c) {
            case '"': output[out++] = '\\'; output[out++] = '"'; break;
            case '\\': output[out++] = '\\'; output[out++] = '\\'; break;
            case '\n': output[out++] = '\\'; output[out++] = 'n'; break;
            case '\r': output[out++] = '\\'; output[out++] = 'r'; break;
            case '\t': output[out++] = '\\'; output[out++] = 't'; break;
            default: output[out++] = c >= 0x20 ? (char)c : ' '; break;
        }
    }
    output[out] = '\0';
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
    char escaped[1024];
    char body[1100];
    ctrl_json_escape(error, escaped, sizeof(escaped));
    int blen = snprintf(body, sizeof(body), "{\"error\":\"%s\"}", escaped);
    if (blen < 0 || (size_t)blen >= sizeof(body)) return;
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

static int json_hex4(const char **cursor, uint32_t *value) {
    uint32_t result = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char c = (unsigned char)(*cursor)[i];
        unsigned int digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return 0;
        result = (result << 4) | digit;
    }
    *cursor += 4;
    *value = result;
    return 1;
}

static int json_append_codepoint(char *out, size_t out_len, size_t *pos, uint32_t cp) {
    unsigned char encoded[4];
    size_t count;
    if (cp == 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
    if (cp <= 0x7f) {
        encoded[0] = (unsigned char)cp;
        count = 1;
    } else if (cp <= 0x7ff) {
        encoded[0] = (unsigned char)(0xc0 | (cp >> 6));
        encoded[1] = (unsigned char)(0x80 | (cp & 0x3f));
        count = 2;
    } else if (cp <= 0xffff) {
        encoded[0] = (unsigned char)(0xe0 | (cp >> 12));
        encoded[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
        encoded[2] = (unsigned char)(0x80 | (cp & 0x3f));
        count = 3;
    } else {
        encoded[0] = (unsigned char)(0xf0 | (cp >> 18));
        encoded[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3f));
        encoded[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
        encoded[3] = (unsigned char)(0x80 | (cp & 0x3f));
        count = 4;
    }
    if (*pos + count >= out_len) return 0;
    memcpy(out + *pos, encoded, count);
    *pos += count;
    return 1;
}

int ctrl_json_string(const char *body, const char *key, char *out, size_t out_len) {
    if (!body || !key || !out || out_len == 0) return 0;
    out[0] = '\0';
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(body, search);
    if (!p) return 0;
    p += strlen(search);
    while (isspace((unsigned char)*p)) p++;
    if (*p != ':') return 0;
    p++;
    while (isspace((unsigned char)*p)) p++;
    if (*p != '"') return 0;
    p++;
    size_t pos = 0;
    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p++;
        if (c < 0x20) {
            out[0] = '\0';
            return 0;
        }
        if (c == '\\') {
            uint32_t cp;
            switch (*p++) {
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case '/': c = '/'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'u':
                    if (!json_hex4(&p, &cp)) { out[0] = '\0'; return 0; }
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        uint32_t low;
                        if (p[0] != '\\' || p[1] != 'u') { out[0] = '\0'; return 0; }
                        p += 2;
                        if (!json_hex4(&p, &low) || low < 0xdc00 || low > 0xdfff) {
                            out[0] = '\0';
                            return 0;
                        }
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                    }
                    if (!json_append_codepoint(out, out_len, &pos, cp)) { out[0] = '\0'; return 0; }
                    continue;
                default:
                    out[0] = '\0';
                    return 0;
            }
        }
        if (pos + 1 >= out_len) { out[0] = '\0'; return 0; }
        out[pos++] = (char)c;
    }
    if (*p != '"') { out[0] = '\0'; return 0; }
    out[pos] = '\0';
    return 1;
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

int ctrl_candidate_session_identity(const char *auth_header, char *out_candidate_id,
                                    size_t out_len) {
    char token[128] = {0};
    if (!out_candidate_id || out_len == 0 ||
        !ctrl_extract_bearer(auth_header, token, sizeof(token))) {
        return 0;
    }
    return candidate_session_identity(token, out_candidate_id, out_len);
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
    if (strcmp(origin, "null") == 0) return 1; /* Allow local kiosk file:/// session */

    /* Normalize origin: remove trailing slash if present */
    char clean_origin[512];
    size_t olen = strlen(origin);
    if (olen >= sizeof(clean_origin)) olen = sizeof(clean_origin) - 1;
    memcpy(clean_origin, origin, olen);
    clean_origin[olen] = '\0';
    while (olen > 0 && clean_origin[olen - 1] == '/') {
        clean_origin[--olen] = '\0';
    }

    /* Standard allowed origins */
    if (strcmp(clean_origin, "https://sppio-os.vercel.app") == 0 ||
        strcmp(clean_origin, "http://localhost:5173") == 0 ||
        strcmp(clean_origin, "http://127.0.0.1:5173") == 0 ||
        strcmp(clean_origin, "http://localhost:3000") == 0 ||
        strcmp(clean_origin, "http://127.0.0.1:3000") == 0 ||
        strcmp(clean_origin, "http://localhost:8895") == 0 ||
        strcmp(clean_origin, "http://127.0.0.1:8895") == 0) {
        return 1;
    }

    /* Allow any *.vercel.app deployment domain */
    if (olen > 11 && strcmp(clean_origin + olen - 11, ".vercel.app") == 0) {
        return 1;
    }

    /* Check EXAMOS_CORS_ALLOWED_ORIGINS environment variable */
    const char *env = getenv("EXAMOS_CORS_ALLOWED_ORIGINS");
    if (env && env[0]) {
        if (strcmp(env, "*") == 0) return 1;
        char buf[1024];
        size_t n = strlen(env);
        if (n >= sizeof(buf)) n = sizeof(buf) - 1;
        memcpy(buf, env, n); buf[n] = '\0';
        char *save = NULL;
        char *tok = strtok_r(buf, ",", &save);
        while (tok) {
            while (*tok == ' ' || *tok == '\t' || *tok == '\r' || *tok == '\n') tok++;
            size_t tlen = strlen(tok);
            while (tlen > 0 && (tok[tlen - 1] == ' ' || tok[tlen - 1] == '\t' ||
                                tok[tlen - 1] == '\r' || tok[tlen - 1] == '\n' ||
                                tok[tlen - 1] == '/')) {
                tok[--tlen] = '\0';
            }
            if (tlen > 0) {
                if (strcmp(tok, "*") == 0 || strcmp(tok, clean_origin) == 0) return 1;
            }
            tok = strtok_r(NULL, ",", &save);
        }
    }
    return 0;
}
