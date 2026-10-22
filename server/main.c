#define _GNU_SOURCE
#include "include/ledger.h"
#include "include/risk_engine.h"
#include "include/exam_manager.h"
#include "include/config_manager.h"
#include "include/candidate_login.h"
#include "include/admin_dashboard.h"
#include "include/attestation_service.h"
#include "include/attestation_config.h"
#include "include/event_chain.h"
#include "include/second_camera.h"
#include "include/enterprise_platform.h"
#include "include/admin_auth_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <spawn.h>
#include <openssl/crypto.h>

extern char **environ;

#define BUFFER_SIZE 65536
#define MAX_HTTP_CLIENTS 512

static volatile sig_atomic_t g_server_running = 1;
static sem_t g_client_slots;
static unsigned int g_max_clients = 128;

static void sig_handler(int sig) {
    (void)sig;
    g_server_running = 0;
}

static int parse_http_content_length(const char *buffer, const char *headers_end,
                                    size_t capacity, size_t *out_expected) {
    if (!buffer || !headers_end || !out_expected || headers_end < buffer) return -1;
    const char *line = strstr(buffer, "\r\n");
    if (!line || line > headers_end) return -1;
    line += 2;
    size_t header_bytes = (size_t)(headers_end + 4 - buffer);
    size_t content_length = 0;
    int content_length_seen = 0;
    while (line < headers_end) {
        const char *line_end = strstr(line, "\r\n");
        if (!line_end || line_end > headers_end || line_end == line) return -1;
        const char *colon = memchr(line, ':', (size_t)(line_end - line));
        if (!colon || colon == line) return -1;
        size_t name_length = (size_t)(colon - line);
        if (name_length == sizeof("Content-Length") - 1 &&
            strncasecmp(line, "Content-Length", name_length) == 0) {
            if (content_length_seen) return -1;
            content_length_seen = 1;
            const char *value = colon + 1;
            while (value < line_end && (*value == ' ' || *value == '\t')) value++;
            if (value == line_end) return -1;
            size_t parsed = 0;
            for (; value < line_end; value++) {
                if (*value < '0' || *value > '9') return -1;
                unsigned int digit = (unsigned int)(*value - '0');
                if (parsed > (SIZE_MAX - digit) / 10) return -1;
                parsed = parsed * 10 + digit;
            }
            if (parsed > capacity - header_bytes - 1) return -1;
            content_length = parsed;
        } else if (name_length == sizeof("Transfer-Encoding") - 1 &&
                   strncasecmp(line, "Transfer-Encoding", name_length) == 0) {
            return -1;
        }
        line = line_end + 2;
    }
    *out_expected = header_bytes + content_length;
    return 0;
}

static int extract_authorization_header(const char *buffer, char *out, size_t out_size) {
    if (!buffer || !out || out_size == 0) return -1;
    out[0] = '\0';
    const char *headers_end = strstr(buffer, "\r\n\r\n");
    const char *line = strstr(buffer, "\r\n");
    if (!headers_end || !line || line > headers_end) return -1;
    line += 2;
    int found = 0;
    while (line < headers_end) {
        const char *line_end = strstr(line, "\r\n");
        if (!line_end || line_end > headers_end) return -1;
        const char *colon = memchr(line, ':', (size_t)(line_end - line));
        if (!colon || colon == line) return -1;
        size_t name_length = (size_t)(colon - line);
        if (name_length == sizeof("Authorization") - 1 &&
            strncasecmp(line, "Authorization", name_length) == 0) {
            if (found) return -1;
            found = 1;
            const char *value = colon + 1;
            while (value < line_end && (*value == ' ' || *value == '\t')) value++;
            const char *value_end = line_end;
            while (value_end > value && (value_end[-1] == ' ' || value_end[-1] == '\t')) value_end--;
            size_t value_length = (size_t)(value_end - value);
            if (value_length == 0 || value_length >= out_size) return -1;
            for (size_t i = 0; i < value_length; i++) {
                unsigned char c = (unsigned char)value[i];
                if (c < 0x20 || c == 0x7f) return -1;
            }
            memcpy(out, value, value_length);
            out[value_length] = '\0';
        }
        line = line_end + 2;
    }
    return 0;
}

static const char *status_text(int status_code) {
    switch (status_code) {
        case 200: return "OK";
        case 202: return "Accepted";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 503: return "Service Unavailable";
        default: return "Internal Server Error";
    }
}

static int send_all(int client_fd, const char *data, size_t length) {
    size_t sent_total = 0;
    while (sent_total < length) {
        ssize_t sent = send(client_fd, data + sent_total, length - sent_total, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return -1;
        sent_total += (size_t)sent;
    }
    return 0;
}

static ssize_t receive_http_request(int fd, char *buffer, size_t capacity) {
    size_t used = 0, expected = 0;
    int headers_complete = 0;
    while (used + 1 < capacity) {
        ssize_t n = recv(fd, buffer + used, capacity - used - 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
        buffer[used] = '\0';
        char *body = strstr(buffer, "\r\n\r\n");
        if (body && !headers_complete) {
            headers_complete = 1;
            if (parse_http_content_length(buffer, body, capacity, &expected) != 0)
                return -2;
        }
        if (headers_complete && used >= expected)
            return used == expected ? (ssize_t)used : -2;
    }
    return headers_complete && used >= expected ? (ssize_t)used : -1;
}

static void send_http_response_ex(int client_fd, int status_code, const char *content_type, const char *body, const char *extra_headers) {
    char header[1024];
    size_t body_len = body ? strlen(body) : 0;
    int header_length = snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Cache-Control: no-store\r\n"
             "X-Content-Type-Options: nosniff\r\n"
             "X-Frame-Options: DENY\r\n"
             "X-XSS-Protection: 1; mode=block\r\n"
             "Connection: close\r\n"
             "%s"
             "\r\n",
             status_code, status_text(status_code), content_type, body_len,
             extra_headers ? extra_headers : "");

    if (header_length < 0 || (size_t)header_length >= sizeof(header)) return;
    if (send_all(client_fd, header, (size_t)header_length) == 0 && body_len > 0) {
        send_all(client_fd, body, body_len);
    }
}

static void send_http_response(int client_fd, int status_code, const char *content_type, const char *body) {
    send_http_response_ex(client_fd, status_code, content_type, body, NULL);
}

static int json_hex4(const char **cursor, uint32_t *value) {
    uint32_t parsed = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned char c = (unsigned char)*(*cursor)++;
        parsed <<= 4;
        if (c >= '0' && c <= '9') parsed |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') parsed |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') parsed |= (uint32_t)(c - 'A' + 10);
        else return -1;
    }
    *value = parsed;
    return 0;
}

static int json_append_codepoint(char *out, size_t capacity, size_t *used, uint32_t cp) {
    unsigned char bytes[4];
    size_t length;
    if (cp == 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return -1;
    if (cp <= 0x7f) { bytes[0] = (unsigned char)cp; length = 1; }
    else if (cp <= 0x7ff) {
        bytes[0] = (unsigned char)(0xc0 | (cp >> 6));
        bytes[1] = (unsigned char)(0x80 | (cp & 0x3f)); length = 2;
    } else if (cp <= 0xffff) {
        bytes[0] = (unsigned char)(0xe0 | (cp >> 12));
        bytes[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
        bytes[2] = (unsigned char)(0x80 | (cp & 0x3f)); length = 3;
    } else {
        bytes[0] = (unsigned char)(0xf0 | (cp >> 18));
        bytes[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3f));
        bytes[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
        bytes[3] = (unsigned char)(0x80 | (cp & 0x3f)); length = 4;
    }
    if (*used + length >= capacity) return -1;
    memcpy(out + *used, bytes, length);
    *used += length;
    return 0;
}

static int json_decode_string(const char **cursor, char *out, size_t capacity) {
    const char *p = *cursor;
    if (*p++ != '"') return -1;
    size_t used = 0;
    while (*p && *p != '"') {
        unsigned char value = (unsigned char)*p++;
        if (value == '\\') {
            value = (unsigned char)*p++;
            if (value == 'u') {
                uint32_t codepoint = 0;
                if (json_hex4(&p, &codepoint) != 0) return -1;
                if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
                    uint32_t low = 0;
                    if (p[0] != '\\' || p[1] != 'u') return -1;
                    p += 2;
                    if (json_hex4(&p, &low) != 0 || low < 0xdc00 || low > 0xdfff) return -1;
                    codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00);
                }
                if (json_append_codepoint(out, capacity, &used, codepoint) != 0) return -1;
                continue;
            }
            switch (value) {
                case '"': case '\\': case '/': break;
                case 'b': value = '\b'; break;
                case 'f': value = '\f'; break;
                case 'n': value = '\n'; break;
                case 'r': value = '\r'; break;
                case 't': value = '\t'; break;
                default: return -1;
            }
        } else if (value < 0x20) return -1;
        if (used + 1 >= capacity) return -1;
        out[used++] = (char)value;
    }
    if (*p != '"') return -1;
    out[used] = '\0';
    *cursor = p + 1;
    return 0;
}

static void parse_json_string(const char *buf, const char *key, char *out, size_t max_out) {
    if (!out || max_out == 0) return;
    out[0] = '\0';
    if (!buf || !key) return;
    const char *p = buf;
    int object_depth = 0, array_depth = 0, found = 0;
    while (*p) {
        if (*p == '{') { object_depth++; p++; continue; }
        if (*p == '}') { object_depth--; p++; continue; }
        if (*p == '[') { array_depth++; p++; continue; }
        if (*p == ']') { array_depth--; p++; continue; }
        if (*p != '"') { p++; continue; }
        char token[256];
        if (json_decode_string(&p, token, sizeof(token)) != 0) return;
        const char *value = p;
        while (*value == ' ' || *value == '\t' || *value == '\r' || *value == '\n') value++;
        if (object_depth == 1 && array_depth == 0 && *value == ':' && strcmp(token, key) == 0) {
            if (found) { out[0] = '\0'; return; }
            found = 1;
            value++;
            while (*value == ' ' || *value == '\t' || *value == '\r' || *value == '\n') value++;
            if (*value != '"' || json_decode_string(&value, out, max_out) != 0) out[0] = '\0';
            return;
        }
    }
}

static int json_escape(const char *input, char *output, size_t capacity) {
    if (!input || !output || capacity == 0) return -1;
    size_t used = 0;
    static const char hex[] = "0123456789abcdef";
    for (const unsigned char *p = (const unsigned char *)input; *p; ++p) {
        char escaped[6];
        const char *value = escaped;
        size_t length = 0;
        switch (*p) {
            case '"': escaped[0] = '\\'; escaped[1] = '"'; length = 2; break;
            case '\\': escaped[0] = '\\'; escaped[1] = '\\'; length = 2; break;
            case '\b': escaped[0] = '\\'; escaped[1] = 'b'; length = 2; break;
            case '\f': escaped[0] = '\\'; escaped[1] = 'f'; length = 2; break;
            case '\n': escaped[0] = '\\'; escaped[1] = 'n'; length = 2; break;
            case '\r': escaped[0] = '\\'; escaped[1] = 'r'; length = 2; break;
            case '\t': escaped[0] = '\\'; escaped[1] = 't'; length = 2; break;
            default:
                if (*p < 0x20) {
                    escaped[0] = '\\'; escaped[1] = 'u'; escaped[2] = '0'; escaped[3] = '0';
                    escaped[4] = hex[*p >> 4]; escaped[5] = hex[*p & 15]; length = 6;
                } else { value = (const char *)p; length = 1; }
        }
        if (used + length >= capacity) return -1;
        memcpy(output + used, value, length);
        used += length;
    }
    output[used] = '\0';
    return 0;
}

static const char *bearer_token(const char *authorization) {
    static const char prefix[] = "Bearer ";
    if (!authorization || strncasecmp(authorization, prefix, sizeof(prefix) - 1) != 0)
        return NULL;
    const char *token = authorization + sizeof(prefix) - 1;
    return *token ? token : NULL;
}

static int candidate_authorized(const char *authorization, char *candidate_id, size_t max_len) {
    const char *token = bearer_token(authorization);
    return token && candidate_session_identity(token, candidate_id, max_len);
}

static int bearer_secret_authorized(const char *authorization, const char *environment_name) {
    const char *provided = bearer_token(authorization);
    const char *expected = getenv(environment_name);
    if (!provided || !expected || strlen(expected) < 32) return 0;
    size_t p_len = strlen(provided), e_len = strlen(expected);
    return p_len == e_len && CRYPTO_memcmp(provided, expected, e_len) == 0;
}

static int parse_json_int(const char *buf, const char *key, int default_val) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(buf, pattern);
    if (!pos) return default_val;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == ':' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    errno = 0;
    char *end = NULL;
    long value = strtol(pos, &end, 10);
    if (errno != 0 || end == pos || value < INT_MIN || value > INT_MAX) return default_val;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') end++;
    if (*end != ',' && *end != '}' && *end != '\0') return default_val;
    return (int)value;
}

static int parse_query_id(const char *path, const char *name, char *out, size_t out_size) {
    if (!path || !name || !out || out_size == 0) return -1;
    out[0] = '\0';
    const char *query = strchr(path, '?');
    if (!query) return -1;
    size_t name_len = strlen(name);
    const char *item = query + 1;
    while (*item) {
        const char *end = strchr(item, '&');
        size_t item_len = end ? (size_t)(end - item) : strlen(item);
        if (item_len > name_len && memcmp(item, name, name_len) == 0 && item[name_len] == '=') {
            size_t value_len = item_len - name_len - 1;
            if (value_len == 0 || value_len >= out_size) return -1;
            for (size_t i = 0; i < value_len; i++) {
                unsigned char c = (unsigned char)item[name_len + 1 + i];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                      c == '.' || c == ':')) return -1;
                out[i] = (char)c;
            }
            out[value_len] = '\0';
            return 0;
        }
        if (!end) break;
        item = end + 1;
    }
    return -1;
}

static void* handle_client(void *arg) {
    int client_fd = (int)(intptr_t)arg;
    char buffer[BUFFER_SIZE] = {0};

    struct timeval timeout = {5, 0};
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    ssize_t bytes_read = receive_http_request(client_fd, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        if (bytes_read == -2)
            send_http_response(client_fd, 400, "application/json", "{\"error\":\"Request too large or invalid Content-Length\"}");
        goto client_done;
    }

    char method[16] = {0}, path[256] = {0};
    if (sscanf(buffer, "%15s %255s", method, path) != 2) {
        send_http_response(client_fd, 400, "application/json", "{\"error\":\"Malformed HTTP request\"}");
        goto client_done;
    }

    // Extract Authorization only from the parsed header block, never from the body.
    char auth_header[512] = {0};
    if (extract_authorization_header(buffer, auth_header, sizeof(auth_header)) != 0) {
        send_http_response(client_fd, 400, "application/json", "{\"error\":\"Invalid or duplicate Authorization header\"}");
        goto client_done;
    }

    // Extract body if POST
    const char *body_pos = strstr(buffer, "\r\n\r\n");
    const char *req_body = body_pos ? body_pos + 4 : "";

    /* Route: GET / -> Candidate Login UI */
    if (strcmp(path, "/") == 0 && strcmp(method, "GET") == 0) {
        send_http_response(client_fd, 200, "text/html; charset=utf-8", candidate_login_html());
    }
    /* Route: POST /api/v1/candidate/login */
    else if (strcmp(path, "/api/v1/candidate/login") == 0 && strcmp(method, "POST") == 0) {
        char cid[64] = {0}, pin[64] = {0};
        parse_json_string(req_body, "candidate_id", cid, sizeof(cid));
        parse_json_string(req_body, "pin", pin, sizeof(pin));

        if (strlen(cid) == 0 || strlen(pin) == 0) {
            send_http_response(client_fd, 400, "application/json", "{\"status\":\"FAIL\",\"error\":\"Candidate ID and PIN are required\"}");
        } else if (!candidate_credentials_validate(cid, pin)) {
            ledger_block_t blk;
            ledger_append_event("CANDIDATE_AUTH_FAILED", cid, "Invalid candidate credentials", &blk);
            send_http_response(client_fd, 401, "application/json", "{\"status\":\"FAIL\",\"error\":\"Invalid credentials\"}");
        } else {
            char token[SESSION_TOKEN_LEN + 1];
            if (candidate_session_create(cid, token) == 0) {
                exam_config_t cfg;
                config_load(&cfg);
                char resp[4096], safe_url[3072], safe_name[768];
                const char *exam_url = cfg.exam_url[0] ? cfg.exam_url : "NOT_CONFIGURED";
                const char *exam_name = cfg.exam_name[0] ? cfg.exam_name : "Not configured";
                if (json_escape(exam_url, safe_url, sizeof(safe_url)) != 0 ||
                    json_escape(exam_name, safe_name, sizeof(safe_name)) != 0) {
                    OPENSSL_cleanse(token, sizeof(token));
                    send_http_response(client_fd, 500, "application/json", "{\"status\":\"FAIL\",\"error\":\"Invalid configured exam text\"}");
                    goto client_done;
                }
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"SUCCESS\",\"token\":\"%s\",\"exam_url\":\"%s\",\"exam_name\":\"%s\"}",
                         token, safe_url, safe_name);
                OPENSSL_cleanse(token, sizeof(token));

                ledger_block_t blk;
                char details[128];
                snprintf(details, sizeof(details), "Candidate %s logged in", cid);
                ledger_append_event("CANDIDATE_AUTH_SUCCESS", cid, details, &blk);

                send_http_response(client_fd, 200, "application/json", resp);
            } else {
                send_http_response(client_fd, 500, "application/json", "{\"status\":\"FAIL\",\"error\":\"Internal session creation error\"}");
            }
        }
    }
    /* Route: POST /api/v1/admin/login -> PostgreSQL-backed admin session */
    else if (strcmp(path, "/api/v1/admin/login") == 0 && strcmp(method, "POST") == 0) {
        char username[64] = {0}, password[256] = {0}, mfa_code[16] = {0};
        parse_json_string(req_body, "username", username, sizeof(username));
        parse_json_string(req_body, "password", password, sizeof(password));
        parse_json_string(req_body, "mfa_code", mfa_code, sizeof(mfa_code));
        auth_session_t session;
        memset(&session, 0, sizeof(session));
        int login_status = admin_auth_store_login(username, password,
            mfa_code[0] ? mfa_code : NULL, &session);
        OPENSSL_cleanse(password, sizeof(password));
        OPENSSL_cleanse(mfa_code, sizeof(mfa_code));
        if (login_status == AUTH_LOGIN_SUCCESS) {
            char response[512];
            snprintf(response, sizeof(response),
                "{\"status\":\"AUTHENTICATED\",\"token\":\"%s\",\"mfa_required\":false}",
                session.session_token);
            send_http_response(client_fd, 200, "application/json", response);
        } else if (login_status == AUTH_LOGIN_MFA_REQUIRED) {
            send_http_response(client_fd, 401, "application/json",
                "{\"status\":\"MFA_REQUIRED\",\"error\":\"MFA code required\"}");
        } else {
            send_http_response(client_fd, 401, "application/json",
                "{\"status\":\"FAIL\",\"error\":\"Invalid credentials or MFA code\"}");
        }
        OPENSSL_cleanse(&session, sizeof(session));
    }
    else if (strcmp(path, "/api/v1/admin/logout") == 0 && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        if (strncmp(auth_header, prefix, sizeof(prefix) - 1) != 0 ||
            admin_auth_store_revoke(auth_header + sizeof(prefix) - 1) != 0) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized\"}");
        } else {
            send_http_response(client_fd, 200, "application/json", "{\"status\":\"SIGNED_OUT\"}");
        }
    }
    /* Route: GET /admin -> Admin Dashboard (requires auth) */
    else if (strcmp(path, "/admin") == 0 && strcmp(method, "GET") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 200, "text/html; charset=utf-8", admin_login_html());
        } else {
            exam_config_t cfg;
            config_load(&cfg);
            const char *dash = admin_dashboard_html(cfg.exam_url, cfg.exam_name, cfg.exam_duration_minutes);
            send_http_response(client_fd, 200, "text/html; charset=utf-8", dash);
        }
    }
    /* Route: POST /api/v1/admin/config -> Update Exam URL / Config */
    else if (strcmp(path, "/api/v1/admin/config") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_EXAM_MUTATION)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized: Admin credentials required\"}");
        } else {
            exam_config_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            parse_json_string(req_body, "exam_url", cfg.exam_url, sizeof(cfg.exam_url));
            parse_json_string(req_body, "exam_name", cfg.exam_name, sizeof(cfg.exam_name));
            cfg.exam_duration_minutes = parse_json_int(req_body, "exam_duration_minutes", 0);

            if (!config_validate_exam_url(cfg.exam_url)) {
                send_http_response(client_fd, 400, "application/json", "{\"error\":\"Exam URL must be HTTPS and its host must be in EXAMOS_ALLOWED_EXAM_HOSTS; loopback HTTP requires explicit development opt-in\"}");
            } else if (!cfg.exam_name[0] || cfg.exam_duration_minutes < 1) {
                send_http_response(client_fd, 400, "application/json", "{\"error\":\"exam_name and a positive exam_duration_minutes are required\"}");
            } else if (config_save(&cfg) == 0) {
                ledger_block_t blk;
                char details[512];
                snprintf(details, sizeof(details), "Exam URL updated to: %s", cfg.exam_url);
                ledger_append_event("ADMIN_CONFIG_UPDATED", "ADMIN_CONSOLE", details, &blk);
                send_http_response(client_fd, 200, "application/json", "{\"status\":\"SAVED\",\"exam_url\":\"saved\"}");
            } else {
                send_http_response(client_fd, 500, "application/json", "{\"error\":\"Failed to save configuration to disk\"}");
            }
        }
    }
    /* Route: POST /api/v1/attestation/nonce -> Issue challenge */
    else if (strcmp(path, "/api/v1/attestation/nonce") == 0 && strcmp(method, "POST") == 0) {
        if (!bearer_secret_authorized(auth_header, "EXAMOS_AGENT_API_TOKEN")) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid agent token required\"}");
            goto client_done;
        }
        char dev_id[64] = {0}, sess_id[64] = {0}, rel_id[64] = {0};
        parse_json_string(req_body, "device_id", dev_id, sizeof(dev_id));
        parse_json_string(req_body, "session_id", sess_id, sizeof(sess_id));
        parse_json_string(req_body, "release_id", rel_id, sizeof(rel_id));

        if (!dev_id[0] || !sess_id[0] || !rel_id[0]) {
            send_http_response(client_fd, 400, "application/json",
                               "{\"error\":\"device_id, session_id, and release_id required\"}");
        } else {
            char nonce[128] = {0}, attest_id[64] = {0}, error_code[64] = {0};
            int rc = attestation_create_challenge(
                dev_id, sess_id, rel_id,
                nonce, attest_id, error_code);
            if (rc == 0) {
                char resp[512];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"CHALLENGE_ISSUED\",\"nonce\":\"%s\","
                         "\"session_id\":\"%s\",\"attestation_id\":\"%s\"}",
                         nonce, sess_id, attest_id);
                send_http_response(client_fd, 200, "application/json", resp);
            } else {
                char resp[256];
                const char *ec = error_code[0] ? error_code : "P3_UNKNOWN_DEVICE";
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"REJECTED\",\"error_code\":\"%s\","
                         "\"error\":\"Challenge refused\"}",
                         ec);
                send_http_response(client_fd, 403, "application/json", resp);
            }
        }
    }
    /* Route: POST /api/v1/attestation/verify -> Verify TPM Evidence */
    else if (strcmp(path, "/api/v1/attestation/verify") == 0 && strcmp(method, "POST") == 0) {
        if (!bearer_secret_authorized(auth_header, "EXAMOS_AGENT_API_TOKEN")) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid agent token required\"}");
            goto client_done;
        }
        char reason[64] = {0}, exam_key[65] = {0};
        if (attestation_verify_evidence(req_body, reason, exam_key) == 0) {
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"TRUSTED\",\"verified\":true,\"reason\":\"%s\","
                     "\"exam_key\":\"%s\"}",
                     reason, exam_key);
            send_http_response(client_fd, 200, "application/json", resp);
        } else {
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"FAILED\",\"verified\":false,"
                     "\"error_code\":\"%s\",\"reason\":\"%s\"}",
                     reason, reason);
            send_http_response(client_fd, 403, "application/json", resp);
        }
    }
    /* Route: POST /api/v1/attestation/re-attest -> Periodic re-attestation challenge
     * BUG-FIX: was trying to re-verify old evidence.
     * Now issues a NEW fresh nonce so the client can produce a fresh quote.
     * Test flow: POST re-attest -> get new_nonce -> POST verify -> TRUSTED again.
     */
    else if (strcmp(path, "/api/v1/attestation/re-attest") == 0 && strcmp(method, "POST") == 0) {
        if (!bearer_secret_authorized(auth_header, "EXAMOS_AGENT_API_TOKEN")) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid agent token required\"}");
            goto client_done;
        }
        char sess_id[64] = {0}, dev_id[64] = {0}, new_nonce[128] = {0};
        parse_json_string(req_body, "session_id",    sess_id, sizeof(sess_id));
        parse_json_string(req_body, "device_id",     dev_id,  sizeof(dev_id));
        /* Also accept attestation_id as an alias for session_id */
        if (!sess_id[0])
            parse_json_string(req_body, "attestation_id", sess_id, sizeof(sess_id));

        if (attestation_re_attest_challenge(sess_id, dev_id, new_nonce) == 0) {
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"RE_ATTESTATION_CHALLENGE\",\"nonce\":\"%s\","
                     "\"session_id\":\"%s\"}",
                     new_nonce, sess_id);
            send_http_response(client_fd, 200, "application/json", resp);
        } else {
            send_http_response(client_fd, 403, "application/json",
                               "{\"status\":\"FAILED\","
                               "\"error\":\"Session not found or not in trusted state\"}");
        }
    }
    /* Route: GET /api/v1/attestation/status */
    else if (strncmp(path, "/api/v1/attestation/status", 26) == 0 &&
             (path[26] == '\0' || path[26] == '?') && strcmp(method, "GET") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Admin credentials required\"}");
        } else {
            char attestation_id[64] = {0}, status[32] = {0};
            if (parse_query_id(path, "attestation_id", attestation_id,
                               sizeof(attestation_id)) != 0 &&
                parse_query_id(path, "session_id", attestation_id,
                               sizeof(attestation_id)) != 0) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"attestation_id or session_id query parameter required\"}");
            } else if (attestation_get_status(attestation_id, status,
                                               sizeof(status)) != 0) {
                send_http_response(client_fd, 404, "application/json",
                                   "{\"status\":\"NOT_FOUND\"}");
            } else {
                char response[128];
                snprintf(response, sizeof(response), "{\"status\":\"%s\"}", status);
                send_http_response(client_fd, 200, "application/json", response);
            }
        }
    }
    /* Route: POST /api/v1/admin/revoke/release */
    else if (strcmp(path, "/api/v1/admin/revoke/release") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized: Admin credentials required\"}");
        } else {
            char release_id[64] = {0};
            parse_json_string(req_body, "release_id", release_id, sizeof(release_id));
            if (attestation_revoke_release(release_id) == 0)
                send_http_response(client_fd, 200, "application/json", "{\"status\":\"REVOKED\"}");
            else
                send_http_response(client_fd, 503, "application/json", "{\"status\":\"UNAVAILABLE\",\"error\":\"Release revocation could not be persisted\"}");
        }
    }
    /* Route: POST /api/v1/admin/revoke/device */
    else if (strcmp(path, "/api/v1/admin/revoke/device") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized: Admin credentials required\"}");
        } else {
            char device_id[64] = {0};
            parse_json_string(req_body, "device_id", device_id, sizeof(device_id));
            if (attestation_revoke_device(device_id) == 0)
                send_http_response(client_fd, 200, "application/json", "{\"status\":\"REVOKED\"}");
            else
                send_http_response(client_fd, 503, "application/json", "{\"status\":\"UNAVAILABLE\",\"error\":\"Device revocation could not be persisted\"}");
        }
    }
    /* Route: POST /api/v1/admin/reload -> Restart Kiosk */
    else if (strcmp(path, "/api/v1/admin/reload") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized\"}");
        } else {
            char *const argv[] = {"systemctl", "restart", "examos-kiosk.service", NULL};
            pid_t child = -1;
            int spawn_status = posix_spawnp(&child, "systemctl", NULL, NULL, argv, environ);
            int child_status = 0;
            int waited = spawn_status == 0 ? waitpid(child, &child_status, 0) : -1;
            if (spawn_status == 0 && waited == child && WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0) {
                send_http_response(client_fd, 202, "application/json", "{\"status\":\"RESTARTED\"}");
            } else {
                send_http_response(client_fd, 503, "application/json", "{\"status\":\"UNAVAILABLE\",\"error\":\"Kiosk restart failed\"}");
            }
        }
    }
    /* Route: POST /api/v1/admin/lock -> Emergency lock */
    else if (strcmp(path, "/api/v1/admin/lock") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized\"}");
        } else {
            send_http_response(client_fd, 503, "application/json", "{\"status\":\"UNAVAILABLE\",\"error\":\"Appliance isolation is not integrated with the system service manager\"}");
        }
    }
    /* Route: GET /exam -> Redirect to Configured Exam URL or candidate portal */
    else if (strcmp(path, "/exam") == 0 && strcmp(method, "GET") == 0) {
        exam_config_t cfg;
        config_load(&cfg);
        if (cfg.configured && strlen(cfg.exam_url) > 0) {
            char redir_hdr[1024];
            snprintf(redir_hdr, sizeof(redir_hdr), "Location: %s\r\n", cfg.exam_url);
            send_http_response_ex(client_fd, 302, "text/plain", "Redirecting to configured exam server...", redir_hdr);
        } else {
            send_http_response(client_fd, 200, "text/html; charset=utf-8", candidate_login_html());
        }
    }
    /* Route: POST /api/v1/heartbeat -> Telemetry */
    else if (strcmp(path, "/api/v1/heartbeat") == 0 && strcmp(method, "POST") == 0) {
        if (!bearer_secret_authorized(auth_header, "EXAMOS_AGENT_API_TOKEN")) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid agent token required\"}");
            goto client_done;
        }
        const char *dev_mode = getenv("EXAMOS_ALLOW_UNPROVISIONED_DEV");
        if (dev_mode && strcmp(dev_mode, "1") == 0) {
            ledger_block_t blk;
            if (ledger_append_event("HEARTBEAT_TELEMETRY", "SECURITY_AGENT", "Untrusted development telemetry received", &blk) != 0) {
                send_http_response(client_fd, 503, "application/json", "{\"status\":\"UNAVAILABLE\"}");
            } else {
                char response[128];
                snprintf(response, sizeof(response), "{\"status\":\"RECEIVED_UNTRUSTED\",\"block_index\":%ld}", ledger_get_block_count());
                send_http_response(client_fd, 202, "application/json", response);
            }
        } else {
            char device_id[64] = {0};
            parse_json_string(req_body, "device_id", device_id, sizeof(device_id));
            const char *body_start = strstr(buffer, "\r\n\r\n");
            size_t payload_length = body_start ? (size_t)(bytes_read - (body_start + 4 - buffer)) : 0;
            long record_id = 0;
            int recorded = device_id[0] ? platform_record_agent_heartbeat(
                device_id, req_body, payload_length, &record_id) : -1;
            if (recorded == 0) {
                char response[128];
                snprintf(response, sizeof(response), "{\"status\":\"STORED\",\"heartbeat_id\":%ld}", record_id);
                send_http_response(client_fd, 202, "application/json", response);
            } else if (recorded == -1) {
                send_http_response(client_fd, 403, "application/json", "{\"status\":\"REJECTED\",\"error\":\"Device is not enrolled or heartbeat is invalid\"}");
            } else {
                send_http_response(client_fd, 503, "application/json", "{\"status\":\"UNAVAILABLE\",\"error\":\"Heartbeat was not durably stored\"}");
            }
        }
    }
    /* Route: GET /api/v1/ledger -> Audit Log */
    else if (strcmp(path, "/api/v1/ledger") == 0 && strcmp(method, "GET") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Admin credentials required\"}");
            goto client_done;
        }
        int valid = ledger_verify_integrity();
        long count = ledger_get_block_count();
        char resp[256];
        snprintf(resp, sizeof(resp),
                 "{\"ledger_integrity\":%s,\"total_blocks\":%ld,\"status\":\"OK\"}",
                 valid ? "\"INTACT\"" : "\"TAMPERED\"", count);
        send_http_response(client_fd, 200, "application/json", resp);
    }
    /* Route: GET /api/v1/status */
    else if (strcmp(path, "/api/v1/status") == 0 && strcmp(method, "GET") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Admin credentials required\"}");
            goto client_done;
        }
        exam_config_t cfg;
        config_load(&cfg);
        char resp[4096];
        char safe_url[3072], safe_name[768];
        if (json_escape(cfg.exam_url[0] ? cfg.exam_url : "NOT_CONFIGURED", safe_url, sizeof(safe_url)) != 0 ||
            json_escape(cfg.exam_name[0] ? cfg.exam_name : "Not configured", safe_name, sizeof(safe_name)) != 0) {
            send_http_response(client_fd, 500, "application/json", "{\"error\":\"Invalid configured exam text\"}");
            goto client_done;
        }
        snprintf(resp, sizeof(resp),
                 "{\"exam_url_configured\":%s,\"exam_url\":\"%s\",\"exam_name\":\"%s\",\"attestation_status\":\"NOT_PRODUCTION_READY\"}",
                 cfg.configured ? "true" : "false", safe_url, safe_name);
        send_http_response(client_fd, 200, "application/json", resp);
    }
    /* Route: POST /api/v1/exam/key-release -> Release session decryption key */
    else if (strcmp(path, "/api/v1/exam/key-release") == 0 && strcmp(method, "POST") == 0) {
        char authenticated_candidate[64] = {0};
        if (!candidate_authorized(auth_header, authenticated_candidate, sizeof(authenticated_candidate))) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid candidate bearer token required\"}");
            goto client_done;
        }
        char sess_id[64] = {0}, dev_id[64] = {0}, exam_key[65] = {0};
        parse_json_string(req_body, "session_id", sess_id, sizeof(sess_id));
        parse_json_string(req_body, "device_id", dev_id, sizeof(dev_id));
        if (strlen(sess_id) == 0) {
            parse_json_string(req_body, "attestation_id", sess_id, sizeof(sess_id));
        }

        if (attestation_get_exam_key(sess_id, dev_id, exam_key, sizeof(exam_key)) == 0) {
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"KEY_RELEASED\",\"session_id\":\"%s\",\"session_key\":\"%s\"}",
                     sess_id, exam_key);
            send_http_response(client_fd, 200, "application/json", resp);
        } else {
            send_http_response(client_fd, 403, "application/json",
                               "{\"status\":\"REJECTED\",\"error_code\":\"P3_SESSION_INVALID\",\"reason\":\"Session untrusted or unverified\"}");
        }
    }
    /* Route: POST /api/v1/consent -> Record candidate consent before camera/mic access */
    else if (strcmp(path, "/api/v1/consent") == 0 && strcmp(method, "POST") == 0) {
        char sess_id[64] = {0}, cand_id[64] = {0};
        parse_json_string(req_body, "session_id", sess_id, sizeof(sess_id));
        parse_json_string(req_body, "candidate_id", cand_id, sizeof(cand_id));

        char authenticated_candidate[64] = {0};
        if (!candidate_authorized(auth_header, authenticated_candidate, sizeof(authenticated_candidate))) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid candidate bearer token required\"}");
        } else if (!sess_id[0] || !cand_id[0] || strcmp(cand_id, authenticated_candidate) != 0) {
            send_http_response(client_fd, 400, "application/json", "{\"error\":\"session_id and authenticated candidate identity are required\"}");
        } else {
            send_http_response(client_fd, 503, "application/json",
                               "{\"status\":\"NOT_CONFIGURED\",\"error\":\"Proctoring consent cannot be recorded because no qualified proctoring service is configured\"}");
        }
    }
    /* Route: POST /api/v1/proctoring/events -> Ingest normalized detection into hash chain */
    else if (strcmp(path, "/api/v1/proctoring/events") == 0 && strcmp(method, "POST") == 0) {
        if (!bearer_secret_authorized(auth_header, "EXAMOS_PROCTOR_API_TOKEN")) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid proctor service token required\"}");
            goto client_done;
        }
        send_http_response(client_fd, 503, "application/json",
                           "{\"status\":\"NOT_CONFIGURED\",\"error\":\"No authenticated inference producer is configured; client submitted events are not accepted as proctoring evidence\"}");
    }
    /* Route: GET /api/v1/proctoring/events */
    else if (strncmp(path, "/api/v1/proctoring/events", 25) == 0 &&
             (path[25] == '\0' || path[25] == '?') && strcmp(method, "GET") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Admin credentials required\"}");
        } else {
            char export_buf[65536];
            char sess_id[64] = {0};
            if (parse_query_id(path, "session_id", sess_id, sizeof(sess_id)) != 0) {
                send_http_response(client_fd, 400, "application/json", "{\"error\":\"valid session_id query parameter required\"}");
            } else if (event_chain_export_json(sess_id, export_buf, sizeof(export_buf)) != 0) {
                send_http_response(client_fd, 500, "application/json", "{\"error\":\"event export failed\"}");
            } else {
                send_http_response(client_fd, 200, "application/json", export_buf);
            }
        }
    }
    /* Route: POST /api/v1/proctoring/checkpoint -> Sign checkpoint */
    else if (strcmp(path, "/api/v1/proctoring/checkpoint") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Admin credentials required\"}");
            goto client_done;
        }
        char sess_id[64] = {0};
        parse_json_string(req_body, "session_id", sess_id, sizeof(sess_id));
        event_checkpoint_t cp;
        if (!sess_id[0]) {
            send_http_response(client_fd, 400, "application/json", "{\"error\":\"session_id required\"}");
        } else if (event_chain_sign_checkpoint(sess_id, &cp) == 0) {
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"CHECKPOINT_SIGNED\",\"sequence\":%lu,\"latest_hash\":\"%s\",\"key_id\":\"%s\",\"signature\":\"%s\"}",
                     (unsigned long)cp.checkpoint_sequence, cp.latest_event_hash,
                     cp.signing_key_id, cp.signature_hex);
            send_http_response(client_fd, 200, "application/json", resp);
        } else {
            send_http_response(client_fd, 400, "application/json", "{\"error\":\"No events found to checkpoint\"}");
        }
    }
    /* Route: POST /api/v1/proctoring/verify -> Verify hash chain */
    else if (strcmp(path, "/api/v1/proctoring/verify") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_check_permission(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Admin credentials required\"}");
            goto client_done;
        }
        char sess_id[64] = {0};
        parse_json_string(req_body, "session_id", sess_id, sizeof(sess_id));
        uint64_t total = 0, corrupt_seq = 0;
        char reason[128] = {0};
        if (!sess_id[0]) {
            send_http_response(client_fd, 400, "application/json", "{\"error\":\"session_id required\"}");
        } else if (event_chain_verify_session(sess_id, &total, &corrupt_seq, reason, sizeof(reason)) == 0) {
            char resp[256];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"VERIFIED\",\"events_verified\":%lu,\"chain_integrity\":\"VALID\"}",
                     (unsigned long)total);
            send_http_response(client_fd, 200, "application/json", resp);
        } else {
            char resp[256];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"CORRUPTED\",\"events_verified\":%lu,\"corrupt_sequence\":%lu,\"reason\":\"%s\"}",
                     (unsigned long)total, (unsigned long)corrupt_seq, reason);
            send_http_response(client_fd, 400, "application/json", resp);
        }
    }
    /* Route: POST /api/v1/second-camera/request -> Generate QR token */
    else if (strcmp(path, "/api/v1/second-camera/request") == 0 && strcmp(method, "POST") == 0) {
        char authenticated_candidate[64] = {0};
        if (!candidate_authorized(auth_header, authenticated_candidate, sizeof(authenticated_candidate))) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid candidate bearer token required\"}");
            goto client_done;
        }
        send_http_response(client_fd, 503, "application/json",
                           "{\"status\":\"NOT_CONFIGURED\",\"error\":\"No candidate-bound session authority or authenticated media transport is configured\"}");
    }
    /* Route: POST /api/v1/second-camera/pair -> Validate QR pairing */
    else if (strcmp(path, "/api/v1/second-camera/pair") == 0 && strcmp(method, "POST") == 0) {
        send_http_response(client_fd, 503, "application/json",
                           "{\"status\":\"NOT_CONFIGURED\",\"error\":\"No authenticated media transport is configured; pairing is unavailable\"}");
    }
    /* Route: GET /second-camera -> Mobile phone camera capture web page */
    else if (strncmp(path, "/second-camera", 14) == 0 && strcmp(method, "GET") == 0) {
        char sess_id[64] = {0}, token[128] = {0};
        const char *q = strchr(path, '?');
        if (q) {
            const char *p_s = strstr(q, "session_id=");
            if (p_s) {
                p_s += 11;
                int i = 0;
                while (*p_s && *p_s != '&' && i < 63) sess_id[i++] = *p_s++;
                sess_id[i] = '\0';
            }
            const char *p_t = strstr(q, "token=");
            if (p_t) {
                p_t += 6;
                int i = 0;
                while (*p_t && *p_t != '&' && i < 127) token[i++] = *p_t++;
                token[i] = '\0';
            }
        }
        if (!sess_id[0] || !token[0]) {
            send_http_response(client_fd, 400, "application/json", "{\"error\":\"session_id and token are required\"}");
        } else {
            send_http_response(client_fd, 503, "application/json",
                               "{\"status\":\"NOT_CONFIGURED\",\"error\":\"No authenticated media transport is configured\"}");
        }
    }
    /* Route: GET /api/v1/health */
    else if (strcmp(path, "/api/v1/health") == 0 && strcmp(method, "GET") == 0) {
        send_http_response(client_fd, 200, "application/json",
                           "{\"status\":\"ok\",\"liveness\":\"LIVE\","
                           "\"readiness\":\"NOT_PRODUCTION_READY\","
                           "\"service\":\"examos-server\",\"phase\":\"P4\"}");
    }
    else {
        send_http_response(client_fd, 404, "application/json", "{\"error\":\"Not Found\"}");
    }

client_done:
    close(client_fd);
    sem_post(&g_client_slots);
    return NULL;
}

static int valid_startup_secret(const char *name, int required) {
    const char *value = getenv(name);
    if (!value || !value[0]) {
        if (required) fprintf(stderr, "[ExamOS-Server] FATAL: required secret %s is not configured.\n", name);
        return required ? 0 : 1;
    }
    size_t length = strlen(value);
    if (length < 32 || length > 128) {
        fprintf(stderr, "[ExamOS-Server] FATAL: secret %s must contain 32 through 128 characters.\n", name);
        return 0;
    }
    for (size_t i = 0; i < length; i++) {
        if (!(isalnum((unsigned char)value[i]) || value[i] == '_' || value[i] == '-')) {
            fprintf(stderr, "[ExamOS-Server] FATAL: secret %s has unsupported encoding.\n", name);
            return 0;
        }
    }
    return 1;
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    const char *tpm_mode = getenv("EXAMOS_TPM_MODE");
    if (!tpm_mode || (strcmp(tpm_mode, "development") != 0 && strcmp(tpm_mode, "production") != 0)) {
        fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_TPM_MODE must be explicitly development or production.\n");
        return 2;
    }
    const int production_mode = strcmp(tpm_mode, "production") == 0;
    const char *allow_unprovisioned = getenv("EXAMOS_ALLOW_UNPROVISIONED_DEV");
    if (production_mode && allow_unprovisioned) {
        fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_ALLOW_UNPROVISIONED_DEV is forbidden in production mode.\n");
        return 2;
    }
    if (!valid_startup_secret("EXAMOS_AGENT_API_TOKEN", 1) ||
        !valid_startup_secret("EXAMOS_PROCTOR_API_TOKEN", 1) ||
        !valid_startup_secret("EXAMOS_EVENT_SIGNING_KEY", 1) ||
        !valid_startup_secret("EXAMOS_VARIANT_SECRET", 1) ||
        !valid_startup_secret("EXAMOS_LEDGER_HMAC_KEY", production_mode)) {
        return 2;
    }

    int server_port = 0;
    const char *port_env = getenv("EXAMOS_SERVER_PORT");
    if (port_env && *port_env) {
        char *end = NULL;
        errno = 0;
        long parsed_port = strtol(port_env, &end, 10);
        if (errno != 0 || end == port_env || *end != '\0' || parsed_port < 1 || parsed_port > 65535) {
            fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_SERVER_PORT must be an integer from 1 through 65535.\n");
            return 2;
        }
        server_port = (int)parsed_port;
    } else {
        fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_SERVER_PORT must be provisioned.\n");
        return 2;
    }

    const char *max_clients_env = getenv("EXAMOS_MAX_CLIENTS");
    if (max_clients_env && *max_clients_env) {
        char *end = NULL;
        errno = 0;
        long parsed = strtol(max_clients_env, &end, 10);
        if (errno || end == max_clients_env || *end || parsed < 1 || parsed > MAX_HTTP_CLIENTS) {
            fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_MAX_CLIENTS must be between 1 and %d.\n", MAX_HTTP_CLIENTS);
            return 2;
        }
        g_max_clients = (unsigned int)parsed;
    }

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    printf("[ExamOS-Server] Initializing ExamOS Security Server on port %d (Phase 4 Proctoring & Tamper-Evident Evidence)...\n", server_port);

    const char *ledger_path = getenv("EXAMOS_LEDGER_PATH");
    if (ledger_init(ledger_path && *ledger_path ? ledger_path : "/tmp/examos_event_ledger.log") != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: evidence ledger is corrupt, truncated, or unreadable; refusing startup.\n");
        return 1;
    }
    exam_manager_init();
    candidate_session_init();
    if (attestation_service_init() != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: attestation service is not production-ready.\n");
        return 1;
    }
    char executable_path[PATH_MAX] = {0};
    ssize_t executable_len = readlink("/proc/self/exe", executable_path,
                                      sizeof(executable_path) - 1);
    if (executable_len > 0) {
        executable_path[executable_len] = '\0';
        char *last_separator = strrchr(executable_path, '/');
        if (last_separator && last_separator != executable_path)
            *last_separator = '\0';
        else if (last_separator)
            last_separator[1] = '\0';
        else
            executable_path[0] = '\0';
    }
    int development_mode = !production_mode && allow_unprovisioned && strcmp(allow_unprovisioned, "1") == 0;
    if (!development_mode && enterprise_platform_init("/var/lib/examos") != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: PostgreSQL TLS connection or required schema unavailable; refusing service startup.\n");
        return 1;
    }
    if (!development_mode && attestation_store_init() != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: durable PostgreSQL attestation state is unavailable; refusing service startup.\n");
        admin_auth_store_shutdown();
        return 1;
    }
    if (attestation_config_load_all(executable_path[0] ? executable_path : NULL) != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: authenticated attestation registries are unavailable or invalid.\n");
        if (!development_mode) admin_auth_store_shutdown();
        return 1;
    }
    event_chain_init("/var/log/examos/proctoring_events.log");
    second_camera_init();
    if (development_mode) {
        fprintf(stderr, "[ExamOS-Server] WARNING: local unprovisioned development mode enabled; production APIs remain unavailable.\n");
    }

    if (sem_init(&g_client_slots, 0, g_max_clients) != 0) {
        perror("[ExamOS-Server] Failed to initialize bounded client capacity");
        if (!development_mode) admin_auth_store_shutdown();
        return 1;
    }

    exam_config_t cfg;
    if (config_load(&cfg) == 0 && cfg.configured) {
        printf("[ExamOS-Server] Active Exam URL: %s (%s)\n", cfg.exam_url, cfg.exam_name);
    } else {
        printf("[ExamOS-Server] No external Exam URL configured; Candidate Portal active at http://127.0.0.1:%d/\n", server_port);
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Failed to create socket");
        sem_destroy(&g_client_slots);
        if (!development_mode) admin_auth_store_shutdown();
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)server_port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        sem_destroy(&g_client_slots);
        if (!development_mode) admin_auth_store_shutdown();
        return 1;
    }

    if (listen(server_fd, (int)g_max_clients) < 0) {
        perror("Listen failed");
        close(server_fd);
        sem_destroy(&g_client_slots);
        if (!development_mode) admin_auth_store_shutdown();
        return 1;
    }

    printf("[ExamOS-Server] Server listening on port %d (Candidate Portal: /, Admin Dashboard: /admin, Attestation API: /api/v1/attestation/verify)\n", server_port);

    while (g_server_running) {
        struct pollfd listener = {.fd = server_fd, .events = POLLIN};
        int ready = poll(&listener, 1, 1000);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("[ExamOS-Server] Listener poll failed");
            break;
        }
        if (ready == 0) continue;
        if (!(listener.revents & POLLIN)) {
            if (listener.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                fprintf(stderr, "[ExamOS-Server] Listener entered an invalid state.\n");
                break;
            }
            continue;
        }
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!g_server_running) break;
            continue;
        }

        struct timeval client_timeout = {5, 0};
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &client_timeout, sizeof(client_timeout));
        if (sem_trywait(&g_client_slots) != 0) {
            send_http_response(client_fd, 503, "application/json", "{\"error\":\"Server connection capacity reached\"}");
            close(client_fd);
            continue;
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, (void *)(intptr_t)client_fd) != 0) {
            close(client_fd);
            sem_post(&g_client_slots);
            continue;
        }
        pthread_detach(thread);
    }

    close(server_fd);
    for (unsigned int i = 0; i < g_max_clients; ++i) {
        while (sem_wait(&g_client_slots) != 0 && errno == EINTR) {}
    }
    sem_destroy(&g_client_slots);
    if (!development_mode) admin_auth_store_shutdown();
    printf("[ExamOS-Server] Clean shutdown complete.\n");
    return 0;
}
