#define _GNU_SOURCE
#include "include/ledger.h"
#include "include/risk_engine.h"
#include "include/exam_manager.h"
#include "include/config_manager.h"
#include "include/candidate_login.h"
#include "include/session_store.h"
#include "include/admin_dashboard.h"
#include "include/attestation_service.h"
#include "include/attestation_config.h"
#include "include/ek_certificate.h"
#include "include/event_chain.h"
#include "include/second_camera.h"
#include "include/firewall_service.h"
#include "include/enterprise_platform.h"
#include "include/admin_auth_store.h"
#include "include/policy_catalog.h"
#include "include/e1_consent.h"
#include "include/environment_engine.h"
#include "include/exam_engine.h"
#include "include/key_release.h"
#include "security/release_signature.h"
#include "include/behaviour_engine.h"
#include "include/variant_engine.h"
#include "include/viva_engine.h"
#include "../common/include/examos_appliance.h"
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
#include <sys/stat.h>
#include <spawn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

/* --- ExamOS Console integration controllers --- */
#include "controllers/controller.h"
#include "controllers/auth_controller.h"
#include "controllers/institution_controller.h"
#include "controllers/exam_controller.h"
#include "controllers/candidate_controller.h"
#include "controllers/device_controller.h"
#include "controllers/tpm_controller.h"
#include "controllers/session_controller.h"
#include "controllers/release_controller.h"
#include "controllers/policy_controller.h"
#include "controllers/modules_controller.h"
#include "controllers/registration_controller.h"
#include "controllers/exam_session_controller.h"
#include "controllers/device_trust_controller.h"
#include "controllers/os_release_controller.h"
#include "controllers/student_controller.h"
#include "controllers/campus_controller.h"
#include "controllers/reports_controller.h"
#include "db/db.h"
#include "security/security.h"
#include "audit/audit.h"

extern char **environ;

#define BUFFER_SIZE 131072
#define MAX_HTTP_CLIENTS 1024

/* CORS configuration for the ExamOS Console frontend.
 * Delegated to ctrl_cors_origin_allowed() in controller.c for uniform enforcement across all routes. */
static int cors_origin_allowed(const char *origin) {
    return ctrl_cors_origin_allowed(origin);
}

static int is_cors_preflight(const char *method, const char *buffer) {
    if (strcmp(method, "OPTIONS") != 0) return 0;
    return strstr(buffer, "Access-Control-Request-Method") != NULL;
}

static volatile sig_atomic_t g_server_running = 1;
static sem_t g_client_slots;
static unsigned int g_max_clients = 256;

/* --- Console integration globals --- */
static int g_db_initialized = 0;
static int g_audit_initialized = 0;


/* CORS origin for the current request (set in handle_client). */
static char g_cors_origin[512] = {0};
static int g_cors_allowed = 0;

static int g_tls_enabled = 0;
#if defined(USE_OPENSSL_TLS)
static SSL_CTX *g_tls_ctx = NULL;
/* Per-connection TLS handle. The listener is threaded, so this must never be
 * a process-global value shared between clients. */
static __thread SSL *g_conn_ssl = NULL;
#endif

typedef struct {
    int fd;
#if defined(USE_OPENSSL_TLS)
    SSL *ssl;
#endif
} client_connection_t;

/* Set exactly once during startup from EXAMOS_TPM_MODE, before the listener
 * begins accepting. Request handlers must never infer deployment mode from
 * ambient state; this is the single authoritative flag. */
static int g_production_mode = 0;

/* --- Dynamic Kiosk Real-Time Synchronization Globals --- */
static pthread_mutex_t g_kiosk_sync_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_kiosk_emergency_lock = 0;
static volatile long g_kiosk_command_seq = 1;
static char g_kiosk_latest_command[64] = "NONE";
static char g_kiosk_latest_payload[512] = "";

typedef struct {
    char terminal_id[64];
    char ip[64];
    char active_url[512];
    char status[32];
    int screen_focus;
    time_t last_heartbeat;
} kiosk_terminal_entry_t;

#define MAX_TRACKED_KIOSKS 64
static kiosk_terminal_entry_t g_tracked_kiosks[MAX_TRACKED_KIOSKS];
static int g_tracked_kiosk_count = 0;

static void kiosk_register_heartbeat(const char *terminal_id, const char *ip, const char *active_url, const char *status, int focus) {
    if (!terminal_id || !terminal_id[0]) return;
    pthread_mutex_lock(&g_kiosk_sync_lock);
    int found = -1;
    for (int i = 0; i < g_tracked_kiosk_count; i++) {
        if (strcmp(g_tracked_kiosks[i].terminal_id, terminal_id) == 0) {
            found = i;
            break;
        }
    }
    if (found < 0 && g_tracked_kiosk_count < MAX_TRACKED_KIOSKS) {
        found = g_tracked_kiosk_count++;
    }
    if (found >= 0) {
        snprintf(g_tracked_kiosks[found].terminal_id, sizeof(g_tracked_kiosks[found].terminal_id), "%s", terminal_id);
        snprintf(g_tracked_kiosks[found].ip, sizeof(g_tracked_kiosks[found].ip), "%s", ip && ip[0] ? ip : "127.0.0.1");
        snprintf(g_tracked_kiosks[found].active_url, sizeof(g_tracked_kiosks[found].active_url), "%s", active_url && active_url[0] ? active_url : "");
        snprintf(g_tracked_kiosks[found].status, sizeof(g_tracked_kiosks[found].status), "%s", status && status[0] ? status : "ONLINE");
        g_tracked_kiosks[found].screen_focus = focus;
        g_tracked_kiosks[found].last_heartbeat = time(NULL);
    }
    pthread_mutex_unlock(&g_kiosk_sync_lock);
}

void kiosk_broadcast_os_update(const char *release_id, const char *channel, const char *security_profile) {
    pthread_mutex_lock(&g_kiosk_sync_lock);
    g_kiosk_command_seq++;
    snprintf(g_kiosk_latest_command, sizeof(g_kiosk_latest_command), "RELOAD");
    snprintf(g_kiosk_latest_payload, sizeof(g_kiosk_latest_payload),
             "{\"event\":\"OS_DEPLOYMENT_UPDATE\",\"release\":\"%s\",\"channel\":\"%s\",\"security\":\"%s\"}",
             release_id ? release_id : "", channel ? channel : "", security_profile ? security_profile : "");
    pthread_mutex_unlock(&g_kiosk_sync_lock);
}

int kiosk_get_active_count(void) {
    pthread_mutex_lock(&g_kiosk_sync_lock);
    int count = g_tracked_kiosk_count;
    pthread_mutex_unlock(&g_kiosk_sync_lock);
    return count;
}

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

/*
 * Extract an arbitrary request header from the parsed header block.  Returns 0
 * when the header was found exactly once, -1 otherwise.  Used for the MFA
 * enrollment token, which must travel in a header (never the URL or body) so it
 * cannot leak through logs, referrers, or JavaScript-visible query strings.
 */
static int extract_named_header(const char *buffer, const char *wanted,
                                char *out, size_t out_size) {
    if (!buffer || !wanted || !out || out_size == 0) return -1;
    out[0] = '\0';
    size_t wanted_len = strlen(wanted);
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
        if (name_length == wanted_len &&
            strncasecmp(line, wanted, name_length) == 0) {
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
    return found ? 0 : -1;
}


int extract_candidate_session_token(const char *buffer, const char *auth_header, char *out, size_t out_size) {
    if (!out || out_size == 0) return 0;
    out[0] = '\0';

    /* 1. Extract Bearer token */
    if (auth_header && strncasecmp(auth_header, "Bearer ", 7) == 0) {
        const char *t = auth_header + 7;
        while (*t == ' ' || *t == '\t') t++;
        size_t t_len = strlen(t);
        if (t_len == SESSION_TOKEN_LEN && t_len < out_size) {
            snprintf(out, out_size, "%s", t);
            return 1;
        }
    }

    /* 2. Extract from Cookie header (examos_token or candidate_token) */
    if (buffer) {
        const char *headers_end = strstr(buffer, "\r\n\r\n");
        const char *line = strstr(buffer, "\r\n");
        if (headers_end && line && line < headers_end) {
            line += 2;
            while (line < headers_end) {
                const char *line_end = strstr(line, "\r\n");
                if (!line_end || line_end > headers_end) break;
                const char *colon = memchr(line, ':', (size_t)(line_end - line));
                if (colon && (size_t)(colon - line) == sizeof("Cookie") - 1 &&
                    strncasecmp(line, "Cookie", sizeof("Cookie") - 1) == 0) {
                    const char *item = colon + 1;
                    while (item < line_end) {
                        while (item < line_end && (*item == ' ' || *item == '\t' || *item == ';')) item++;
                        const char *item_end = memchr(item, ';', (size_t)(line_end - item));
                        if (!item_end) item_end = line_end;
                        const char *equals = memchr(item, '=', (size_t)(item_end - item));
                        if (equals) {
                            size_t key_len = (size_t)(equals - item);
                            if ((key_len == 12 && strncmp(item, "examos_token", 12) == 0) ||
                                (key_len == 15 && strncmp(item, "candidate_token", 15) == 0)) {
                                const char *value = equals + 1;
                                size_t length = (size_t)(item_end - value);
                                if (length == SESSION_TOKEN_LEN && length < out_size) {
                                    memcpy(out, value, length);
                                    out[length] = '\0';
                                    return 1;
                                }
                            }
                        }
                        item = item_end < line_end ? item_end + 1 : line_end;
                    }
                }
                line = line_end + 2;
            }
        }
    }
    return 0;
}

static int extract_admin_session_cookie(const char *buffer, char *out, size_t out_size) {
    if (!buffer || !out || out_size == 0) return -1;
    out[0] = '\0';
    const char *headers_end = strstr(buffer, "\r\n\r\n");
    const char *line = strstr(buffer, "\r\n");
    if (!headers_end || !line || line > headers_end) return -1;
    line += 2;
    int cookie_header_seen = 0;
    int session_seen = 0;
    while (line < headers_end) {
        const char *line_end = strstr(line, "\r\n");
        if (!line_end || line_end > headers_end) return -1;
        const char *colon = memchr(line, ':', (size_t)(line_end - line));
        if (!colon || colon == line) return -1;
        if ((size_t)(colon - line) == sizeof("Cookie") - 1 &&
            strncasecmp(line, "Cookie", sizeof("Cookie") - 1) == 0) {
            if (cookie_header_seen++) return -1;
            const char *item = colon + 1;
            while (item < line_end) {
                while (item < line_end && (*item == ' ' || *item == '\t' || *item == ';')) item++;
                const char *item_end = memchr(item, ';', (size_t)(line_end - item));
                if (!item_end) item_end = line_end;
                const char *equals = memchr(item, '=', (size_t)(item_end - item));
                if (equals && (size_t)(equals - item) == sizeof("admin_session") - 1 &&
                    strncmp(item, "admin_session", sizeof("admin_session") - 1) == 0) {
                    if (session_seen++) return -1;
                    const char *value = equals + 1;
                    size_t length = (size_t)(item_end - value);
                    if (!length || length >= out_size) return -1;
                    for (size_t i = 0; i < length; ++i) {
                        unsigned char c = (unsigned char)value[i];
                        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                              (c >= '0' && c <= '9') || c == '-' || c == '_')) return -1;
                    }
                    memcpy(out, value, length);
                    out[length] = '\0';
                }
                item = item_end < line_end ? item_end + 1 : line_end;
            }
        }
        line = line_end + 2;
    }
    return 0;
}

static const char *status_text(int status_code) {
    switch (status_code) {
        case 200: return "OK";
        case 201: return "Created";
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

static int send_all(int client_fd, const char *data, size_t length) {
    size_t sent_total = 0;
    while (sent_total < length) {
        ssize_t sent = -1;
#if defined(USE_OPENSSL_TLS)
        if (g_conn_ssl) {
            if (length - sent_total > (size_t)INT_MAX) return -1;
            int written = SSL_write(g_conn_ssl, data + sent_total,
                                    (int)(length - sent_total));
            if (written <= 0) {
                int ssl_error = SSL_get_error(g_conn_ssl, written);
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
                    continue;
                return -1;
            }
            sent = (ssize_t)written;
        } else
#endif
        {
            sent = send(client_fd, data + sent_total, length - sent_total, MSG_NOSIGNAL);
            if (sent < 0 && errno == EINTR) continue;
        }
        if (sent <= 0) return -1;
        sent_total += (size_t)sent;
    }
    return 0;
}

static ssize_t receive_http_request(int fd, char *buffer, size_t capacity) {
    size_t used = 0, expected = 0;
    int headers_complete = 0;
    while (used + 1 < capacity) {
        ssize_t n = -1;
#if defined(USE_OPENSSL_TLS)
        if (g_conn_ssl) {
            if (capacity - used - 1 > (size_t)INT_MAX) return -2;
            int received = SSL_read(g_conn_ssl, buffer + used,
                                    (int)(capacity - used - 1));
            if (received <= 0) {
                int ssl_error = SSL_get_error(g_conn_ssl, received);
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
                    continue;
                break;
            }
            n = (ssize_t)received;
        } else
#endif
        {
            n = recv(fd, buffer + used, capacity - used - 1, 0);
            if (n < 0 && errno == EINTR) continue;
        }
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
    char header[2400];
    size_t body_len = body ? strlen(body) : 0;
    const char *hsts = "";
#if defined(USE_OPENSSL_TLS)
    if (g_conn_ssl) {
        hsts = "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n";
    }
#endif
    /* CORS headers for console integration. */
    char cors_header[700] = {0};
    if (g_cors_allowed && g_cors_origin[0]) {
        int cl = snprintf(cors_header, sizeof(cors_header),
            "Access-Control-Allow-Origin: %s\r\n"
            "Vary: Origin\r\n"
            "Access-Control-Allow-Credentials: true\r\n",
            g_cors_origin);
        if (cl < 0 || (size_t)cl >= sizeof(cors_header)) cors_header[0] = '\0';
    }
    int header_length = snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Cache-Control: no-store, no-cache, must-revalidate\r\n"
             "Pragma: no-cache\r\n"
             "X-Content-Type-Options: nosniff\r\n"
             "X-Frame-Options: DENY\r\n"
             "X-XSS-Protection: 1; mode=block\r\n"
             "X-Permitted-Cross-Domain-Policies: none\r\n"
             "Referrer-Policy: no-referrer\r\n"
             "Cross-Origin-Opener-Policy: same-origin\r\n"
             "Cross-Origin-Resource-Policy: cross-origin\r\n"
             "Permissions-Policy: camera=(self), microphone=(self), geolocation=(), payment=(), usb=()\r\n"
             "Content-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\n"
             "%s"
             "Connection: close\r\n"
             "%s%s"
             "\r\n",
             status_code, status_text(status_code), content_type, body_len,
             cors_header,
             hsts, extra_headers ? extra_headers : "");

    if (header_length < 0 || (size_t)header_length >= sizeof(header)) return;
    if (send_all(client_fd, header, (size_t)header_length) == 0 && body_len > 0) {
        send_all(client_fd, body, body_len);
    }
}

static void send_http_response(int client_fd, int status_code, const char *content_type, const char *body) {
    send_http_response_ex(client_fd, status_code, content_type, body, NULL);
}

/* Checks if client connected via 127.0.0.0/8 or IPv6 loopback ::1 */
static int is_loopback_client(int fd) {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *)&addr, &len) != 0) {
        return 0;
    }
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        uint32_t ip = ntohl(s->sin_addr.s_addr);
        return (ip >> 24) == 127;
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        static const unsigned char loopback6[16] = {
            0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1
        };
        static const unsigned char v4mapped_loopback[16] = {
            0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1
        };
        return memcmp(&s->sin6_addr, loopback6, 16) == 0 ||
               memcmp(&s->sin6_addr, v4mapped_loopback, 12) == 0;
    }
    return 0;
}

static int extract_user_agent(const char *buffer, char *out, size_t out_size) {
    if (!buffer || !out || out_size == 0) return -1;
    out[0] = '\0';
    const char *headers_end = strstr(buffer, "\r\n\r\n");
    const char *line = strstr(buffer, "\r\n");
    if (headers_end && line && line < headers_end) {
        line += 2;
        while (line < headers_end) {
            const char *line_end = strstr(line, "\r\n");
            if (!line_end || line_end > headers_end) break;
            const char *colon = memchr(line, ':', (size_t)(line_end - line));
            if (colon && (size_t)(colon - line) == sizeof("User-Agent") - 1 &&
                strncasecmp(line, "User-Agent", sizeof("User-Agent") - 1) == 0) {
                const char *val = colon + 1;
                while (val < line_end && (*val == ' ' || *val == '\t')) val++;
                size_t vlen = (size_t)(line_end - val);
                if (vlen >= out_size) vlen = out_size - 1;
                memcpy(out, val, vlen);
                out[vlen] = '\0';
                return 0;
            }
            line = line_end + 2;
        }
    }
    return -1;
}

static int has_kiosk_header(const char *buffer) {
    if (!buffer) return 0;
    return strstr(buffer, "X-ExamOS-Kiosk:") != NULL || strstr(buffer, "x-examos-kiosk:") != NULL;
}

static const char *candidate_kiosk_lockout_html(void) {
    return "<!DOCTYPE html>\n"
           "<html lang=\"en\">\n"
           "<head>\n"
           "  <meta charset=\"UTF-8\">\n"
           "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
           "  <title>ExamOS — Access Restricted</title>\n"
           "  <style>\n"
           "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
           "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;\n"
           "           background: #090d16; color: #f1f5f9; min-height: 100vh; display: flex;\n"
           "           flex-direction: column; justify-content: center; align-items: center; padding: 24px; }\n"
           "    .card { background: #131d2e; border: 1px solid #dc2626; border-radius: 14px; width: 100%;\n"
           "            max-width: 560px; padding: 36px; box-shadow: 0 25px 50px -12px rgba(220, 38, 38, 0.25); text-align: center; }\n"
           "    .icon { width: 56px; height: 56px; margin: 0 auto 16px; display: flex; align-items: center; justify-content: center;\n"
           "            background: rgba(220, 38, 38, 0.15); border: 2px solid #ef4444; border-radius: 14px; color: #f87171; font-size: 28px; }\n"
           "    .title { font-size: 22px; font-weight: 800; color: #f8fafc; margin-bottom: 8px; }\n"
           "    .tag { display: inline-block; background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d;\n"
           "           padding: 4px 12px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase;\n"
           "           letter-spacing: 0.05em; margin-bottom: 20px; }\n"
           "    .desc { font-size: 14px; color: #cbd5e1; line-height: 1.6; margin-bottom: 20px; text-align: left; }\n"
           "    .rules { background: #0b1120; border: 1px solid #1e293b; border-radius: 10px; padding: 18px;\n"
           "             text-align: left; margin-bottom: 24px; font-size: 13px; color: #94a3b8; line-height: 1.6; }\n"
           "    .rules strong { color: #e2e8f0; }\n"
           "    .rules ul { margin-left: 20px; margin-top: 8px; }\n"
           "    .rules li { margin-bottom: 6px; }\n"
           "    .footer { font-size: 11px; color: #64748b; border-top: 1px solid #1e293b; padding-top: 16px; margin-top: 8px; }\n"
           "    .footer a { color: #38bdf8; text-decoration: none; }\n"
           "  </style>\n"
           "</head>\n"
           "<body>\n"
           "  <div class=\"card\">\n"
           "    <div class=\"icon\">&#9888;</div>\n"
           "    <div class=\"title\">ExamOS Appliance Required</div>\n"
           "    <span class=\"tag\">Candidate Terminal Lockdown</span>\n"
           "    <p class=\"desc\">Candidate authentication and examination sessions cannot be run inside standard desktop operating systems (Windows, macOS, unmanaged Linux) or regular consumer browsers.</p>\n"
           "    <div class=\"rules\">\n"
           "      <strong>Examination Security Standards:</strong>\n"
           "      <ul>\n"
           "        <li><strong>Dedicated Appliance OS:</strong> Candidates must boot directly from the verified ExamOS bootable ISO or USB drive.</li>\n"
           "        <li><strong>Hardware Kiosk Supervisor:</strong> Examination runs exclusively inside the hardened Wayland/Cage kiosk sandbox with TPM attestation.</li>\n"
           "        <li><strong>Anti-Tamper Isolation:</strong> Virtual terminal switching, external processes, developer shortcuts, and host OS telemetry are disabled.</li>\n"
           "      </ul>\n"
           "    </div>\n"
           "    <div class=\"footer\">\n"
           "      ExamOS Appliance Gateway • Hardware Security Module • <a href=\"/admin\">Admin Portal</a>\n"
           "    </div>\n"
           "  </div>\n"
           "</body>\n"
           "</html>\n";
}

static int is_examos_kiosk_request(int client_fd, const char *buffer, const char *origin) {
    (void)origin;
    char ua[512] = {0};
    extract_user_agent(buffer, ua, sizeof(ua));

    int is_loopback = is_loopback_client(client_fd);
    int has_kiosk_ua = (strstr(ua, "ExamOS-Kiosk") != NULL);
    int has_header = has_kiosk_header(buffer);

    /* In production mode: MUST be loopback OR behind an authenticated TLS-terminated ingress proxy, AND have ExamOS Kiosk runtime signature */
    if (g_production_mode) {
        const char *tls_term = getenv("EXAMOS_TLS_TERMINATED");
        int is_tls_proxy = (tls_term && (strcmp(tls_term, "1") == 0 || strcmp(tls_term, "true") == 0));
        if (!is_loopback && !is_tls_proxy) return 0;
        return has_kiosk_ua || has_header;
    }

    /* In development mode: allow if kiosk UA, or kiosk header, or query param dev_kiosk=1 */
    if (has_kiosk_ua || has_header) return 1;
    if (buffer && (strstr(buffer, "dev_kiosk=1") != NULL || strstr(buffer, "kiosk=1") != NULL)) return 1;

    /* External standard browser or remote connection: rejected */
    return 0;
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

static int create_platform_id(const char *prefix, char *output, size_t capacity) {
    unsigned char random_bytes[16];
    static const char hex[] = "0123456789abcdef";
    if (!prefix || !output || capacity == 0 || RAND_bytes(random_bytes, sizeof(random_bytes)) != 1)
        return -1;
    int written = snprintf(output, capacity, "%s-", prefix);
    if (written < 0 || (size_t)written + sizeof(random_bytes) * 2 + 1 > capacity) {
        OPENSSL_cleanse(random_bytes, sizeof(random_bytes));
        return -1;
    }
    size_t offset = (size_t)written;
    for (size_t i = 0; i < sizeof(random_bytes); ++i) {
        output[offset++] = hex[random_bytes[i] >> 4];
        output[offset++] = hex[random_bytes[i] & 15];
    }
    output[offset] = '\0';
    OPENSSL_cleanse(random_bytes, sizeof(random_bytes));
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
    return ctrl_candidate_session_identity(authorization, candidate_id, max_len);
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

static int parse_json_int64(const char *buf, const char *key, int64_t *out) {
    if (!buf || !key || !out) return -1;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(buf, pattern);
    if (!pos) return -1;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == ':' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    errno = 0;
    char *end = NULL;
    long long value = strtoll(pos, &end, 10);
    if (errno != 0 || end == pos) return -1;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') end++;
    if (*end != ',' && *end != '}' && *end != '\0') return -1;
    *out = (int64_t)value;
    return 0;
}

static int parse_json_double(const char *buf, const char *key, double *out) {
    if (!buf || !key || !out) return -1;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(buf, pattern);
    if (!pos) return -1;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == ':' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    errno = 0;
    char *end = NULL;
    double value = strtod(pos, &end);
    if (errno != 0 || end == pos) return -1;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') end++;
    if (*end != ',' && *end != '}' && *end != '\0') return -1;
    *out = value;
    return 0;
}

/* Parse a JSON array of integer samples. Returns the number of values parsed,
 * or -1 when the key is absent or the array is malformed/oversized. */
static int parse_json_int_array(const char *buf, const char *key,
                                int32_t *out, int max_values) {
    if (!buf || !key || !out || max_values <= 0) return -1;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(buf, pattern);
    if (!pos) return -1;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    if (*pos != ':') return -1;
    pos++;
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    if (*pos != '[') return -1;
    pos++;

    int count = 0;
    for (;;) {
        while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
        if (*pos == ']') {
            pos++;
            break;
        }
        if (*pos == '\0') return -1;
        errno = 0;
        char *end = NULL;
        long value = strtol(pos, &end, 10);
        if (errno != 0 || end == pos || value < INT32_MIN || value > INT32_MAX)
            return -1;
        if (count >= max_values) return -1;
        out[count++] = (int32_t)value;
        pos = end;
        while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
        if (*pos == ',') {
            pos++;
            continue;
        }
        if (*pos == ']') {
            pos++;
            break;
        }
        return -1;
    }
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    if (*pos != ',' && *pos != '}' && *pos != '\0') return -1;
    return count;
}

static int reviewer_authorized(const char *authorization) {
    return bearer_secret_authorized(authorization, "EXAMOS_REVIEWER_TOKEN");
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

static int route_path_matches(const char *request_path, const char *route) {
    if (!request_path || !route) return 0;
    size_t route_len = strlen(route);
    return strncmp(request_path, route, route_len) == 0 &&
           (request_path[route_len] == '\0' || request_path[route_len] == '?');
}

/*
 * Session risk state.
 *
 * The proctoring evidence is the only input to the risk engine, so the
 * indicators are accumulated per session from the events the detectors
 * actually reported. Nothing here infers a violation that no detector
 * reported.
 */
#define RISK_MAX_SESSIONS 512

typedef struct {
    char                   session_id[64];
    time_t                 updated_at;
    violation_indicators_t indicators;
    risk_assessment_t      assessment;
} session_risk_state_t;

static session_risk_state_t g_risk_states[RISK_MAX_SESSIONS];
static pthread_mutex_t      g_risk_lock = PTHREAD_MUTEX_INITIALIZER;

static void risk_engine_assess_session(const char *session_id, const char *event_type,
                                        risk_assessment_t *out_assessment) {
    if (out_assessment) memset(out_assessment, 0, sizeof(*out_assessment));

    if (!session_id || !session_id[0] || !event_type) return;

    pthread_mutex_lock(&g_risk_lock);

    session_risk_state_t *state = NULL;
    for (int i = 0; i < RISK_MAX_SESSIONS; i++) {
        if (g_risk_states[i].updated_at &&
            strcmp(g_risk_states[i].session_id, session_id) == 0) {
            state = &g_risk_states[i];
            break;
        }
    }
    if (!state) {
        for (int i = 0; i < RISK_MAX_SESSIONS; i++) {
            if (!g_risk_states[i].updated_at) {
                state = &g_risk_states[i];
                memset(state, 0, sizeof(*state));
                snprintf(state->session_id, sizeof(state->session_id), "%s", session_id);
                break;
            }
        }
    }

    int should_log_risk = 0;
    char risk_desc[256] = {0};

    if (state) {
        if (strcmp(event_type, "NO_FACE") == 0) {
            state->indicators.face_absent_count++;
        } else if (strcmp(event_type, "MULTIPLE_FACES") == 0) {
            state->indicators.multiple_faces_count++;
        }
        state->updated_at = time(NULL);
        risk_engine_evaluate(&state->indicators, &state->assessment);
        if (out_assessment) *out_assessment = state->assessment;
        snprintf(risk_desc, sizeof(risk_desc), "score=%.2f level=%s no_face=%d multi_face=%d term=%d ev=%s",
                 state->assessment.composite_risk_score,
                 state->assessment.risk_level ? state->assessment.risk_level : "NORMAL",
                 state->indicators.face_absent_count,
                 state->indicators.multiple_faces_count,
                 state->assessment.should_terminate_exam,
                 event_type);
        should_log_risk = 1;
    }

    pthread_mutex_unlock(&g_risk_lock);

    /* ISS-03: Persist risk assessment state to durable tamper-evident ledger */
    if (should_log_risk) {
        ledger_block_t blk;
        ledger_append_event("RISK_ASSESSMENT_UPDATE", session_id, risk_desc, &blk);
    }
}

/*
 * Extracts the resource identifier from "/api/v1/platform/exams/<id>/<action>".
 * The identifier is the single path segment between the collection and the
 * action. Matching the action exactly (rather than searching for a substring
 * anywhere in the path) prevents one action from matching another action
 * whose name merely contains it, and prevents query-string content from
 * being mistaken for the action.
 */
static int platform_route_id(const char *path, const char *action,
                             char *out_id, size_t max_len) {
    if (!path || !action || !out_id || max_len == 0) return -1;
    static const char prefix[] = "/api/v1/platform/exams/";
    if (strncmp(path, prefix, sizeof(prefix) - 1) != 0) return -1;

    const char *rest = path + sizeof(prefix) - 1;
    const char *slash = strchr(rest, '/');
    if (!slash) return -1;

    size_t id_len = (size_t)(slash - rest);
    if (id_len == 0 || id_len >= max_len) return -1;
    memcpy(out_id, rest, id_len);
    out_id[id_len] = '\0';

    if (strcmp(slash + 1, action) != 0) return -1;
    return 0;
}

/*
 * Extracts the device identifier from "/api/v1/admin/fleet/<id>/<action>".
 * The action must match exactly, so that one action cannot be matched by
 * another whose name merely contains it.
 */
static int fleet_route_id(const char *path, const char *action,
                         char *out_id, size_t max_len) {
    if (!path || !action || !out_id || max_len == 0) return -1;
    static const char prefix[] = "/api/v1/admin/fleet/";
    if (strncmp(path, prefix, sizeof(prefix) - 1) != 0) return -1;

    const char *rest = path + sizeof(prefix) - 1;
    const char *slash = strchr(rest, '/');
    if (!slash) return -1;

    size_t id_len = (size_t)(slash - rest);
    if (id_len == 0 || id_len >= max_len) return -1;
    memcpy(out_id, rest, id_len);
    out_id[id_len] = '\0';

    if (strcmp(slash + 1, action) != 0) return -1;
    return 0;
}

/*
 * Administrative authorization for route handlers.
 *
 * Every administrative route resolves its permission from the durable role
 * and permission store through the administrator's bearer token. A single
 * helper is used so that no route can accidentally fall back to a weaker
 * check.
 */
static int admin_route_authorized(const char *auth_header, uint32_t permission) {
    const char *token = bearer_token(auth_header);
    if (!token || !token[0]) return 0;
    auth_session_t session;
    memset(&session, 0, sizeof(session));
    int allowed = admin_auth_store_authorize(token, permission, &session) == 0;
    OPENSSL_cleanse(&session, sizeof(session));
    return allowed;
}

static void* handle_client(void *arg) {

    client_connection_t *conn = (client_connection_t *)arg;
    int client_fd = conn->fd;
#if defined(USE_OPENSSL_TLS)
    g_conn_ssl = conn->ssl;
#endif
    free(conn);

#if defined(USE_OPENSSL_TLS)
    if (g_conn_ssl && SSL_accept(g_conn_ssl) <= 0) {
        goto client_done;
    }
#endif

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

    /* Extract Origin header for CORS. */
    char origin[512] = {0};
    {
        const char *headers_end = strstr(buffer, "\r\n\r\n");
        const char *line = strstr(buffer, "\r\n");
        if (headers_end && line && line < headers_end) {
            line += 2;
            while (line < headers_end) {
                const char *line_end = strstr(line, "\r\n");
                if (!line_end || line_end > headers_end) break;
                const char *colon = memchr(line, ':', (size_t)(line_end - line));
                if (colon && (size_t)(colon - line) == sizeof("Origin") - 1 &&
                    strncasecmp(line, "Origin", sizeof("Origin") - 1) == 0) {
                    const char *value = colon + 1;
                    while (value < line_end && (*value == ' ' || *value == '\t')) value++;
                    size_t vlen = (size_t)(line_end - value);
                    if (vlen > 0 && vlen < sizeof(origin)) {
                        memcpy(origin, value, vlen);
                        origin[vlen] = '\0';
                    }
                    break;
                }
                line = line_end + 2;
            }
        }
    }
    int cors_ok = cors_origin_allowed(origin);
    if (cors_ok) {
        g_cors_allowed = 1;
        snprintf(g_cors_origin, sizeof(g_cors_origin), "%s", origin);
    }

    /*
     * Routing compares the path without its query string. The original
     * path is kept so that query parameters can still be parsed.
     */
    char route_path[256] = {0};
    snprintf(route_path, sizeof(route_path), "%s", path);
    {
        char *query_delimiter = strchr(route_path, '?');
        if (query_delimiter) *query_delimiter = '\0';
    }

    /* CORS preflight: reply immediately with allowed headers, no auth needed. */
    if (is_cors_preflight(method, buffer)) {
        if (!cors_ok) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"CORS origin not allowed\"}");
            goto client_done;
        }
        char extra[512];
        int elen = snprintf(extra, sizeof(extra),
            "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Authorization, Content-Type, X-Enrollment-Token, X-ExamOS-Console, X-ExamOS-Console-Version, X-ExamOS-Request-Id, X-ExamOS-Timestamp, X-ExamOS-Signature, X-ExamOS-Signature-Alg, X-ExamOS-Signature-Key-Id, X-Requested-With\r\n"
            "Access-Control-Max-Age: 86400\r\n");
        if (elen > 0 && (size_t)elen < sizeof(extra))
            send_http_response_ex(client_fd, 204, "application/json", "", extra);
        else
            send_http_response(client_fd, 204, "application/json", "");
        goto client_done;
    }

    char extra[700] = {0};
    /* Note: send_http_response_ex already emits Access-Control-Allow-Origin from g_cors_origin */

    // Extract Authorization only from the parsed header block, never from the body.
    char auth_header[512] = {0};
    if (extract_authorization_header(buffer, auth_header, sizeof(auth_header)) != 0) {
        send_http_response(client_fd, 400, "application/json", "{\"error\":\"Invalid or duplicate Authorization header\"}");
        goto client_done;
    }
    if (auth_header[0] == '\0') {
        char cookie_token[256] = {0};
        if (extract_admin_session_cookie(buffer, cookie_token, sizeof(cookie_token)) == 0 && cookie_token[0]) {
            snprintf(auth_header, sizeof(auth_header), "Bearer %s", cookie_token);
        }
    }

    /* Single-use authenticator enrollment token issued by /admin/login. */
    char enrollment_token[128] = {0};
    if (extract_named_header(buffer, "X-Enrollment-Token",
                             enrollment_token, sizeof(enrollment_token)) != 0) {
        enrollment_token[0] = '\0';
    }

    // Extract body if POST
    const char *body_pos = strstr(buffer, "\r\n\r\n");
    const char *req_body = body_pos ? body_pos + 4 : "";

    /* Resource identifier for /api/v1/platform/exams/<id>/<action> routes. */
    char exam_route_id[128] = {0};
    /* Resource identifier for /api/v1/admin/fleet/<id>/<action> routes. */
    char fleet_route_device[128] = {0};

    /* Route: GET / -> Candidate Login UI */
    if (strcmp(route_path, "/") == 0 && strcmp(method, "GET") == 0) {
        if (!is_examos_kiosk_request(client_fd, buffer, origin)) {
            send_http_response(client_fd, 403, "text/html; charset=utf-8", candidate_kiosk_lockout_html());
        } else {
            send_http_response(client_fd, 200, "text/html; charset=utf-8", candidate_login_html());
        }
    }
    /* Authenticated policy enforcement acknowledgement. */
    else if (strcmp(route_path, "/api/v1/policies/acknowledge") == 0 &&
             strcmp(method, "POST") == 0) {
        char challenge_id[64], exam_id[64], institution_id[64], device_id[64];
        char policy_release_id[64], policy_digest[72], nonce_sha256[65];
        char attestation_id[64], signature_base64[8192], canonical_ack[16384];
        char enforcement_status[32];
        memset(challenge_id, 0, sizeof(challenge_id));
        memset(exam_id, 0, sizeof(exam_id));
        memset(institution_id, 0, sizeof(institution_id));
        memset(device_id, 0, sizeof(device_id));
        memset(policy_release_id, 0, sizeof(policy_release_id));
        memset(policy_digest, 0, sizeof(policy_digest));
        memset(nonce_sha256, 0, sizeof(nonce_sha256));
        memset(attestation_id, 0, sizeof(attestation_id));
        memset(signature_base64, 0, sizeof(signature_base64));
        memset(canonical_ack, 0, sizeof(canonical_ack));
        memset(enforcement_status, 0, sizeof(enforcement_status));
        parse_json_string(req_body, "challenge_id", challenge_id, sizeof(challenge_id));
        parse_json_string(req_body, "exam_id", exam_id, sizeof(exam_id));
        parse_json_string(req_body, "institution_id", institution_id, sizeof(institution_id));
        parse_json_string(req_body, "device_id", device_id, sizeof(device_id));
        parse_json_string(req_body, "policy_release_id", policy_release_id, sizeof(policy_release_id));
        parse_json_string(req_body, "policy_digest", policy_digest, sizeof(policy_digest));
        parse_json_string(req_body, "nonce_sha256", nonce_sha256, sizeof(nonce_sha256));
        parse_json_string(req_body, "attestation_id", attestation_id, sizeof(attestation_id));
        parse_json_string(req_body, "signature_base64", signature_base64, sizeof(signature_base64));
        parse_json_string(req_body, "canonical_acknowledgement", canonical_ack, sizeof(canonical_ack));
        parse_json_string(req_body, "enforcement_status", enforcement_status, sizeof(enforcement_status));
        int policy_version = parse_json_int(req_body, "policy_version", 0);

        if (!challenge_id[0] || !exam_id[0] || !institution_id[0] ||
            !device_id[0] || !policy_release_id[0] || !policy_digest[0] ||
            !nonce_sha256[0] || !attestation_id[0] || !signature_base64[0] ||
            !canonical_ack[0] || policy_version <= 0 ||
            (strcmp(enforcement_status, "ENFORCED") != 0 &&
             strcmp(enforcement_status, "FAILED") != 0)) {
            send_http_response(client_fd, 400, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Complete challenge-bound acknowledgement fields are required\"}");
            goto client_done;
        }
        if (strlen(nonce_sha256) != 64 || strlen(policy_digest) != 71 ||
            strncmp(policy_digest, "sha256:", 7) != 0 ||
            !is_examos_kiosk_request(client_fd, buffer, origin)) {
            send_http_response(client_fd, 403, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Acknowledgement must come from the ExamOS kiosk with valid digest fields\"}");
            goto client_done;
        }

        PGconn *conn = db_acquire();
        if (!conn) {
            send_http_response(client_fd, 503, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Acknowledgement database unavailable\"}");
            goto client_done;
        }
        PGresult *begin = PQexec(conn, "BEGIN");
        if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
            if (begin) PQclear(begin);
            db_release(conn, 1);
            send_http_response(client_fd, 503, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Acknowledgement transaction could not start\"}");
            goto client_done;
        }
        PQclear(begin);

        char version_text[16];
        snprintf(version_text, sizeof(version_text), "%d", policy_version);
        const char *params[7] = { challenge_id, exam_id, institution_id, device_id,
                                  policy_release_id, policy_digest, version_text };
        int lengths[7];
        for (int i = 0; i < 7; i++) lengths[i] = (int)strlen(params[i]);
        PGresult *challenge = db_simple(conn,
            "SELECT c.nonce_sha256,c.expires_at,c.state,p.canonical_payload_sha256,"
            "a.attestation_id,a.state,a.verified_at,a.device_id,a.institution_id "
            "FROM examos_policy_enforcement_challenges c "
            "JOIN examos_published_policies p ON p.policy_release_id=c.policy_release_id "
            "JOIN examos_attestation_challenges a ON a.attestation_id=$8 "
            "WHERE c.challenge_id=$1 AND c.exam_id=$2 AND c.institution_id=$3 "
            "AND c.device_id=$4 AND c.policy_release_id=$5 "
            "AND c.policy_digest=$6 AND c.policy_version=$7::integer "
            "AND a.institution_id=c.institution_id AND a.device_id=c.device_id "
            "AND a.purpose='exam_launch' AND a.state='TRUSTED' "
            "AND a.verified_at > clock_timestamp()-interval '10 minutes' "
            "AND c.expires_at > clock_timestamp() "
            "FOR UPDATE OF c",
            8, (const char *[]){ challenge_id, exam_id, institution_id, device_id,
                                  policy_release_id, policy_digest, version_text,
                                  attestation_id },
            (const int []){ lengths[0], lengths[1], lengths[2], lengths[3],
                            lengths[4], lengths[5], lengths[6], (int)strlen(attestation_id) });
        if (!challenge || PQresultStatus(challenge) != PGRES_TUPLES_OK ||
            PQntuples(challenge) != 1) {
            if (challenge) PQclear(challenge);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_http_response(client_fd, 409, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Acknowledgement challenge or policy binding mismatch\"}");
            goto client_done;
        }
        if (strcmp(PQgetvalue(challenge, 0, 0), nonce_sha256) != 0 ||
            strcmp(PQgetvalue(challenge, 0, 2), "pending") != 0 ||
            strcmp(PQgetvalue(challenge, 0, 3), policy_digest) != 0 ||
            strcmp(PQgetvalue(challenge, 0, 4), attestation_id) != 0 ||
            strcmp(PQgetvalue(challenge, 0, 5), "TRUSTED") != 0 ||
            strcmp(PQgetvalue(challenge, 0, 7), device_id) != 0 ||
            strcmp(PQgetvalue(challenge, 0, 8), institution_id) != 0) {
            PQclear(challenge);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_http_response(client_fd, 409, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Stale, mismatched, or untrusted acknowledgement challenge\"}");
            goto client_done;
        }
        PQclear(challenge);

        char ack_challenge[64] = {0}, ack_exam[64] = {0},
             ack_institution[64] = {0}, ack_device[64] = {0},
             ack_policy_release[64] = {0}, ack_policy_digest[72] = {0},
             ack_nonce[65] = {0}, ack_attestation[64] = {0},
             ack_enforcement_status[32] = {0};
        int ack_policy_version = 0;
        parse_json_string(canonical_ack, "challenge_id", ack_challenge,
                          sizeof(ack_challenge));
        parse_json_string(canonical_ack, "exam_id", ack_exam,
                          sizeof(ack_exam));
        parse_json_string(canonical_ack, "institution_id", ack_institution,
                          sizeof(ack_institution));
        parse_json_string(canonical_ack, "device_id", ack_device,
                          sizeof(ack_device));
        parse_json_string(canonical_ack, "policy_release_id",
                          ack_policy_release, sizeof(ack_policy_release));
        parse_json_string(canonical_ack, "policy_digest", ack_policy_digest,
                          sizeof(ack_policy_digest));
        parse_json_string(canonical_ack, "nonce_sha256", ack_nonce,
                          sizeof(ack_nonce));
        parse_json_string(canonical_ack, "attestation_id", ack_attestation,
                          sizeof(ack_attestation));
        parse_json_string(canonical_ack, "enforcement_status",
                          ack_enforcement_status,
                          sizeof(ack_enforcement_status));
        ack_policy_version = parse_json_int(canonical_ack, "policy_version", 0);
        if (strcmp(ack_challenge, challenge_id) != 0 ||
            strcmp(ack_exam, exam_id) != 0 ||
            strcmp(ack_institution, institution_id) != 0 ||
            strcmp(ack_device, device_id) != 0 ||
            strcmp(ack_policy_release, policy_release_id) != 0 ||
            strcmp(ack_policy_digest, policy_digest) != 0 ||
            strcmp(ack_nonce, nonce_sha256) != 0 ||
            strcmp(ack_attestation, attestation_id) != 0 ||
            strcmp(ack_enforcement_status, enforcement_status) != 0 ||
            ack_policy_version != policy_version) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_http_response(client_fd, 409, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Canonical acknowledgement fields do not match the challenge\"}");
            goto client_done;
        }

        PGresult *ak = db_simple(conn,
            "SELECT k.public_key_pem,k.public_key_fingerprint,k.key_algorithm,"
            "k.status FROM device_attestation_keys k "
            "WHERE k.device_id=$1 AND k.status='active'",
            1, (const char *[]){ device_id }, (const int []){ (int)strlen(device_id) });
        if (!ak || PQresultStatus(ak) != PGRES_TUPLES_OK || PQntuples(ak) != 1) {
            if (ak) PQclear(ak);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_http_response(client_fd, 403, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"No active device attestation key is bound to the device\"}");
            goto client_done;
        }
        const char *ak_pem = PQgetvalue(ak, 0, 0);
        const char *ak_fingerprint = PQgetvalue(ak, 0, 1);
        const char *ak_algorithm = PQgetvalue(ak, 0, 2);
        char signature_algorithm[32];
        if (strcmp(ak_algorithm, "RSA-2048") == 0 || strcmp(ak_algorithm, "RSA-3072") == 0)
            snprintf(signature_algorithm, sizeof(signature_algorithm), "rsa-sha256");
        else if (strcmp(ak_algorithm, "ECC-P256") == 0)
            snprintf(signature_algorithm, sizeof(signature_algorithm), "ecdsa-p256-sha256");
        else if (strcmp(ak_algorithm, "ECC-P384") == 0)
            snprintf(signature_algorithm, sizeof(signature_algorithm), "ecdsa-p384-sha384");
        else
            signature_algorithm[0] = '\0';
        int signature_valid = signature_algorithm[0] &&
            release_signature_verify(canonical_ack, strlen(canonical_ack),
                                    policy_digest, policy_digest, policy_digest,
                                    signature_algorithm, signature_algorithm,
                                    signature_base64, ak_pem, ak_fingerprint) == 1;
        PQclear(ak);
        if (!signature_valid) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_http_response(client_fd, 403, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Forged or unauthenticated policy acknowledgement\"}");
            goto client_done;
        }
        unsigned char random[16];
        char ack_id[64];
        if (RAND_bytes(random, sizeof(random)) != 1) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 1);
            send_http_response(client_fd, 500, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Acknowledgement randomness unavailable\"}");
            goto client_done;
        }
        static const char ack_hex[] = "0123456789abcdef";
        memcpy(ack_id, "pka_", 4);
        for (size_t i = 0; i < sizeof(random); i++) {
            ack_id[4 + i * 2] = ack_hex[random[i] >> 4];
            ack_id[5 + i * 2] = ack_hex[random[i] & 15];
        }
        ack_id[36] = '\0';
        OPENSSL_cleanse(random, sizeof(random));

        const char *ack_params[10] = {
            ack_id, challenge_id, exam_id, institution_id, device_id,
            policy_release_id, version_text, policy_digest,
            enforcement_status, attestation_id
        };
        int ack_lengths[10];
        for (int i = 0; i < 10; i++) ack_lengths[i] = (int)strlen(ack_params[i]);
        PGresult *insert_ack = db_simple(conn,
            "INSERT INTO examos_policy_device_acknowledgements "
            "(acknowledgement_id,challenge_id,exam_id,institution_id,device_id,"
            "policy_release_id,policy_version,policy_digest,enforcement_status,"
            "attestation_id,signature_base64) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7::integer,$8,$9,$10,$11)",
            11,
            (const char *[]){ ack_params[0], ack_params[1], ack_params[2],
                              ack_params[3], ack_params[4], ack_params[5],
                              ack_params[6], ack_params[7], ack_params[8],
                              ack_params[9], signature_base64 },
            (const int []){ ack_lengths[0], ack_lengths[1], ack_lengths[2],
                            ack_lengths[3], ack_lengths[4], ack_lengths[5],
                            ack_lengths[6], ack_lengths[7], ack_lengths[8],
                            ack_lengths[9], (int)strlen(signature_base64) });
        int ack_inserted = insert_ack && PQresultStatus(insert_ack) == PGRES_COMMAND_OK;
        if (insert_ack) PQclear(insert_ack);
        PGresult *consume = ack_inserted ? db_simple(conn,
            "UPDATE examos_policy_enforcement_challenges "
            "SET state='used',used_at=clock_timestamp() "
            "WHERE challenge_id=$1 AND state='pending'",
            1, (const char *[]){ challenge_id },
            (const int []){ (int)strlen(challenge_id) }) : NULL;
        int consumed = consume && PQresultStatus(consume) == PGRES_COMMAND_OK &&
                       strcmp(PQcmdTuples(consume), "1") == 0;
        if (consume) PQclear(consume);
        PGresult *commit = ack_inserted && consumed ? PQexec(conn, "COMMIT") : NULL;
        int committed = commit && PQresultStatus(commit) == PGRES_COMMAND_OK;
        if (commit) PQclear(commit);
        if (!committed) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            send_http_response(client_fd, 409, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Acknowledgement changed or was already consumed\"}");
            goto client_done;
        }
        db_release(conn, 0);
        char response[192];
        snprintf(response, sizeof(response),
                 "{\"status\":\"ACKNOWLEDGED\",\"acknowledgement_id\":\"%s\","
                 "\"challenge_id\":\"%s\",\"policy_version\":%d}",
                 ack_id, challenge_id, policy_version);
        send_http_response(client_fd, 200, "application/json", response);
    }
    /* Route: POST /api/v1/candidate/login */
    else if (strcmp(route_path, "/api/v1/candidate/login") == 0 && strcmp(method, "POST") == 0) {
        if (!is_examos_kiosk_request(client_fd, buffer, origin)) {
            send_http_response_ex(client_fd, 403, "application/json",
                "{\"status\":\"FAIL\",\"error\":\"ACCESS_DENIED: Candidate portal is strictly restricted to the ExamOS secure bootable kiosk operating system. External operating systems and browsers are prohibited.\"}",
                extra);
            goto client_done;
        }
        auth_candidate_login(client_fd, req_body, origin, extra, sizeof(extra));
        goto client_done;
    }
    /* Route: POST /api/v1/candidate/logout */
    else if (strcmp(route_path, "/api/v1/candidate/logout") == 0 && strcmp(method, "POST") == 0) {
        auth_candidate_logout(client_fd, auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if (strcmp(route_path, "/api/v1/candidate/checkin/status") == 0 &&
             strcmp(method, "POST") == 0) {
        if (!is_examos_kiosk_request(client_fd, buffer, origin)) {
            send_http_response_ex(client_fd, 403, "application/json",
                "{\"status\":\"FAIL\",\"error\":\"Candidate check-in polling is restricted to the ExamOS kiosk.\"}",
                extra);
            goto client_done;
        }
        auth_candidate_workflow_handle(client_fd, method, route_path, req_body,
                                       auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    /* Canonical dashboard route plus the established API login alias. */
    else if ((strcmp(route_path, "/api/v1/admin/login") == 0 ||
              strcmp(route_path, "/api/v1/auth/login") == 0) && strcmp(method, "POST") == 0) {
        auth_admin_login(client_fd, req_body, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if (strcmp(route_path, "/api/v1/admin/logout") == 0 && strcmp(method, "POST") == 0) {
        auth_admin_logout(client_fd, auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strcmp(route_path, "/api/v1/admin/session") == 0 ||
              strcmp(route_path, "/api/v1/auth/session") == 0) && strcmp(method, "GET") == 0) {
        auth_admin_session(client_fd, auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strcmp(route_path, "/api/v1/admin/mfa/setup") == 0 ||
              strcmp(route_path, "/api/v1/auth/mfa/setup") == 0) && strcmp(method, "POST") == 0) {
        auth_mfa_setup(client_fd, req_body, auth_header, enrollment_token, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strcmp(route_path, "/api/v1/admin/mfa/confirm") == 0 ||
              strcmp(route_path, "/api/v1/auth/mfa/confirm") == 0) && strcmp(method, "POST") == 0) {
        auth_mfa_confirm(client_fd, req_body, auth_header, enrollment_token, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strcmp(route_path, "/api/v1/admin/recovery/reset") == 0 ||
              strcmp(route_path, "/api/v1/auth/recovery/reset") == 0) && strcmp(method, "POST") == 0) {
        auth_recovery_reset(client_fd, req_body, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strcmp(route_path, "/api/v1/admin/password/change") == 0 ||
              strcmp(route_path, "/api/v1/auth/password/change") == 0) && strcmp(method, "POST") == 0) {
        auth_change_password(client_fd, req_body, auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strcmp(route_path, "/api/v1/admin/sessions") == 0 ||
              strcmp(route_path, "/api/v1/auth/sessions") == 0) && strcmp(method, "GET") == 0) {
        auth_admin_sessions_list(client_fd, auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strcmp(route_path, "/api/v1/admin/sessions/others") == 0 ||
              strcmp(route_path, "/api/v1/auth/sessions/others") == 0) && strcmp(method, "POST") == 0) {
        auth_admin_sessions_revoke_others(client_fd, auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strncmp(route_path, "/api/v1/admin/sessions/", 23) == 0 ||
              strncmp(route_path, "/api/v1/auth/sessions/", 22) == 0) &&
             (strcmp(method, "DELETE") == 0 || strcmp(method, "POST") == 0)) {
        const char *sid_part = strncmp(route_path, "/api/v1/admin/sessions/", 23) == 0
            ? route_path + 23 : route_path + 22;
        auth_admin_session_revoke(client_fd, sid_part, auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strcmp(route_path, "/api/v1/admin/recovery/regenerate") == 0 ||
              strcmp(route_path, "/api/v1/auth/recovery/regenerate") == 0) && strcmp(method, "POST") == 0) {
        auth_recovery_regenerate(client_fd, auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strcmp(route_path, "/api/v1/admin/profile") == 0 ||
              strcmp(route_path, "/api/v1/auth/profile") == 0) &&
             (strcmp(method, "PATCH") == 0 || strcmp(method, "PUT") == 0)) {
        auth_update_profile(client_fd, req_body, auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    else if ((strcmp(route_path, "/api/v1/audit/batch") == 0 ||
              strcmp(route_path, "/api/v1/admin/audit/batch") == 0) && strcmp(method, "POST") == 0) {
        ctrl_set_cors(extra, sizeof(extra), origin, ctrl_cors_origin_allowed(origin));

        /* Audit writes are attributed to the authenticated principal, never to
         * an actor string supplied in the request body. */
        char audit_actor[80] = {0};
        auth_session_t audit_sess;
        memset(&audit_sess, 0, sizeof(audit_sess));
        if (ctrl_authorize(auth_header, AUTH_PERM_READ, &audit_sess) == 0) {
            snprintf(audit_actor, sizeof(audit_actor), "%s",
                     audit_sess.user_id[0] ? audit_sess.user_id : "admin");
        } else {
            char candidate_id[64] = {0};
            if (ctrl_candidate_session_identity(auth_header, candidate_id,
                                                sizeof(candidate_id)) &&
                candidate_id[0]) {
                snprintf(audit_actor, sizeof(audit_actor), "%s", candidate_id);
            }
        }

        if (!audit_actor[0]) {
            ctrl_send_json(client_fd, 401,
                "{\"error\":\"Authenticated session required to record audit events\"}", extra);
            goto client_done;
        }

        int audit_appended = 0;
        char audit_error[192] = {0};
        if (audit_append_batch_json(req_body, audit_actor, &audit_appended,
                                    audit_error, sizeof(audit_error)) != 0) {
            int status = strstr(audit_error, "Failed to persist") ? 500 : 400;
            char err_body[384];
            snprintf(err_body, sizeof(err_body),
                     "{\"error\":\"%s\",\"appended\":%d}", audit_error, audit_appended);
            ctrl_send_json(client_fd, status, err_body, extra);
            goto client_done;
        }

        char ok_body[96];
        snprintf(ok_body, sizeof(ok_body),
                 "{\"status\":\"RECORDED\",\"appended\":%d}", audit_appended);
        ctrl_send_json(client_fd, 200, ok_body, extra);
        goto client_done;
    }
    /* Enterprise Institution, Applications, Agreements, Licenses, Deployments, Campuses, Centers, Departments, and Staff Management */
    else if (strncmp(route_path, "/api/v1/admin/institutions", 26) == 0 ||
             strncmp(route_path, "/api/v1/admin/institution-applications", 38) == 0 ||
             strncmp(route_path, "/api/v1/institutions/apply", 26) == 0 ||
             strncmp(route_path, "/api/v1/admin/agreements", 24) == 0 ||
             strncmp(route_path, "/api/v1/admin/licenses", 22) == 0 ||
             strncmp(route_path, "/api/v1/admin/deployments", 25) == 0 ||
             strncmp(route_path, "/api/v1/admin/campuses", 22) == 0 ||
             strncmp(route_path, "/api/v1/admin/centers", 21) == 0 ||
             strncmp(route_path, "/api/v1/admin/departments", 25) == 0 ||
             strncmp(route_path, "/api/v1/admin/staff", 19) == 0) {
        /* Pass the original path (which retains the query string) so that
         * institution_handle can read query parameters such as institution_id
         * via inst_query_param(). route_path has '?' stripped and cannot be
         * used for query-string parsing. */
        institution_handle(client_fd, method, path, req_body,
                           auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    /* Organization reads are session-scoped; only the platform owner can enumerate tenants. */
    else if (strcmp(route_path, "/api/v1/admin/institutions") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *token = strncmp(auth_header, prefix, sizeof(prefix) - 1) == 0
            ? auth_header + sizeof(prefix) - 1 : NULL;
        auth_session_t session;
        memset(&session, 0, sizeof(session));
        if (!token || admin_auth_store_authorize(token, AUTH_PERM_INSTITUTION_ADMIN, &session) != 0 ||
            session.role != ROLE_PLATFORM_OWNER) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"Platform owner authorization required\"}");
        } else {
            char response[32768];
            if (platform_get_institutions_json(response, sizeof(response)) == 0)
                send_http_response(client_fd, 200, "application/json", response);
            else
                send_http_response(client_fd, 503, "application/json", "{\"error\":\"Institution service unavailable\"}");
        }
        OPENSSL_cleanse(&session, sizeof(session));
    }
    else if (strncmp(route_path, "/api/v1/admin/institutions/", 27) == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *token = strncmp(auth_header, prefix, sizeof(prefix) - 1) == 0
            ? auth_header + sizeof(prefix) - 1 : NULL;
        auth_session_t session;
        memset(&session, 0, sizeof(session));
        const char *institution_id = path + 27;
        int id_valid = institution_id[0] != '\0' && !strpbrk(institution_id, "/?&#");
        int authorized = token && admin_auth_store_authorize(token, AUTH_PERM_EXAM_READ, &session) == 0;
        if (!authorized || !id_valid ||
            (session.role != ROLE_PLATFORM_OWNER &&
             strcmp(session.institution_id, institution_id) != 0)) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"Institution scope denied\"}");
        } else {
            char response[4096];
            if (platform_get_institution_json(institution_id, response, sizeof(response)) == 0)
                send_http_response(client_fd, 200, "application/json", response);
            else
                send_http_response(client_fd, 404, "application/json", "{\"error\":\"Institution not found\"}");
        }
        OPENSSL_cleanse(&session, sizeof(session));
    }
    else if (strcmp(route_path, "/api/v1/admin/exams") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *token = strncmp(auth_header, prefix, sizeof(prefix) - 1) == 0
            ? auth_header + sizeof(prefix) - 1 : NULL;
        auth_session_t session;
        memset(&session, 0, sizeof(session));
        if (!token || admin_auth_store_authorize(token, AUTH_PERM_EXAM_READ, &session) != 0) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"Exam read permission required\"}");
        } else {
            char response[65536];
            if (platform_get_exams_for_admin(&session, response, sizeof(response)) == 0)
                send_http_response(client_fd, 200, "application/json", response);
            else
                send_http_response(client_fd, 503, "application/json", "{\"error\":\"Exam service unavailable\"}");
        }
        OPENSSL_cleanse(&session, sizeof(session));
    }
    /* Campus and room records are tenant scoped and persisted by the platform store. */
    else if (route_path_matches(route_path, "/api/v1/admin/campuses") &&
             (strcmp(method, "GET") == 0 || strcmp(method, "POST") == 0)) {
        const char *token = bearer_token(auth_header);
        auth_session_t session; memset(&session, 0, sizeof(session));
        if (!token || admin_auth_store_authorize(token,
                strcmp(method, "GET") == 0 ? AUTH_PERM_EXAM_READ : AUTH_PERM_LOCATION_ADMIN,
                &session) != 0) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"Institution access denied\"}");
        } else if (strcmp(method, "GET") == 0) {
            char institution_id[128] = {0};
            parse_query_id(path, "institution_id", institution_id, sizeof(institution_id));
            if ((session.role != ROLE_PLATFORM_OWNER && !session.institution_id[0]) ||
                (session.role != ROLE_PLATFORM_OWNER && institution_id[0] &&
                 strcmp(session.institution_id, institution_id) != 0)) {
                send_http_response(client_fd, 403, "application/json", "{\"error\":\"Institution scope denied\"}");
            } else {
                const char *scope = session.role == ROLE_PLATFORM_OWNER ? institution_id : session.institution_id;
                char response[65536];
                if (platform_get_campuses_json(scope, response, sizeof(response)) == 0)
                    send_http_response(client_fd, 200, "application/json", response);
                else send_http_response(client_fd, 503, "application/json", "{\"error\":\"Campus service unavailable\"}");
            }
        } else {
            campus_t campus; memset(&campus, 0, sizeof(campus));
            parse_json_string(req_body, "institution_id", campus.institution_id, sizeof(campus.institution_id));
            parse_json_string(req_body, "name", campus.name, sizeof(campus.name));
            parse_json_string(req_body, "address", campus.address, sizeof(campus.address));
            if (session.role != ROLE_PLATFORM_OWNER) {
                if (session.institution_id[0]) snprintf(campus.institution_id, sizeof(campus.institution_id), "%s", session.institution_id);
                else campus.institution_id[0] = '\0';
            }
            if (!campus.institution_id[0] || !campus.name[0] ||
                create_platform_id("campus", campus.campus_id, sizeof(campus.campus_id)) != 0) {
                send_http_response(client_fd, 400, "application/json", "{\"error\":\"Valid institution_id and name are required\"}");
            } else if (platform_create_campus(&campus) == 0) {
                char response[192]; snprintf(response, sizeof(response), "{\"status\":\"created\",\"campus_id\":\"%s\"}", campus.campus_id);
                send_http_response(client_fd, 201, "application/json", response);
            } else {
                char resp[640];
                snprintf(resp, sizeof(resp), "{\"error\":\"%s\"}", platform_last_error());
                send_http_response(client_fd, 409, "application/json", resp);
            }
        }
        OPENSSL_cleanse(&session, sizeof(session));
    }
    else if (route_path_matches(route_path, "/api/v1/admin/rooms") &&
             (strcmp(method, "GET") == 0 || strcmp(method, "POST") == 0)) {
        const char *token = bearer_token(auth_header);
        auth_session_t session; memset(&session, 0, sizeof(session));
        if (!token || admin_auth_store_authorize(token,
                strcmp(method, "GET") == 0 ? AUTH_PERM_EXAM_READ : AUTH_PERM_LOCATION_ADMIN,
                &session) != 0) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"Room access denied\"}");
        } else if (strcmp(method, "GET") == 0) {
            char campus_id[128] = {0}; parse_query_id(path, "campus_id", campus_id, sizeof(campus_id));
            if (!campus_id[0]) send_http_response(client_fd, 400, "application/json", "{\"error\":\"campus_id query parameter required\"}");
            else if (session.role != ROLE_PLATFORM_OWNER && !session.institution_id[0]) send_http_response(client_fd, 403, "application/json", "{\"error\":\"Institution scope required\"}");
            else {
                char response[65536];
                const char *scope = session.role == ROLE_PLATFORM_OWNER ? NULL : session.institution_id;
                if (platform_get_rooms_for_institution_json(campus_id, scope, response, sizeof(response)) == 0)
                    send_http_response(client_fd, 200, "application/json", response);
                else send_http_response(client_fd, 503, "application/json", "{\"error\":\"Room service unavailable\"}");
            }
        } else {
            room_t room; memset(&room, 0, sizeof(room));
            parse_json_string(req_body, "campus_id", room.campus_id, sizeof(room.campus_id));
            parse_json_string(req_body, "institution_id", room.institution_id, sizeof(room.institution_id));
            parse_json_string(req_body, "name", room.name, sizeof(room.name));
            parse_json_string(req_body, "supervisor", room.supervisor, sizeof(room.supervisor));
            room.capacity = parse_json_int(req_body, "capacity", 0);
            if (session.role != ROLE_PLATFORM_OWNER) {
                if (session.institution_id[0]) snprintf(room.institution_id, sizeof(room.institution_id), "%s", session.institution_id);
                else room.institution_id[0] = '\0';
            }
            if (!room.campus_id[0] || !room.institution_id[0] || !room.name[0] || room.capacity < 1 ||
                create_platform_id("room", room.room_id, sizeof(room.room_id)) != 0) {
                send_http_response(client_fd, 400, "application/json", "{\"error\":\"Valid scoped campus, institution, name and positive capacity are required\"}");
            } else if (platform_create_room(&room) == 0) {
                char response[192]; snprintf(response, sizeof(response), "{\"status\":\"created\",\"room_id\":\"%s\"}", room.room_id);
                send_http_response(client_fd, 201, "application/json", response);
            } else send_http_response(client_fd, 400, "application/json", "{\"error\":\"Room creation failed\"}");
        }
        OPENSSL_cleanse(&session, sizeof(session));
    }
    else if (strcmp(route_path, "/api/v1/admin/roles") == 0 && strcmp(method, "GET") == 0) {
        const char *token = bearer_token(auth_header); auth_session_t session; memset(&session, 0, sizeof(session));
        if (!token || admin_auth_store_authorize(token, AUTH_PERM_USER_MANAGEMENT, &session) != 0) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"User management permission required\"}");
        } else {
            static const user_role_t roles[] = { ROLE_PLATFORM_OWNER, ROLE_INSTITUTION_ADMIN, ROLE_EXAM_MANAGER,
                ROLE_SECURITY_ADMIN, ROLE_INVIGILATOR, ROLE_TECH_OPERATOR, ROLE_INCIDENT_INVESTIGATOR,
                ROLE_READONLY_AUDITOR, ROLE_SUPPORT_ENGINEER };
            static const uint32_t permissions[] = { AUTH_PERM_READ, AUTH_PERM_EXAM_READ, AUTH_PERM_EXAM_MUTATION,
                AUTH_PERM_FLEET_MUTATION, AUTH_PERM_SECURITY_ADMIN, AUTH_PERM_USER_MANAGEMENT,
                AUTH_PERM_INSTITUTION_ADMIN, AUTH_PERM_INCIDENT_READ, AUTH_PERM_MFA_ADMIN,
                AUTH_PERM_LOCATION_ADMIN, AUTH_PERM_INCIDENT_MUTATION };
            static const char *permission_names[] = { "read", "exam_read", "exam_mutation", "fleet_mutation",
                "security_admin", "user_management", "institution_admin", "incident_read", "mfa_admin",
                "location_admin", "incident_mutation" };
            char response[8192]; size_t used = (size_t)snprintf(response, sizeof(response), "{\"roles\":[");
            for (size_t i = 0; i < sizeof(roles)/sizeof(roles[0]); ++i) {
                int n = snprintf(response + used, sizeof(response) - used, "%s{\"role\":\"%s\",\"permissions\":[",
                    i ? "," : "", admin_role_to_string(roles[i]));
                if (n < 0 || (size_t)n >= sizeof(response) - used) { used = sizeof(response); break; } used += (size_t)n;
                int first = 1;
                for (size_t j = 0; j < sizeof(permissions)/sizeof(permissions[0]); ++j) if (admin_role_has_permission(roles[i], permissions[j])) {
                    n = snprintf(response + used, sizeof(response) - used, "%s\"%s\"", first ? "" : ",", permission_names[j]);
                    if (n < 0 || (size_t)n >= sizeof(response) - used) { used = sizeof(response); break; } used += (size_t)n; first = 0;
                }
                if (used >= sizeof(response)) break;
                n = snprintf(response + used, sizeof(response) - used, "]}");
                if (n < 0 || (size_t)n >= sizeof(response) - used) { used = sizeof(response); break; } used += (size_t)n;
            }
            if (used < sizeof(response) - 2) { snprintf(response + used, sizeof(response) - used, "]}"); send_http_response(client_fd, 200, "application/json", response); }
            else send_http_response(client_fd, 500, "application/json", "{\"error\":\"Role matrix response overflow\"}");
        }
        OPENSSL_cleanse(&session, sizeof(session));
    }
    else if (route_path_matches(route_path, "/api/v1/admin/roster") && strcmp(method, "GET") == 0) {
        const char *token = bearer_token(auth_header); auth_session_t session; memset(&session, 0, sizeof(session));
        enterprise_exam_t exam; memset(&exam, 0, sizeof(exam));
        if (!token || admin_auth_store_authorize(token, AUTH_PERM_EXAM_READ, &session) != 0) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"Exam read permission required\"}");
        } else {
            char exam_id[128] = {0}; parse_query_id(path, "exam_id", exam_id, sizeof(exam_id));
            if (!exam_id[0]) {
                /* No exam_id: fall through to candidate_controller which returns all candidates */
                OPENSSL_cleanse(&session, sizeof(session)); OPENSSL_cleanse(&exam, sizeof(exam));
                goto roster_fallthrough;
            }
            else if (platform_get_exam_by_id(exam_id, &exam) != 0 ||
                     (session.role != ROLE_PLATFORM_OWNER && strcmp(session.institution_id, exam.institution_id) != 0))
                send_http_response(client_fd, 403, "application/json", "{\"error\":\"Exam scope denied\"}");
            else {
                char *roster_response = malloc(131072);
                if (!roster_response) {
                    send_http_response(client_fd, 503, "application/json", "{\"error\":\"Out of memory\"}");
                } else {
                    char audit_details[192]; ledger_block_t audit_block;
                    snprintf(audit_details, sizeof(audit_details), "actor=%s resource=exam_roster", session.user_id);
                    if (ledger_append_event("ADMIN_CANDIDATE_ROSTER_READ", exam_id, audit_details, &audit_block) != 0)
                        send_http_response(client_fd, 503, "application/json", "{\"error\":\"Roster access audit unavailable\"}");
                    else if (platform_get_roster_json(exam_id, roster_response, 131072) == 0)
                        send_http_response(client_fd, 200, "application/json", roster_response);
                    else send_http_response(client_fd, 503, "application/json", "{\"error\":\"Roster service unavailable\"}");
                    free(roster_response);
                }
            }
        }
        OPENSSL_cleanse(&session, sizeof(session)); OPENSSL_cleanse(&exam, sizeof(exam));
    }
    /* Dashboard route for /admin and its subpaths (requires authentication). */
    else if ((strcmp(route_path, "/admin") == 0 || strncmp(route_path, "/admin/", 7) == 0) && strcmp(method, "GET") == 0) {
        char cookie_token[256] = {0};
        char cookie_auth[sizeof(cookie_token) + sizeof("Bearer ")];
        int cookie_status = extract_admin_session_cookie(buffer, cookie_token, sizeof(cookie_token));
        const char *page_auth = auth_header;
        if (cookie_status == 0 && cookie_token[0]) {
            snprintf(cookie_auth, sizeof(cookie_auth), "Bearer %s", cookie_token);
            if (!page_auth[0]) page_auth = cookie_auth;
        }
        if (cookie_status != 0 || !admin_route_authorized(page_auth, AUTH_PERM_READ)) {
            send_http_response(client_fd, 200, "text/html; charset=utf-8", admin_login_html());
        } else {
            exam_config_t dashboard_config = {0};
            int config_loaded = config_load(&dashboard_config) == 0;
            send_http_response(client_fd, 200, "text/html; charset=utf-8",
                admin_dashboard_html(config_loaded ? dashboard_config.exam_url : "",
                                     config_loaded ? dashboard_config.exam_name : "",
                                     config_loaded ? dashboard_config.allowed_origins : "",
                                     config_loaded ? dashboard_config.exam_duration_minutes : 0));
        }
        OPENSSL_cleanse(cookie_token, sizeof(cookie_token));
        OPENSSL_cleanse(cookie_auth, sizeof(cookie_auth));
    }
    /* Route: POST /api/v1/admin/config -> Update Exam URL / Config */
    else if (strcmp(route_path, "/api/v1/admin/config") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_EXAM_MUTATION)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized: Admin credentials required\"}");
        } else {
            exam_config_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            parse_json_string(req_body, "exam_url", cfg.exam_url, sizeof(cfg.exam_url));
            parse_json_string(req_body, "exam_name", cfg.exam_name, sizeof(cfg.exam_name));
            parse_json_string(req_body, "exam_id", cfg.exam_id, sizeof(cfg.exam_id));
            parse_json_string(req_body, "allowed_origins", cfg.allowed_origins,
                              sizeof(cfg.allowed_origins));
            cfg.exam_duration_minutes = parse_json_int(req_body, "exam_duration_minutes", 0);

            if (!config_validate_exam_url(cfg.exam_url) ||
                !config_validate_allowed_origins(cfg.allowed_origins)) {
                send_http_response(client_fd, 400, "application/json", "{\"error\":\"Exam URL must be HTTPS and its host must be in EXAMOS_ALLOWED_EXAM_HOSTS; loopback HTTP requires explicit development opt-in\"}");
            } else if (!cfg.exam_name[0] || cfg.exam_duration_minutes < 1) {
                send_http_response(client_fd, 400, "application/json", "{\"error\":\"exam_name and a positive exam_duration_minutes are required\"}");
            } else if (cfg.exam_id[0] && !config_validate_exam_id(cfg.exam_id)) {
                send_http_response(client_fd, 400, "application/json", "{\"error\":\"exam_id must be 1-63 characters of [A-Za-z0-9._-]\"}");
            } else if (config_save(&cfg) == 0) {
                pthread_mutex_lock(&g_kiosk_sync_lock);
                g_kiosk_command_seq++;
                snprintf(g_kiosk_latest_command, sizeof(g_kiosk_latest_command), "DISPATCH");
                snprintf(g_kiosk_latest_payload, sizeof(g_kiosk_latest_payload), "%s", cfg.exam_url);
                pthread_mutex_unlock(&g_kiosk_sync_lock);

                ledger_block_t blk;
                char details[512];
                snprintf(details, sizeof(details), "Exam configuration updated for URL host: %s",
                         cfg.exam_url);
                ledger_append_event("ADMIN_CONFIG_UPDATED", "ADMIN_CONSOLE", details, &blk);
                send_http_response(client_fd, 200, "application/json", "{\"status\":\"SAVED\",\"exam_url\":\"saved\"}");
            } else {
                send_http_response(client_fd, 500, "application/json", "{\"error\":\"Failed to save configuration to disk\"}");
            }
        }
    }
    /* Route: POST /api/v1/attestation/nonce -> Issue challenge */
    else if (strcmp(route_path, "/api/v1/attestation/nonce") == 0 && strcmp(method, "POST") == 0) {
        if (!bearer_secret_authorized(auth_header, "EXAMOS_AGENT_API_TOKEN")) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid agent token required\"}");
            goto client_done;
        }
        char dev_id[64] = {0}, sess_id[64] = {0}, rel_id[64] = {0};
        char purpose[32] = {0};
        parse_json_string(req_body, "device_id", dev_id, sizeof(dev_id));
        parse_json_string(req_body, "session_id", sess_id, sizeof(sess_id));
        parse_json_string(req_body, "release_id", rel_id, sizeof(rel_id));
        parse_json_string(req_body, "purpose", purpose, sizeof(purpose));
        if (!purpose[0]) snprintf(purpose, sizeof(purpose), "%s", "re_attestation");

        if (!dev_id[0] || !sess_id[0] || !rel_id[0]) {
            send_http_response(client_fd, 400, "application/json",
                               "{\"error\":\"device_id, session_id, and release_id required\"}");
        } else {
            char nonce[128] = {0}, attest_id[64] = {0}, error_code[64] = {0};
            int rc = attestation_create_challenge(
                dev_id, sess_id, rel_id,
                "", purpose, "system",
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
                int status = strcmp(ec, "P3_CHALLENGE_STORE_UNAVAILABLE") == 0 ||
                             strcmp(ec, "P3_REVOCATION_STORE_UNAVAILABLE") == 0
                    ? 503 : 403;
                OPENSSL_cleanse(nonce, sizeof(nonce));
                OPENSSL_cleanse(attest_id, sizeof(attest_id));
                send_http_response(client_fd, status, "application/json", resp);
            }
        }
    }
    /* Route: POST /api/v1/attestation/verify -> Verify TPM Evidence */
    else if (strcmp(route_path, "/api/v1/attestation/verify") == 0 && strcmp(method, "POST") == 0) {
        if (!bearer_secret_authorized(auth_header, "EXAMOS_AGENT_API_TOKEN")) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid agent token required\"}");
            goto client_done;
        }
        char reason[64] = {0}, exam_key[65] = {0};
        if (attestation_verify_evidence(req_body, NULL, reason, exam_key) == 0) {
            int key_release_required = exam_key[0] != '\0';
            /* The exam key is deliberately not echoed here. It is bound to
               the trusted session and delivered only through the audited
               key-release path, which enforces session and device binding. */
            OPENSSL_cleanse(exam_key, sizeof(exam_key));
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"TRUSTED\",\"verified\":true,\"reason\":\"%s\","
                     "\"key_release_required\":%s}",
                     reason, key_release_required ? "true" : "false");
            send_http_response(client_fd, 200, "application/json", resp);
        } else {
            OPENSSL_cleanse(exam_key, sizeof(exam_key));
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
    else if (strcmp(route_path, "/api/v1/attestation/re-attest") == 0 && strcmp(method, "POST") == 0) {
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
    else if (strncmp(route_path, "/api/v1/attestation/status", 26) == 0 &&
             (path[26] == '\0' || path[26] == '?') && strcmp(method, "GET") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_READ)) {
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
    else if (strcmp(route_path, "/api/v1/admin/revoke/release") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
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
    else if (strcmp(route_path, "/api/v1/admin/revoke/device") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
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
    /* Route: POST /api/v1/admin/reload -> Restart / Refresh Kiosk */
    else if (strcmp(route_path, "/api/v1/admin/reload") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized\"}");
        } else {
            pthread_mutex_lock(&g_kiosk_sync_lock);
            g_kiosk_command_seq++;
            snprintf(g_kiosk_latest_command, sizeof(g_kiosk_latest_command), "RELOAD");
            snprintf(g_kiosk_latest_payload, sizeof(g_kiosk_latest_payload), "Policy and session refresh requested");
            pthread_mutex_unlock(&g_kiosk_sync_lock);

            const char *cat_path = getenv("EXAMOS_BROWSER_POLICY_CATALOG");
            if (cat_path && cat_path[0]) policy_catalog_load(cat_path);
            attestation_config_load_all(NULL);

            /* Try systemctl if running on systemd appliance, but succeed regardless */
            char *const argv[] = {"systemctl", "restart", "examos-kiosk.service", NULL};
            pid_t child = -1;
            posix_spawnp(&child, "systemctl", NULL, NULL, argv, environ);

            ledger_block_t blk;
            ledger_append_event("ADMIN_RELOAD_SUCCESS", "ADMIN_CONSOLE", "Policies and kiosk runtime reloaded", &blk);
            send_http_response(client_fd, 200, "application/json", "{\"status\":\"RELOADED\",\"command_seq\":1}");
        }
    }
    /* Route: POST /api/v1/admin/lock -> Emergency lock */
    else if (strcmp(route_path, "/api/v1/admin/lock") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized\"}");
        } else {
            pthread_mutex_lock(&g_kiosk_sync_lock);
            g_kiosk_emergency_lock = 1;
            g_kiosk_command_seq++;
            snprintf(g_kiosk_latest_command, sizeof(g_kiosk_latest_command), "LOCK");
            snprintf(g_kiosk_latest_payload, sizeof(g_kiosk_latest_payload), "Emergency lockdown triggered by administrator");
            pthread_mutex_unlock(&g_kiosk_sync_lock);

            ledger_block_t blk;
            ledger_append_event("EMERGENCY_LOCKDOWN_TRIGGERED", "ADMIN_CONSOLE", "Fleet emergency lockdown active", &blk);
            send_http_response(client_fd, 200, "application/json", "{\"status\":\"LOCKED\",\"emergency_lock\":true}");
        }
    }
    /* Route: POST /api/v1/admin/unlock -> Release Emergency lock */
    else if (strcmp(route_path, "/api/v1/admin/unlock") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized\"}");
        } else {
            pthread_mutex_lock(&g_kiosk_sync_lock);
            g_kiosk_emergency_lock = 0;
            g_kiosk_command_seq++;
            snprintf(g_kiosk_latest_command, sizeof(g_kiosk_latest_command), "UNLOCK");
            snprintf(g_kiosk_latest_payload, sizeof(g_kiosk_latest_payload), "Emergency lockdown released by administrator");
            pthread_mutex_unlock(&g_kiosk_sync_lock);

            ledger_block_t blk;
            ledger_append_event("EMERGENCY_LOCKDOWN_RELEASED", "ADMIN_CONSOLE", "Fleet emergency lockdown released", &blk);
            send_http_response(client_fd, 200, "application/json", "{\"status\":\"UNLOCKED\",\"emergency_lock\":false}");
        }
    }
    /* Route: GET /api/v1/kiosk/check-update -> Real-time dynamic sync for running OS kiosk */
    else if (strcmp(route_path, "/api/v1/kiosk/check-update") == 0 && strcmp(method, "GET") == 0) {
        exam_config_t cfg;
        config_load(&cfg);
        char safe_url[3072] = {0}, safe_name[768] = {0}, safe_ann[512] = {0};
        json_escape(cfg.exam_url[0] ? cfg.exam_url : "NOT_CONFIGURED", safe_url, sizeof(safe_url));
        json_escape(cfg.exam_name[0] ? cfg.exam_name : "ExamOS Standby Terminal", safe_name, sizeof(safe_name));

        pthread_mutex_lock(&g_kiosk_sync_lock);
        int lock = g_kiosk_emergency_lock;
        long seq = g_kiosk_command_seq;
        char cmd[64], payload[512];
        snprintf(cmd, sizeof(cmd), "%s", g_kiosk_latest_command);
        snprintf(payload, sizeof(payload), "%s", g_kiosk_latest_payload);
        pthread_mutex_unlock(&g_kiosk_sync_lock);

        const char *ann_json = center_master_get_announcements_json();
        if (ann_json) {
            parse_json_string(ann_json, "announcement", safe_ann, sizeof(safe_ann));
        }

        char dep_inst[64] = {0}, dep_rel[64] = {0}, dep_chan[32] = {0};
        char dep_hw[64] = {0}, dep_sec[64] = {0}, dep_hash[128] = {0};
        PGconn *c_db = db_acquire();
        if (c_db) {
            PGresult *dr = PQexec(c_db, "SELECT institution_id, release_id, channel, hardware_profile, security_profile, COALESCE(policy_hash,'') "
                                        "FROM institution_os_deployments WHERE status = 'ACTIVE' ORDER BY updated_at DESC LIMIT 1");
            if (dr && PQresultStatus(dr) == PGRES_TUPLES_OK && PQntuples(dr) > 0) {
                snprintf(dep_inst, sizeof(dep_inst), "%s", PQgetvalue(dr, 0, 0));
                snprintf(dep_rel, sizeof(dep_rel), "%s", PQgetvalue(dr, 0, 1));
                snprintf(dep_chan, sizeof(dep_chan), "%s", PQgetvalue(dr, 0, 2));
                snprintf(dep_hw, sizeof(dep_hw), "%s", PQgetvalue(dr, 0, 3));
                snprintf(dep_sec, sizeof(dep_sec), "%s", PQgetvalue(dr, 0, 4));
                snprintf(dep_hash, sizeof(dep_hash), "%s", PQgetvalue(dr, 0, 5));
            }
            if (dr) PQclear(dr);
            db_release(c_db, 0);
        }

        char resp[4096];
        snprintf(resp, sizeof(resp),
                 "{"
                 "\"status\":\"ok\","
                 "\"exam_configured\":%s,"
                 "\"exam_url\":\"%s\","
                 "\"exam_name\":\"%s\","
                 "\"exam_id\":\"%s\","
                 "\"duration_minutes\":%d,"
                 "\"emergency_lock\":%s,"
                 "\"command\":\"%s\","
                 "\"command_seq\":%ld,"
                 "\"announcement\":\"%s\","
                 "\"server_time\":%ld,"
                 "\"attestation_status\":\"%s\","
                 "\"tpm_mode\":\"%s\","
                 "\"institution_id\":\"%s\","
                 "\"os_release\":\"%s\","
                 "\"rollout_channel\":\"%s\","
                 "\"hardware_profile\":\"%s\","
                 "\"security_profile\":\"%s\","
                 "\"policy_hash\":\"%s\""
                 "}",
                 cfg.configured ? "true" : "false",
                 safe_url, safe_name,
                 cfg.exam_id[0] ? cfg.exam_id : "",
                 cfg.exam_duration_minutes,
                 lock ? "true" : "false",
                 cmd, seq, safe_ann,
                 (long)time(NULL),
                 "UNKNOWN",
                 "UNKNOWN",
                 dep_inst, dep_rel, dep_chan, dep_hw, dep_sec, dep_hash);
        send_http_response(client_fd, 200, "application/json", resp);
    }
    /* Route: POST /api/v1/kiosk/heartbeat -> Kiosk terminal presence & telemetry */
    else if (strcmp(route_path, "/api/v1/kiosk/heartbeat") == 0 && strcmp(method, "POST") == 0) {
        char term_id[64] = {0}, term_ip[64] = {0}, active_url[512] = {0}, term_status[32] = "UNKNOWN";
        int focus = 0;
        char p_id[64] = {0}, p_ip[64] = {0}, p_url[512] = {0}, p_status[32] = {0};
        parse_json_string(req_body, "terminal_id", p_id, sizeof(p_id));
        if (p_id[0]) snprintf(term_id, sizeof(term_id), "%s", p_id);
        if (!term_id[0]) {
            send_http_response(client_fd, 400, "application/json",
                               "{\"error\":\"terminal_id is required\"}");
            goto client_done;
        }

        parse_json_string(req_body, "ip", p_ip, sizeof(p_ip));
        if (p_ip[0]) snprintf(term_ip, sizeof(term_ip), "%s", p_ip);

        parse_json_string(req_body, "active_url", p_url, sizeof(p_url));
        if (p_url[0]) snprintf(active_url, sizeof(active_url), "%s", p_url);

        parse_json_string(req_body, "status", p_status, sizeof(p_status));
        if (p_status[0]) snprintf(term_status, sizeof(term_status), "%s", p_status);

        focus = parse_json_int(req_body, "screen_focus", 0);

        kiosk_register_heartbeat(term_id, term_ip, active_url, term_status, focus);

        char resp[256];
        snprintf(resp, sizeof(resp), "{\"status\":\"ACK\",\"terminal_id\":\"%s\",\"server_time\":%ld}",
                 term_id, (long)time(NULL));
        send_http_response(client_fd, 200, "application/json", resp);
    }
    /* Route: GET /api/v1/kiosk/terminals -> Live tracked kiosk fleet */
    else if (strcmp(route_path, "/api/v1/kiosk/terminals") == 0 && strcmp(method, "GET") == 0) {
        pthread_mutex_lock(&g_kiosk_sync_lock);
        char resp[16384];
        size_t off = snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"terminals\":[");
        for (int i = 0; i < g_tracked_kiosk_count; i++) {
            off += snprintf(resp + off, sizeof(resp) - off,
                "%s{\"terminal_id\":\"%s\",\"ip\":\"%s\",\"active_url\":\"%s\",\"status\":\"%s\",\"screen_focus\":%d,\"last_heartbeat\":%ld}",
                i > 0 ? "," : "",
                g_tracked_kiosks[i].terminal_id,
                g_tracked_kiosks[i].ip,
                g_tracked_kiosks[i].active_url,
                g_tracked_kiosks[i].status,
                g_tracked_kiosks[i].screen_focus,
                (long)g_tracked_kiosks[i].last_heartbeat);
        }
        snprintf(resp + off, sizeof(resp) - off, "],\"count\":%d}", g_tracked_kiosk_count);
        pthread_mutex_unlock(&g_kiosk_sync_lock);
        send_http_response(client_fd, 200, "application/json", resp);
    }
    /* Candidate workbench is available only on the managed ExamOS kiosk. */
    else if ((strcmp(route_path, "/exam") == 0 || strcmp(route_path, "/workbench") == 0) && strcmp(method, "GET") == 0) {
        if (!is_examos_kiosk_request(client_fd, buffer, origin)) {
            send_http_response(client_fd, 403, "text/html; charset=utf-8", candidate_kiosk_lockout_html());
            goto client_done;
        }
        send_http_response_ex(client_fd, 200, "text/html; charset=utf-8",
                              candidate_workbench_html(),
                              "Cache-Control: no-store\r\n");
        goto client_done;
    }
    /* Route: GET /api/v1/exam/paper -> Question battery */
    else if (strcmp(route_path, "/api/v1/exam/paper") == 0 && strcmp(method, "GET") == 0) {
        if (!is_examos_kiosk_request(client_fd, buffer, origin)) {
            send_http_response_ex(client_fd, 403, "application/json",
                "{\"status\":\"FAIL\",\"error\":\"ACCESS_DENIED: Candidate examination is restricted to ExamOS kiosk.\"}", extra);
            goto client_done;
        }
        session_handle(client_fd, method, route_path, req_body,
                       auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    /* Route: POST /api/v1/exam/save_answer -> Real-time answer auto-save */
    else if (strcmp(route_path, "/api/v1/exam/save_answer") == 0 && strcmp(method, "POST") == 0) {
        if (!is_examos_kiosk_request(client_fd, buffer, origin)) {
            send_http_response_ex(client_fd, 403, "application/json",
                "{\"status\":\"FAIL\",\"error\":\"ACCESS_DENIED: Candidate examination is restricted to ExamOS kiosk.\"}", extra);
            goto client_done;
        }
        session_handle(client_fd, method, route_path, req_body,
                       auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    /* Route: POST /api/v1/exam/submit -> Final exam submission with cryptographic SHA-256 HMAC digest */
    else if (strcmp(route_path, "/api/v1/exam/submit") == 0 && strcmp(method, "POST") == 0) {
        if (!is_examos_kiosk_request(client_fd, buffer, origin)) {
            send_http_response_ex(client_fd, 403, "application/json",
                "{\"status\":\"FAIL\",\"error\":\"ACCESS_DENIED: Candidate examination is restricted to ExamOS kiosk.\"}", extra);
            goto client_done;
        }
        session_handle(client_fd, method, route_path, req_body,
                       auth_header, origin, extra, sizeof(extra));
        goto client_done;
    }
    /* Route: GET /api/v1/exam/announcements -> Real-time broadcast alerts */
    else if (strcmp(route_path, "/api/v1/exam/announcements") == 0 && strcmp(method, "GET") == 0) {
        const char *ann_json = center_master_get_announcements_json();
        send_http_response(client_fd, 200, "application/json", ann_json ? ann_json : "{\"announcements\":[]}");
    }
    /* Route: GET /api/v1/exam/terminals -> Center Master invigilator monitor */
    else if (strcmp(route_path, "/api/v1/exam/terminals") == 0 && strcmp(method, "GET") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Admin credentials required\"}");
            goto client_done;
        }
        const char *terms = center_master_get_terminals_json();
        send_http_response(client_fd, 200, "application/json", terms ? terms : "[]");
    }
    /* Route: POST /api/v1/exam/command -> Center Master invigilator control */
    else if (strcmp(route_path, "/api/v1/exam/command") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_EXAM_MUTATION)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Admin write permissions required\"}");
            goto client_done;
        }
        char command[64] = {0}, target_cid[64] = {0}, payload[256] = {0};
        parse_json_string(req_body, "command", command, sizeof(command));
        parse_json_string(req_body, "target_candidate_id", target_cid, sizeof(target_cid));
        parse_json_string(req_body, "payload", payload, sizeof(payload));

        /* Broadcast command dynamically to all active kiosk OS terminals */
        pthread_mutex_lock(&g_kiosk_sync_lock);
        g_kiosk_command_seq++;
        snprintf(g_kiosk_latest_command, sizeof(g_kiosk_latest_command), "%s", command);
        snprintf(g_kiosk_latest_payload, sizeof(g_kiosk_latest_payload), "%s", payload);
        if (strcmp(command, "LOCK") == 0) {
            g_kiosk_emergency_lock = 1;
        } else if (strcmp(command, "UNLOCK") == 0) {
            g_kiosk_emergency_lock = 0;
        }
        pthread_mutex_unlock(&g_kiosk_sync_lock);

        if (center_master_execute_command(command, target_cid[0] ? target_cid : NULL, payload) == 0) {
            send_http_response(client_fd, 200, "application/json", "{\"status\":\"COMMAND_EXECUTED\"}");
        } else {
            send_http_response(client_fd, 400, "application/json", "{\"status\":\"FAIL\",\"error\":\"Command execution failed\"}");
        }
    }
    /* Route: POST /api/v1/heartbeat -> Telemetry */
    else if (strcmp(route_path, "/api/v1/heartbeat") == 0 && strcmp(method, "POST") == 0) {
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
    else if (strcmp(route_path, "/api/v1/ledger") == 0 && strcmp(method, "GET") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_READ)) {
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
    else if (strcmp(route_path, "/api/v1/status") == 0 && strcmp(method, "GET") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_READ)) {
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
                 "{\"exam_url_configured\":%s,\"exam_url\":\"%s\",\"exam_name\":\"%s\","
                 "\"attestation_status\":\"%s\",\"tpm_mode\":\"%s\"}",
                 cfg.configured ? "true" : "false", safe_url, safe_name,
                 g_production_mode ? "PRODUCTION" : "DEVELOPMENT",
                 g_production_mode ? "production" : "development");
        send_http_response(client_fd, 200, "application/json", resp);
    }
    /* Route: POST /api/v1/exam/key-release -> Release session decryption key */
    else if (strcmp(route_path, "/api/v1/exam/key-release") == 0 && strcmp(method, "POST") == 0) {
        char authenticated_candidate[64] = {0};
        if (!candidate_authorized(auth_header, authenticated_candidate, sizeof(authenticated_candidate))) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid candidate bearer token required\"}");
            goto client_done;
        }
        char session_id[64] = {0}, device_id[64] = {0};
        parse_json_string(req_body, "session_id", session_id, sizeof(session_id));
        parse_json_string(req_body, "device_id", device_id, sizeof(device_id));
        if (!session_id[0] || !device_id[0]) {
            send_http_response(client_fd, 400, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"session_id and device_id are required\"}");
            goto client_done;
        }
        char envelope[8192] = {0}, error_code[64] = {0};
        if (key_release_wrap_session_key(authenticated_candidate, session_id,
                                         device_id, envelope, sizeof(envelope),
                                         error_code) != 0) {
            char response[512];
            snprintf(response, sizeof(response),
                     "{\"status\":\"REJECTED\",\"error_code\":\"%s\"}",
                     error_code[0] ? error_code : "P3_DEVICE_BOUND_TRANSPORT_UNAVAILABLE");
            send_http_response(client_fd, 409, "application/json", response);
            goto client_done;
        }
        send_http_response(client_fd, 200, "application/json", envelope);
    }
    /* Route: GET /api/v1/exam/key-release/eligibility -> Non-destructive eligibility check */
    else if (strcmp(route_path, "/api/v1/exam/key-release/eligibility") == 0 && strcmp(method, "GET") == 0) {
        char authenticated_candidate[64] = {0};
        if (!candidate_authorized(auth_header, authenticated_candidate, sizeof(authenticated_candidate))) {
            send_http_response(client_fd, 401, "application/json",
                               "{\"error\":\"Valid candidate bearer token required\"}");
            goto client_done;
        }
        send_http_response(client_fd, 503, "application/json",
            "{\"status\":\"UNAVAILABLE\",\"error\":\"Eligibility cannot be confirmed until the authenticated candidate is durably bound to the attested exam session.\"}");
    }
    /* Route: POST /api/v1/consent -> Record candidate consent before camera/mic access */
    else if (strcmp(route_path, "/api/v1/consent") == 0 && strcmp(method, "POST") == 0) {
        if (!is_examos_kiosk_request(client_fd, buffer, origin)) {
            send_http_response_ex(client_fd, 403, "application/json",
                "{\"status\":\"FAIL\",\"error\":\"ACCESS_DENIED: Candidate examination is restricted to ExamOS kiosk.\"}", extra);
            goto client_done;
        }
        char sess_id[64] = {0}, cand_id[64] = {0};
        parse_json_string(req_body, "session_id",   sess_id, sizeof(sess_id));
        parse_json_string(req_body, "candidate_id", cand_id, sizeof(cand_id));

        char authenticated_candidate[64] = {0};
        if (!candidate_authorized(auth_header, authenticated_candidate, sizeof(authenticated_candidate))) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid candidate bearer token required\"}");
        } else if (!sess_id[0] || !cand_id[0] || strcmp(cand_id, authenticated_candidate) != 0) {
            send_http_response(client_fd, 400, "application/json", "{\"error\":\"session_id and authenticated candidate identity are required\"}");
        } else {
            ledger_block_t blk;
            char details[192];
            snprintf(details, sizeof(details),
                "candidate_id=%s session_id=%s consent=GRANTED", cand_id, sess_id);
            if (ledger_append_event("CANDIDATE_CONSENT_GRANTED", cand_id, details, &blk) == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                    "{\"status\":\"CONSENT_RECORDED\",\"session_id\":\"%s\","
                    "\"block_index\":%ld}", sess_id, blk.block_index);
                send_http_response(client_fd, 200, "application/json", resp);
            } else {
                send_http_response(client_fd, 503, "application/json",
                    "{\"error\":\"Consent could not be durably recorded to the tamper-evident ledger\"}");
            }
        }
    }
    /* Route: POST /api/v1/proctoring/events -> Ingest normalized detection into hash chain */
    else if (strcmp(route_path, "/api/v1/proctoring/events") == 0 && strcmp(method, "POST") == 0) {
        if (!bearer_secret_authorized(auth_header, "EXAMOS_PROCTOR_API_TOKEN")) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid proctor service token required\"}");
            goto client_done;
        }
        char sess_id[EVENT_SESSION_ID_LEN] = {0}, source_type[64] = {0}, event_type[64] = {0};
        char model_name[64] = {0}, model_version[64] = {0};
        parse_json_string(req_body, "session_id",    sess_id,      sizeof(sess_id));
        parse_json_string(req_body, "source_type",   source_type,  sizeof(source_type));
        parse_json_string(req_body, "event_type",    event_type,   sizeof(event_type));
        parse_json_string(req_body, "model_name",    model_name,   sizeof(model_name));
        parse_json_string(req_body, "model_version", model_version,sizeof(model_version));
        /* Extract raw payload object */
        const char *payload_start = strstr(req_body, "\"payload\":");
        char payload_json[4096] = {0};
        if (payload_start) {
            payload_start += 10;
            while (*payload_start == ' ' || *payload_start == '\t') payload_start++;
            if (*payload_start == '{' || *payload_start == '[') {
                int depth = 0; size_t pi = 0;
                for (const char *pc = payload_start; *pc && pi < sizeof(payload_json) - 1; pc++) {
                    if (*pc == '{' || *pc == '[') depth++;
                    else if (*pc == '}' || *pc == ']') depth--;
                    payload_json[pi++] = *pc;
                    if (depth == 0) break;
                }
                payload_json[pi] = '\0';
            }
        }
        if (!payload_json[0]) snprintf(payload_json, sizeof(payload_json), "{}");
        if (!sess_id[0] || !source_type[0] || !event_type[0]) {
            send_http_response(client_fd, 400, "application/json",
                "{\"error\":\"session_id, source_type and event_type are required\"}");
            goto client_done;
        }
        if (!model_name[0] || !model_version[0]) {
            /* Provenance must be stated by the producer. Inventing a model
               name here would attribute an event to a detector that may
               never have run. */
            send_http_response(client_fd, 400, "application/json",
                "{\"error\":\"model_name and model_version are required and must identify the detector that produced this event\"}");
            goto client_done;
        }
        if (strlen(model_name) >= sizeof(model_name) ||
            strlen(model_version) >= sizeof(model_version)) {
            send_http_response(client_fd, 400, "application/json",
                "{\"error\":\"model_name and model_version are too long\"}");
            goto client_done;
        }
        proctoring_event_t ev;
        if (event_chain_append(sess_id, source_type, event_type, payload_json,
                               model_name, model_version, &ev) == 0) {
            risk_assessment_t assessment;
            risk_engine_assess_session(sess_id, event_type, &assessment);
            char resp[320];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"RECORDED\",\"sequence\":%lu,\"event_hash\":\"%s\","
                "\"risk_score\":%.2f,\"risk_level\":\"%s\",\"terminate_recommended\":%s}",
                (unsigned long)ev.sequence, ev.event_hash,
                assessment.composite_risk_score,
                assessment.risk_level ? assessment.risk_level : "UNKNOWN",
                assessment.should_terminate_exam ? "true" : "false");
            send_http_response(client_fd, 202, "application/json", resp);
        } else {
            send_http_response(client_fd, 503, "application/json",
                "{\"error\":\"Event chain append failed; storage may be unavailable\"}");
        }
    }
    /* Route: GET /api/v1/proctoring/events */
    else if (strncmp(route_path, "/api/v1/proctoring/events", 25) == 0 &&
             (path[25] == '\0' || path[25] == '?') && strcmp(method, "GET") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Admin credentials required\"}");
        } else {
            char export_buf[65536];
            char sess_id[EVENT_SESSION_ID_LEN] = {0};
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
    else if (strcmp(route_path, "/api/v1/proctoring/checkpoint") == 0 && strcmp(method, "POST") == 0) {
        /* The proctoring service owns the evidence stream and may checkpoint
           it directly; a human administrator may also request a checkpoint. */
        if (!bearer_secret_authorized(auth_header, "EXAMOS_PROCTOR_API_TOKEN") &&
            !admin_route_authorized(auth_header, AUTH_PERM_SECURITY_ADMIN)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Proctor service or admin credentials required\"}");
            goto client_done;
        }
        char sess_id[EVENT_SESSION_ID_LEN] = {0};
        parse_json_string(req_body, "session_id", sess_id, sizeof(sess_id));
        event_checkpoint_t cp;
        if (!sess_id[0]) {
            send_http_response(client_fd, 400, "application/json", "{\"error\":\"session_id required\"}");
        } else if (event_chain_sign_checkpoint(sess_id, &cp) == 0) {
            char resp[1024];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"CHECKPOINT_SIGNED\",\"session_id\":\"%s\","
                     "\"sequence\":%lu,\"latest_hash\":\"%s\",\"key_id\":\"%s\","
                     "\"server_timestamp\":\"%s\",\"signature\":\"%s\"}",
                     cp.session_id, (unsigned long)cp.checkpoint_sequence,
                     cp.latest_event_hash, cp.signing_key_id,
                     cp.server_timestamp, cp.signature_hex);
            send_http_response(client_fd, 200, "application/json", resp);
        } else {
            send_http_response(client_fd, 400, "application/json", "{\"error\":\"No events found to checkpoint\"}");
        }
    }
    /* Route: POST /api/v1/proctoring/verify -> Verify hash chain */
    else if (strcmp(route_path, "/api/v1/proctoring/verify") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_route_authorized(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Admin credentials required\"}");
            goto client_done;
        }
        char sess_id[EVENT_SESSION_ID_LEN] = {0};
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
    else if (strcmp(route_path, "/api/v1/second-camera/request") == 0 && strcmp(method, "POST") == 0) {
        char authenticated_candidate[64] = {0};
        if (!candidate_authorized(auth_header, authenticated_candidate, sizeof(authenticated_candidate))) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Valid candidate bearer token required\"}");
            goto client_done;
        }
        /* The pairing token is bound to the authenticated candidate session
           and is single-use with a short expiry. */
        char pairing_token[QR_TOKEN_LEN + 1] = {0};
        if (second_camera_create_pairing_token(authenticated_candidate, pairing_token,
                                               sizeof(pairing_token)) != 0) {
            send_http_response(client_fd, 503, "application/json",
                "{\"status\":\"UNAVAILABLE\",\"error\":\"Second-camera pairing could not be created\"}");
        } else {
            char resp[256];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"PAIRING_REQUESTED\",\"session_id\":\"%s\","
                     "\"pairing_token\":\"%s\",\"expires_in_seconds\":300}",
                     authenticated_candidate, pairing_token);
            OPENSSL_cleanse(pairing_token, sizeof(pairing_token));
            send_http_response(client_fd, 201, "application/json", resp);
        }
    }
    /* Route: POST /api/v1/second-camera/pair -> Validate QR pairing */
    else if (strcmp(route_path, "/api/v1/second-camera/pair") == 0 && strcmp(method, "POST") == 0) {
        char sess_id[64] = {0}, token[128] = {0};
        parse_json_string(req_body, "session_id", sess_id, sizeof(sess_id));
        parse_json_string(req_body, "token",     token,  sizeof(token));
        if (!sess_id[0] || !token[0]) {
            send_http_response(client_fd, 400, "application/json",
                "{\"error\":\"session_id and token are required\"}");
        } else if (second_camera_validate_pairing(sess_id, token) != 0) {
            send_http_response(client_fd, 403, "application/json",
                "{\"status\":\"REJECTED\",\"error\":\"Pairing token is invalid, expired, or already used\"}");
        } else {
            char resp[192];
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"PAIRED\",\"session_id\":\"%s\"}", sess_id);
            OPENSSL_cleanse(token, sizeof(token));
            send_http_response(client_fd, 200, "application/json", resp);
        }
    }
    /* Route: GET /second-camera -> Mobile phone camera capture web page */
    else if (strncmp(route_path, "/second-camera", 14) == 0 && strcmp(method, "GET") == 0) {
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
            /* The portal is served only for a session/token pair that is
               actually in the pairing flow; it is not a public page. */
            second_cam_state_t state = second_camera_get_status(sess_id);
            if (state == SECOND_CAM_STATE_UNPAIRED || state == SECOND_CAM_STATE_EXPIRED) {
                send_http_response(client_fd, 403, "application/json",
                    "{\"error\":\"No active pairing request exists for this session\"}");
            } else {
                const char *page = second_camera_portal_html(sess_id, token);
                send_http_response(client_fd, 200, "text/html; charset=utf-8",
                                   page ? page : "<!DOCTYPE html><html><body>Second camera portal unavailable</body></html>");
            }
        }
    }
    /* Route: GET /api/v1/health */
    else if (strcmp(route_path, "/api/v1/health") == 0 && strcmp(method, "GET") == 0) {
        /*
         * Readiness reflects every dependency the service needs to serve a
         * request: the authenticated evidence ledger, the durable platform
         * store, and the attestation store. Reporting READY from the ledger
         * alone would hide a platform-store outage.
         */
        int ledger_ok = ledger_verify_integrity();
        int ledger_authenticated = ledger_is_authenticated();
        int database_ok = (db_health() == 0 || platform_database_health() == 0);
        int attestation_ok = (attestation_store_health() == 0);

        const char *readiness;
        if (!g_production_mode) {
            readiness = "DEVELOPMENT";
        } else if (ledger_ok && ledger_authenticated && database_ok && attestation_ok) {
            readiness = "READY";
        } else {
            readiness = "NOT_READY";
        }

        char health_resp[512];
        snprintf(health_resp, sizeof(health_resp),
            "{\"status\":\"ok\",\"liveness\":\"LIVE\","
            "\"readiness\":\"%s\","
            "\"ledger_integrity\":\"%s\","
            "\"ledger_authenticated\":%s,"
            "\"database\":%s,"
            "\"attestation_store\":%s,"
            "\"service\":\"examos-server\","
            "\"tpm_mode\":\"%s\"}",
            readiness,
            ledger_ok ? "INTACT" : "TAMPERED",
            ledger_authenticated ? "true" : "false",
            database_ok ? "true" : "false",
            attestation_ok ? "true" : "false",
            g_production_mode ? "production" : "development");
        send_http_response_ex(client_fd, 200, "application/json", health_resp, extra);
    }
    /* ================================================================
     * Enterprise Platform API Routes
     * ================================================================ */

    /* POST /api/v1/admin/institutions -> Create institution (Platform Owner only) */
    else if (strcmp(route_path, "/api/v1/admin/institutions") == 0 && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_INSTITUTION_ADMIN, &sess) != 0
                 || sess.role != ROLE_PLATFORM_OWNER) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Platform owner required to create institutions\"}");
        } else {
            institution_t inst; memset(&inst, 0, sizeof(inst));
            parse_json_string(req_body, "name",          inst.name,          sizeof(inst.name));
            parse_json_string(req_body, "code",          inst.code,          sizeof(inst.code));
            parse_json_string(req_body, "contact_email", inst.contact_email, sizeof(inst.contact_email));
            inst.retention_days = parse_json_int(req_body, "retention_days", 0);
            inst.active = 1;
            if (create_platform_id("inst", inst.institution_id, sizeof(inst.institution_id)) != 0) {
                send_http_response(client_fd, 503, "application/json",
                                   "{\"error\":\"Secure ID generation unavailable\"}");
            } else if (!inst.name[0] || !inst.code[0] || inst.retention_days <= 0) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"name, code and retention_days are required\"}");
            } else if (platform_create_institution(&inst) == 0) {
                char resp[512];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"created\",\"institution_id\":\"%s\"}", inst.institution_id);
                send_http_response(client_fd, 200, "application/json", resp);
            } else {
                char resp[640];
                snprintf(resp, sizeof(resp), "{\"error\":\"%s\"}", platform_last_error());
                send_http_response(client_fd, 409, "application/json", resp);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    else if (strcmp(route_path, "/api/v1/admin/users") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_USER_MANAGEMENT, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"User management permission required\"}");
        } else {
            char institution_id[128] = {0};
            if (sess.role != ROLE_PLATFORM_OWNER) {
                snprintf(institution_id, sizeof(institution_id), "%s", sess.institution_id);
            } else {
                parse_query_id(path, "institution_id", institution_id, sizeof(institution_id));
            }
            char *users_buf = malloc(65536);
            if (!users_buf) {
                send_http_response(client_fd, 503, "application/json", "{\"error\":\"Out of memory\"}");
            } else {
                if (admin_auth_store_list_users_json_for_institution(users_buf, 65536, institution_id) == 0)
                    send_http_response(client_fd, 200, "application/json", users_buf);
                else
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"User service unavailable\"}");
                free(users_buf);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/users -> Create admin user */
    else if (strcmp(route_path, "/api/v1/admin/users") == 0 && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_USER_MANAGEMENT, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"User management permission required\"}");
        } else {
            user_account_t u; memset(&u, 0, sizeof(u));
            parse_json_string(req_body, "username",       u.username,           sizeof(u.username));
            parse_json_string(req_body, "full_name",      u.full_name,          sizeof(u.full_name));
            parse_json_string(req_body, "email",          u.email,              sizeof(u.email));
            char plaintext_password[257] = {0};
            char password_hash[256] = {0};
            parse_json_string(req_body, "password", plaintext_password, sizeof(plaintext_password));
            parse_json_string(req_body, "institution_id", u.institution_id,     sizeof(u.institution_id));
            u.role = (user_role_t)parse_json_int(req_body, "role", 0);
            u.active = 1;
            if (create_platform_id("admin", u.user_id, sizeof(u.user_id)) != 0) {
                send_http_response(client_fd, 503, "application/json",
                                   "{\"error\":\"Secure ID generation unavailable\"}");
            } else if (!u.username[0] || !plaintext_password[0] ||
                       config_create_password_hash(plaintext_password, password_hash,
                                                   sizeof(password_hash)) != 0) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"username and a valid strong password are required\"}");
            } else {
                snprintf(u.password_hash, sizeof(u.password_hash), "%s", password_hash);
                if (admin_auth_store_create_user(&u, sess.user_id) == 0) {
                    PGconn *uconn = db_acquire();
                    if (uconn) {
                        unsigned char sbytes[16];
                        RAND_bytes(sbytes, sizeof(sbytes));
                        char shex[33] = {0};
                        static const char hexc[] = "0123456789abcdef";
                        for (int k = 0; k < 16; k++) {
                            shex[k * 2] = hexc[sbytes[k] >> 4];
                            shex[k * 2 + 1] = hexc[sbytes[k] & 0x0f];
                        }
                        char pbkdf2_hash[256] = {0};
                        security_pbkdf2_hash(plaintext_password, shex, pbkdf2_hash, sizeof(pbkdf2_hash));
                        char nowstr[32];
                        snprintf(nowstr, sizeof(nowstr), "%ld", (long)time(NULL));
                        const char *r_str = security_role_to_string(u.role);
                        const char *upvals[9] = {
                            u.user_id, u.username, u.full_name, r_str,
                            u.institution_id, u.email, pbkdf2_hash, shex, nowstr
                        };
                        int uplens[9];
                        for (int k = 0; k < 9; k++) uplens[k] = (int)strlen(upvals[k]);
                        PGresult *uins = db_simple(uconn,
                            "INSERT INTO users (id, username, name, role, tenant_id, email, password_hash, salt, status, created_at, mfa_enabled) "
                            "VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, 'active', $9::bigint, 0) "
                            "ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash, salt = EXCLUDED.salt, role = EXCLUDED.role",
                            9, upvals, uplens);
                        if (uins) PQclear(uins);
                        db_release(uconn, 0);
                    }
                    char resp[256];
                    snprintf(resp, sizeof(resp),
                             "{\"status\":\"created\",\"username\":\"%s\",\"user_id\":\"%s\"}", u.username, u.user_id);
                    send_http_response(client_fd, 200, "application/json", resp);
                } else {
                    send_http_response(client_fd, 409, "application/json",
                                       "{\"error\":\"User creation failed (duplicate or authorization denied)\"}");
                }
            }
            OPENSSL_cleanse(plaintext_password, sizeof(plaintext_password));
            OPENSSL_cleanse(password_hash, sizeof(password_hash));
            OPENSSL_cleanse(&u, sizeof(u));
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* Dispatch /api/v1/admin/users/:sub */
    else if (strncmp(route_path, "/api/v1/admin/users/", 20) == 0) {
        auth_admin_user_dispatch(client_fd, method, route_path + 20, req_body, auth_header,
                                 origin, extra, sizeof(extra));
        goto client_done;
    }
    /* GET /api/v1/admin/telemetry -> Platform telemetry overview */
    else if (strcmp(route_path, "/api/v1/admin/telemetry") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"Auth required\"}");
        } else {
            char *tel_buf = malloc(16384);
            if (!tel_buf) {
                send_http_response(client_fd, 503, "application/json", "{\"error\":\"Out of memory\"}");
            } else {
                if (platform_get_telemetry_json(tel_buf, 16384) == 0)
                    send_http_response(client_fd, 200, "application/json", tel_buf);
                else
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"Telemetry unavailable\"}");
                free(tel_buf);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/admin/fleet -> Device fleet list */
    else if (strcmp(route_path, "/api/v1/admin/fleet") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"Auth required\"}");
        } else {
            char *fleet_buf = malloc(131072);
            if (!fleet_buf) {
                send_http_response(client_fd, 503, "application/json", "{\"error\":\"Out of memory\"}");
            } else {
                const char *inst = (sess.role == ROLE_PLATFORM_OWNER) ? NULL : sess.institution_id;
                if (platform_get_fleet_json(inst, fleet_buf, 131072) == 0)
                    send_http_response(client_fd, 200, "application/json", fleet_buf);
                else
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"Fleet service unavailable\"}");
                free(fleet_buf);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/admin/fleet/compliance -> Fleet compliance summary */
    else if (strcmp(route_path, "/api/v1/admin/fleet/compliance") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"Auth required\"}");
        } else {
            char *comp_buf = malloc(65536);
            if (!comp_buf) {
                send_http_response(client_fd, 503, "application/json", "{\"error\":\"Out of memory\"}");
            } else {
                const char *inst = (sess.role == ROLE_PLATFORM_OWNER) ? NULL : sess.institution_id;
                if (platform_get_fleet_compliance_json(inst, comp_buf, 65536) == 0)
                    send_http_response(client_fd, 200, "application/json", comp_buf);
                else
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"Compliance service unavailable\"}");
                free(comp_buf);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/admin/incidents -> Security incidents */
    else if (strcmp(route_path, "/api/v1/admin/incidents") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_INCIDENT_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Incident read permission required\"}");
        } else {
            char *inc_buf = malloc(131072);
            if (!inc_buf) {
                send_http_response(client_fd, 503, "application/json", "{\"error\":\"Out of memory\"}");
            } else {
                const char *inst = (sess.role == ROLE_PLATFORM_OWNER) ? NULL : sess.institution_id;
                if (platform_get_incidents_json(inst, inc_buf, 131072) == 0)
                    send_http_response(client_fd, 200, "application/json", inc_buf);
                else
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"Incident service unavailable\"}");
                free(inc_buf);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/admin/policies -> Policy list (optional ?exam_id=) */
    else if (strcmp(route_path, "/api/v1/admin/policies") == 0 && strcmp(method, "GET") == 0) {
        policy_handle(client_fd, method, route_path, req_body, auth_header,
                      origin, extra, sizeof(extra));
    }
    /* GET /api/v1/admin/policies/catalog -> Provisioned browser policy catalog */
    else if (strcmp(route_path, "/api/v1/admin/policies/catalog") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam read permission required\"}");
        } else {
            char *catalog_json = malloc(16384);
            if (!catalog_json) {
                send_http_response(client_fd, 503, "application/json", "{\"error\":\"Out of memory\"}");
            } else {
                if (policy_catalog_names_json(catalog_json, 16384) != 0 || !catalog_json[0]) {
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"Browser policy catalog is unavailable\"}");
                } else {
                    send_http_response(client_fd, 200, "application/json", catalog_json);
                }
                free(catalog_json);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/create -> Create exam draft */
    else if (strcmp(route_path, "/api/v1/platform/exams/create") == 0 && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
        } else {
            enterprise_exam_t exam; memset(&exam, 0, sizeof(exam));
            parse_json_string(req_body, "title",           exam.title,           sizeof(exam.title));
            parse_json_string(req_body, "institution_id",  exam.institution_id,  sizeof(exam.institution_id));
            parse_json_string(req_body, "exam_url",        exam.exam_url,        sizeof(exam.exam_url));
            parse_json_string(req_body, "allowed_origins", exam.allowed_origins, sizeof(exam.allowed_origins));
            parse_json_string(req_body, "timezone",        exam.timezone,        sizeof(exam.timezone));
            parse_json_string(req_body, "permitted_device_group", exam.permitted_device_group, sizeof(exam.permitted_device_group));
            exam.duration_minutes = parse_json_int(req_body, "duration_minutes", 0);
            exam.retention_days = parse_json_int(req_body, "retention_days", 0);
            exam.scheduled_start = (time_t)parse_json_int(req_body, "scheduled_start", 0);
            exam.scheduled_end = (time_t)parse_json_int(req_body, "scheduled_end", 0);
            if (sess.role != ROLE_PLATFORM_OWNER && sess.institution_id[0])
                snprintf(exam.institution_id, sizeof(exam.institution_id), "%s", sess.institution_id);

            /*
             * Every policy-relevant field must be supplied explicitly. The
             * platform does not invent a timezone, device group, browser
             * policy, retention window, or schedule: those are administrative
             * decisions and must be explicit and auditable.
             */
            char browser_policy_name[64] = {0};
            parse_json_string(req_body, "browser_policy", browser_policy_name,
                              sizeof(browser_policy_name));

            char resolved_policy[POLICY_JSON_MAX] = {0};
            int policy_resolved = 0;
            if (browser_policy_name[0] &&
                policy_catalog_get(browser_policy_name, resolved_policy,
                                   sizeof(resolved_policy)) == 0) {
                policy_resolved = 1;
                snprintf(exam.browser_policy_json, sizeof(exam.browser_policy_json),
                         "%s", resolved_policy);
            }

            char url_error[256] = {0};
            int timezone_valid = 0;
            if (exam.timezone[0]) {
                char zone_path[256];
                snprintf(zone_path, sizeof(zone_path), "/usr/share/zoneinfo/%s", exam.timezone);
                if (access(zone_path, F_OK) == 0) timezone_valid = 1;
            }

            if (create_platform_id("exam", exam.exam_id, sizeof(exam.exam_id)) != 0) {
                OPENSSL_cleanse(&sess, sizeof(sess));
                send_http_response(client_fd, 503, "application/json",
                    "{\"error\":\"Secure ID generation unavailable\"}");
                goto client_done;
            }
            snprintf(exam.code, sizeof(exam.code), "%.8s", exam.exam_id + 5);
            snprintf(exam.owner_user_id, sizeof(exam.owner_user_id), "%s", sess.user_id);
            exam.state = EXAM_STATE_DRAFT;
            if (!exam.title[0] || !exam.institution_id[0] || exam.duration_minutes < 1) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"title, institution_id and a positive duration_minutes are required\"}");
            } else if (!exam.exam_url[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_url is required\"}");
            } else if (platform_validate_exam_url(exam.exam_url, url_error, sizeof(url_error)) != 0) {
                send_http_response(client_fd, 422, "application/json",
                                   url_error[0] ? url_error
                                                : "{\"error\":\"exam_url is not an approved exam origin\"}");
            } else if (!timezone_valid) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"timezone must be a valid IANA time zone name\"}");
            } else if (!exam.permitted_device_group[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"permitted_device_group is required and must name an enrolled device group\"}");
            } else if (!policy_resolved) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"browser_policy must name a policy from the provisioned browser policy catalog\"}");
            } else if (exam.retention_days < 1 || exam.retention_days > 36500) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"retention_days must be between 1 and 36500\"}");
            } else if (exam.scheduled_start <= 0 || exam.scheduled_end <= 0 ||
                       exam.scheduled_end <= exam.scheduled_start) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"scheduled_start and scheduled_end are required, and scheduled_end must be after scheduled_start\"}");
            } else if (platform_create_exam(&exam) == 0) {
                char resp[512];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"created\",\"exam_id\":\"%s\"}", exam.exam_id);
                send_http_response(client_fd, 200, "application/json", resp);
            } else {
                char resp[640];
                snprintf(resp, sizeof(resp), "{\"error\":\"%s\"}", platform_last_error());
                send_http_response(client_fd, 409, "application/json", resp);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/:id/validate */
    else if (strncmp(route_path, "/api/v1/platform/exams/", 23) == 0 &&
             strstr(route_path + 23, "/validate") != NULL && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
        } else {
            char exam_id[128] = {0};
            const char *id_end = strstr(route_path + 23, "/validate");
            size_t id_len = id_end ? (size_t)(id_end - (route_path + 23)) : 0;
            if (id_len > 0 && id_len < sizeof(exam_id)) memcpy(exam_id, route_path + 23, id_len);
            char err_msg[512] = {0};
            if (!exam_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_id required in path\"}");
            } else if (platform_validate_exam_config(exam_id, err_msg, sizeof(err_msg)) == 0) {
                send_http_response(client_fd, 200, "application/json", "{\"status\":\"VALID\"}");
            } else {
                char resp[640];
                snprintf(resp, sizeof(resp), "{\"status\":\"INVALID\",\"error\":\"%s\"}", err_msg);
                send_http_response(client_fd, 422, "application/json", resp);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/:id/approve */
    else if (strncmp(route_path, "/api/v1/platform/exams/", 23) == 0 &&
             strstr(route_path + 23, "/approve") != NULL && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
        } else {
            char exam_id[128] = {0};
            const char *id_end = strstr(route_path + 23, "/approve");
            size_t id_len = id_end ? (size_t)(id_end - (route_path + 23)) : 0;
            if (id_len > 0 && id_len < sizeof(exam_id)) memcpy(exam_id, route_path + 23, id_len);
            if (!exam_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_id required in path\"}");
            } else if (platform_approve_exam(exam_id, sess.user_id) == 0) {
                send_http_response(client_fd, 200, "application/json", "{\"status\":\"approved\"}");
            } else {
                send_http_response(client_fd, 500, "application/json",
                                   "{\"error\":\"Approval failed\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/sessions -> Create an in-memory exam session */
    else if (strcmp(route_path, "/api/v1/platform/exams/sessions") == 0 && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
            OPENSSL_cleanse(&sess, sizeof(sess));
        } else {
            char candidate_id[64] = {0}, exam_code[32] = {0};
            long max_duration = parse_json_int(req_body, "max_duration_seconds", 0);
            parse_json_string(req_body, "candidate_id", candidate_id, sizeof(candidate_id));
            parse_json_string(req_body, "exam_code", exam_code, sizeof(exam_code));
            exam_session_t es; memset(&es, 0, sizeof(es));
            if (!candidate_id[0] || !exam_code[0] || max_duration <= 0) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"candidate_id, exam_code and max_duration_seconds are required\"}");
            } else if (exam_manager_create_session(candidate_id, exam_code, max_duration, &es) != 0) {
                send_http_response(client_fd, 500, "application/json",
                                   "{\"error\":\"Failed to create exam session\"}");
            } else {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"SESSION_CREATED\",\"session_id\":\"%s\",\"candidate_id\":\"%s\",\"exam_code\":\"%s\",\"state\":%d,\"start_time\":%ld,\"max_duration_seconds\":%ld}",
                         es.session_id, es.candidate_id, es.exam_code, (int)es.state, es.start_time, es.max_duration_seconds);
                send_http_response(client_fd, 201, "application/json", resp);
            }
            OPENSSL_cleanse(&sess, sizeof(sess));
        }
    }
    /* POST /api/v1/platform/exams/sessions/:id/state -> Update exam session state */
    else if (strncmp(route_path, "/api/v1/platform/exams/sessions/", 32) == 0 &&
             strstr(route_path + 32, "/state") != NULL && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
            OPENSSL_cleanse(&sess, sizeof(sess));
        } else {
            char session_id[64] = {0};
            const char *id_start = route_path + 32;
            const char *id_end = strstr(id_start, "/state");
            size_t id_len = id_end ? (size_t)(id_end - id_start) : 0;
            if (id_len == 0 || id_len >= sizeof(session_id)) {
                send_http_response(client_fd, 400, "application/json", "{\"error\":\"session_id required in path\"}");
            } else {
                memcpy(session_id, id_start, id_len);
                session_id[id_len] = '\0';
                int new_state = parse_json_int(req_body, "state", -1);
                exam_session_t es; memset(&es, 0, sizeof(es));
                if (exam_manager_get_session(session_id, &es) != 0) {
                    send_http_response(client_fd, 404, "application/json",
                                       "{\"error\":\"Exam session not found\"}");
                } else if (new_state < EXAM_STATE_REGISTERED || new_state > EXAM_STATE_FLAGGED_TERMINATED) {
                    send_http_response(client_fd, 400, "application/json",
                                       "{\"error\":\"Invalid state value\"}");
                } else if (exam_manager_update_state(session_id, (exam_session_state_t)new_state) != 0) {
                    send_http_response(client_fd, 500, "application/json",
                                       "{\"error\":\"Failed to update exam session state\"}");
                } else {
                    char resp[256];
                    snprintf(resp, sizeof(resp),
                             "{\"status\":\"STATE_UPDATED\",\"session_id\":\"%s\",\"state\":%d}",
                             session_id, new_state);
                    send_http_response(client_fd, 200, "application/json", resp);
                }
            }
            OPENSSL_cleanse(&sess, sizeof(sess));
        }
    }
    else if (strncmp(route_path, "/api/v1/platform/exams/", 23) == 0 &&
             strstr(route_path + 23, "/url") != NULL && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
        } else {
            char exam_id[128] = {0};
            const char *id_end = strstr(route_path + 23, "/url");
            size_t id_len = id_end ? (size_t)(id_end - (route_path + 23)) : 0;
            if (id_len > 0 && id_len < sizeof(exam_id)) memcpy(exam_id, route_path + 23, id_len);
            char new_url[4096] = {0}, allowed_origins[2048] = {0};
            parse_json_string(req_body, "exam_url",        new_url,         sizeof(new_url));
            parse_json_string(req_body, "allowed_origins", allowed_origins, sizeof(allowed_origins));
            enterprise_exam_t exam; memset(&exam, 0, sizeof(exam));
            if (!exam_id[0] || !new_url[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_id (path) and exam_url required\"}");
            } else if (platform_get_exam_by_id(exam_id, &exam) != 0 ||
                       (sess.role != ROLE_PLATFORM_OWNER &&
                        strcmp(sess.institution_id, exam.institution_id) != 0)) {
                /* Do not let an institution-scoped operator retarget another
                 * tenant's examination to a URL they control. */
                send_http_response(client_fd, 403, "application/json",
                                   "{\"error\":\"Exam scope denied\"}");
                OPENSSL_cleanse(&exam, sizeof(exam));
            } else if (platform_update_exam_url(exam_id, new_url, allowed_origins, sess.user_id) == 0) {
                send_http_response(client_fd, 200, "application/json",
                                   "{\"status\":\"url_updated\"}");
                OPENSSL_cleanse(&exam, sizeof(exam));
            } else {
                char escaped_error[1024], response[1100];
                const char *error = platform_last_error();
                if (json_escape(error, escaped_error, sizeof(escaped_error)) == 0) {
                    snprintf(response, sizeof(response), "{\"error\":\"%s\"}", escaped_error);
                    send_http_response(client_fd,
                        errno == EINVAL ? 400 : errno == ENOTSUP ? 503 :
                        errno == ENOENT ? 404 : errno == EPERM ? 409 : 500,
                        "application/json", response);
                } else {
                    send_http_response(client_fd, 500, "application/json",
                        "{\"error\":\"Exam URL update failed\"}");
                }
                OPENSSL_cleanse(&exam, sizeof(exam));
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/:id/schedule */
    else if (strncmp(route_path, "/api/v1/platform/exams/", 23) == 0 &&
             strstr(route_path + 23, "/schedule") != NULL && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
        } else {
            char exam_id[128] = {0};
            const char *id_end = strstr(route_path + 23, "/schedule");
            size_t id_len = id_end ? (size_t)(id_end - (route_path + 23)) : 0;
            if (id_len > 0 && id_len < sizeof(exam_id)) memcpy(exam_id, route_path + 23, id_len);
            char timezone[64] = {0};
            parse_json_string(req_body, "timezone", timezone, sizeof(timezone));
            int start_ts = parse_json_int(req_body, "start_time", 0);
            int end_ts   = parse_json_int(req_body, "end_time",   0);
            if (!exam_id[0] || start_ts <= 0 || end_ts <= 0) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_id, start_time and end_time required\"}");
            } else if (platform_schedule_exam(exam_id, (time_t)start_ts, (time_t)end_ts,
                                              timezone[0] ? timezone : "UTC", sess.user_id) == 0) {
                send_http_response(client_fd, 200, "application/json",
                                   "{\"status\":\"scheduled\"}");
            } else {
                send_http_response(client_fd, 500, "application/json",
                                   "{\"error\":\"Schedule failed\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/:id/policy/rollback */
    else if (strncmp(route_path, "/api/v1/platform/exams/", 23) == 0 &&
             strstr(route_path + 23, "/policy/rollback") != NULL && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_SECURITY_ADMIN, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Security admin permission required\"}");
        } else {
            char exam_id[128] = {0};
            const char *id_end = strstr(route_path + 23, "/policy/rollback");
            size_t id_len = id_end ? (size_t)(id_end - (route_path + 23)) : 0;
            if (id_len > 0 && id_len < sizeof(exam_id)) memcpy(exam_id, route_path + 23, id_len);
            int target_version = parse_json_int(req_body, "target_version", 0);
            if (!exam_id[0] || target_version <= 0) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_id and target_version required\"}");
            } else {
                send_http_response(client_fd, 409, "application/json",
                    "{\"error\":\"Direct policy rollback is disabled; submit a policy-rollback request through the centralized approval workflow\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/:id/state -> Advance the exam lifecycle */
    else if (platform_route_id(route_path, "state", exam_route_id, sizeof(exam_route_id)) == 0 &&
             strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
        } else {
            char state_name[64] = {0};
            parse_json_string(req_body, "state", state_name, sizeof(state_name));
            exam_state_t next_state = string_to_exam_state(state_name);
            if (!state_name[0] ||
                (next_state == EXAM_STATE_DRAFT && strcmp(state_name, "DRAFT") != 0)) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"state must be one of DRAFT, VALIDATED, APPROVED, SCHEDULED, OPEN, ACTIVE, PAUSED, SUBMISSION, CLOSED, RECONCILED\"}");
            } else if (platform_update_exam_state(exam_route_id, next_state, sess.user_id) == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"updated\",\"exam_id\":\"%s\",\"state\":\"%s\"}",
                         exam_route_id, exam_state_to_string(next_state));
                /* When an exam goes ACTIVE, load its questions into the engine
                 * so paper delivery is immediately available. Fail closed:
                 * if questions cannot be loaded the state update is still
                 * committed but the engine reports not-ready until questions
                 * are provisioned. */
                if (next_state == EXAM_STATE_ACTIVE) {
                    if (exam_engine_load_questions_from_db(exam_route_id) <= 0) {
                        fprintf(stderr,
                            "[Server] WARNING: exam '%s' transitioned to ACTIVE but "
                            "no questions could be loaded from the database. "
                            "Provision questions via examos_exam_questions before "
                            "candidates attempt to access the paper.\n",
                            exam_route_id);
                    }
                }
                send_http_response(client_fd, 200, "application/json", resp);
            } else if (next_state == EXAM_STATE_ACTIVE && errno == ENOTSUP) {
                send_http_response(client_fd, 503, "application/json",
                    "{\"error\":\"Exam activation is blocked until signed policy publication and authenticated device acknowledgements are available\"}");
            } else {
                send_http_response(client_fd, 409, "application/json",
                    "{\"error\":\"Exam state transition is not permitted from the current state\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/:id/roster -> Add or update a roster entry */
    else if (platform_route_id(route_path, "roster", exam_route_id, sizeof(exam_route_id)) == 0 &&
             strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
        } else {
            candidate_roster_entry_t entry; memset(&entry, 0, sizeof(entry));
            parse_json_string(req_body, "candidate_id", entry.candidate_id, sizeof(entry.candidate_id));
            parse_json_string(req_body, "full_name",    entry.full_name,    sizeof(entry.full_name));
            parse_json_string(req_body, "email",        entry.email,        sizeof(entry.email));
            parse_json_string(req_body, "room_id",      entry.room_id,      sizeof(entry.room_id));
            parse_json_string(req_body, "assigned_seat", entry.assigned_seat, sizeof(entry.assigned_seat));
            parse_json_string(req_body, "assigned_device_id", entry.assigned_device_id, sizeof(entry.assigned_device_id));
            entry.accommodation_extra_time_mins =
                parse_json_int(req_body, "accommodation_extra_time_mins", 0);

            /* The candidate PIN is never stored; only a PBKDF2 hash is kept. */
            char pin[64] = {0};
            parse_json_string(req_body, "pin", pin, sizeof(pin));
            int pin_ok = 0;
            if (pin[0] && config_create_password_hash(pin, entry.pin_hash,
                                                      sizeof(entry.pin_hash)) == 0) {
                pin_ok = 1;
            }
            OPENSSL_cleanse(pin, sizeof(pin));

            snprintf(entry.exam_id, sizeof(entry.exam_id), "%s", exam_route_id);
            entry.status = CANDIDATE_ELIGIBLE;

            if (!entry.candidate_id[0] || !entry.full_name[0] || !entry.email[0] || !pin_ok ||
                entry.accommodation_extra_time_mins < 0) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"candidate_id, full_name, email and pin are required; accommodation_extra_time_mins must not be negative\"}");
            } else if (platform_add_candidate_roster(&entry) == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"created\",\"exam_id\":\"%s\",\"candidate_id\":\"%s\"}",
                         exam_route_id, entry.candidate_id);
                send_http_response(client_fd, 201, "application/json", resp);
            } else {
                char resp[640];
                snprintf(resp, sizeof(resp), "{\"error\":\"%s\"}", platform_last_error());
                send_http_response(client_fd, 409, "application/json", resp);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/:id/checkin -> Check a candidate in */
    else if (platform_route_id(route_path, "checkin", exam_route_id, sizeof(exam_route_id)) == 0 &&
             strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
        } else {
            char candidate_id[64] = {0}, device_id[64] = {0};
            parse_json_string(req_body, "candidate_id", candidate_id, sizeof(candidate_id));
            parse_json_string(req_body, "device_id",    device_id,    sizeof(device_id));
            if (!candidate_id[0] || !device_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"candidate_id and device_id are required\"}");
            } else if (platform_checkin_candidate(exam_route_id, candidate_id, device_id) == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"CHECKED_IN\",\"exam_id\":\"%s\",\"candidate_id\":\"%s\",\"device_id\":\"%s\"}",
                         exam_route_id, candidate_id, device_id);
                send_http_response(client_fd, 200, "application/json", resp);
            } else {
                send_http_response(client_fd, 409, "application/json",
                    "{\"error\":\"Candidate could not be checked in for this exam and device\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/:id/submissions -> Record a submission */
    else if (platform_route_id(route_path, "submissions", exam_route_id, sizeof(exam_route_id)) == 0 &&
             strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam mutation permission required\"}");
        } else {
            durable_submission_t submission; memset(&submission, 0, sizeof(submission));
            parse_json_string(req_body, "submission_id",  submission.submission_id,  sizeof(submission.submission_id));
            parse_json_string(req_body, "candidate_id",   submission.candidate_id, sizeof(submission.candidate_id));
            parse_json_string(req_body, "session_id",     submission.session_id,   sizeof(submission.session_id));
            parse_json_string(req_body, "receipt_hash",   submission.receipt_hash, sizeof(submission.receipt_hash));
            parse_json_string(req_body, "status",         submission.status,       sizeof(submission.status));
            snprintf(submission.exam_id, sizeof(submission.exam_id), "%s", exam_route_id);

            /* The submitted answer payload is hashed server-side; the
               answers themselves are never retained in the platform store. */
            const char *answers = strstr(req_body, "\"answers\"");
            size_t answers_len = answers ? strlen(answers) : 0;
            submission.payload_bytes = answers_len;

            if (!submission.candidate_id[0] || !submission.session_id[0] ||
                !submission.receipt_hash[0] || strlen(submission.receipt_hash) != 64) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"candidate_id, session_id and a 64-character receipt_hash are required\"}");
            } else if (platform_record_submission(&submission, answers ? answers : "") == 0) {
                char resp[320];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"ACCEPTED\",\"submission_id\":\"%s\",\"exam_id\":\"%s\",\"candidate_id\":\"%s\"}",
                         submission.submission_id[0] ? submission.submission_id : "",
                         exam_route_id, submission.candidate_id);
                send_http_response(client_fd, 201, "application/json", resp);
            } else {
                char resp[640];
                snprintf(resp, sizeof(resp), "{\"error\":\"%s\"}", platform_last_error());
                send_http_response(client_fd, 409, "application/json", resp);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/platform/exams/:id/readiness?device_id= */
    else if (platform_route_id(route_path, "readiness", exam_route_id, sizeof(exam_route_id)) == 0 &&
             strcmp(method, "GET") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam read permission required\"}");
        } else {
            char device_id[64] = {0};
            if (parse_query_id(path, "device_id", device_id, sizeof(device_id)) != 0) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"device_id query parameter required\"}");
            } else {
                char readiness_json[1024] = {0};
                int ready = platform_check_readiness(exam_route_id, device_id,
                                                      readiness_json, sizeof(readiness_json));
                if (readiness_json[0]) {
                    send_http_response(client_fd, ready == 0 ? 200 : 200,
                                       "application/json", readiness_json);
                } else {
                    send_http_response(client_fd, 503, "application/json",
                        "{\"error\":\"Readiness evidence is unavailable\"}");
                }
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/platform/exams/purge -> Purge exams past their retention window */
    else if (strcmp(route_path, "/api/v1/platform/exams/purge") == 0 && strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_SECURITY_ADMIN, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Security admin permission required\"}");
        } else {
            char summary[2048] = {0};
            int retention_days = parse_json_int(req_body, "retention_days", 0);
            if (retention_days <= 0) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"retention_days must be a positive number of days\"}");
            } else if (platform_purge_expired_exams(retention_days, summary, sizeof(summary)) == 0) {
                send_http_response(client_fd, 200, "application/json",
                                   summary[0] ? summary : "{\"status\":\"purged\"}");
            } else {
                send_http_response(client_fd, 500, "application/json",
                    "{\"error\":\"Retention purge failed\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/fleet/bulk -> Apply a bulk device action */
    else if (strcmp(route_path, "/api/v1/admin/fleet/bulk") == 0 && strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_SECURITY_ADMIN, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Security admin permission required\"}");
        } else {
            char action_type[64] = {0}, target_group[64] = {0}, target_inst[64] = {0};
            char target_campus[64] = {0}, target_room[64] = {0}, param[256] = {0};
            parse_json_string(req_body, "action_type",   action_type,   sizeof(action_type));
            parse_json_string(req_body, "target_group",  target_group,  sizeof(target_group));
            parse_json_string(req_body, "institution_id", target_inst,  sizeof(target_inst));
            parse_json_string(req_body, "campus_id",     target_campus, sizeof(target_campus));
            parse_json_string(req_body, "room_id",       target_room,   sizeof(target_room));
            parse_json_string(req_body, "parameter",     param,         sizeof(param));
            int preview = parse_json_int(req_body, "preview_only", 0);

            char bulk_json[4096] = {0};
            if (!action_type[0]) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"action_type is required\"}");
            } else if (platform_bulk_device_action(action_type, target_group, target_inst,
                                                   target_campus, target_room, param,
                                                   preview ? 1 : 0, sess.user_id,
                                                   bulk_json, sizeof(bulk_json)) == 0) {
                send_http_response(client_fd, 200, "application/json",
                                   bulk_json[0] ? bulk_json : "{\"status\":\"ok\"}");
            } else {
                send_http_response(client_fd, 500, "application/json",
                    "{\"error\":\"Bulk device action failed\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/incidents -> Raise a security incident */
    else if (strcmp(route_path, "/api/v1/admin/incidents") == 0 && strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_INCIDENT_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Incident management permission required\"}");
        } else {
            security_incident_t incident; memset(&incident, 0, sizeof(incident));
            parse_json_string(req_body, "title",           incident.title,           sizeof(incident.title));
            parse_json_string(req_body, "institution_id",  incident.institution_id,  sizeof(incident.institution_id));
            parse_json_string(req_body, "device_id",       incident.device_id,       sizeof(incident.device_id));
            parse_json_string(req_body, "candidate_id",    incident.candidate_id,    sizeof(incident.candidate_id));
            parse_json_string(req_body, "exam_id",         incident.exam_id,         sizeof(incident.exam_id));
            parse_json_string(req_body, "summary",         incident.summary,         sizeof(incident.summary));
            parse_json_string(req_body, "assigned_to",     incident.assigned_to,     sizeof(incident.assigned_to));

            char severity_name[32] = {0};
            parse_json_string(req_body, "severity", severity_name, sizeof(severity_name));
            incident.severity = SEV_INFO;
            if (strcasecmp(severity_name, "LOW") == 0) incident.severity = SEV_LOW;
            else if (strcasecmp(severity_name, "MEDIUM") == 0) incident.severity = SEV_MEDIUM;
            else if (strcasecmp(severity_name, "HIGH") == 0) incident.severity = SEV_HIGH;
            else if (strcasecmp(severity_name, "CRITICAL") == 0) incident.severity = SEV_CRITICAL;
            else if (severity_name[0] && strcasecmp(severity_name, "INFO") != 0) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"severity must be one of INFO, LOW, MEDIUM, HIGH, CRITICAL\"}");
                OPENSSL_cleanse(&sess, sizeof(sess));
                goto client_done;
            }
            snprintf(incident.status, sizeof(incident.status), "OPEN");

            if (!incident.title[0] || !incident.summary[0]) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"title and summary are required\"}");
            } else if (platform_create_incident(&incident) == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"created\",\"incident_id\":\"%s\"}", incident.incident_id);
                send_http_response(client_fd, 201, "application/json", resp);
            } else {
                char resp[640];
                snprintf(resp, sizeof(resp), "{\"error\":\"%s\"}", platform_last_error());
                send_http_response(client_fd, 409, "application/json", resp);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/releases -> Publish a software release record */
    else if (strcmp(route_path, "/api/v1/admin/releases") == 0 && strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_SECURITY_ADMIN, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Security admin permission required\"}");
        } else {
            enterprise_release_t release; memset(&release, 0, sizeof(release));
            parse_json_string(req_body, "release_id",    release.release_id,    sizeof(release.release_id));
            parse_json_string(req_body, "version_name",  release.version_name,  sizeof(release.version_name));
            parse_json_string(req_body, "image_digest",  release.image_digest,  sizeof(release.image_digest));
            parse_json_string(req_body, "uki_digest",    release.uki_digest,    sizeof(release.uki_digest));
            parse_json_string(req_body, "sbom_digest",   release.sbom_digest,   sizeof(release.sbom_digest));

            char ring_name[32] = {0};
            parse_json_string(req_body, "target_ring", ring_name, sizeof(ring_name));
            release.target_ring = RING_CANARY;
            if (strcasecmp(ring_name, "PILOT") == 0) release.target_ring = RING_PILOT;
            else if (strcasecmp(ring_name, "GENERAL") == 0) release.target_ring = RING_GENERAL;
            else if (ring_name[0] && strcasecmp(ring_name, "CANARY") != 0) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"target_ring must be one of CANARY, PILOT, GENERAL\"}");
                OPENSSL_cleanse(&sess, sizeof(sess));
                goto client_done;
            }
            snprintf(release.status, sizeof(release.status), "DRAFT");
            snprintf(release.signed_by, sizeof(release.signed_by), "%s", sess.user_id);
            release.release_date = time(NULL);

            char requested_status[32] = {0};
            parse_json_string(req_body, "status", requested_status, sizeof(requested_status));
            if (requested_status[0]) {
                if (strcmp(requested_status, "DRAFT") == 0 ||
                    strcmp(requested_status, "PUBLISHED") == 0) {
                    snprintf(release.status, sizeof(release.status), "%s", requested_status);
                } else {
                    send_http_response(client_fd, 400, "application/json",
                        "{\"error\":\"status must be DRAFT or PUBLISHED\"}");
                    OPENSSL_cleanse(&sess, sizeof(sess));
                    goto client_done;
                }
            }

            if (!release.release_id[0] || !release.version_name[0] ||
                strlen(release.image_digest) != 64 || strlen(release.uki_digest) != 64 ||
                strlen(release.sbom_digest) != 64) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"release_id, version_name and 64-character image_digest, uki_digest and sbom_digest are required\"}");
            } else if (platform_create_release(&release) == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"created\",\"release_id\":\"%s\"}", release.release_id);
                send_http_response(client_fd, 201, "application/json", resp);
            } else {
                char resp[640];
                snprintf(resp, sizeof(resp), "{\"error\":\"%s\"}", platform_last_error());
                send_http_response(client_fd, 409, "application/json", resp);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/fleet/enroll -> Enrol a device into the fleet */
    else if (strcmp(route_path, "/api/v1/admin/fleet/enroll") == 0 && strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_SECURITY_ADMIN, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Security admin permission required\"}");
        } else {
            fleet_device_record_t device; memset(&device, 0, sizeof(device));
            parse_json_string(req_body, "device_id",      device.device_id,      sizeof(device.device_id));
            parse_json_string(req_body, "hostname",       device.hostname,       sizeof(device.hostname));
            parse_json_string(req_body, "institution_id", device.institution_id, sizeof(device.institution_id));
            parse_json_string(req_body, "campus_id",      device.campus_id,      sizeof(device.campus_id));
            parse_json_string(req_body, "room_id",        device.room_id,        sizeof(device.room_id));
            parse_json_string(req_body, "group_name",     device.group_name,     sizeof(device.group_name));
            char ring_name[32] = {0};
            parse_json_string(req_body, "deployment_ring", ring_name, sizeof(ring_name));
            device.ring = RING_CANARY;
            if (strcasecmp(ring_name, "PILOT") == 0) device.ring = RING_PILOT;
            else if (strcasecmp(ring_name, "GENERAL") == 0) device.ring = RING_GENERAL;
            parse_json_string(req_body, "hardware_platform", device.hardware_platform, sizeof(device.hardware_platform));
            parse_json_string(req_body, "crypto_identity_ref", device.crypto_identity_ref, sizeof(device.crypto_identity_ref));
            parse_json_string(req_body, "os_release",     device.os_release,     sizeof(device.os_release));
            parse_json_string(req_body, "image_digest",   device.image_digest,   sizeof(device.image_digest));
            parse_json_string(req_body, "uki_digest",     device.uki_digest,     sizeof(device.uki_digest));

            if (!device.device_id[0] || !device.hostname[0] || !device.group_name[0] ||
                !device.hardware_platform[0] || !device.crypto_identity_ref[0] ||
                strlen(device.image_digest) != 64 || strlen(device.uki_digest) != 64) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"device_id, hostname, group_name, hardware_platform, crypto_identity_ref and 64-character image_digest and uki_digest are required\"}");
            } else if (platform_enroll_device(&device, sess.user_id) == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"enrolled\",\"device_id\":\"%s\"}", device.device_id);
                send_http_response(client_fd, 201, "application/json", resp);
            } else {
                send_http_response(client_fd, 409, "application/json",
                    "{\"error\":\"Device enrolment was refused\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/policies/distribute -> Produce the signed policy bundle for a device */
    else if (strcmp(route_path, "/api/v1/admin/policies/distribute") == 0 && strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam read permission required\"}");
        } else {
            char exam_id[64] = {0}, device_id[64] = {0};
            parse_json_string(req_body, "exam_id",   exam_id,   sizeof(exam_id));
            parse_json_string(req_body, "device_id", device_id, sizeof(device_id));
            if (!exam_id[0] || !device_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"exam_id and device_id are required\"}");
            } else {
                char bundle[8192] = {0};
                if (platform_distribute_policy_bundle_json(exam_id, device_id,
                                                            bundle, sizeof(bundle)) == 0) {
                    send_http_response(client_fd, 200, "application/json", bundle);
                } else {
                    send_http_response(client_fd, 503, "application/json",
                        "{\"error\":\"No active signed policy is available for this exam and device\"}");
                }
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/policies/verify -> Verify a client-supplied policy */
    else if (strcmp(route_path, "/api/v1/admin/policies/verify") == 0 && strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam read permission required\"}");
        } else {
            char expected_exam_id[64] = {0}, device_id[64] = {0};
            parse_json_string(req_body, "exam_id",   expected_exam_id, sizeof(expected_exam_id));
            parse_json_string(req_body, "device_id", device_id,        sizeof(device_id));
            const char *policy_json = strstr(req_body, "\"policy\"");
            char policy_text[8192] = {0};
            if (policy_json) {
                const char *colon = strchr(policy_json, ':');
                if (colon) {
                    const char *start = colon + 1;
                    while (*start == ' ' || *start == '"') start++;
                    size_t n = 0;
                    while (start[n] && start[n] != '"' && n + 1 < sizeof(policy_text)) n++;
                    memcpy(policy_text, start, n);
                    policy_text[n] = '\0';
                }
            }
            if (!expected_exam_id[0] || !device_id[0] || !policy_text[0]) {
                send_http_response(client_fd, 400, "application/json",
                    "{\"error\":\"exam_id, device_id and policy are required\"}");
            } else {
                char err_msg[512] = {0};
                if (platform_verify_client_policy(policy_text, expected_exam_id, device_id,
                                                  err_msg, sizeof(err_msg)) == 0) {
                    send_http_response(client_fd, 200, "application/json",
                        "{\"status\":\"VERIFIED\",\"exam_id\":\"expected\"}");
                } else {
                    char resp[640];
                    snprintf(resp, sizeof(resp),
                             "{\"status\":\"REJECTED\",\"error\":\"%s\"}", err_msg);
                    send_http_response(client_fd, 403, "application/json", resp);
                }
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/admin/audit -> Administrative audit trail */
    else if (strcmp(route_path, "/api/v1/admin/audit") == 0 && strcmp(method, "GET") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_READ, &sess) != 0 ||
            (sess.role != ROLE_PLATFORM_OWNER &&
             sess.role != ROLE_INCIDENT_INVESTIGATOR &&
             sess.role != ROLE_READONLY_AUDITOR)) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Platform audit permission required\"}");
        } else {
            char exam_id[64] = {0};
            parse_query_id(path, "exam_id", exam_id, sizeof(exam_id));
            /* Parse ?limit= from the query string, not from a JSON body */
            int limit = 100;
            {
                char limit_str[16] = {0};
                if (parse_query_id(path, "limit", limit_str, sizeof(limit_str)) == 0
                    && limit_str[0]) {
                    char *end = NULL;
                    errno = 0;
                    long v = strtol(limit_str, &end, 10);
                    if (errno == 0 && end != limit_str && *end == '\0'
                        && v >= 1 && v <= 10000)
                        limit = (int)v;
                }
            }
            static char audit_buf[65536];
            if (platform_get_audit_json(exam_id[0] ? exam_id : NULL, limit,
                                        audit_buf, sizeof(audit_buf)) == 0) {
                send_http_response(client_fd, 200, "application/json", audit_buf);
            } else {
                send_http_response(client_fd, 503, "application/json",
                                   "{\"error\":\"Audit trail is unavailable\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/admin/operations -> Live examination operations */
    else if (strcmp(route_path, "/api/v1/admin/operations") == 0 && strcmp(method, "GET") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam read permission required\"}");
        } else {
            static char ops_buf[32768];
            if (platform_get_operations_json(ops_buf, sizeof(ops_buf)) == 0) {
                send_http_response(client_fd, 200, "application/json", ops_buf);
            } else {
                send_http_response(client_fd, 503, "application/json",
                                   "{\"error\":\"Operational summary is unavailable\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/admin/fleet/groups -> Device groups and deployment rings */
    else if (strcmp(route_path, "/api/v1/admin/fleet/groups") == 0 && strcmp(method, "GET") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_FLEET_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Fleet permission required\"}");
        } else {
            static char groups_buf[32768];
            if (platform_get_device_groups_json(groups_buf, sizeof(groups_buf)) == 0) {
                send_http_response(client_fd, 200, "application/json", groups_buf);
            } else {
                send_http_response(client_fd, 503, "application/json",
                                   "{\"error\":\"Device group summary is unavailable\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/institutions/:id -> Update institution settings */
    else if (strncmp(route_path, "/api/v1/admin/institutions/", 27) == 0 &&
             strcmp(method, "POST") == 0) {
        const char *tok = bearer_token(auth_header);
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_INSTITUTION_ADMIN, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Institution administration permission required\"}");
        } else {
            char institution_id[64] = {0};
            const char *id_end = route_path + 27;
            const char *slash = strchr(id_end, '/');
            size_t id_len = slash ? (size_t)(slash - id_end) : strlen(id_end);
            if (id_len > 0 && id_len < sizeof(institution_id)) {
                memcpy(institution_id, id_end, id_len);
                institution_id[id_len] = '\0';
            }
            char name[128] = {0}, contact_email[128] = {0};
            parse_json_string(req_body, "name", name, sizeof(name));
            parse_json_string(req_body, "contact_email", contact_email, sizeof(contact_email));
            int retention_days = parse_json_int(req_body, "retention_days", 0);
            if (!institution_id[0] || !name[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"institution_id in the path and name are required\"}");
            } else if (platform_update_institution(institution_id, name, contact_email,
                                                   retention_days, sess.user_id) == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"updated\",\"institution_id\":\"%s\",\"retention_days\":%d}",
                         institution_id, retention_days);
                send_http_response(client_fd, 200, "application/json", resp);
            } else {
                char resp[640];
                snprintf(resp, sizeof(resp), "{\"error\":\"%s\"}", platform_last_error());
                send_http_response(client_fd, 409, "application/json", resp);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/admin/reconciliation?exam_id= */
    else if (strcmp(route_path, "/api/v1/admin/reconciliation") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam read permission required\"}");
        } else {
            char exam_id[128] = {0};
            parse_query_id(path, "exam_id", exam_id, sizeof(exam_id));
            if (!exam_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_id query parameter required\"}");
            } else {
                static char rec_buf[65536];
                if (platform_get_reconciliation_json(exam_id, rec_buf, sizeof(rec_buf)) == 0)
                    send_http_response(client_fd, 200, "application/json", rec_buf);
                else
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"Reconciliation unavailable\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/admin/submissions?exam_id= */
    else if (strcmp(route_path, "/api/v1/admin/submissions") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_EXAM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Exam read permission required\"}");
        } else {
            char exam_id[128] = {0};
            parse_query_id(path, "exam_id", exam_id, sizeof(exam_id));
            if (!exam_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_id query parameter required\"}");
            } else {
                static char sub_buf[131072];
                if (platform_get_submissions_json(exam_id, sub_buf, sizeof(sub_buf)) == 0)
                    send_http_response(client_fd, 200, "application/json", sub_buf);
                else
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"Submissions unavailable\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/incidents/:id/status */
    else if (strncmp(route_path, "/api/v1/admin/incidents/", 24) == 0 &&
             strstr(path + 24, "/status") != NULL && strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_INCIDENT_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Incident permission required\"}");
        } else {
            char inc_id[128] = {0};
            const char *id_end = strstr(path + 24, "/status");
            size_t id_len = id_end ? (size_t)(id_end - (path + 24)) : 0;
            if (id_len > 0 && id_len < sizeof(inc_id)) memcpy(inc_id, path + 24, id_len);
            char new_status[64] = {0}, notes[512] = {0};
            parse_json_string(req_body, "status", new_status, sizeof(new_status));
            parse_json_string(req_body, "notes",  notes,      sizeof(notes));
            if (sess.role != ROLE_PLATFORM_OWNER && !sess.institution_id[0]) {
                send_http_response(client_fd, 403, "application/json", "{\"error\":\"Incident institution scope required\"}");
            } else if (!inc_id[0] || !new_status[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"incident id (path) and status required\"}");
            } else if (platform_update_incident_status_scoped(inc_id,
                       sess.role == ROLE_PLATFORM_OWNER ? NULL : sess.institution_id,
                       new_status, notes, sess.user_id) == 0) {
                send_http_response(client_fd, 200, "application/json",
                                   "{\"status\":\"updated\"}");
            } else {
                send_http_response(client_fd, 500, "application/json",
                                   "{\"error\":\"Status update failed\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/fleet/:id/approve */
    else if (fleet_route_id(route_path, "approve", fleet_route_device, sizeof(fleet_route_device)) == 0 &&
             strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_FLEET_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Fleet mutation permission required\"}");
        } else {
            char dev_id[128] = {0};
            snprintf(dev_id, sizeof(dev_id), "%s", fleet_route_device);
            if (!dev_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"device_id required in path\"}");
            } else if (platform_approve_device_enrollment(dev_id, sess.user_id) == 0) {
                send_http_response(client_fd, 200, "application/json",
                                   "{\"status\":\"approved\"}");
            } else {
                send_http_response(client_fd, 500, "application/json",
                                   "{\"error\":\"Device approval failed\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/fleet/:id/quarantine */
    else if (fleet_route_id(route_path, "quarantine", fleet_route_device, sizeof(fleet_route_device)) == 0 &&
             strcmp(method, "POST") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_FLEET_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Fleet mutation permission required\"}");
        } else {
            char dev_id[128] = {0};
            snprintf(dev_id, sizeof(dev_id), "%s", fleet_route_device);
            char reason[256] = {0};
            parse_json_string(req_body, "reason", reason, sizeof(reason));
            if (!dev_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"device_id required in path\"}");
            } else if (platform_quarantine_device(dev_id, reason[0] ? reason : "admin_action", sess.user_id) == 0) {
                send_http_response(client_fd, 200, "application/json",
                                   "{\"status\":\"quarantined\"}");
            } else {
                send_http_response(client_fd, 500, "application/json",
                                   "{\"error\":\"Quarantine failed\"}");
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* POST /api/v1/admin/fleet/:id/assign -> Assign a device to an exam */
    else if (fleet_route_id(route_path, "assign", fleet_route_device, sizeof(fleet_route_device)) == 0 &&
             strcmp(method, "POST") == 0) {
        const char *prefix[] = { "Bearer " };
        const char *tok = strncmp(auth_header, prefix[0], sizeof(prefix[0]) - 1) == 0
                          ? auth_header + sizeof(prefix[0]) - 1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_FLEET_MUTATION, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Fleet mutation permission required\"}");
        } else {
            char exam_id[64] = {0};
            parse_json_string(req_body, "exam_id", exam_id, sizeof(exam_id));
            if (!exam_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_id is required\"}");
            } else if (platform_assign_device_to_exam(fleet_route_device, exam_id, sess.user_id) == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"assigned\",\"device_id\":\"%s\",\"exam_id\":\"%s\"}",
                         fleet_route_device, exam_id);
                send_http_response(client_fd, 200, "application/json", resp);
            } else {
                char resp[640];
                snprintf(resp, sizeof(resp), "{\"error\":\"%s\"}", platform_last_error());
                send_http_response(client_fd, 409, "application/json", resp);
            }
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* GET /api/v1/admin/releases -> Software releases */
    else if (strcmp(route_path, "/api/v1/admin/releases") == 0 && strcmp(method, "GET") == 0) {
        static const char prefix[] = "Bearer ";
        const char *tok = strncmp(auth_header, prefix, sizeof(prefix)-1) == 0
                          ? auth_header + sizeof(prefix)-1 : NULL;
        auth_session_t sess; memset(&sess, 0, sizeof(sess));
        if (!tok || admin_auth_store_authorize(tok, AUTH_PERM_READ, &sess) != 0) {
            send_http_response(client_fd, 403, "application/json", "{\"error\":\"Auth required\"}");
        } else {
            static char rel_buf[65536];
            if (platform_get_releases_json(rel_buf, sizeof(rel_buf)) == 0)
                send_http_response(client_fd, 200, "application/json", rel_buf);
            else
                send_http_response(client_fd, 503, "application/json",
                                   "{\"error\":\"Releases unavailable\"}");
        }
        OPENSSL_cleanse(&sess, sizeof(sess));
    }
    /* =====================================================================
     * Phase 5: behaviour evidence, variant delivery and post-exam viva.
     * Every route binds the candidate identity to the authenticated session
     * token; client-supplied candidate identifiers are never trusted.
     * ===================================================================== */
    else if (strcmp(route_path, "/api/v1/behaviour/events") == 0 && strcmp(method, "POST") == 0) {
        const char *candidate_token = bearer_token(auth_header);
        char candidate_id[64] = {0};
        if (!candidate_token ||
            !ctrl_candidate_session_identity(auth_header, candidate_id, sizeof(candidate_id))) {
            send_http_response(client_fd, 401, "application/json",
                               "{\"error\":\"Valid candidate bearer token required\"}");
        } else {
            behaviour_raw_input_t in;
            memset(&in, 0, sizeof(in));
            parse_json_string(req_body, "exam_id", in.exam_id, sizeof(in.exam_id));
            in.question_id = parse_json_int(req_body, "question_id", -1);
            int64_t presented = 0, first_input = 0, submitted = 0;
            int has_presented = parse_json_int64(req_body, "question_presented_server_ts_ms", &presented) == 0;
            int has_first = parse_json_int64(req_body, "first_input_server_ts_ms", &first_input) == 0;
            int has_submitted = parse_json_int64(req_body, "answer_submitted_server_ts_ms", &submitted) == 0;
            in.question_presented_server_ts_ms = has_presented ? presented : 0;
            in.first_input_server_ts_ms = has_first ? first_input : 0;
            in.answer_submitted_server_ts_ms = has_submitted ? submitted : 0;
            in.question_char_length = parse_json_int(req_body, "question_char_length", 0);
            in.edit_count = parse_json_int(req_body, "edit_count", 0);

            int interval_count = parse_json_int_array(req_body, "typing_intervals_ms",
                                                      in.typing_intervals_ms, 256);
            if (interval_count < 0) interval_count = 0;
            in.typing_interval_count = interval_count;

            double value = 0.0;
            in.focus_fraction = parse_json_double(req_body, "focus_fraction", &value) == 0
                                ? (float)value : 0.0f;
            in.gaze_fraction = parse_json_double(req_body, "gaze_fraction", &value) == 0
                               ? (float)value : 0.0f;
            in.gaze_confidence_pct = parse_json_int(req_body, "gaze_confidence_pct", -1);
            in.camera_available = parse_json_int(req_body, "camera_available", 0);
            in.question_score = parse_json_double(req_body, "question_score", &value) == 0
                                ? (float)value : -1.0f;
            in.question_max_marks = parse_json_int(req_body, "question_max_marks", 0);
            snprintf(in.session_id, sizeof(in.session_id), "%s", candidate_token);
            snprintf(in.candidate_id, sizeof(in.candidate_id), "%s", candidate_id);

            if (in.question_id < 0 || !in.exam_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_id and a non-negative question_id are required\"}");
            } else {
                behaviour_feature_record_t record;
                if (behaviour_ingest_question(&in, &record) != 0) {
                    send_http_response(client_fd, 409, "application/json",
                                       "{\"error\":\"BEHAVIOUR_SOURCE_EVENT_UNVERIFIED\"}");
                } else {
                    char resp[512];
                    snprintf(resp, sizeof(resp),
                             "{\"status\":\"FEATURES_INGESTED\",\"session_id\":\"%s\","
                             "\"question_id\":%d,\"f1_quality\":%d,\"f2_quality\":%d,"
                             "\"f3_quality\":%d,\"f4_quality\":%d,\"f5_quality\":%d,\"f6_quality\":%d}",
                             candidate_token, in.question_id, (int)record.f1_quality,
                             (int)record.f2_quality, (int)record.f3_quality,
                             (int)record.f4_quality, (int)record.f5_quality,
                             (int)record.f6_quality);
                    send_http_response(client_fd, 200, "application/json", resp);
                }
            }
        }
    }
    else if (strcmp(route_path, "/api/v1/behaviour/practice") == 0 && strcmp(method, "POST") == 0) {
        const char *candidate_token = bearer_token(auth_header);
        char candidate_id[64] = {0};
        if (!candidate_token ||
            !ctrl_candidate_session_identity(auth_header, candidate_id, sizeof(candidate_id))) {
            send_http_response(client_fd, 401, "application/json",
                               "{\"error\":\"Valid candidate bearer token required\"}");
        } else {
            char practice_session_id[128] = {0};
            parse_json_string(req_body, "practice_session_id", practice_session_id,
                              sizeof(practice_session_id));
            if (!practice_session_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"practice_session_id is required\"}");
            } else {
                char reason[128] = {0};
                int rc = behaviour_record_practice_quiz(candidate_id, practice_session_id,
                                                        reason, sizeof(reason));
                int count = behaviour_get_practice_count(candidate_id);
                char resp[384];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"%s\",\"candidate_id\":\"%s\","
                         "\"eligible_count\":%d,\"minimum_required\":%d%s%s%s}",
                         rc == 0 ? "RECORDED" : "NOT_ELIGIBLE",
                         candidate_id, count, BEHAVIOUR_MIN_PRACTICE_QUIZZES,
                         reason[0] ? ",\"reason\":\"" : "",
                         reason[0] ? reason : "",
                         reason[0] ? "\"" : "");
                send_http_response(client_fd, rc == 0 ? 200 : 409,
                                   "application/json", resp);
            }
        }
    }
    else if (strcmp(route_path, "/api/v1/behaviour/baseline") == 0 && strcmp(method, "GET") == 0) {
        char requested_candidate[64] = {0};
        char authenticated_candidate[64] = {0};
        int is_reviewer = reviewer_authorized(auth_header) ||
                          admin_route_authorized(auth_header, AUTH_PERM_READ);
        int is_candidate = candidate_authorized(auth_header, authenticated_candidate,
                                                sizeof(authenticated_candidate));
        if (!is_reviewer && !is_candidate) {
            send_http_response(client_fd, 401, "application/json",
                               "{\"error\":\"Candidate or reviewer authentication required\"}");
        } else if (parse_query_id(path, "candidate_id", requested_candidate,
                                  sizeof(requested_candidate)) != 0) {
            if (is_candidate) {
                snprintf(requested_candidate, sizeof(requested_candidate), "%s",
                         authenticated_candidate);
            } else {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"candidate_id is required\"}");
                goto p5_baseline_done;
            }
        } else if (is_candidate && !is_reviewer &&
                   strcmp(requested_candidate, authenticated_candidate) != 0) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Candidates may only read their own baseline\"}");
        } else {
            char resp[8192];
            int rc = behaviour_export_baseline_json(requested_candidate, resp, sizeof(resp));
            send_http_response(client_fd, rc == 0 ? 200 : 200,
                               "application/json", resp);
        }
p5_baseline_done:
        ;
    }
    else if (strcmp(route_path, "/api/v1/behaviour/score/compute") == 0 && strcmp(method, "POST") == 0) {
        const char *candidate_token = bearer_token(auth_header);
        char candidate_id[64] = {0};
        if (!candidate_token ||
            !ctrl_candidate_session_identity(auth_header, candidate_id, sizeof(candidate_id))) {
            send_http_response(client_fd, 401, "application/json",
                               "{\"error\":\"Valid candidate bearer token required\"}");
        } else {
            char exam_id[128] = {0};
            parse_json_string(req_body, "exam_id", exam_id, sizeof(exam_id));
            if (!exam_id[0]) {
                /* No caller-supplied identity: fall back to the provisioned
                   examination identity. Never fabricate a default exam id. */
                if (config_active_exam_id(exam_id, sizeof(exam_id)) != 0) {
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"EXAM_IDENTITY_NOT_PROVISIONED\"}");
                    goto p5_score_done;
                }
            }
            behaviour_risk_score_t score;
            (void)behaviour_compute_risk_score(candidate_token, candidate_id, exam_id, &score);
            char resp[8192];
            if (behaviour_export_score_json(candidate_token, resp, sizeof(resp)) != 0) {
                snprintf(resp, sizeof(resp),
                         "{\"session_id\":\"%s\",\"candidate_id\":\"%s\","
                         "\"risk_score\":-1,\"confidence_status\":\"SCORE_INSUFFICIENT_EVIDENCE\"}",
                         candidate_token, candidate_id);
            }
            send_http_response(client_fd, 200, "application/json", resp);
        }
p5_score_done:
        ;
    }
    else if (strcmp(route_path, "/api/v1/behaviour/features") == 0 && strcmp(method, "GET") == 0) {
        if (!reviewer_authorized(auth_header) &&
            !admin_route_authorized(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Reviewer authentication required\"}");
        } else {
            char session_id[128] = {0};
            if (parse_query_id(path, "session_id", session_id, sizeof(session_id)) != 0) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"session_id is required\"}");
            } else {
                char resp[16384];
                if (behaviour_export_features_json(session_id, resp, sizeof(resp)) != 0) {
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"BEHAVIOUR_STORE_UNAVAILABLE\"}");
                } else {
                    send_http_response(client_fd, 200, "application/json", resp);
                }
            }
        }
    }
    else if (strcmp(route_path, "/api/v1/exam/variant") == 0 && strcmp(method, "GET") == 0) {
        char candidate_id[64] = {0};
        if (!candidate_authorized(auth_header, candidate_id, sizeof(candidate_id))) {
            send_http_response(client_fd, 401, "application/json",
                               "{\"error\":\"Valid candidate bearer token required\"}");
        } else {
            question_template_t tmpl;
            question_variant_t variant;
            char exam_id[128] = {0};
            if (config_active_exam_id(exam_id, sizeof(exam_id)) != 0) {
                /* No provisioned examination identity: refuse to fabricate one. */
                send_http_response(client_fd, 503, "application/json",
                                   "{\"error\":\"EXAM_IDENTITY_NOT_PROVISIONED\"}");
            } else if (variant_get_template(NULL, &tmpl) != 0 ||
                variant_generate(candidate_id, exam_id, &tmpl, &variant) != 0) {
                send_http_response(client_fd, 503, "application/json",
                                   "{\"error\":\"VARIANT_GENERATION_FAILED\"}");
            } else {
                char resp[8192];
                if (variant_export_candidate_json(variant.variant_id, resp,
                                                  sizeof(resp)) != 0) {
                    send_http_response(client_fd, 503, "application/json",
                                       "{\"error\":\"VARIANT_NOT_AVAILABLE\"}");
                } else {
                    send_http_response(client_fd, 200, "application/json", resp);
                }
            }
        }
    }
    else if (strcmp(route_path, "/api/v1/reviewer/variant") == 0 && strcmp(method, "GET") == 0) {
        if (!reviewer_authorized(auth_header) &&
            !admin_route_authorized(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Reviewer authentication required\"}");
        } else {
            char variant_id[64] = {0};
            if (parse_query_id(path, "variant_id", variant_id, sizeof(variant_id)) != 0) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"variant_id is required\"}");
            } else {
                char resp[8192];
                if (variant_export_reviewer_json(variant_id, resp, sizeof(resp)) != 0) {
                    send_http_response(client_fd, 404, "application/json",
                                       "{\"error\":\"VARIANT_NOT_FOUND\"}");
                } else {
                    send_http_response(client_fd, 200, "application/json", resp);
                }
            }
        }
    }
    else if (strcmp(route_path, "/api/v1/reviewer/watermark/trace") == 0 && strcmp(method, "POST") == 0) {
        if (!reviewer_authorized(auth_header) &&
            !admin_route_authorized(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Reviewer authentication required\"}");
        } else {
            char fragment[256] = {0};
            parse_json_string(req_body, "watermark_fragment", fragment, sizeof(fragment));
            if (!fragment[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"watermark_fragment is required\"}");
            } else {
                char candidate_ref[64] = {0}, variant_id[64] = {0};
                if (variant_trace_watermark(fragment, candidate_ref, sizeof(candidate_ref),
                                            variant_id, sizeof(variant_id)) != 0) {
                    send_http_response(client_fd, 404, "application/json",
                                       "{\"status\":\"NOT_FOUND\",\"error\":\"Watermark is not traceable\"}");
                } else {
                    char resp[384];
                    snprintf(resp, sizeof(resp),
                             "{\"status\":\"TRACED\",\"candidate_ref\":\"%s\","
                             "\"variant_id\":\"%s\"}", candidate_ref, variant_id);
                    send_http_response(client_fd, 200, "application/json", resp);
                }
            }
        }
    }
    else if (strcmp(route_path, "/api/v1/viva/generate") == 0 && strcmp(method, "POST") == 0) {
        const char *candidate_token = bearer_token(auth_header);
        char authenticated_candidate[64] = {0};
        if (!candidate_token ||
            !ctrl_candidate_session_identity(auth_header, authenticated_candidate,
                                             sizeof(authenticated_candidate))) {
            send_http_response(client_fd, 401, "application/json",
                               "{\"error\":\"Valid candidate bearer token required\"}");
        } else {
            char exam_id[128] = {0}, receipt[65] = {0};
            char requested_candidate[64] = {0};
            char submitted_candidate[64] = {0};
            char question_context[4096] = {0}, answer_context[4096] = {0};
            parse_json_string(req_body, "candidate_id", requested_candidate,
                              sizeof(requested_candidate));
            parse_json_string(req_body, "exam_id", exam_id, sizeof(exam_id));
            parse_json_string(req_body, "submission_receipt_hash", receipt, sizeof(receipt));
            if (requested_candidate[0] &&
                strcmp(requested_candidate, authenticated_candidate) != 0) {
                send_http_response(client_fd, 403, "application/json",
                                   "{\"error\":\"Candidate identity mismatch\"}");
            } else if (!exam_id[0] || !receipt[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"exam_id and submission_receipt_hash are required\"}");
            } else if (exam_engine_get_submitted_context(
                           candidate_token, receipt, submitted_candidate,
                           sizeof(submitted_candidate), question_context,
                           sizeof(question_context), answer_context,
                           sizeof(answer_context)) != 0) {
                /* Viva context is never accepted from the client. It must be
                   the server-held, receipt-bound submission. */
                send_http_response(client_fd, 409, "application/json",
                                   "{\"error\":\"VIVA_SUBMISSION_NOT_FOUND_OR_RECEIPT_MISMATCH\"}");
            } else if (strcmp(submitted_candidate, authenticated_candidate) != 0) {
                send_http_response(client_fd, 403, "application/json",
                                   "{\"error\":\"Submitted work does not belong to this candidate\"}");
            } else {
                viva_generation_t generation;
                int rc = viva_generate(candidate_token, authenticated_candidate, exam_id,
                                       receipt, question_context, answer_context,
                                       &generation);
                if (rc != 0) {
                    char resp[768];
                    snprintf(resp, sizeof(resp),
                             "{\"status\":\"%s\",\"viva_id\":\"%s\","
                             "\"error\":\"%s\"}",
                             generation.status_str[0] ? generation.status_str
                                                      : "VIVA_GENERATION_FAILED",
                             generation.viva_id,
                             generation.status_str[0] ? generation.status_str
                                                      : "VIVA_GENERATION_FAILED");
                    send_http_response(client_fd, 503, "application/json", resp);
                } else {
                    char resp[16384];
                    if (viva_export_candidate_json(generation.viva_id,
                                                   authenticated_candidate,
                                                   resp, sizeof(resp)) != 0) {
                        send_http_response(client_fd, 503, "application/json",
                                           "{\"error\":\"VIVA_EXPORT_FAILED\"}");
                    } else {
                        send_http_response(client_fd, 200, "application/json", resp);
                    }
                }
            }
        }
    }
    else if (strcmp(route_path, "/api/v1/viva/response") == 0 && strcmp(method, "POST") == 0) {
        char authenticated_candidate[64] = {0};
        if (!candidate_authorized(auth_header, authenticated_candidate,
                                  sizeof(authenticated_candidate))) {
            send_http_response(client_fd, 401, "application/json",
                               "{\"error\":\"Valid candidate bearer token required\"}");
        } else {
            char viva_id[64] = {0}, question_id[64] = {0};
            char response_text[4096] = {0}, requested_candidate[64] = {0};
            parse_json_string(req_body, "viva_id", viva_id, sizeof(viva_id));
            parse_json_string(req_body, "question_id", question_id, sizeof(question_id));
            parse_json_string(req_body, "response_text", response_text,
                              sizeof(response_text));
            parse_json_string(req_body, "candidate_id", requested_candidate,
                              sizeof(requested_candidate));
            if (requested_candidate[0] &&
                strcmp(requested_candidate, authenticated_candidate) != 0) {
                send_http_response(client_fd, 403, "application/json",
                                   "{\"error\":\"Candidate identity mismatch\"}");
            } else if (!viva_id[0] || !question_id[0] || !response_text[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"viva_id, question_id and response_text are required\"}");
            } else {
                viva_response_t response;
                int rc = viva_submit_response(viva_id, question_id,
                                              authenticated_candidate,
                                              response_text, &response);
                if (rc == 0) {
                    char resp[384];
                    snprintf(resp, sizeof(resp),
                             "{\"status\":\"RESPONSE_RECORDED\",\"response_id\":\"%s\","
                             "\"viva_id\":\"%s\",\"question_id\":\"%s\"}",
                             response.response_id, viva_id, question_id);
                    send_http_response(client_fd, 200, "application/json", resp);
                } else if (rc == -2) {
                    send_http_response(client_fd, 409, "application/json",
                                       "{\"status\":\"DUPLICATE_REJECTED\"}");
                } else {
                    send_http_response(client_fd, 403, "application/json",
                                       "{\"status\":\"REJECTED\",\"error\":\"Viva response is not permitted\"}");
                }
            }
        }
    }
    else if (strcmp(route_path, "/api/v1/reviewer/viva") == 0 && strcmp(method, "GET") == 0) {
        if (!reviewer_authorized(auth_header) &&
            !admin_route_authorized(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Reviewer authentication required\"}");
        } else {
            char viva_id[64] = {0};
            if (parse_query_id(path, "viva_id", viva_id, sizeof(viva_id)) != 0) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"viva_id is required\"}");
            } else {
                char resp[16384];
                if (viva_export_reviewer_json(viva_id, resp, sizeof(resp)) != 0) {
                    send_http_response(client_fd, 404, "application/json",
                                       "{\"error\":\"VIVA_NOT_FOUND\"}");
                } else {
                    send_http_response(client_fd, 200, "application/json", resp);
                }
            }
        }
    }
    else if (strcmp(route_path, "/api/v1/reviewer/viva/decide") == 0 && strcmp(method, "POST") == 0) {
        if (!reviewer_authorized(auth_header) &&
            !admin_route_authorized(auth_header, AUTH_PERM_READ)) {
            send_http_response(client_fd, 403, "application/json",
                               "{\"error\":\"Reviewer authentication required\"}");
        } else {
            char viva_id[64] = {0}, reviewer_id[64] = {0}, reason[32] = {0};
            char rationale[1024] = {0};
            parse_json_string(req_body, "viva_id", viva_id, sizeof(viva_id));
            parse_json_string(req_body, "reviewer_id", reviewer_id, sizeof(reviewer_id));
            parse_json_string(req_body, "reason_code", reason, sizeof(reason));
            parse_json_string(req_body, "written_rationale", rationale, sizeof(rationale));
            int state = parse_json_int(req_body, "state", -1);
            double final_score = -1.0;
            (void)parse_json_double(req_body, "final_score", &final_score);
            if (final_score > 1.0 && final_score <= 100.0) final_score /= 100.0;
            if (!viva_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"viva_id is required\"}");
            } else if (state < 0 || state > 3 || final_score < 0.0 || final_score > 1.0) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"state must be 0-3 and final_score must be 0-1 or 0-100\"}");
            } else if (!reviewer_id[0]) {
                send_http_response(client_fd, 400, "application/json",
                                   "{\"error\":\"reviewer_id is required\"}");
            } else {
                reviewer_decision_t decision;
                if (viva_reviewer_decide(viva_id, reviewer_id, (review_state_t)state,
                                         final_score, reason, rationale, &decision) == 0) {
                    char resp[512];
                    snprintf(resp, sizeof(resp),
                             "{\"status\":\"DECISION_RECORDED\",\"decision_id\":\"%s\","
                             "\"viva_id\":\"%s\",\"state\":\"%s\"}",
                             decision.decision_id, viva_id, decision.state_str);
                    send_http_response(client_fd, 200, "application/json", resp);
                } else {
                    send_http_response(client_fd, 409, "application/json",
                                       "{\"error\":\"Decision rejected\"}");
                }
            }
        }
    }
    else {
        /* --- ExamOS Console controller dispatch (fallback for /api/v1/ routes) --- */
        if (strncmp(route_path, "/api/v1/", 8) == 0) {
            char origin[512] = {0};
            /* Re-extract origin for CORS on controller responses */
            {
                const char *headers_end = strstr(buffer, "\r\n\r\n");
                const char *line = strstr(buffer, "\r\n");
                if (headers_end && line && line < headers_end) {
                    line += 2;
                    while (line < headers_end) {
                        const char *line_end = strstr(line, "\r\n");
                        if (!line_end || line_end > headers_end) break;
                        const char *colon = memchr(line, ':', (size_t)(line_end - line));
                        if (colon && (size_t)(colon - line) == sizeof("Origin") - 1 &&
                            strncasecmp(line, "Origin", sizeof("Origin") - 1) == 0) {
                            const char *v = colon + 1;
                            while (v < line_end && (*v == ' ' || *v == '\t')) v++;
                            size_t vlen = (size_t)(line_end - v);
                            if (vlen > 0 && vlen < sizeof(origin)) {
                                memcpy(origin, v, vlen);
                                origin[vlen] = '\0';
                            }
                            break;
                        }
                        line = line_end + 2;
                    }
                }
            }
            int cors_ok = cors_origin_allowed(origin);
            char extra[700] = {0};
            if (cors_ok && origin[0]) {
                int cl = snprintf(extra, sizeof(extra),
                    "Access-Control-Allow-Origin: %s\r\n"
                    "Vary: Origin\r\n"
                    "Access-Control-Allow-Credentials: true\r\n",
                    origin);
                if (cl < 0 || (size_t)cl >= sizeof(extra)) extra[0] = '\0';
            }

            /* Auth routes */
            if (strcmp(route_path, "/api/v1/admin/login") == 0 && strcmp(method, "POST") == 0) {
                auth_admin_login(client_fd, req_body, origin, extra, sizeof(extra));
                goto client_done;
            }
            if (strcmp(route_path, "/api/v1/admin/logout") == 0 && strcmp(method, "POST") == 0) {
                auth_admin_logout(client_fd, auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }
            if (strcmp(route_path, "/api/v1/admin/session") == 0 && strcmp(method, "GET") == 0) {
                auth_admin_session(client_fd, auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }
            if ((strcmp(route_path, "/api/v1/admin/mfa/setup") == 0 ||
                 strcmp(route_path, "/api/v1/auth/mfa/setup") == 0) && strcmp(method, "POST") == 0) {
                auth_mfa_setup(client_fd, req_body, auth_header, enrollment_token, origin, extra, sizeof(extra));
                goto client_done;
            }
            if ((strcmp(route_path, "/api/v1/admin/mfa/confirm") == 0 ||
                 strcmp(route_path, "/api/v1/auth/mfa/confirm") == 0) && strcmp(method, "POST") == 0) {
                auth_mfa_confirm(client_fd, req_body, auth_header, enrollment_token, origin, extra, sizeof(extra));
                goto client_done;
            }
            if ((strcmp(route_path, "/api/v1/admin/recovery/reset") == 0 ||
                 strcmp(route_path, "/api/v1/auth/recovery/reset") == 0) && strcmp(method, "POST") == 0) {
                auth_recovery_reset(client_fd, req_body, origin, extra, sizeof(extra));
                goto client_done;
            }
            if ((strcmp(route_path, "/api/v1/admin/password/change") == 0 ||
                 strcmp(route_path, "/api/v1/auth/password/change") == 0) && strcmp(method, "POST") == 0) {
                auth_change_password(client_fd, req_body, auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }
            if (strcmp(route_path, "/api/v1/candidate/login") == 0 && strcmp(method, "POST") == 0) {
                if (!is_examos_kiosk_request(client_fd, buffer, origin)) {
                    send_http_response_ex(client_fd, 403, "application/json",
                        "{\"status\":\"FAIL\",\"error\":\"ACCESS_DENIED: Candidate portal is strictly restricted to the ExamOS secure bootable kiosk operating system. External operating systems and browsers are prohibited.\"}",
                        extra);
                    goto client_done;
                }
                auth_candidate_login(client_fd, req_body, origin, extra, sizeof(extra));
                goto client_done;
            }
            if (strcmp(route_path, "/api/v1/candidate/logout") == 0 && strcmp(method, "POST") == 0) {
                auth_candidate_logout(client_fd, auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }
            if (strcmp(route_path, "/api/v1/candidate/checkin/status") == 0 &&
                strcmp(method, "POST") == 0) {
                if (!is_examos_kiosk_request(client_fd, buffer, origin)) {
                    send_http_response_ex(client_fd, 403, "application/json",
                        "{\"status\":\"FAIL\",\"error\":\"Candidate check-in polling is restricted to the ExamOS kiosk.\"}",
                        extra);
                    goto client_done;
                }
                auth_candidate_workflow_handle(client_fd, method, route_path, req_body,
                                               auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Institution routes */
            if (strncmp(route_path, "/api/v1/admin/institutions", 26) == 0 ||
                strncmp(route_path, "/api/v1/admin/institution-applications", 38) == 0 ||
                strncmp(route_path, "/api/v1/institutions/apply", 26) == 0 ||
                strncmp(route_path, "/api/v1/admin/agreements", 24) == 0 ||
                strncmp(route_path, "/api/v1/admin/licenses", 22) == 0 ||
                strncmp(route_path, "/api/v1/admin/deployments", 25) == 0 ||
                strncmp(route_path, "/api/v1/admin/campuses", 22) == 0 ||
                strncmp(route_path, "/api/v1/admin/centers", 21) == 0 ||
                strncmp(route_path, "/api/v1/admin/departments", 25) == 0 ||
                strncmp(route_path, "/api/v1/admin/staff", 19) == 0) {
                /* Pass original path so inst_query_param can read query parameters. */
                institution_handle(client_fd, method, path, req_body,
                                   auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Student Management System routes (Module 5) */
            if (strncmp(route_path, "/api/v1/students", 16) == 0 ||
                strncmp(route_path, "/api/v1/admin/students", 22) == 0 ||
                strncmp(route_path, "/api/v1/student-enrollments", 27) == 0 ||
                strncmp(route_path, "/api/v1/student-correction-requests", 35) == 0 ||
                strncmp(route_path, "/api/v1/student-imports", 23) == 0) {
                student_handle(client_fd, method, route_path, req_body,
                               auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Registration & Eligibility routes (Module 10) */
            if (strncmp(route_path, "/api/v1/registrations", 21) == 0 ||
                strncmp(route_path, "/api/v1/registration-imports", 28) == 0 ||
                (strncmp(route_path, "/api/v1/examinations/", 21) == 0 &&
                 (strstr(route_path, "/registrations") ||
                  strstr(route_path, "/rules") ||
                  strstr(route_path, "/roster/publish") ||
                  strstr(route_path, "/eligibility/")))) {
                registration_handle(client_fd, method, route_path, req_body,
                                    auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Exam check-in and one-time desk-token workflows */
            if (strncmp(route_path, "/api/v1/examinations/", 21) == 0 &&
                (strstr(route_path, "/candidate-tokens") ||
                 strstr(route_path, "/candidate-pins") ||
                 strstr(route_path, "/candidate-checkins"))) {
                auth_candidate_workflow_handle(client_fd, method, route_path, req_body,
                                               auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Exam Session Management routes (Module 11) */
            if (strncmp(route_path, "/api/v1/exam-sessions", 21) == 0 ||
                (strncmp(route_path, "/api/v1/examinations/", 21) == 0 &&
                 strstr(route_path, "/sessions"))) {
                char candidate_id[64] = {0};
                if (ctrl_candidate_session_identity(auth_header, candidate_id,
                                                    sizeof(candidate_id)) &&
                    !is_examos_kiosk_request(client_fd, buffer, origin)) {
                    send_http_response_ex(client_fd, 403, "application/json",
                        "{\"status\":\"FAIL\",\"error\":\"Candidate exam sessions are restricted to the managed ExamOS kiosk\"}",
                        extra);
                    goto client_done;
                }
                exam_session_handle(client_fd, method, route_path, req_body,
                                    auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Exam routes */
            if (strncmp(route_path, "/api/v1/admin/exams", 19) == 0 ||
                strncmp(route_path, "/api/v1/platform/exams", 22) == 0 ||
                strncmp(route_path, "/api/v1/examinations", 20) == 0) {
                exam_handle(client_fd, method, route_path, req_body,
                            auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Candidate routes */
            roster_fallthrough:
            if (strncmp(route_path, "/api/v1/admin/roster", 20) == 0 ||
                strncmp(route_path, "/api/v1/platform/exams/", 23) == 0) {
                candidate_handle(client_fd, method, route_path, req_body,
                                 auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Device Trust, Registration & Attestation routes (Module 13) */
            if (strncmp(route_path, "/api/v1/devices", 15) == 0 ||
                strncmp(route_path, "/api/v1/device-trust-policies", 27) == 0 ||
                strcmp(route_path, "/api/v1/exam-launch/authorize") == 0) {
                device_trust_handle(client_fd, method, route_path, req_body,
                                    auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Secure OS Release, Updates, Rollback & Deployment routes (Module 14) */
            if (strncmp(route_path, "/api/v1/os/releases", 19) == 0 ||
                strncmp(route_path, "/api/v1/os/deployments", 22) == 0 ||
                strncmp(route_path, "/api/v1/os/devices", 18) == 0) {
                os_release_handle(client_fd, method, route_path, req_body,
                                  auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Device/fleet/heartbeat routes */
            if (strncmp(route_path, "/api/v1/admin/fleet", 19) == 0 ||
                strcmp(route_path, "/api/v1/heartbeat") == 0) {
                device_handle(client_fd, method, route_path, req_body,
                              auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* TPM/attestation routes */
            if (strncmp(route_path, "/api/v1/attestation", 19) == 0 ||
                strcmp(route_path, "/api/v1/agent/exam-attestation/pending") == 0) {
                tpm_handle(client_fd, method, route_path, req_body,
                           auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Session/proctoring/consent/key-release routes */
            if (strncmp(route_path, "/api/v1/exam", 10) == 0 ||
                strcmp(route_path, "/api/v1/consent") == 0 ||
                strncmp(route_path, "/api/v1/proctoring", 18) == 0 ||
                strncmp(route_path, "/api/v1/second-camera", 21) == 0) {
                session_handle(client_fd, method, route_path, req_body,
                               auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Release revocation routes */
            if (strncmp(route_path, "/api/v1/admin/revoke", 20) == 0) {
                release_handle(client_fd, method, route_path, req_body,
                               auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Campus, center, and organization routes */
            if (strncmp(route_path, "/api/v1/admin/campuses", 22) == 0 ||
                strncmp(route_path, "/api/v1/admin/campus-approvals", 33) == 0 ||
                strncmp(route_path, "/api/v1/admin/campus-user-assignments", 38) == 0 ||
                strncmp(route_path, "/api/v1/admin/campus-os-policies", 33) == 0 ||
                strncmp(route_path, "/api/v1/admin/campus-capacity", 31) == 0 ||
                strncmp(route_path, "/api/v1/admin/org/change-history", 33) == 0) {
                institution_handle(client_fd, method, path, req_body,
                                   auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Department routes */
            if (strncmp(route_path, "/api/v1/admin/departments", 25) == 0 ||
                strncmp(route_path, "/api/v1/admin/department-approvals", 36) == 0 ||
                strncmp(route_path, "/api/v1/admin/department-user-assignments", 42) == 0 ||
                strncmp(route_path, "/api/v1/admin/academic-programs", 33) == 0) {
                institution_handle(client_fd, method, path, req_body,
                                   auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Policy routes */
            if (strncmp(route_path, "/api/v1/admin/policies", 22) == 0) {
                policy_handle(client_fd, method, route_path, req_body,
                              auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* Reporting platform: must run before generic module routing so
             * /api/v1/reports does not fall through to the console stub. */
            if (strncmp(route_path, "/api/v1/reports", 15) == 0 &&
                (route_path[15] == '\0' || route_path[15] == '/')) {
                reports_handle(client_fd, method, path, req_body,
                               auth_header, origin, extra, sizeof(extra));
                goto client_done;
            }

            /* All remaining module routes */
            modules_handle(client_fd, method, route_path, req_body,
                           auth_header, origin, extra, sizeof(extra));
            goto client_done;
        }
        send_http_response(client_fd, 404, "application/json", "{\"error\":\"Not Found\"}");
    }

client_done:
#if defined(USE_OPENSSL_TLS)
    if (g_conn_ssl) {
        (void)SSL_shutdown(g_conn_ssl);
        SSL_free(g_conn_ssl);
        g_conn_ssl = NULL;
    }
#endif
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
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (argc > 1 && strcmp(argv[1], "--bootstrap-schema-only") == 0) {
        if (db_init(NULL) != 0) {
            fprintf(stderr, "[ExamOS-Server] FATAL: database pool initialization failed.\n");
            return 1;
        }
        if (db_create_schema() != 0) {
            fprintf(stderr, "[ExamOS-Server] FATAL: database schema creation failed.\n");
            db_shutdown();
            return 1;
        }
        db_shutdown();
        printf("[ExamOS-Server] Database base schema bootstrapped successfully.\n");
        return 0;
    }

    const char *tpm_mode = getenv("EXAMOS_TPM_MODE");
    if (!tpm_mode || (strcmp(tpm_mode, "development") != 0 && strcmp(tpm_mode, "production") != 0)) {
        fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_TPM_MODE must be explicitly development or production.\n");
        return 2;
    }
    const int production_mode = strcmp(tpm_mode, "production") == 0;
    g_production_mode = production_mode;

    /* Validate required secrets first — before any system or appliance check.
     * This ensures a missing secret always produces a diagnostic that names
     * the exact secret, regardless of deployment environment.  The appliance
     * check may exit early on its own error, but secrets must be checked
     * unconditionally so the startup-fail-closed test contract is preserved.
     */
    if (!valid_startup_secret("EXAMOS_AGENT_API_TOKEN", 1) ||
        !valid_startup_secret("EXAMOS_PROCTOR_API_TOKEN", 1) ||
        !valid_startup_secret("EXAMOS_EVENT_SIGNING_KEY", 1) ||
        !valid_startup_secret("EXAMOS_VARIANT_SECRET", 1) ||
        !valid_startup_secret("EXAMOS_LEDGER_HMAC_KEY", 1)) {
        return 2;
    }

    /* In production, forbid the development bypass before any system check. */
    const char *allow_unprovisioned = getenv("EXAMOS_ALLOW_UNPROVISIONED_DEV");
    if (production_mode && allow_unprovisioned && strcmp(allow_unprovisioned, "0") != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_ALLOW_UNPROVISIONED_DEV is forbidden in production mode.\n");
        return 2;
    }

    /* The exam key-encryption key seals released exam keys. It must be
       provisioned before the service can accept any attestation. */
    if (production_mode) {
        const char *kek = getenv("EXAMOS_EXAM_KEY_KEK");
        if (!kek || strlen(kek) < 32) {
            fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_EXAM_KEY_KEK must be provisioned with at least 32 characters in production mode.\n");
            return 2;
        }
        for (size_t i = 0; i < strlen(kek); i++) {
            if (isspace((unsigned char)kek[i]) || (unsigned char)kek[i] < 0x20) {
                fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_EXAM_KEY_KEK contains unsupported characters.\n");
                return 2;
            }
        }
    }

    /*
     * In production the service only runs on an ExamOS appliance. The
     * examination evidence, the attestation state and the sealed secrets
     * this server handles are meaningful only on a measured, Secure Boot
     * verified, dm-verity sealed image.
     */
    {
        char appliance_reason[256] = {0};
        if (examos_appliance_verify(appliance_reason, sizeof(appliance_reason)) != 0) {
            if (production_mode) {
                fprintf(stderr,
                        "[ExamOS-Server] FATAL: %s. This server only runs on an ExamOS appliance.\n",
                        appliance_reason);
                return 2;
            }
            fprintf(stderr,
                    "[ExamOS-Server] WARNING: %s. Development mode continues without the appliance posture.\n",
                    appliance_reason);
        }
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

    /* The ledger path is provisioned explicitly in production: a shared
       world-writable location (for example /tmp) cannot hold evidence. */
    const char *ledger_path = getenv("EXAMOS_LEDGER_PATH");
    if (!ledger_path || !*ledger_path) {
        if (production_mode) {
            fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_LEDGER_PATH must be provisioned in production mode.\n");
            return 2;
        }
        ledger_path = "var/examos-event-ledger.log";
    }
    const char *ledger_key = getenv("EXAMOS_LEDGER_HMAC_KEY");
    if (ledger_init(ledger_path, ledger_key) != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: evidence ledger is corrupt, truncated, unauthenticated, or unreadable; refusing startup.\n");
        return 1;
    }
    candidate_session_init();
    /* Replay the journal only after the in-memory session table is initialized. */
    if (session_store_init() != 0 && production_mode) {
        fprintf(stderr, "[ExamOS-Server] FATAL: session journal unavailable in production mode.\n");
        return 1;
    }
    exam_manager_init();
    exam_engine_init();

    /* --- ExamOS Console integration: PostgreSQL database --- */
    if (db_init(NULL) != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: database pool initialization failed.\n");
        return 1;
    }
    g_db_initialized = 1;
    if (db_create_schema() != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: database schema creation failed.\n");
        return 1;
    }

    /* --- ExamOS Console integration: audit hash chain --- */
    if (audit_init() != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: audit chain initialization failed.\n");
        return 1;
    }
    g_audit_initialized = 1;

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
    /* The platform data directory is provisioned, not compiled in. */
    const char *data_dir_env = getenv("EXAMOS_DATA_DIR");
    const char *platform_data_dir = (data_dir_env && data_dir_env[0]) ? data_dir_env : "/var/lib/examos";
    if (!development_mode && enterprise_platform_init(platform_data_dir) != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: PostgreSQL TLS connection or required schema unavailable; refusing service startup.\n");
        return 1;
    }
    if (!development_mode && attestation_store_init() != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: durable PostgreSQL attestation state is unavailable; refusing service startup.\n");
        admin_auth_store_shutdown();
        return 1;
    }
    if (ek_certificate_load_trust_anchors() != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: approved EK trust anchors are unavailable or invalid.\n");
        if (!development_mode) admin_auth_store_shutdown();
        return 1;
    }
    if (attestation_config_load_all(executable_path[0] ? executable_path : NULL) != 0) {
        fprintf(stderr, "[ExamOS-Server] FATAL: authenticated attestation registries are unavailable or invalid.\n");
        if (!development_mode) admin_auth_store_shutdown();
        return 1;
    }
    /* The browser policy catalog is provisioned deployment content. Without
       it an exam could not reference a real policy, so the service refuses
       to start rather than inventing one. */
    {
        const char *catalog_env = getenv("EXAMOS_BROWSER_POLICY_CATALOG");
        char catalog_path[1024] = {0};
        if (catalog_env && catalog_env[0]) {
            snprintf(catalog_path, sizeof(catalog_path), "%s", catalog_env);
        } else if (production_mode) {
            snprintf(catalog_path, sizeof(catalog_path), "%s",
                     "/etc/examos/browser_policies.json");
        } else if (executable_path[0]) {
            snprintf(catalog_path, sizeof(catalog_path), "%s/config/browser_policies.json",
                     executable_path);
        }
        if (!catalog_path[0] || policy_catalog_load(catalog_path) != 0) {
            fprintf(stderr, "[ExamOS-Server] FATAL: browser policy catalog is unavailable or invalid.\n");
            if (!development_mode) admin_auth_store_shutdown();
            return 1;
        }
    }
    const char *event_chain_path = getenv("EXAMOS_EVENT_CHAIN_PATH");
    event_chain_init(event_chain_path && event_chain_path[0]
        ? event_chain_path : "/var/log/examos/proctoring_events.log");
    second_camera_init();

    /* Phase 5 evidence engines. Their stores are provisioned directories; a
       failure to open them is fatal in production because an engine that
       cannot persist evidence must not accept requests. */
    if (e1_engine_init(NULL) != 0 ||
        behaviour_engine_init() != 0 ||
        variant_engine_init() != 0 ||
        viva_engine_init() != 0) {
        fprintf(stderr, "[ExamOS-Server] %s: Phase 5 evidence stores are unavailable.\n",
                production_mode ? "FATAL" : "WARNING");
        if (production_mode) {
            admin_auth_store_shutdown();
            return 1;
        }
    }

    /* Firewall state directory â€” provisioned via EXAMOS_FIREWALL_STATE_DIR. */
    {
        const char *fw_state_dir = getenv("EXAMOS_FIREWALL_STATE_DIR");
        if (fw_state_dir && fw_state_dir[0]) {
            if (firewall_init(fw_state_dir) != 0) {
                fprintf(stderr, "[ExamOS-Server] %s: firewall state directory unavailable.\n",
                        production_mode ? "FATAL" : "WARNING");
                if (production_mode) {
                    admin_auth_store_shutdown();
                    return 1;
                }
            }
        }
    }

    if (development_mode) {
        fprintf(stderr, "[ExamOS-Server] WARNING: local unprovisioned development mode enabled; production APIs remain unavailable.\n");
    } else {
        printf("[ExamOS-Server] Production posture active: Enterprise platform APIs, PostgreSQL stores, and hardware attestation ready.\n");
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

    /* Bind address is provisioned via EXAMOS_BIND_ADDR. Production defaults
     * to loopback only; development may bind to 0.0.0.0 when explicitly set.
     * Never bind to all interfaces in production without explicit opt-in. */
    const char *bind_addr_env = getenv("EXAMOS_BIND_ADDR");
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)server_port);

    if (bind_addr_env && bind_addr_env[0]) {
        if (strcmp(bind_addr_env, "0.0.0.0") == 0) {
            address.sin_addr.s_addr = htonl(INADDR_ANY);
        } else if (inet_pton(AF_INET, bind_addr_env, &address.sin_addr) <= 0) {
            fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_BIND_ADDR '%s' is not a valid IPv4 address.\n", bind_addr_env);
            close(server_fd);
            sem_destroy(&g_client_slots);
            if (!development_mode) admin_auth_store_shutdown();
            return 2;
        }
    } else {
        /* Default: loopback only. Production appliances terminate TLS at the
         * ingress proxy; the server itself is not exposed on the LAN. */
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    /* Optional in-process TLS. When EXAMOS_TLS_CERT and EXAMOS_TLS_KEY are
     * both provisioned, the server speaks HTTPS on the same listening socket.
     * Production deployments may terminate TLS at an ingress proxy instead. */
#if defined(USE_OPENSSL_TLS)
    const char *tls_cert = getenv("EXAMOS_TLS_CERT");
    const char *tls_key  = getenv("EXAMOS_TLS_KEY");
    if ((tls_cert && tls_cert[0]) || (tls_key && tls_key[0])) {
        if (!tls_cert || !tls_cert[0] || !tls_key || !tls_key[0]) {
            fprintf(stderr, "[ExamOS-Server] FATAL: EXAMOS_TLS_CERT and EXAMOS_TLS_KEY must both be set for TLS.\n");
            close(server_fd);
            sem_destroy(&g_client_slots);
            if (!development_mode) admin_auth_store_shutdown();
            return 2;
        }
        SSL_library_init();
        SSL_load_error_strings();
        g_tls_ctx = SSL_CTX_new(TLS_server_method());
        if (!g_tls_ctx) {
            fprintf(stderr, "[ExamOS-Server] FATAL: cannot create TLS context.\n");
            close(server_fd);
            sem_destroy(&g_client_slots);
            if (!development_mode) admin_auth_store_shutdown();
            return 1;
        }
        if (SSL_CTX_use_certificate_file(g_tls_ctx, tls_cert, SSL_FILETYPE_PEM) <= 0) {
            fprintf(stderr, "[ExamOS-Server] FATAL: cannot load TLS certificate '%s'.\n", tls_cert);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(g_tls_ctx);
            g_tls_ctx = NULL;
            close(server_fd);
            sem_destroy(&g_client_slots);
            if (!development_mode) admin_auth_store_shutdown();
            return 1;
        }
        if (SSL_CTX_use_PrivateKey_file(g_tls_ctx, tls_key, SSL_FILETYPE_PEM) <= 0) {
            fprintf(stderr, "[ExamOS-Server] FATAL: cannot load TLS private key '%s'.\n", tls_key);
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(g_tls_ctx);
            g_tls_ctx = NULL;
            close(server_fd);
            sem_destroy(&g_client_slots);
            if (!development_mode) admin_auth_store_shutdown();
            return 1;
        }
        if (!SSL_CTX_check_private_key(g_tls_ctx)) {
            fprintf(stderr, "[ExamOS-Server] FATAL: TLS private key does not match certificate.\n");
            SSL_CTX_free(g_tls_ctx);
            g_tls_ctx = NULL;
            close(server_fd);
            sem_destroy(&g_client_slots);
            if (!development_mode) admin_auth_store_shutdown();
            return 1;
        }

        struct stat key_stat;
        if (stat(tls_key, &key_stat) != 0 || !S_ISREG(key_stat.st_mode)) {
            fprintf(stderr, "[ExamOS-Server] FATAL: TLS private key is not a regular file.\n");
            SSL_CTX_free(g_tls_ctx);
            g_tls_ctx = NULL;
            close(server_fd);
            sem_destroy(&g_client_slots);
            if (!development_mode) admin_auth_store_shutdown();
            return 1;
        }
        if (!development_mode && (key_stat.st_mode & 0077)) {
            fprintf(stderr, "[ExamOS-Server] FATAL: TLS private key must not be readable by group or other.\n");
            SSL_CTX_free(g_tls_ctx);
            g_tls_ctx = NULL;
            close(server_fd);
            sem_destroy(&g_client_slots);
            if (!development_mode) admin_auth_store_shutdown();
            return 1;
        }

        SSL_CTX_set_min_proto_version(g_tls_ctx, TLS1_2_VERSION);
        SSL_CTX_set_options(g_tls_ctx,
                            SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                            SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
                            SSL_OP_NO_COMPRESSION);
        SSL_CTX_set_session_cache_mode(g_tls_ctx, SSL_SESS_CACHE_OFF);
        if (SSL_CTX_set_cipher_list(g_tls_ctx,
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256") != 1 ||
            SSL_CTX_set_ciphersuites(g_tls_ctx,
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
                "TLS_AES_128_GCM_SHA256") != 1) {
            fprintf(stderr, "[ExamOS-Server] FATAL: cannot install the approved TLS cipher policy.\n");
            SSL_CTX_free(g_tls_ctx);
            g_tls_ctx = NULL;
            close(server_fd);
            sem_destroy(&g_client_slots);
            if (!development_mode) admin_auth_store_shutdown();
            return 1;
        }
        g_tls_enabled = 1;
        printf("[ExamOS-Server] TLS enabled (cert=%s)\n", tls_cert);

        /* ISS-07: Optional Mutual TLS (mTLS) — client certificate verification.
         *
         * If EXAMOS_MTLS_CA_CERT is set to a PEM CA bundle path, the server
         * requires client certificates signed by that CA on every connection.
         * This prevents rogue hardware from submitting forged agent telemetry
         * using only a bearer token.
         *
         * Appliance client certificates must be:
         *   1. Issued by the provisioning CA whose root is in EXAMOS_MTLS_CA_CERT.
         *   2. Stored on the appliance under the TPM (sealed, not exportable).
         *   3. Presented during TLS handshake by libcurl on the agent side.
         *
         * When EXAMOS_MTLS_CA_CERT is absent, mTLS is not enforced and the
         * server falls back to bearer-token-only agent authentication.
         */
        const char *mtls_ca = getenv("EXAMOS_MTLS_CA_CERT");
        if (mtls_ca && mtls_ca[0]) {
            if (SSL_CTX_load_verify_locations(g_tls_ctx, mtls_ca, NULL) != 1) {
                fprintf(stderr, "[ExamOS-Server] FATAL: cannot load mTLS CA bundle '%s'.\n", mtls_ca);
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(g_tls_ctx);
                g_tls_ctx = NULL;
                close(server_fd);
                sem_destroy(&g_client_slots);
                if (!development_mode) admin_auth_store_shutdown();
                return 1;
            }
            /* Require peer certificate; fail handshake if absent or invalid. */
            SSL_CTX_set_verify(g_tls_ctx,
                               SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                               NULL /* use default verify callback */);
            /* Accept certificate chains up to 3 levels deep (root → intermediate → leaf). */
            SSL_CTX_set_verify_depth(g_tls_ctx, 3);
            fprintf(stderr, "[ExamOS-Server] mTLS enforced: client certificates required (CA: %s)\n", mtls_ca);
        } else {
            fprintf(stderr, "[ExamOS-Server] mTLS not configured (EXAMOS_MTLS_CA_CERT not set); "
                            "bearer-token-only agent authentication active.\n");
        }
    }
#endif

    /* Cleartext is only acceptable on loopback, or behind a verified edge-terminated
       TLS reverse proxy (EXAMOS_TLS_TERMINATED=1). Anything reachable from the
       network must be wrapped by TLS, either in-process, by a same-host
       ingress proxy that binds loopback, or terminated at the cloud ingress proxy. */
    const char *tls_term_env = getenv("EXAMOS_TLS_TERMINATED");
    int tls_terminated = (tls_term_env && (strcmp(tls_term_env, "1") == 0 || strcmp(tls_term_env, "true") == 0));

    if (address.sin_addr.s_addr != htonl(INADDR_LOOPBACK) && !g_tls_enabled && !tls_terminated) {
        if (production_mode) {
            fprintf(stderr, "[ExamOS-Server] FATAL: refusing a cleartext listener on a non-loopback address without in-process TLS or edge proxy.\n");
            close(server_fd);
            sem_destroy(&g_client_slots);
            if (!development_mode) admin_auth_store_shutdown();
            return 2;
        } else {
            fprintf(stderr, "[ExamOS-Server] NOTICE: cleartext listener bound to non-loopback in development mode for appliance testing.\n");
        }
    } else if (tls_terminated && !g_tls_enabled) {
        printf("[ExamOS-Server] Ingress TLS termination recognized: secure edge proxy forwards to internal listener.\n");
    }

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

        client_connection_t *conn = calloc(1, sizeof(*conn));
        if (!conn) {
            close(client_fd);
            continue;
        }
        conn->fd = client_fd;
#if defined(USE_OPENSSL_TLS)
        if (g_tls_enabled) {
            conn->ssl = SSL_new(g_tls_ctx);
            if (!conn->ssl || SSL_set_fd(conn->ssl, client_fd) != 1) {
                if (conn->ssl) SSL_free(conn->ssl);
                free(conn);
                close(client_fd);
                continue;
            }
        }
#endif
        if (sem_trywait(&g_client_slots) != 0) {
            if (!g_tls_enabled) {
                send_http_response(client_fd, 503, "application/json", "{\"error\":\"Server connection capacity reached\"}");
            }
#if defined(USE_OPENSSL_TLS)
            if (conn->ssl) SSL_free(conn->ssl);
#endif
            free(conn);
            close(client_fd);
            continue;
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, conn) != 0) {
#if defined(USE_OPENSSL_TLS)
            if (conn->ssl) SSL_free(conn->ssl);
#endif
            free(conn);
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
    session_store_close();
    printf("[ExamOS-Server] Clean shutdown complete.\n");
    return 0;
}
