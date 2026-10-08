#define _GNU_SOURCE
#include "include/ledger.h"
#include "include/risk_engine.h"
#include "include/exam_manager.h"
#include "include/config_manager.h"
#include "include/candidate_login.h"
#include "include/admin_dashboard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>

#define DEFAULT_SERVER_PORT 8000
#define BUFFER_SIZE 8192

static volatile sig_atomic_t g_server_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_server_running = 0;
}

static const char *status_text(int status_code) {
    switch (status_code) {
        case 200: return "OK";
        case 202: return "Accepted";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
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

static void parse_json_string(const char *buf, const char *key, char *out, size_t max_out) {
    out[0] = '\0';
    if (!buf || !key) return;

    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(buf, pattern);
    if (!pos) return;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == ':' || *pos == '\t') pos++;
    if (*pos == '\"') {
        pos++;
        size_t idx = 0;
        while (*pos && *pos != '\"' && idx + 1 < max_out) {
            out[idx++] = *pos++;
        }
        out[idx] = '\0';
    }
}

static int parse_json_int(const char *buf, const char *key, int default_val) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(buf, pattern);
    if (!pos) return default_val;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == ':' || *pos == '\t') pos++;
    return atoi(pos);
}

static void* handle_client(void *arg) {
    int client_fd = (int)(intptr_t)arg;
    char buffer[BUFFER_SIZE] = {0};

    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        close(client_fd);
        return NULL;
    }

    char method[16] = {0}, path[256] = {0};
    if (sscanf(buffer, "%15s %255s", method, path) != 2) {
        send_http_response(client_fd, 400, "application/json", "{\"error\":\"Malformed HTTP request\"}");
        close(client_fd);
        return NULL;
    }

    // Extract headers
    char auth_header[512] = {0};
    const char *auth_pos = strcasestr(buffer, "\r\nAuthorization:");
    if (auth_pos) {
        auth_pos += 16;
        while (*auth_pos == ' ') auth_pos++;
        const char *eol = strstr(auth_pos, "\r\n");
        if (eol) {
            size_t len = eol - auth_pos;
            if (len < sizeof(auth_header)) {
                strncpy(auth_header, auth_pos, len);
                auth_header[len] = '\0';
            }
        }
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
        } else {
            char token[SESSION_TOKEN_LEN + 1];
            if (candidate_session_create(cid, token) == 0) {
                exam_config_t cfg;
                config_load(&cfg);
                char resp[1024];
                snprintf(resp, sizeof(resp),
                         "{\"status\":\"SUCCESS\",\"token\":\"%s\",\"exam_url\":\"%s\",\"exam_name\":\"%s\"}",
                         token, cfg.exam_url[0] ? cfg.exam_url : "NOT_CONFIGURED",
                         cfg.exam_name[0] ? cfg.exam_name : "ExamOS Final");

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
    /* Route: GET /admin -> Admin Dashboard (requires auth) */
    else if (strcmp(path, "/admin") == 0 && strcmp(method, "GET") == 0) {
        if (!admin_check_auth(auth_header)) {
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
        if (!admin_check_auth(auth_header)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized: Admin credentials required\"}");
        } else {
            exam_config_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            parse_json_string(req_body, "exam_url", cfg.exam_url, sizeof(cfg.exam_url));
            parse_json_string(req_body, "exam_name", cfg.exam_name, sizeof(cfg.exam_name));
            cfg.exam_duration_minutes = parse_json_int(req_body, "exam_duration_minutes", 120);

            if (strncmp(cfg.exam_url, "http://", 7) != 0 && strncmp(cfg.exam_url, "https://", 8) != 0) {
                send_http_response(client_fd, 400, "application/json", "{\"error\":\"Exam URL must start with http:// or https://\"}");
            } else if (config_save(&cfg) == 0) {
                ledger_block_t blk;
                char details[512];
                snprintf(details, sizeof(details), "Exam URL updated to: %s", cfg.exam_url);
                ledger_append_event("ADMIN_CONFIG_UPDATED", "ADMIN_CONSOLE", details, &blk);
                send_http_response(client_fd, 200, "application/json", "{\"status\":\"SAVED\",\"exam_url\":\"" "saved" "\"}");
            } else {
                send_http_response(client_fd, 500, "application/json", "{\"error\":\"Failed to save configuration to disk\"}");
            }
        }
    }
    /* Route: POST /api/v1/admin/reload -> Restart Kiosk */
    else if (strcmp(path, "/api/v1/admin/reload") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_check_auth(auth_header)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized\"}");
        } else {
            system("systemctl restart examos-kiosk 2>/dev/null || true");
            send_http_response(client_fd, 202, "application/json", "{\"status\":\"RELOAD_QUEUED\"}");
        }
    }
    /* Route: POST /api/v1/admin/lock -> Emergency lock */
    else if (strcmp(path, "/api/v1/admin/lock") == 0 && strcmp(method, "POST") == 0) {
        if (!admin_check_auth(auth_header)) {
            send_http_response(client_fd, 401, "application/json", "{\"error\":\"Unauthorized\"}");
        } else {
            ledger_block_t blk;
            ledger_append_event("EMERGENCY_LOCK_ENGAGED", "ADMIN_CONSOLE", "Appliance locked by administrator", &blk);
            send_http_response(client_fd, 202, "application/json", "{\"status\":\"LOCKED\"}");
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
        ledger_block_t blk;
        if (ledger_append_event("HEARTBEAT_TELEMETRY", "SECURITY_AGENT", "Telemetry digest received", &blk) != 0) {
            send_http_response(client_fd, 503, "application/json", "{\"status\":\"UNAVAILABLE\"}");
        } else {
            send_http_response(client_fd, 202, "application/json", "{\"status\":\"RECEIVED\",\"block_index\":1}");
        }
    }
    /* Route: GET /api/v1/ledger -> Audit Log */
    else if (strcmp(path, "/api/v1/ledger") == 0 && strcmp(method, "GET") == 0) {
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
        exam_config_t cfg;
        config_load(&cfg);
        char resp[1024];
        snprintf(resp, sizeof(resp),
                 "{\"exam_url_configured\":%s,\"exam_url\":\"%s\",\"exam_name\":\"%s\",\"appliance_version\":\"0.2.0\"}",
                 cfg.configured ? "true" : "false",
                 cfg.exam_url[0] ? cfg.exam_url : "NOT_CONFIGURED",
                 cfg.exam_name[0] ? cfg.exam_name : "ExamOS Final");
        send_http_response(client_fd, 200, "application/json", resp);
    }
    /* Route: GET /api/v1/health */
    else if (strcmp(path, "/api/v1/health") == 0 && strcmp(method, "GET") == 0) {
        send_http_response(client_fd, 200, "application/json", "{\"status\":\"HEALTHY\",\"service\":\"examos-server\"}");
    }
    else {
        send_http_response(client_fd, 404, "application/json", "{\"error\":\"Not Found\"}");
    }

    close(client_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    int server_port = DEFAULT_SERVER_PORT;
    const char *port_env = getenv("EXAMOS_SERVER_PORT");
    if (port_env && *port_env) {
        char *end = NULL;
        errno = 0;
        long parsed_port = strtol(port_env, &end, 10);
        if (errno == 0 && end != port_env && *end == '\0' && parsed_port >= 1 && parsed_port <= 65535) {
            server_port = (int)parsed_port;
        }
    }

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    printf("[ExamOS-Server] Initializing ExamOS Security Server on port %d...\n", server_port);

    const char *ledger_path = getenv("EXAMOS_LEDGER_PATH");
    ledger_init(ledger_path && *ledger_path ? ledger_path : "/tmp/examos_event_ledger.log");
    exam_manager_init();
    candidate_session_init();

    exam_config_t cfg;
    if (config_load(&cfg) == 0 && cfg.configured) {
        printf("[ExamOS-Server] Active Exam URL: %s (%s)\n", cfg.exam_url, cfg.exam_name);
    } else {
        printf("[ExamOS-Server] No external Exam URL configured; Candidate Portal active at http://127.0.0.1:%d/\n", server_port);
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Failed to create socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t)server_port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 32) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    printf("[ExamOS-Server] Server listening on port %d (Candidate Portal: /, Admin Dashboard: /admin)\n", server_port);

    while (g_server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!g_server_running) break;
            continue;
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, (void *)(intptr_t)client_fd) != 0) {
            close(client_fd);
            continue;
        }
        pthread_detach(thread);
    }

    close(server_fd);
    printf("[ExamOS-Server] Clean shutdown complete.\n");
    return 0;
}
