#define _GNU_SOURCE
#include "../include/config_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

static int configured_exam_host(const char *host) {
    const char *allowlist = getenv("EXAMOS_ALLOWED_EXAM_HOSTS");
    if (!allowlist || !allowlist[0] || !host || !host[0]) return 0;
    const char *entry = allowlist;
    while (*entry) {
        const char *end = strchr(entry, ',');
        size_t length = end ? (size_t)(end - entry) : strlen(entry);
        while (length && isspace((unsigned char)*entry)) { entry++; length--; }
        while (length && isspace((unsigned char)entry[length - 1])) length--;
        if (strlen(host) == length && strncasecmp(entry, host, length) == 0) return 1;
        if (!end) break;
        entry = end + 1;
    }
    return 0;
}

int config_validate_exam_url(const char *url) {
    if (!url || !url[0] || strlen(url) >= EXAM_URL_MAX ||
        strchr(url, '@') || strchr(url, '*') || strstr(url, "..") ||
        strpbrk(url, "\\\r\n\t ")) return 0;

    const char *authority = NULL;
    int loopback_http = 0;
    if (strncasecmp(url, "https://", 8) == 0) {
        authority = url + 8;
    } else if (strncasecmp(url, "http://", 7) == 0 &&
               getenv("EXAMOS_ALLOW_LOOPBACK_EXAM_URL") &&
               strcmp(getenv("EXAMOS_ALLOW_LOOPBACK_EXAM_URL"), "1") == 0) {
        authority = url + 7;
        loopback_http = 1;
    } else {
        return 0;
    }

    const char *authority_end = strpbrk(authority, "/?#");
    size_t authority_len = authority_end ? (size_t)(authority_end - authority) : strlen(authority);
    if (authority_len == 0 || authority_len >= 256) return 0;
    char host_port[256];
    memcpy(host_port, authority, authority_len);
    host_port[authority_len] = '\0';
    if (strchr(host_port, '@')) return 0;

    char *host = host_port;
    char *port = NULL;
    if (host[0] == '[') {
        char *close = strchr(host, ']');
        if (!close) return 0;
        if (close[1]) {
            if (close[1] != ':') return 0;
            port = close + 2;
        }
        close[1] = '\0';
    } else {
        char *colon = strrchr(host, ':');
        if (colon) {
            if (strchr(host, ':') != colon) return 0;
            *colon = '\0';
            port = colon + 1;
        }
    }
    if (!host[0]) return 0;
    if (port) {
        if (!port[0]) return 0;
        char *end = NULL;
        errno = 0;
        long number = strtol(port, &end, 10);
        if (errno || end == port || *end || number < 1 || number > 65535) return 0;
    }
    if (loopback_http) {
        return strcasecmp(host, "localhost") == 0 ||
               strcmp(host, "127.0.0.1") == 0 || strcmp(host, "[::1]") == 0;
    }
    return configured_exam_host(host);
}

int config_load(exam_config_t *cfg) {
    if (!cfg) return -1;
    memset(cfg, 0, sizeof(exam_config_t));
    cfg->exam_duration_minutes = 0;

    FILE *f = fopen(EXAM_CONF_PATH, "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!strchr(line, '\n') && !feof(f)) {
            fclose(f);
            return -1;
        }
        char *nl = strchr(line, '\r');
        if (nl) *nl = '\0';
        nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strncmp(line, "EXAM_URL=", 9) == 0) {
            char *v = line + 9;
            while (*v == ' ' || *v == '\t') v++;
            size_t length = strlen(v);
            if (length >= sizeof(cfg->exam_url)) { fclose(f); return -1; }
            memcpy(cfg->exam_url, v, length + 1);
        } else if (strncmp(line, "EXAM_NAME=", 10) == 0) {
            char *v = line + 10;
            while (*v == ' ' || *v == '\t') v++;
            size_t length = strlen(v);
            if (length >= sizeof(cfg->exam_name)) { fclose(f); return -1; }
            memcpy(cfg->exam_name, v, length + 1);
        } else if (strncmp(line, "EXAM_DURATION_MINUTES=", 22) == 0) {
            char *v = line + 22;
            char *end = NULL;
            errno = 0;
            long duration = strtol(v, &end, 10);
            while (end && (*end == ' ' || *end == '\t')) ++end;
            if (errno || end == v || !end || *end || duration < 1 ||
                duration > INT_MAX) { fclose(f); return -1; }
            cfg->exam_duration_minutes = (int)duration;
        }
    }
    fclose(f);

    cfg->configured = config_validate_exam_url(cfg->exam_url) &&
                      cfg->exam_name[0] && cfg->exam_duration_minutes > 0;
    return 0;
}

int config_save(const exam_config_t *cfg) {
    if (!cfg || !config_validate_exam_url(cfg->exam_url) || !cfg->exam_name[0] ||
        cfg->exam_duration_minutes < 1) return -1;

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", EXAM_CONF_PATH, getpid());

    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;

    fprintf(f, "# ExamOS Examination Configuration\n");
    fprintf(f, "# Managed automatically by ExamOS Admin Dashboard\n");
    fprintf(f, "EXAM_URL=%s\n", cfg->exam_url);
    fprintf(f, "EXAM_NAME=%s\n", cfg->exam_name);
    fprintf(f, "EXAM_DURATION_MINUTES=%d\n", cfg->exam_duration_minutes);

    if (fflush(f) != 0 || fsync(fileno(f)) != 0 || fclose(f) != 0) {
        unlink(tmp_path);
        return -1;
    }

    chmod(tmp_path, 0644);
    if (rename(tmp_path, EXAM_CONF_PATH) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(const char *text, unsigned char *out, size_t out_size) {
    if (!text || strlen(text) != out_size * 2) return -1;
    for (size_t i = 0; i < out_size; ++i) {
        int high = hex_value(text[i * 2]);
        int low = hex_value(text[i * 2 + 1]);
        if (high < 0 || low < 0) return -1;
        out[i] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

int config_verify_password_hash(const char *plaintext_password,
                                const char *credential) {
    enum { SALT_BYTES = 16, HASH_BYTES = 32, MIN_ITERATIONS = 100000,
           MAX_ITERATIONS = 2000000 };
    if (!plaintext_password || !credential) return 0;
    size_t password_length = strlen(plaintext_password);
    if (password_length < 12 || password_length > 1024) return 0;
    const char *first = strchr(credential, ':');
    if (!first || first == credential) return 0;
    const char *second = strchr(first + 1, ':');
    if (!second || strchr(second + 1, ':')) return 0;
    size_t iteration_length = (size_t)(first - credential);
    if (iteration_length > 7) return 0;
    for (size_t i = 0; i < iteration_length; ++i) {
        if (credential[i] < '0' || credential[i] > '9') return 0;
    }
    char iteration_text[8] = {0};
    memcpy(iteration_text, credential, iteration_length);
    char *end = NULL;
    errno = 0;
    unsigned long iterations = strtoul(iteration_text, &end, 10);
    if (errno || end == iteration_text || *end || iterations < MIN_ITERATIONS ||
        iterations > MAX_ITERATIONS) return 0;
    size_t salt_text_length = (size_t)(second - first - 1);
    size_t hash_text_length = strlen(second + 1);
    if (salt_text_length != SALT_BYTES * 2 || hash_text_length != HASH_BYTES * 2)
        return 0;
    char salt_text[SALT_BYTES * 2 + 1] = {0};
    memcpy(salt_text, first + 1, salt_text_length);

    unsigned char salt[SALT_BYTES] = {0};
    unsigned char expected[HASH_BYTES] = {0};
    unsigned char actual[HASH_BYTES] = {0};
    int valid = decode_hex(salt_text, salt, sizeof(salt)) == 0 &&
                decode_hex(second + 1, expected, sizeof(expected)) == 0 &&
                PKCS5_PBKDF2_HMAC(plaintext_password,
                    (int)password_length, salt, sizeof(salt),
                    (int)iterations, EVP_sha256(), sizeof(actual), actual) == 1 &&
                CRYPTO_memcmp(actual, expected, sizeof(actual)) == 0;
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(salt_text, sizeof(salt_text));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual, sizeof(actual));
    return valid ? 1 : 0;
}

static int read_admin_config(char *username, size_t username_size,
                             char *credential, size_t credential_size) {
    if (!username || username_size < 2 || !credential || credential_size < 2)
        return -1;
    const char *configured_path = getenv("EXAMOS_ADMIN_CONFIG");
    const char *path = configured_path && configured_path[0]
        ? configured_path : ADMIN_CONF_PATH;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat status;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid() || (status.st_mode & 0077) != 0 ||
        status.st_size <= 0 || status.st_size > 4096) {
        close(fd);
        return -1;
    }
    FILE *file = fdopen(fd, "r");
    if (!file) {
        close(fd);
        return -1;
    }
    int found_user = 0, found_credential = 0, ok = 1;
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        if (!strchr(line, '\n') && !feof(file)) { ok = 0; break; }
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "ADMIN_USERNAME=", 15) == 0) {
            const char *value = line + 15;
            if (!value[0] || strlen(value) >= username_size || found_user) {
                ok = 0; break;
            }
            memcpy(username, value, strlen(value) + 1);
            found_user = 1;
        } else if (strncmp(line, "ADMIN_PASSWORD_PBKDF2=", 22) == 0) {
            const char *value = line + 22;
            if (!value[0] || strlen(value) >= credential_size || found_credential) {
                ok = 0; break;
            }
            memcpy(credential, value, strlen(value) + 1);
            found_credential = 1;
        } else if (strncmp(line, "ADMIN_PASSWORD_SHA256=", 22) == 0) {
            ok = 0; break;
        }
    }
    if (ferror(file)) ok = 0;
    if (fclose(file) != 0) ok = 0;
    return ok && found_user && found_credential ? 0 : -1;
}

int config_verify_admin_credentials(const char *username,
                                    const char *plaintext_password) {
    if (!username || !username[0] || !plaintext_password || !plaintext_password[0])
        return 0;
    char configured_username[128] = {0};
    char credential[192] = {0};
    int loaded = read_admin_config(configured_username, sizeof(configured_username),
                                   credential, sizeof(credential));
    int valid = loaded == 0 && strlen(username) == strlen(configured_username) &&
                CRYPTO_memcmp(username, configured_username, strlen(username)) == 0 &&
                config_verify_password_hash(plaintext_password, credential);
    OPENSSL_cleanse(credential, sizeof(credential));
    OPENSSL_cleanse(configured_username, sizeof(configured_username));
    return valid ? 1 : 0;
}
