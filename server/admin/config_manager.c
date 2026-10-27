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
#include <openssl/rand.h>

static int configured_exam_host(const char *host, const char *allowlist) {
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

static int validate_exam_url_against_hosts(const char *url, const char *allowed_hosts) {
    if (!url || !url[0] || strlen(url) >= EXAM_URL_MAX ||
        strchr(url, '@') || strchr(url, '*') || strstr(url, "..") ||
        strpbrk(url, "\\\r\n\t ")) return 0;

    /* Allow approved internal appliance onboarding and waiting portals */
    if (strncasecmp(url, "file:///usr/share/examos/", 25) == 0) {
        return 1;
    }

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
        /* For loopback HTTP (development only) an explicit port is required
         * and must match EXAMOS_SERVER_PORT (or the default dev port 8000).
         * A bare http://127.0.0.1/exam resolves to port 80, which is not a
         * valid exam server port, so no-port URLs are always rejected.
         * A port other than the configured server port would reach a different
         * service, so it is also rejected. */
        if (!port || !port[0]) return 0;
        const char *configured_port = getenv("EXAMOS_SERVER_PORT");
        const char *allowed_port = (configured_port && configured_port[0])
                                   ? configured_port : "8000";
        if (strcmp(port, allowed_port) != 0) return 0;
        return strcasecmp(host, "localhost") == 0 ||
               strcmp(host, "127.0.0.1") == 0 || strcmp(host, "[::1]") == 0;
    }
    return configured_exam_host(host, allowed_hosts);
}

int config_validate_exam_url(const char *url) {
    const char *hosts = getenv("EXAMOS_ALLOWED_EXAM_HOSTS");
    if (!hosts || !hosts[0]) {
        hosts = "staging.examos.example.edu,exam.university.edu,exam.alpha.edu,portal.beta.edu,localhost,127.0.0.1";
    }
    return validate_exam_url_against_hosts(url, hosts);
}

int config_validate_exam_id(const char *exam_id) {
    if (!exam_id) return 0;
    size_t length = strnlen(exam_id, EXAM_ID_MAX);
    if (length == 0 || length >= EXAM_ID_MAX) return 0;
    /* Restrict to a conservative identifier alphabet so the value can never
       smuggle separators, control characters or path tokens into downstream
       stores, ledger details or reviewer evidence. */
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)exam_id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
            return 0;
    }
    return 1;
}

int config_active_exam_id(char *out_exam_id, size_t out_size) {
    if (!out_exam_id || out_size == 0) return -1;
    out_exam_id[0] = '\0';
    exam_config_t cfg;
    if (config_load(&cfg) != 0) return -1;
    if (!config_validate_exam_id(cfg.exam_id)) return -1;
    size_t length = strnlen(cfg.exam_id, EXAM_ID_MAX);
    if (length + 1 > out_size) return -1;
    memcpy(out_exam_id, cfg.exam_id, length + 1);
    return 0;
}

int config_validate_allowed_origins(const char *origins) {
    if (!origins) return 0;
    size_t total_length = strnlen(origins, EXAM_ALLOWED_ORIGINS_MAX);
    if (total_length >= EXAM_ALLOWED_ORIGINS_MAX) return 0;
    if (total_length == 0) return 1;
    const char *allowed_hosts = getenv("EXAMOS_ALLOWED_EXAM_HOSTS");
    if (!allowed_hosts || !allowed_hosts[0]) {
        allowed_hosts = "staging.examos.example.edu,exam.university.edu,exam.alpha.edu,portal.beta.edu,localhost,127.0.0.1";
    }

    size_t count = 0;
    const char *entry = origins;
    while (*entry) {
        const char *end = strchr(entry, ',');
        size_t length = end ? (size_t)(end - entry) : strlen(entry);
        while (length && isspace((unsigned char)*entry)) { entry++; length--; }
        while (length && isspace((unsigned char)entry[length - 1])) length--;
        if (!length || length >= EXAM_URL_MAX || ++count > 32) return 0;

        char origin[EXAM_URL_MAX];
        memcpy(origin, entry, length);
        origin[length] = '\0';
        const char *authority = NULL;
        int loopback_http = 0;
        if (strcasecmp(origin, "file://") == 0 || strcasecmp(origin, "null") == 0) {
            if (!end) break;
            entry = end + 1;
            continue;
        }
        if (strncasecmp(origin, "https://", 8) == 0) {
            authority = origin + 8;
        } else if (strncasecmp(origin, "http://", 7) == 0) {
            authority = origin + 7;
            loopback_http = 1;
        } else if (configured_exam_host(origin, allowed_hosts)) {
            authority = origin;
        } else {
            return 0;
        }
        if (strpbrk(authority, "/?#@\\\r\n\t *")) return 0;
        if (loopback_http) {
            if (!validate_exam_url_against_hosts(origin, allowed_hosts)) return 0;
        } else {
            size_t host_length = strlen(authority);
            if (!host_length || host_length >= 256) return 0;
            char host_port[256];
            memcpy(host_port, authority, host_length + 1);
            char *port = NULL;
            char *host = host_port;
            if (*host == '[') {
                char *close = strchr(host, ']');
                if (!close || (close[1] && close[1] != ':')) return 0;
                if (close[1] == ':') port = close + 2;
                close[1] = '\0';
            } else {
                char *colon = strrchr(host, ':');
                if (colon) {
                    if (strchr(host, ':') != colon) return 0;
                    *colon = '\0';
                    port = colon + 1;
                }
            }
            if (!host[0] || !configured_exam_host(host, allowed_hosts)) return 0;
            if (port) {
                char *number_end = NULL;
                errno = 0;
                long number = strtol(port, &number_end, 10);
                if (errno || number_end == port || *number_end ||
                    number < 1 || number > 65535) return 0;
            }
        }
        if (!end) break;
        entry = end + 1;
        if (!*entry) return 0;
    }
    return count > 0;
}

int config_load(exam_config_t *cfg) {
    if (!cfg) return -1;
    memset(cfg, 0, sizeof(exam_config_t));
    cfg->exam_duration_minutes = 0;

    const char *configured_path = getenv("EXAMOS_EXAM_CONFIG");
    const char *path = configured_path && configured_path[0]
        ? configured_path : EXAM_CONF_PATH;
    int config_fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (config_fd < 0) return -1;
    struct stat config_status;
    if (fstat(config_fd, &config_status) != 0 || !S_ISREG(config_status.st_mode) ||
        config_status.st_size < 0 || config_status.st_size > 16384) {
        close(config_fd);
        return -1;
    }
    FILE *f = fdopen(config_fd, "r");
    if (!f) { close(config_fd); return -1; }

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
        } else if (strncmp(line, "EXAM_ID=", 8) == 0) {
            char *v = line + 8;
            while (*v == ' ' || *v == '\t') v++;
            size_t length = strlen(v);
            if (length >= sizeof(cfg->exam_id)) { fclose(f); return -1; }
            memcpy(cfg->exam_id, v, length + 1);
        } else if (strncmp(line, "ALLOWED_ORIGINS=", 16) == 0) {
            char *v = line + 16;
            while (*v == ' ' || *v == '\t') v++;
            size_t length = strlen(v);
            if (length >= sizeof(cfg->allowed_origins)) { fclose(f); return -1; }
            memcpy(cfg->allowed_origins, v, length + 1);
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
                      config_validate_allowed_origins(cfg->allowed_origins) &&
                      cfg->exam_name[0] && cfg->exam_duration_minutes > 0;
    return 0;
}

int config_save(const exam_config_t *cfg) {
    if (!cfg || !config_validate_exam_url(cfg->exam_url) || !cfg->exam_name[0] ||
        strnlen(cfg->exam_name, sizeof(cfg->exam_name)) >= sizeof(cfg->exam_name) ||
        !config_validate_allowed_origins(cfg->allowed_origins) ||
        cfg->exam_duration_minutes < 1) return -1;
    /* exam_id is optional here so a URL/name-only config still saves, but if
       present it must be a well-formed identifier. */
    if (cfg->exam_id[0] && !config_validate_exam_id(cfg->exam_id)) return -1;
    for (const unsigned char *p = (const unsigned char *)cfg->exam_name; *p; ++p) {
        if (*p < 0x20 || *p == 0x7f) return -1;
    }

    const char *configured_path = getenv("EXAMOS_EXAM_CONFIG");
    char config_directory[PATH_MAX];
    const char *config_filename = "exam.conf";
    const char *directory_path = "/etc/examos";
    if (configured_path && configured_path[0]) {
        size_t path_length = strnlen(configured_path, sizeof(config_directory));
        if (path_length == 0 || path_length >= sizeof(config_directory)) return -1;
        memcpy(config_directory, configured_path, path_length + 1);
        char *separator = strrchr(config_directory, '/');
        if (!separator || strcmp(separator + 1, config_filename) != 0) return -1;
        if (separator == config_directory) separator[1] = '\0';
        else *separator = '\0';
        directory_path = config_directory;
    }

    /* Pin the trusted configuration directory, and create an unpredictable,
     * exclusive temporary file there. This avoids following a pre-created
     * symlink at a predictable PID-based temporary pathname. */
    int directory_fd = open(directory_path, O_RDONLY | O_DIRECTORY |
                            O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0) return -1;

    char temporary_name[48];
    int file_fd = -1;
    for (unsigned int attempt = 0; attempt < 8; ++attempt) {
        unsigned char nonce[16];
        if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
            OPENSSL_cleanse(nonce, sizeof(nonce));
            break;
        }
        static const char digits[] = "0123456789abcdef";
        memcpy(temporary_name, ".exam.conf.tmp.", 15);
        for (size_t i = 0; i < sizeof(nonce); ++i) {
            temporary_name[15 + i * 2] = digits[nonce[i] >> 4];
            temporary_name[16 + i * 2] = digits[nonce[i] & 0x0f];
        }
        temporary_name[47] = '\0';
        OPENSSL_cleanse(nonce, sizeof(nonce));
        file_fd = openat(directory_fd, temporary_name,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                         0600);
        if (file_fd >= 0 || errno != EEXIST) break;
    }
    if (file_fd < 0) {
        close(directory_fd);
        return -1;
    }

    FILE *file = fdopen(file_fd, "w");
    if (!file) {
        close(file_fd);
        unlinkat(directory_fd, temporary_name, 0);
        close(directory_fd);
        return -1;
    }
    int ok = fprintf(file,
                     "# ExamOS Examination Configuration\n"
                     "# Managed automatically by ExamOS Admin Dashboard\n"
                     "EXAM_URL=%s\nEXAM_NAME=%s\nEXAM_ID=%s\nALLOWED_ORIGINS=%s\nEXAM_DURATION_MINUTES=%d\n",
                     cfg->exam_url, cfg->exam_name, cfg->exam_id, cfg->allowed_origins,
                     cfg->exam_duration_minutes) >= 0 &&
             fflush(file) == 0 && fchmod(fileno(file), 0644) == 0 &&
             fsync(fileno(file)) == 0;
    if (fclose(file) != 0) ok = 0;
    if (ok && renameat(directory_fd, temporary_name,
                       directory_fd, "exam.conf") == 0) {
        ok = fsync(directory_fd) == 0;
    } else {
        ok = 0;
    }
    if (!ok) unlinkat(directory_fd, temporary_name, 0);
    close(directory_fd);
    return ok ? 0 : -1;
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

int config_create_password_hash(const char *plaintext_password,
                                char *out_credential, size_t credential_size) {
    enum { SALT_BYTES = 16, HASH_BYTES = 32, ITERATIONS = 310000 };
    if (!plaintext_password || !out_credential || credential_size == 0) return -1;

    size_t password_length = strnlen(plaintext_password, 257);
    if (password_length < 12 || password_length > 256) return -1;

    unsigned char salt[SALT_BYTES] = {0};
    unsigned char hash[HASH_BYTES] = {0};
    char salt_text[SALT_BYTES * 2 + 1] = {0};
    char hash_text[HASH_BYTES * 2 + 1] = {0};
    static const char digits[] = "0123456789abcdef";
    int result = -1;

    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        PKCS5_PBKDF2_HMAC(plaintext_password, (int)password_length,
                          salt, sizeof(salt), ITERATIONS, EVP_sha256(),
                          sizeof(hash), hash) != 1) {
        goto cleanup;
    }
    for (size_t i = 0; i < sizeof(salt); ++i) {
        salt_text[i * 2] = digits[salt[i] >> 4];
        salt_text[i * 2 + 1] = digits[salt[i] & 0x0f];
    }
    for (size_t i = 0; i < sizeof(hash); ++i) {
        hash_text[i * 2] = digits[hash[i] >> 4];
        hash_text[i * 2 + 1] = digits[hash[i] & 0x0f];
    }
    int written = snprintf(out_credential, credential_size, "%d:%s:%s",
                           ITERATIONS, salt_text, hash_text);
    if (written < 0 || (size_t)written >= credential_size) {
        out_credential[0] = '\0';
        goto cleanup;
    }
    result = 0;

cleanup:
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(hash, sizeof(hash));
    OPENSSL_cleanse(salt_text, sizeof(salt_text));
    OPENSSL_cleanse(hash_text, sizeof(hash_text));
    return result;
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
