#define _GNU_SOURCE
#include "../include/policy_catalog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>

/*
 * Catalog storage. Entries are copied out of the provisioned file at load
 * time so that later file changes cannot alter the policy an already
 * published exam refers to.
 */
static pthread_mutex_t g_catalog_lock = PTHREAD_MUTEX_INITIALIZER;
static policy_catalog_entry_t g_entries[POLICY_CATALOG_MAX];
static int g_entry_count = 0;
static int g_loaded = 0;

static char *read_file_all(const char *path, size_t *out_len) {
    if (!path || !out_len) return NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        st.st_size > (off_t)(1024 * 1024)) {
        close(fd);
        return NULL;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    size_t used = 0;
    while (used < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + used, (size_t)st.st_size - used);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf); close(fd); return NULL;
        }
        if (n == 0) break;
        used += (size_t)n;
    }
    close(fd);
    buf[used] = '\0';
    *out_len = used;
    return buf;
}

/* Extracts a JSON string value for a key. Mirrors the house-style scanner. */
static int catalog_json_str(const char *buf, const char *key,
                            char *out, size_t out_len) {
    if (!buf || !key || !out || out_len == 0) return -1;
    out[0] = '\0';

    char pattern[128];
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) >= (int)sizeof(pattern))
        return -1;
    const char *pos = strstr(buf, pattern);
    if (!pos) return -1;
    pos += strlen(pattern);
    while (*pos == ' ' || *pos == ':' || *pos == '\t' || *pos == '\n' || *pos == '\r') pos++;
    if (*pos != '"') return -1;
    pos++;

    size_t i = 0;
    while (*pos && *pos != '"' && i + 1 < out_len) {
        if (*pos == '\\' && *(pos + 1)) pos++;
        out[i++] = *pos++;
    }
    out[i] = '\0';
    return 0;
}

/* Copies the balanced JSON object that starts at *cursor. */
static int catalog_extract_object(const char *buf, const char **cursor,
                                  char *out, size_t out_len) {
    if (!buf || !cursor || !out || out_len == 0) return -1;
    const char *start = strchr(*cursor, '{');
    if (!start) return -1;

    int depth = 0;
    int in_string = 0;
    int escaped = 0;
    const char *p = start;
    for (; *p; p++) {
        if (in_string) {
            if (escaped) { escaped = 0; continue; }
            if (*p == '\\') { escaped = 1; continue; }
            if (*p == '"') in_string = 0;
            continue;
        }
        if (*p == '"') { in_string = 1; continue; }
        if (*p == '{') depth++;
        else if (*p == '}') {
            depth--;
            if (depth == 0) {
                size_t length = (size_t)(p - start) + 1;
                if (length >= out_len) return -1;
                memcpy(out, start, length);
                out[length] = '\0';
                *cursor = p + 1;
                return 0;
            }
        }
    }
    return -1;
}

int policy_catalog_load(const char *path) {
    if (!path || !path[0]) return -1;

    size_t len = 0;
    char *buf = read_file_all(path, &len);
    if (!buf) {
        fprintf(stderr, "[PolicyCatalog] FATAL: browser policy catalog '%s' is unreadable.\n", path);
        return -1;
    }

    char schema[64] = {0};
    if (catalog_json_str(buf, "_schema", schema, sizeof(schema)) != 0 ||
        strcmp(schema, "examos-browser-policy-catalog-v1") != 0) {
        fprintf(stderr, "[PolicyCatalog] FATAL: browser policy catalog '%s' has an unsupported schema.\n", path);
        free(buf);
        return -1;
    }

    const char *arr = strstr(buf, "\"policies\"");
    if (!arr) {
        fprintf(stderr, "[PolicyCatalog] FATAL: browser policy catalog '%s' has no policies array.\n", path);
        free(buf);
        return -1;
    }
    arr = strchr(arr, '[');
    if (!arr) { free(buf); return -1; }

    policy_catalog_entry_t parsed[POLICY_CATALOG_MAX];
    int count = 0;
    const char *cursor = arr + 1;

    while (count < POLICY_CATALOG_MAX) {
        const char *obj_start = strchr(cursor, '{');
        if (!obj_start) break;
        /* Stop at the end of the policies array. */
        const char *array_end = strchr(cursor, ']');
        if (array_end && obj_start > array_end) break;

        policy_catalog_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        char policy_body[POLICY_JSON_MAX] = {0};

        const char *inner = obj_start + 1;
        if (catalog_json_str(inner, "name", entry.name, sizeof(entry.name)) != 0 ||
            !entry.name[0]) {
            break;
        }
        catalog_json_str(inner, "description", entry.description, sizeof(entry.description));

        const char *policy_key = strstr(inner, "\"policy\"");
        if (!policy_key) break;
        const char *policy_cursor = policy_key + strlen("\"policy\"");
        if (catalog_extract_object(buf, &policy_cursor, policy_body, sizeof(policy_body)) != 0)
            break;
        snprintf(entry.policy_json, sizeof(entry.policy_json), "%s", policy_body);

        parsed[count++] = entry;

        /* Advance past this entry. */
        const char *next = strchr(obj_start, '}');
        if (!next) break;
        cursor = next + 1;
    }

    free(buf);

    if (count == 0) {
        fprintf(stderr, "[PolicyCatalog] FATAL: browser policy catalog '%s' contains no usable policy.\n", path);
        return -1;
    }

    pthread_mutex_lock(&g_catalog_lock);
    memset(g_entries, 0, sizeof(g_entries));
    memcpy(g_entries, parsed, sizeof(parsed[0]) * (size_t)count);
    g_entry_count = count;
    g_loaded = 1;
    pthread_mutex_unlock(&g_catalog_lock);

    fprintf(stderr, "[PolicyCatalog] Loaded %d browser policies from %s.\n", count, path);
    return 0;
}

int policy_catalog_is_loaded(void) {
    pthread_mutex_lock(&g_catalog_lock);
    int loaded = g_loaded;
    pthread_mutex_unlock(&g_catalog_lock);
    return loaded;
}

int policy_catalog_get(const char *name, char *out_json, size_t max_len) {
    if (!name || !name[0] || !out_json || max_len == 0) return -1;
    out_json[0] = '\0';

    pthread_mutex_lock(&g_catalog_lock);
    int found = 0;
    for (int i = 0; i < g_entry_count; i++) {
        if (strcmp(g_entries[i].name, name) == 0) {
            snprintf(out_json, max_len, "%s", g_entries[i].policy_json);
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_catalog_lock);
    return found ? 0 : -1;
}

int policy_catalog_names_json(char *out_json, size_t max_len) {
    if (!out_json || max_len == 0) return -1;

    pthread_mutex_lock(&g_catalog_lock);
    size_t used = 0;
    int written = snprintf(out_json, max_len, "[");
    used = (written > 0) ? (size_t)written : 0;
    for (int i = 0; i < g_entry_count && used + 1 < max_len; i++) {
        char item[512];
        int n = snprintf(item, sizeof(item),
                         "%s{\"name\":\"%s\",\"description\":\"%s\"}",
                         i > 0 ? "," : "",
                         g_entries[i].name, g_entries[i].description);
        if (n <= 0 || used + (size_t)n >= max_len) break;
        memcpy(out_json + used, item, (size_t)n);
        used += (size_t)n;
    }
    if (used + 2 < max_len) {
        out_json[used++] = ']';
        out_json[used] = '\0';
    } else {
        out_json[max_len - 1] = '\0';
    }
    pthread_mutex_unlock(&g_catalog_lock);
    return 0;
}
