#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "include/examos_appliance.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/*
 * The appliance identity marker is written by the image build. Its absence
 * means the host is not an ExamOS appliance, or that the image was modified
 * after it was built.
 */
#define APPLIANCE_IDENTITY_PATH "/etc/examos/appliance-identity"
#define OS_RELEASE_PATH        "/etc/os-release"
#define LOCKDOWN_PATH          "/sys/kernel/security/lockdown"

/* Reads the first line of a file into a buffer. Returns 0 on success. */
static int read_first_line(const char *path, char *out, size_t out_len) {
    if (!out || out_len == 0) return -1;
    out[0] = '\0';

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    ssize_t n = read(fd, out, out_len - 1);
    close(fd);
    if (n <= 0) return -1;
    out[n] = '\0';

    char *newline = strchr(out, '\n');
    if (newline) *newline = '\0';
    return 0;
}

/* Returns 1 when the file contains a line equal to the given key=value. */
static int file_has_line(const char *path, const char *expected) {
    FILE *file = fopen(path, "r");
    if (!file) return 0;

    char line[512];
    int found = 0;
    while (!found && fgets(line, sizeof(line), file)) {
        size_t length = strcspn(line, "\r\n");
        line[length] = '\0';
        if (strcmp(line, expected) == 0) found = 1;
    }
    fclose(file);
    return found;
}

/*
 * Reads the active kernel lockdown mode.
 *
 * The kernel reports the available modes with the active one in brackets:
 *   none [integrity] confidentiality
 */
static int lockdown_active_mode(char *out_mode, size_t mode_len) {
    if (!out_mode || mode_len == 0) return -1;
    out_mode[0] = '\0';

    FILE *file = fopen(LOCKDOWN_PATH, "r");
    if (!file) return -1;

    char line[256] = {0};
    if (!fgets(line, sizeof(line), file)) {
        fclose(file);
        return -1;
    }
    fclose(file);

    char *open_bracket = strchr(line, '[');
    char *close_bracket = open_bracket ? strchr(open_bracket, ']') : NULL;
    if (!open_bracket || !close_bracket || close_bracket <= open_bracket + 1) return -1;

    size_t length = (size_t)(close_bracket - open_bracket - 1);
    if (length >= mode_len) length = mode_len - 1;
    memcpy(out_mode, open_bracket + 1, length);
    out_mode[length] = '\0';
    return 0;
}

int examos_appliance_verify(char *out_reason, size_t reason_len) {
    char reason[256] = {0};

    /* 1. The host must identify itself as ExamOS. */
    if (!file_has_line(OS_RELEASE_PATH, "ID=examos")) {
        snprintf(reason, sizeof(reason),
                 "this host is not an ExamOS appliance: %s does not identify as examos",
                 OS_RELEASE_PATH);
    }

    /* 2. The image must carry the appliance identity marker. */
    if (!reason[0]) {
        char identity[128] = {0};
        if (read_first_line(APPLIANCE_IDENTITY_PATH, identity, sizeof(identity)) != 0 ||
            !identity[0]) {
            snprintf(reason, sizeof(reason),
                     "the ExamOS appliance identity marker %s is missing or empty",
                     APPLIANCE_IDENTITY_PATH);
        }
    }

    /* 3. The kernel lockdown posture the image requires must be active. */
    if (!reason[0]) {
        char mode[64] = {0};
        if (lockdown_active_mode(mode, sizeof(mode)) != 0 ||
            strcmp(mode, "confidentiality") != 0) {
            snprintf(reason, sizeof(reason),
                     "kernel lockdown is '%s'; the ExamOS image requires 'confidentiality'",
                     mode);
        }
    }

    if (reason[0]) {
        if (out_reason && reason_len) snprintf(out_reason, reason_len, "%s", reason);
        return -1;
    }

    if (out_reason && reason_len) snprintf(out_reason, reason_len, "ExamOS appliance verified");
    return 0;
}

int examos_appliance_identity(char *out_id, size_t id_len) {
    if (!out_id || id_len == 0) return -1;
    out_id[0] = '\0';
    return read_first_line(APPLIANCE_IDENTITY_PATH, out_id, id_len);
}

