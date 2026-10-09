#define _GNU_SOURCE
#include "../include/attestation_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int key_release_get_session_key(const char *attestation_id, char *out_exam_key, size_t max_len) {
    if (!attestation_id || !out_exam_key || max_len < 65) return -1;
    out_exam_key[0] = '\0';

    char status_json[256];
    if (attestation_get_status(attestation_id, status_json, sizeof(status_json)) != 0) {
        return -1;
    }

    if (strstr(status_json, "\"state\":\"TRUSTED\"") == NULL) {
        return -1; // Not trusted
    }

    return 0;
}
