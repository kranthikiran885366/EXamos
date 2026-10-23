#define _GNU_SOURCE
#include "../include/key_release.h"
#include "../include/attestation_service.h"
#include "../include/ledger.h"
#include <string.h>
#include <stdio.h>

int key_release_get_session_key(const char *session_id,
                                char *out_exam_key, size_t max_len,
                                const char *device_id,
                                char *out_error_code) {
    if (!session_id || !session_id[0] || !out_exam_key || max_len < 65) {
        if (out_error_code) snprintf(out_error_code, 64, "P3_INVALID_REQUEST");
        return -1;
    }
    out_exam_key[0] = '\0';
    if (out_error_code) out_error_code[0] = '\0';

    /* Verify session is in TRUSTED state before releasing key */
    char status[32] = {0};
    if (attestation_get_status(session_id, status, sizeof(status)) != 0) {
        if (out_error_code) snprintf(out_error_code, 64, "P3_SESSION_NOT_FOUND");
        return -1;
    }
    if (strcmp(status, "TRUSTED") != 0) {
        if (out_error_code) snprintf(out_error_code, 64, "P3_SESSION_NOT_TRUSTED");
        return -1;
    }

    int rc = attestation_get_exam_key(session_id, device_id, out_exam_key, max_len);
    if (rc != 0) {
        if (out_error_code) snprintf(out_error_code, 64, "P3_KEY_UNAVAILABLE");
        return -1;
    }
    return 0;
}

int key_release_check_eligibility(const char *session_id,
                                  const char *device_id,
                                  char *out_reason) {
    if (!session_id || !session_id[0]) {
        if (out_reason) snprintf(out_reason, 64, "P3_INVALID_REQUEST");
        return -1;
    }
    if (out_reason) out_reason[0] = '\0';

    char status[32] = {0};
    if (attestation_get_status(session_id, status, sizeof(status)) != 0) {
        if (out_reason) snprintf(out_reason, 64, "P3_SESSION_NOT_FOUND");
        return -1;
    }
    if (strcmp(status, "TRUSTED") != 0) {
        if (out_reason) snprintf(out_reason, 64, "P3_SESSION_NOT_TRUSTED");
        return -1;
    }
    (void)device_id;
    return 0;
}
