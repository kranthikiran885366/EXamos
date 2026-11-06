#define _GNU_SOURCE
#include "viva_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s STORE_DIRECTORY\n", argv[0]);
        return 2;
    }

    if (setenv("EXAMOS_VIVA_STORE", argv[1], 1) != 0 ||
        setenv("EXAMOS_LLM_MODEL", "test-only-offline-fallback", 1) != 0 ||
        setenv("EXAMOS_BUILD_ID", "test-only", 1) != 0) {
        perror("setenv");
        return 1;
    }
    unsetenv("EXAMOS_LLM_ENDPOINT");
    unsetenv("EXAMOS_LLM_API_KEY");

    if (viva_engine_init() != 0) {
        fprintf(stderr, "viva_engine_init failed\n");
        return 1;
    }

    viva_generation_t first;
    if (viva_generate("test-session", "test-candidate", "test-exam", "abc123",
                      "Explain the submitted solution's key reasoning.",
                      "The candidate used a structured derivation.", &first) != 0) {
        fprintf(stderr, "offline fallback generation failed: %s\n", first.failure_reason);
        return 1;
    }
    if (first.status != VIVA_STATUS_OFFLINE_FALLBACK ||
        strcmp(first.status_str, "VIVA_OFFLINE_FALLBACK") != 0 ||
        first.question_count < VIVA_MIN_QUESTIONS || first.question_count > VIVA_MAX_QUESTIONS) {
        fprintf(stderr, "unexpected fallback result: status=%d text=%s questions=%d\n",
                first.status, first.status_str, first.question_count);
        return 1;
    }

    viva_generation_t second;
    if (viva_generate("test-session", "test-candidate", "test-exam", "abc123",
                      "Explain the submitted solution's key reasoning.",
                      "The candidate used a structured derivation.", &second) != 0 ||
        !second.idempotency_key_used || strcmp(first.viva_id, second.viva_id) != 0) {
        fprintf(stderr, "fallback idempotency was not preserved\n");
        return 1;
    }

    char candidate_json[8192];
    if (viva_export_candidate_json(first.viva_id, "test-candidate", candidate_json,
                                   sizeof(candidate_json)) != 0 ||
        !strstr(candidate_json, "VIVA_OFFLINE_FALLBACK") ||
        strstr(candidate_json, "rubric_reference")) {
        fprintf(stderr, "candidate offline-fallback export is invalid\n");
        return 1;
    }

    puts("[TEST-ONLY-VIVA] PASS: unavailable provider used flagged offline fallback and remained idempotent");
    return 0;
}
