#define _GNU_SOURCE
#include "../../server/include/candidate_login.h"
#include "../../server/include/session_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char journal_path[] = "/tmp/examos-session-store-test-XXXXXX";
    int fd = mkstemp(journal_path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);
    if (unlink(journal_path) != 0 ||
        setenv("EXAMOS_SESSION_JOURNAL", journal_path, 1) != 0 ||
        setenv("EXAMOS_LEDGER_HMAC_KEY",
               "session-store-test-hmac-key-0123456789", 1) != 0 ||
        setenv("EXAMOS_TPM_MODE", "development", 1) != 0) {
        perror("test setup");
        unlink(journal_path);
        return 1;
    }

    const char token[SESSION_TOKEN_LEN + 1] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char candidate_id[] = "candidate-test";
    time_t now = time(NULL);
    int failed = 0;

    candidate_session_init();
    if (session_store_init() != 0 ||
        candidate_session_restore(token, candidate_id, now) != 0) {
        fprintf(stderr, "Could not initialize the session journal test.\n");
        failed = 1;
        goto cleanup;
    }

    session_journal_record_t record;
    memset(&record, 0, sizeof(record));
    record.event_type = SESSION_EVENT_CREATE;
    snprintf(record.token, sizeof(record.token), "%s", token);
    snprintf(record.candidate_id, sizeof(record.candidate_id), "%s", candidate_id);
    record.created_at = now;
    record.expires_at = now + 28800;
    if (session_store_record(&record) != 0) {
        fprintf(stderr, "Could not persist session creation.\n");
        failed = 1;
        goto cleanup;
    }

    session_store_close();
    candidate_session_init();
    if (session_store_init() != 0 || !candidate_session_validate(token)) {
        fprintf(stderr, "Session creation did not survive journal replay.\n");
        failed = 1;
        goto cleanup;
    }

    memset(&record, 0, sizeof(record));
    record.event_type = SESSION_EVENT_INVALIDATE;
    snprintf(record.token, sizeof(record.token), "%s", token);
    record.created_at = now;
    record.expires_at = now + 28800;
    if (session_store_record(&record) != 0) {
        fprintf(stderr, "Could not persist session invalidation without a candidate ID.\n");
        failed = 1;
        goto cleanup;
    }

    session_store_close();
    candidate_session_init();
    if (session_store_init() != 0 || candidate_session_validate(token)) {
        fprintf(stderr, "Session invalidation did not survive journal replay.\n");
        failed = 1;
        goto cleanup;
    }

    puts("Candidate session create/invalidate journal lifecycle passed.");

cleanup:
    session_store_close();
    unlink(journal_path);
    return failed;
}
