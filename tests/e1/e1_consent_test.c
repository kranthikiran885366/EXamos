#define _GNU_SOURCE
#include "../../server/include/e1_consent.h"
#include "../../server/include/event_chain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int expect(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "[E1-CONSENT] FAIL: %s\n", message);
        return 0;
    }
    return 1;
}

int main(void)
{
    char directory[] = "/tmp/examos-e1-consent.XXXXXX";
    char ledger_path[256];
    char unavailable_path[256];
    const char *session_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *consent_json =
        "{\"session_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"wifi\":false,\"ble\":true,\"rf\":false,\"second_camera\":false}";
    const char *duplicate_scope_json =
        "{\"session_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"wifi\":false,\"wifi\":true,\"ble\":false,\"rf\":false,\"second_camera\":false}";
    const char *extra_field_json =
        "{\"session_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"wifi\":false,\"ble\":false,\"rf\":false,\"second_camera\":false,\"extra\":true}";
    e1_consent_scopes_t scopes;
    uint64_t event_count = 0;
    uint64_t corrupt_sequence = 0;
    char error[128];

    if (!mkdtemp(directory)) {
        perror("mkdtemp");
        return 1;
    }
    if (snprintf(ledger_path, sizeof(ledger_path), "%s/events.jsonl", directory) < 0 ||
        snprintf(unavailable_path, sizeof(unavailable_path), "%s", directory) < 0 ||
        event_chain_init(ledger_path) != 0) {
        rmdir(directory);
        fprintf(stderr, "[E1-CONSENT] FAIL: event chain initialization failed\n");
        return 1;
    }

    int passed =
        expect(e1_consent_record_json(session_id, "{}", &scopes) == -1,
               "missing scopes must be rejected") &&
        expect(e1_consent_record_json(session_id, duplicate_scope_json, &scopes) == -1,
               "duplicate scopes must be rejected") &&
        expect(e1_consent_record_json(session_id, extra_field_json, &scopes) == -1,
               "unknown fields must be rejected") &&
        expect(e1_consent_record_json(
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                   consent_json, &scopes) == -1,
               "body session must match the authenticated session") &&
        expect(e1_consent_record_json(session_id, consent_json, &scopes) == 0,
               "valid per-source consent must append to the real event chain") &&
        expect(scopes.wifi == 0 && scopes.ble == 1 &&
               scopes.rf == 0 && scopes.second_camera == 0,
               "parsed source scopes must match the request");

    if (passed) {
        passed = expect(event_chain_verify_session(session_id, &event_count,
                                                   &corrupt_sequence, error,
                                                   sizeof(error)) == 0 &&
                        event_count == 1,
                        "consent event must be durably written and verifiable");
    }

    FILE *ledger = fopen(ledger_path, "r");
    char line[4096] = {0};
    if (passed) {
        passed = expect(ledger != NULL && fgets(line, sizeof(line), ledger) != NULL &&
                        strstr(line, "\"event_type\":\"E1_CONSENT_RECORDED\"") != NULL &&
                        strstr(line, "\"collection_status\":\"DISABLED_BY_POLICY\"") != NULL &&
                        strstr(line, "\"ble\":true") != NULL,
                        "persisted event must record scope but keep collection disabled");
    }
    if (ledger) {
        fclose(ledger);
    }

    if (passed) {
        passed = expect(event_chain_init(unavailable_path) == 0,
                        "event chain must initialize without creating the target path");
        if (passed) {
            passed = expect(e1_consent_record_json(session_id, consent_json,
                                                   &scopes) == -2,
                            "consent must report event persistence failure");
        }
    }

    unlink(ledger_path);
    rmdir(directory);
    if (!passed) {
        return 1;
    }

    puts("[E1-CONSENT] PASS: strict scoped consent was appended and verified in the canonical event chain; collection remains disabled.");
    return 0;
}
