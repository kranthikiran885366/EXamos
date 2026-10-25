#include "../../server/include/attestation_service.h"
#include "../../server/include/enterprise_platform.h"
#include "../../server/include/exam_engine.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int expect_unsupported(int result, const char *operation) {
    if (result == -1 && errno == ENOTSUP) return 0;
    fprintf(stderr, "FAIL: %s did not fail with ENOTSUP (result=%d errno=%d)\n",
            operation, result, errno);
    return 1;
}

int main(void) {
    int failures = 0;

    /*
     * The exam engine is intentionally always ready: it ships a built-in
     * NQT question battery so candidates can sit exams without a database.
     * The unprovisioned contract applies to platform persistence (PostgreSQL)
     * and fleet/policy operations — not to the in-memory exam engine.
     */
    if (exam_engine_init() != 0) {
        fprintf(stderr, "FAIL: exam engine init returned non-zero\n");
        failures++;
    }

    errno = 0;
    failures += expect_unsupported(enterprise_platform_save_all(),
                                   "platform persistence");

    /* platform_update_exam_state: pass a non-empty exam_id so validation
     * does not short-circuit before reaching the DB connection check. */
    errno = 0;
    failures += expect_unsupported(
        platform_update_exam_state("no-such-exam", EXAM_STATE_ACTIVE, NULL),
        "exam lifecycle mutation");

    /* platform_update_exam_url: non-empty exam_id + non-empty url. */
    errno = 0;
    failures += expect_unsupported(
        platform_update_exam_url("no-such-exam", "https://exam.example.edu/", "", NULL),
        "signed exam policy update");

    /* platform_rollback_policy: non-empty exam_id + target_version > 0. */
    errno = 0;
    failures += expect_unsupported(
        platform_rollback_policy("no-such-exam", 1, NULL),
        "signed policy rollback");

    /* platform_set_device_maintenance: non-empty device_id + valid flag. */
    errno = 0;
    failures += expect_unsupported(
        platform_set_device_maintenance("no-such-device", 1),
        "fleet maintenance mutation");

    char telemetry[1024] = {0};
    if (platform_get_telemetry_json(telemetry, sizeof(telemetry)) != 0 ||
        !strstr(telemetry, "\"status\":\"NOT_PRODUCTION_READY\"") ||
        !strstr(telemetry, "\"platform_registry_persistence\":\"NOT_IMPLEMENTED\"") ||
        !strstr(telemetry, "\"submission_storage\":\"NOT_PROVISIONED\"")) {
        fprintf(stderr,
                "FAIL: platform telemetry does not expose its unprovisioned state"
                " (got: %.256s)\n", telemetry);
        failures++;
    }

    char reconciliation[512] = {0};
    if (platform_get_reconciliation_json(NULL, reconciliation, sizeof(reconciliation)) != 0 ||
        !strstr(reconciliation, "\"reconciliation_status\":\"NO_DATA\"")) {
        fprintf(stderr,
                "FAIL: empty reconciliation was reported as a balanced exam"
                " (got: %.256s)\n", reconciliation);
        failures++;
    }

    if (failures != 0) return 1;
    puts("PASS: unprovisioned policy, storage, fleet, and reconciliation paths fail closed");
    return 0;
}
