#include "../../server/include/attestation_service.h"
#include "../../server/include/enterprise_platform.h"
#include "../../server/include/exam_engine.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int expect_unsupported(int result, const char *operation) {
    if (result == -1 && errno == ENOTSUP) return 0;
    fprintf(stderr, "FAIL: %s did not fail with ENOTSUP\n", operation);
    return 1;
}

int main(void) {
    int failures = 0;

    if (exam_engine_init() != 0 || exam_engine_is_ready()) {
        fprintf(stderr, "FAIL: exam engine was ready without provisioned content\n");
        failures++;
    }

    errno = 0;
    failures += expect_unsupported(enterprise_platform_save_all(),
                                   "platform persistence");
    errno = 0;
    failures += expect_unsupported(platform_update_exam_state("", EXAM_STATE_ACTIVE, NULL),
                                   "exam lifecycle mutation");
    errno = 0;
    failures += expect_unsupported(platform_update_exam_url("", "", "", NULL),
                                   "signed exam policy update");
    errno = 0;
    failures += expect_unsupported(platform_rollback_policy("", 0, NULL),
                                   "signed policy rollback");
    errno = 0;
    failures += expect_unsupported(platform_set_device_maintenance("", 0),
                                   "fleet maintenance mutation");

    char telemetry[1024] = {0};
    if (platform_get_telemetry_json(telemetry, sizeof(telemetry)) != 0 ||
        !strstr(telemetry, "\"status\":\"NOT_PRODUCTION_READY\"") ||
        !strstr(telemetry, "\"platform_registry_persistence\":\"NOT_IMPLEMENTED\"") ||
        !strstr(telemetry, "\"submission_storage\":\"NOT_PROVISIONED\"")) {
        fprintf(stderr, "FAIL: platform telemetry does not expose its unprovisioned state\n");
        failures++;
    }

    char reconciliation[512] = {0};
    if (platform_get_reconciliation_json(NULL, reconciliation, sizeof(reconciliation)) != 0 ||
        !strstr(reconciliation, "\"reconciliation_status\":\"NO_DATA\"")) {
        fprintf(stderr, "FAIL: empty reconciliation was reported as a balanced exam\n");
        failures++;
    }

    if (failures != 0) return 1;
    puts("PASS: unprovisioned exam, policy, storage, fleet, and reconciliation paths fail closed");
    return 0;
}
