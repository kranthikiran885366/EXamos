#include "../../agent/include/rf_scanner.h"

#include <stdio.h>
#include <string.h>

static int require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "[E1-RF] FAIL: %s\n", message);
        return 0;
    }
    return 1;
}

int main(void)
{
    rf_environment_t environment;
    char json[256];
    char short_json[8];

    if (!require(rf_scanner_get_status(&environment) == 0,
                 "collection status retrieval failed") ||
        !require(environment.wifi_state == RF_SENSOR_STATE_DISABLED_BY_POLICY &&
                 environment.ble_state == RF_SENSOR_STATE_DISABLED_BY_POLICY &&
                 environment.rf_state == RF_SENSOR_STATE_DISABLED_BY_POLICY,
                 "unconfigured environment sources must remain disabled") ||
        !require(rf_scanner_format_json(&environment, json, sizeof(json)) == 0,
                 "status JSON formatting failed") ||
        !require(strstr(json, "\"state\":\"DISABLED_BY_POLICY\"") != NULL &&
                 strstr(json, "\"observation\":\"NOT_COLLECTED\"") != NULL,
                 "serialized status must distinguish disabled from zero observations") ||
        !require(strstr(json, "bssid") == NULL &&
                 strstr(json, "ssid") == NULL &&
                 strstr(json, "signal") == NULL &&
                 strstr(json, "bluetooth_devices") == NULL,
                 "status JSON must not contain unapproved identifiers or invented measurements") ||
        !require(rf_scanner_format_json(&environment, short_json, sizeof(short_json)) == -1,
                 "truncated JSON output must be reported") ||
        !require(rf_scanner_get_status(NULL) == -1,
                 "null status output must be rejected") ||
        !require(rf_scanner_format_json(NULL, json, sizeof(json)) == -1,
                 "null environment input must be rejected")) {
        return 1;
    }

    puts("[E1-RF] PASS: no radio scan is performed; unconfigured sources are explicitly not collected.");
    return 0;
}
