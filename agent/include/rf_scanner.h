#ifndef EXAMOS_RF_SCANNER_H
#define EXAMOS_RF_SCANNER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char bssid[32];
    char ssid[64];
    int signal_dbm;
} wifi_ap_t;

typedef struct {
    int wifi_network_count;
    wifi_ap_t networks[16];
    int bluetooth_devices_nearby;
} rf_environment_t;

int rf_scanner_init(void);
int rf_scanner_scan(rf_environment_t *rf_env);
int rf_scanner_format_json(const rf_environment_t *rf_env, char *out_buf, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif // EXAMOS_RF_SCANNER_H
