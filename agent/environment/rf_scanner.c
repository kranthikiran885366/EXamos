#define _GNU_SOURCE
#include "../include/rf_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stddef.h>

int rf_scanner_init(void) {
    return 0;
}

int rf_scanner_scan(rf_environment_t *rf_env) {
    if (!rf_env) return -1;
    memset(rf_env, 0, sizeof(rf_environment_t));

    int count = 0;

    /* First inspect /proc/net/wireless to detect active wireless interfaces */
    FILE *fp = fopen("/proc/net/wireless", "r");
    char ifnames[4][32];
    int if_count = 0;

    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            char ifname[32] = {0};
            int link = 0, level = 0, noise = 0;
            if (sscanf(line, " %31[^:]: %*d %d. %d. %d", ifname, &link, &level, &noise) >= 3) {
                if (if_count < 4) {
                    strncpy(ifnames[if_count], ifname, sizeof(ifnames[if_count]) - 1);
                    ifnames[if_count][sizeof(ifnames[if_count]) - 1] = '\0';
                    if_count++;
                }
            }
        }
        fclose(fp);
    }

    /* Try real active scan using iw command for each detected wireless interface */
    for (int i = 0; i < if_count && count < 16; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "iw dev %s scan 2>/dev/null", ifnames[i]);
        FILE *iw_fp = popen(cmd, "r");
        if (iw_fp) {
            char line[512];
            char cur_bssid[32] = {0};
            char cur_ssid[64] = {0};
            int cur_signal = -100;
            int in_bss = 0;

            while (fgets(line, sizeof(line), iw_fp) && count < 16) {
                if (strncmp(line, "BSS ", 4) == 0) {
                    if (in_bss && cur_bssid[0] != '\0') {
                        strncpy(rf_env->networks[count].bssid, cur_bssid, sizeof(rf_env->networks[count].bssid) - 1);
                        strncpy(rf_env->networks[count].ssid, cur_ssid[0] ? cur_ssid : "[Hidden]", sizeof(rf_env->networks[count].ssid) - 1);
                        rf_env->networks[count].signal_dbm = cur_signal;
                        count++;
                    }
                    in_bss = 1;
                    cur_ssid[0] = '\0';
                    cur_signal = -100;
                    sscanf(line, "BSS %31[0-9a-fA-F:](", cur_bssid);
                } else if (in_bss && strstr(line, "SSID: ")) {
                    char *p = strstr(line, "SSID: ") + 6;
                    char *nl = strchr(p, '\n');
                    if (nl) *nl = '\0';
                    strncpy(cur_ssid, p, sizeof(cur_ssid) - 1);
                } else if (in_bss && strstr(line, "signal: ")) {
                    float sig = -100.0f;
                    if (sscanf(strstr(line, "signal: ") + 8, "%f", &sig) == 1) {
                        cur_signal = (int)sig;
                    }
                }
            }
            if (in_bss && cur_bssid[0] != '\0' && count < 16) {
                strncpy(rf_env->networks[count].bssid, cur_bssid, sizeof(rf_env->networks[count].bssid) - 1);
                strncpy(rf_env->networks[count].ssid, cur_ssid[0] ? cur_ssid : "[Hidden]", sizeof(rf_env->networks[count].ssid) - 1);
                rf_env->networks[count].signal_dbm = cur_signal;
                count++;
            }
            pclose(iw_fp);
        }
    }

    /* If no iw results found, report interfaces honestly as UNKNOWN BSSID */
    if (count == 0 && if_count > 0) {
        for (int i = 0; i < if_count && count < 16; i++) {
            strncpy(rf_env->networks[count].bssid, "UNKNOWN", sizeof(rf_env->networks[count].bssid) - 1);
            snprintf(rf_env->networks[count].ssid, sizeof(rf_env->networks[count].ssid), "WLAN-%s", ifnames[i]);
            rf_env->networks[count].signal_dbm = -70;
            count++;
        }
    }

    rf_env->wifi_network_count = count;

    /* Count Bluetooth state in sysfs */
    int bt_count = 0;
    DIR *bt_dir = opendir("/sys/class/bluetooth");
    if (bt_dir) {
        struct dirent *entry;
        while ((entry = readdir(bt_dir)) != NULL) {
            if (entry->d_name[0] != '.') {
                bt_count++;
            }
        }
        closedir(bt_dir);
    }
    rf_env->bluetooth_devices_nearby = bt_count;

    return 0;
}

int rf_scanner_format_json(const rf_environment_t *rf_env, char *out_buf, size_t max_len) {
    if (!rf_env || !out_buf || max_len == 0) return -1;

    char nets_json[1024] = {0};
    strcat(nets_json, "[");
    for (int i = 0; i < rf_env->wifi_network_count; i++) {
        char item[128];
        snprintf(item, sizeof(item),
                 "{\"bssid\":\"%s\",\"ssid\":\"%s\",\"signal\":%d}%s",
                 rf_env->networks[i].bssid,
                 rf_env->networks[i].ssid,
                 rf_env->networks[i].signal_dbm,
                 (i < rf_env->wifi_network_count - 1) ? "," : "");
        strcat(nets_json, item);
    }
    strcat(nets_json, "]");

    snprintf(out_buf, max_len,
             "{"
             "\"wifi_count\":%d,"
             "\"networks\":%s,"
             "\"bluetooth_devices\":%d"
             "}",
             rf_env->wifi_network_count,
             nets_json,
             rf_env->bluetooth_devices_nearby);

    return 0;
}
