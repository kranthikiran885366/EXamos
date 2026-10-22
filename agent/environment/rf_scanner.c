#define _GNU_SOURCE
#include "../include/rf_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stddef.h>
#include <net/if.h>
#include <ctype.h>
#include <stdarg.h>

static void copy_field(char *destination, size_t capacity, const char *source) {
    if (!destination || capacity == 0) return;
    size_t length = source ? strnlen(source, capacity - 1) : 0;
    if (length) memcpy(destination, source, length);
    destination[length] = '\0';
}

static int valid_interface_name(const char *name) {
    size_t length = name ? strnlen(name, IFNAMSIZ) : 0;
    if (length == 0 || length >= IFNAMSIZ) return 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) return 0;
    }
    return 1;
}

static int append_format(char *buffer, size_t capacity, size_t *used,
                         const char *format, ...) {
    if (*used >= capacity) return -1;
    va_list args;
    va_start(args, format);
    int written = vsnprintf(buffer + *used, capacity - *used, format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= capacity - *used) return -1;
    *used += (size_t)written;
    return 0;
}

static int append_json_string(char *buffer, size_t capacity, size_t *used,
                              const char *value, size_t value_capacity) {
    if (append_format(buffer, capacity, used, "\"") != 0) return -1;
    size_t value_length = strnlen(value, value_capacity);
    if (value_length == value_capacity) return -1;
    for (size_t i = 0; i < value_length; ++i) {
        const unsigned char *p = (const unsigned char *)value + i;
        char escaped[6];
        size_t length = 0;
        switch (*p) {
            case '"': escaped[0] = '\\'; escaped[1] = '"'; length = 2; break;
            case '\\': escaped[0] = '\\'; escaped[1] = '\\'; length = 2; break;
            case '\b': escaped[0] = '\\'; escaped[1] = 'b'; length = 2; break;
            case '\f': escaped[0] = '\\'; escaped[1] = 'f'; length = 2; break;
            case '\n': escaped[0] = '\\'; escaped[1] = 'n'; length = 2; break;
            case '\r': escaped[0] = '\\'; escaped[1] = 'r'; length = 2; break;
            case '\t': escaped[0] = '\\'; escaped[1] = 't'; length = 2; break;
            default:
                if (*p < 0x20) {
                    static const char hex[] = "0123456789abcdef";
                    escaped[0] = '\\'; escaped[1] = 'u'; escaped[2] = '0'; escaped[3] = '0';
                    escaped[4] = hex[*p >> 4]; escaped[5] = hex[*p & 15]; length = 6;
                } else {
                    if (*used + 1 >= capacity) return -1;
                    buffer[(*used)++] = (char)*p;
                    buffer[*used] = '\0';
                    continue;
                }
        }
        if (*used + length >= capacity) return -1;
        memcpy(buffer + *used, escaped, length);
        *used += length;
        buffer[*used] = '\0';
    }
    return append_format(buffer, capacity, used, "\"");
}

int rf_scanner_init(void) {
    return 0;
}

int rf_scanner_scan(rf_environment_t *rf_env) {
    if (!rf_env) return -1;
    memset(rf_env, 0, sizeof(rf_environment_t));

    int count = 0;

    /* First inspect /proc/net/wireless to detect active wireless interfaces */
    FILE *fp = fopen("/proc/net/wireless", "r");
    char ifnames[4][IFNAMSIZ];
    int if_count = 0;

    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            char ifname[IFNAMSIZ] = {0};
            int link = 0, level = 0, noise = 0;
            if (sscanf(line, " %15[^:]: %*d %d. %d. %d", ifname, &link, &level, &noise) >= 3 &&
                valid_interface_name(ifname)) {
                if (if_count < 4) {
                    memcpy(ifnames[if_count], ifname, strlen(ifname) + 1);
                    if_count++;
                }
            }
        }
        fclose(fp);
    }

    /* Try real active scan using iw command for each detected wireless interface */
    for (int i = 0; i < if_count && count < 16; i++) {
        char cmd[64];
        int command_length = snprintf(cmd, sizeof(cmd), "iw dev %s scan 2>/dev/null", ifnames[i]);
        if (command_length < 0 || (size_t)command_length >= sizeof(cmd)) continue;
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
                        copy_field(rf_env->networks[count].bssid, sizeof(rf_env->networks[count].bssid), cur_bssid);
                        copy_field(rf_env->networks[count].ssid, sizeof(rf_env->networks[count].ssid), cur_ssid[0] ? cur_ssid : "[Hidden]");
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
                    copy_field(cur_ssid, sizeof(cur_ssid), p);
                } else if (in_bss && strstr(line, "signal: ")) {
                    float sig = -100.0f;
                    if (sscanf(strstr(line, "signal: ") + 8, "%f", &sig) == 1) {
                        cur_signal = (int)sig;
                    }
                }
            }
            if (in_bss && cur_bssid[0] != '\0' && count < 16) {
                copy_field(rf_env->networks[count].bssid, sizeof(rf_env->networks[count].bssid), cur_bssid);
                copy_field(rf_env->networks[count].ssid, sizeof(rf_env->networks[count].ssid), cur_ssid[0] ? cur_ssid : "[Hidden]");
                rf_env->networks[count].signal_dbm = cur_signal;
                count++;
            }
            pclose(iw_fp);
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
    out_buf[0] = '\0';
    if (rf_env->wifi_network_count < 0 ||
        rf_env->wifi_network_count > (int)(sizeof(rf_env->networks) / sizeof(rf_env->networks[0])) ||
        rf_env->bluetooth_devices_nearby < 0) return -1;
    size_t used = 0;
    if (append_format(out_buf, max_len, &used,
        "{\"wifi_count\":%d,\"networks\":[", rf_env->wifi_network_count) != 0) return -1;
    for (int i = 0; i < rf_env->wifi_network_count; ++i) {
        if (i && append_format(out_buf, max_len, &used, ",") != 0) return -1;
        if (append_format(out_buf, max_len, &used, "{\"bssid\":") != 0 ||
            append_json_string(out_buf, max_len, &used, rf_env->networks[i].bssid,
                               sizeof(rf_env->networks[i].bssid)) != 0 ||
            append_format(out_buf, max_len, &used, ",\"ssid\":") != 0 ||
            append_json_string(out_buf, max_len, &used, rf_env->networks[i].ssid,
                               sizeof(rf_env->networks[i].ssid)) != 0 ||
            append_format(out_buf, max_len, &used, ",\"signal\":%d}",
                          rf_env->networks[i].signal_dbm) != 0) return -1;
    }
    return append_format(out_buf, max_len, &used,
        "],\"bluetooth_devices\":%d}", rf_env->bluetooth_devices_nearby);
}
