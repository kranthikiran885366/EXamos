#define _GNU_SOURCE
#include "../include/rf_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stddef.h>
#include <fcntl.h>
#include <net/if.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/wait.h>

static void copy_field(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    size_t len = src ? strnlen(src, cap - 1) : 0;
    if (len) memcpy(dst, src, len);
    dst[len] = '\0';
}

static int valid_interface_name(const char *name) {
    size_t len = name ? strnlen(name, IFNAMSIZ) : 0;
    if (len == 0 || len >= IFNAMSIZ) return 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) return 0;
    }
    return 1;
}

static int append_fmt(char *buf, size_t cap, size_t *used, const char *fmt, ...) {
    if (*used >= cap) return -1;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *used) return -1;
    *used += (size_t)n;
    return 0;
}

static int append_json_str(char *buf, size_t cap, size_t *used,
                           const char *val, size_t val_cap) {
    if (append_fmt(buf, cap, used, "\"") != 0) return -1;
    size_t vlen = strnlen(val, val_cap);
    if (vlen == val_cap) return -1;
    for (size_t i = 0; i < vlen; ++i) {
        unsigned char c = (unsigned char)val[i];
        char esc[6]; size_t elen = 0;
        switch (c) {
            case '"':  esc[0]='\\'; esc[1]='"';  elen=2; break;
            case '\\': esc[0]='\\'; esc[1]='\\'; elen=2; break;
            case '\b': esc[0]='\\'; esc[1]='b';  elen=2; break;
            case '\f': esc[0]='\\'; esc[1]='f';  elen=2; break;
            case '\n': esc[0]='\\'; esc[1]='n';  elen=2; break;
            case '\r': esc[0]='\\'; esc[1]='r';  elen=2; break;
            case '\t': esc[0]='\\'; esc[1]='t';  elen=2; break;
            default:
                if (c < 0x20) {
                    static const char hex[] = "0123456789abcdef";
                    esc[0]='\\'; esc[1]='u'; esc[2]='0'; esc[3]='0';
                    esc[4]=hex[c>>4]; esc[5]=hex[c&15]; elen=6;
                } else {
                    if (*used + 1 >= cap) return -1;
                    buf[(*used)++] = (char)c;
                    buf[*used] = '\0';
                    continue;
                }
        }
        if (*used + elen >= cap) return -1;
        memcpy(buf + *used, esc, elen);
        *used += elen;
        buf[*used] = '\0';
    }
    return append_fmt(buf, cap, used, "\"");
}

int rf_scanner_init(void) { return 0; }

int rf_scanner_scan(rf_environment_t *rf_env) {
    if (!rf_env) return -1;
    memset(rf_env, 0, sizeof(rf_environment_t));

    int count = 0;
    char ifnames[4][IFNAMSIZ];
    int if_count = 0;

    /* Detect wireless interfaces from /proc/net/wireless */
    FILE *fp = fopen("/proc/net/wireless", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            char ifname[IFNAMSIZ] = {0};
            int link = 0, level = 0, noise = 0;
            if (sscanf(line, " %15[^:]: %*d %d. %d. %d",
                       ifname, &link, &level, &noise) >= 3 &&
                valid_interface_name(ifname) && if_count < 4) {
                memcpy(ifnames[if_count++], ifname, strlen(ifname) + 1);
            }
        }
        fclose(fp);
    }

    /*
     * Scan each interface with: iw dev <ifname> scan
     * Uses fork/execvp — no shell, no injection possible.
     */
    for (int i = 0; i < if_count && count < 16; i++) {
        int pipefd[2];
        if (pipe(pipefd) != 0) continue;

        pid_t child = fork();
        if (child < 0) { close(pipefd[0]); close(pipefd[1]); continue; }
        if (child == 0) {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
            char *const argv[] = { "iw", "dev", ifnames[i], "scan", NULL };
            execvp("iw", argv);
            _exit(127);
        }
        close(pipefd[1]);

        FILE *iw_fp = fdopen(pipefd[0], "r");
        if (!iw_fp) { close(pipefd[0]); waitpid(child, NULL, 0); continue; }

        char scan_line[512];
        char cur_bssid[32] = {0}, cur_ssid[64] = {0};
        int  cur_signal = -100, in_bss = 0;

        while (fgets(scan_line, sizeof(scan_line), iw_fp) && count < 16) {
            if (strncmp(scan_line, "BSS ", 4) == 0) {
                if (in_bss && cur_bssid[0]) {
                    copy_field(rf_env->networks[count].bssid,
                               sizeof(rf_env->networks[count].bssid), cur_bssid);
                    copy_field(rf_env->networks[count].ssid,
                               sizeof(rf_env->networks[count].ssid),
                               cur_ssid[0] ? cur_ssid : "[Hidden]");
                    rf_env->networks[count].signal_dbm = cur_signal;
                    count++;
                }
                in_bss = 1; cur_ssid[0] = '\0'; cur_signal = -100;
                sscanf(scan_line, "BSS %31[0-9a-fA-F:](", cur_bssid);
            } else if (in_bss && strstr(scan_line, "SSID: ")) {
                char *p = strstr(scan_line, "SSID: ") + 6;
                char *nl = strchr(p, '\n'); if (nl) *nl = '\0';
                copy_field(cur_ssid, sizeof(cur_ssid), p);
            } else if (in_bss && strstr(scan_line, "signal: ")) {
                float sig = -100.0f;
                if (sscanf(strstr(scan_line, "signal: ") + 8, "%f", &sig) == 1)
                    cur_signal = (int)sig;
            }
        }
        if (in_bss && cur_bssid[0] && count < 16) {
            copy_field(rf_env->networks[count].bssid,
                       sizeof(rf_env->networks[count].bssid), cur_bssid);
            copy_field(rf_env->networks[count].ssid,
                       sizeof(rf_env->networks[count].ssid),
                       cur_ssid[0] ? cur_ssid : "[Hidden]");
            rf_env->networks[count].signal_dbm = cur_signal;
            count++;
        }
        fclose(iw_fp);
        waitpid(child, NULL, 0);
    }

    rf_env->wifi_network_count = count;

    /* Count Bluetooth adapters from sysfs */
    int bt_count = 0;
    DIR *bt_dir = opendir("/sys/class/bluetooth");
    if (bt_dir) {
        struct dirent *entry;
        while ((entry = readdir(bt_dir)) != NULL)
            if (entry->d_name[0] != '.') bt_count++;
        closedir(bt_dir);
    }
    rf_env->bluetooth_devices_nearby = bt_count;
    return 0;
}

int rf_scanner_format_json(const rf_environment_t *rf_env, char *out_buf, size_t max_len) {
    if (!rf_env || !out_buf || max_len == 0) return -1;
    out_buf[0] = '\0';
    if (rf_env->wifi_network_count < 0 ||
        rf_env->wifi_network_count > (int)(sizeof(rf_env->networks)/sizeof(rf_env->networks[0])) ||
        rf_env->bluetooth_devices_nearby < 0) return -1;
    size_t used = 0;
    if (append_fmt(out_buf, max_len, &used,
        "{\"wifi_count\":%d,\"networks\":[", rf_env->wifi_network_count) != 0) return -1;
    for (int i = 0; i < rf_env->wifi_network_count; ++i) {
        if (i && append_fmt(out_buf, max_len, &used, ",") != 0) return -1;
        if (append_fmt(out_buf, max_len, &used, "{\"bssid\":") != 0 ||
            append_json_str(out_buf, max_len, &used, rf_env->networks[i].bssid,
                            sizeof(rf_env->networks[i].bssid)) != 0 ||
            append_fmt(out_buf, max_len, &used, ",\"ssid\":") != 0 ||
            append_json_str(out_buf, max_len, &used, rf_env->networks[i].ssid,
                            sizeof(rf_env->networks[i].ssid)) != 0 ||
            append_fmt(out_buf, max_len, &used, ",\"signal\":%d}",
                       rf_env->networks[i].signal_dbm) != 0) return -1;
    }
    return append_fmt(out_buf, max_len, &used,
        "],\"bluetooth_devices\":%d}", rf_env->bluetooth_devices_nearby);
}
