#define _GNU_SOURCE
#include "../include/hardware_guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

int hardware_guard_init(void) {
    return 0;
}

static int count_active_displays(int *out_external) {
    int connected_count = 0;
    int external_count = 0;
    DIR *dir = opendir("/sys/class/drm");
    if (!dir) return 1; // Default assume 1 primary display if sysfs inaccessible

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "card", 4) == 0 && strchr(entry->d_name, '-')) {
            char status_path[512];
            snprintf(status_path, sizeof(status_path), "/sys/class/drm/%s/status", entry->d_name);
            FILE *f = fopen(status_path, "r");
            if (f) {
                char status[32] = {0};
                if (fgets(status, sizeof(status), f)) {
                    if (strncmp(status, "connected", 9) == 0) {
                        connected_count++;
                        // Check if it is an external display (HDMI, DP, VGA, DVI) vs internal eDP/LVDS
                        if (strstr(entry->d_name, "HDMI") || strstr(entry->d_name, "DP") ||
                            strstr(entry->d_name, "VGA") || strstr(entry->d_name, "DVI")) {
                            external_count++;
                        }
                    }
                }
                fclose(f);
            }
        }
    }
    closedir(dir);

    if (out_external) *out_external = (external_count > 0 && connected_count > 1);
    return (connected_count > 0) ? connected_count : 1;
}

static int check_usb_mass_storage(void) {
    DIR *dir = opendir("/sys/bus/usb/devices");
    if (!dir) return 0;

    int storage_found = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char class_path[512];
        snprintf(class_path, sizeof(class_path), "/sys/bus/usb/devices/%s/bInterfaceClass", entry->d_name);
        FILE *f = fopen(class_path, "r");
        if (f) {
            char class_code[16] = {0};
            if (fgets(class_code, sizeof(class_code), f)) {
                // Class 08 = Mass Storage
                if (strncmp(class_code, "08", 2) == 0) {
                    storage_found = 1;
                }
            }
            fclose(f);
        }
    }
    closedir(dir);
    return storage_found;
}

int hardware_guard_scan(hardware_state_t *state) {
    if (!state) return -1;
    memset(state, 0, sizeof(hardware_state_t));

    int external_flag = 0;
    state->display_count = count_active_displays(&external_flag);
    state->external_display_detected = external_flag;
    state->usb_storage_detected = check_usb_mass_storage();
    state->audio_input_available = (access("/dev/snd/pcmC0D0c", F_OK) == 0 || access("/dev/snd", F_OK) == 0);
    state->audio_output_available = (access("/dev/snd/pcmC0D0p", F_OK) == 0 || access("/dev/snd", F_OK) == 0);

    // Flag security violation if unauthorized multi-display or USB storage is detected
    state->unauthorized_device_flag = (state->external_display_detected || state->usb_storage_detected);

    return 0;
}

int hardware_guard_format_json(const hardware_state_t *state, char *out_buf, size_t max_len) {
    if (!state || !out_buf || max_len == 0) return -1;

    snprintf(out_buf, max_len,
             "{"
             "\"displays\":%d,"
             "\"external_display_violation\":%s,"
             "\"usb_storage_violation\":%s,"
             "\"audio_in\":%s,"
             "\"audio_out\":%s,"
             "\"unauthorized_hardware\":%s"
             "}",
             state->display_count,
             state->external_display_detected ? "true" : "false",
             state->usb_storage_detected ? "true" : "false",
             state->audio_input_available ? "true" : "false",
             state->audio_output_available ? "true" : "false",
             state->unauthorized_device_flag ? "true" : "false");

    return 0;
}
