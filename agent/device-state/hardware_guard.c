#define _GNU_SOURCE
#include "../include/hardware_guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

static const char *g_blacklisted_processes[] = {
    "gdb", "strace", "ltrace", "wireshark", "tshark", "tcpdump",
    "obs", "ffmpeg", "vlc", "nc", "netcat", "ncat", "socat",
    "anydesk", "teamviewer", "rustdesk", "vncserver", NULL
};

int hardware_guard_init(void) {
    return 0;
}

static int scan_and_terminate_prohibited_processes(void) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return 0;

    int violation_found = 0;
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            char *pid_end = NULL;
            errno = 0;
            long parsed_pid = strtol(entry->d_name, &pid_end, 10);
            if (errno != 0 || pid_end == entry->d_name || *pid_end != '\0' ||
                parsed_pid <= 1 || parsed_pid > INT_MAX || parsed_pid == getpid()) continue;
            pid_t pid = (pid_t)parsed_pid;

            char comm_path[512];
            int path_length = snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", parsed_pid);
            if (path_length < 0 || (size_t)path_length >= sizeof(comm_path)) continue;
            FILE *f = fopen(comm_path, "r");
            if (f) {
                char comm[64] = {0};
                if (fgets(comm, sizeof(comm), f)) {
                    char *nl = strchr(comm, '\n');
                    if (nl) *nl = '\0';

                    for (int i = 0; g_blacklisted_processes[i] != NULL; i++) {
                        if (strcasecmp(comm, g_blacklisted_processes[i]) == 0) {
                            violation_found = 1;
                            kill(pid, SIGKILL);
                            break;
                        }
                    }
                }
                fclose(f);
            }
        }
    }
    closedir(proc_dir);
    return violation_found;
}

static int count_active_displays(int *out_external) {
    int connected_count = 0;
    int external_count = 0;
    DIR *dir = opendir("/sys/class/drm");
    if (!dir) return 1;

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
    state->process_violation_detected = scan_and_terminate_prohibited_processes();
    state->audio_input_available = (access("/dev/snd/pcmC0D0c", F_OK) == 0 || access("/dev/snd", F_OK) == 0);
    state->audio_output_available = (access("/dev/snd/pcmC0D0p", F_OK) == 0 || access("/dev/snd", F_OK) == 0);

    state->unauthorized_device_flag = (state->external_display_detected ||
                                       state->usb_storage_detected ||
                                       state->process_violation_detected);

    return 0;
}

int hardware_guard_format_json(const hardware_state_t *state, char *out_buf, size_t max_len) {
    if (!state || !out_buf || max_len == 0) return -1;

    snprintf(out_buf, max_len,
             "{"
             "\"displays\":%d,"
             "\"external_display_violation\":%s,"
             "\"usb_storage_violation\":%s,"
             "\"process_violation\":%s,"
             "\"audio_in\":%s,"
             "\"audio_out\":%s,"
             "\"unauthorized_hardware\":%s"
             "}",
             state->display_count,
             state->external_display_detected ? "true" : "false",
             state->usb_storage_detected ? "true" : "false",
             state->process_violation_detected ? "true" : "false",
             state->audio_input_available ? "true" : "false",
             state->audio_output_available ? "true" : "false",
             state->unauthorized_device_flag ? "true" : "false");

    return 0;
}
