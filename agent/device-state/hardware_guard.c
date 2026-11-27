#define _GNU_SOURCE
#include "../include/hardware_guard.h"
#include "../include/anti_vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/videodev2.h>

static const char *g_blacklisted_processes[] = {
    "gdb", "strace", "ltrace", "wireshark", "tshark", "tcpdump",
    "obs", "ffmpeg", "vlc", "nc", "netcat", "ncat", "socat",
    "anydesk", "teamviewer", "rustdesk", "vncserver", NULL
};

static int g_baseline_displays = 1;
static int g_guard_initialized = 0;
static int g_uevent_fd = -1;
static int g_uevent_pending = 0;

static int scan_and_terminate_prohibited_processes(void);
static int count_active_displays(int *out_external);

/*
 * Opens the kernel udev/kobject netlink socket so hotplug events are observed
 * as they happen instead of only on the next polling pass. The socket is
 * non-blocking; scan drains whatever is queued.
 */
static int init_uevent_monitor(void) {
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                    NETLINK_KOBJECT_UEVENT);
    if (fd < 0) return -1;

    struct sockaddr_nl address;
    memset(&address, 0, sizeof(address));
    address.nl_family = AF_NETLINK;
    address.nl_groups = 1; /* kernel events */

    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    g_uevent_fd = fd;
    return 0;
}

static void drain_uevents(void) {
    if (g_uevent_fd < 0) return;

    char buffer[4096];
    for (;;) {
        ssize_t length = recv(g_uevent_fd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
        if (length <= 0) break;
        buffer[length] = '\0';
        if (strncmp(buffer, "add@", 4) == 0 ||
            strncmp(buffer, "remove@", 7) == 0 ||
            strncmp(buffer, "change@", 7) == 0) {
            g_uevent_pending = 1;
        }
    }
}

int hardware_guard_uevent_pending(void) {
    drain_uevents();
    int pending = g_uevent_pending;
    g_uevent_pending = 0;
    return pending;
}

void hardware_guard_shutdown(void) {
    if (g_uevent_fd >= 0) {
        close(g_uevent_fd);
        g_uevent_fd = -1;
    }
    g_guard_initialized = 0;
}

int hardware_guard_init(void) {
    if (access("/proc", R_OK | X_OK) != 0) {
        return -1;
    }
    if (g_uevent_fd < 0 && init_uevent_monitor() != 0) {
        return -1;
    }
    int ext = 0;
    g_baseline_displays = count_active_displays(&ext);
    scan_and_terminate_prohibited_processes();
    g_guard_initialized = 1;
    return ext ? -1 : 0;
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

/*
 * Enumerates V4L2 capture devices and verifies that each one is a real
 * video-capture device by issuing a VIDIOC_QUERYCAP ioctl. Presence of a
 * /dev/videoN node is not enough: the node may be a metadata or output
 * device, or may be busy.
 */
static int detect_cameras(int *out_count) {
    if (out_count) *out_count = 0;
    DIR *dev_dir = opendir("/dev");
    if (!dev_dir) return -1;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dev_dir)) != NULL) {
        if (strncmp(entry->d_name, "video", 5) != 0) continue;
        if (!isdigit((unsigned char)entry->d_name[5])) continue;

        char path[256];
        if (snprintf(path, sizeof(path), "/dev/%s", entry->d_name) >= (int)sizeof(path))
            continue;

        int fd = open(path, O_RDWR | O_NONBLOCK);
        if (fd < 0) fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;

        struct v4l2_capability cap;
        memset(&cap, 0, sizeof(cap));
        if (ioctl(fd, VIDIOC_QUERYCAP, &cap) == 0 &&
            (cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
            count++;
        }
        close(fd);
    }
    closedir(dev_dir);
    if (out_count) *out_count = count;
    return 0;
}

/*
 * Measures network reachability from the kernel's own view of the link
 * state. Every non-loopback interface is inspected; the device is ONLINE
 * when at least one of them is up. This deliberately does not assume a
 * particular interface name, address scheme, or gateway.
 */
device_network_state_t hardware_guard_detect_network(void) {
    DIR *net_dir = opendir("/sys/class/net");
    if (!net_dir) return DEVICE_NETWORK_UNKNOWN;

    device_network_state_t state = DEVICE_NETWORK_UNKNOWN;
    int usable_interfaces = 0;
    int up_interfaces = 0;

    struct dirent *entry;
    while ((entry = readdir(net_dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (strcmp(entry->d_name, "lo") == 0) continue;

        usable_interfaces++;

        char operstate_path[512];
        if (snprintf(operstate_path, sizeof(operstate_path),
                     "/sys/class/net/%s/operstate", entry->d_name) >= (int)sizeof(operstate_path))
            continue;

        FILE *f = fopen(operstate_path, "r");
        if (!f) continue;
        char operstate[32] = {0};
        if (fgets(operstate, sizeof(operstate), f)) {
            char *newline = strchr(operstate, '\n');
            if (newline) *newline = '\0';
            if (strcmp(operstate, "up") == 0) up_interfaces++;
        }
        fclose(f);
    }
    closedir(net_dir);

    if (up_interfaces > 0) state = DEVICE_NETWORK_ONLINE;
    else if (usable_interfaces > 0) state = DEVICE_NETWORK_OFFLINE;
    return state;
}

const char *hardware_guard_network_state_name(device_network_state_t state) {
    switch (state) {
        case DEVICE_NETWORK_ONLINE:  return "ONLINE";
        case DEVICE_NETWORK_OFFLINE: return "OFFLINE";
        default:                     return "UNKNOWN";
    }
}

int hardware_guard_scan(hardware_state_t *state) {
    if (!state) return -1;
    memset(state, 0, sizeof(hardware_state_t));
    drain_uevents();

    int external_flag = 0;
    state->display_count = count_active_displays(&external_flag);
    state->external_display_detected = external_flag;
    state->usb_storage_detected = check_usb_mass_storage();
    state->process_violation_detected = scan_and_terminate_prohibited_processes();
    state->audio_input_available = (access("/dev/snd/pcmC0D0c", F_OK) == 0 || access("/dev/snd", F_OK) == 0);
    state->audio_output_available = (access("/dev/snd/pcmC0D0p", F_OK) == 0 || access("/dev/snd", F_OK) == 0);

    state->camera_count = 0;
    detect_cameras(&state->camera_count);
    state->camera_available = (state->camera_count > 0);

    state->network_state = (int)hardware_guard_detect_network();

    examos_anti_vm_report_t vm_report;
    if (examos_anti_vm_check(&vm_report) == 1) {
        state->vm_detected = 1;
    }

    state->unauthorized_device_flag = (state->external_display_detected ||
                                       state->usb_storage_detected ||
                                       state->process_violation_detected ||
                                       state->vm_detected);

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
             "\"camera_available\":%s,"
             "\"camera_count\":%d,"
             "\"network_state\":\"%s\","
             "\"vm_detected\":%s,"
             "\"unauthorized_hardware\":%s"
             "}",
             state->display_count,
             state->external_display_detected ? "true" : "false",
             state->usb_storage_detected ? "true" : "false",
             state->process_violation_detected ? "true" : "false",
             state->audio_input_available ? "true" : "false",
             state->audio_output_available ? "true" : "false",
             state->camera_available ? "true" : "false",
             state->camera_count,
             hardware_guard_network_state_name((device_network_state_t)state->network_state),
             state->vm_detected ? "true" : "false",
             state->unauthorized_device_flag ? "true" : "false");

    return 0;
}
