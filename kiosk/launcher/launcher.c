/*
 * ExamOS Kiosk Launcher (C Implementation)
 * Production-grade Wayland / Cage session supervisor for Chromium kiosk.
 * Manages ephemeral RAM user profile, handles POSIX signals, enforces security flags,
 * supports candidate accommodations (zoom, contrast, screen reader),
 * detects crash signals (WIFSIGNALED), and limits rapid crash loops (MAX_CRASH_COUNT).
 */

#define _GNU_SOURCE
#include "../../server/include/config_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>

#define EXAM_CONF_PATH "/etc/examos/exam.conf"
#define ACCOMMODATIONS_CONF_PATH "/etc/examos/accommodations.json"
#define CHROMIUM_BIN "/usr/bin/chromium"
#define MAX_CRASH_COUNT 5

static volatile sig_atomic_t g_running = 1;
static pid_t g_child_pid = -1;
static char g_profile_dir[256] = {0};

static void log_msg(const char *level, const char *msg) {
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
    fprintf(stderr, "%s [%s] [KioskLauncher] %s\n", time_str, level, msg);
}

static void handle_signal(int sig) {
    (void)sig;
    log_msg("INFO", "Signal received, terminating kiosk session...");
    g_running = 0;
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGTERM);
    }
}

static int remove_directory_recursive(const char *path) {
    if (!path || !path[0]) return -1;
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    const char *safe_prefix = (runtime && runtime[0]) ? runtime : "/tmp";
    if (strncmp(path, safe_prefix, strlen(safe_prefix)) != 0) return -1;

    DIR *dir = opendir(path);
    if (!dir) return (errno == ENOENT) ? 0 : -1;
    struct dirent *entry;
    int result = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char child[512];
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >= (int)sizeof(child)) {
            result = -1; continue;
        }
        struct stat st;
        if (lstat(child, &st) != 0) { result = -1; continue; }
        if (S_ISDIR(st.st_mode)) {
            if (remove_directory_recursive(child) != 0) result = -1;
        } else {
            if (unlink(child) != 0) result = -1;
        }
    }
    closedir(dir);
    if (rmdir(path) != 0) result = -1;
    return result;
}

static int create_ephemeral_profile(char *out_path, size_t max_len) {
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    if (!runtime_dir || strlen(runtime_dir) == 0) {
        runtime_dir = "/tmp";
    }

    snprintf(out_path, max_len, "%s/examos_kiosk_XXXXXX", runtime_dir);
    if (mkdtemp(out_path) == NULL) {
        /* Failsafe fallback to /tmp */
        snprintf(out_path, max_len, "/tmp/examos_kiosk_XXXXXX");
        if (mkdtemp(out_path) == NULL) {
            char err[512];
            snprintf(err, sizeof(err), "Failed to create ephemeral profile directory (%s): %s", out_path, strerror(errno));
            log_msg("ERROR", err);
            return -1;
        }
    }
    log_msg("INFO", "Created ephemeral browser profile in RAM");
    return 0;
}

/* Parse accommodations JSON for zoom, high contrast, and accessibility */
static void load_accommodations(char *scale_flag, size_t scale_sz,
                                int *out_high_contrast, int *out_screen_reader) {
    scale_flag[0] = '\0';
    *out_high_contrast = 0;
    *out_screen_reader = 0;

    const char *paths[] = {
        getenv("EXAMOS_ACCOMMODATIONS_PATH"),
        ACCOMMODATIONS_CONF_PATH,
        NULL
    };

    FILE *fp = NULL;
    for (int i = 0; paths[i]; i++) {
        if (paths[i] && paths[i][0]) {
            fp = fopen(paths[i], "r");
            if (fp) break;
        }
    }
    if (!fp) return;

    char buf[4096];
    size_t len = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    if (len == 0) return;
    buf[len] = '\0';

    char *zoom_ptr = strstr(buf, "\"zoom_factor\"");
    if (zoom_ptr) {
        char *col = strchr(zoom_ptr, ':');
        if (col) {
            float factor = 1.0f;
            if (sscanf(col + 1, "%f", &factor) == 1 && factor >= 0.5f && factor <= 3.0f) {
                snprintf(scale_flag, scale_sz, "--force-device-scale-factor=%.2f", factor);
            }
        }
    }

    if (strstr(buf, "\"high_contrast\": true") || strstr(buf, "\"high_contrast\":true")) {
        *out_high_contrast = 1;
    }
    if (strstr(buf, "\"screen_reader\": true") || strstr(buf, "\"screen_reader\":true")) {
        *out_screen_reader = 1;
    }
}

/* Validate sandbox environment: dedicated unprivileged user and sandbox prerequisites */
static int validate_sandbox_environment(void) {
    /* Check runtime user: must NOT run as root in production */
    if (geteuid() == 0) {
        const char *allow_dev = getenv("EXAMOS_ALLOW_UNSANDBOXED_DEV");
        if (!allow_dev || strcmp(allow_dev, "1") != 0) {
            log_msg("FATAL", "Security Violation: Kiosk supervisor running as root (UID 0). Production must run under dedicated unprivileged 'exam' user.");
            return -1;
        }
        log_msg("WARN", "Running as root under explicit EXAMOS_ALLOW_UNSANDBOXED_DEV=1 override.");
    }

    /* Check unprivileged user namespace or SUID sandbox helper availability */
    int userns_enabled = 0;
    FILE *fp = fopen("/proc/sys/kernel/unprivileged_userns_clone", "r");
    if (fp) {
        char val = 0;
        if (fread(&val, 1, 1, fp) == 1 && val == '1') {
            userns_enabled = 1;
        }
        fclose(fp);
    } else {
        /* On standard upstream kernels without sysctl switch, userns is enabled by default */
        userns_enabled = 1;
    }

    struct stat st;
    int suid_helper = (stat("/usr/lib/chromium/chrome-sandbox", &st) == 0 && (st.st_mode & S_ISUID));

    if (!userns_enabled && !suid_helper) {
        const char *allow_dev = getenv("EXAMOS_ALLOW_UNSANDBOXED_DEV");
        if (!allow_dev || strcmp(allow_dev, "1") != 0) {
            log_msg("FATAL", "Security Violation: Chromium sandbox prerequisites missing (user namespaces disabled and no SUID helper). Refusing to launch unsandboxed.");
            return -1;
        }
        log_msg("WARN", "Sandbox prerequisites missing, running under EXAMOS_ALLOW_UNSANDBOXED_DEV=1.");
    }

    log_msg("INFO", "Chromium sandbox runtime validated successfully.");
    return 0;
}

int main(int argc, char *argv[]) {
    /* Audit arguments for any disallowed security flags */
    for (int i = 1; i < argc; i++) {
        if (strstr(argv[i], "--no-sandbox") ||
            strstr(argv[i], "--disable-gpu-sandbox") ||
            strstr(argv[i], "--disable-seccomp-filter-sandbox")) {
            log_msg("FATAL", "Security Violation: Insecure flag detected in arguments; refusing to launch.");
            return 1;
        }
    }

    /* Enforce unprivileged user and functioning sandbox environment */
    if (validate_sandbox_environment() != 0) {
        return 1;
    }

    const char *exam_url = NULL;
    exam_config_t exam_config = {0};

    if (argc > 1) {
        if (!argv[1] || !argv[1][0] || !config_validate_exam_url(argv[1])) {
            log_msg("ERROR", "Exam URL argument is missing or not approved; refusing to launch");
            return 1;
        }
        exam_url = argv[1];
    } else {
        if (config_load(&exam_config) != 0 || !exam_config.configured ||
            !config_validate_exam_url(exam_config.exam_url)) {
            log_msg("ERROR", "Exam URL is missing or not approved; refusing to launch the kiosk browser");
            return 1;
        }
        exam_url = exam_config.exam_url;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    log_msg("INFO", "ExamOS Native C Kiosk Supervisor Starting");
    char launch_msg[600];
    snprintf(launch_msg, sizeof(launch_msg), "Target exam URL: %s", exam_url);
    log_msg("INFO", launch_msg);

    int consecutive_crashes = 0;

    while (g_running) {
        if (create_ephemeral_profile(g_profile_dir, sizeof(g_profile_dir)) != 0) {
            sleep(2);
            continue;
        }

        char user_data_flag[300];
        snprintf(user_data_flag, sizeof(user_data_flag), "--user-data-dir=%s", g_profile_dir);

        char app_flag[600];
        snprintf(app_flag, sizeof(app_flag), "--app=%s", exam_url);

        /* Candidate accommodations */
        char scale_flag[64] = {0};
        int high_contrast = 0;
        int screen_reader = 0;
        load_accommodations(scale_flag, sizeof(scale_flag), &high_contrast, &screen_reader);

        time_t start_time = time(NULL);
        pid_t pid = fork();

        if (pid < 0) {
            log_msg("ERROR", "Failed to fork child process for Chromium");
            remove_directory_recursive(g_profile_dir);
            sleep(2);
            continue;
        }

        if (pid == 0) {
            // Child Process - Execute Chromium with locked-down flags and accommodations
            char *args[48];
            int arg_idx = 0;

            args[arg_idx++] = (char *)CHROMIUM_BIN;
            args[arg_idx++] = user_data_flag;
            args[arg_idx++] = (char *)"--kiosk";
            args[arg_idx++] = (char *)"--no-first-run";
            args[arg_idx++] = (char *)"--no-default-browser-check";
            args[arg_idx++] = (char *)"--disable-sync";
            args[arg_idx++] = (char *)"--disable-extensions";
            args[arg_idx++] = (char *)"--disable-plugins";
            args[arg_idx++] = (char *)"--disable-translate";
            args[arg_idx++] = (char *)"--disable-save-password-bubble";
            args[arg_idx++] = (char *)"--disable-infobars";
            args[arg_idx++] = (char *)"--disable-session-crashed-bubble";
            args[arg_idx++] = (char *)"--disable-component-update";
            args[arg_idx++] = (char *)"--disable-background-networking";
            args[arg_idx++] = (char *)"--disable-dev-tools";
            args[arg_idx++] = (char *)"--disable-print-preview";
            args[arg_idx++] = (char *)"--password-store=basic";
            args[arg_idx++] = (char *)"--ozone-platform=wayland";
            args[arg_idx++] = (char *)"--enable-features=UseOzonePlatform";
            args[arg_idx++] = (char *)"--autoplay-policy=no-user-gesture-required";
            args[arg_idx++] = (char *)"--disable-developer-tools";
            args[arg_idx++] = (char *)"--disable-popup-blocking";
            args[arg_idx++] = (char *)"--disable-notifications";
            args[arg_idx++] = (char *)"--incognito";
            args[arg_idx++] = (char *)"--disable-pinch";
            args[arg_idx++] = (char *)"--overscroll-history-navigation=0";
            args[arg_idx++] = (char *)"--disable-dev-shm-usage";

            /* ExamOS Kiosk User-Agent enforcement */
            args[arg_idx++] = (char *)"--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 ExamOS-Kiosk/1.0 (ExamOS Secure Kiosk Environment; Cage/Wayland)";

            /* Accommodations dynamically applied */
            if (scale_flag[0]) {
                args[arg_idx++] = scale_flag;
            }
            if (high_contrast) {
                args[arg_idx++] = (char *)"--high-contrast-mode";
            }
            if (screen_reader) {
                args[arg_idx++] = (char *)"--enable-features=AccessibilitySharedLibrary";
            }

            args[arg_idx++] = app_flag;
            args[arg_idx] = NULL;

            execvp(CHROMIUM_BIN, args);
            fprintf(stderr, "Fatal: execvp failed for %s: %s\n", CHROMIUM_BIN, strerror(errno));
            _exit(127);
        }

        // Parent Process - Supervise child
        g_child_pid = pid;
        int status = 0;
        waitpid(pid, &status, 0);
        g_child_pid = -1;

        time_t uptime = time(NULL) - start_time;

        /* Signal crash detection */
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            char alert[128];
            snprintf(alert, sizeof(alert), "SECURITY ALERT: Chromium killed by signal %d (%s)", sig, strsignal(sig));
            log_msg("ERROR", alert);
        }

        char msg[128];
        snprintf(msg, sizeof(msg), "Chromium exited (Uptime: %ld seconds). Cleaning profile...", (long)uptime);
        log_msg("WARN", msg);

        remove_directory_recursive(g_profile_dir);

        if (!g_running) {
            break;
        }

        // Anti-spin latching and crash throttling
        if (uptime < 5) {
            consecutive_crashes++;
            if (consecutive_crashes >= MAX_CRASH_COUNT) {
                log_msg("FATAL", "Anti-spin latching triggered: rapid crashes exceeded MAX_CRASH_COUNT. Halting kiosk supervisor.");
                break;
            }
            log_msg("INFO", "Crash throttle: sleeping 3 seconds before respawning...");
            sleep(3);
        } else {
            consecutive_crashes = 0;
        }
    }

    log_msg("INFO", "ExamOS Kiosk Supervisor shutdown complete.");
    return 0;
}
