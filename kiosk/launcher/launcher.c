/*
 * ExamOS Kiosk Launcher (C Implementation)
 * Production-grade Wayland / Cage session supervisor for Chromium kiosk.
 * Manages ephemeral RAM user profile, handles POSIX signals, enforces security flags,
 * and loads the configured Exam URL from /etc/examos/exam.conf or EXAMOS_EXAM_URL.
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
#define CHROMIUM_BIN "/usr/bin/chromium"

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
    /* Validate path is under a safe prefix to prevent accidental root deletion */
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
        log_msg("ERROR", "Failed to create ephemeral profile directory");
        return -1;
    }
    log_msg("INFO", "Created ephemeral browser profile in RAM");
    return 0;
}

int main(void) {
    exam_config_t exam_config = {0};
    if (config_load(&exam_config) != 0 || !exam_config.configured ||
        !config_validate_exam_url(exam_config.exam_url)) {
        log_msg("ERROR", "Exam URL is missing or not approved; refusing to launch the kiosk browser");
        return 1;
    }
    const char *exam_url = exam_config.exam_url;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    log_msg("INFO", "ExamOS Native C Kiosk Supervisor Starting");
    char launch_msg[600];
    snprintf(launch_msg, sizeof(launch_msg), "Target exam URL: %s", exam_url);
    log_msg("INFO", launch_msg);

    while (g_running) {
        if (create_ephemeral_profile(g_profile_dir, sizeof(g_profile_dir)) != 0) {
            sleep(2);
            continue;
        }

        char user_data_flag[300];
        snprintf(user_data_flag, sizeof(user_data_flag), "--user-data-dir=%s", g_profile_dir);

        char app_flag[600];
        snprintf(app_flag, sizeof(app_flag), "--app=%s", exam_url);

        time_t start_time = time(NULL);
        pid_t pid = fork();

        if (pid < 0) {
            log_msg("ERROR", "Failed to fork child process for Chromium");
            remove_directory_recursive(g_profile_dir);
            sleep(2);
            continue;
        }

        if (pid == 0) {
            // Child Process - Execute Chromium with locked-down flags
            char *const args[] = {
                (char *)CHROMIUM_BIN,
                user_data_flag,
                (char *)"--kiosk",
                (char *)"--no-first-run",
                (char *)"--no-default-browser-check",
                (char *)"--disable-sync",
                (char *)"--disable-extensions",
                (char *)"--disable-plugins",
                (char *)"--disable-translate",
                (char *)"--disable-save-password-bubble",
                (char *)"--disable-infobars",
                (char *)"--disable-session-crashed-bubble",
                (char *)"--disable-component-update",
                (char *)"--disable-background-networking",
                (char *)"--disable-dev-tools",
                (char *)"--disable-print-preview",
                (char *)"--password-store=basic",
                (char *)"--ozone-platform=wayland",
                (char *)"--enable-features=UseOzonePlatform",
                (char *)"--autoplay-policy=no-user-gesture-required",
                /* --- Security hardening flags added below ---
                 * --disable-developer-tools  : belt-and-suspenders alongside --disable-dev-tools
                 *                              (flag name varies across Chromium builds).
                 * --disable-gpu-sandbox      : required on some embedded/kiosk GPU stacks where
                 *                              the GPU sandbox cannot initialise; remove if the
                 *                              target hardware supports it.
                 * --disable-popup-blocking   : exam portals may open result/print pop-ups.
                 * --disable-notifications    : suppress OS-level notification permission prompts.
                 * --incognito                : ensures no residual session state is persisted
                 *                             (defence-in-depth alongside the ephemeral profile).
                 * --disable-pinch            : disable touchscreen pinch-to-zoom gesture.
                 * --overscroll-history-navigation=0 : prevent swipe-back/forward navigation.
                 */
                (char *)"--disable-developer-tools",
                (char *)"--disable-gpu-sandbox",
                (char *)"--disable-popup-blocking",
                (char *)"--disable-notifications",
                (char *)"--incognito",
                (char *)"--disable-pinch",
                (char *)"--overscroll-history-navigation=0",
                app_flag,
                NULL
            };

            execvp(CHROMIUM_BIN, args);
            // If execvp fails:
            fprintf(stderr, "Fatal: execvp failed for %s: %s\n", CHROMIUM_BIN, strerror(errno));
            _exit(127);
        }

        // Parent Process - Supervise child
        g_child_pid = pid;
        int status = 0;
        waitpid(pid, &status, 0);
        g_child_pid = -1;

        time_t uptime = time(NULL) - start_time;
        char msg[128];
        snprintf(msg, sizeof(msg), "Chromium exited (Uptime: %ld seconds). Cleaning profile...", (long)uptime);
        log_msg("WARN", msg);

        remove_directory_recursive(g_profile_dir);

        if (!g_running) {
            break;
        }

        // Prevent rapid CPU spin on instantaneous crash
        if (uptime < 5) {
            log_msg("INFO", "Crash throttle: sleeping 3 seconds before respawning...");
            sleep(3);
        }
    }

    log_msg("INFO", "ExamOS Kiosk Supervisor shutdown complete.");
    return 0;
}
