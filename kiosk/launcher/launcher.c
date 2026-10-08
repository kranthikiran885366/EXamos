/*
 * ExamOS Kiosk Launcher (C Implementation)
 * Production-grade Wayland / Cage session supervisor for Chromium kiosk.
 * Manages ephemeral RAM user profile, handles POSIX signals, enforces security flags,
 * and loads the configured Exam URL from /etc/examos/exam.conf or EXAMOS_EXAM_URL.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
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
    char command[512];
    snprintf(command, sizeof(command), "rm -rf \"%s\"", path);
    return system(command);
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

static int load_exam_url_from_config(char *out_url, size_t max_len) {
    FILE *f = fopen(EXAM_CONF_PATH, "r");
    if (!f) {
        return -1;
    }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "EXAM_URL=", 9) == 0) {
            char *val = line + 9;
            char *nl = strchr(val, '\r');
            if (nl) *nl = '\0';
            nl = strchr(val, '\n');
            if (nl) *nl = '\0';

            /* Trim spaces */
            while (*val == ' ' || *val == '\t') val++;

            if (strlen(val) > 0 && strcmp(val, "NOT_CONFIGURED") != 0) {
                if (strncmp(val, "http://", 7) == 0 || strncmp(val, "https://", 8) == 0) {
                    strncpy(out_url, val, max_len - 1);
                    out_url[max_len - 1] = '\0';
                    found = 1;
                    break;
                }
            }
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

int main(int argc, char *argv[]) {
    char exam_url_buf[512] = {0};
    const char *exam_url = NULL;

    if (argc > 1 && strlen(argv[1]) > 0) {
        exam_url = argv[1];
    } else {
        const char *env_url = getenv("EXAMOS_EXAM_URL");
        if (env_url && strlen(env_url) > 0) {
            exam_url = env_url;
        } else if (load_exam_url_from_config(exam_url_buf, sizeof(exam_url_buf)) == 0) {
            exam_url = exam_url_buf;
        }
    }

    if (!exam_url || strlen(exam_url) == 0) {
        /* Fallback: default to local candidate portal if nothing external configured */
        exam_url = "http://127.0.0.1:8000/";
        log_msg("INFO", "No external exam URL configured; loading local ExamOS Candidate Portal (http://127.0.0.1:8000/)");
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
