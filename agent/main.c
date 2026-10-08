#define _GNU_SOURCE
#include "include/attestation.h"
#include "include/hardware_guard.h"
#include "include/heartbeat.h"
#include "include/rf_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

static volatile sig_atomic_t g_running = 1;

static void log_info(const char *msg) {
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    fprintf(stdout, "%s [INFO] [ExamOS-Agent] %s\n", tbuf, msg);
    fflush(stdout);
}

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

int main(int argc, char *argv[]) {
    const char *server_url = (argc > 1) ? argv[1] : "http://127.0.0.1:8000/api/v1/heartbeat";
    const char *device_id = (argc > 2) ? argv[2] : "examos-device-node-01";

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    log_info("Starting ExamOS Security & Attestation Agent (Native C)");

    if (tpm_attestation_init() != 0) {
        log_info("TPM device unavailable; no PCR report can be produced.");
    }
    hardware_guard_init();
    rf_scanner_init();
    if (heartbeat_init(server_url, device_id) != 0) {
        log_info("Heartbeat client initialization failed.");
        return 1;
    }

    // Initial Attestation Generation
    attestation_report_t report;
    if (tpm_attestation_generate_report("INITIAL-BOOT-NONCE", &report) == 0) {
        char report_json[4096];
        tpm_attestation_format_json(&report, report_json, sizeof(report_json));
        log_info("Unsigned PCR measurement digest computed; this is not a TPM quote.");
        log_info(report.composite_digest);
    } else {
        log_info("PCR measurement unavailable; TPM attestation is not established.");
    }

    int iteration = 0;
    while (g_running) {
        hardware_state_t hw_state;
        hardware_guard_scan(&hw_state);
        char hw_json[512];
        hardware_guard_format_json(&hw_state, hw_json, sizeof(hw_json));

        if (hw_state.unauthorized_device_flag) {
            log_info("SECURITY ALERT: Unauthorized hardware modification detected!");
        }

        rf_environment_t rf_env;
        rf_scanner_scan(&rf_env);
        char rf_json[1024];
        rf_scanner_format_json(&rf_env, rf_json, sizeof(rf_json));

        heartbeat_payload_t hb;
        heartbeat_collect_metrics(&hb);

        int heartbeat_status = heartbeat_send(&hb, hw_json, rf_json);

        if (iteration % 12 == 0) {
            char status_msg[256];
            snprintf(status_msg, sizeof(status_msg),
                     "%s | Displays: %d | Uptime: %lds | CPU: %.2f",
                     heartbeat_status == 0 ? "Telemetry delivered; not trusted" : "Telemetry delivery failed",
                     hw_state.display_count, hb.uptime_seconds, hb.cpu_load);
            log_info(status_msg);
        }

        iteration++;
        sleep(5);
    }

    log_info("ExamOS Agent shutting down cleanly.");
    return 0;
}
