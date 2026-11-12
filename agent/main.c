#define _GNU_SOURCE
#include "include/attestation.h"
#include "include/attestation_client.h"
#include "include/hardware_guard.h"
#include "include/heartbeat.h"
#include "include/rf_scanner.h"
#include "../common/include/examos_appliance.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <openssl/rand.h>

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
    /*
     * The agent attests this appliance and reports its hardware state. It
     * only has meaning on an ExamOS appliance, so it refuses to run
     * anywhere else.
     */
    {
        char appliance_reason[256] = {0};
        if (examos_appliance_verify(appliance_reason, sizeof(appliance_reason)) != 0) {
            fprintf(stderr, "[ExamOS-Agent] FATAL: %s. The agent only runs on an ExamOS appliance.\n",
                    appliance_reason);
            return 2;
        }
    }

    if (argc != 3 || !argv[1][0] || !argv[2][0] ||
        strcmp(argv[1], "NOT_PROVISIONED") == 0 || strcmp(argv[2], "NOT_PROVISIONED") == 0) {
        fprintf(stderr, "Agent requires a provisioned server URL and device identity.\n");
        return 2;
    }
    const char *server_url = argv[1];
    const char *device_id = argv[2];
    const char *release_id = getenv("EXAMOS_RELEASE_ID");
    if (!release_id || !*release_id || strcmp(release_id, "NOT_PROVISIONED") == 0) {
        fprintf(stderr, "Agent requires a provisioned release ID.\n");
        return 2;
    }

    /* Configurable heartbeat interval — default 5s, min 1s, max 300s */
    int heartbeat_interval = 5;
    const char *interval_env = getenv("EXAMOS_HEARTBEAT_INTERVAL_SECONDS");
    if (interval_env && *interval_env) {
        char *end = NULL;
        long parsed = strtol(interval_env, &end, 10);
        if (end != interval_env && *end == '\0' && parsed >= 1 && parsed <= 300)
            heartbeat_interval = (int)parsed;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    log_info("Starting ExamOS Security & Attestation Agent (Native C)");

    if (tpm_attestation_init() != 0) {
        log_info("TPM device unavailable; refusing to start without hardware attestation.");
        return 2;
    }
    if (attestation_client_activate(server_url, device_id) != 0) {
        log_info("TPM EK-to-AK credential activation failed; refusing to attest.");
        return 2;
    }
    log_info("TPM EK-to-AK credential activation is verified.");
    hardware_guard_init();
    rf_scanner_init();
    if (heartbeat_init(server_url, device_id) != 0) {
        log_info("Heartbeat client initialization failed.");
        return 1;
    }

    unsigned char session_random[16];
    char session_id[40];
    static const char hex[] = "0123456789abcdef";
    if (RAND_bytes(session_random, sizeof(session_random)) != 1) {
        log_info("Could not create a cryptographically random boot session identifier.");
        return 2;
    }
    for (size_t i = 0; i < sizeof(session_random); ++i) {
        session_id[i * 2] = hex[session_random[i] >> 4];
        session_id[i * 2 + 1] = hex[session_random[i] & 15];
    }
    session_id[sizeof(session_random) * 2] = '\0';
    memset(session_random, 0, sizeof(session_random));

    char challenge_nonce[65] = {0};
    if (attestation_client_issue_challenge(server_url, device_id, release_id,
                                          session_id, challenge_nonce,
                                          sizeof(challenge_nonce)) != 0) {
        log_info("Server did not issue a fresh attestation challenge; refusing to run.");
        return 2;
    }

    // Initial attestation uses the server's one-time challenge.
    attestation_report_t report;
    if (tpm_attestation_generate_report(device_id, release_id, challenge_nonce, &report) == 0) {
        char report_json[16384];
        if (tpm_attestation_format_json(&report, report_json, sizeof(report_json)) != 0 ||
            attestation_client_verify(server_url, report_json) != 0) {
            log_info("Server rejected the TPM quote; refusing to run.");
            OPENSSL_cleanse(report_json, sizeof(report_json));
            OPENSSL_cleanse(&report, sizeof(report));
            OPENSSL_cleanse(challenge_nonce, sizeof(challenge_nonce));
            return 2;
        }
        log_info("Fresh TPM quote verified by the server; attestation state is trusted.");
        OPENSSL_cleanse(report_json, sizeof(report_json));
        OPENSSL_cleanse(&report, sizeof(report));
    } else {
        log_info("TPM quote and event-log attestation are not established; refusing to start.");
        OPENSSL_cleanse(challenge_nonce, sizeof(challenge_nonce));
        return 2;
    }
    OPENSSL_cleanse(challenge_nonce, sizeof(challenge_nonce));

    /* Re-attest every N heartbeat cycles — default 60, configurable */
    int reattest_every = 60;
    const char *reattest_env = getenv("EXAMOS_REATTEST_INTERVAL_CYCLES");
    if (reattest_env && *reattest_env) {
        char *end = NULL;
        long parsed = strtol(reattest_env, &end, 10);
        if (end != reattest_env && *end == '\0' && parsed >= 1 && parsed <= 3600)
            reattest_every = (int)parsed;
    }

    int iteration = 0;
    while (g_running) {
        char exam_session_id[64] = {0}, exam_release_id[64] = {0};
        int exam_pending = attestation_client_poll_exam_session(
            server_url, device_id, exam_session_id, sizeof(exam_session_id),
            exam_release_id, sizeof(exam_release_id));
        if (exam_pending == 1) {
            char exam_nonce[65] = {0};
            attestation_report_t exam_report;
            char exam_json[16384];
            if (attestation_client_issue_challenge(server_url, device_id,
                    exam_release_id, exam_session_id, exam_nonce,
                    sizeof(exam_nonce)) != 0 ||
                tpm_attestation_generate_report(device_id, exam_release_id,
                    exam_nonce, &exam_report) != 0 ||
                tpm_attestation_format_json(&exam_report, exam_json,
                    sizeof(exam_json)) != 0 ||
                attestation_client_verify(server_url, exam_json) != 0) {
                log_info("Candidate exam-session TPM attestation failed; no candidate session will be authorized.");
            } else {
                log_info("Candidate exam-session TPM quote verified by the server.");
            }
            OPENSSL_cleanse(exam_nonce, sizeof(exam_nonce));
            OPENSSL_cleanse(&exam_report, sizeof(exam_report));
            OPENSSL_cleanse(exam_json, sizeof(exam_json));
        } else if (exam_pending < 0 && iteration % 12 == 0) {
            log_info("Could not poll the candidate exam-session attestation queue.");
        }

        if (iteration > 0 && iteration % reattest_every == 0) {
            char re_nonce[65] = {0};
            attestation_report_t re_report;
            char re_json[16384];
            if (attestation_client_rechallenge(server_url, device_id, session_id,
                                               re_nonce, sizeof(re_nonce)) != 0 ||
                tpm_attestation_generate_report(device_id, release_id, re_nonce,
                                                &re_report) != 0 ||
                tpm_attestation_format_json(&re_report, re_json, sizeof(re_json)) != 0 ||
                attestation_client_verify(server_url, re_json) != 0) {
                log_info("Periodic TPM re-attestation failed; stopping the agent.");
                break;
            }
            log_info("Periodic TPM re-attestation verified by the server.");
        }
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

        if (iteration % 12 == 0 || iteration == 0) {
            char status_msg[256];
            snprintf(status_msg, sizeof(status_msg),
                     "%s | Displays: %d | Uptime: %lds | CPU: %.2f",
                     heartbeat_status == 0 ? "Telemetry delivered; not trusted" : "Telemetry delivery failed",
                     hw_state.display_count, hb.uptime_seconds, hb.cpu_load);
            log_info(status_msg);
        }

        iteration++;
        sleep((unsigned int)heartbeat_interval);
    }

    log_info("ExamOS Agent shutting down cleanly.");
    return 0;
}
