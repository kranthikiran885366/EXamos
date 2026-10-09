#include "include/proctor.h"
#include "include/vision_engine.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <csignal>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <curl/curl.h>

static volatile std::sig_atomic_t g_proctor_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_proctor_running = 0;
}

static void send_proctoring_event(const std::string &server_url, const std::string &session_id,
                                  const std::string &source_type, const std::string &event_type,
                                  const std::string &payload_json) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    std::string endpoint = server_url + "/api/v1/proctoring/events";
    std::string json_body = "{\"session_id\":\"" + session_id + "\","
                            "\"source_type\":\"" + source_type + "\","
                            "\"event_type\":\"" + event_type + "\","
                            "\"payload\":" + payload_json + "}";

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    const char *api_token = std::getenv("EXAMOS_PROCTOR_API_TOKEN");
    if (!api_token || std::strlen(api_token) < 32) {
        std::cerr << "[ExamOS-Proctor] EXAMOS_PROCTOR_API_TOKEN is missing or too short; evidence rejected locally." << std::endl;
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return;
    }
    std::string authorization = std::string("Authorization: Bearer ") + api_token;
    headers = curl_slist_append(headers, authorization.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    (void)res;

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

int main(int argc, char *argv[]) {
    std::string session_id = "exam-session-01";
    std::string server_url = "http://127.0.0.1:8000";
    std::string video_dev = "/dev/video0";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--session") == 0 && i + 1 < argc) {
            session_id = argv[++i];
        } else if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server_url = argv[++i];
        } else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            video_dev = argv[++i];
        }
    }

    std::signal(SIGTERM, sig_handler);
    std::signal(SIGINT, sig_handler);

    std::cout << "[ExamOS-Proctor] Starting Phase 4 Proctoring & Vision Engine..." << std::endl;
    std::cout << "[ExamOS-Proctor] Session ID: " << session_id << " | Server: " << server_url << std::endl;

    vision_engine_init(nullptr);
    curl_global_init(CURL_GLOBAL_DEFAULT);

    examos::proctoring::MediaCapture capture;
    bool camera_online = capture.initialize(video_dev);
    if (!camera_online) {
        std::cerr << "[ExamOS-Proctor] V4L2 Device " << video_dev << " not accessible; running in synthetic/headless monitor mode." << std::endl;
        send_proctoring_event(server_url, session_id, "PRIMARY_CAMERA", "MEDIA_CAMERA_STARTING", "{\"device\":\"" + video_dev + "\"}");
    } else {
        std::cout << "[ExamOS-Proctor] Camera initialized on " << video_dev << std::endl;
        send_proctoring_event(server_url, session_id, "PRIMARY_CAMERA", "CAMERA_ACTIVE", "{\"resolution\":\"640x480\",\"fps\":15}");
    }

    uint64_t frame_seq = 0;
    int sample_interval_ms = 1000; /* Sample every 1 second */

    while (g_proctor_running) {
        frame_seq++;
        vision_frame_result_t result{};

        if (camera_online) {
            examos::proctoring::FrameStats stats{};
            if (capture.capture_frame(stats)) {
                vision_engine_analyze_frame(capture.frame_data(), stats.width, stats.height,
                                            capture.frame_stride(), capture.frame_channels(),
                                            frame_seq, &result);
            } else {
                std::cerr << "[ExamOS-Proctor] Camera frame acquisition failed; no synthetic evidence emitted." << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(sample_interval_ms));
                continue;
            }
        } else {
            /* Fail closed: synthetic frames must never become examination evidence. */
            std::this_thread::sleep_for(std::chrono::milliseconds(sample_interval_ms));
            continue;
        }

        /* Emit normalized events to tamper-evident pipeline */
        char face_json[512], pose_json[256];
        std::string event_type = (result.face_count == 1) ? "FACE_PRESENT" :
                                 (result.face_count > 1)  ? "MULTIPLE_FACES" : "NO_FACE";

        vision_engine_format_event_json(&result, event_type.c_str(), face_json, sizeof(face_json));
        send_proctoring_event(server_url, session_id, "PRIMARY_CAMERA", event_type, face_json);

        if (result.face_count > 0) {
            vision_engine_format_event_json(&result, "HEAD_POSE", pose_json, sizeof(pose_json));
            send_proctoring_event(server_url, session_id, "PRIMARY_CAMERA", "HEAD_POSE", pose_json);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(sample_interval_ms));
    }

    if (camera_online) {
        capture.close_devices();
    }
    vision_engine_destroy();
    curl_global_cleanup();

    std::cout << "[ExamOS-Proctor] Clean shutdown complete." << std::endl;
    return 0;
}
