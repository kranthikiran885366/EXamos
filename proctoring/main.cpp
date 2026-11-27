#include "include/proctor.h"
#include "include/vision_engine.h"
#include "../common/include/examos_appliance.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <csignal>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <curl/curl.h>

static volatile std::sig_atomic_t g_proctor_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_proctor_running = 0;
}

/*
 * Escapes a string value for embedding inside a JSON quoted string.
 * Handles the JSON control characters (RFC 8259 §7) and any byte below 0x20.
 */
static std::string json_escape(const std::string &raw) {
    std::string out;
    out.reserve(raw.size() + 8);
    for (unsigned char c : raw) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

/*
 * Sends a normalized proctoring event to the server.
 *
 * Returns true when the server accepted the event. The caller must not
 * treat a failed delivery as a delivered event: the evidence chain is
 * append-only, so a silently dropped detection would leave a gap that no
 * later record could fill.
 */
static bool send_proctoring_event(const std::string &server_url, const std::string &session_id,
                                  const std::string &source_type, const std::string &event_type,
                                  const std::string &payload_json) {
    CURL *curl = curl_easy_init();
    if (!curl) return false;

    std::string endpoint = server_url + "/api/v1/proctoring/events";
    const char *model_name = std::getenv("EXAMOS_PROCTOR_MODEL_NAME");
    const char *model_version = std::getenv("EXAMOS_PROCTOR_MODEL_VERSION");
    if (!model_name || !model_version || !model_name[0] || !model_version[0]) {
        std::cerr << "[ExamOS-Proctor] FATAL: EXAMOS_PROCTOR_MODEL_NAME and "
                     "EXAMOS_PROCTOR_MODEL_VERSION must identify the detector that produced "
                     "this evidence; refusing to attribute events to an unnamed model."
                  << std::endl;
        curl_easy_cleanup(curl);
        return false;
    }

    std::string json_body = "{\"session_id\":\"" + json_escape(session_id) + "\","
                            "\"source_type\":\"" + json_escape(source_type) + "\","
                            "\"event_type\":\"" + json_escape(event_type) + "\","
                            "\"model_name\":\"" + json_escape(model_name) + "\","
                            "\"model_version\":\"" + json_escape(model_version) + "\","
                            "\"payload\":" + payload_json + "}";

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    const char *api_token = std::getenv("EXAMOS_PROCTOR_API_TOKEN");
    if (!api_token || std::strlen(api_token) < 32) {
        std::cerr << "[ExamOS-Proctor] EXAMOS_PROCTOR_API_TOKEN is missing or too short; evidence rejected locally." << std::endl;
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }
    std::string authorization = std::string("Authorization: Bearer ") + api_token;
    headers = curl_slist_append(headers, authorization.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    bool delivered = false;
    if (res != CURLE_OK) {
        std::cerr << "[ExamOS-Proctor] Evidence delivery failed: "
                  << curl_easy_strerror(res) << " (event " << event_type << " was NOT recorded)"
                  << std::endl;
    } else {
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (status >= 200 && status < 300) {
            delivered = true;
        } else {
            std::cerr << "[ExamOS-Proctor] Evidence rejected by the server (HTTP "
                      << status << "); event " << event_type << " was NOT recorded" << std::endl;
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return delivered;
}

int main(int argc, char *argv[]) {
    /*
     * The proctoring worker produces examination evidence. It only has
     * meaning on an ExamOS appliance, so it refuses to run anywhere else.
     */
    {
        char appliance_reason[256] = {0};
        if (examos_appliance_verify(appliance_reason, sizeof(appliance_reason)) != 0) {
            std::cerr << "[ExamOS-Proctor] FATAL: " << appliance_reason
                      << ". The proctoring worker only runs on an ExamOS appliance." << std::endl;
            return 2;
        }
    }

    /* Require provisioned session and server — no hardcoded defaults */
    const char *env_session = std::getenv("EXAMOS_PROCTOR_SESSION_ID");
    const char *env_server  = std::getenv("EXAMOS_SERVER_URL");
    const char *env_device  = std::getenv("EXAMOS_VIDEO_DEVICE");

    std::string session_id = env_session ? env_session : "";
    std::string server_url = env_server  ? env_server  : "";
    std::string video_dev  = env_device  ? env_device  : "/dev/video0";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--session") == 0 && i + 1 < argc) {
            session_id = argv[++i];
        } else if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server_url = argv[++i];
        } else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            video_dev = argv[++i];
        }
    }

    if (session_id.empty() || server_url.empty()) {
        std::cerr << "[ExamOS-Proctor] FATAL: EXAMOS_PROCTOR_SESSION_ID and EXAMOS_SERVER_URL "
                     "must be provisioned (or passed via --session / --server)." << std::endl;
        return 2;
    }
    auto is_loopback_http = [](const std::string &u, const char *prefix) -> bool {
        size_t plen = strlen(prefix);
        if (u.size() < plen || u.compare(0, plen, prefix) != 0) return false;
        return u.size() == plen || u[plen] == ':' || u[plen] == '/';
    };
    if (server_url.substr(0, 8) != "https://" &&
        !is_loopback_http(server_url, "http://127.0.0.1") &&
        !is_loopback_http(server_url, "http://localhost")) {
        std::cerr << "[ExamOS-Proctor] FATAL: EXAMOS_SERVER_URL must be HTTPS "
                     "(loopback HTTP permitted for development only)." << std::endl;
        return 2;
    }

    std::signal(SIGTERM, sig_handler);
    std::signal(SIGINT, sig_handler);

    std::cout << "[ExamOS-Proctor] Starting Phase 4 Proctoring & Vision Engine..." << std::endl;
    std::cout << "[ExamOS-Proctor] Session ID: " << session_id << " | Server: " << server_url << std::endl;

    /*
     * The detector must be available before any evidence is produced. A
     * proctor without a detector cannot see anything, and evidence that
     * claims otherwise would be fabricated.
     */
    const char *detector_manifest = std::getenv("EXAMOS_PROCTOR_DETECTOR_CONFIG");
    if (vision_engine_init(detector_manifest) != VISION_ENGINE_OK) {
        std::cerr << "[ExamOS-Proctor] FATAL: ANALYSIS_WORKER_DOWN - no approved detector is "
                     "available. Refusing to produce examination evidence." << std::endl;
        return 3;
    }
    std::cout << "[ExamOS-Proctor] Detector: " << vision_engine_scorer() << std::endl;

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
int analysis = vision_engine_analyze_frame(capture.frame_data(), stats.width, stats.height,
                                                           capture.frame_stride(), capture.frame_channels(),
                                                           frame_seq, &result);
                if (analysis != VISION_ENGINE_OK) {
                    std::cerr << "[ExamOS-Proctor] Frame analysis unavailable (status "
                              << analysis << "); no event was produced for this frame." << std::endl;
                    std::this_thread::sleep_for(std::chrono::milliseconds(sample_interval_ms));
                    continue;
                }
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
        char face_json[1024];
        std::string event_type = (result.face_count == 1) ? "FACE_PRESENT" :
                                 (result.face_count > 1)  ? "MULTIPLE_FACES" : "NO_FACE";

        vision_engine_format_event_json(&result, event_type.c_str(), face_json, sizeof(face_json));
        send_proctoring_event(server_url, session_id, "PRIMARY_CAMERA", event_type, face_json);

        /* Unauthorized-device events are emitted only when the provisioned
           object detector actually matched the class.  A missing detector
           leaves phone_detected/book_detected at zero, and main emits
           nothing rather than a fabricated "detected: false" claim. */
        if (result.phone_detected) {
            char phone_json[1024];
            vision_engine_format_event_json(&result, "PHONE_DETECTED", phone_json, sizeof(phone_json));
            send_proctoring_event(server_url, session_id, "PRIMARY_CAMERA", "PHONE_DETECTED", phone_json);
        }
        if (result.book_detected) {
            char book_json[1024];
            vision_engine_format_event_json(&result, "BOOK_DETECTED", book_json, sizeof(book_json));
            send_proctoring_event(server_url, session_id, "PRIMARY_CAMERA", "BOOK_DETECTED", book_json);
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
