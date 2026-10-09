#define _GNU_SOURCE
#include "../include/second_camera.h"
#include "../include/event_chain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#define TOKEN_VALIDITY_SECONDS 300 /* 5 minutes */

static second_camera_session_t g_second_cams[MAX_SECOND_CAMERA_SESSIONS];
static int                     g_second_cam_count = 0;
static pthread_mutex_t         g_second_cam_lock = PTHREAD_MUTEX_INITIALIZER;

static void random_hex(char *out, size_t num_bytes) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        unsigned char *buf = malloc(num_bytes);
        if (buf && read(fd, buf, num_bytes) == (ssize_t)num_bytes) {
            for (size_t i = 0; i < num_bytes; i++) {
                sprintf(out + (i * 2), "%02x", buf[i]);
            }
            out[num_bytes * 2] = '\0';
        }
        free(buf);
        close(fd);
    }
}

void second_camera_init(void) {
    pthread_mutex_lock(&g_second_cam_lock);
    memset(g_second_cams, 0, sizeof(g_second_cams));
    g_second_cam_count = 0;
    pthread_mutex_unlock(&g_second_cam_lock);
}

int second_camera_create_pairing_token(const char *session_id, char *out_token, size_t max_out) {
    if (!session_id || !out_token || max_out < QR_TOKEN_LEN + 1) return -1;

    pthread_mutex_lock(&g_second_cam_lock);

    second_camera_session_t *sc = NULL;
    for (int i = 0; i < g_second_cam_count; i++) {
        if (strcmp(g_second_cams[i].session_id, session_id) == 0) {
            sc = &g_second_cams[i];
            break;
        }
    }

    if (!sc) {
        if (g_second_cam_count >= MAX_SECOND_CAMERA_SESSIONS) {
            pthread_mutex_unlock(&g_second_cam_lock);
            return -1;
        }
        sc = &g_second_cams[g_second_cam_count++];
        memset(sc, 0, sizeof(*sc));
        strncpy(sc->session_id, session_id, sizeof(sc->session_id) - 1);
    }

    random_hex(sc->qr_pairing_token, 32);
    sc->state = SECOND_CAM_STATE_PAIRING_REQUESTED;
    sc->token_created_at = time(NULL);
    sc->expires_at = sc->token_created_at + TOKEN_VALIDITY_SECONDS;
    sc->token_used = 0;

    strncpy(out_token, sc->qr_pairing_token, max_out - 1);
    out_token[max_out - 1] = '\0';

    /* Record tamper-evident event */
    event_chain_append(session_id, "SYSTEM", "SECOND_CAMERA_REQUESTED",
                       "{\"action\":\"pairing_token_created\",\"validity_sec\":300}",
                       "second-camera-manager", "1.0.0", NULL);

    pthread_mutex_unlock(&g_second_cam_lock);
    return 0;
}

int second_camera_validate_pairing(const char *session_id, const char *pairing_token) {
    if (!session_id || !pairing_token) return -1;

    pthread_mutex_lock(&g_second_cam_lock);

    second_camera_session_t *sc = NULL;
    for (int i = 0; i < g_second_cam_count; i++) {
        if (strcmp(g_second_cams[i].session_id, session_id) == 0) {
            sc = &g_second_cams[i];
            break;
        }
    }

    time_t now = time(NULL);

    if (!sc) {
        event_chain_append(session_id, "SECONDARY_ROOM_CAMERA", "SECOND_CAMERA_AUTH_FAILED",
                           "{\"reason\":\"UNKNOWN_SESSION\"}", "second-camera-manager", "1.0.0", NULL);
        pthread_mutex_unlock(&g_second_cam_lock);
        return -1;
    }

    if (sc->token_used) {
        event_chain_append(session_id, "SECONDARY_ROOM_CAMERA", "SECOND_CAMERA_AUTH_FAILED",
                           "{\"reason\":\"TOKEN_ALREADY_USED\"}", "second-camera-manager", "1.0.0", NULL);
        pthread_mutex_unlock(&g_second_cam_lock);
        return -1;
    }

    if (now > sc->expires_at) {
        sc->state = SECOND_CAM_STATE_EXPIRED;
        event_chain_append(session_id, "SECONDARY_ROOM_CAMERA", "SECOND_CAMERA_AUTH_FAILED",
                           "{\"reason\":\"TOKEN_EXPIRED\"}", "second-camera-manager", "1.0.0", NULL);
        pthread_mutex_unlock(&g_second_cam_lock);
        return -1;
    }

    if (strcmp(sc->qr_pairing_token, pairing_token) != 0) {
        event_chain_append(session_id, "SECONDARY_ROOM_CAMERA", "SECOND_CAMERA_AUTH_FAILED",
                           "{\"reason\":\"INVALID_TOKEN\"}", "second-camera-manager", "1.0.0", NULL);
        pthread_mutex_unlock(&g_second_cam_lock);
        return -1;
    }

    sc->token_used = 1;
    sc->state = SECOND_CAM_STATE_CONNECTED;
    sc->connected_at = now;

    event_chain_append(session_id, "SECONDARY_ROOM_CAMERA", "SECOND_CAMERA_CONNECTED",
                       "{\"role\":\"room_desk_view\",\"status\":\"STREAMING\"}",
                       "second-camera-manager", "1.0.0", NULL);

    pthread_mutex_unlock(&g_second_cam_lock);
    return 0;
}

void second_camera_disconnect(const char *session_id) {
    if (!session_id) return;

    pthread_mutex_lock(&g_second_cam_lock);
    for (int i = 0; i < g_second_cam_count; i++) {
        if (strcmp(g_second_cams[i].session_id, session_id) == 0) {
            g_second_cams[i].state = SECOND_CAM_STATE_DISCONNECTED;
            event_chain_append(session_id, "SECONDARY_ROOM_CAMERA", "SECOND_CAMERA_DISCONNECTED",
                               "{\"reason\":\"stream_closed\"}", "second-camera-manager", "1.0.0", NULL);
            break;
        }
    }
    pthread_mutex_unlock(&g_second_cam_lock);
}

second_cam_state_t second_camera_get_status(const char *session_id) {
    if (!session_id) return SECOND_CAM_STATE_UNPAIRED;

    pthread_mutex_lock(&g_second_cam_lock);
    for (int i = 0; i < g_second_cam_count; i++) {
        if (strcmp(g_second_cams[i].session_id, session_id) == 0) {
            second_cam_state_t st = g_second_cams[i].state;
            pthread_mutex_unlock(&g_second_cam_lock);
            return st;
        }
    }
    pthread_mutex_unlock(&g_second_cam_lock);
    return SECOND_CAM_STATE_UNPAIRED;
}

const char *second_camera_portal_html(const char *session_id, const char *token) {
    static char s_html[16384];
    snprintf(s_html, sizeof(s_html),
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no\">\n"
        "  <title>ExamOS — Secondary Room Camera</title>\n"
        "  <style>\n"
        "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "    body { background: #0b1329; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 1rem; }\n"
        "    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; width: 100%%; max-width: 480px; padding: 1.5rem; text-align: center; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }\n"
        "    h1 { font-size: 1.25rem; font-weight: 700; color: #38bdf8; margin-bottom: 0.5rem; }\n"
        "    p.sub { font-size: 0.85rem; color: #94a3b8; margin-bottom: 1.25rem; }\n"
        "    .video-box { width: 100%%; aspect-ratio: 4/3; background: #000; border-radius: 8px; overflow: hidden; position: relative; margin-bottom: 1rem; border: 2px solid #475569; }\n"
        "    video { width: 100%%; height: 100%%; object-fit: cover; }\n"
        "    .badge { position: absolute; top: 8px; left: 8px; background: rgba(15,23,42,0.85); color: #22c55e; border: 1px solid #22c55e; font-size: 0.75rem; font-weight: 600; padding: 4px 8px; border-radius: 4px; display: flex; align-items: center; gap: 4px; }\n"
        "    .dot { width: 6px; height: 6px; border-radius: 50%%; background: #22c55e; animation: pulse 1.5s infinite; }\n"
        "    @keyframes pulse { 0%%,100%% { opacity: 1; } 50%% { opacity: 0.3; } }\n"
        "    .instructions { text-align: left; background: #0f172a; border-radius: 8px; padding: 0.85rem; font-size: 0.8rem; color: #cbd5e1; margin-bottom: 1rem; line-height: 1.4; }\n"
        "    .btn { width: 100%%; padding: 0.75rem; background: #0284c7; color: #fff; font-weight: 600; border: none; border-radius: 6px; cursor: pointer; font-size: 0.95rem; }\n"
        "    .btn:hover { background: #0369a1; }\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <div class=\"card\">\n"
        "    <h1>ExamOS Room & Desk Feed</h1>\n"
        "    <p class=\"sub\">Session: <code>%s</code></p>\n"
        "    <div class=\"video-box\">\n"
        "      <video id=\"secondVideo\" autoplay playsinline muted></video>\n"
        "      <div class=\"badge\"><span class=\"dot\"></span> SECONDARY STREAM ACTIVE</div>\n"
        "    </div>\n"
        "    <div class=\"instructions\">\n"
        "      <strong>Placement Guidelines:</strong><br>\n"
        "      &bull; Place your phone ~45&deg; behind you showing your hands, keyboard, and desk.<br>\n"
        "      &bull; Keep device plugged in and screen on throughout the exam.\n"
        "    </div>\n"
        "    <button id=\"startBtn\" class=\"btn\" onclick=\"initStream()\">Activate Room Camera</button>\n"
        "  </div>\n"
        "  <script>\n"
        "    const sessionId = '%s';\n"
        "    const token = '%s';\n"
        "    async function initStream() {\n"
        "      try {\n"
        "        const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } }, audio: false });\n"
        "        document.getElementById('secondVideo').srcObject = stream;\n"
        "        document.getElementById('startBtn').style.display = 'none';\n"
        "        await fetch('/api/v1/second-camera/pair', {\n"
        "          method: 'POST',\n"
        "          headers: { 'Content-Type': 'application/json' },\n"
        "          body: JSON.stringify({ session_id: sessionId, token: token, status: 'CONNECTED' })\n"
        "        });\n"
        "      } catch (err) {\n"
        "        alert('Camera access denied: ' + err.message);\n"
        "      }\n"
        "    }\n"
        "  </script>\n"
        "</body>\n"
        "</html>\n",
        session_id ? session_id : "UNKNOWN",
        session_id ? session_id : "",
        token ? token : "");
    return s_html;
}
