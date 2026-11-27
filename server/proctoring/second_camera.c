#define _GNU_SOURCE
#include "../include/second_camera.h"
#include "../include/event_chain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/random.h>

#define TOKEN_VALIDITY_SECONDS 300 /* 5 minutes */

static second_camera_session_t g_second_cams[MAX_SECOND_CAMERA_SESSIONS];
static int                     g_second_cam_count = 0;
static pthread_mutex_t         g_second_cam_lock = PTHREAD_MUTEX_INITIALIZER;

static int random_hex(char *out, size_t num_bytes) {
    unsigned char *buf = malloc(num_bytes);
    if (!buf) return -1;
    size_t offset = 0;
    while (offset < num_bytes) {
        ssize_t count = getrandom(buf + offset, num_bytes - offset, 0);
        if (count <= 0) {
            free(buf);
            return -1;
        }
        offset += (size_t)count;
    }
    for (size_t i = 0; i < num_bytes; i++) {
        snprintf(out + (i * 2), 3, "%02x", buf[i]);
    }
    out[num_bytes * 2] = '\0';
    free(buf);
    return 0;
}

void second_camera_init(void) {
    pthread_mutex_lock(&g_second_cam_lock);
    for (int i = 0; i < g_second_cam_count; i++) {
        free(g_second_cams[i].latest_frame_b64);
    }
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

    if (sc) {
        free(sc->latest_frame_b64);
        sc->latest_frame_b64 = NULL;
        sc->latest_frame_len = 0;
        sc->last_frame_at = 0;
        sc->frame_count = 0;
    } else {
        if (g_second_cam_count >= MAX_SECOND_CAMERA_SESSIONS) {
            pthread_mutex_unlock(&g_second_cam_lock);
            return -1;
        }
        sc = &g_second_cams[g_second_cam_count++];
        memset(sc, 0, sizeof(*sc));
        strncpy(sc->session_id, session_id, sizeof(sc->session_id) - 1);
    }

    if (random_hex(sc->qr_pairing_token, 32) != 0) {
        memset(sc, 0, sizeof(*sc));
        pthread_mutex_unlock(&g_second_cam_lock);
        return -1;
    }
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
    sc->state = SECOND_CAM_STATE_PAIRED;
    sc->connected_at = now;

    event_chain_append(session_id, "SECONDARY_ROOM_CAMERA", "SECOND_CAMERA_PAIRED",
                       "{\"role\":\"room_desk_view\",\"status\":\"PAIRED_READY_FOR_STREAM\"}",
                       "second-camera-manager", "1.0.0", NULL);

    pthread_mutex_unlock(&g_second_cam_lock);
    return 0;
}

int second_camera_store_frame(const char *session_id, const char *pairing_token, const char *frame_b64) {
    if (!session_id || !pairing_token || !frame_b64 || !frame_b64[0]) return -1;
    size_t len = strlen(frame_b64);
    if (len > 262144) return -1; /* 256 KB max per frame */

    pthread_mutex_lock(&g_second_cam_lock);
    second_camera_session_t *sc = NULL;
    for (int i = 0; i < g_second_cam_count; i++) {
        if (strcmp(g_second_cams[i].session_id, session_id) == 0) {
            sc = &g_second_cams[i];
            break;
        }
    }
    if (!sc || (sc->state != SECOND_CAM_STATE_PAIRED && sc->state != SECOND_CAM_STATE_CONNECTED) ||
        strcmp(sc->qr_pairing_token, pairing_token) != 0) {
        pthread_mutex_unlock(&g_second_cam_lock);
        return -1;
    }

    char *copy = malloc(len + 1);
    if (!copy) {
        pthread_mutex_unlock(&g_second_cam_lock);
        return -1;
    }
    memcpy(copy, frame_b64, len + 1);
    free(sc->latest_frame_b64);
    sc->latest_frame_b64 = copy;
    sc->latest_frame_len = len;
    sc->last_frame_at = time(NULL);
    sc->frame_count++;
    sc->state = SECOND_CAM_STATE_CONNECTED;

    pthread_mutex_unlock(&g_second_cam_lock);
    return 0;
}

int second_camera_get_latest_frame(const char *session_id, char *out_b64, size_t max_out,
                                   time_t *out_ts, unsigned long *out_count,
                                   second_cam_state_t *out_state) {
    if (!session_id) return -1;

    pthread_mutex_lock(&g_second_cam_lock);
    second_camera_session_t *sc = NULL;
    for (int i = 0; i < g_second_cam_count; i++) {
        if (strcmp(g_second_cams[i].session_id, session_id) == 0) {
            sc = &g_second_cams[i];
            break;
        }
    }
    if (!sc) {
        pthread_mutex_unlock(&g_second_cam_lock);
        return -1;
    }
    if (out_state) *out_state = sc->state;
    if (out_ts) *out_ts = sc->last_frame_at;
    if (out_count) *out_count = sc->frame_count;
    if (!sc->latest_frame_b64 || !sc->latest_frame_b64[0]) {
        pthread_mutex_unlock(&g_second_cam_lock);
        return 1; /* Session exists, waiting for first frame */
    }
    if (!out_b64 || sc->latest_frame_len + 1 > max_out) {
        pthread_mutex_unlock(&g_second_cam_lock);
        return -1;
    }
    memcpy(out_b64, sc->latest_frame_b64, sc->latest_frame_len + 1);
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
        "    .badge { position: absolute; top: 8px; left: 8px; background: rgba(15,23,42,0.85); color: #fbbf24; border: 1px solid #fbbf24; font-size: 0.75rem; font-weight: 600; padding: 4px 8px; border-radius: 4px; }\n"
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
        "      <div id=\"cameraStatus\" class=\"badge\">CAMERA NOT STARTED</div>\n"
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
        "    let streamTimer = null;\n"
        "    let frameCount = 0;\n"
        "    async function initStream() {\n"
        "      const statusEl = document.getElementById('cameraStatus');\n"
        "      const btnEl = document.getElementById('startBtn');\n"
        "      try {\n"
        "        const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } }, audio: false });\n"
        "        const video = document.getElementById('secondVideo');\n"
        "        video.srcObject = stream;\n"
        "        statusEl.textContent = 'PAIRING CAMERA...';\n"
        "        const pairRes = await fetch('/api/v1/second-camera/pair', {\n"
        "          method: 'POST',\n"
        "          headers: { 'Content-Type': 'application/json' },\n"
        "          body: JSON.stringify({ session_id: sessionId, token: token, status: 'CONNECTED' })\n"
        "        });\n"
        "        if (!pairRes.ok) {\n"
        "          const errData = await pairRes.json().catch(() => ({}));\n"
        "          throw new Error(errData.error || 'Pairing rejected by server');\n"
        "        }\n"
        "        btnEl.disabled = true;\n"
        "        btnEl.textContent = 'Streaming Active';\n"
        "        statusEl.style.color = '#4ade80';\n"
        "        statusEl.style.borderColor = '#4ade80';\n"
        "        statusEl.textContent = 'LIVE STREAMING ACTIVE';\n"
        "        const canvas = document.createElement('canvas');\n"
        "        canvas.width = 480;\n"
        "        canvas.height = 360;\n"
        "        const ctx = canvas.getContext('2d');\n"
        "        if (streamTimer) clearInterval(streamTimer);\n"
        "        streamTimer = setInterval(async () => {\n"
        "          if (video.readyState < 2) return;\n"
        "          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);\n"
        "          const frameB64 = canvas.toDataURL('image/jpeg', 0.65);\n"
        "          try {\n"
        "            const up = await fetch('/api/v1/second-camera/frame', {\n"
        "              method: 'POST',\n"
        "              headers: { 'Content-Type': 'application/json' },\n"
        "              body: JSON.stringify({ session_id: sessionId, token: token, frame_base64: frameB64 })\n"
        "            });\n"
        "            if (up.ok) {\n"
        "              frameCount++;\n"
        "              statusEl.textContent = 'LIVE STREAMING · Frame #' + frameCount;\n"
        "            }\n"
        "          } catch (_) {}\n"
        "        }, 1500);\n"
        "      } catch (err) {\n"
        "        statusEl.textContent = 'ERROR: ' + err.message;\n"
        "        alert('Camera error: ' + err.message);\n"
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
