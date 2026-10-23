#define _GNU_SOURCE
#include "../include/candidate_login.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <ctype.h>

#define CANDIDATE_STORE_DEFAULT "/etc/examos/candidates.conf"
#define PIN_DERIVED_LEN 32

static int hex_decode(const char *hex, unsigned char *out, size_t out_len) {
    if (!hex || strlen(hex) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int byte = 0;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

static int valid_candidate_id(const char *id) {
    size_t len = id ? strlen(id) : 0;
    if (len == 0 || len >= MAX_CANDIDATE_ID_LEN) return 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)id[i];
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.')) return 0;
    }
    return 1;
}

int candidate_credentials_validate(const char *candidate_id, const char *pin) {
    if (!valid_candidate_id(candidate_id) || !pin || strlen(pin) < 6 || strlen(pin) > 128)
        return 0;

    const char *path = getenv("EXAMOS_CANDIDATE_STORE");
    if (!path || !*path) path = CANDIDATE_STORE_DEFAULT;
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fp = fopen("candidates.conf", "r");
    }
    if (!fp) {
        fp = fopen("/var/lib/examos/candidates.conf", "r");
    }
    if (!fp) return 0; /* Missing identity store is a fail-closed condition. */

    char line[1024];
    int valid = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *save = NULL;
        char *id = strtok_r(line, ":", &save);
        char *iterations_text = strtok_r(NULL, ":", &save);
        char *salt_hex = strtok_r(NULL, ":", &save);
        char *hash_hex = strtok_r(NULL, ":\r\n", &save);
        if (!id || !iterations_text || !salt_hex || !hash_hex || strcmp(id, candidate_id) != 0)
            continue;

        char *end = NULL;
        long iterations = strtol(iterations_text, &end, 10);
        size_t salt_len = strlen(salt_hex) / 2;
        if (*end || iterations < 100000 || iterations > 5000000 || salt_len < 16 || salt_len > 64)
            break;
        unsigned char salt[64], expected[PIN_DERIVED_LEN], derived[PIN_DERIVED_LEN];
        if (hex_decode(salt_hex, salt, salt_len) != 0 ||
            hex_decode(hash_hex, expected, sizeof(expected)) != 0)
            break;
        if (PKCS5_PBKDF2_HMAC(pin, (int)strlen(pin), salt, (int)salt_len,
                              (int)iterations, EVP_sha256(), sizeof(derived), derived) == 1)
            valid = CRYPTO_memcmp(expected, derived, sizeof(derived)) == 0;
        OPENSSL_cleanse(derived, sizeof(derived));
        break;
    }
    fclose(fp);
    return valid;
}

static candidate_session_t g_sessions[MAX_SESSIONS];
static pthread_mutex_t g_session_lock = PTHREAD_MUTEX_INITIALIZER;

void candidate_session_init(void) {
    pthread_mutex_lock(&g_session_lock);
    memset(g_sessions, 0, sizeof(g_sessions));
    pthread_mutex_unlock(&g_session_lock);
}

int candidate_session_create(const char *candidate_id, char *out_token) {
    if (!candidate_id || !out_token) return -1;

    unsigned char rand_bytes[32];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    if (read(fd, rand_bytes, sizeof(rand_bytes)) != sizeof(rand_bytes)) {
        close(fd);
        return -1;
    }
    close(fd);

    char token[SESSION_TOKEN_LEN + 1];
    for (int i = 0; i < 32; i++) {
        sprintf(token + (i * 2), "%02x", rand_bytes[i]);
    }
    token[SESSION_TOKEN_LEN] = '\0';

    pthread_mutex_lock(&g_session_lock);
    time_t now = time(NULL);
    int slot = -1;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].active || (now - g_sessions[i].created_at > 28800)) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        slot = 0;
    }

    memcpy(g_sessions[slot].token, token, sizeof(g_sessions[slot].token));
    g_sessions[slot].token[SESSION_TOKEN_LEN] = '\0';
    strncpy(g_sessions[slot].candidate_id, candidate_id, MAX_CANDIDATE_ID_LEN - 1);
    g_sessions[slot].candidate_id[MAX_CANDIDATE_ID_LEN - 1] = '\0';
    g_sessions[slot].created_at = now;
    g_sessions[slot].active = 1;

    strcpy(out_token, token);
    pthread_mutex_unlock(&g_session_lock);
    return 0;
}

int candidate_session_validate(const char *token) {
    if (!token || strlen(token) != SESSION_TOKEN_LEN) return 0;

    pthread_mutex_lock(&g_session_lock);
    time_t now = time(NULL);
    int valid = 0;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].active && strcmp(g_sessions[i].token, token) == 0) {
            if (now - g_sessions[i].created_at <= 28800) {
                valid = 1;
            } else {
                g_sessions[i].active = 0;
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_session_lock);
    return valid;
}

int candidate_session_restore(const char *token, const char *candidate_id, time_t created_at) {
    if (!token || !candidate_id || strlen(token) != SESSION_TOKEN_LEN) return -1;
    pthread_mutex_lock(&g_session_lock);
    time_t now = time(NULL);
    /* Reject already-expired sessions */
    if (now - created_at > 28800) { pthread_mutex_unlock(&g_session_lock); return -1; }
    /* Find free or expired slot */
    int slot = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].active || (now - g_sessions[i].created_at > 28800)) {
            slot = i; break;
        }
    }
    if (slot == -1) slot = 0; /* evict oldest */
    memcpy(g_sessions[slot].token, token, SESSION_TOKEN_LEN + 1);
    strncpy(g_sessions[slot].candidate_id, candidate_id, MAX_CANDIDATE_ID_LEN - 1);
    g_sessions[slot].candidate_id[MAX_CANDIDATE_ID_LEN - 1] = '\0';
    g_sessions[slot].created_at = created_at;
    g_sessions[slot].active = 1;
    pthread_mutex_unlock(&g_session_lock);
    return 0;
}

int candidate_session_identity(const char *token, char *out_candidate_id, size_t max_len) {
    if (!token || !out_candidate_id || max_len == 0 || strlen(token) != SESSION_TOKEN_LEN) return 0;
    out_candidate_id[0] = '\0';
    pthread_mutex_lock(&g_session_lock);
    time_t now = time(NULL);
    int valid = 0;
    for (int i = 0; i < MAX_SESSIONS; ++i) {
        if (g_sessions[i].active && strcmp(g_sessions[i].token, token) == 0 &&
            now - g_sessions[i].created_at <= 28800) {
            snprintf(out_candidate_id, max_len, "%s", g_sessions[i].candidate_id);
            valid = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_session_lock);
    return valid;
}

void candidate_session_invalidate(const char *token) {
    if (!token) return;
    pthread_mutex_lock(&g_session_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (strcmp(g_sessions[i].token, token) == 0) {
            g_sessions[i].active = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_session_lock);
}

const char *candidate_login_html(void) {
    return "<!DOCTYPE html>\n"
           "<html lang=\"en\">\n"
           "<head>\n"
           "  <meta charset=\"UTF-8\">\n"
           "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
           "  <title>ExamOS — Secure Examination Portal</title>\n"
           "  <style>\n"
           "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
           "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;\n"
           "           background: #0f172a; color: #e2e8f0; min-height: 100vh; display: flex; flex-direction: column;\n"
           "           justify-content: center; align-items: center; padding: 20px; user-select: none; }\n"
           "    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; width: 100%; max-width: 480px;\n"
           "            padding: 32px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }\n"
           "    .header { text-align: center; margin-bottom: 24px; }\n"
           "    .shield { width: 44px; height: 44px; margin: 0 auto 10px; display: flex; align-items: center; justify-content: center;\n"
           "              background: #0284c7; border-radius: 10px; color: #fff; font-weight: bold; font-size: 22px; }\n"
           "    .title { font-size: 20px; font-weight: 700; color: #f8fafc; }\n"
           "    .subtitle { font-size: 13px; color: #94a3b8; margin-top: 4px; }\n"
           "    .badge { display: inline-block; background: #0369a1; color: #e0f2fe; padding: 3px 10px; border-radius: 9999px;\n"
           "             font-size: 11px; font-weight: 600; margin-top: 8px; text-transform: uppercase; }\n"
           "    .form-group { margin-bottom: 16px; }\n"
           "    label { display: block; font-size: 13px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }\n"
           "    input[type=\"text\"], input[type=\"password\"] {\n"
           "      width: 100%; padding: 12px 14px; background: #0f172a; border: 1px solid #334155; border-radius: 8px;\n"
           "      color: #f8fafc; font-size: 15px; outline: none; transition: border-color 0.2s;\n"
           "    }\n"
           "    input:focus { border-color: #38bdf8; }\n"
           "    .btn { width: 100%; padding: 12px; background: #0284c7; color: white; border: none; border-radius: 8px;\n"
           "           font-size: 15px; font-weight: 600; cursor: pointer; transition: background 0.2s; }\n"
           "    .btn:hover { background: #0369a1; }\n"
           "    .btn-secondary { background: #334155; margin-top: 8px; }\n"
           "    .btn-secondary:hover { background: #475569; }\n"
           "    .msg { margin-top: 16px; padding: 10px 14px; border-radius: 6px; font-size: 13px; display: none; text-align: center; }\n"
           "    .msg-error { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; display: block; }\n"
           "    .msg-success { background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; color: #86efac; display: block; }\n"
           "    /* Consent Modal */\n"
           "    #consent-modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.8); z-index: 100;\n"
           "                     align-items: center; justify-content: center; padding: 20px; }\n"
           "    .modal-box { background: #1e293b; border: 1px solid #475569; border-radius: 12px; max-width: 520px; width: 100%;\n"
           "                 padding: 24px; max-height: 90vh; overflow-y: auto; }\n"
           "    .modal-title { font-size: 18px; font-weight: 700; color: #38bdf8; margin-bottom: 12px; }\n"
           "    .consent-text { font-size: 13px; color: #cbd5e1; line-height: 1.5; margin-bottom: 16px; background: #0f172a;\n"
           "                    padding: 14px; border-radius: 8px; border: 1px solid #334155; }\n"
           "    .consent-list { margin-left: 18px; margin-top: 8px; }\n"
           "    .preview-box { width: 100%; aspect-ratio: 16/9; background: #000; border-radius: 8px; overflow: hidden;\n"
           "                   margin-bottom: 14px; border: 1px solid #475569; position: relative; }\n"
           "    video { width: 100%; height: 100%; object-fit: cover; }\n"
           "    .footer { margin-top: 20px; text-align: center; font-size: 11px; color: #64748b; }\n"
           "  </style>\n"
           "</head>\n"
           "<body>\n"
           "  <div class=\"card\" id=\"login-card\">\n"
           "    <div class=\"header\">\n"
           "      <div class=\"shield\">E</div>\n"
           "      <div class=\"title\">ExamOS Appliance</div>\n"
           "      <div class=\"subtitle\">Phase 4 Proctoring & Tamper-Evident Examination Platform</div>\n"
           "      <span class=\"badge\">Candidate Verification</span>\n"
           "    </div>\n"
           "    <div id=\"alert-box\" class=\"msg\"></div>\n"
           "    <form id=\"login-form\">\n"
           "      <div class=\"form-group\">\n"
           "        <label for=\"candidate_id\">Candidate ID / Roll Number</label>\n"
           "        <input type=\"text\" id=\"candidate_id\" name=\"candidate_id\" required placeholder=\"e.g. CAND-2026-001\" autocomplete=\"off\">\n"
           "      </div>\n"
           "      <div class=\"form-group\">\n"
           "        <label for=\"pin\">Exam Access PIN / Password</label>\n"
           "        <input type=\"password\" id=\"pin\" name=\"pin\" required placeholder=\"Enter exam PIN\" autocomplete=\"off\">\n"
           "      </div>\n"
           "      <button type=\"submit\" class=\"btn\" id=\"submit-btn\">Proceed to Verification</button>\n"
           "    </form>\n"
           "    <div class=\"footer\">\n"
           "      ExamOS v0.4.0 • <span id=\"tpm-status\">Checking service…</span><br>\n"
           "      <a href=\"/admin\" style=\"color: #475569; text-decoration: none; font-size: 10px; margin-top: 8px; display: inline-block;\">Admin Portal</a>\n"
           "    </div>\n"
           "  </div>\n"
           "\n"
           "  <!-- Candidate Consent and Camera Check Modal -->\n"
           "  <div id=\"consent-modal\">\n"
           "    <div class=\"modal-box\">\n"
           "      <div class=\"modal-title\">Secure Examination Integrity & Proctoring Agreement</div>\n"
           "      <div class=\"consent-text\">\n"
           "        <strong>TCS iON NQT-Level Secure Examination Environment:</strong><br>\n"
           "        This examination runs within an isolated, tamper-evident ExamOS secure kiosk. By entering, you acknowledge and agree:\n"
           "        <ul class=\"consent-list\">\n"
           "          <li><strong>Real-time AI Proctoring:</strong> WebRTC camera monitoring validates candidate identity, head pose, and presence. Derived inference events are recorded.</li>\n"
           "          <li><strong>Kiosk Lockdown:</strong> Window switching, multi-monitors, background applications, developer shortcuts, and clipboard operations are strictly blocked.</li>\n"
           "          <li><strong>Cryptographic Ledger:</strong> All answer submissions, timing milestones, and security risk telemetry are permanently signed into the SHA-256 HMAC event chain.</li>\n"
           "          <li><strong>Violations & Termination:</strong> Excessive head turns, leaving the camera frame, or unauthorized keystrokes trigger automated security strikes and session invalidation.</li>\n"
           "        </ul>\n"
           "      </div>\n"
           "      <div class=\"preview-box\">\n"
           "        <video id=\"preview-cam\" autoplay playsinline muted></video>\n"
           "      </div>\n"
           "      <button class=\"btn\" id=\"consent-btn\" onclick=\"acceptConsent()\">I Agree & Enter Secure Exam Workbench</button>\n"
           "      <button class=\"btn btn-secondary\" onclick=\"closeConsent()\">Cancel</button>\n"
           "    </div>\n"
           "  </div>\n"
           "\n"
           "  <script>\n"
           "    let currentSessionId = '';\n"
           "    let currentExamUrl = '';\n"
           "    let localStream = null;\n"
           "\n"
           "    document.getElementById('login-form').addEventListener('submit', async function(e) {\n"
           "      e.preventDefault();\n"
           "      const cid = document.getElementById('candidate_id').value.trim();\n"
           "      const pin = document.getElementById('pin').value.trim();\n"
           "      const btn = document.getElementById('submit-btn');\n"
           "      const alert = document.getElementById('alert-box');\n"
           "      btn.disabled = true; btn.innerText = 'Authenticating...';\n"
           "      alert.className = 'msg'; alert.style.display = 'none';\n"
           "      try {\n"
           "        const res = await fetch('/api/v1/candidate/login', {\n"
           "          method: 'POST',\n"
           "          headers: { 'Content-Type': 'application/json' },\n"
           "          body: JSON.stringify({ candidate_id: cid, pin: pin })\n"
           "        });\n"
           "        const data = await res.json();\n"
           "        if (res.ok && data.status === 'SUCCESS') {\n"
           "          currentSessionId = data.token;\n"
           "          currentExamUrl = data.exam_url;\n"
           "          sessionStorage.setItem('examos_session_token', data.token);\n"
           "          sessionStorage.setItem('examos_candidate_id', cid);\n"
           "          document.cookie = 'examos_token=' + encodeURIComponent(data.token) + '; path=/; max-age=28800; SameSite=Strict';\n"
           "          openConsent();\n"
           "        } else {\n"
           "          alert.className = 'msg msg-error';\n"
           "          alert.innerText = data.error || 'Authentication rejected.';\n"
           "          btn.disabled = false; btn.innerText = 'Proceed to Verification';\n"
           "        }\n"
           "      } catch (err) {\n"
           "        alert.className = 'msg msg-error';\n"
           "        alert.innerText = 'Network error connecting to ExamOS.';\n"
           "        btn.disabled = false; btn.innerText = 'Proceed to Verification';\n"
           "      }\n"
           "    });\n"
           "\n"
           "    async function openConsent() {\n"
           "      document.getElementById('consent-modal').style.display = 'flex';\n"
           "      try {\n"
           "        if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {\n"
           "          localStream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 360 }, audio: false });\n"
           "          const video = document.getElementById('preview-cam');\n"
           "          if (video) { video.srcObject = localStream; }\n"
           "        }\n"
           "      } catch (err) {\n"
           "        console.warn('Webcam preview notice:', err);\n"
           "      }\n"
           "    }\n"
           "\n"
           "    function closeConsent() {\n"
           "      if (localStream) { localStream.getTracks().forEach(t => t.stop()); }\n"
           "      document.getElementById('consent-modal').style.display = 'none';\n"
           "      document.getElementById('submit-btn').disabled = false;\n"
           "      document.getElementById('submit-btn').innerText = 'Proceed to Verification';\n"
           "    }\n"
           "\n"
           "    async function acceptConsent() {\n"
           "      const cid = document.getElementById('candidate_id').value.trim();\n"
           "      const token = currentSessionId || sessionStorage.getItem('examos_session_token');\n"
           "      try {\n"
           "        await fetch('/api/v1/consent', {\n"
           "          method: 'POST',\n"
           "          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },\n"
           "          body: JSON.stringify({ session_id: token, candidate_id: cid, consent: true })\n"
           "        });\n"
           "      } catch (err) {\n"
           "        console.warn('Consent recording failed:', err);\n"
           "      }\n"
           "      if (localStream) { localStream.getTracks().forEach(t => t.stop()); }\n"
           "      window.location.href = '/exam';\n"
           "    }\n"
           "    fetch('/api/v1/health',{cache:'no-store'}).then(r=>r.json()).then(h=>{\n"
           "      const el=document.getElementById('tpm-status');\n"
           "      if(el) el.textContent='TPM: '+(h.tpm_mode||'unknown')+' | Ledger: '+(h.ledger_integrity||'unknown')+' | '+h.readiness;\n"
           "    }).catch(()=>{});\n"
           "  </script>\n"
           "</body>\n"
           "</html>\n";
}
