#define _GNU_SOURCE
#include "../include/candidate_login.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

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

    // Find free slot or overwrite expired slot
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].active || (now - g_sessions[i].created_at > 28800)) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        slot = 0; // overwrite oldest
    }

    strncpy(g_sessions[slot].token, token, SESSION_TOKEN_LEN);
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
            if (now - g_sessions[i].created_at <= 28800) { // 8 hours
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
           "    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; width: 100%; max-width: 440px;\n"
           "            padding: 36px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5); }\n"
           "    .header { text-align: center; margin-bottom: 28px; }\n"
           "    .shield { width: 48px; height: 48px; margin: 0 auto 12px; display: flex; align-items: center; justify-content: center;\n"
           "              background: #0284c7; border-radius: 10px; color: #fff; font-weight: bold; font-size: 24px; }\n"
           "    .title { font-size: 22px; font-weight: 700; color: #f8fafc; letter-spacing: -0.5px; }\n"
           "    .subtitle { font-size: 13px; color: #94a3b8; margin-top: 4px; }\n"
           "    .badge { display: inline-block; background: #0369a1; color: #e0f2fe; padding: 3px 10px; border-radius: 9999px;\n"
           "             font-size: 11px; font-weight: 600; margin-top: 8px; letter-spacing: 0.5px; text-transform: uppercase; }\n"
           "    .form-group { margin-bottom: 20px; }\n"
           "    label { display: block; font-size: 13px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }\n"
           "    input[type=\"text\"], input[type=\"password\"] {\n"
           "      width: 100%; padding: 12px 14px; background: #0f172a; border: 1px solid #334155; border-radius: 8px;\n"
           "      color: #f8fafc; font-size: 15px; outline: none; transition: border-color 0.2s;\n"
           "    }\n"
           "    input:focus { border-color: #38bdf8; box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2); }\n"
           "    .btn { width: 100%; padding: 13px; background: #0284c7; color: white; border: none; border-radius: 8px;\n"
           "           font-size: 15px; font-weight: 600; cursor: pointer; transition: background 0.2s, transform 0.1s; }\n"
           "    .btn:hover { background: #0369a1; }\n"
           "    .btn:active { transform: scale(0.99); }\n"
           "    .msg { margin-top: 16px; padding: 10px 14px; border-radius: 6px; font-size: 13px; display: none; text-align: center; }\n"
           "    .msg-error { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; display: block; }\n"
           "    .msg-success { background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; color: #86efac; display: block; }\n"
           "    .footer { margin-top: 24px; text-align: center; font-size: 11px; color: #64748b; }\n"
           "  </style>\n"
           "</head>\n"
           "<body>\n"
           "  <div class=\"card\">\n"
           "    <div class=\"header\">\n"
           "      <div class=\"shield\">E</div>\n"
           "      <div class=\"title\">ExamOS Appliance</div>\n"
           "      <div class=\"subtitle\">Prevention-First Secure Examination Platform</div>\n"
           "      <span class=\"badge\">Candidate Verification</span>\n"
           "    </div>\n"
           "    <div id=\"alert-box\" class=\"msg\"></div>\n"
           "    <form id=\"login-form\">\n"
           "      <div class=\"form-group\">\n"
           "        <label for=\"candidate_id\">Candidate ID / Roll Number</label>\n"
           "        <input type=\"text\" id=\"candidate_id\" name=\"candidate_id\" required placeholder=\"e.g. CAND-2025-08912\" autocomplete=\"off\">\n"
           "      </div>\n"
           "      <div class=\"form-group\">\n"
           "        <label for=\"pin\">Exam Access PIN / Password</label>\n"
           "        <input type=\"password\" id=\"pin\" name=\"pin\" required placeholder=\"Enter exam PIN\" autocomplete=\"off\">\n"
           "      </div>\n"
           "      <button type=\"submit\" class=\"btn\" id=\"submit-btn\">Begin Examination</button>\n"
           "    </form>\n"
           "    <div class=\"footer\">\n"
           "      ExamOS Appliance v0.2.0 • Hardware Guard: ACTIVE • Attestation: MEASURED<br>\n"
           "      <a href=\"/admin\" style=\"color: #475569; text-decoration: none; font-size: 10px; margin-top: 8px; display: inline-block;\">Admin Portal</a>\n"
           "    </div>\n"
           "  </div>\n"
           "  <script>\n"
           "    document.getElementById('login-form').addEventListener('submit', async function(e) {\n"
           "      e.preventDefault();\n"
           "      const cid = document.getElementById('candidate_id').value.trim();\n"
           "      const pin = document.getElementById('pin').value.trim();\n"
           "      const btn = document.getElementById('submit-btn');\n"
           "      const alert = document.getElementById('alert-box');\n"
           "      btn.disabled = true; btn.innerText = 'Authenticating Secure Environment...';\n"
           "      alert.className = 'msg'; alert.style.display = 'none';\n"
           "      try {\n"
           "        const res = await fetch('/api/v1/candidate/login', {\n"
           "          method: 'POST',\n"
           "          headers: { 'Content-Type': 'application/json' },\n"
           "          body: JSON.stringify({ candidate_id: cid, pin: pin })\n"
           "        });\n"
           "        const data = await res.json();\n"
           "        if (res.ok && data.status === 'SUCCESS') {\n"
           "          alert.className = 'msg msg-success';\n"
           "          alert.innerText = 'Authenticated. Launching secure exam session...';\n"
           "          document.cookie = 'examos_session=' + data.token + '; path=/; SameSite=Strict';\n"
           "          setTimeout(() => {\n"
           "            if (data.exam_url && data.exam_url !== 'NOT_CONFIGURED') {\n"
           "              window.location.href = data.exam_url;\n"
           "            } else {\n"
           "              window.location.href = '/exam';\n"
           "            }\n"
           "          }, 800);\n"
           "        } else {\n"
           "          alert.className = 'msg msg-error';\n"
           "          alert.innerText = data.error || 'Authentication rejected. Contact proctor.';\n"
           "          btn.disabled = false; btn.innerText = 'Begin Examination';\n"
           "        }\n"
           "      } catch (err) {\n"
           "        alert.className = 'msg msg-error';\n"
           "        alert.innerText = 'Network error connecting to ExamOS security service.';\n"
           "        btn.disabled = false; btn.innerText = 'Begin Examination';\n"
           "      }\n"
           "    });\n"
           "  </script>\n"
           "</body>\n"
           "</html>\n";
}
