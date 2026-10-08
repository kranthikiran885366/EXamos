#define _GNU_SOURCE
#include "../include/admin_dashboard.h"
#include "../include/config_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Base64 decoding helper */
static int base64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int base64_decode(const char *input, char *output, size_t max_out) {
    size_t in_len = strlen(input);
    size_t out_idx = 0;
    int buf = 0, bits = 0;

    for (size_t i = 0; i < in_len; i++) {
        if (input[i] == '=') break;
        int val = base64_char_value(input[i]);
        if (val == -1) continue; // skip whitespace or invalid
        buf = (buf << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out_idx + 1 < max_out) {
                output[out_idx++] = (char)((buf >> bits) & 0xFF);
            }
        }
    }
    if (out_idx < max_out) output[out_idx] = '\0';
    return (int)out_idx;
}

int admin_check_auth(const char *auth_header) {
    if (!auth_header || strlen(auth_header) < 6) return 0;
    if (strncmp(auth_header, "Basic ", 6) != 0) return 0;

    const char *b64 = auth_header + 6;
    while (*b64 == ' ') b64++;

    char decoded[256] = {0};
    if (base64_decode(b64, decoded, sizeof(decoded)) <= 0) return 0;

    char *colon = strchr(decoded, ':');
    if (!colon) return 0;

    *colon = '\0';
    char *user = decoded;
    char *pass = colon + 1;

    /* Accept admin or examos username */
    if (strcmp(user, "admin") != 0 && strcmp(user, "examos") != 0) {
        return 0;
    }

    return config_verify_admin_password(pass);
}

const char *admin_login_html(void) {
    return "<!DOCTYPE html>\n"
           "<html lang=\"en\">\n"
           "<head>\n"
           "  <meta charset=\"UTF-8\">\n"
           "  <title>ExamOS Admin Portal — Authentication</title>\n"
           "  <style>\n"
           "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
           "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;\n"
           "           background: #090d16; color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }\n"
           "    .card { background: #131c2e; border: 1px solid #1e293b; border-radius: 12px; width: 100%; max-width: 400px; padding: 32px; }\n"
           "    .header { text-align: center; margin-bottom: 24px; }\n"
           "    .badge { background: #dc2626; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }\n"
           "    h1 { font-size: 20px; font-weight: 700; margin: 10px 0 4px; color: #f8fafc; }\n"
           "    p { font-size: 13px; color: #94a3b8; }\n"
           "    .form-group { margin-bottom: 18px; }\n"
           "    label { display: block; font-size: 12px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }\n"
           "    input { width: 100%; padding: 10px 12px; background: #090d16; border: 1px solid #334155; border-radius: 6px; color: #fff; font-size: 14px; outline: none; }\n"
           "    input:focus { border-color: #38bdf8; }\n"
           "    .btn { width: 100%; padding: 12px; background: #0284c7; color: white; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }\n"
           "    .btn:hover { background: #0369a1; }\n"
           "    .warn { font-size: 11px; color: #64748b; text-align: center; margin-top: 18px; line-height: 1.4; }\n"
           "  </style>\n"
           "</head>\n"
           "<body>\n"
           "  <div class=\"card\">\n"
           "    <div class=\"header\">\n"
           "      <span class=\"badge\">RESTRICTED ACCESS</span>\n"
           "      <h1>ExamOS Admin Portal</h1>\n"
           "      <p>Enter administrator credentials to configure appliance</p>\n"
           "    </div>\n"
           "    <form onsubmit=\"event.preventDefault(); auth();\">\n"
           "      <div class=\"form-group\">\n"
           "        <label>Username</label>\n"
           "        <input type=\"text\" id=\"u\" required autocomplete=\"off\" value=\"admin\">\n"
           "      </div>\n"
           "      <div class=\"form-group\">\n"
           "        <label>Admin Password</label>\n"
           "        <input type=\"password\" id=\"p\" required autocomplete=\"off\" placeholder=\"••••••••••••\">\n"
           "      </div>\n"
           "      <button type=\"submit\" class=\"btn\">Authenticate</button>\n"
           "    </form>\n"
           "    <div class=\"warn\">Authorized Personnel Only.<br>All configuration modifications are cryptographically signed to the tamper-evident ledger.</div>\n"
           "  </div>\n"
           "  <script>\n"
           "    function auth() {\n"
           "      const u = document.getElementById('u').value;\n"
           "      const p = document.getElementById('p').value;\n"
           "      const token = btoa(u + ':' + p);\n"
           "      fetch('/admin', {\n"
           "        headers: { 'Authorization': 'Basic ' + token }\n"
           "      }).then(r => {\n"
           "        if (r.ok) {\n"
           "          sessionStorage.setItem('examos_admin_auth', token);\n"
           "          window.location.reload();\n"
           "        } else {\n"
           "          alert('Invalid administrator credentials.');\n"
           "        }\n"
           "      }).catch(() => alert('Network error connecting to ExamOS server.'));\n"
           "    }\n"
           "  </script>\n"
           "</body>\n"
           "</html>\n";
}

const char *admin_dashboard_html(const char *current_url, const char *current_name, int duration_minutes) {
    static char buf[65536];
    const char *url_val = (current_url && strlen(current_url) > 0) ? current_url : "NOT_CONFIGURED";
    const char *name_val = (current_name && strlen(current_name) > 0) ? current_name : "ExamOS Final Examination";
    int dur_val = (duration_minutes > 0) ? duration_minutes : 120;

    snprintf(buf, sizeof(buf),
             "<!DOCTYPE html>\n"
             "<html lang=\"en\">\n"
             "<head>\n"
             "  <meta charset=\"UTF-8\">\n"
             "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
             "  <title>ExamOS Administrator Dashboard</title>\n"
             "  <style>\n"
             "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
             "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;\n"
             "           background: #090d16; color: #e2e8f0; min-height: 100vh; display: flex; }\n"
             "    .sidebar { width: 240px; background: #0f172a; border-right: 1px solid #1e293b; padding: 24px 16px; display: flex; flex-direction: column; }\n"
             "    .logo { font-size: 16px; font-weight: bold; color: #38bdf8; display: flex; align-items: center; gap: 8px; margin-bottom: 28px; }\n"
             "    .nav-item { padding: 10px 12px; border-radius: 6px; font-size: 13px; font-weight: 500; color: #94a3b8; text-decoration: none; margin-bottom: 4px; display: block; }\n"
             "    .nav-item.active { background: #1e293b; color: #38bdf8; }\n"
             "    .nav-item:hover { background: #1e293b; color: #fff; }\n"
             "    .main { flex: 1; padding: 32px 40px; overflow-y: auto; }\n"
             "    .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 28px; }\n"
             "    h1 { font-size: 24px; font-weight: 700; color: #f8fafc; }\n"
             "    .status-pill { background: #10b981; color: #fff; font-size: 11px; font-weight: bold; padding: 4px 12px; border-radius: 9999px; }\n"
             "    .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }\n"
             "    .card { background: #131c2e; border: 1px solid #1e293b; border-radius: 10px; padding: 24px; margin-bottom: 24px; }\n"
             "    .card-title { font-size: 16px; font-weight: 600; color: #f8fafc; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }\n"
             "    .form-group { margin-bottom: 18px; }\n"
             "    label { display: block; font-size: 13px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }\n"
             "    input[type=\"text\"], input[type=\"number\"] {\n"
             "      width: 100%%; padding: 10px 14px; background: #090d16; border: 1px solid #334155; border-radius: 6px;\n"
             "      color: #fff; font-size: 14px; outline: none; }\n"
             "    input:focus { border-color: #38bdf8; }\n"
             "    .btn-primary { background: #0284c7; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px; }\n"
             "    .btn-primary:hover { background: #0369a1; }\n"
             "    .btn-danger { background: #dc2626; color: white; border: none; padding: 8px 14px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; }\n"
             "    .btn-danger:hover { background: #b91c1c; }\n"
             "    .metric-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #1e293b; font-size: 13px; }\n"
             "    .metric-name { color: #94a3b8; }\n"
             "    .metric-val { font-weight: 600; color: #f8fafc; font-family: monospace; }\n"
             "    .alert-box { padding: 12px 16px; border-radius: 6px; margin-bottom: 18px; font-size: 13px; display: none; }\n"
             "  </style>\n"
             "</head>\n"
             "<body>\n"
             "  <div class=\"sidebar\">\n"
             "    <div class=\"logo\">🛡️ ExamOS Control</div>\n"
             "    <a href=\"#\" class=\"nav-item active\">Configuration</a>\n"
             "    <a href=\"/api/v1/ledger\" target=\"_blank\" class=\"nav-item\">Tamper-Evident Ledger</a>\n"
             "    <a href=\"/\" class=\"nav-item\">Candidate Portal</a>\n"
             "    <div style=\"margin-top: auto;\">\n"
             "      <button onclick=\"sessionStorage.removeItem('examos_admin_auth'); window.location.href='/';\" class=\"btn-danger\" style=\"width:100%%;\">Log Out</button>\n"
             "    </div>\n"
             "  </div>\n"
             "  <div class=\"main\">\n"
             "    <div class=\"topbar\">\n"
             "      <h1>Appliance Configuration</h1>\n"
             "      <span class=\"status-pill\">OPERATIONAL</span>\n"
             "    </div>\n"
             "    <div id=\"alert\" class=\"alert-box\"></div>\n"
             "    <div class=\"grid\">\n"
             "      <div>\n"
             "        <div class=\"card\">\n"
             "          <div class=\"card-title\">Target Examination Settings</div>\n"
             "          <form id=\"cfg-form\">\n"
             "            <div class=\"form-group\">\n"
             "              <label>Target Examination URL (HTTPS required)</label>\n"
             "              <input type=\"text\" id=\"exam_url\" value=\"%s\" required placeholder=\"https://exam.university.edu/session/start\">\n"
             "            </div>\n"
             "            <div class=\"form-group\">\n"
             "              <label>Exam Title / Subject Name</label>\n"
             "              <input type=\"text\" id=\"exam_name\" value=\"%s\" required>\n"
             "            </div>\n"
             "            <div class=\"form-group\">\n"
             "              <label>Exam Duration (Minutes)</label>\n"
             "              <input type=\"number\" id=\"exam_duration\" value=\"%d\" required min=\"10\" max=\"600\">\n"
             "            </div>\n"
             "            <button type=\"submit\" class=\"btn-primary\" id=\"save-btn\">Save & Update Kiosk Target</button>\n"
             "          </form>\n"
             "        </div>\n"
             "        <div class=\"card\">\n"
             "          <div class=\"card-title\">Kiosk Session Controls</div>\n"
             "          <p style=\"font-size: 13px; color: #94a3b8; margin-bottom: 16px;\">Restart the kiosk runtime supervisor or isolate the appliance.</p>\n"
             "          <div style=\"display: flex; gap: 12px;\">\n"
             "            <button onclick=\"reloadKiosk()\" class=\"btn-primary\" style=\"background: #475569;\">Restart Kiosk Browser</button>\n"
             "            <button onclick=\"lockAppliance()\" class=\"btn-danger\">Emergency Lock Device</button>\n"
             "          </div>\n"
             "        </div>\n"
             "      </div>\n"
             "      <div>\n"
             "        <div class=\"card\">\n"
             "          <div class=\"card-title\">System Telemetry</div>\n"
             "          <div class=\"metric-row\"><span class=\"metric-name\">OS Version</span><span class=\"metric-val\">ExamOS v0.2.0 (Debian 13)</span></div>\n"
             "          <div class=\"metric-row\"><span class=\"metric-name\">Security Profile</span><span class=\"metric-val\">AppArmor + nftables</span></div>\n"
             "          <div class=\"metric-row\"><span class=\"metric-name\">Kernel Hardening</span><span class=\"metric-val\">Lockdown (Integrity)</span></div>\n"
             "          <div class=\"metric-row\"><span class=\"metric-name\">USB Port Lockdown</span><span class=\"metric-val\">HID Only (Class 08 Blocked)</span></div>\n"
             "          <div class=\"metric-row\"><span class=\"metric-name\">Kiosk Engine</span><span class=\"metric-val\">Cage / Wayland + Chromium</span></div>\n"
             "        </div>\n"
             "      </div>\n"
             "    </div>\n"
             "  </div>\n"
             "  <script>\n"
             "    document.getElementById('cfg-form').addEventListener('submit', async function(e) {\n"
             "      e.preventDefault();\n"
             "      const auth = sessionStorage.getItem('examos_admin_auth');\n"
             "      const url = document.getElementById('exam_url').value.trim();\n"
             "      const name = document.getElementById('exam_name').value.trim();\n"
             "      const dur = parseInt(document.getElementById('exam_duration').value, 10);\n"
             "      const alert = document.getElementById('alert');\n"
             "      try {\n"
             "        const res = await fetch('/api/v1/admin/config', {\n"
             "          method: 'POST',\n"
             "          headers: { 'Content-Type': 'application/json', 'Authorization': 'Basic ' + auth },\n"
             "          body: JSON.stringify({ exam_url: url, exam_name: name, exam_duration_minutes: dur })\n"
             "        });\n"
             "        const data = await res.json();\n"
             "        if (res.ok) {\n"
             "          alert.style.display = 'block'; alert.style.background = '#065f46'; alert.innerText = 'Configuration saved. URL configured successfully.';\n"
             "        } else {\n"
             "          alert.style.display = 'block'; alert.style.background = '#991b1b'; alert.innerText = data.error || 'Failed to save configuration.';\n"
             "        }\n"
             "      } catch (err) {\n"
             "        alert.style.display = 'block'; alert.style.background = '#991b1b'; alert.innerText = 'Network error saving configuration.';\n"
             "      }\n"
             "    });\n"
             "    async function reloadKiosk() {\n"
             "      const auth = sessionStorage.getItem('examos_admin_auth');\n"
             "      await fetch('/api/v1/admin/reload', { method: 'POST', headers: { 'Authorization': 'Basic ' + auth } });\n"
             "      alert('Kiosk restart command issued.');\n"
             "    }\n"
             "    async function lockAppliance() {\n"
             "      if (confirm('Are you sure you want to lock this ExamOS device into rescue target?')) {\n"
             "        const auth = sessionStorage.getItem('examos_admin_auth');\n"
             "        await fetch('/api/v1/admin/lock', { method: 'POST', headers: { 'Authorization': 'Basic ' + auth } });\n"
             "      }\n"
             "    }\n"
             "  </script>\n"
             "</body>\n"
             "</html>\n",
             url_val, name_val, dur_val);

    return buf;
}
