#define _GNU_SOURCE
#include "../include/admin_dashboard.h"
#include "../include/config_manager.h"
#include "../include/admin_auth_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

static int base64_decode(const char *input, char *output, size_t max_out) {
    if (!input || !output || max_out < 2) return -1;
    size_t in_len = strlen(input);
    if (in_len == 0 || in_len % 4 != 0 || in_len > 340) return -1;
    size_t padding = 0;
    if (input[in_len - 1] == '=') ++padding;
    if (in_len > 1 && input[in_len - 2] == '=') ++padding;
    for (size_t i = 0; i < in_len; ++i) {
        char c = input[i];
        int alphabet = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                       (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (alphabet) {
            if (i >= in_len - padding) return -1;
        } else if (c != '=' || i < in_len - padding) {
            return -1;
        }
    }
    int decoded = EVP_DecodeBlock((unsigned char *)output,
                                  (const unsigned char *)input, (int)in_len);
    if (decoded < 0 || (size_t)decoded < padding) return -1;
    size_t output_length = (size_t)decoded - padding;
    if (output_length == 0 || output_length >= max_out ||
        memchr(output, '\0', output_length) != NULL) return -1;
    for (size_t i = 0; i < output_length; ++i) {
        unsigned char c = (unsigned char)output[i];
        if (c < 0x20 || c == 0x7f) return -1;
    }
    char canonical[344] = {0};
    int canonical_length = EVP_EncodeBlock((unsigned char *)canonical,
                                            (const unsigned char *)output,
                                            (int)output_length);
    int canonical_valid = canonical_length >= 0 &&
        (size_t)canonical_length == in_len &&
        CRYPTO_memcmp(canonical, input, in_len) == 0;
    OPENSSL_cleanse(canonical, sizeof(canonical));
    if (!canonical_valid) return -1;
    output[output_length] = '\0';
    return (int)output_length;
}

static int html_escape(const char *input, char *output, size_t capacity) {
    size_t used = 0;
    if (!input || !output || capacity == 0) return -1;
    for (const unsigned char *p = (const unsigned char *)input; *p; ++p) {
        const char *replacement = NULL;
        switch (*p) {
            case '&': replacement = "&amp;"; break;
            case '<': replacement = "&lt;"; break;
            case '>': replacement = "&gt;"; break;
            case '\"': replacement = "&quot;"; break;
            case '\'': replacement = "&#39;"; break;
            default: break;
        }
        size_t n = replacement ? strlen(replacement) : 1;
        if (used + n >= capacity || *p < 0x20 || *p == 0x7f) return -1;
        if (replacement) {
            memcpy(output + used, replacement, n);
            used += n;
        } else output[used++] = (char)*p;
    }
    output[used] = '\0';
    return 0;
}

int admin_check_auth(const char *auth_header) {

    if (!auth_header) return 0;
    const char *dev_mode = getenv("EXAMOS_ALLOW_UNPROVISIONED_DEV");
    if (dev_mode && strcmp(dev_mode, "1") == 0) {
        if (strlen(auth_header) < 6 || strncmp(auth_header, "Basic ", 6) != 0) return 0;

        const char *b64 = auth_header + 6;
        while (*b64 == ' ') b64++;

        char decoded[256] = {0};
        if (base64_decode(b64, decoded, sizeof(decoded)) <= 0) {
            OPENSSL_cleanse(decoded, sizeof(decoded));
            return 0;
        }

        char *colon = strchr(decoded, ':');
        if (!colon) {
            OPENSSL_cleanse(decoded, sizeof(decoded));
            return 0;
        }

        *colon = '\0';
        int valid = config_verify_admin_credentials(decoded, colon + 1);
        OPENSSL_cleanse(decoded, sizeof(decoded));
        return valid;
    }

    static const char prefix[] = "Bearer ";
    if (strncmp(auth_header, prefix, sizeof(prefix) - 1) != 0) return 0;
    auth_session_t session;
    int valid = admin_auth_store_verify(auth_header + sizeof(prefix) - 1, &session) == 0;
    OPENSSL_cleanse(&session, sizeof(session));
    return valid;
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
           "        <input type=\"text\" id=\"u\" required autocomplete=\"username\">\n"
           "      </div>\n"
           "      <div class=\"form-group\">\n"
           "        <label>Admin Password</label>\n"
           "        <input type=\"password\" id=\"p\" required autocomplete=\"off\" placeholder=\"••••••••••••\">\n"
           "      </div>\n"
           "      <div class=\"form-group\">\n"
           "        <label>MFA Code (if enrolled)</label>\n"
           "        <input type=\"text\" id=\"mfa\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9]{6}\" maxlength=\"6\">\n"
           "      </div>\n"
           "      <button type=\"submit\" class=\"btn\">Authenticate</button>\n"
           "    </form>\n"
           "    <div class=\"warn\">Authorized Personnel Only.<br>All configuration modifications are cryptographically signed to the tamper-evident ledger.</div>\n"
           "  </div>\n"
           "  <script>\n"
           "    function auth() {\n"
           "      const u = document.getElementById('u').value;\n"
           "      const p = document.getElementById('p').value;\n"
           "      const mfa = document.getElementById('mfa').value;\n"
           "      fetch('/api/v1/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },\n"
           "        credentials: 'same-origin',\n"
           "        body: JSON.stringify({ username: u, password: p, mfa_code: mfa })\n"
           "      }).then(async r => { const data = await r.json(); if (r.ok && data.token) {\n"
           "          sessionStorage.setItem('examos_admin_auth', data.token); window.location.replace('/admin');\n"
           "        } else if (data.status === 'MFA_REQUIRED') { alert('Enter your MFA code and sign in again.'); document.getElementById('mfa').focus();\n"
           "        } else { alert('Invalid administrator credentials.'); }\n"
           "      }).catch(() => alert('Network error connecting to ExamOS server.'));\n"
           "    }\n"
           "  </script>\n"
           "</body>\n"
           "</html>\n";
}

const char *admin_dashboard_html(const char *current_url, const char *current_name,
                                const char *current_origins, int duration_minutes) {
    static _Thread_local char buf[65536];
    char escaped_url[4096], escaped_name[1024];
    char escaped_origins[EXAM_ALLOWED_ORIGINS_MAX * 2];
    const char *url_val = (current_url && strlen(current_url) > 0) ? current_url : "";
    const char *name_val = (current_name && strlen(current_name) > 0) ? current_name : "";
    int dur_val = (duration_minutes > 0) ? duration_minutes : 0;
    if (html_escape(url_val, escaped_url, sizeof(escaped_url)) != 0 ||
        html_escape(name_val, escaped_name, sizeof(escaped_name)) != 0 ||
        html_escape(current_origins ? current_origins : "", escaped_origins,
                    sizeof(escaped_origins)) != 0) return "";

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
             "    .nav-item { width: 100%%; border: 0; background: transparent; text-align: left; cursor: pointer; font: inherit; }\n"
             "    .page { display: none; } .page.active { display: block; }\n"
             "    .wide { grid-column: 1 / -1; }\n"
             "    .data-wrap { overflow: auto; max-height: 65vh; }\n"
             "    table { border-collapse: collapse; width: 100%%; font-size: 12px; }\n"
             "    th, td { border-bottom: 1px solid #263449; padding: 9px 10px; text-align: left; vertical-align: top; }\n"
             "    th { color: #7dd3fc; position: sticky; top: 0; background: #131c2e; }\n"
             "    td { color: #cbd5e1; max-width: 280px; overflow-wrap: anywhere; }\n"
             "    .muted { color: #94a3b8; font-size: 13px; line-height: 1.5; }\n"
             "    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }\n"
             "    .form-grid input, .form-grid select { width: 100%%; padding: 10px; background: #090d16; border: 1px solid #334155; border-radius: 6px; color: #fff; }\n"
             "    .inline-actions { display: flex; flex-wrap: wrap; gap: 6px; }\n"
             "    .btn-small { border: 1px solid #475569; background: #1e293b; color: #e2e8f0; border-radius: 5px; padding: 6px 9px; cursor: pointer; }\n"
             "    .btn-small:hover { border-color: #38bdf8; }\n"
             "    .metric-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }\n"
             "    pre { white-space: pre-wrap; overflow-wrap: anywhere; color: #cbd5e1; font-size: 12px; }\n"
             "    @media (max-width: 760px) { body { display: block; } .sidebar { width: 100%%; } .main { padding: 20px 14px; } .grid { grid-template-columns: 1fr; } }\n"
             "  </style>\n"
             "</head>\n"
             "<body>\n"
             "  <div class=\"sidebar\">\n"
             "    <div class=\"logo\">🛡️ ExamOS Control</div>\n"
             "    <button class=\"nav-item active\" data-view=\"overview\">Overview</button>\n"
             "    <button class=\"nav-item\" data-view=\"config\">Exam configuration</button>\n"
             "    <button class=\"nav-item\" data-view=\"institutions\">Institutions</button>\n"
             "    <button class=\"nav-item\" data-view=\"locations\">Campuses and rooms</button>\n"
             "    <button class=\"nav-item\" data-view=\"exams\">Exams</button>\n"
             "    <button class=\"nav-item\" data-view=\"roster\">Candidate roster</button>\n"
             "    <button class=\"nav-item\" data-view=\"users\">Admin users</button>\n"
             "    <button class=\"nav-item\" data-view=\"roles\">Roles and permissions</button>\n"
             "    <button class=\"nav-item\" data-view=\"fleet\">Device fleet</button>\n"
             "    <button class=\"nav-item\" data-view=\"operations\">Live operations</button>\n"
             "    <button class=\"nav-item\" data-view=\"groups\">Device groups</button>\n"
             "    <button class=\"nav-item\" data-view=\"incidents\">Incidents</button>\n"
             "    <button class=\"nav-item\" data-view=\"policies\">Policies</button>\n"
             "    <button class=\"nav-item\" data-view=\"evidence\">Exam evidence</button>\n"
             "    <button class=\"nav-item\" data-view=\"releases\">Releases</button>\n"
             "    <button class=\"nav-item\" data-view=\"security\">Security controls</button>\n"
             "    <button class=\"nav-item\" data-view=\"reports\">Reports and audit</button>\n"
             "    <button class=\"nav-item\" data-view=\"recovery\">Backup and recovery</button>\n"
             "    <button class=\"nav-item\" data-view=\"settings\">Institution settings</button>\n"
             "    <a href=\"/api/v1/ledger\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"nav-item\">Tamper-Evident Ledger</a>\n"
             "    <a href=\"/\" class=\"nav-item\">Candidate Portal</a>\n"
             "    <div style=\"margin-top: auto;\">\n"
             "      <button onclick=\"adminLogout()\" class=\"btn-danger\" style=\"width:100%%;\">Log Out</button>\n"
             "    </div>\n"
             "  </div>\n"
             "  <div class=\"main\">\n"
             "    <div class=\"topbar\">\n"
             "      <h1 id=\"page-title\">Operations overview</h1>\n"
             "      <span id=\"admin-profile\" class=\"muted\">Loading signed-in role…</span>\n"
             "      <span class=\"status-pill\" id=\"service-state\">Checking service</span>\n"
             "    </div>\n"
             "    <div id=\"alert\" class=\"alert-box\"></div>\n"
             "    <section class=\"page active\" id=\"page-overview\">\n"
             "      <div class=\"metric-cards\">\n"
             "        <div class=\"card\"><div class=\"card-title\">Service health</div><div id=\"overview-health\" class=\"muted\">Loading live health…</div></div>\n"
             "        <div class=\"card\"><div class=\"card-title\">Platform telemetry</div><div id=\"overview-telemetry\" class=\"muted\">Loading database-backed telemetry…</div></div>\n"
             "        <div class=\"card\"><div class=\"card-title\">Fleet compliance</div><div id=\"overview-compliance\" class=\"muted\">Loading device compliance…</div></div>\n"
             "      </div>\n"
             "      <div class=\"card\"><div class=\"card-title\">Administration</div><p class=\"muted\">Dashboard data and actions are loaded from the authenticated server APIs. Your role and institution scope are enforced by the server. Access denied or unavailable services are shown as returned.</p></div>\n"
             "    </section>\n"
             "    <section class=\"page\" id=\"page-locations\">\n"
             "      <div class=\"card\"><div class=\"card-title\">Campuses</div><p class=\"muted\">Stored in PostgreSQL. Campus records currently belong directly to an institution; buildings are not a separate implemented resource.</p><form class=\"api-form form-grid\" data-endpoint=\"/api/v1/admin/campuses\"><input name=\"institution_id\" required maxlength=\"63\" placeholder=\"Institution ID\"><input name=\"name\" required maxlength=\"127\" placeholder=\"Campus name\"><input name=\"address\" maxlength=\"255\" placeholder=\"Address\"><button class=\"btn-primary\" type=\"submit\">Create campus</button></form><div id=\"campuses-table\" class=\"data-wrap\"></div></div>\n"
             "      <div class=\"card\"><div class=\"card-title\">Rooms and labs</div><p class=\"muted\">Rooms are stored in PostgreSQL. Lab classification is not currently modeled, so labs are unavailable as a distinct type.</p><form class=\"api-form form-grid\" data-endpoint=\"/api/v1/admin/rooms\"><input name=\"institution_id\" required maxlength=\"63\" placeholder=\"Institution ID\"><input name=\"campus_id\" required maxlength=\"63\" placeholder=\"Campus ID\"><input name=\"name\" required maxlength=\"63\" placeholder=\"Room name\"><input name=\"capacity\" type=\"number\" min=\"1\" required placeholder=\"Capacity\"><input name=\"supervisor\" maxlength=\"63\" placeholder=\"Supervisor ID\"><button class=\"btn-primary\" type=\"submit\">Create room</button></form><form id=\"rooms-query-form\" class=\"form-grid\"><input id=\"rooms-campus-id\" required maxlength=\"63\" placeholder=\"Campus ID to list\"><button class=\"btn-primary\" type=\"submit\">Load rooms</button></form><div id=\"rooms-table\" class=\"data-wrap\"></div></div>\n"
             "    </section>\n"
             "    <section class=\"page\" id=\"page-config\"><div class=\"grid\">\n"
             "      <div>\n"
             "        <div class=\"card\">\n"
             "          <div class=\"card-title\">Target Examination Settings</div>\n"
             "          <form id=\"cfg-form\">\n"
             "            <div class=\"form-group\">\n"
             "              <label>Target Examination URL (HTTPS required)</label>\n"
             "              <input type=\"text\" id=\"exam_url\" value=\"%s\" required placeholder=\"https://exam.university.edu/session/start\">\n"
             "            </div>\n"
             "            <div class=\"form-group\">\n"
             "              <label>Additional approved origins (comma-separated exact HTTPS origins)</label>\n"
             "              <input type=\"text\" id=\"allowed_origins\" value=\"%s\" placeholder=\"https://identity.university.edu,https://media.university.edu\">\n"
             "              <small>Only exact origins are permitted. Leave empty unless the exam requires another origin.</small>\n"
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
             "            <button onclick=\"adminLogout()\" class=\"btn-primary\">Sign Out</button>\n"
             "          </div>\n"
             "        </div>\n"
             "      </div>\n"
             "      <div>\n"
             "        <div class=\"card\">\n"
             "          <div class=\"card-title\">Hardware and Runtime Status</div>\n"
             "          <p role=\"status\">Live platform telemetry is unavailable. Device posture and active security controls have not been verified by this server.</p>\n"
             "        </div>\n"
             "      </div>\n"
             "    </div>\n"
             "    </section>\n"
             "    <section class=\"page\" id=\"page-roster\"><div class=\"card\"><div class=\"card-title\">Candidate eligibility roster</div><p class=\"muted\">Roster records are stored in PostgreSQL and scoped to the exam institution. Candidate PINs are hashed by the server and never returned.</p><form id=\"roster-query-form\" class=\"form-grid\"><input id=\"roster-exam-id\" required maxlength=\"63\" placeholder=\"Exam ID\"><button class=\"btn-primary\" type=\"submit\">Load roster</button></form><div id=\"roster-table\" class=\"data-wrap\"></div></div><div class=\"card\"><div class=\"card-title\">Add candidate to roster</div><form id=\"roster-add-form\" class=\"form-grid\"><input id=\"roster-add-exam-id\" required maxlength=\"63\" placeholder=\"Exam ID\"><input id=\"roster-add-candidate-id\" required maxlength=\"63\" placeholder=\"Candidate ID\"><input id=\"roster-add-full-name\" required maxlength=\"127\" placeholder=\"Full name\"><input id=\"roster-add-email\" type=\"email\" required maxlength=\"127\" placeholder=\"Email\"><input id=\"roster-add-pin\" type=\"password\" autocomplete=\"new-password\" minlength=\"6\" required placeholder=\"Candidate PIN\"><input id=\"roster-add-seat\" maxlength=\"31\" placeholder=\"Assigned seat\"><input id=\"roster-add-device\" maxlength=\"63\" placeholder=\"Assigned device ID\"><button class=\"btn-primary\" type=\"submit\">Add candidate</button></form></div><div class=\"card\"><div class=\"card-title\">Check a candidate in</div><form id=\"roster-checkin-form\" class=\"form-grid\"><input id=\"checkin-exam-id\" required maxlength=\"63\" placeholder=\"Exam ID\"><input id=\"checkin-candidate-id\" required maxlength=\"63\" placeholder=\"Candidate ID\"><input id=\"checkin-device-id\" required maxlength=\"63\" placeholder=\"Device ID\"><button class=\"btn-primary\" type=\"submit\">Check in</button></form></div></section>\n"
             "    <section class=\"page\" id=\"page-institutions\">\n"
             "      <div class=\"card\"><div class=\"card-title\">Create institution</div><form class=\"api-form form-grid\" data-endpoint=\"/api/v1/admin/institutions\"><input name=\"name\" required maxlength=\"127\" placeholder=\"Institution name\"><input name=\"code\" required maxlength=\"31\" placeholder=\"Unique institution code\"><input name=\"contact_email\" type=\"email\" maxlength=\"127\" placeholder=\"Contact email\"><input name=\"retention_days\" type=\"number\" min=\"1\" max=\"36500\" required placeholder=\"Retention days\"><button class=\"btn-primary\" type=\"submit\">Create institution</button></form></div>\n"
             "      <div class=\"card\"><div class=\"card-title\">Institutions</div><div id=\"institutions-table\" class=\"data-wrap\"></div></div>\n"
             "    </section>\n"
             "    <section class=\"page\" id=\"page-roles\"><div class=\"card\"><div class=\"card-title\">RBAC permission matrix</div><p class=\"muted\">This matrix is computed from the server authorization rules at request time. Editing custom roles and granular per-institution permission overrides are unavailable.</p><div id=\"roles-table\" class=\"data-wrap\"></div></div></section>\n"
             "    <section class=\"page\" id=\"page-exams\">\n      <div class=\"card\"><div class=\"card-title\">Create exam draft</div><form class=\"api-form form-grid\" data-endpoint=\"/api/v1/platform/exams/create\"><input name=\"title\" required maxlength=\"127\" placeholder=\"Exam title\"><input name=\"institution_id\" required maxlength=\"63\" placeholder=\"Institution ID (scoped admins are auto-scoped)\"><input name=\"exam_url\" type=\"url\" required placeholder=\"https://exam.example.edu/path\"><input name=\"allowed_origins\" placeholder=\"Approved HTTPS origins\"><input name=\"timezone\" required placeholder=\"IANA timezone, e.g. Asia/Kolkata\"><input name=\"permitted_device_group\" required maxlength=\"63\" placeholder=\"Permitted device group\"><select name=\"browser_policy\" id=\"exam-browser-policy\" required><option value=\"\">Select browser policy</option></select><input name=\"retention_days\" type=\"number\" min=\"1\" max=\"36500\" required placeholder=\"Retention days\"><input name=\"duration_minutes\" type=\"number\" min=\"1\" required placeholder=\"Duration minutes\"><input name=\"scheduled_start\" id=\"exam-scheduled-start\" type=\"datetime-local\" required><input name=\"scheduled_end\" id=\"exam-scheduled-end\" type=\"datetime-local\" required><button class=\"btn-primary\" type=\"submit\">Create draft</button></form><p class=\"muted\">The browser policy must name a template from the provisioned policy catalog. The platform never supplies a default policy, device group, retention window or schedule.</p></div>\n      <div class=\"card\"><div class=\"card-title\">Schedule approved exam</div><form id=\"exam-schedule-form\" class=\"form-grid\"><input id=\"schedule-exam-id\" required maxlength=\"127\" placeholder=\"Exam ID\"><input id=\"schedule-start\" type=\"datetime-local\" required><input id=\"schedule-end\" type=\"datetime-local\" required><input id=\"schedule-zone\" required placeholder=\"IANA timezone\"><button class=\"btn-primary\" type=\"submit\">Schedule exam</button></form><p class=\"muted\">Local start/end times are converted to Unix timestamps by the browser; enter the timezone used for the exam.</p></div>\n      <div class=\"card\"><div class=\"card-title\">Exams</div><div id=\"exams-table\" class=\"data-wrap\"></div></div>\n    </section>\n"
             "      <div class=\"card\"><div class=\"card-title\">Create exam draft</div><form class=\"api-form form-grid\" data-endpoint=\"/api/v1/platform/exams/create\"><input name=\"title\" required maxlength=\"127\" placeholder=\"Exam title\"><input name=\"institution_id\" required maxlength=\"63\" placeholder=\"Institution ID (scoped admins are auto-scoped)\"><input name=\"exam_url\" type=\"url\" required placeholder=\"https://exam.example.edu/path\"><input name=\"allowed_origins\" placeholder=\"Approved HTTPS origins\"><input name=\"timezone\" required placeholder=\"IANA timezone, e.g. Asia/Kolkata\"><input name=\"duration_minutes\" type=\"number\" min=\"1\" required placeholder=\"Duration minutes\"><button class=\"btn-primary\" type=\"submit\">Create draft</button></form></div>\n"
             "      <div class=\"card\"><div class=\"card-title\">Schedule approved exam</div><form id=\"exam-schedule-form\" class=\"form-grid\"><input id=\"schedule-exam-id\" required maxlength=\"127\" placeholder=\"Exam ID\"><input id=\"schedule-start\" type=\"datetime-local\" required><input id=\"schedule-end\" type=\"datetime-local\" required><input id=\"schedule-zone\" required placeholder=\"IANA timezone\"><button class=\"btn-primary\" type=\"submit\">Schedule exam</button></form><p class=\"muted\">Local start/end times are converted to Unix timestamps by the browser; enter the timezone used for the exam.</p></div>\n"
             "      <div class=\"card\"><div class=\"card-title\">Exams</div><div id=\"exams-table\" class=\"data-wrap\"></div></div>\n"
             "    </section>\n"
             "    <section class=\"page\" id=\"page-users\">\n"
             "      <div class=\"card\"><div class=\"card-title\">Create administrator</div><form class=\"api-form form-grid\" data-endpoint=\"/api/v1/admin/users\"><input name=\"username\" required maxlength=\"63\" placeholder=\"Username\"><input name=\"full_name\" maxlength=\"127\" placeholder=\"Full name\"><input name=\"email\" type=\"email\" maxlength=\"127\" placeholder=\"Email\"><input name=\"password\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\" required placeholder=\"Initial password (12+ characters)\"><select name=\"role\" required><option value=\"\">Select role</option><option value=\"2\">Institution administrator</option><option value=\"3\">Exam manager</option><option value=\"4\">Security administrator</option><option value=\"5\">Invigilator</option><option value=\"6\">Technical operator</option><option value=\"7\">Incident investigator</option><option value=\"8\">Read-only auditor</option><option value=\"9\">Support engineer</option></select><input name=\"institution_id\" maxlength=\"63\" placeholder=\"Institution ID if required by role\"><button class=\"btn-primary\" type=\"submit\">Create account</button></form><p class=\"muted\">Passwords are sent only to the authenticated server, which hashes them before database storage. The platform-owner role cannot be delegated from this form.</p></div>\n"
             "      <div class=\"card\"><div class=\"card-title\">Administrator accounts</div><div id=\"users-table\" class=\"data-wrap\"></div></div>\n"
             "    </section>\n"
             "    <section class=\"page\" id=\"page-fleet\"><div class=\"grid\"><div class=\"card wide\"><div class=\"card-title\">Fleet compliance</div><div id=\"fleet-compliance\" class=\"data-wrap\"></div></div><div class=\"card wide\"><div class=\"card-title\">Registered devices</div><div id=\"fleet-table\" class=\"data-wrap\"></div></div></div></section>\n"
             "    <section class=\"page\" id=\"page-operations\"><div class=\"card\"><div class=\"card-title\">Live exam operations</div><p class=\"muted\">Examination state distribution and candidate progress, read from the durable store.</p><div id=\"operations-table\" class=\"data-wrap\"></div></div><div class=\"card\"><div class=\"card-title\">Examination readiness</div><form id=\"readiness-form\" class=\"form-grid\"><input id=\"readiness-exam-id\" required maxlength=\"127\" placeholder=\"Exam ID\"><input id=\"readiness-device-id\" required maxlength=\"63\" placeholder=\"Device ID\"><button class=\"btn-primary\" type=\"submit\">Check readiness</button></form><div id=\"readiness-result\" class=\"muted\" role=\"status\"></div><p class=\"muted\">Each control is reported as OK, FAILED or UNKNOWN. UNKNOWN means the platform holds no evidence either way; it is never reported as a pass.</p></div></section>\n"
             "    <section class=\"page\" id=\"page-groups\"><div class=\"card\"><div class=\"card-title\">Device groups and deployment rings</div><div id=\"groups-table\" class=\"data-wrap\"></div></div><div class=\"card\"><div class=\"card-title\">Bulk device action</div><form id=\"fleet-bulk-form\" class=\"form-grid\"><input id=\"bulk-action-type\" required placeholder=\"Action type, e.g. QUARANTINE\"><input id=\"bulk-target-group\" maxlength=\"63\" placeholder=\"Target device group\"><input id=\"bulk-institution-id\" maxlength=\"63\" placeholder=\"Target institution ID\"><input id=\"bulk-parameter\" maxlength=\"255\" placeholder=\"Action parameter\"><button class=\"btn-primary\" type=\"submit\">Apply action</button></form><p class=\"muted\">Bulk actions change live fleet state.</p></div><div class=\"card\"><div class=\"card-title\">Assign a device to an examination</div><form id=\"fleet-assign-form\" class=\"form-grid\"><input id=\"assign-device-id\" required maxlength=\"63\" placeholder=\"Device ID\"><input id=\"assign-exam-id\" required maxlength=\"127\" placeholder=\"Exam ID\"><button class=\"btn-primary\" type=\"submit\">Assign device</button></form></div></section>\n"
             "    <section class=\"page\" id=\"page-incidents\"><div class=\"card\"><div class=\"card-title\">Security incidents</div><p class=\"muted\">Incident records and status history are stored in PostgreSQL and are institution scoped. A security signal is not a finding of misconduct.</p><form id=\"incident-create-form\" class=\"form-grid\"><input id=\"incident-title\" required maxlength=\"127\" placeholder=\"Incident title\"><select id=\"incident-severity\" required><option value=\"INFO\">INFO</option><option value=\"LOW\">LOW</option><option value=\"MEDIUM\">MEDIUM</option><option value=\"HIGH\">HIGH</option><option value=\"CRITICAL\">CRITICAL</option></select><input id=\"incident-institution-id\" maxlength=\"63\" placeholder=\"Institution ID\"><input id=\"incident-device-id\" maxlength=\"63\" placeholder=\"Device ID\"><input id=\"incident-exam-id\" maxlength=\"63\" placeholder=\"Exam ID\"><input id=\"incident-summary\" required maxlength=\"511\" placeholder=\"Summary\"><button class=\"btn-primary\" type=\"submit\">Raise incident</button></form><div id=\"incidents-table\" class=\"data-wrap\"></div></div></section>\n"
             "    <section class=\"page\" id=\"page-policies\"><div class=\"card\"><div class=\"card-title\">Exam policy records</div><div id=\"policies-table\" class=\"data-wrap\"></div></div><div class=\"card\"><div class=\"card-title\">Browser policy catalog</div><p class=\"muted\">These are the only browser policies this deployment ships. An examination must reference one of them by name.</p><div id=\"policy-catalog-table\" class=\"data-wrap\"></div></div><div class=\"card\"><div class=\"card-title\">Distribute the signed policy to a device</div><form id=\"policy-distribute-form\" class=\"form-grid\"><input id=\"distribute-exam-id\" required maxlength=\"127\" placeholder=\"Exam ID\"><input id=\"distribute-device-id\" required maxlength=\"63\" placeholder=\"Device ID\"><button class=\"btn-primary\" type=\"submit\">Distribute policy</button></form><div id=\"policy-distribute-result\" class=\"muted\" role=\"status\"></div></div></section>\n"
             "    <section class=\"page\" id=\"page-evidence\"><div class=\"card\"><div class=\"card-title\">Submissions and reconciliation</div><form id=\"evidence-form\" class=\"form-grid\"><input id=\"evidence-exam-id\" required maxlength=\"127\" placeholder=\"Exam ID\"><button class=\"btn-primary\" type=\"submit\">Load exam evidence</button></form></div><div class=\"grid\"><div class=\"card\"><div class=\"card-title\">Submissions</div><div id=\"submissions-table\" class=\"data-wrap\"></div></div><div class=\"card\"><div class=\"card-title\">Reconciliation</div><div id=\"reconciliation-table\" class=\"data-wrap\"></div></div></div></section>\n"
             "    <section class=\"page\" id=\"page-releases\"><div class=\"card\"><div class=\"card-title\">Software release records</div><p class=\"muted\">Release metadata and artefact digests are stored in PostgreSQL.</p><form id=\"release-create-form\" class=\"form-grid\"><input id=\"release-id\" required maxlength=\"63\" placeholder=\"Release ID\"><input id=\"release-version\" required maxlength=\"63\" placeholder=\"Version name\"><input id=\"release-image-digest\" required maxlength=\"64\" placeholder=\"Image digest (64 hex characters)\"><input id=\"release-uki-digest\" required maxlength=\"64\" placeholder=\"UKI digest (64 hex characters)\"><input id=\"release-sbom-digest\" required maxlength=\"64\" placeholder=\"SBOM digest (64 hex characters)\"><select id=\"release-ring\" required><option value=\"CANARY\">CANARY</option><option value=\"PILOT\">PILOT</option><option value=\"GENERAL\">GENERAL</option></select><button class=\"btn-primary\" type=\"submit\">Create release</button></form><div id=\"releases-table\" class=\"data-wrap\"></div></div></section>\n"
             "    <section class=\"page\" id=\"page-security\"><div class=\"card\"><div class=\"card-title\">Security actions</div><div class=\"form-grid\"><form class=\"api-form\" data-endpoint=\"/api/v1/admin/revoke/release\"><input name=\"release_id\" required placeholder=\"Release ID to revoke\"><button class=\"btn-danger\" type=\"submit\">Revoke release</button></form><form class=\"api-form\" data-endpoint=\"/api/v1/admin/revoke/device\"><input name=\"device_id\" required placeholder=\"Device ID to revoke\"><button class=\"btn-danger\" type=\"submit\">Revoke device</button></form></div><p class=\"muted\">Revocation is persistent and security-sensitive. Confirm the identifier before submitting. Appliance isolation and dashboard-based MFA enrollment are not integrated.</p><form id=\"attestation-form\" class=\"form-grid\"><input id=\"attestation-id\" required maxlength=\"63\" placeholder=\"Attestation or session ID\"><button class=\"btn-primary\" type=\"submit\">Check attestation state</button></form><div id=\"attestation-status\" class=\"muted\" role=\"status\"></div><button id=\"restart-kiosk\" class=\"btn-primary\" type=\"button\">Restart kiosk browser</button><div id=\"security-result\" class=\"muted\" role=\"status\"></div></div></section>\n"
             "    <section class=\"page\" id=\"page-reports\"><div class=\"card\"><div class=\"card-title\">Administrative audit trail</div><form id=\"audit-query-form\" class=\"form-grid\"><input id=\"audit-exam-id\" maxlength=\"63\" placeholder=\"Filter by subject ID (optional)\"><button class=\"btn-primary\" type=\"submit\">Load audit trail</button></form><div id=\"audit-table\" class=\"data-wrap\"></div></div><div class=\"card\"><div class=\"card-title\">Reports and evidence export</div><p class=\"muted\">Examination submissions and reconciliation are available under Exam evidence. The tamper-evident ledger is served separately at /api/v1/ledger.</p></div></section>\n"
             "    <section class=\"page\" id=\"page-recovery\"><div class=\"card\"><div class=\"card-title\">Service health and evidence integrity</div><p class=\"muted\">Readiness reflects every dependency the service needs: the authenticated evidence ledger, the durable platform store, and the attestation store.</p><div id=\"recovery-table\" class=\"data-wrap\"></div></div></section>\n"
             "    <section class=\"page\" id=\"page-settings\"><div class=\"card\"><div class=\"card-title\">Institution settings and retention</div><form id=\"institution-settings-form\" class=\"form-grid\"><input id=\"settings-institution-id\" required maxlength=\"63\" placeholder=\"Institution ID\"><input id=\"settings-name\" required maxlength=\"127\" placeholder=\"Institution name\"><input id=\"settings-contact-email\" type=\"email\" maxlength=\"127\" placeholder=\"Contact email\"><input id=\"settings-retention-days\" type=\"number\" min=\"1\" max=\"36500\" required placeholder=\"Retention days\"><button class=\"btn-primary\" type=\"submit\">Save settings</button></form><div id=\"institutions-table\" class=\"data-wrap\"></div></div></section>\n"
             "  </div>\n"
             "  <script>\n"
             "    document.getElementById('cfg-form').addEventListener('submit', async function(e) {\n"
             "      e.preventDefault();\n"
             "      const auth = sessionStorage.getItem('examos_admin_auth');\n"
             "      const url = document.getElementById('exam_url').value.trim();\n"
             "      const name = document.getElementById('exam_name').value.trim();\n"
             "      const allowedOrigins = document.getElementById('allowed_origins').value.trim();\n"
             "      const dur = parseInt(document.getElementById('exam_duration').value, 10);\n"
             "      const alert = document.getElementById('alert');\n"
             "      try {\n"
             "        const res = await fetch('/api/v1/admin/config', {\n"
             "          method: 'POST',\n"
             "          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + auth },\n"
             "          body: JSON.stringify({ exam_url: url, exam_name: name, allowed_origins: allowedOrigins, exam_duration_minutes: dur })\n"
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
             "      const out = document.getElementById('security-result'); out.textContent = 'Requesting kiosk restart…';\n"
             "      try { const res = await fetch('/api/v1/admin/reload', { method: 'POST', headers: { 'Authorization': 'Bearer ' + auth } }); const data = await res.json(); out.textContent = res.ok ? 'Kiosk restart accepted by the server.' : (data.error || 'Kiosk restart failed.'); }\n"
             "      catch (_) { out.textContent = 'Could not contact the kiosk control service.'; }\n"
             "    }\n"
             "    async function adminLogout() {\n"
             "      const token = sessionStorage.getItem('examos_admin_auth');\n"
             "      try { await fetch('/api/v1/admin/logout', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token } }); }\n"
             "      finally { sessionStorage.removeItem('examos_admin_auth'); window.location.href = '/admin'; }\n"
             "    }\n"
             "    const viewTitles = { overview: 'Operations overview', config: 'Exam configuration', institutions: 'Institutions', locations: 'Campuses and rooms', exams: 'Exams', roster: 'Candidate roster', users: 'Admin users', roles: 'Roles and permissions', fleet: 'Device fleet', operations: 'Live exam operations', groups: 'Device groups', incidents: 'Incidents', policies: 'Policies', evidence: 'Exam evidence', releases: 'Trusted releases', security: 'Security controls', reports: 'Reports and audit', recovery: 'Backup and recovery', settings: 'Institution settings' };\n"
             "    function adminToken() { return sessionStorage.getItem('examos_admin_auth') || ''; }\n"
             "    async function apiRequest(path, options) {\n"
             "      const token = adminToken(); if (!token) throw new Error('Your dashboard session is missing. Sign in again.');\n"
             "      const headers = new Headers((options && options.headers) || {}); headers.set('Authorization', 'Bearer ' + token);\n"
             "      const response = await fetch(path, Object.assign({ credentials: 'same-origin' }, options || {}, { headers }));\n"
             "      let data = {}; try { data = await response.json(); } catch (_) {}\n"
             "      if (!response.ok) throw new Error(data.error || data.reason || ('Request failed with HTTP ' + response.status));\n"
             "      return data;\n"
             "    }\n"
             "    function showMessage(node, text, isError) { node.textContent = text; node.style.color = isError ? '#fca5a5' : '#86efac'; }\n"
             "    function renderTable(node, data, kind) {\n"
             "      node.replaceChildren(); node.style.color = '';\n"
             "      const pair = Object.entries(data || {}).find(entry => Array.isArray(entry[1]));\n"
             "      const rows = pair ? pair[1] : null;\n"
             "      if (!rows) { const pre = document.createElement('pre'); pre.textContent = JSON.stringify(data, null, 2); node.appendChild(pre); return; }\n"
             "      if (!rows.length) { const empty = document.createElement('p'); empty.className = 'muted'; empty.textContent = 'No records returned by the service.'; node.appendChild(empty); return; }\n"
             "      const columns = [...new Set(rows.filter(row => row && typeof row === 'object').flatMap(row => Object.keys(row)))].slice(0, 24);\n"
             "      if (!columns.length) { const pre = document.createElement('pre'); pre.textContent = JSON.stringify(rows, null, 2); node.appendChild(pre); return; }\n"
             "      const table = document.createElement('table'), head = table.createTHead().insertRow();\n"
             "      columns.forEach(key => { const th = document.createElement('th'); th.textContent = key.replaceAll('_', ' '); head.appendChild(th); });\n"
             "      if (kind) { const th = document.createElement('th'); th.textContent = 'Actions'; head.appendChild(th); }\n"
             "      const body = table.createTBody();\n"
             "      rows.slice(0, 500).forEach(row => { const tr = body.insertRow(); columns.forEach(key => { const td = tr.insertCell(); const value = row && row[key]; td.textContent = value === null || value === undefined ? '' : (typeof value === 'object' ? JSON.stringify(value) : String(value)); }); if (kind) addRowActions(tr.insertCell(), row, kind); });\n"
             "      node.appendChild(table);\n"
             "    }\n"
             "    function addRowActions(cell, row, kind) {\n"
             "      const actions = document.createElement('div'); actions.className = 'inline-actions'; cell.appendChild(actions);\n"
             "      const id = row.device_id || row.incident_id || row.exam_id || row.id || ''; if (!id) { actions.textContent = 'No action identifier'; return; }\n"
             "      const add = (label, endpoint, payload, confirmText) => { const button = document.createElement('button'); button.className = 'btn-small'; button.type = 'button'; button.textContent = label; button.addEventListener('click', async () => { if (!window.confirm(confirmText)) return; button.disabled = true; try { await apiRequest(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload || {}) }); await loadCurrentView(); } catch (error) { window.alert(error.message); button.disabled = false; } }); actions.appendChild(button); };\n"
             "      const safeId = encodeURIComponent(String(id));\n"
             "      if (kind === 'fleet') { add('Approve', '/api/v1/admin/fleet/' + safeId + '/approve', {}, 'Approve this device enrollment?'); add('Quarantine', '/api/v1/admin/fleet/' + safeId + '/quarantine', { reason: 'Admin dashboard action' }, 'Quarantine this device? This changes live fleet state.'); }\n"
             "      else if (kind === 'incident') { const status = document.createElement('select'); ['INVESTIGATING','CONTAINED','RESOLVED'].forEach(value => { const option = document.createElement('option'); option.value = value; option.textContent = value; status.appendChild(option); }); actions.appendChild(status); const button = document.createElement('button'); button.className = 'btn-small'; button.type = 'button'; button.textContent = 'Update status'; button.onclick = async () => { const notes = window.prompt('Investigation or resolution notes (do not enter credentials or secrets)', ''); if (notes === null || !window.confirm('Save status ' + status.value + ' with these notes?')) return; button.disabled = true; try { await apiRequest('/api/v1/admin/incidents/' + safeId + '/status', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: status.value, notes }) }); await loadCurrentView(); } catch (error) { window.alert(error.message); button.disabled = false; } }; actions.appendChild(button); }\n"
             "      else if (kind === 'exam') { add('Validate', '/api/v1/platform/exams/' + safeId + '/validate', {}, 'Validate this exam configuration?'); add('Approve', '/api/v1/platform/exams/' + safeId + '/approve', {}, 'Approve this exam? Ensure required review is complete.'); const update = document.createElement('button'); update.className = 'btn-small'; update.type = 'button'; update.textContent = 'Change URL'; update.onclick = async () => { const url = window.prompt('Enter the new HTTPS exam URL'); if (!url) return; const origins = window.prompt('Enter allowed HTTPS origins, if required', ''); try { await apiRequest('/api/v1/platform/exams/' + safeId + '/url', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ exam_url: url, allowed_origins: origins || '' }) }); await loadCurrentView(); } catch (error) { window.alert(error.message); } }; actions.appendChild(update); const rollback = document.createElement('button'); rollback.className = 'btn-small'; rollback.type = 'button'; rollback.textContent = 'Rollback policy'; rollback.onclick = async () => { const version = window.prompt('Target policy version number'); if (!version || !/^[1-9][0-9]*$/.test(version)) return; if (!window.confirm('Roll back this exam policy to version ' + version + '?')) return; try { await apiRequest('/api/v1/platform/exams/' + safeId + '/policy/rollback', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_version: Number(version) }) }); await loadCurrentView(); } catch (error) { window.alert(error.message); } }; actions.appendChild(rollback); }\n"
             "    }\n"
             "    async function loadTable(path, targetId, kind) { const node = document.getElementById(targetId); node.textContent = 'Loading…'; try { renderTable(node, await apiRequest(path), kind); } catch (error) { node.textContent = error.message; node.style.color = '#fca5a5'; } }\n"
             "    async function loadOverview() {\n"
             "      const profile = document.getElementById('admin-profile'); try { const user = await apiRequest('/api/v1/admin/session'); profile.textContent = user.username + ' · ' + user.role + (user.institution_id ? ' · ' + user.institution_id : ''); } catch (error) { profile.textContent = error.message; profile.style.color = '#fca5a5'; }\n"
             "      const healthNode = document.getElementById('overview-health');\n"
             "      try { const response = await fetch('/api/v1/health', { cache: 'no-store' }); const health = await response.json(); healthNode.textContent = 'HTTP ' + response.status + ' · ' + (health.readiness || health.status || 'status unknown'); document.getElementById('service-state').textContent = health.readiness === 'READY' ? 'Ready' : (health.status === 'ok' ? 'Live · readiness limited' : 'Unavailable'); document.getElementById('service-state').style.background = health.readiness === 'READY' ? '#059669' : '#b45309'; } catch (_) { healthNode.textContent = 'Health endpoint unavailable.'; document.getElementById('service-state').textContent = 'Unavailable'; document.getElementById('service-state').style.background = '#b91c1c'; }\n"
             "      for (const [path, id] of [['/api/v1/admin/telemetry','overview-telemetry'], ['/api/v1/admin/fleet/compliance','overview-compliance']]) { const node = document.getElementById(id); try { const data = await apiRequest(path); renderTable(node, data); } catch (error) { node.textContent = error.message; node.style.color = '#fca5a5'; } }\n"
             "    }\n"
             "    const loaders = { overview: loadOverview, config: async () => { await loadTable('/api/v1/admin/institutions','institutions-table'); await loadPolicyCatalog(); }, institutions: () => loadTable('/api/v1/admin/institutions','institutions-table'), locations: async () => { const input = document.querySelector('#page-locations form[data-endpoint=\\\"/api/v1/admin/campuses\\\"] input[name=\\\"institution_id\\\"]'); const id = input && input.value.trim(); await loadTable('/api/v1/admin/campuses' + (id ? '?institution_id=' + encodeURIComponent(id) : ''),'campuses-table'); }, exams: async () => { await loadTable('/api/v1/admin/exams','exams-table','exam'); await loadPolicyCatalog(); }, roster: async () => { const id = document.getElementById('roster-exam-id').value.trim(); if (id) await loadTable('/api/v1/admin/roster?exam_id=' + encodeURIComponent(id), 'roster-table'); }, users: () => loadTable('/api/v1/admin/users','users-table'), roles: () => loadTable('/api/v1/admin/roles','roles-table'), fleet: async () => { await loadTable('/api/v1/admin/fleet/compliance','fleet-compliance'); await loadTable('/api/v1/admin/fleet','fleet-table','fleet'); }, incidents: () => loadTable('/api/v1/admin/incidents','incidents-table','incident'), policies: async () => { await loadTable('/api/v1/admin/policies','policies-table'); await loadPolicyCatalog(); }, releases: () => loadTable('/api/v1/admin/releases','releases-table'), operations: () => loadTable('/api/v1/admin/operations','operations-table'), groups: () => loadTable('/api/v1/admin/fleet/groups','groups-table'), evidence: async () => { const id = document.getElementById('evidence-exam-id').value.trim(); if (id) { await loadTable('/api/v1/admin/submissions?exam_id=' + encodeURIComponent(id), 'submissions-table'); await loadTable('/api/v1/admin/reconciliation?exam_id=' + encodeURIComponent(id), 'reconciliation-table'); } }, security: async () => { await loadTable('/api/v1/health','recovery-table'); const node = document.getElementById('security-result'); if (node) { try { const data = await apiRequest('/api/v1/attestation/status?attestation_id='); renderTable(node, data); } catch (e) { node.textContent = e.message; node.style.color = '#fca5a5'; } } }, reports: () => loadTable('/api/v1/admin/audit','audit-table'), recovery: () => loadTable('/api/v1/health','recovery-table'), settings: () => loadTable('/api/v1/admin/institutions','institutions-table') };\n"
             "    let currentView = 'overview';\n"
             "    async function loadCurrentView() { const loader = loaders[currentView]; if (loader) await loader(); }\n"
             "    document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', async () => { currentView = button.dataset.view; document.querySelectorAll('.page').forEach(page => page.classList.toggle('active', page.id === 'page-' + currentView)); document.querySelectorAll('[data-view]').forEach(nav => nav.classList.toggle('active', nav === button)); document.getElementById('page-title').textContent = viewTitles[currentView] || 'Administration'; await loadCurrentView(); }));\n"
             "    document.querySelectorAll('.api-form').forEach(form => form.addEventListener('submit', async event => { event.preventDefault(); const endpoint = form.dataset.endpoint; if ((endpoint.includes('/revoke/')) && !window.confirm('This revocation is persistent. Continue only after verifying the target?')) return; const payload = Object.fromEntries(new FormData(form).entries()); form.querySelectorAll('input[type=number]').forEach(input => { if (input.name in payload) payload[input.name] = Number(payload[input.name]); });['scheduled_start','scheduled_end'].forEach(name => { if (typeof payload[name] === 'string' && payload[name]) { const parsed = Date.parse(payload[name]); if (Number.isFinite(parsed)) payload[name] = Math.floor(parsed / 1000); } }); const button = form.querySelector('[type=submit]'); if (button) button.disabled = true; try { const data = await apiRequest(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }); window.alert(data.status || 'Change accepted by server.'); const password = form.querySelector('input[type=password]'); if (password) password.value = ''; if (endpoint.endsWith('/institutions')) await loadTable('/api/v1/admin/institutions','institutions-table'); if (endpoint.endsWith('/users')) await loadTable('/api/v1/admin/users','users-table'); if (endpoint.includes('/platform/exams/create')) await loadTable('/api/v1/admin/exams','exams-table','exam'); if (endpoint.endsWith('/campuses')) await loaders.locations(); if (endpoint.endsWith('/rooms') && payload.campus_id) { document.getElementById('rooms-campus-id').value = payload.campus_id; await loadTable('/api/v1/admin/rooms?campus_id=' + encodeURIComponent(payload.campus_id),'rooms-table'); } } catch (error) { window.alert(error.message); } finally { if (button) button.disabled = false; } }));\n"
             "    async function loadPolicyCatalog() {\n      const node = document.getElementById('policy-catalog-table');\n      if (!node) return;\n      try {\n        const entries = await apiRequest('/api/v1/admin/policies/catalog');\n        const select = document.getElementById('exam-browser-policy');\n        if (select && select.options.length <= 1) {\n          entries.forEach(entry => {\n            const option = document.createElement('option');\n            option.value = entry.name;\n            option.textContent = entry.name + (entry.description ? ' - ' + entry.description : '');\n            select.appendChild(option);\n          });\n        }\n        renderTable(node, entries);\n      } catch (error) {\n        node.textContent = error.message;\n        node.style.color = '#fca5a5';\n      }\n    }\n    document.getElementById('roster-add-form').addEventListener('submit', async event => {\n      event.preventDefault();\n      const examId = document.getElementById('roster-add-exam-id').value.trim();\n      const pin = document.getElementById('roster-add-pin').value;\n      try {\n        await apiRequest('/api/v1/platform/exams/' + encodeURIComponent(examId) + '/roster', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ candidate_id: document.getElementById('roster-add-candidate-id').value.trim(), full_name: document.getElementById('roster-add-full-name').value.trim(), email: document.getElementById('roster-add-email').value.trim(), pin: pin, assigned_seat: document.getElementById('roster-add-seat').value.trim(), assigned_device_id: document.getElementById('roster-add-device').value.trim() }) });\n        window.alert('Candidate added to the roster.');\n        document.getElementById('roster-add-pin').value = '';\n        await loadTable('/api/v1/admin/roster?exam_id=' + encodeURIComponent(examId), 'roster-table');\n      } catch (error) { window.alert(error.message); }\n    });\n    document.getElementById('roster-checkin-form').addEventListener('submit', async event => {\n      event.preventDefault();\n      const examId = document.getElementById('checkin-exam-id').value.trim();\n      try {\n        await apiRequest('/api/v1/platform/exams/' + encodeURIComponent(examId) + '/checkin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ candidate_id: document.getElementById('checkin-candidate-id').value.trim(), device_id: document.getElementById('checkin-device-id').value.trim() }) });\n        window.alert('Candidate checked in.');\n        await loadTable('/api/v1/admin/roster?exam_id=' + encodeURIComponent(examId), 'roster-table');\n      } catch (error) { window.alert(error.message); }\n    });\n    document.getElementById('readiness-form').addEventListener('submit', async event => {\n      event.preventDefault();\n      const node = document.getElementById('readiness-result');\n      try {\n        const data = await apiRequest('/api/v1/platform/exams/' + encodeURIComponent(document.getElementById('readiness-exam-id').value.trim()) + '/readiness?device_id=' + encodeURIComponent(document.getElementById('readiness-device-id').value.trim()));\n        node.textContent = 'network=' + data.network + ' tpm=' + data.tpm + ' kiosk_policy=' + data.kiosk_policy + ' camera=' + data.camera + ' verdict=' + data.verdict;\n      } catch (error) { node.textContent = error.message; node.style.color = '#fca5a5'; }\n    });\n    document.getElementById('fleet-bulk-form').addEventListener('submit', async event => {\n      event.preventDefault();\n      if (!window.confirm('This changes live fleet state. Continue?')) return;\n      try {\n        await apiRequest('/api/v1/admin/fleet/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action_type: document.getElementById('bulk-action-type').value.trim(), target_group: document.getElementById('bulk-target-group').value.trim(), institution_id: document.getElementById('bulk-institution-id').value.trim(), parameter: document.getElementById('bulk-parameter').value.trim(), preview_only: 0 }) });\n        window.alert('Bulk action applied.');\n        await loadCurrentView();\n      } catch (error) { window.alert(error.message); }\n    });\n    document.getElementById('fleet-assign-form').addEventListener('submit', async event => {\n      event.preventDefault();\n      const deviceId = encodeURIComponent(document.getElementById('assign-device-id').value.trim());\n      try {\n        await apiRequest('/api/v1/admin/fleet/' + deviceId + '/assign', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ exam_id: document.getElementById('assign-exam-id').value.trim() }) });\n        window.alert('Device assigned to the examination.');\n      } catch (error) { window.alert(error.message); }\n    });\n    document.getElementById('incident-create-form').addEventListener('submit', async event => {\n      event.preventDefault();\n      try {\n        await apiRequest('/api/v1/admin/incidents', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: document.getElementById('incident-title').value.trim(), severity: document.getElementById('incident-severity').value, institution_id: document.getElementById('incident-institution-id').value.trim(), device_id: document.getElementById('incident-device-id').value.trim(), exam_id: document.getElementById('incident-exam-id').value.trim(), summary: document.getElementById('incident-summary').value.trim() }) });\n        window.alert('Incident raised.');\n        await loadCurrentView();\n      } catch (error) { window.alert(error.message); }\n    });\n    document.getElementById('release-create-form').addEventListener('submit', async event => {\n      event.preventDefault();\n      try {\n        await apiRequest('/api/v1/admin/releases', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ release_id: document.getElementById('release-id').value.trim(), version_name: document.getElementById('release-version').value.trim(), image_digest: document.getElementById('release-image-digest').value.trim(), uki_digest: document.getElementById('release-uki-digest').value.trim(), sbom_digest: document.getElementById('release-sbom-digest').value.trim(), target_ring: document.getElementById('release-ring').value }) });\n        window.alert('Release record created.');\n        await loadCurrentView();\n      } catch (error) { window.alert(error.message); }\n    });\n    document.getElementById('policy-distribute-form').addEventListener('submit', async event => {\n      event.preventDefault();\n      const node = document.getElementById('policy-distribute-result');\n      try {\n        const data = await apiRequest('/api/v1/admin/policies/distribute', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ exam_id: document.getElementById('distribute-exam-id').value.trim(), device_id: document.getElementById('distribute-device-id').value.trim() }) });\n        node.textContent = 'Policy version ' + data.policy_version + ' signed by ' + (data.approved_by || 'the platform');\n      } catch (error) { node.textContent = error.message; node.style.color = '#fca5a5'; }\n    });\n    document.getElementById('audit-query-form').addEventListener('submit', async event => {\n      event.preventDefault();\n      const subject = document.getElementById('audit-exam-id').value.trim();\n      await loadTable('/api/v1/admin/audit' + (subject ? '?exam_id=' + encodeURIComponent(subject) : ''), 'audit-table');\n    });\n    document.getElementById('institution-settings-form').addEventListener('submit', async event => {\n      event.preventDefault();\n      const institutionId = encodeURIComponent(document.getElementById('settings-institution-id').value.trim());\n      try {\n        await apiRequest('/api/v1/admin/institutions/' + institutionId, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: document.getElementById('settings-name').value.trim(), contact_email: document.getElementById('settings-contact-email').value.trim(), retention_days: Number(document.getElementById('settings-retention-days').value) }) });\n        window.alert('Institution settings saved.');\n        await loadCurrentView();\n      } catch (error) { window.alert(error.message); }\n    });\n"
             "    document.getElementById('evidence-form').addEventListener('submit', async event => { event.preventDefault(); const examId = encodeURIComponent(document.getElementById('evidence-exam-id').value.trim()); await loadTable('/api/v1/admin/submissions?exam_id=' + examId, 'submissions-table'); await loadTable('/api/v1/admin/reconciliation?exam_id=' + examId, 'reconciliation-table'); });\n"
             "    document.getElementById('roster-query-form').addEventListener('submit', async event => { event.preventDefault(); const examId = encodeURIComponent(document.getElementById('roster-exam-id').value.trim()); await loadTable('/api/v1/admin/roster?exam_id=' + examId, 'roster-table'); });\n"
             "    document.getElementById('rooms-query-form').addEventListener('submit', async event => { event.preventDefault(); const campusId = encodeURIComponent(document.getElementById('rooms-campus-id').value.trim()); await loadTable('/api/v1/admin/rooms?campus_id=' + campusId, 'rooms-table'); });\n"
             "    document.getElementById('exam-schedule-form').addEventListener('submit', async event => { event.preventDefault(); const examId = document.getElementById('schedule-exam-id').value.trim(); const start = Date.parse(document.getElementById('schedule-start').value); const end = Date.parse(document.getElementById('schedule-end').value); const zone = document.getElementById('schedule-zone').value.trim(); if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) { window.alert('Enter a valid start and end time; end must be after start.'); return; } const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone; if (zone !== browserZone) { window.alert('The selected timezone must match this browser timezone (' + browserZone + ') so the entered local times map to the intended instants.'); return; } try { await apiRequest('/api/v1/platform/exams/' + encodeURIComponent(examId) + '/schedule', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ start_time: Math.floor(start / 1000), end_time: Math.floor(end / 1000), timezone: zone }) }); window.alert('Exam schedule saved by the server.'); await loadTable('/api/v1/admin/exams','exams-table','exam'); } catch (error) { window.alert(error.message); } });\n"
             "    document.getElementById('attestation-form').addEventListener('submit', async event => { event.preventDefault(); const id = encodeURIComponent(document.getElementById('attestation-id').value.trim()); const node = document.getElementById('attestation-status'); try { const data = await apiRequest('/api/v1/attestation/status?attestation_id=' + id); renderTable(node, data); } catch (error) { node.textContent = error.message; node.style.color = '#fca5a5'; } });\n"
             "    document.getElementById('restart-kiosk').addEventListener('click', reloadKiosk);\n"
             "    loadOverview();\n"
             "  </script>\n"
             "</body>\n"
             "</html>\n",
             escaped_url, escaped_origins, escaped_name, dur_val);

    return buf;
}
