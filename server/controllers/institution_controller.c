/*
 * institution_controller.c — Production-grade Institution, Campus, Department,
 * and Staff Enterprise Management Service with Multi-Tenant Security Isolation,
 * Tamper-Evident Ledger Integrity, Dual-Write PostgreSQL Persistence,
 * Digital Agreements, Enforceable Licenses, Multi-OS Deployments, and Guided Onboarding.
 */

#include "institution_controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../security/security.h"
#include "../include/ledger.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void inst_send_json(int fd, int code, const char *body,
                           const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void inst_send_error(int fd, int code, const char *msg,
                            const char *origin, char *extra, size_t extra_len) {
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg ? msg : "An unexpected error occurred");
    inst_send_json(fd, code, buf, origin, extra, extra_len);
}

static void audit_and_ledger(const char *actor, const char *event,
                             const char *target, const char *detail) {
    audit_append(actor ? actor : "system", event, detail ? detail : "");
    ledger_block_t blk;
    ledger_append_event(event, target ? target : "SYSTEM", detail ? detail : "", &blk);
}

static void sanitize_utf8(char *str) {
    if (!str) return;
    for (size_t i = 0; str[i]; i++) {
        unsigned char c = (unsigned char)str[i];
        if (c == 0xb7) {
            str[i] = '-';
        } else if (c >= 0x80 && c <= 0xbf) {
            if (i == 0 || (unsigned char)str[i - 1] < 0xc0) {
                str[i] = ' ';
            }
        }
    }
}

static void escape_json_str(const char *in, char *out, size_t out_len) {
    if (!in || !out || out_len == 0) return;
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"') { out[j++] = '\\'; out[j++] = '"'; }
        else if (c == '\\') { out[j++] = '\\'; out[j++] = '\\'; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (c == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else if (c >= 32 && c <= 126) { out[j++] = (char)c; }
    }
    out[j] = '\0';
}

static void escape_sql_str(const char *in, char *out, size_t out_len) {
    if (!in || !out || out_len == 0) return;
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < out_len; i++) {
        if (in[i] == '\'') {
            out[j++] = '\'';
            out[j++] = '\'';
        } else {
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
}

static void compute_sha256_hex(const char *input, char *out, size_t out_len) {
    if (!input || !out || out_len < 65) return;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(out + (i * 2), "%02x", hash[i]);
    }
    out[64] = '\0';
}

/* Extract raw JSON object or array from body: e.g. "domains": [...] or "examDefaults": {...} */
static int ctrl_json_raw(const char *body, const char *key, char *out, size_t out_len) {
    if (!body || !key || !out || out_len == 0) return 0;
    out[0] = '\0';
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(body, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p != '{' && *p != '[') return 0;
    char open_char = *p;
    char close_char = (open_char == '{') ? '}' : ']';
    int depth = 0;
    size_t i = 0;
    while (*p && i + 1 < out_len) {
        if (*p == open_char) depth++;
        else if (*p == close_char) depth--;
        out[i++] = *p++;
        if (depth == 0) break;
    }
    out[i] = '\0';
    return depth == 0 && i > 0;
}

/* Build a JSON array of institutions from a PGresult */
static void inst_list_json(PGresult *res, char *out, size_t out_len) {
    int n = PQntuples(res);
    size_t pos = 0;
    pos += snprintf(out + pos, out_len - pos, "{\"institutions\":[");
    for (int i = 0; i < n; i++) {
        if (i > 0 && pos < out_len - 1) pos += snprintf(out + pos, out_len - pos, ",");
        char id_esc[128] = {0}, name_esc[256] = {0}, code_esc[64] = {0};
        char status_esc[64] = {0}, plan_esc[64] = {0}, region_esc[128] = {0};
        char tz_esc[128] = {0}, model_esc[64] = {0}, email_esc[256] = {0}, phone_esc[64] = {0};

        escape_json_str(PQgetvalue(res, i, 0), id_esc, sizeof(id_esc));
        escape_json_str(PQgetvalue(res, i, 1), name_esc, sizeof(name_esc));
        escape_json_str(PQgetvalue(res, i, 2), code_esc, sizeof(code_esc));
        escape_json_str(PQgetvalue(res, i, 3), status_esc, sizeof(status_esc));
        escape_json_str(PQgetvalue(res, i, 4), plan_esc, sizeof(plan_esc));
        escape_json_str(PQgetvalue(res, i, 5), region_esc, sizeof(region_esc));
        escape_json_str(PQgetvalue(res, i, 6), tz_esc, sizeof(tz_esc));
        escape_json_str(PQgetvalue(res, i, 9), model_esc, sizeof(model_esc));
        escape_json_str(PQgetvalue(res, i, 11), email_esc, sizeof(email_esc));
        escape_json_str(PQgetvalue(res, i, 12), phone_esc, sizeof(phone_esc));

        const char *domains = PQgetvalue(res, i, 13);
        if (!domains || !domains[0]) domains = "[]";
        const char *exam_defs = PQgetvalue(res, i, 14);
        if (!exam_defs || !exam_defs[0]) exam_defs = "{\"durationMin\":60,\"lateEntryMin\":15,\"attestationLevel\":\"tpm\"}";
        const char *security = PQgetvalue(res, i, 15);
        if (!security || !security[0]) security = "{\"requireTpm\":true,\"requireSecureBoot\":true,\"allowUsbStorage\":false}";
        const char *notif = PQgetvalue(res, i, 16);
        if (!notif || !notif[0]) notif = "{\"email\":true,\"inApp\":true}";

        pos += snprintf(out + pos, out_len - pos,
            "{\"id\":\"%s\",\"name\":\"%s\",\"code\":\"%s\","
            "\"status\":\"%s\",\"plan\":\"%s\",\"region\":\"%s\","
            "\"timezone\":\"%s\",\"maxCenters\":%s,\"maxCandidates\":%s,"
            "\"deploymentModel\":\"%s\",\"createdAt\":%s,\"contactEmail\":\"%s\","
            "\"contactPhone\":\"%s\",\"domains\":%s,\"examDefaults\":%s,"
            "\"security\":%s,\"notificationPrefs\":%s}",
            id_esc, name_esc, code_esc,
            status_esc[0] ? status_esc : "active",
            plan_esc[0] ? plan_esc : "pilot",
            region_esc[0] ? region_esc : "India · Mumbai",
            tz_esc[0] ? tz_esc : "Asia/Kolkata",
            PQgetvalue(res, i, 7)[0] ? PQgetvalue(res, i, 7) : "5",
            PQgetvalue(res, i, 8)[0] ? PQgetvalue(res, i, 8) : "500",
            model_esc[0] ? model_esc : "usb-boot",
            PQgetvalue(res, i, 10)[0] ? PQgetvalue(res, i, 10) : "0",
            email_esc, phone_esc, domains, exam_defs, security, notif);
    }
    snprintf(out + pos, out_len - pos, "]}");
}

/* Parse institution ID from path, e.g. /api/v1/admin/institutions/ins_123 or /ins_123/stats */
static int extract_inst_id_and_sub(const char *path, char *out_id, size_t out_id_len,
                                   char *out_sub, size_t out_sub_len) {
    out_id[0] = '\0';
    out_sub[0] = '\0';
    const char *prefix = "/api/v1/admin/institutions/";
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) != 0) return 0;
    const char *p = path + plen;
    const char *slash = strchr(p, '/');
    if (!slash) {
        size_t len = strlen(p);
        if (len >= out_id_len) return 0;
        memcpy(out_id, p, len);
        out_id[len] = '\0';
        return 1;
    }
    size_t id_len = (size_t)(slash - p);
    if (id_len >= out_id_len) return 0;
    memcpy(out_id, p, id_len);
    out_id[id_len] = '\0';
    const char *sub = slash + 1;
    size_t sub_len = strlen(sub);
    if (sub_len >= out_sub_len) return 0;
    memcpy(out_sub, sub, sub_len);
    out_sub[sub_len] = '\0';
    return 1;
}

/* Parse subresource ID from path, e.g. /api/v1/admin/campuses/cmp_123 or /cmp_123/status */
static int extract_sub_id_and_action(const char *path, const char *prefix,
                                     char *out_id, size_t out_id_len,
                                     char *out_action, size_t out_action_len) {
    out_id[0] = '\0';
    out_action[0] = '\0';
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) != 0) return 0;
    const char *p = path + plen;
    const char *slash = strchr(p, '/');
    if (!slash) {
        size_t len = strlen(p);
        if (len >= out_id_len) return 0;
        memcpy(out_id, p, len);
        out_id[len] = '\0';
        return 1;
    }
    size_t id_len = (size_t)(slash - p);
    if (id_len >= out_id_len) return 0;
    memcpy(out_id, p, id_len);
    out_id[id_len] = '\0';
    const char *act = slash + 1;
    size_t act_len = strlen(act);
    if (act_len >= out_action_len) return 0;
    memcpy(out_action, act, act_len);
    out_action[act_len] = '\0';
    return 1;
}

/* =========================================================================
 * Institution Main Dispatcher
 * ========================================================================= */
void institution_handle(int client_fd, const char *method, const char *path,
                        const char *body, const char *auth_header,
                        const char *origin, char *extra_headers, size_t extra_len) {
    /* Route: Public Apply is open without prior admin authentication */
    int is_public_apply = (strncmp(path, "/api/v1/institutions/apply", 26) == 0);
    auth_session_t sess;
    memset(&sess, 0, sizeof(sess));

    if (!is_public_apply) {
        if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
            inst_send_error(client_fd, 401, "Admin credentials required", origin, extra_headers, extra_len);
            return;
        }
    }

    int is_owner = (sess.role == ROLE_PLATFORM_OWNER);
    PGconn *conn = db_acquire();
    if (!conn) {
        inst_send_error(client_fd, 503, "Durable database connection unavailable", origin, extra_headers, extra_len);
        return;
    }

    /* -------------------------------------------------------------------------
     * 0. Institution Applications Workflow
     * ------------------------------------------------------------------------- */

    /* 0a. Public Application Submission: POST /api/v1/institutions/apply */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/institutions/apply") == 0) {
        char legal_name[160] = {0}, display_name[160] = {0}, entity_type[40] = {0};
        char reg_num[60] = {0}, country[60] = {0}, state[60] = {0}, address[512] = {0};
        char domain[120] = {0}, rep_name[120] = {0}, rep_role[60] = {0};
        char rep_email[120] = {0}, rep_phone[40] = {0};
        char coord_name[120] = {0}, coord_email[120] = {0};
        char tech_name[120] = {0}, tech_email[120] = {0};
        int campus_count = 1, student_count = 500, device_count = 100;
        char deployment_model[40] = {0}, hardware_profile[60] = {0}, plan[40] = {0};
        char docs_raw[4096] = {0}, decl_raw[2048] = {0};

        ctrl_json_string(body, "legalName", legal_name, sizeof(legal_name));
        ctrl_json_string(body, "displayName", display_name, sizeof(display_name));
        if (!display_name[0]) snprintf(display_name, sizeof(display_name), "%s", legal_name);
        ctrl_json_string(body, "entityType", entity_type, sizeof(entity_type));
        if (!entity_type[0]) snprintf(entity_type, sizeof(entity_type), "university");
        ctrl_json_string(body, "registrationNumber", reg_num, sizeof(reg_num));
        ctrl_json_string(body, "country", country, sizeof(country));
        if (!country[0]) snprintf(country, sizeof(country), "India");
        ctrl_json_string(body, "state", state, sizeof(state));
        if (!state[0]) snprintf(state, sizeof(state), "Maharashtra");
        ctrl_json_string(body, "address", address, sizeof(address));
        ctrl_json_string(body, "domain", domain, sizeof(domain));
        ctrl_json_string(body, "repName", rep_name, sizeof(rep_name));
        ctrl_json_string(body, "repRole", rep_role, sizeof(rep_role));
        ctrl_json_string(body, "repEmail", rep_email, sizeof(rep_email));
        ctrl_json_string(body, "repPhone", rep_phone, sizeof(rep_phone));
        ctrl_json_string(body, "coordName", coord_name, sizeof(coord_name));
        ctrl_json_string(body, "coordEmail", coord_email, sizeof(coord_email));
        ctrl_json_string(body, "techName", tech_name, sizeof(tech_name));
        ctrl_json_string(body, "techEmail", tech_email, sizeof(tech_email));

        ctrl_json_int(body, "campusCount", &campus_count);
        ctrl_json_int(body, "studentCount", &student_count);
        ctrl_json_int(body, "deviceCount", &device_count);

        ctrl_json_string(body, "deploymentModel", deployment_model, sizeof(deployment_model));
        if (!deployment_model[0]) snprintf(deployment_model, sizeof(deployment_model), "usb-boot");
        ctrl_json_string(body, "hardwareProfile", hardware_profile, sizeof(hardware_profile));
        if (!hardware_profile[0]) snprintf(hardware_profile, sizeof(hardware_profile), "standard-uefi");
        ctrl_json_string(body, "plan", plan, sizeof(plan));
        if (!plan[0]) snprintf(plan, sizeof(plan), "pilot");

        if (!ctrl_json_raw(body, "documents", docs_raw, sizeof(docs_raw))) {
            snprintf(docs_raw, sizeof(docs_raw), "[]");
        }
        if (!ctrl_json_raw(body, "declarations", decl_raw, sizeof(decl_raw))) {
            snprintf(decl_raw, sizeof(decl_raw), "{\"termsAgreed\":true,\"privacyAgreed\":true}");
        }

        sanitize_utf8(legal_name);
        sanitize_utf8(display_name);
        sanitize_utf8(reg_num);
        sanitize_utf8(address);
        sanitize_utf8(domain);
        sanitize_utf8(rep_name);
        sanitize_utf8(rep_email);
        sanitize_utf8(rep_phone);

        if (!legal_name[0] || !reg_num[0] || !domain[0] || !rep_email[0] || !address[0]) {
            db_release(conn, 0);
            inst_send_error(client_fd, 400, "Legal name, registration number, address, domain, and representative email are required", origin, extra_headers, extra_len);
            return;
        }

        /* Duplicate detection: check registration number and domain */
        const char *chk_vals[3] = { reg_num, domain, rep_email };
        int chk_lens[3] = { (int)strlen(reg_num), (int)strlen(domain), (int)strlen(rep_email) };
        PGresult *dup_res = db_simple(conn,
            "SELECT id FROM tenants WHERE contact_email = $3 OR domains @> to_jsonb($2::text) "
            "UNION "
            "SELECT id FROM institution_applications WHERE status NOT IN ('REJECTED', 'WITHDRAWN') "
            "AND (registration_number = $1 OR domain = $2 OR rep_email = $3)",
            3, chk_vals, chk_lens);

        int is_dup = dup_res && PQresultStatus(dup_res) == PGRES_TUPLES_OK && PQntuples(dup_res) > 0;
        if (dup_res) PQclear(dup_res);

        if (is_dup) {
            db_release(conn, 0);
            inst_send_error(client_fd, 409, "An institution with this registration number, domain, or primary email already exists or is under active review", origin, extra_headers, extra_len);
            return;
        }

        char app_id[64];
        snprintf(app_id, sizeof(app_id), "app_%ld_%04d", (long)time(NULL), rand() % 10000);
        char now[32];
        snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

        char c_cnt[16], s_cnt[16], d_cnt[16];
        snprintf(c_cnt, sizeof(c_cnt), "%d", campus_count);
        snprintf(s_cnt, sizeof(s_cnt), "%d", student_count);
        snprintf(d_cnt, sizeof(d_cnt), "%d", device_count);

        const char *ins_vals[25] = {
            app_id, legal_name, display_name, entity_type, reg_num,
            country, state, address, domain, rep_name,
            rep_role, rep_email, rep_phone, coord_name, coord_email,
            tech_name, tech_email, c_cnt, s_cnt, d_cnt,
            deployment_model, hardware_profile, plan, now, now
        };
        int ins_lens[25];
        for (int i = 0; i < 25; i++) ins_lens[i] = (int)strlen(ins_vals[i]);

        PGresult *ins = db_simple(conn,
            "INSERT INTO institution_applications ("
            "  id, legal_name, display_name, entity_type, registration_number,"
            "  country, state, address, domain, rep_name,"
            "  rep_role, rep_email, rep_phone, coord_name, coord_email,"
            "  tech_name, tech_email, campus_count, student_count, device_count,"
            "  deployment_model, hardware_profile, plan, status, created_at, updated_at,"
            "  documents, declarations"
            ") VALUES ("
            "  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,"
            "  $11,$12,$13,$14,$15,$16,$17,$18::integer,$19::integer,$20::integer,"
            "  $21,$22,$23,'SUBMITTED',$24::bigint,$25::bigint,"
            "  '[]'::jsonb, '{}'::jsonb"
            ")", 25, ins_vals, ins_lens);

        int ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
        if (ins) PQclear(ins);

        if (!ok) {
            fprintf(stderr, "[INST APPLICATION ERROR] %s\n", PQerrorMessage(conn));
            db_release(conn, 0);
            inst_send_error(client_fd, 503, "Failed to submit institution application", origin, extra_headers, extra_len);
            return;
        }

        audit_and_ledger("applicant", "INSTITUTION_APPLICATION_SUBMITTED", app_id, legal_name);
        db_release(conn, 0);

        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"submitted\",\"application_id\":\"%s\",\"reference_number\":\"APP-2026-%04d\","
            "\"message\":\"Institution application submitted successfully and queued for verification.\"}",
            app_id, rand() % 9000 + 1000);
        inst_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        return;
    }

    /* 0b. Public Application Status Check: GET /api/v1/institutions/apply/:id */
    if (strncmp(path, "/api/v1/institutions/apply/", 27) == 0 && strcmp(method, "GET") == 0) {
        char app_id[64] = {0}, act[32] = {0};
        extract_sub_id_and_action(path, "/api/v1/institutions/apply/", app_id, sizeof(app_id), act, sizeof(act));
        if (app_id[0]) {
            const char *pvals[1] = { app_id };
            int plens[1] = { (int)strlen(app_id) };
            PGresult *res = db_simple(conn,
                "SELECT id, legal_name, display_name, entity_type, status, created_at, reviewed_at "
                "FROM institution_applications WHERE id = $1", 1, pvals, plens);
            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char id_esc[128] = {0}, l_name[256] = {0}, d_name[256] = {0}, st[64] = {0};
                escape_json_str(PQgetvalue(res, 0, 0), id_esc, sizeof(id_esc));
                escape_json_str(PQgetvalue(res, 0, 1), l_name, sizeof(l_name));
                escape_json_str(PQgetvalue(res, 0, 2), d_name, sizeof(d_name));
                escape_json_str(PQgetvalue(res, 0, 4), st, sizeof(st));

                char resp[512];
                snprintf(resp, sizeof(resp),
                    "{\"id\":\"%s\",\"legalName\":\"%s\",\"displayName\":\"%s\",\"status\":\"%s\","
                    "\"createdAt\":%s,\"reviewedAt\":%s}",
                    id_esc, l_name, d_name, st,
                    PQgetvalue(res, 0, 5)[0] ? PQgetvalue(res, 0, 5) : "0",
                    PQgetvalue(res, 0, 6)[0] ? PQgetvalue(res, 0, 6) : "null");
                PQclear(res);
                db_release(conn, 0);
                inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                return;
            }
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_error(client_fd, 404, "Application reference not found", origin, extra_headers, extra_len);
            return;
        }
    }

    /* 0c. Admin List Applications: GET /api/v1/admin/institution-applications */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/institution-applications") == 0) {
        if (!is_owner) {
            db_release(conn, 0);
            inst_send_error(client_fd, 403, "Platform owner access required to review applications", origin, extra_headers, extra_len);
            return;
        }

        PGresult *res = PQexec(conn,
            "SELECT id, legal_name, display_name, entity_type, registration_number, "
            "       country, state, address, domain, rep_name, "
            "       rep_role, rep_email, rep_phone, campus_count, student_count, "
            "       device_count, deployment_model, hardware_profile, plan, status, "
            "       review_notes, reviewed_by, reviewed_at, institution_id, created_at, updated_at "
            "FROM institution_applications ORDER BY created_at DESC");

        char json[65536] = {0};
        size_t pos = 0;
        pos += snprintf(json + pos, sizeof(json) - pos, "{\"applications\":[");
        int n = (res && PQresultStatus(res) == PGRES_TUPLES_OK) ? PQntuples(res) : 0;
        for (int i = 0; i < n; i++) {
            if (i > 0 && pos < sizeof(json) - 1) pos += snprintf(json + pos, sizeof(json) - pos, ",");
            char id_esc[64] = {0}, l_name[256] = {0}, d_name[256] = {0}, reg[64] = {0};
            char dom[128] = {0}, r_email[128] = {0}, st[64] = {0}, ins_id[64] = {0};
            char notes[512] = {0};

            escape_json_str(PQgetvalue(res, i, 0), id_esc, sizeof(id_esc));
            escape_json_str(PQgetvalue(res, i, 1), l_name, sizeof(l_name));
            escape_json_str(PQgetvalue(res, i, 2), d_name, sizeof(d_name));
            escape_json_str(PQgetvalue(res, i, 4), reg, sizeof(reg));
            escape_json_str(PQgetvalue(res, i, 8), dom, sizeof(dom));
            escape_json_str(PQgetvalue(res, i, 11), r_email, sizeof(r_email));
            escape_json_str(PQgetvalue(res, i, 19), st, sizeof(st));
            escape_json_str(PQgetvalue(res, i, 20), notes, sizeof(notes));
            escape_json_str(PQgetvalue(res, i, 23), ins_id, sizeof(ins_id));

            pos += snprintf(json + pos, sizeof(json) - pos,
                "{\"id\":\"%s\",\"legalName\":\"%s\",\"displayName\":\"%s\",\"entityType\":\"%s\","
                "\"registrationNumber\":\"%s\",\"country\":\"%s\",\"state\":\"%s\",\"domain\":\"%s\","
                "\"repEmail\":\"%s\",\"campusCount\":%s,\"studentCount\":%s,\"deviceCount\":%s,"
                "\"deploymentModel\":\"%s\",\"plan\":\"%s\",\"status\":\"%s\",\"reviewNotes\":\"%s\","
                "\"institutionId\":\"%s\",\"createdAt\":%s,\"reviewedAt\":%s}",
                id_esc, l_name, d_name, PQgetvalue(res, i, 3),
                reg, PQgetvalue(res, i, 5), PQgetvalue(res, i, 6), dom,
                r_email, PQgetvalue(res, i, 13), PQgetvalue(res, i, 14), PQgetvalue(res, i, 15),
                PQgetvalue(res, i, 16), PQgetvalue(res, i, 18), st, notes,
                ins_id, PQgetvalue(res, i, 24),
                PQgetvalue(res, i, 22)[0] ? PQgetvalue(res, i, 22) : "null");
        }
        snprintf(json + pos, sizeof(json) - pos, "]}");
        if (res) PQclear(res);
        db_release(conn, 0);
        inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        return;
    }

    /* 0d. Admin Application Details & Review & Provision */
    if (strncmp(path, "/api/v1/admin/institution-applications/", 39) == 0) {
        char app_id[64] = {0}, act[32] = {0};
        extract_sub_id_and_action(path, "/api/v1/admin/institution-applications/", app_id, sizeof(app_id), act, sizeof(act));

        /* Review Action: POST /api/v1/admin/institution-applications/:id/review */
        if (strcmp(method, "POST") == 0 && strcmp(act, "review") == 0) {
            if (!is_owner) {
                db_release(conn, 0);
                inst_send_error(client_fd, 403, "Platform owner permission required to review applications", origin, extra_headers, extra_len);
                return;
            }

            char action_val[64] = {0}, review_notes[512] = {0};
            ctrl_json_string(body, "action", action_val, sizeof(action_val));
            ctrl_json_string(body, "reviewNotes", review_notes, sizeof(review_notes));
            if (!review_notes[0]) ctrl_json_string(body, "notes", review_notes, sizeof(review_notes));

            if (strcmp(action_val, "APPROVED") != 0 && strcmp(action_val, "REJECTED") != 0 &&
                strcmp(action_val, "UNDER_REVIEW") != 0 && strcmp(action_val, "VERIFICATION_PENDING") != 0 &&
                strcmp(action_val, "MORE_INFORMATION_REQUIRED") != 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "Invalid review action", origin, extra_headers, extra_len);
                return;
            }

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            const char *u_vals[5] = { action_val, review_notes, sess.user_id, now, app_id };
            int u_lens[5]; for (int i = 0; i < 5; i++) u_lens[i] = (int)strlen(u_vals[i]);

            PGresult *u_res = db_simple(conn,
                "UPDATE institution_applications SET status = $1, review_notes = $2, "
                "reviewed_by = $3, reviewed_at = $4::bigint, updated_at = $4::bigint "
                "WHERE id = $5", 5, u_vals, u_lens);
            int ok = u_res && PQresultStatus(u_res) == PGRES_COMMAND_OK;
            (void)ok;
            if (u_res) PQclear(u_res);

            audit_and_ledger(sess.user_id, "INSTITUTION_APPLICATION_REVIEWED", app_id, action_val);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"action\":\"%s\",\"application_id\":\"%s\"}", action_val, app_id);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* Provision Action: POST /api/v1/admin/institution-applications/:id/provision */
        if (strcmp(method, "POST") == 0 && strcmp(act, "provision") == 0) {
            if (!is_owner) {
                db_release(conn, 0);
                inst_send_error(client_fd, 403, "Platform owner permission required to provision institutions", origin, extra_headers, extra_len);
                return;
            }

            const char *pvals[1] = { app_id };
            int plens[1] = { (int)strlen(app_id) };
            PGresult *a_res = db_simple(conn,
                "SELECT display_name, registration_number, country, state, address, domain, "
                "       rep_name, rep_email, rep_phone, campus_count, student_count, device_count, "
                "       deployment_model, plan, institution_id, status "
                "FROM institution_applications WHERE id = $1", 1, pvals, plens);

            if (!a_res || PQresultStatus(a_res) != PGRES_TUPLES_OK || PQntuples(a_res) == 0) {
                if (a_res) PQclear(a_res);
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Application not found", origin, extra_headers, extra_len);
                return;
            }

            char existing_inst[64] = {0};
            snprintf(existing_inst, sizeof(existing_inst), "%s", PQgetvalue(a_res, 0, 14));
            if (existing_inst[0]) {
                PQclear(a_res);
                db_release(conn, 0);
                char err_msg[256];
                snprintf(err_msg, sizeof(err_msg), "Application already provisioned as institution %s", existing_inst);
                inst_send_error(client_fd, 400, err_msg, origin, extra_headers, extra_len);
                return;
            }

            char d_name[160] = {0}, reg_no[60] = {0}, ctry[60] = {0}, addr[512] = {0};
            char dom[120] = {0}, r_email[120] = {0}, r_phone[40] = {0}, d_model[40] = {0}, d_plan[40] = {0};
            int c_cnt = atoi(PQgetvalue(a_res, 0, 9));
            int s_cnt = atoi(PQgetvalue(a_res, 0, 10));
            int dev_cnt = atoi(PQgetvalue(a_res, 0, 11));
            snprintf(d_name, sizeof(d_name), "%s", PQgetvalue(a_res, 0, 0));
            snprintf(reg_no, sizeof(reg_no), "%s", PQgetvalue(a_res, 0, 1));
            snprintf(ctry, sizeof(ctry), "%s", PQgetvalue(a_res, 0, 2));
            snprintf(addr, sizeof(addr), "%s", PQgetvalue(a_res, 0, 4));
            snprintf(dom, sizeof(dom), "%s", PQgetvalue(a_res, 0, 5));
            snprintf(r_email, sizeof(r_email), "%s", PQgetvalue(a_res, 0, 7));
            snprintf(r_phone, sizeof(r_phone), "%s", PQgetvalue(a_res, 0, 8));
            snprintf(d_model, sizeof(d_model), "%s", PQgetvalue(a_res, 0, 12));
            snprintf(d_plan, sizeof(d_plan), "%s", PQgetvalue(a_res, 0, 13));
            PQclear(a_res);

            /* Generate unique institution, agreement, license, and campus identifiers */
            char new_inst_id[64], new_agr_id[64], new_lic_id[64], new_cmp_id[64], new_dep_id[64];
            long now_sec = (long)time(NULL);
            snprintf(new_inst_id, sizeof(new_inst_id), "ins_%ld_%04d", now_sec, rand() % 10000);
            snprintf(new_agr_id, sizeof(new_agr_id), "agr_%ld_%04d", now_sec, rand() % 10000);
            snprintf(new_lic_id, sizeof(new_lic_id), "lic_%ld_%04d", now_sec, rand() % 10000);
            snprintf(new_cmp_id, sizeof(new_cmp_id), "cmp_%ld_%04d", now_sec, rand() % 10000);
            snprintf(new_dep_id, sizeof(new_dep_id), "dep_%ld_%04d", now_sec, rand() % 10000);

            char code[32] = {0};
            char pfx[8] = {0};
            for (size_t ci = 0; d_name[ci] && strlen(pfx) < 4; ci++) {
                char ch = d_name[ci];
                if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
                    pfx[strlen(pfx)] = (ch >= 'a' && ch <= 'z') ? (ch - 32) : ch;
                }
            }
            if (strlen(pfx) < 3) snprintf(pfx, sizeof(pfx), "INS");
            snprintf(code, sizeof(code), "%s-%03d", pfx, rand() % 900 + 100);

            char now_ms[32], valid_until_ms[32];
            snprintf(now_ms, sizeof(now_ms), "%ld000", now_sec);
            snprintf(valid_until_ms, sizeof(valid_until_ms), "%ld000", now_sec + 31536000L); /* 1 year */

            /* Transactional multi-table provisioning */
            PQexec(conn, "BEGIN");

            /* 1. Insert Tenant */
            char dom_json[256];
            snprintf(dom_json, sizeof(dom_json), "[\"%s\"]", dom);
            char c_str[16], s_str[16];
            snprintf(c_str, sizeof(c_str), "%d", c_cnt > 0 ? c_cnt : 5);
            snprintf(s_str, sizeof(s_str), "%d", s_cnt > 0 ? s_cnt : 500);

            const char *t_vals[13] = {
                new_inst_id, d_name, code, r_email, r_phone,
                "India · Mumbai", "Asia/Kolkata", d_plan[0] ? d_plan : "pilot",
                c_str, s_str, d_model[0] ? d_model : "usb-boot", now_ms, dom_json
            };
            int t_lens[13]; for (int i = 0; i < 13; i++) t_lens[i] = (int)strlen(t_vals[i]);

            PGresult *t_ins = db_simple(conn,
                "INSERT INTO tenants (id, name, code, contact_email, contact_phone, "
                "region, timezone, plan, status, max_centers, max_candidates, "
                "deployment_model, created_at, created_by, domains, exam_defaults, security, notification_prefs, history) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9::integer,$10::integer,$11,$12::bigint,'admin',$13::jsonb,"
                "'{\"durationMin\":60,\"lateEntryMin\":15,\"attestationLevel\":\"tpm\"}'::jsonb,"
                "'{\"requireTpm\":true,\"requireSecureBoot\":true,\"allowUsbStorage\":false}'::jsonb,"
                "'{\"email\":true,\"inApp\":true}'::jsonb,"
                "jsonb_build_array(jsonb_build_object('at',$12::bigint,'by','admin','action','Provisioned from Application')))",
                13, t_vals, t_lens);

            /* 2. Dual-sync examos_institutions */
            const char *s_vals[4] = { new_inst_id, d_name, code, r_email };
            int s_lens[4]; for (int i = 0; i < 4; i++) s_lens[i] = (int)strlen(s_vals[i]);
            PGresult *s_ins = db_simple(conn,
                "INSERT INTO examos_institutions (institution_id, name, code, domain_email, retention_days, active) "
                "VALUES ($1,$2,$3,$4,365,true) ON CONFLICT (institution_id) DO UPDATE SET active = true",
                4, s_vals, s_lens);

            /* 3. Agreement Draft */
            const char *agr_vals[4] = { new_agr_id, new_inst_id, d_plan, now_ms };
            int agr_lens[4]; for (int i = 0; i < 4; i++) agr_lens[i] = (int)strlen(agr_vals[i]);
            PGresult *agr_ins = db_simple(conn,
                "INSERT INTO institution_agreements (id, institution_id, type, title, version, status, terms_payload, audit_trail, created_at) "
                "VALUES ($1, $2, 'msa', 'Master Services Agreement & Exam Security Covenant', '2026.1', 'APPROVED_FOR_ISSUE', "
                "jsonb_build_object('plan',$3::varchar,'sla','99.9% uptime','supportTier','gold'), "
                "jsonb_build_array(jsonb_build_object('at',$4::bigint,'by','platform_owner','action','Issued for electronic execution')), $4::bigint)",
                4, agr_vals, agr_lens);

            /* 4. Enforceable License */
            char dev_str[16]; snprintf(dev_str, sizeof(dev_str), "%d", dev_cnt > 0 ? dev_cnt : 250);
            const char *lic_vals[9] = { new_lic_id, new_inst_id, new_agr_id, d_plan, now_ms, valid_until_ms, c_str, dev_str, s_str };
            int lic_lens[9]; for (int i = 0; i < 9; i++) lic_lens[i] = (int)strlen(lic_vals[i]);
            PGresult *lic_ins = db_simple(conn,
                "INSERT INTO institution_licenses (id, institution_id, agreement_id, plan, plan_version, status, "
                "valid_from, valid_until, grace_period_days, max_campuses, max_devices, max_candidates, max_exams, "
                "allowed_channels, enabled_modules, usage_current, created_at, updated_at) "
                "VALUES ($1, $2, $3, $4, '2026.1', 'ACTIVE', $5::bigint, $6::bigint, 14, $7::integer, $8::integer, $9::integer, 50, "
                "'[\"stable\",\"pilot\"]'::jsonb, '[\"exams\",\"kiosk\",\"tpm\",\"firewall\",\"auditing\"]'::jsonb, "
                "'{\"campuses\":1,\"devices\":0,\"candidates\":0,\"exams\":0}'::jsonb, $5::bigint, $5::bigint)",
                9, lic_vals, lic_lens);

            /* 5. Guided Onboarding State Record */
            const char *onb_vals[4] = { new_inst_id, r_email, now_ms, app_id };
            int onb_lens[4]; for (int i = 0; i < 4; i++) onb_lens[i] = (int)strlen(onb_vals[i]);
            PGresult *onb_ins = db_simple(conn,
                "INSERT INTO institution_onboarding (institution_id, status, checklist, completed_steps, total_steps, "
                "first_admin_email, first_admin_invited, mfa_enforced, updated_at) "
                "VALUES ($1, 'VERIFIED', jsonb_build_object("
                "'registration', jsonb_build_object('completed', true, 'ref', $4::varchar),"
                "'identity_verification', jsonb_build_object('completed', true),"
                "'agreement', jsonb_build_object('completed', false),"
                "'license', jsonb_build_object('completed', true),"
                "'admin_mfa', jsonb_build_object('completed', false),"
                "'campus_hierarchy', jsonb_build_object('completed', true),"
                "'os_deployment', jsonb_build_object('completed', true),"
                "'production_readiness', jsonb_build_object('completed', false)"
                "), 4, 8, $2, 1, 1, $3::bigint)",
                4, onb_vals, onb_lens);

            /* 6. Default Main Campus */
            const char *cmp_vals[5] = { new_cmp_id, new_inst_id, addr[0] ? addr : "Campus Headquarters", now_ms, now_ms };
            int cmp_lens[5]; for (int i = 0; i < 5; i++) cmp_lens[i] = (int)strlen(cmp_vals[i]);
            PGresult *cmp_ins = db_simple(conn,
                "INSERT INTO campuses (id, tenant_id, name, code, address, capacity, status, created_at, updated_at) "
                "VALUES ($1, $2, 'Main Campus', 'MAIN', $3, 250, 'active', $4::bigint, $5::bigint)",
                5, cmp_vals, cmp_lens);

            /* 7. Default OS Release Assignment */
            const char *dep_vals[4] = { new_dep_id, new_inst_id, new_cmp_id, now_ms };
            int dep_lens[4]; for (int i = 0; i < 4; i++) dep_lens[i] = (int)strlen(dep_vals[i]);
            PGresult *dep_ins = db_simple(conn,
                "INSERT INTO institution_os_deployments (id, institution_id, campus_id, release_id, channel, "
                "hardware_profile, security_profile, status, policy_hash, devices_targeted, devices_acknowledged, created_at, updated_at) "
                "VALUES ($1, $2, $3, 'examos-dev-0.1', 'stable', 'standard-uefi', 'high-assurance', 'ACTIVE', 'sha256-policy-default', 0, 0, $4::bigint, $4::bigint)",
                4, dep_vals, dep_lens);

            /* 8. Link Application to Institution */
            const char *app_u_vals[3] = { new_inst_id, now_ms, app_id };
            int app_u_lens[3]; for (int i = 0; i < 3; i++) app_u_lens[i] = (int)strlen(app_u_vals[i]);
            PGresult *app_u_res = db_simple(conn,
                "UPDATE institution_applications SET institution_id = $1, status = 'PROVISIONED', updated_at = $2::bigint WHERE id = $3",
                3, app_u_vals, app_u_lens);

            int all_ok = t_ins && PQresultStatus(t_ins) == PGRES_COMMAND_OK &&
                         s_ins && PQresultStatus(s_ins) == PGRES_COMMAND_OK &&
                         agr_ins && PQresultStatus(agr_ins) == PGRES_COMMAND_OK &&
                         lic_ins && PQresultStatus(lic_ins) == PGRES_COMMAND_OK &&
                         onb_ins && PQresultStatus(onb_ins) == PGRES_COMMAND_OK &&
                         cmp_ins && PQresultStatus(cmp_ins) == PGRES_COMMAND_OK &&
                         dep_ins && PQresultStatus(dep_ins) == PGRES_COMMAND_OK &&
                         app_u_res && PQresultStatus(app_u_res) == PGRES_COMMAND_OK;

            if (!t_ins || PQresultStatus(t_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 1 tenants] %s\n", t_ins ? PQresultErrorMessage(t_ins) : "null");
            if (!s_ins || PQresultStatus(s_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 2 examos_institutions] %s\n", s_ins ? PQresultErrorMessage(s_ins) : "null");
            if (!agr_ins || PQresultStatus(agr_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 3 agreements] %s\n", agr_ins ? PQresultErrorMessage(agr_ins) : "null");
            if (!lic_ins || PQresultStatus(lic_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 4 licenses] %s\n", lic_ins ? PQresultErrorMessage(lic_ins) : "null");
            if (!onb_ins || PQresultStatus(onb_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 5 onboarding] %s\n", onb_ins ? PQresultErrorMessage(onb_ins) : "null");
            if (!cmp_ins || PQresultStatus(cmp_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 6 campuses] %s\n", cmp_ins ? PQresultErrorMessage(cmp_ins) : "null");
            if (!dep_ins || PQresultStatus(dep_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 7 deployments] %s\n", dep_ins ? PQresultErrorMessage(dep_ins) : "null");
            if (!app_u_res || PQresultStatus(app_u_res) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 8 applications] %s\n", app_u_res ? PQresultErrorMessage(app_u_res) : "null");

            if (t_ins) PQclear(t_ins);
            if (s_ins) PQclear(s_ins);
            if (agr_ins) PQclear(agr_ins);
            if (lic_ins) PQclear(lic_ins);
            if (onb_ins) PQclear(onb_ins);
            if (cmp_ins) PQclear(cmp_ins);
            if (dep_ins) PQclear(dep_ins);
            if (app_u_res) PQclear(app_u_res);

            if (all_ok) {
                PQexec(conn, "COMMIT");
                audit_and_ledger(sess.user_id, "INSTITUTION_TRANSACTIONALLY_PROVISIONED", new_inst_id, d_name);
                db_release(conn, 0);

                char resp[512];
                snprintf(resp, sizeof(resp),
                    "{\"status\":\"provisioned\",\"institution_id\":\"%s\",\"tenant_id\":\"%s\","
                    "\"license_id\":\"%s\",\"agreement_id\":\"%s\",\"name\":\"%s\"}",
                    new_inst_id, new_inst_id, new_lic_id, new_agr_id, d_name);
                inst_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
                return;
            } else {
                PQexec(conn, "ROLLBACK");
                fprintf(stderr, "[INST PROVISION TRANSACTION FAILED] %s\n", PQerrorMessage(conn));
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Transaction failed while provisioning institution", origin, extra_headers, extra_len);
                return;
            }
        }

        /* Get single application: GET /api/v1/admin/institution-applications/:id */
        if (strcmp(method, "GET") == 0 && !act[0]) {
            const char *pvals[1] = { app_id };
            int plens[1] = { (int)strlen(app_id) };
            PGresult *res = db_simple(conn,
                "SELECT id, legal_name, display_name, entity_type, registration_number, "
                "       country, state, address, domain, rep_name, "
                "       rep_role, rep_email, rep_phone, coord_name, coord_email, "
                "       tech_name, tech_email, campus_count, student_count, device_count, "
                "       deployment_model, hardware_profile, plan, status, review_notes, "
                "       reviewed_by, reviewed_at, institution_id, documents, declarations, "
                "       created_at, updated_at FROM institution_applications WHERE id = $1",
                1, pvals, plens);

            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char id_esc[64] = {0}, l_name[256] = {0}, d_name[256] = {0}, reg[64] = {0};
                char dom[120] = {0}, r_name[120] = {0}, r_email[120] = {0}, r_phone[40] = {0};
                char st[40] = {0}, notes[512] = {0}, ins_id[64] = {0};

                escape_json_str(PQgetvalue(res, 0, 0), id_esc, sizeof(id_esc));
                escape_json_str(PQgetvalue(res, 0, 1), l_name, sizeof(l_name));
                escape_json_str(PQgetvalue(res, 0, 2), d_name, sizeof(d_name));
                escape_json_str(PQgetvalue(res, 0, 4), reg, sizeof(reg));
                escape_json_str(PQgetvalue(res, 0, 8), dom, sizeof(dom));
                escape_json_str(PQgetvalue(res, 0, 9), r_name, sizeof(r_name));
                escape_json_str(PQgetvalue(res, 0, 11), r_email, sizeof(r_email));
                escape_json_str(PQgetvalue(res, 0, 12), r_phone, sizeof(r_phone));
                escape_json_str(PQgetvalue(res, 0, 23), st, sizeof(st));
                escape_json_str(PQgetvalue(res, 0, 24), notes, sizeof(notes));
                escape_json_str(PQgetvalue(res, 0, 27), ins_id, sizeof(ins_id));

                const char *docs = PQgetvalue(res, 0, 28);
                if (!docs || !docs[0]) docs = "[]";
                const char *decl = PQgetvalue(res, 0, 29);
                if (!decl || !decl[0]) decl = "{}";

                char json[8192];
                snprintf(json, sizeof(json),
                    "{\"id\":\"%s\",\"legalName\":\"%s\",\"displayName\":\"%s\",\"entityType\":\"%s\","
                    "\"registrationNumber\":\"%s\",\"country\":\"%s\",\"state\":\"%s\",\"address\":\"%s\","
                    "\"domain\":\"%s\",\"repName\":\"%s\",\"repRole\":\"%s\",\"repEmail\":\"%s\",\"repPhone\":\"%s\","
                    "\"campusCount\":%s,\"studentCount\":%s,\"deviceCount\":%s,\"deploymentModel\":\"%s\","
                    "\"hardwareProfile\":\"%s\",\"plan\":\"%s\",\"status\":\"%s\",\"reviewNotes\":\"%s\","
                    "\"institutionId\":\"%s\",\"documents\":%s,\"declarations\":%s,\"createdAt\":%s,\"reviewedAt\":%s}",
                    id_esc, l_name, d_name, PQgetvalue(res, 0, 3),
                    reg, PQgetvalue(res, 0, 5), PQgetvalue(res, 0, 6), PQgetvalue(res, 0, 7),
                    dom, r_name, PQgetvalue(res, 0, 10), r_email, r_phone,
                    PQgetvalue(res, 0, 17), PQgetvalue(res, 0, 18), PQgetvalue(res, 0, 19),
                    PQgetvalue(res, 0, 20), PQgetvalue(res, 0, 21), PQgetvalue(res, 0, 22),
                    st, notes, ins_id, docs, decl,
                    PQgetvalue(res, 0, 30),
                    PQgetvalue(res, 0, 26)[0] ? PQgetvalue(res, 0, 26) : "null");

                PQclear(res);
                db_release(conn, 0);
                inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
                return;
            }
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_error(client_fd, 404, "Application not found", origin, extra_headers, extra_len);
            return;
        }
    }

    /* -------------------------------------------------------------------------
     * 1. GET /api/v1/admin/institutions -> List institutions
     * ------------------------------------------------------------------------- */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/admin/institutions") == 0) {
        PGresult *res = NULL;
        if (is_owner) {
            res = PQexec(conn,
                "SELECT id, name, code, status, plan, region, timezone, "
                "       max_centers, max_candidates, deployment_model, created_at, "
                "       contact_email, contact_phone, domains, exam_defaults, "
                "       security, notification_prefs "
                "FROM tenants ORDER BY created_at DESC");
        } else {
            const char *pvals[1] = { sess.institution_id };
            int lens[1] = { (int)strlen(sess.institution_id) };
            res = db_simple(conn,
                "SELECT id, name, code, status, plan, region, timezone, "
                "       max_centers, max_candidates, deployment_model, created_at, "
                "       contact_email, contact_phone, domains, exam_defaults, "
                "       security, notification_prefs "
                "FROM tenants WHERE id = $1", 1, pvals, lens);
        }

        char json[65536] = {0};
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK)
            inst_list_json(res, json, sizeof(json));
        else
            snprintf(json, sizeof(json), "{\"institutions\":[]}");
        if (res) PQclear(res);
        db_release(conn, 0);
        inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        return;
    }

    /* -------------------------------------------------------------------------
     * 2. POST /api/v1/admin/institutions -> Direct create institution
     * ------------------------------------------------------------------------- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/admin/institutions") == 0) {
        if (!is_owner) {
            db_release(conn, 0);
            inst_send_error(client_fd, 403, "Platform owner required to create institutions", origin, extra_headers, extra_len);
            return;
        }

        char name[128] = {0}, code[32] = {0}, email[120] = {0};
        char phone[32] = {0}, region[64] = {0}, tz[40] = {0};
        char plan[40] = {0}, model[32] = {0}, domains_raw[512] = {0};
        int max_c = 5, max_cd = 500, ret = 365;

        ctrl_json_string(body, "name", name, sizeof(name));
        ctrl_json_string(body, "code", code, sizeof(code));
        ctrl_json_string(body, "contactEmail", email, sizeof(email));
        if (!email[0]) ctrl_json_string(body, "contact_email", email, sizeof(email));
        ctrl_json_string(body, "contactPhone", phone, sizeof(phone));
        if (!phone[0]) ctrl_json_string(body, "contact_phone", phone, sizeof(phone));
        ctrl_json_string(body, "region", region, sizeof(region));
        ctrl_json_string(body, "timezone", tz, sizeof(tz));
        ctrl_json_string(body, "plan", plan, sizeof(plan));
        ctrl_json_string(body, "deploymentModel", model, sizeof(model));
        if (!model[0]) ctrl_json_string(body, "deployment_model", model, sizeof(model));
        ctrl_json_int(body, "retention_days", &ret);
        ctrl_json_int(body, "maxCenters", &max_c);
        if (max_c == 5) ctrl_json_int(body, "max_centers", &max_c);
        ctrl_json_int(body, "maxCandidates", &max_cd);
        if (max_cd == 500) ctrl_json_int(body, "max_candidates", &max_cd);

        if (!ctrl_json_raw(body, "domains", domains_raw, sizeof(domains_raw))) {
            char d_str[256] = {0};
            ctrl_json_string(body, "domains", d_str, sizeof(d_str));
            if (d_str[0]) snprintf(domains_raw, sizeof(domains_raw), "[\"%s\"]", d_str);
            else snprintf(domains_raw, sizeof(domains_raw), "[]");
        }

        sanitize_utf8(name);
        sanitize_utf8(code);
        sanitize_utf8(email);
        sanitize_utf8(phone);
        sanitize_utf8(region);
        sanitize_utf8(tz);
        sanitize_utf8(plan);
        sanitize_utf8(model);
        sanitize_utf8(domains_raw);

        if (!name[0] || !code[0]) {
            db_release(conn, 0);
            inst_send_error(client_fd, 400, "name and code are required", origin, extra_headers, extra_len);
            return;
        }

        /* Check duplicates against tenants and examos_institutions */
        const char *chk[2] = { name, code };
        int clen[2] = { (int)strlen(name), (int)strlen(code) };
        PGresult *dup = db_simple(conn,
            "SELECT id FROM tenants WHERE LOWER(name) = LOWER($1) OR UPPER(code) = UPPER($2) "
            "UNION SELECT institution_id FROM examos_institutions WHERE LOWER(name) = LOWER($1) OR UPPER(code) = UPPER($2)",
            2, chk, clen);
        int dup_found = dup && PQresultStatus(dup) == PGRES_TUPLES_OK && PQntuples(dup) > 0;
        if (dup) PQclear(dup);

        if (dup_found) {
            db_release(conn, 0);
            inst_send_error(client_fd, 409, "Institution name or code already exists", origin, extra_headers, extra_len);
            return;
        }

        char id[64];
        long now_sec = (long)time(NULL);
        snprintf(id, sizeof(id), "ins_%ld_%04d", now_sec, rand() % 10000);
        char now[32], valid_until[32];
        snprintf(now, sizeof(now), "%ld000", now_sec);
        snprintf(valid_until, sizeof(valid_until), "%ld000", now_sec + 31536000L);

        char max_c_str[16], max_cd_str[16];
        snprintf(max_c_str, sizeof(max_c_str), "%d", max_c);
        snprintf(max_cd_str, sizeof(max_cd_str), "%d", max_cd);

        const char *pvals[14] = {
            id, name, code, email, phone,
            region[0] ? region : "India · Mumbai",
            tz[0] ? tz : "Asia/Kolkata",
            plan[0] ? plan : "pilot",
            max_c_str, max_cd_str,
            model[0] ? model : "usb-boot",
            now, sess.user_id,
            domains_raw
        };
        int plens[14];
        for (int i = 0; i < 14; i++) plens[i] = pvals[i] ? (int)strlen(pvals[i]) : 0;

        PGresult *ins = db_simple(conn,
            "INSERT INTO tenants (id, name, code, contact_email, contact_phone, "
            "region, timezone, plan, status, max_centers, max_candidates, "
            "deployment_model, created_at, created_by, domains, exam_defaults, security, notification_prefs, history) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9::integer,$10::integer,$11,$12::bigint,$13::varchar,$14::jsonb,"
            "'{\"durationMin\":60,\"lateEntryMin\":15,\"attestationLevel\":\"tpm\"}'::jsonb,"
            "'{\"requireTpm\":true,\"requireSecureBoot\":true,\"allowUsbStorage\":false}'::jsonb,"
            "'{\"email\":true,\"inApp\":true}'::jsonb,"
            "jsonb_build_array(jsonb_build_object('at',$12::bigint,'by',$13::varchar,'action','Institution registered')))",
            14, pvals, plens);
        int ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
        if (!ok) {
            fprintf(stderr, "[INST DB ERROR] %s\n", PQerrorMessage(conn));
        }
        if (ins) PQclear(ins);

        /* Dual sync to examos_institutions and initialize related modules */
        if (ok) {
            char ret_str[16]; snprintf(ret_str, sizeof(ret_str), "%d", ret);
            const char *sync_vals[5] = { id, name, code, email, ret_str };
            int sync_lens[5];
            for (int i = 0; i < 5; i++) sync_lens[i] = (int)strlen(sync_vals[i]);
            PGresult *sync_res = db_simple(conn,
                "INSERT INTO examos_institutions (institution_id, name, code, domain_email, retention_days, active) "
                "VALUES ($1,$2,$3,$4,$5::integer,true) "
                "ON CONFLICT (institution_id) DO UPDATE SET name = EXCLUDED.name, code = EXCLUDED.code, "
                "domain_email = EXCLUDED.domain_email, retention_days = EXCLUDED.retention_days, active = true",
                5, sync_vals, sync_lens);
            if (sync_res) PQclear(sync_res);

            /* Seed Agreement */
            char agr_id[64]; snprintf(agr_id, sizeof(agr_id), "agr_%ld_%04d", now_sec, rand() % 10000);
            const char *av[4] = { agr_id, id, plan[0] ? plan : "pilot", now };
            int al[4]; for (int i = 0; i < 4; i++) al[i] = (int)strlen(av[i]);
            PGresult *ar = db_simple(conn,
                "INSERT INTO institution_agreements (id, institution_id, type, title, version, status, terms_payload, audit_trail, created_at) "
                "VALUES ($1, $2, 'msa', 'Master Services Agreement & Exam Security Covenant', '2026.1', 'APPROVED_FOR_ISSUE', "
                "jsonb_build_object('plan',$3::varchar,'sla','99.9% uptime'), jsonb_build_array(jsonb_build_object('at',$4::bigint,'action','Initialized')), $4::bigint) "
                "ON CONFLICT (id) DO NOTHING", 4, av, al);
            if (ar) PQclear(ar);

            /* Seed License */
            char lic_id[64]; snprintf(lic_id, sizeof(lic_id), "lic_%ld_%04d", now_sec, rand() % 10000);
            const char *lv[9] = { lic_id, id, agr_id, plan[0] ? plan : "pilot", now, valid_until, max_c_str, "250", max_cd_str };
            int ll[9]; for (int i = 0; i < 9; i++) ll[i] = (int)strlen(lv[i]);
            PGresult *lr = db_simple(conn,
                "INSERT INTO institution_licenses (id, institution_id, agreement_id, plan, plan_version, status, valid_from, valid_until, "
                "grace_period_days, max_campuses, max_devices, max_candidates, max_exams, allowed_channels, enabled_modules, usage_current, created_at, updated_at) "
                "VALUES ($1, $2, $3, $4, '2026.1', 'ACTIVE', $5::bigint, $6::bigint, 14, $7::integer, $8::integer, $9::integer, 50, "
                "'[\"stable\",\"pilot\"]'::jsonb, '[\"exams\",\"kiosk\",\"tpm\",\"firewall\"]'::jsonb, '{\"campuses\":1,\"devices\":0,\"candidates\":0,\"exams\":0}'::jsonb, $5::bigint, $5::bigint) "
                "ON CONFLICT (institution_id) DO NOTHING", 9, lv, ll);
            if (lr) PQclear(lr);

            /* Seed Onboarding */
            const char *ov[3] = { id, email, now };
            int ol[3]; for (int i = 0; i < 3; i++) ol[i] = (int)strlen(ov[i]);
            PGresult *obr = db_simple(conn,
                "INSERT INTO institution_onboarding (institution_id, status, checklist, completed_steps, total_steps, first_admin_email, first_admin_invited, mfa_enforced, updated_at) "
                "VALUES ($1, 'VERIFIED', jsonb_build_object("
                "'registration', jsonb_build_object('completed', true),"
                "'identity_verification', jsonb_build_object('completed', true),"
                "'agreement', jsonb_build_object('completed', false),"
                "'license', jsonb_build_object('completed', true),"
                "'admin_mfa', jsonb_build_object('completed', false),"
                "'campus_hierarchy', jsonb_build_object('completed', true),"
                "'os_deployment', jsonb_build_object('completed', true),"
                "'production_readiness', jsonb_build_object('completed', false)"
                "), 4, 8, $2, 1, 1, $3::bigint) ON CONFLICT (institution_id) DO NOTHING", 3, ov, ol);
            if (obr) PQclear(obr);

            /* Seed Main Campus */
            char cmp_id[64]; snprintf(cmp_id, sizeof(cmp_id), "cmp_%ld_%04d", now_sec, rand() % 10000);
            const char *cv[4] = { cmp_id, id, now, now };
            int cl_lens[4]; for (int i = 0; i < 4; i++) cl_lens[i] = (int)strlen(cv[i]);
            PGresult *cmr = db_simple(conn,
                "INSERT INTO campuses (id, tenant_id, name, code, address, capacity, status, created_at, updated_at) "
                "VALUES ($1, $2, 'Main Campus', 'MAIN', 'Campus Headquarters', 250, 'active', $3::bigint, $4::bigint) "
                "ON CONFLICT (id) DO NOTHING", 4, cv, cl_lens);
            if (cmr) PQclear(cmr);

            /* Seed OS Deployment */
            char dep_id[64]; snprintf(dep_id, sizeof(dep_id), "dep_%ld_%04d", now_sec, rand() % 10000);
            const char *dv[5] = { dep_id, id, cmp_id, now, now };
            int dl[5]; for (int i = 0; i < 5; i++) dl[i] = (int)strlen(dv[i]);
            PGresult *dpr = db_simple(conn,
                "INSERT INTO institution_os_deployments (id, institution_id, campus_id, release_id, channel, "
                "hardware_profile, security_profile, status, policy_hash, devices_targeted, devices_acknowledged, created_at, updated_at) "
                "VALUES ($1, $2, $3, 'examos-dev-0.1', 'stable', 'standard-uefi', 'high-assurance', 'ACTIVE', 'sha256-policy-default', 0, 0, $4::bigint, $5::bigint) "
                "ON CONFLICT (id) DO NOTHING", 5, dv, dl);
            if (dpr) PQclear(dpr);
        }

        if (!ok) {
            db_release(conn, 0);
            inst_send_error(client_fd, 503, "Failed to persist institution in database", origin, extra_headers, extra_len);
            return;
        }

        audit_and_ledger(sess.user_id, "TENANT_CREATED", id, name);
        char resp[256];
        snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"institution_id\":\"%s\"}", id);
        db_release(conn, 0);
        inst_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        return;
    }

    /* -------------------------------------------------------------------------
     * 3. Institution Subpaths: /api/v1/admin/institutions/:id/...
     * ------------------------------------------------------------------------- */
    char inst_id[64] = {0}, sub[64] = {0};
    if (extract_inst_id_and_sub(path, inst_id, sizeof(inst_id), sub, sizeof(sub))) {
        /* Multi-tenant scope enforcement */
        if (!is_owner && strcmp(sess.institution_id, inst_id) != 0) {
            db_release(conn, 0);
            inst_send_error(client_fd, 403, "Access denied: institution boundary violation", origin, extra_headers, extra_len);
            return;
        }

        /* 3a. GET /api/v1/admin/institutions/:id/stats */
        if (strcmp(method, "GET") == 0 && strcmp(sub, "stats") == 0) {
            const char *pvals[1] = { inst_id };
            int lens[1] = { (int)strlen(inst_id) };
            PGresult *res = db_simple(conn,
                "SELECT "
                "  (SELECT COUNT(*) FROM campuses WHERE tenant_id = $1) AS campuses, "
                "  (SELECT COUNT(*) FROM departments WHERE tenant_id = $1) AS departments, "
                "  (SELECT COUNT(*) FROM centers WHERE tenant_id = $1) AS centers, "
                "  (SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND status = 'active') AS users, "
                "  (SELECT COUNT(*) FROM devices WHERE tenant_id = $1) AS devices, "
                "  (SELECT COUNT(*) FROM devices WHERE tenant_id = $1 AND status = 'enrolled') AS enrolled_devices, "
                "  (SELECT COUNT(*) FROM candidates WHERE tenant_id = $1) AS candidates, "
                "  (SELECT COUNT(*) FROM exams WHERE tenant_id = $1) AS exams, "
                "  (SELECT COUNT(*) FROM exams WHERE tenant_id = $1 AND status = 'live') AS live_exams, "
                "  (SELECT COUNT(*) FROM exams WHERE tenant_id = $1 AND status = 'published') AS published_exams, "
                "  (SELECT COUNT(*) FROM incidents WHERE tenant_id = $1 AND status IN ('open','investigating','contained')) AS open_incidents",
                1, pvals, lens);

            char resp[1024] = {0};
            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                snprintf(resp, sizeof(resp),
                    "{\"campuses\":%s,\"departments\":%s,\"centers\":%s,\"users\":%s,\"devices\":%s,"
                    "\"enrolledDevices\":%s,\"candidates\":%s,\"exams\":%s,\"liveExams\":%s,"
                    "\"publishedExams\":%s,\"openIncidents\":%s}",
                    PQgetvalue(res, 0, 0), PQgetvalue(res, 0, 1), PQgetvalue(res, 0, 2),
                    PQgetvalue(res, 0, 3), PQgetvalue(res, 0, 4), PQgetvalue(res, 0, 5),
                    PQgetvalue(res, 0, 6), PQgetvalue(res, 0, 7), PQgetvalue(res, 0, 8),
                    PQgetvalue(res, 0, 9), PQgetvalue(res, 0, 10));
            } else {
                snprintf(resp, sizeof(resp),
                    "{\"campuses\":0,\"departments\":0,\"centers\":0,\"users\":0,\"devices\":0,"
                    "\"enrolledDevices\":0,\"candidates\":0,\"exams\":0,\"liveExams\":0,\"publishedExams\":0,\"openIncidents\":0}");
            }
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 3b. POST /api/v1/admin/institutions/:id/status */
        if (strcmp(method, "POST") == 0 && strcmp(sub, "status") == 0) {
            if (!is_owner) {
                db_release(conn, 0);
                inst_send_error(client_fd, 403, "Platform owner permission required to change tenant status", origin, extra_headers, extra_len);
                return;
            }

            char st[32] = {0}, reason[256] = {0};
            ctrl_json_string(body, "status", st, sizeof(st));
            ctrl_json_string(body, "reason", reason, sizeof(reason));

            if (strcmp(st, "active") != 0 && strcmp(st, "suspended") != 0 && strcmp(st, "archived") != 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "Invalid status: must be active, suspended, or archived", origin, extra_headers, extra_len);
                return;
            }
            if (strlen(reason) < 8) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "A valid reason of at least 8 characters is required for status change", origin, extra_headers, extra_len);
                return;
            }

            /* Business rules validation */
            if (strcmp(st, "suspended") == 0) {
                PGresult *c_act = PQexec(conn, "SELECT COUNT(*) FROM tenants WHERE status = 'active'");
                if (c_act && PQresultStatus(c_act) == PGRES_TUPLES_OK && atoi(PQgetvalue(c_act, 0, 0)) <= 1) {
                    PQclear(c_act); db_release(conn, 0);
                    inst_send_error(client_fd, 400, "Cannot suspend the last active institution", origin, extra_headers, extra_len);
                    return;
                }
                if (c_act) PQclear(c_act);

                const char *chk_live[1] = { inst_id };
                int chk_lens[1] = { (int)strlen(inst_id) };
                PGresult *c_live = db_simple(conn, "SELECT COUNT(*) FROM exams WHERE tenant_id = $1 AND status = 'live'", 1, chk_live, chk_lens);
                if (c_live && PQresultStatus(c_live) == PGRES_TUPLES_OK && atoi(PQgetvalue(c_live, 0, 0)) > 0) {
                    PQclear(c_live); db_release(conn, 0);
                    inst_send_error(client_fd, 400, "Close live exams before suspending this institution", origin, extra_headers, extra_len);
                    return;
                }
                if (c_live) PQclear(c_live);
            }

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            const char *u_vals[5] = { st, now, sess.user_id, reason, inst_id };
            int u_lens[5];
            for (int i = 0; i < 5; i++) u_lens[i] = (int)strlen(u_vals[i]);

            PGresult *u_res = db_simple(conn,
                "UPDATE tenants SET status = $1, "
                "history = history || jsonb_build_array(jsonb_build_object('at',$2::bigint,'by',$3::varchar,'action',('Status -> ' || $1)::varchar,'reason',$4::varchar)) "
                "WHERE id = $5", 5, u_vals, u_lens);
            int ok = u_res && PQresultStatus(u_res) == PGRES_COMMAND_OK;
            (void)ok;
            if (u_res) PQclear(u_res);

            if (ok) {
                const char *s_vals[2] = { strcmp(st, "active") == 0 ? "true" : "false", inst_id };
                int s_lens[2] = { (int)strlen(s_vals[0]), (int)strlen(s_vals[1]) };
                PGresult *s_res = db_simple(conn, "UPDATE examos_institutions SET active = $1::boolean WHERE institution_id = $2", 2, s_vals, s_lens);
                if (s_res) PQclear(s_res);
            }

            char evt[64]; snprintf(evt, sizeof(evt), "TENANT_%s", st);
            audit_and_ledger(sess.user_id, evt, inst_id, reason);

            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"institution_id\":\"%s\",\"current_status\":\"%s\"}", inst_id, st);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 3c. POST /api/v1/admin/institutions/:id/exam-defaults */
        if (strcmp(method, "POST") == 0 && strcmp(sub, "exam-defaults") == 0) {
            int duration = 60, late_entry = 15;
            char attestation[32] = {0};
            ctrl_json_int(body, "durationMin", &duration);
            if (duration == 60) ctrl_json_int(body, "duration_min", &duration);
            ctrl_json_int(body, "lateEntryMin", &late_entry);
            if (late_entry == 15) ctrl_json_int(body, "late_entry_min", &late_entry);
            ctrl_json_string(body, "attestationLevel", attestation, sizeof(attestation));
            if (!attestation[0]) ctrl_json_string(body, "attestation_level", attestation, sizeof(attestation));
            if (!attestation[0]) snprintf(attestation, sizeof(attestation), "tpm");

            char defs_json[256];
            snprintf(defs_json, sizeof(defs_json),
                "{\"durationMin\":%d,\"lateEntryMin\":%d,\"attestationLevel\":\"%s\"}",
                duration, late_entry, attestation);

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            const char *vals[4] = { defs_json, now, sess.user_id, inst_id };
            int vlens[4]; for (int i = 0; i < 4; i++) vlens[i] = (int)strlen(vals[i]);

            PGresult *res = db_simple(conn,
                "UPDATE tenants SET exam_defaults = $1::jsonb, "
                "history = history || jsonb_build_array(jsonb_build_object('at',$2::bigint,'by',$3::varchar,'action','Exam defaults updated')) "
                "WHERE id = $4", 4, vals, vlens);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "TENANT_EXAM_DEFAULTS", inst_id, defs_json);
            db_release(conn, 0);

            char resp[512];
            snprintf(resp, sizeof(resp), "{\"status\":\"saved\",\"exam_defaults\":%s}", defs_json);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 3d. POST /api/v1/admin/institutions/:id/security */
        if (strcmp(method, "POST") == 0 && strcmp(sub, "security") == 0) {
            int req_tpm = 1, req_sb = 1, allow_usb = 0;
            ctrl_json_bool(body, "requireTpm", &req_tpm);
            ctrl_json_bool(body, "requireSecureBoot", &req_sb);
            ctrl_json_bool(body, "allowUsbStorage", &allow_usb);

            char sec_json[256];
            snprintf(sec_json, sizeof(sec_json),
                "{\"requireTpm\":%s,\"requireSecureBoot\":%s,\"allowUsbStorage\":%s}",
                req_tpm ? "true" : "false", req_sb ? "true" : "false", allow_usb ? "true" : "false");

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            const char *vals[4] = { sec_json, now, sess.user_id, inst_id };
            int vlens[4]; for (int i = 0; i < 4; i++) vlens[i] = (int)strlen(vals[i]);

            PGresult *res = db_simple(conn,
                "UPDATE tenants SET security = $1::jsonb, "
                "history = history || jsonb_build_array(jsonb_build_object('at',$2::bigint,'by',$3::varchar,'action','Security defaults updated')) "
                "WHERE id = $4", 4, vals, vlens);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "TENANT_SECURITY_UPDATED", inst_id, sec_json);
            db_release(conn, 0);

            char resp[512];
            snprintf(resp, sizeof(resp), "{\"status\":\"saved\",\"security\":%s}", sec_json);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 3e. Agreements: GET /api/v1/admin/institutions/:id/agreements */
        if (strcmp(method, "GET") == 0 && strcmp(sub, "agreements") == 0) {
            const char *pvals[1] = { inst_id };
            int lens[1] = { (int)strlen(inst_id) };
            PGresult *res = db_simple(conn,
                "SELECT id, institution_id, type, title, version, status, "
                "       document_digest, signer_name, signer_email, signer_role, "
                "       signed_at, effective_from, effective_until, terms_payload, "
                "       audit_trail, created_at "
                "FROM institution_agreements WHERE institution_id = $1 ORDER BY created_at DESC",
                1, pvals, lens);

            char json[65536] = {0};
            size_t pos = 0;
            pos += snprintf(json + pos, sizeof(json) - pos, "{\"agreements\":[");
            int n = (res && PQresultStatus(res) == PGRES_TUPLES_OK) ? PQntuples(res) : 0;
            for (int i = 0; i < n; i++) {
                if (i > 0 && pos < sizeof(json) - 1) pos += snprintf(json + pos, sizeof(json) - pos, ",");
                char id_esc[64] = {0}, title_esc[256] = {0}, digest_esc[128] = {0};
                char sname[120] = {0}, semail[120] = {0}, srole[80] = {0};

                escape_json_str(PQgetvalue(res, i, 0), id_esc, sizeof(id_esc));
                escape_json_str(PQgetvalue(res, i, 3), title_esc, sizeof(title_esc));
                escape_json_str(PQgetvalue(res, i, 6), digest_esc, sizeof(digest_esc));
                escape_json_str(PQgetvalue(res, i, 7), sname, sizeof(sname));
                escape_json_str(PQgetvalue(res, i, 8), semail, sizeof(semail));
                escape_json_str(PQgetvalue(res, i, 9), srole, sizeof(srole));

                const char *terms = PQgetvalue(res, i, 13);
                if (!terms || !terms[0]) terms = "{}";
                const char *audit = PQgetvalue(res, i, 14);
                if (!audit || !audit[0]) audit = "[]";

                pos += snprintf(json + pos, sizeof(json) - pos,
                    "{\"id\":\"%s\",\"institutionId\":\"%s\",\"type\":\"%s\",\"title\":\"%s\","
                    "\"version\":\"%s\",\"status\":\"%s\",\"documentDigest\":\"%s\","
                    "\"signerName\":\"%s\",\"signerEmail\":\"%s\",\"signerRole\":\"%s\","
                    "\"signedAt\":%s,\"effectiveFrom\":%s,\"effectiveUntil\":%s,"
                    "\"termsPayload\":%s,\"auditTrail\":%s,\"createdAt\":%s}",
                    id_esc, PQgetvalue(res, i, 1), PQgetvalue(res, i, 2), title_esc,
                    PQgetvalue(res, i, 4), PQgetvalue(res, i, 5), digest_esc,
                    sname, semail, srole,
                    PQgetvalue(res, i, 10)[0] ? PQgetvalue(res, i, 10) : "null",
                    PQgetvalue(res, i, 11)[0] ? PQgetvalue(res, i, 11) : "null",
                    PQgetvalue(res, i, 12)[0] ? PQgetvalue(res, i, 12) : "null",
                    terms, audit, PQgetvalue(res, i, 15));
            }
            snprintf(json + pos, sizeof(json) - pos, "]}");
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            return;
        }

        /* 3f. Create Agreement Draft: POST /api/v1/admin/institutions/:id/agreements */
        if (strcmp(method, "POST") == 0 && strcmp(sub, "agreements") == 0) {
            char type[60] = {0}, title[160] = {0}, version[20] = {0}, terms_raw[4096] = {0};
            ctrl_json_string(body, "type", type, sizeof(type));
            if (!type[0]) snprintf(type, sizeof(type), "msa");
            ctrl_json_string(body, "title", title, sizeof(title));
            if (!title[0]) snprintf(title, sizeof(title), "Master Services Agreement");
            ctrl_json_string(body, "version", version, sizeof(version));
            if (!version[0]) snprintf(version, sizeof(version), "1.0");

            if (!ctrl_json_raw(body, "termsPayload", terms_raw, sizeof(terms_raw))) {
                if (!ctrl_json_raw(body, "terms", terms_raw, sizeof(terms_raw)))
                    snprintf(terms_raw, sizeof(terms_raw), "{}");
            }

            char agr_id[64];
            snprintf(agr_id, sizeof(agr_id), "agr_%ld_%04d", (long)time(NULL), rand() % 10000);
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            char sql[10240];
            char escaped_terms[4096];
            escape_sql_str(terms_raw, escaped_terms, sizeof(escaped_terms));

            snprintf(sql, sizeof(sql),
                "INSERT INTO institution_agreements (id, institution_id, type, title, version, status, terms_payload, audit_trail, created_at) "
                "VALUES ('%s', '%s', '%s', '%s', '%s', 'DRAFT', '%s'::jsonb, "
                "jsonb_build_array(jsonb_build_object('at',%s::bigint,'by','%s','action','Draft created')), %s::bigint)",
                agr_id, inst_id, type, title, version, escaped_terms, now, sess.user_id, now);

            PGresult *res = PQexec(conn, sql);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to create agreement draft", origin, extra_headers, extra_len);
                return;
            }

            audit_and_ledger(sess.user_id, "AGREEMENT_DRAFT_CREATED", agr_id, title);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"agreement_id\":\"%s\"}", agr_id);
            inst_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 3g. License Details: GET /api/v1/admin/institutions/:id/license */
        if (strcmp(method, "GET") == 0 && strcmp(sub, "license") == 0) {
            const char *pvals[1] = { inst_id };
            int lens[1] = { (int)strlen(inst_id) };
            PGresult *res = db_simple(conn,
                "SELECT id, institution_id, agreement_id, plan, plan_version, status, "
                "       valid_from, valid_until, grace_period_days, max_campuses, "
                "       max_devices, max_candidates, max_exams, allowed_channels, "
                "       enabled_modules, usage_current, created_at, updated_at "
                "FROM institution_licenses WHERE institution_id = $1", 1, pvals, lens);

            /* Also query live dynamic usage metrics */
            PGresult *u_res = db_simple(conn,
                "SELECT "
                "  (SELECT COUNT(*) FROM campuses WHERE tenant_id = $1) AS campuses, "
                "  (SELECT COUNT(*) FROM devices WHERE tenant_id = $1) AS devices, "
                "  (SELECT COUNT(*) FROM candidates WHERE tenant_id = $1) AS candidates, "
                "  (SELECT COUNT(*) FROM exams WHERE tenant_id = $1) AS exams", 1, pvals, lens);

            char u_live[256];
            if (u_res && PQresultStatus(u_res) == PGRES_TUPLES_OK && PQntuples(u_res) > 0) {
                snprintf(u_live, sizeof(u_live),
                    "{\"campuses\":%s,\"devices\":%s,\"candidates\":%s,\"exams\":%s}",
                    PQgetvalue(u_res, 0, 0), PQgetvalue(u_res, 0, 1),
                    PQgetvalue(u_res, 0, 2), PQgetvalue(u_res, 0, 3));
            } else {
                snprintf(u_live, sizeof(u_live), "{\"campuses\":0,\"devices\":0,\"candidates\":0,\"exams\":0}");
            }
            if (u_res) PQclear(u_res);

            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                const char *channels = PQgetvalue(res, 0, 13);
                if (!channels || !channels[0]) channels = "[\"stable\",\"pilot\"]";
                const char *modules = PQgetvalue(res, 0, 14);
                if (!modules || !modules[0]) modules = "[\"exams\",\"kiosk\",\"tpm\",\"firewall\"]";

                char json[4096];
                snprintf(json, sizeof(json),
                    "{\"id\":\"%s\",\"institutionId\":\"%s\",\"agreementId\":\"%s\","
                    "\"plan\":\"%s\",\"planVersion\":\"%s\",\"status\":\"%s\","
                    "\"validFrom\":%s,\"validUntil\":%s,\"gracePeriodDays\":%s,"
                    "\"maxCampuses\":%s,\"maxDevices\":%s,\"maxCandidates\":%s,\"maxExams\":%s,"
                    "\"allowedChannels\":%s,\"enabledModules\":%s,\"usage\":%s,"
                    "\"createdAt\":%s,\"updatedAt\":%s}",
                    PQgetvalue(res, 0, 0), PQgetvalue(res, 0, 1), PQgetvalue(res, 0, 2),
                    PQgetvalue(res, 0, 3), PQgetvalue(res, 0, 4), PQgetvalue(res, 0, 5),
                    PQgetvalue(res, 0, 6), PQgetvalue(res, 0, 7), PQgetvalue(res, 0, 8),
                    PQgetvalue(res, 0, 9), PQgetvalue(res, 0, 10), PQgetvalue(res, 0, 11),
                    PQgetvalue(res, 0, 12), channels, modules, u_live,
                    PQgetvalue(res, 0, 16), PQgetvalue(res, 0, 17));

                PQclear(res);
                db_release(conn, 0);
                inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
                return;
            }
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_error(client_fd, 404, "No active license found for this institution", origin, extra_headers, extra_len);
            return;
        }

        /* 3h. Update License: POST /api/v1/admin/institutions/:id/license */
        if (strcmp(method, "POST") == 0 && strcmp(sub, "license") == 0) {
            if (!is_owner) {
                db_release(conn, 0);
                inst_send_error(client_fd, 403, "Platform owner required to update license terms", origin, extra_headers, extra_len);
                return;
            }

            char plan[40] = {0}, status[40] = {0};
            int max_c = -1, max_d = -1, max_cand = -1, max_ex = -1;
            ctrl_json_string(body, "plan", plan, sizeof(plan));
            ctrl_json_string(body, "status", status, sizeof(status));
            ctrl_json_int(body, "maxCampuses", &max_c);
            ctrl_json_int(body, "maxDevices", &max_d);
            ctrl_json_int(body, "maxCandidates", &max_cand);
            ctrl_json_int(body, "maxExams", &max_ex);

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            char sql[1024];
            snprintf(sql, sizeof(sql),
                "UPDATE institution_licenses SET "
                "plan = COALESCE(NULLIF('%s',''), plan), "
                "status = COALESCE(NULLIF('%s',''), status), "
                "max_campuses = CASE WHEN %d >= 0 THEN %d ELSE max_campuses END, "
                "max_devices = CASE WHEN %d >= 0 THEN %d ELSE max_devices END, "
                "max_candidates = CASE WHEN %d >= 0 THEN %d ELSE max_candidates END, "
                "max_exams = CASE WHEN %d >= 0 THEN %d ELSE max_exams END, "
                "updated_at = %s::bigint "
                "WHERE institution_id = '%s'",
                plan, status, max_c, max_c, max_d, max_d, max_cand, max_cand, max_ex, max_ex, now, inst_id);

            PGresult *res = PQexec(conn, sql);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "INSTITUTION_LICENSE_UPDATED", inst_id, plan[0] ? plan : "limits");
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"updated\",\"institution_id\":\"%s\"}", inst_id);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 3i. Entitlement Check: GET /api/v1/admin/institutions/:id/entitlements/check */
        if (strcmp(method, "GET") == 0 && strncmp(sub, "entitlements/check", 18) == 0) {
            char res_type[32] = {0};
            ctrl_json_string(body, "resource", res_type, sizeof(res_type));
            if (!res_type[0]) {
                const char *q = strstr(path, "resource=");
                if (q) {
                    sscanf(q + 9, "%31[^& \t\r\n]", res_type);
                }
            }
            if (!res_type[0]) snprintf(res_type, sizeof(res_type), "exams");

            const char *pvals[1] = { inst_id };
            int lens[1] = { (int)strlen(inst_id) };
            PGresult *res = db_simple(conn,
                "SELECT status, valid_until, grace_period_days, max_campuses, max_devices, max_candidates, max_exams "
                "FROM institution_licenses WHERE institution_id = $1", 1, pvals, lens);

            int allowed = 1;
            int limit = 100, current = 0;
            char reason[256] = "Entitlement valid and within limits";

            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                const char *st = PQgetvalue(res, 0, 0);
                long valid_until = atol(PQgetvalue(res, 0, 1));
                int grace = atoi(PQgetvalue(res, 0, 2));
                long now_sec = (long)time(NULL) * 1000L;
                long grace_ms = (long)grace * 86400000L;

                if (strcmp(st, "ACTIVE") != 0 && strcmp(st, "EXPIRING") != 0) {
                    allowed = 0;
                    snprintf(reason, sizeof(reason), "License status is %s", st);
                } else if (now_sec > (valid_until + grace_ms)) {
                    allowed = 0;
                    snprintf(reason, sizeof(reason), "License validity period and grace period have expired");
                }

                if (strcmp(res_type, "campuses") == 0) limit = atoi(PQgetvalue(res, 0, 3));
                else if (strcmp(res_type, "devices") == 0) limit = atoi(PQgetvalue(res, 0, 4));
                else if (strcmp(res_type, "candidates") == 0) limit = atoi(PQgetvalue(res, 0, 5));
                else limit = atoi(PQgetvalue(res, 0, 6)); /* exams */
            } else {
                allowed = 0;
                snprintf(reason, sizeof(reason), "No active license registered for institution");
            }
            if (res) PQclear(res);

            /* Query live usage for requested resource */
            char csql[256];
            if (strcmp(res_type, "campuses") == 0)
                snprintf(csql, sizeof(csql), "SELECT COUNT(*) FROM campuses WHERE tenant_id = '%s'", inst_id);
            else if (strcmp(res_type, "devices") == 0)
                snprintf(csql, sizeof(csql), "SELECT COUNT(*) FROM devices WHERE tenant_id = '%s'", inst_id);
            else if (strcmp(res_type, "candidates") == 0)
                snprintf(csql, sizeof(csql), "SELECT COUNT(*) FROM candidates WHERE tenant_id = '%s'", inst_id);
            else
                snprintf(csql, sizeof(csql), "SELECT COUNT(*) FROM exams WHERE tenant_id = '%s'", inst_id);

            PGresult *cres = PQexec(conn, csql);
            if (cres && PQresultStatus(cres) == PGRES_TUPLES_OK && PQntuples(cres) > 0) {
                current = atoi(PQgetvalue(cres, 0, 0));
            }
            if (cres) PQclear(cres);

            if (allowed && current >= limit) {
                allowed = 0;
                snprintf(reason, sizeof(reason), "Quota exceeded: %d of %d %s allocated", current, limit, res_type);
            }

            db_release(conn, 0);
            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"allowed\":%s,\"resource\":\"%s\",\"usage\":%d,\"limit\":%d,\"reason\":\"%s\"}",
                allowed ? "true" : "false", res_type, current, limit, reason);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 3j. OS Deployments: GET /api/v1/admin/institutions/:id/deployments */
        if (strcmp(method, "GET") == 0 && strcmp(sub, "deployments") == 0) {
            const char *pvals[1] = { inst_id };
            int lens[1] = { (int)strlen(inst_id) };
            PGresult *res = db_simple(conn,
                "SELECT id, institution_id, campus_id, release_id, channel, "
                "       hardware_profile, security_profile, status, policy_hash, "
                "       devices_targeted, devices_acknowledged, created_at, updated_at "
                "FROM institution_os_deployments WHERE institution_id = $1 ORDER BY created_at DESC",
                1, pvals, lens);

            char json[32768] = {0};
            size_t pos = 0;
            pos += snprintf(json + pos, sizeof(json) - pos, "{\"deployments\":[");
            int n = (res && PQresultStatus(res) == PGRES_TUPLES_OK) ? PQntuples(res) : 0;
            for (int i = 0; i < n; i++) {
                if (i > 0 && pos < sizeof(json) - 1) pos += snprintf(json + pos, sizeof(json) - pos, ",");
                char id_esc[64] = {0}, hash_esc[128] = {0};
                escape_json_str(PQgetvalue(res, i, 0), id_esc, sizeof(id_esc));
                escape_json_str(PQgetvalue(res, i, 8), hash_esc, sizeof(hash_esc));

                pos += snprintf(json + pos, sizeof(json) - pos,
                    "{\"id\":\"%s\",\"institutionId\":\"%s\",\"campusId\":\"%s\","
                    "\"releaseId\":\"%s\",\"channel\":\"%s\",\"hardwareProfile\":\"%s\","
                    "\"securityProfile\":\"%s\",\"status\":\"%s\",\"policyHash\":\"%s\","
                    "\"devicesTargeted\":%s,\"devicesAcknowledged\":%s,\"createdAt\":%s,\"updatedAt\":%s}",
                    id_esc, PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                    PQgetvalue(res, i, 3), PQgetvalue(res, i, 4), PQgetvalue(res, i, 5),
                    PQgetvalue(res, i, 6), PQgetvalue(res, i, 7), hash_esc,
                    PQgetvalue(res, i, 9)[0] ? PQgetvalue(res, i, 9) : "0",
                    PQgetvalue(res, i, 10)[0] ? PQgetvalue(res, i, 10) : "0",
                    PQgetvalue(res, i, 11), PQgetvalue(res, i, 12));
            }
            snprintf(json + pos, sizeof(json) - pos, "]}");
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            return;
        }

        /* 3k. Assign OS Deployment: POST /api/v1/admin/institutions/:id/deployments */
        if (strcmp(method, "POST") == 0 && strcmp(sub, "deployments") == 0) {
            char campus_id[64] = {0}, release_id[64] = {0}, channel[40] = {0};
            char hw_prof[60] = {0}, sec_prof[60] = {0}, pol_hash[128] = {0};

            ctrl_json_string(body, "campusId", campus_id, sizeof(campus_id));
            ctrl_json_string(body, "releaseId", release_id, sizeof(release_id));
            if (!release_id[0]) snprintf(release_id, sizeof(release_id), "examos-dev-0.1");
            ctrl_json_string(body, "channel", channel, sizeof(channel));
            if (!channel[0]) snprintf(channel, sizeof(channel), "stable");
            ctrl_json_string(body, "hardwareProfile", hw_prof, sizeof(hw_prof));
            if (!hw_prof[0]) snprintf(hw_prof, sizeof(hw_prof), "standard-uefi");
            ctrl_json_string(body, "securityProfile", sec_prof, sizeof(sec_prof));
            if (!sec_prof[0]) snprintf(sec_prof, sizeof(sec_prof), "high-assurance");
            ctrl_json_string(body, "policyHash", pol_hash, sizeof(pol_hash));
            if (!pol_hash[0]) snprintf(pol_hash, sizeof(pol_hash), "sha256-policy-default");

            char dep_id[64]; snprintf(dep_id, sizeof(dep_id), "dep_%ld_%04d", (long)time(NULL), rand() % 10000);
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            const char *dv[9] = { dep_id, inst_id, campus_id, release_id, channel, hw_prof, sec_prof, pol_hash, now };
            int dl[9]; for (int i = 0; i < 9; i++) dl[i] = (int)strlen(dv[i]);

            PGresult *res = db_simple(conn,
                "INSERT INTO institution_os_deployments (id, institution_id, campus_id, release_id, channel, "
                "hardware_profile, security_profile, status, policy_hash, devices_targeted, devices_acknowledged, created_at, updated_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, 'ACTIVE', $8, 0, 0, $9::bigint, $9::bigint)",
                9, dv, dl);

            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to assign OS deployment", origin, extra_headers, extra_len);
                return;
            }

            audit_and_ledger(sess.user_id, "OS_DEPLOYMENT_ASSIGNED", dep_id, release_id);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"assigned\",\"deployment_id\":\"%s\"}", dep_id);
            inst_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 3l. Guided Onboarding Checklist: GET /api/v1/admin/institutions/:id/onboarding */
        if (strcmp(method, "GET") == 0 && strcmp(sub, "onboarding") == 0) {
            const char *pvals[1] = { inst_id };
            int lens[1] = { (int)strlen(inst_id) };
            PGresult *res = db_simple(conn,
                "SELECT status, checklist, completed_steps, total_steps, "
                "       first_admin_email, first_admin_invited, mfa_enforced, updated_at "
                "FROM institution_onboarding WHERE institution_id = $1", 1, pvals, lens);

            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                const char *chk = PQgetvalue(res, 0, 1);
                if (!chk || !chk[0]) chk = "{}";

                char json[8192];
                snprintf(json, sizeof(json),
                    "{\"institutionId\":\"%s\",\"status\":\"%s\",\"checklist\":%s,"
                    "\"completedSteps\":%s,\"totalSteps\":%s,\"firstAdminEmail\":\"%s\","
                    "\"firstAdminInvited\":%s,\"mfaEnforced\":%s,\"updatedAt\":%s}",
                    inst_id, PQgetvalue(res, 0, 0), chk,
                    PQgetvalue(res, 0, 2), PQgetvalue(res, 0, 3),
                    PQgetvalue(res, 0, 4),
                    PQgetvalue(res, 0, 5)[0] ? PQgetvalue(res, 0, 5) : "1",
                    PQgetvalue(res, 0, 6)[0] ? PQgetvalue(res, 0, 6) : "1",
                    PQgetvalue(res, 0, 7));

                PQclear(res);
                db_release(conn, 0);
                inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
                return;
            }
            if (res) PQclear(res);

            /* Auto-initialize onboarding record if missing */
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            const char *ov[3] = { inst_id, "admin@examos.local", now };
            int ol[3]; for (int i = 0; i < 3; i++) ol[i] = (int)strlen(ov[i]);
            PGresult *ires = db_simple(conn,
                "INSERT INTO institution_onboarding (institution_id, status, checklist, completed_steps, total_steps, "
                "first_admin_email, first_admin_invited, mfa_enforced, updated_at) "
                "VALUES ($1, 'VERIFIED', jsonb_build_object("
                "'registration', jsonb_build_object('completed', true),"
                "'identity_verification', jsonb_build_object('completed', true),"
                "'agreement', jsonb_build_object('completed', false),"
                "'license', jsonb_build_object('completed', true),"
                "'admin_mfa', jsonb_build_object('completed', false),"
                "'campus_hierarchy', jsonb_build_object('completed', true),"
                "'os_deployment', jsonb_build_object('completed', true),"
                "'production_readiness', jsonb_build_object('completed', false)"
                "), 4, 8, $2, 1, 1, $3::bigint) "
                "ON CONFLICT (institution_id) DO UPDATE SET updated_at = EXCLUDED.updated_at "
                "RETURNING status, checklist, completed_steps, total_steps, first_admin_email, first_admin_invited, mfa_enforced, updated_at",
                3, ov, ol);

            if (ires && PQresultStatus(ires) == PGRES_TUPLES_OK && PQntuples(ires) > 0) {
                char json[8192];
                snprintf(json, sizeof(json),
                    "{\"institutionId\":\"%s\",\"status\":\"%s\",\"checklist\":%s,"
                    "\"completedSteps\":%s,\"totalSteps\":%s,\"firstAdminEmail\":\"%s\","
                    "\"firstAdminInvited\":%s,\"mfaEnforced\":%s,\"updatedAt\":%s}",
                    inst_id, PQgetvalue(ires, 0, 0), PQgetvalue(ires, 0, 1),
                    PQgetvalue(ires, 0, 2), PQgetvalue(ires, 0, 3),
                    PQgetvalue(ires, 0, 4), PQgetvalue(ires, 0, 5),
                    PQgetvalue(ires, 0, 6), PQgetvalue(ires, 0, 7));
                PQclear(ires);
                db_release(conn, 0);
                inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
                return;
            }
            if (ires) PQclear(ires);
            db_release(conn, 0);
            inst_send_error(client_fd, 500, "Unable to load onboarding checklist", origin, extra_headers, extra_len);
            return;
        }

        /* 3m. Update Onboarding Step: POST /api/v1/admin/institutions/:id/onboarding/step */
        if (strcmp(method, "POST") == 0 && strcmp(sub, "onboarding/step") == 0) {
            char step_key[64] = {0}, notes[256] = {0};
            int completed = 1;
            ctrl_json_string(body, "stepKey", step_key, sizeof(step_key));
            if (!step_key[0]) ctrl_json_string(body, "step", step_key, sizeof(step_key));
            ctrl_json_bool(body, "completed", &completed);
            ctrl_json_string(body, "notes", notes, sizeof(notes));

            if (!step_key[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "stepKey is required", origin, extra_headers, extra_len);
                return;
            }

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            char sql[2048];
            snprintf(sql, sizeof(sql),
                "UPDATE institution_onboarding SET "
                "checklist = jsonb_set(checklist, '{%s}', jsonb_build_object('completed', %s, 'at', %s::bigint, 'by', '%s', 'notes', '%s')), "
                "updated_at = %s::bigint "
                "WHERE institution_id = '%s' "
                "RETURNING checklist",
                step_key, completed ? "true" : "false", now, sess.user_id, notes, now, inst_id);

            PGresult *res = PQexec(conn, sql);
            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                /* Count completed steps */
                char count_sql[1024];
                snprintf(count_sql, sizeof(count_sql),
                    "UPDATE institution_onboarding SET "
                    "completed_steps = (SELECT count(*) FROM jsonb_each(checklist) WHERE value->>'completed' = 'true'), "
                    "status = CASE "
                    "  WHEN (SELECT count(*) FROM jsonb_each(checklist) WHERE value->>'completed' = 'true') >= 8 THEN 'ACTIVE' "
                    "  WHEN (SELECT count(*) FROM jsonb_each(checklist) WHERE value->>'completed' = 'true') >= 6 THEN 'CONFIGURED' "
                    "  WHEN (SELECT count(*) FROM jsonb_each(checklist) WHERE value->>'completed' = 'true') >= 4 THEN 'LICENSED' "
                    "  ELSE 'VERIFIED' "
                    "END "
                    "WHERE institution_id = '%s' RETURNING status, completed_steps", inst_id);

                PGresult *cres = PQexec(conn, count_sql);
                char new_status[64] = "CONFIGURED", c_steps[16] = "5";
                if (cres && PQresultStatus(cres) == PGRES_TUPLES_OK && PQntuples(cres) > 0) {
                    snprintf(new_status, sizeof(new_status), "%s", PQgetvalue(cres, 0, 0));
                    snprintf(c_steps, sizeof(c_steps), "%s", PQgetvalue(cres, 0, 1));
                }
                if (cres) PQclear(cres);
                PQclear(res);

                audit_and_ledger(sess.user_id, "ONBOARDING_STEP_UPDATED", inst_id, step_key);
                db_release(conn, 0);

                char resp[512];
                snprintf(resp, sizeof(resp),
                    "{\"status\":\"updated\",\"institution_id\":\"%s\",\"step\":\"%s\","
                    "\"lifecycle_status\":\"%s\",\"completed_steps\":%s}",
                    inst_id, step_key, new_status, c_steps);
                inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                return;
            }
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_error(client_fd, 500, "Failed to update onboarding step", origin, extra_headers, extra_len);
            return;
        }

        /* 3n. GET /api/v1/admin/institutions/:id -> Get single institution */
        if (strcmp(method, "GET") == 0 && !sub[0]) {
            const char *pvals[1] = { inst_id };
            int lens[1] = { (int)strlen(inst_id) };
            PGresult *res = db_simple(conn,
                "SELECT id, name, code, status, plan, region, timezone, "
                "       max_centers, max_candidates, deployment_model, created_at, "
                "       contact_email, contact_phone, domains, exam_defaults, "
                "       security, notification_prefs "
                "FROM tenants WHERE id = $1", 1, pvals, lens);

            char json[8192] = {0};
            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                inst_list_json(res, json, sizeof(json));
                /* Unwrap list to single object */
                if (strncmp(json, "{\"institutions\":[", 17) == 0) {
                    size_t jlen = strlen(json);
                    if (jlen > 18) {
                        json[jlen - 2] = '\0'; /* drop ]} */
                        memmove(json, json + 17, jlen - 16);
                    }
                }
            } else {
                snprintf(json, sizeof(json), "{\"error\":\"Institution not found\"}");
            }
            if (res) PQclear(res);
            db_release(conn, 0);
            int code = (json[0] == '{' && strstr(json, "\"error\"")) ? 404 : 200;
            inst_send_json(client_fd, code, json, origin, extra_headers, extra_len);
            return;
        }

        /* 3o. PUT or POST /api/v1/admin/institutions/:id -> Update settings */
        if ((strcmp(method, "PUT") == 0 || strcmp(method, "POST") == 0) && !sub[0]) {
            char name[128] = {0}, email[120] = {0}, phone[32] = {0};
            char region[64] = {0}, tz[40] = {0}, model[32] = {0}, plan[40] = {0};
            char domains_raw[512] = {0};
            int max_c = -1, max_cd = -1;

            ctrl_json_string(body, "name", name, sizeof(name));
            ctrl_json_string(body, "contactEmail", email, sizeof(email));
            if (!email[0]) ctrl_json_string(body, "contact_email", email, sizeof(email));
            ctrl_json_string(body, "contactPhone", phone, sizeof(phone));
            if (!phone[0]) ctrl_json_string(body, "contact_phone", phone, sizeof(phone));
            ctrl_json_string(body, "region", region, sizeof(region));
            ctrl_json_string(body, "timezone", tz, sizeof(tz));
            ctrl_json_string(body, "deploymentModel", model, sizeof(model));
            if (!model[0]) ctrl_json_string(body, "deployment_model", model, sizeof(model));
            if (is_owner) ctrl_json_string(body, "plan", plan, sizeof(plan));

            ctrl_json_int(body, "maxCenters", &max_c);
            if (max_c == -1) ctrl_json_int(body, "max_centers", &max_c);
            ctrl_json_int(body, "maxCandidates", &max_cd);
            if (max_cd == -1) ctrl_json_int(body, "max_candidates", &max_cd);

            if (!ctrl_json_raw(body, "domains", domains_raw, sizeof(domains_raw))) {
                char d_str[256] = {0};
                ctrl_json_string(body, "domains", d_str, sizeof(d_str));
                if (d_str[0]) snprintf(domains_raw, sizeof(domains_raw), "[\"%s\"]", d_str);
            }

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            char plan_clause[128] = {0}, dom_clause[600] = {0};
            if (plan[0]) snprintf(plan_clause, sizeof(plan_clause), "plan = '%s', ", plan);
            if (domains_raw[0]) snprintf(dom_clause, sizeof(dom_clause), "domains = '%s'::jsonb, ", domains_raw);

            char sql[1536];
            snprintf(sql, sizeof(sql),
                "UPDATE tenants SET "
                "name = COALESCE(NULLIF('%s',''), name), "
                "contact_email = COALESCE(NULLIF('%s',''), contact_email), "
                "contact_phone = COALESCE(NULLIF('%s',''), contact_phone), "
                "region = COALESCE(NULLIF('%s',''), region), "
                "timezone = COALESCE(NULLIF('%s',''), timezone), "
                "deployment_model = COALESCE(NULLIF('%s',''), deployment_model), "
                "%s%s"
                "history = history || jsonb_build_array(jsonb_build_object('at',%s::bigint,'by','%s','action','Institution settings updated')) "
                "WHERE id = '%s'",
                name, email, phone, region, tz, model,
                plan_clause, dom_clause,
                now, sess.user_id, inst_id);

            PGresult *res = PQexec(conn, sql);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            if (name[0]) {
                char s_sql[512];
                snprintf(s_sql, sizeof(s_sql),
                    "UPDATE examos_institutions SET name = '%s' WHERE institution_id = '%s'",
                    name, inst_id);
                PGresult *s_res = PQexec(conn, s_sql);
                if (s_res) PQclear(s_res);
            }

            audit_and_ledger(sess.user_id, "TENANT_UPDATED", inst_id, name[0] ? name : "settings");
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"updated\",\"institution_id\":\"%s\"}", inst_id);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }
    }

    /* -------------------------------------------------------------------------
     * Standalone Digital Agreements: POST /api/v1/admin/agreements/:id/sign
     * ------------------------------------------------------------------------- */
    if (strncmp(path, "/api/v1/admin/agreements/", 25) == 0) {
        char agr_id[64] = {0}, act[32] = {0};
        extract_sub_id_and_action(path, "/api/v1/admin/agreements/", agr_id, sizeof(agr_id), act, sizeof(act));

        if (strcmp(method, "POST") == 0 && strcmp(act, "sign") == 0) {
            char signer_name[120] = {0}, signer_email[120] = {0}, signer_role[80] = {0};
            ctrl_json_string(body, "signerName", signer_name, sizeof(signer_name));
            ctrl_json_string(body, "signerEmail", signer_email, sizeof(signer_email));
            ctrl_json_string(body, "signerRole", signer_role, sizeof(signer_role));

            if (!signer_name[0] || !signer_email[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "signerName and signerEmail are required for digital signature", origin, extra_headers, extra_len);
                return;
            }

            long now_sec = (long)time(NULL);
            char now_ms[32], valid_until_ms[32];
            snprintf(now_ms, sizeof(now_ms), "%ld000", now_sec);
            snprintf(valid_until_ms, sizeof(valid_until_ms), "%ld000", now_sec + 31536000L);

            /* Generate SHA256 document digest over agreement id, signer, and timestamp */
            char sign_payload[512];
            snprintf(sign_payload, sizeof(sign_payload), "%s:%s:%s:%s:%s",
                agr_id, signer_name, signer_email, signer_role, now_ms);

            char digest[128] = {0};
            compute_sha256_hex(sign_payload, digest, sizeof(digest));

            const char *u_vals[7] = { signer_name, signer_email, signer_role, now_ms, digest, valid_until_ms, agr_id };
            int u_lens[7]; for (int i = 0; i < 7; i++) u_lens[i] = (int)strlen(u_vals[i]);

            PGresult *res = db_simple(conn,
                "UPDATE institution_agreements SET "
                "status = 'EXECUTED', signer_name = $1, signer_email = $2, signer_role = $3, "
                "signed_at = $4::bigint, document_digest = $5::text, effective_from = $4::bigint, effective_until = $6::bigint, "
                "audit_trail = audit_trail || jsonb_build_array(jsonb_build_object('at',$4::bigint,'by',$2::varchar,'action','Digitally executed','digest',$5::text)) "
                "WHERE id = $7 RETURNING institution_id", 7, u_vals, u_lens);

            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char affected_inst[64] = {0};
                snprintf(affected_inst, sizeof(affected_inst), "%s", PQgetvalue(res, 0, 0));
                PQclear(res);

                /* Automatically advance agreement step on onboarding checklist */
                if (affected_inst[0]) {
                    char onb_up[1024];
                    snprintf(onb_up, sizeof(onb_up),
                        "UPDATE institution_onboarding SET "
                        "checklist = jsonb_set(checklist, '{agreement}', jsonb_build_object('completed', true, 'at', %s::bigint, 'digest', '%s')), "
                        "completed_steps = (SELECT count(*) FROM jsonb_each(checklist) WHERE value->>'completed' = 'true'), "
                        "updated_at = %s::bigint WHERE institution_id = '%s'",
                        now_ms, digest, now_ms, affected_inst);
                    PGresult *or = PQexec(conn, onb_up);
                    if (or) PQclear(or);
                }

                audit_and_ledger(sess.user_id, "AGREEMENT_DIGITALLY_SIGNED", agr_id, digest);
                db_release(conn, 0);

                char resp[512];
                snprintf(resp, sizeof(resp),
                    "{\"status\":\"executed\",\"agreement_id\":\"%s\",\"document_digest\":\"%s\",\"signed_at\":%s}",
                    agr_id, digest, now_ms);
                inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                return;
            }
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_error(client_fd, 404, "Agreement not found", origin, extra_headers, extra_len);
            return;
        }
    }

    /* -------------------------------------------------------------------------
     * Standalone Deployment Status: POST /api/v1/admin/deployments/:id/status
     * ------------------------------------------------------------------------- */
    if (strncmp(path, "/api/v1/admin/deployments/", 26) == 0) {
        char dep_id[64] = {0}, act[32] = {0};
        extract_sub_id_and_action(path, "/api/v1/admin/deployments/", dep_id, sizeof(dep_id), act, sizeof(act));

        if (strcmp(method, "POST") == 0 && strcmp(act, "status") == 0) {
            char st[40] = {0};
            int ack = -1;
            ctrl_json_string(body, "status", st, sizeof(st));
            ctrl_json_int(body, "devicesAcknowledged", &ack);

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            char sql[512];
            snprintf(sql, sizeof(sql),
                "UPDATE institution_os_deployments SET "
                "status = COALESCE(NULLIF('%s',''), status), "
                "devices_acknowledged = CASE WHEN %d >= 0 THEN %d ELSE devices_acknowledged END, "
                "updated_at = %s::bigint "
                "WHERE id = '%s'",
                st, ack, ack, now, dep_id);

            PGresult *res = PQexec(conn, sql);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "OS_DEPLOYMENT_STATUS_UPDATED", dep_id, st);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"updated\",\"deployment_id\":\"%s\"}", dep_id);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        if (strcmp(method, "POST") == 0 && (strcmp(act, "push-kiosk") == 0 || strcmp(act, "push") == 0)) {
            char sql[512];
            snprintf(sql, sizeof(sql),
                "SELECT release_id, channel, hardware_profile, security_profile FROM institution_os_deployments WHERE id = '%s'",
                dep_id);
            PGresult *q = PQexec(conn, sql);
            char rel[64] = "examos-2026.1-stable", chan[40] = "stable", sec[60] = "high-assurance";
            if (q && PQresultStatus(q) == PGRES_TUPLES_OK && PQntuples(q) > 0) {
                snprintf(rel, sizeof(rel), "%s", PQgetvalue(q, 0, 0));
                snprintf(chan, sizeof(chan), "%s", PQgetvalue(q, 0, 1));
                snprintf(sec, sizeof(sec), "%s", PQgetvalue(q, 0, 2));
            }
            if (q) PQclear(q);

            int target_count = kiosk_get_active_count();
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            snprintf(sql, sizeof(sql),
                "UPDATE institution_os_deployments SET status = 'ACTIVE', devices_targeted = %d, updated_at = %s::bigint WHERE id = '%s'",
                target_count, now, dep_id);
            PGresult *u = PQexec(conn, sql);
            if (u) PQclear(u);

            kiosk_broadcast_os_update(rel, chan, sec);
            audit_and_ledger(sess.user_id, "OS_DEPLOYMENT_PUSHED_TO_KIOSK", dep_id, rel);
            db_release(conn, 0);

            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"PUSHED\",\"deployment_id\":\"%s\",\"release_id\":\"%s\",\"channel\":\"%s\",\"security_profile\":\"%s\",\"devices_targeted\":%d,\"message\":\"OS deployment successfully pushed and synchronized to live ExamOS Kiosk Fleet\"}",
                dep_id, rel, chan, sec, target_count);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }
    }

    /* -------------------------------------------------------------------------
     * 4. Campuses Routes: /api/v1/admin/campuses...
     * ------------------------------------------------------------------------- */
    if (strncmp(path, "/api/v1/admin/campuses", 22) == 0) {
        char cmp_id[64] = {0}, act[32] = {0};
        extract_sub_id_and_action(path, "/api/v1/admin/campuses/", cmp_id, sizeof(cmp_id), act, sizeof(act));

        /* 4a. GET /api/v1/admin/campuses */
        if (strcmp(method, "GET") == 0 && !cmp_id[0]) {
            char target_inst[64] = {0};
            if (!is_owner) snprintf(target_inst, sizeof(target_inst), "%s", sess.institution_id);
            else ctrl_json_string(body, "institution_id", target_inst, sizeof(target_inst));

            PGresult *res = NULL;
            if (target_inst[0]) {
                const char *pvals[1] = { target_inst };
                int lens[1] = { (int)strlen(target_inst) };
                res = db_simple(conn,
                    "SELECT id, tenant_id, name, code, city, address, capacity, status, created_at "
                    "FROM campuses WHERE tenant_id = $1 ORDER BY created_at DESC", 1, pvals, lens);
            } else {
                res = PQexec(conn,
                    "SELECT id, tenant_id, name, code, city, address, capacity, status, created_at "
                    "FROM campuses ORDER BY created_at DESC");
            }

            char json[32768] = {0};
            size_t pos = 0;
            pos += snprintf(json + pos, sizeof(json) - pos, "{\"campuses\":[");
            int n = (res && PQresultStatus(res) == PGRES_TUPLES_OK) ? PQntuples(res) : 0;
            for (int i = 0; i < n; i++) {
                if (i > 0 && pos < sizeof(json) - 1) pos += snprintf(json + pos, sizeof(json) - pos, ",");
                char c_id[64] = {0}, c_tid[64] = {0}, c_name[256] = {0}, c_code[64] = {0}, c_city[128] = {0}, c_addr[256] = {0};
                escape_json_str(PQgetvalue(res, i, 0), c_id, sizeof(c_id));
                escape_json_str(PQgetvalue(res, i, 1), c_tid, sizeof(c_tid));
                escape_json_str(PQgetvalue(res, i, 2), c_name, sizeof(c_name));
                escape_json_str(PQgetvalue(res, i, 3), c_code, sizeof(c_code));
                escape_json_str(PQgetvalue(res, i, 4), c_city, sizeof(c_city));
                escape_json_str(PQgetvalue(res, i, 5), c_addr, sizeof(c_addr));

                pos += snprintf(json + pos, sizeof(json) - pos,
                    "{\"id\":\"%s\",\"tenantId\":\"%s\",\"name\":\"%s\",\"code\":\"%s\","
                    "\"city\":\"%s\",\"address\":\"%s\",\"capacity\":%s,\"status\":\"%s\",\"createdAt\":%s}",
                    c_id, c_tid, c_name, c_code, c_city, c_addr,
                    PQgetvalue(res, i, 6)[0] ? PQgetvalue(res, i, 6) : "100",
                    PQgetvalue(res, i, 7)[0] ? PQgetvalue(res, i, 7) : "active",
                    PQgetvalue(res, i, 8)[0] ? PQgetvalue(res, i, 8) : "0");
            }
            snprintf(json + pos, sizeof(json) - pos, "]}");
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            return;
        }

        /* 4b. POST /api/v1/admin/campuses -> Create campus */
        if (strcmp(method, "POST") == 0 && !cmp_id[0]) {
            char tenant_id[64] = {0}, name[128] = {0}, code[32] = {0};
            char city[64] = {0}, address[256] = {0};
            int capacity = 100;

            ctrl_json_string(body, "tenantId", tenant_id, sizeof(tenant_id));
            if (!tenant_id[0]) ctrl_json_string(body, "tenant_id", tenant_id, sizeof(tenant_id));
            ctrl_json_string(body, "name", name, sizeof(name));
            ctrl_json_string(body, "code", code, sizeof(code));
            ctrl_json_string(body, "city", city, sizeof(city));
            ctrl_json_string(body, "address", address, sizeof(address));
            ctrl_json_int(body, "capacity", &capacity);

            if (!is_owner) snprintf(tenant_id, sizeof(tenant_id), "%s", sess.institution_id);

            sanitize_utf8(name);
            sanitize_utf8(code);
            sanitize_utf8(city);
            sanitize_utf8(address);

            if (!name[0] || !tenant_id[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "name and tenantId are required", origin, extra_headers, extra_len);
                return;
            }

            if (!code[0]) {
                snprintf(code, sizeof(code), "CMP-%03d", rand() % 900 + 100);
            }

            char id[64]; snprintf(id, sizeof(id), "cmp_%ld_%04d", (long)time(NULL), rand() % 10000);
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            char cap_str[16]; snprintf(cap_str, sizeof(cap_str), "%d", capacity);

            const char *pvals[8] = { id, tenant_id, name, code, city, address, cap_str, now };
            int plens[8]; for (int i = 0; i < 8; i++) plens[i] = (int)strlen(pvals[i]);

            PGresult *res = db_simple(conn,
                "INSERT INTO campuses (id, tenant_id, name, code, city, address, capacity, status, created_at, updated_at) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7::integer,'active',$8::bigint,$8::bigint)",
                8, pvals, plens);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "CAMPUS_CREATED", id, name);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"campus_id\":\"%s\"}", id);
            inst_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 4c. POST /api/v1/admin/campuses/:id/status -> Status transition */
        if (strcmp(method, "POST") == 0 && strcmp(act, "status") == 0) {
            char st[32] = {0}, reason[256] = {0};
            ctrl_json_string(body, "status", st, sizeof(st));
            ctrl_json_string(body, "reason", reason, sizeof(reason));

            if (strcmp(st, "active") != 0 && strcmp(st, "inactive") != 0 && strcmp(st, "archived") != 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "Invalid campus status: must be active, inactive, or archived", origin, extra_headers, extra_len);
                return;
            }

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            char sql[512];
            snprintf(sql, sizeof(sql),
                "UPDATE campuses SET status = '%s', updated_at = %s::bigint "
                "WHERE id = '%s'%s%s%s",
                st, now, cmp_id,
                !is_owner ? " AND tenant_id = '" : "", !is_owner ? sess.institution_id : "", !is_owner ? "'" : "");

            PGresult *res = PQexec(conn, sql);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "CAMPUS_STATUS_UPDATED", cmp_id, st);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"campus_id\":\"%s\",\"new_status\":\"%s\"}", cmp_id, st);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 4d. PUT or POST /api/v1/admin/campuses/:id -> Update campus */
        if ((strcmp(method, "PUT") == 0 || strcmp(method, "POST") == 0) && cmp_id[0] && !act[0]) {
            char name[128] = {0}, code[32] = {0}, city[64] = {0}, address[256] = {0};
            int capacity = -1;
            ctrl_json_string(body, "name", name, sizeof(name));
            ctrl_json_string(body, "code", code, sizeof(code));
            ctrl_json_string(body, "city", city, sizeof(city));
            ctrl_json_string(body, "address", address, sizeof(address));
            ctrl_json_int(body, "capacity", &capacity);

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            char sql[1024];
            snprintf(sql, sizeof(sql),
                "UPDATE campuses SET "
                "name = COALESCE(NULLIF('%s',''), name), "
                "code = COALESCE(NULLIF('%s',''), code), "
                "city = COALESCE(NULLIF('%s',''), city), "
                "address = COALESCE(NULLIF('%s',''), address), "
                "capacity = CASE WHEN %d >= 0 THEN %d ELSE capacity END, "
                "updated_at = %s::bigint "
                "WHERE id = '%s'%s%s%s",
                name, code, city, address, capacity, capacity, now, cmp_id,
                !is_owner ? " AND tenant_id = '" : "", !is_owner ? sess.institution_id : "", !is_owner ? "'" : "");

            PGresult *res = PQexec(conn, sql);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "CAMPUS_UPDATED", cmp_id, name[0] ? name : "settings");
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"updated\",\"campus_id\":\"%s\"}", cmp_id);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }
    }

    /* -------------------------------------------------------------------------
     * 5. Departments Routes: /api/v1/admin/departments...
     * ------------------------------------------------------------------------- */
    if (strncmp(path, "/api/v1/admin/departments", 25) == 0) {
        char dep_id[64] = {0}, act[32] = {0};
        extract_sub_id_and_action(path, "/api/v1/admin/departments/", dep_id, sizeof(dep_id), act, sizeof(act));

        /* 5a. GET /api/v1/admin/departments */
        if (strcmp(method, "GET") == 0 && !dep_id[0]) {
            char target_inst[64] = {0};
            if (!is_owner) snprintf(target_inst, sizeof(target_inst), "%s", sess.institution_id);
            else ctrl_json_string(body, "institution_id", target_inst, sizeof(target_inst));

            PGresult *res = NULL;
            if (target_inst[0]) {
                const char *pvals[1] = { target_inst };
                int lens[1] = { (int)strlen(target_inst) };
                res = db_simple(conn,
                    "SELECT id, tenant_id, campus_id, name, code, type, status, created_at "
                    "FROM departments WHERE tenant_id = $1 ORDER BY created_at DESC", 1, pvals, lens);
            } else {
                res = PQexec(conn,
                    "SELECT id, tenant_id, campus_id, name, code, type, status, created_at "
                    "FROM departments ORDER BY created_at DESC");
            }

            char json[32768] = {0};
            size_t pos = 0;
            pos += snprintf(json + pos, sizeof(json) - pos, "{\"departments\":[");
            int n = (res && PQresultStatus(res) == PGRES_TUPLES_OK) ? PQntuples(res) : 0;
            for (int i = 0; i < n; i++) {
                if (i > 0 && pos < sizeof(json) - 1) pos += snprintf(json + pos, sizeof(json) - pos, ",");
                char d_id[64] = {0}, d_tid[64] = {0}, d_cid[64] = {0}, d_name[256] = {0}, d_code[64] = {0}, d_type[64] = {0};
                escape_json_str(PQgetvalue(res, i, 0), d_id, sizeof(d_id));
                escape_json_str(PQgetvalue(res, i, 1), d_tid, sizeof(d_tid));
                escape_json_str(PQgetvalue(res, i, 2), d_cid, sizeof(d_cid));
                escape_json_str(PQgetvalue(res, i, 3), d_name, sizeof(d_name));
                escape_json_str(PQgetvalue(res, i, 4), d_code, sizeof(d_code));
                escape_json_str(PQgetvalue(res, i, 5), d_type, sizeof(d_type));

                pos += snprintf(json + pos, sizeof(json) - pos,
                    "{\"id\":\"%s\",\"tenantId\":\"%s\",\"campusId\":\"%s\",\"name\":\"%s\","
                    "\"code\":\"%s\",\"type\":\"%s\",\"status\":\"%s\",\"createdAt\":%s}",
                    d_id, d_tid, d_cid, d_name, d_code,
                    d_type[0] ? d_type : "academic",
                    PQgetvalue(res, i, 6)[0] ? PQgetvalue(res, i, 6) : "active",
                    PQgetvalue(res, i, 7)[0] ? PQgetvalue(res, i, 7) : "0");
            }
            snprintf(json + pos, sizeof(json) - pos, "]}");
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            return;
        }

        /* 5b. POST /api/v1/admin/departments -> Create department */
        if (strcmp(method, "POST") == 0 && !dep_id[0]) {
            char tenant_id[64] = {0}, campus_id[64] = {0}, name[128] = {0}, code[32] = {0}, type[32] = {0};
            ctrl_json_string(body, "tenantId", tenant_id, sizeof(tenant_id));
            if (!tenant_id[0]) ctrl_json_string(body, "tenant_id", tenant_id, sizeof(tenant_id));
            ctrl_json_string(body, "campusId", campus_id, sizeof(campus_id));
            ctrl_json_string(body, "name", name, sizeof(name));
            ctrl_json_string(body, "code", code, sizeof(code));
            ctrl_json_string(body, "type", type, sizeof(type));

            if (!is_owner) snprintf(tenant_id, sizeof(tenant_id), "%s", sess.institution_id);
            if (!name[0] || !tenant_id[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "name and tenantId are required", origin, extra_headers, extra_len);
                return;
            }

            char id[64]; snprintf(id, sizeof(id), "dep_%ld_%04d", (long)time(NULL), rand() % 10000);
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            const char *pvals[7] = { id, tenant_id, campus_id, name, code, type[0] ? type : "academic", now };
            int plens[7]; for (int i = 0; i < 7; i++) plens[i] = (int)strlen(pvals[i]);

            PGresult *res = db_simple(conn,
                "INSERT INTO departments (id, tenant_id, campus_id, name, code, type, status, created_at, updated_at) "
                "VALUES ($1,$2,$3,$4,$5,$6,'active',$7::bigint,$7::bigint)",
                7, pvals, plens);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "DEPARTMENT_CREATED", id, name);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"department_id\":\"%s\"}", id);
            inst_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 5c. POST /api/v1/admin/departments/:id/status -> Status update */
        if (strcmp(method, "POST") == 0 && strcmp(act, "status") == 0) {
            char st[32] = {0};
            ctrl_json_string(body, "status", st, sizeof(st));
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            char sql[512];
            snprintf(sql, sizeof(sql),
                "UPDATE departments SET status = '%s', updated_at = %s::bigint "
                "WHERE id = '%s'%s%s%s",
                st, now, dep_id,
                !is_owner ? " AND tenant_id = '" : "", !is_owner ? sess.institution_id : "", !is_owner ? "'" : "");

            PGresult *res = PQexec(conn, sql);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "DEPARTMENT_STATUS_UPDATED", dep_id, st);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"department_id\":\"%s\"}", dep_id);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }
    }

    /* -------------------------------------------------------------------------
     * 6. Staff Routes: /api/v1/admin/staff...
     * ------------------------------------------------------------------------- */
    if (strncmp(path, "/api/v1/admin/staff", 19) == 0) {
        char stf_id[64] = {0}, act[32] = {0};
        extract_sub_id_and_action(path, "/api/v1/admin/staff/", stf_id, sizeof(stf_id), act, sizeof(act));

        /* 6a. GET /api/v1/admin/staff */
        if (strcmp(method, "GET") == 0 && !stf_id[0]) {
            char target_inst[64] = {0};
            if (!is_owner) snprintf(target_inst, sizeof(target_inst), "%s", sess.institution_id);
            else ctrl_json_string(body, "institution_id", target_inst, sizeof(target_inst));

            PGresult *res = NULL;
            if (target_inst[0]) {
                const char *pvals[1] = { target_inst };
                int lens[1] = { (int)strlen(target_inst) };
                res = db_simple(conn,
                    "SELECT id, tenant_id, user_id, name, role_title, campus_id, department_id, status, created_at, updated_at "
                    "FROM staff WHERE tenant_id = $1 ORDER BY created_at DESC", 1, pvals, lens);
            } else {
                res = PQexec(conn,
                    "SELECT id, tenant_id, user_id, name, role_title, campus_id, department_id, status, created_at, updated_at "
                    "FROM staff ORDER BY created_at DESC");
            }

            char json[32768] = {0};
            size_t pos = 0;
            pos += snprintf(json + pos, sizeof(json) - pos, "{\"staff\":[");
            int n = (res && PQresultStatus(res) == PGRES_TUPLES_OK) ? PQntuples(res) : 0;
            for (int i = 0; i < n; i++) {
                if (i > 0 && pos < sizeof(json) - 1) pos += snprintf(json + pos, sizeof(json) - pos, ",");
                char s_id[64] = {0}, s_tid[64] = {0}, s_uid[64] = {0}, s_name[256] = {0};
                char s_role[128] = {0}, s_cid[64] = {0}, s_did[64] = {0};

                escape_json_str(PQgetvalue(res, i, 0), s_id, sizeof(s_id));
                escape_json_str(PQgetvalue(res, i, 1), s_tid, sizeof(s_tid));
                escape_json_str(PQgetvalue(res, i, 2), s_uid, sizeof(s_uid));
                escape_json_str(PQgetvalue(res, i, 3), s_name, sizeof(s_name));
                escape_json_str(PQgetvalue(res, i, 4), s_role, sizeof(s_role));
                escape_json_str(PQgetvalue(res, i, 5), s_cid, sizeof(s_cid));
                escape_json_str(PQgetvalue(res, i, 6), s_did, sizeof(s_did));

                pos += snprintf(json + pos, sizeof(json) - pos,
                    "{\"id\":\"%s\",\"tenantId\":\"%s\",\"userId\":\"%s\",\"name\":\"%s\","
                    "\"roleTitle\":\"%s\",\"campusId\":\"%s\",\"departmentId\":\"%s\","
                    "\"status\":\"%s\",\"createdAt\":%s,\"updatedAt\":%s}",
                    s_id, s_tid, s_uid, s_name, s_role, s_cid, s_did,
                    PQgetvalue(res, i, 7)[0] ? PQgetvalue(res, i, 7) : "active",
                    PQgetvalue(res, i, 8)[0] ? PQgetvalue(res, i, 8) : "0",
                    PQgetvalue(res, i, 9)[0] ? PQgetvalue(res, i, 9) : "0");
            }
            snprintf(json + pos, sizeof(json) - pos, "]}");
            if (res) PQclear(res);
            db_release(conn, 0);
            inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            return;
        }

        /* 6b. POST /api/v1/admin/staff -> Assign staff */
        if (strcmp(method, "POST") == 0 && !stf_id[0]) {
            char tenant_id[64] = {0}, user_id[64] = {0}, name[128] = {0}, role_title[64] = {0};
            char campus_id[64] = {0}, department_id[64] = {0};
            ctrl_json_string(body, "tenantId", tenant_id, sizeof(tenant_id));
            if (!tenant_id[0]) ctrl_json_string(body, "tenant_id", tenant_id, sizeof(tenant_id));
            ctrl_json_string(body, "userId", user_id, sizeof(user_id));
            ctrl_json_string(body, "name", name, sizeof(name));
            ctrl_json_string(body, "roleTitle", role_title, sizeof(role_title));
            ctrl_json_string(body, "campusId", campus_id, sizeof(campus_id));
            ctrl_json_string(body, "departmentId", department_id, sizeof(department_id));

            if (!is_owner) snprintf(tenant_id, sizeof(tenant_id), "%s", sess.institution_id);
            if (!tenant_id[0] || !user_id[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "tenantId and userId are required", origin, extra_headers, extra_len);
                return;
            }

            /* Lookup user name if missing */
            if (!name[0]) {
                const char *u_vals[1] = { user_id };
                int u_lens[1] = { (int)strlen(user_id) };
                PGresult *u_res = db_simple(conn, "SELECT name, title FROM users WHERE id = $1", 1, u_vals, u_lens);
                if (u_res && PQresultStatus(u_res) == PGRES_TUPLES_OK && PQntuples(u_res) > 0) {
                    snprintf(name, sizeof(name), "%s", PQgetvalue(u_res, 0, 0));
                    if (!role_title[0]) snprintf(role_title, sizeof(role_title), "%s", PQgetvalue(u_res, 0, 1));
                }
                if (u_res) PQclear(u_res);
            }

            char id[64]; snprintf(id, sizeof(id), "stf_%ld_%04d", (long)time(NULL), rand() % 10000);
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            const char *pvals[8] = { id, tenant_id, user_id, name, role_title, campus_id, department_id, now };
            int plens[8]; for (int i = 0; i < 8; i++) plens[i] = (int)strlen(pvals[i]);

            PGresult *res = db_simple(conn,
                "INSERT INTO staff (id, tenant_id, user_id, name, role_title, campus_id, department_id, status, created_at, updated_at) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8::bigint,$8::bigint) "
                "ON CONFLICT (id) DO UPDATE SET campus_id = EXCLUDED.campus_id, department_id = EXCLUDED.department_id, "
                "role_title = EXCLUDED.role_title, status = 'active', updated_at = EXCLUDED.updated_at",
                8, pvals, plens);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "STAFF_ASSIGNED", user_id, campus_id[0] ? campus_id : "all campuses");
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"saved\",\"staff_id\":\"%s\"}", id);
            inst_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 6c. DELETE or POST /api/v1/admin/staff/:id/remove -> Remove staff */
        if ((strcmp(method, "DELETE") == 0 || strcmp(method, "POST") == 0) && stf_id[0]) {
            char reason[256] = {0};
            ctrl_json_string(body, "reason", reason, sizeof(reason));
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            char sql[512];
            snprintf(sql, sizeof(sql),
                "UPDATE staff SET status = 'inactive', status_reason = '%s', updated_at = %s::bigint "
                "WHERE id = '%s'%s%s%s",
                reason, now, stf_id,
                !is_owner ? " AND tenant_id = '" : "", !is_owner ? sess.institution_id : "", !is_owner ? "'" : "");

            PGresult *res = PQexec(conn, sql);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            (void)ok;
            if (res) PQclear(res);

            audit_and_ledger(sess.user_id, "STAFF_REMOVED", stf_id, reason);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"removed\",\"staff_id\":\"%s\"}", stf_id);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }
    }

    db_release(conn, 0);
    inst_send_error(client_fd, 404, "Endpoint not found", origin, extra_headers, extra_len);
}
