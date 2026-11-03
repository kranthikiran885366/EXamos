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
#include <openssl/rand.h>

static void inst_generate_id(const char *prefix, char *out, size_t out_len) {
    unsigned char rnd[6];
    if (RAND_bytes(rnd, sizeof(rnd)) == 1) {
        snprintf(out, out_len, "%s_%ld_%02x%02x%02x%02x", prefix,
                 (long)time(NULL), rnd[0], rnd[1], rnd[2], rnd[3]);
    } else {
        snprintf(out, out_len, "%s_%ld", prefix, (long)time(NULL));
    }
}

static void inst_generate_code(const char *prefix, char *out, size_t out_len) {
    out[0] = '\0';
    unsigned char rnd[2];
    if (RAND_bytes(rnd, sizeof(rnd)) != 1) return;
    unsigned int val = (((unsigned int)rnd[0] << 8) | rnd[1]) % 900 + 100;
    snprintf(out, out_len, "%s-%03u", prefix, val);
}

static void get_latest_os_release_id(PGconn *conn, char *out_release_id, size_t max_len) {
    out_release_id[0] = '\0';
    if (!conn) {
        out_release_id[0] = '\0';
        return;
    }
    PGresult *res = PQexec(conn,
        "SELECT release_id FROM os_releases WHERE status = 'active' ORDER BY created_at DESC LIMIT 1");
    if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && PQgetvalue(res, 0, 0)[0]) {
        snprintf(out_release_id, max_len, "%s", PQgetvalue(res, 0, 0));
    }
    if (res) PQclear(res);
    if (out_release_id[0]) return;

    res = PQexec(conn,
        "SELECT release_id FROM examos_software_releases WHERE status = 'PUBLISHED' ORDER BY release_date DESC LIMIT 1");
    if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && PQgetvalue(res, 0, 0)[0]) {
        snprintf(out_release_id, max_len, "%s", PQgetvalue(res, 0, 0));
    }
    if (res) PQclear(res);
    if (out_release_id[0]) return;

    res = PQexec(conn,
        "SELECT release_id FROM os_releases WHERE status != 'revoked' ORDER BY created_at DESC LIMIT 1");
    if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && PQgetvalue(res, 0, 0)[0]) {
        snprintf(out_release_id, max_len, "%s", PQgetvalue(res, 0, 0));
    }
    if (res) PQclear(res);
    if (out_release_id[0]) return;

    out_release_id[0] = '\0';
}

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
        if (!exam_defs || !exam_defs[0]) exam_defs = "null";
        const char *security = PQgetvalue(res, i, 15);
        if (!security || !security[0]) security = "null";
        const char *notif = PQgetvalue(res, i, 16);
        if (!notif || !notif[0]) notif = "null";

        /* H1 fix: return actual DB values, null for missing fields — no fabrication. */
        pos += snprintf(out + pos, out_len - pos,
            "{\"id\":\"%s\",\"name\":\"%s\",\"code\":\"%s\","
            "\"status\":\"%s\",\"plan\":\"%s\",\"region\":\"%s\","
            "\"timezone\":\"%s\",\"maxCenters\":%s,\"maxCandidates\":%s,"
            "\"deploymentModel\":\"%s\",\"createdAt\":%s,\"contactEmail\":\"%s\","
            "\"contactPhone\":\"%s\",\"domains\":%s,\"examDefaults\":%s,"
            "\"security\":%s,\"notificationPrefs\":%s}",
            id_esc, name_esc, code_esc,
            status_esc[0] ? status_esc : "unknown",
            plan_esc,
            region_esc[0] ? region_esc : "null",
            tz_esc[0] ? tz_esc : "null",
            PQgetvalue(res, i, 7)[0] ? PQgetvalue(res, i, 7) : "0",
            PQgetvalue(res, i, 8)[0] ? PQgetvalue(res, i, 8) : "0",
            model_esc,
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
        /* Reads require any authenticated management role; every mutation
         * requires the institution-administration permission. Previously all
         * methods were authorized with AUTH_PERM_READ, which let read-only
         * auditors change tenant, campus, department and staff records. */
        uint32_t required = (strcmp(method, "GET") == 0)
            ? AUTH_PERM_READ
            : AUTH_PERM_INSTITUTION_ADMIN;
        if (ctrl_authorize(auth_header, required, &sess) != 0) {
            inst_send_error(client_fd, required == AUTH_PERM_READ ? 401 : 403,
                            required == AUTH_PERM_READ
                                ? "Admin credentials required"
                                : "Institution administration permission required",
                            origin, extra_headers, extra_len);
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
        int campus_count = 0, student_count = 0, device_count = 0;
        char deployment_model[40] = {0}, hardware_profile[60] = {0}, plan[40] = {0};
        char docs_raw[4096] = {0}, decl_raw[2048] = {0};

        ctrl_json_string(body, "legalName", legal_name, sizeof(legal_name));
        ctrl_json_string(body, "displayName", display_name, sizeof(display_name));
        if (!display_name[0]) snprintf(display_name, sizeof(display_name), "%s", legal_name);
        ctrl_json_string(body, "entityType", entity_type, sizeof(entity_type));
        ctrl_json_string(body, "registrationNumber", reg_num, sizeof(reg_num));
        ctrl_json_string(body, "country", country, sizeof(country));
        ctrl_json_string(body, "state", state, sizeof(state));
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
        ctrl_json_string(body, "hardwareProfile", hardware_profile, sizeof(hardware_profile));
        ctrl_json_string(body, "plan", plan, sizeof(plan));

        /* Documents and declarations must come from the applicant. An absent
         * declaration is stored as an empty object, never as implied consent. */
        if (!ctrl_json_raw(body, "documents", docs_raw, sizeof(docs_raw))) {
            snprintf(docs_raw, sizeof(docs_raw), "[]");
        }
        if (!ctrl_json_raw(body, "declarations", decl_raw, sizeof(decl_raw))) {
            snprintf(decl_raw, sizeof(decl_raw), "{}");
        }

        /* Corporate / Recruitment-specific fields (migration 025) */
        char company_size[30] = {0}, industry_sector[80] = {0}, tech_stack[512] = {0};
        char hr_contact_name[120] = {0}, hr_contact_email[120] = {0};
        char job_roles_targeted[255] = {0}, linkedin_url[255] = {0}, website_url[255] = {0};
        int hiring_volume = 0, annual_exam_count = 0;

        ctrl_json_string(body, "companySize", company_size, sizeof(company_size));
        ctrl_json_string(body, "industrySector", industry_sector, sizeof(industry_sector));
        ctrl_json_string(body, "techStack", tech_stack, sizeof(tech_stack));
        ctrl_json_string(body, "hrContactName", hr_contact_name, sizeof(hr_contact_name));
        ctrl_json_string(body, "hrContactEmail", hr_contact_email, sizeof(hr_contact_email));
        ctrl_json_string(body, "jobRolesTargeted", job_roles_targeted, sizeof(job_roles_targeted));
        ctrl_json_string(body, "linkedinUrl", linkedin_url, sizeof(linkedin_url));
        ctrl_json_string(body, "websiteUrl", website_url, sizeof(website_url));
        ctrl_json_int(body, "hiringVolume", &hiring_volume);
        ctrl_json_int(body, "annualExamCount", &annual_exam_count);

        /* For corporate entities, also accept hrContactEmail as coordinator email fallback */
        int is_corporate = (strncmp(entity_type, "enterprise", 10) == 0 ||
                            strncmp(entity_type, "technology", 10) == 0 ||
                            strncmp(entity_type, "government", 10) == 0 ||
                            strncmp(entity_type, "testing_agency", 14) == 0);
        if (is_corporate && !coord_email[0] && hr_contact_email[0]) {
            snprintf(coord_email, sizeof(coord_email), "%s", hr_contact_email);
        }
        if (is_corporate && !coord_name[0] && hr_contact_name[0]) {
            snprintf(coord_name, sizeof(coord_name), "%s", hr_contact_name);
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
        {
            unsigned char rnd[6];
            if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
                db_release(conn, 0);
                inst_send_error(client_fd, 503, "Secure ID generation unavailable", origin, extra_headers, extra_len);
                return;
            }
            snprintf(app_id, sizeof(app_id), "app_%ld_%02x%02x%02x",
                     (long)time(NULL), rnd[0], rnd[1], rnd[2]);
        }
        char now[32];
        snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

        char c_cnt[16], s_cnt[16], d_cnt[16];
        snprintf(c_cnt, sizeof(c_cnt), "%d", campus_count);
        snprintf(s_cnt, sizeof(s_cnt), "%d", student_count);
        snprintf(d_cnt, sizeof(d_cnt), "%d", device_count);

        char h_vol[16], a_exam[16];
        snprintf(h_vol, sizeof(h_vol), "%d", hiring_volume);
        snprintf(a_exam, sizeof(a_exam), "%d", annual_exam_count);

        const char *ins_vals[37] = {
            app_id, legal_name, display_name, entity_type, reg_num,
            country, state, address, domain, rep_name,
            rep_role, rep_email, rep_phone, coord_name, coord_email,
            tech_name, tech_email, c_cnt, s_cnt, d_cnt,
            deployment_model, hardware_profile, plan, now, now,
            /* corporate fields */
            company_size[0] ? company_size : "",
            industry_sector[0] ? industry_sector : "",
            h_vol,
            hr_contact_name[0] ? hr_contact_name : "",
            hr_contact_email[0] ? hr_contact_email : "",
            tech_stack[0] ? tech_stack : "",
            linkedin_url[0] ? linkedin_url : "",
            website_url[0] ? website_url : "",
            a_exam,
            job_roles_targeted[0] ? job_roles_targeted : "",
            docs_raw,
            decl_raw
        };
        int ins_lens[37];
        for (int i = 0; i < 37; i++) ins_lens[i] = (int)strlen(ins_vals[i]);

        PGresult *ins = db_simple(conn,
            "INSERT INTO institution_applications ("
            "  id, legal_name, display_name, entity_type, registration_number,"
            "  country, state, address, domain, rep_name,"
            "  rep_role, rep_email, rep_phone, coord_name, coord_email,"
            "  tech_name, tech_email, campus_count, student_count, device_count,"
            "  deployment_model, hardware_profile, plan, status, created_at, updated_at,"
            "  documents, declarations,"
            "  company_size, industry_sector, hiring_volume, hr_contact_name, hr_contact_email,"
            "  tech_stack, linkedin_url, website_url, annual_exam_count, job_roles_targeted"
            ") VALUES ("
            "  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,"
            "  $11,$12,$13,$14,$15,$16,$17,$18::integer,$19::integer,$20::integer,"
            "  $21,$22,$23,'SUBMITTED',$24::bigint,$25::bigint,"
            "  $36::jsonb, $37::jsonb,"
            "  NULLIF($26,''), NULLIF($27,''), $28::integer, NULLIF($29,''), NULLIF($30,''),"
            "  NULLIF($31,''), NULLIF($32,''), NULLIF($33,''), $34::integer, NULLIF($35,'')"
            ")", 37, ins_vals, ins_lens);

        int ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
        if (ins) PQclear(ins);

        /* Schema Self-Heal: if corporate columns are missing, apply schema update and retry */
        if (!ok) {
            fprintf(stderr, "[INST APPLICATION] Primary 37-col insert failed (%s). Attempting schema self-heal...\n", PQerrorMessage(conn));
            PGresult *alt = db_simple(conn,
                "ALTER TABLE institution_applications "
                "ADD COLUMN IF NOT EXISTS company_size VARCHAR(30), "
                "ADD COLUMN IF NOT EXISTS industry_sector VARCHAR(80), "
                "ADD COLUMN IF NOT EXISTS hiring_volume INTEGER DEFAULT 0, "
                "ADD COLUMN IF NOT EXISTS hr_contact_name VARCHAR(120), "
                "ADD COLUMN IF NOT EXISTS hr_contact_email VARCHAR(120), "
                "ADD COLUMN IF NOT EXISTS tech_stack TEXT, "
                "ADD COLUMN IF NOT EXISTS linkedin_url VARCHAR(255), "
                "ADD COLUMN IF NOT EXISTS website_url VARCHAR(255), "
                "ADD COLUMN IF NOT EXISTS annual_exam_count INTEGER DEFAULT 0, "
                "ADD COLUMN IF NOT EXISTS job_roles_targeted TEXT;", 0, NULL, NULL);
            if (alt) PQclear(alt);

            ins = db_simple(conn,
                "INSERT INTO institution_applications ("
                "  id, legal_name, display_name, entity_type, registration_number,"
                "  country, state, address, domain, rep_name,"
                "  rep_role, rep_email, rep_phone, coord_name, coord_email,"
                "  tech_name, tech_email, campus_count, student_count, device_count,"
                "  deployment_model, hardware_profile, plan, status, created_at, updated_at,"
                "  documents, declarations,"
                "  company_size, industry_sector, hiring_volume, hr_contact_name, hr_contact_email,"
                "  tech_stack, linkedin_url, website_url, annual_exam_count, job_roles_targeted"
                ") VALUES ("
                "  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,"
                "  $11,$12,$13,$14,$15,$16,$17,$18::integer,$19::integer,$20::integer,"
                "  $21,$22,$23,'SUBMITTED',$24::bigint,$25::bigint,"
                "  $36::jsonb, $37::jsonb,"
                "  NULLIF($26,''), NULLIF($27,''), $28::integer, NULLIF($29,''), NULLIF($30,''),"
                "  NULLIF($31,''), NULLIF($32,''), NULLIF($33,''), $34::integer, NULLIF($35,'')"
                ")", 37, ins_vals, ins_lens);
            ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
            if (ins) PQclear(ins);
        }

        /* Fallback: insert using 25 standard base columns if extended columns are not available */
        if (!ok) {
            fprintf(stderr, "[INST APPLICATION] Retrying with base columns... (%s)\n", PQerrorMessage(conn));
            const char *base_vals[27];
            int base_lens[27];
            for (int k = 0; k < 25; k++) {
                base_vals[k] = ins_vals[k];
                base_lens[k] = ins_lens[k];
            }
            base_vals[25] = docs_raw;
            base_lens[25] = (int)strlen(docs_raw);
            base_vals[26] = decl_raw;
            base_lens[26] = (int)strlen(decl_raw);
            ins = db_simple(conn,
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
                "  $26::jsonb, $27::jsonb"
                ")", 27, base_vals, base_lens);
            ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
            if (ins) PQclear(ins);
        }

        if (!ok) {
            fprintf(stderr, "[INST APPLICATION ERROR] %s\n", PQerrorMessage(conn));
            db_release(conn, 0);
            inst_send_error(client_fd, 503, "Failed to submit institution application", origin, extra_headers, extra_len);
            return;
        }

        audit_and_ledger("applicant", "INSTITUTION_APPLICATION_SUBMITTED", app_id, legal_name);
        db_release(conn, 0);

        char resp[512];
        /* reference_number is the application_id itself — no fabricated random number */
        snprintf(resp, sizeof(resp),
            "{\"status\":\"submitted\",\"application_id\":\"%s\",\"reference_number\":\"%s\","
            "\"message\":\"Institution application submitted successfully and queued for verification.\"}",
            app_id, app_id);
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
                "SELECT id, legal_name, display_name, entity_type, status, created_at, reviewed_at, "
                "       COALESCE(review_notes, ''), domain, plan, deployment_model "
                "FROM institution_applications WHERE id = $1 OR domain = $1 OR registration_number = $1", 1, pvals, plens);
            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char id_esc[128] = {0}, l_name[256] = {0}, d_name[256] = {0}, st[64] = {0}, notes_esc[512] = {0};
                char dom_esc[128] = {0}, plan_esc[64] = {0}, mod_esc[64] = {0};
                escape_json_str(PQgetvalue(res, 0, 0), id_esc, sizeof(id_esc));
                escape_json_str(PQgetvalue(res, 0, 1), l_name, sizeof(l_name));
                escape_json_str(PQgetvalue(res, 0, 2), d_name, sizeof(d_name));
                escape_json_str(PQgetvalue(res, 0, 4), st, sizeof(st));
                escape_json_str(PQgetvalue(res, 0, 7), notes_esc, sizeof(notes_esc));
                escape_json_str(PQgetvalue(res, 0, 8), dom_esc, sizeof(dom_esc));
                escape_json_str(PQgetvalue(res, 0, 9), plan_esc, sizeof(plan_esc));
                escape_json_str(PQgetvalue(res, 0, 10), mod_esc, sizeof(mod_esc));

                char resp[1024];
                snprintf(resp, sizeof(resp),
                    "{\"id\":\"%s\",\"legalName\":\"%s\",\"displayName\":\"%s\",\"entityType\":\"%s\","
                    "\"status\":\"%s\",\"createdAt\":%s,\"reviewedAt\":%s,\"reviewNotes\":\"%s\","
                    "\"domain\":\"%s\",\"plan\":\"%s\",\"deploymentModel\":\"%s\"}",
                    id_esc, l_name, d_name, PQgetvalue(res, 0, 3), st,
                    PQgetvalue(res, 0, 5)[0] ? PQgetvalue(res, 0, 5) : "0",
                    PQgetvalue(res, 0, 6)[0] ? PQgetvalue(res, 0, 6) : "null",
                    notes_esc, dom_esc, plan_esc, mod_esc);
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

        /* 0d-1. GET Single Application: GET /api/v1/admin/institution-applications/:id */
        if (strcmp(method, "GET") == 0 && act[0] == '\0') {
            if (!is_owner) {
                db_release(conn, 0);
                inst_send_error(client_fd, 403, "Platform owner permission required to view application", origin, extra_headers, extra_len);
                return;
            }
            const char *pvals[1] = { app_id };
            int plens[1] = { (int)strlen(app_id) };
            PGresult *res = db_simple(conn,
                "SELECT id, legal_name, display_name, entity_type, registration_number, "
                "       country, state, address, domain, rep_name, "
                "       rep_role, rep_email, rep_phone, campus_count, student_count, "
                "       device_count, deployment_model, hardware_profile, plan, status, "
                "       COALESCE(review_notes, ''), reviewed_by, reviewed_at, institution_id, created_at, updated_at "
                "FROM institution_applications WHERE id = $1", 1, pvals, plens);
            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char id_esc[64] = {0}, l_name[256] = {0}, d_name[256] = {0}, reg[64] = {0};
                char dom[128] = {0}, r_name[128] = {0}, r_role[128] = {0}, r_email[128] = {0}, r_phone[64] = {0};
                char addr[512] = {0}, hw_prof[128] = {0}, st[64] = {0}, ins_id[64] = {0}, notes[512] = {0};
                escape_json_str(PQgetvalue(res, 0, 0), id_esc, sizeof(id_esc));
                escape_json_str(PQgetvalue(res, 0, 1), l_name, sizeof(l_name));
                escape_json_str(PQgetvalue(res, 0, 2), d_name, sizeof(d_name));
                escape_json_str(PQgetvalue(res, 0, 4), reg, sizeof(reg));
                escape_json_str(PQgetvalue(res, 0, 7), addr, sizeof(addr));
                escape_json_str(PQgetvalue(res, 0, 8), dom, sizeof(dom));
                escape_json_str(PQgetvalue(res, 0, 9), r_name, sizeof(r_name));
                escape_json_str(PQgetvalue(res, 0, 10), r_role, sizeof(r_role));
                escape_json_str(PQgetvalue(res, 0, 11), r_email, sizeof(r_email));
                escape_json_str(PQgetvalue(res, 0, 12), r_phone, sizeof(r_phone));
                escape_json_str(PQgetvalue(res, 0, 17), hw_prof, sizeof(hw_prof));
                escape_json_str(PQgetvalue(res, 0, 19), st, sizeof(st));
                escape_json_str(PQgetvalue(res, 0, 20), notes, sizeof(notes));
                escape_json_str(PQgetvalue(res, 0, 23), ins_id, sizeof(ins_id));

                char json[4096];
                snprintf(json, sizeof(json),
                    "{\"id\":\"%s\",\"legalName\":\"%s\",\"displayName\":\"%s\",\"entityType\":\"%s\","
                    "\"registrationNumber\":\"%s\",\"country\":\"%s\",\"state\":\"%s\",\"address\":\"%s\",\"domain\":\"%s\","
                    "\"repName\":\"%s\",\"repRole\":\"%s\",\"repEmail\":\"%s\",\"repPhone\":\"%s\","
                    "\"campusCount\":%s,\"studentCount\":%s,\"deviceCount\":%s,"
                    "\"deploymentModel\":\"%s\",\"hardwareProfile\":\"%s\",\"plan\":\"%s\",\"status\":\"%s\",\"reviewNotes\":\"%s\","
                    "\"institutionId\":\"%s\",\"createdAt\":%s,\"reviewedAt\":%s}",
                    id_esc, l_name, d_name, PQgetvalue(res, 0, 3),
                    reg, PQgetvalue(res, 0, 5), PQgetvalue(res, 0, 6), addr, dom,
                    r_name, r_role, r_email, r_phone,
                    PQgetvalue(res, 0, 13), PQgetvalue(res, 0, 14), PQgetvalue(res, 0, 15),
                    PQgetvalue(res, 0, 16), hw_prof, PQgetvalue(res, 0, 18), st, notes,
                    ins_id, PQgetvalue(res, 0, 24),
                    PQgetvalue(res, 0, 22)[0] ? PQgetvalue(res, 0, 22) : "null");
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

            for (size_t ai = 0; action_val[ai]; ai++) {
                if (action_val[ai] >= 'a' && action_val[ai] <= 'z') action_val[ai] -= 32;
            }
            if (strcmp(action_val, "APPROVE") == 0) snprintf(action_val, sizeof(action_val), "APPROVED");
            if (strcmp(action_val, "REJECT") == 0) snprintf(action_val, sizeof(action_val), "REJECTED");
            if (strcmp(action_val, "REQUEST_CORRECTIONS") == 0 || strcmp(action_val, "CORRECTIONS_REQUESTED") == 0)
                snprintf(action_val, sizeof(action_val), "MORE_INFORMATION_REQUIRED");
            if (strcmp(action_val, "VERIFIED") == 0) snprintf(action_val, sizeof(action_val), "VERIFICATION_PENDING");

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
            if (u_res) PQclear(u_res);
            if (!ok) { /* H3 fix: check UPDATE result, fail on error. */
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to update application review status", origin, extra_headers, extra_len);
                return;
            }

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

            /* Read application data — now including entity_type and corporate fields */
            PGresult *a_res = db_simple(conn,
                "SELECT display_name, registration_number, country, state, address, domain, "
                "       rep_name, rep_email, rep_phone, campus_count, student_count, device_count, "
                "       deployment_model, plan, institution_id, status, entity_type, "
                "       COALESCE(company_size,''), COALESCE(industry_sector,''), "
                "       COALESCE(hiring_volume::text,'0'), COALESCE(hr_contact_name,''), "
                "       COALESCE(hr_contact_email,''), COALESCE(tech_stack,''), "
                "       COALESCE(website_url,'') "
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
            char state[60] = {0};
            char dom[120] = {0}, r_email[120] = {0}, r_phone[40] = {0}, d_model[40] = {0}, d_plan[40] = {0};
            int c_cnt = atoi(PQgetvalue(a_res, 0, 9));
            int s_cnt = atoi(PQgetvalue(a_res, 0, 10));
            int dev_cnt = atoi(PQgetvalue(a_res, 0, 11));
            snprintf(d_name, sizeof(d_name), "%s", PQgetvalue(a_res, 0, 0));
            snprintf(reg_no, sizeof(reg_no), "%s", PQgetvalue(a_res, 0, 1));
            snprintf(ctry, sizeof(ctry), "%s", PQgetvalue(a_res, 0, 2));
            snprintf(state, sizeof(state), "%s", PQgetvalue(a_res, 0, 3));
            snprintf(addr, sizeof(addr), "%s", PQgetvalue(a_res, 0, 4));
            snprintf(dom, sizeof(dom), "%s", PQgetvalue(a_res, 0, 5));
            snprintf(r_email, sizeof(r_email), "%s", PQgetvalue(a_res, 0, 7));
            snprintf(r_phone, sizeof(r_phone), "%s", PQgetvalue(a_res, 0, 8));
            snprintf(d_model, sizeof(d_model), "%s", PQgetvalue(a_res, 0, 12));
            snprintf(d_plan, sizeof(d_plan), "%s", PQgetvalue(a_res, 0, 13));

            /* Corporate / entity-type fields from application (col 16+) */
            char ent_type[40] = {0}, co_size[30] = {0}, industry[80] = {0};
            char h_vol_s[16] = {0}, hr_name[120] = {0}, hr_email[120] = {0};
            char t_stack[512] = {0}, web_url[255] = {0};
            snprintf(ent_type, sizeof(ent_type), "%s", PQgetvalue(a_res, 0, 16));
            snprintf(co_size,  sizeof(co_size),  "%s", PQgetvalue(a_res, 0, 17));
            snprintf(industry, sizeof(industry), "%s", PQgetvalue(a_res, 0, 18));
            snprintf(h_vol_s,  sizeof(h_vol_s),  "%s", PQgetvalue(a_res, 0, 19)[0] ? PQgetvalue(a_res, 0, 19) : "0");
            snprintf(hr_name,  sizeof(hr_name),  "%s", PQgetvalue(a_res, 0, 20));
            snprintf(hr_email, sizeof(hr_email), "%s", PQgetvalue(a_res, 0, 21));
            snprintf(t_stack,  sizeof(t_stack),  "%s", PQgetvalue(a_res, 0, 22));
            snprintf(web_url,  sizeof(web_url),  "%s", PQgetvalue(a_res, 0, 23));
            PQclear(a_res);

            /* Generate unique institution, agreement, and license identifiers */
            char new_inst_id[64], new_agr_id[64], new_lic_id[64];
            long now_sec = (long)time(NULL);
            {
                unsigned char rnd[15];
                if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
                    db_release(conn, 0);
                    inst_send_error(client_fd, 503, "Secure ID generation unavailable", origin, extra_headers, extra_len);
                    return;
                }
                snprintf(new_inst_id, sizeof(new_inst_id), "ins_%ld_%02x%02x", now_sec, rnd[0], rnd[1]);
                snprintf(new_agr_id, sizeof(new_agr_id), "agr_%ld_%02x%02x", now_sec, rnd[2], rnd[3]);
                snprintf(new_lic_id, sizeof(new_lic_id), "lic_%ld_%02x%02x", now_sec, rnd[4], rnd[5]);
            }

            char code[32] = {0};
            char pfx[8] = {0};
            for (size_t ci = 0; d_name[ci] && strlen(pfx) < 4; ci++) {
                char ch = d_name[ci];
                if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
                    pfx[strlen(pfx)] = (ch >= 'a' && ch <= 'z') ? (ch - 32) : ch;
                }
            }
            if (strlen(pfx) < 3) snprintf(pfx, sizeof(pfx), "INS");
            inst_generate_code(pfx, code, sizeof(code));
            if (!code[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 503, "Secure institution code generation unavailable", origin, extra_headers, extra_len);
                return;
            }

            char now_ms[32], valid_until_ms[32];
            snprintf(now_ms, sizeof(now_ms), "%ld000", now_sec);
            snprintf(valid_until_ms, sizeof(valid_until_ms), "%ld000", now_sec + 31536000L); /* 1 year */

            /* Transactional multi-table provisioning */
            PQexec(conn, "BEGIN");

            /* 1. Insert Tenant */
            char dom_json[256];
            snprintf(dom_json, sizeof(dom_json), "[\"%s\"]", dom);
            char c_str[16], s_str[16];
            snprintf(c_str, sizeof(c_str), "%d", c_cnt);
            snprintf(s_str, sizeof(s_str), "%d", s_cnt);

            const char *t_vals[22] = {
                new_inst_id, d_name, code, r_email, r_phone,
                state, "", d_plan,
                c_str, s_str, d_model, now_ms,
                /* M8 fix: created_by uses the real session user_id, not 'admin'. */
                sess.user_id, dom_json,
                /* corporate fields */
                ent_type,
                co_size[0]  ? co_size  : "",
                industry[0] ? industry : "",
                h_vol_s,
                hr_name[0]  ? hr_name  : "",
                hr_email[0] ? hr_email : "",
                t_stack[0]  ? t_stack  : "",
                web_url[0]  ? web_url  : ""
            };
            int t_lens[22]; for (int i = 0; i < 22; i++) t_lens[i] = (int)strlen(t_vals[i]);

            PGresult *t_ins = db_simple(conn,
                "INSERT INTO tenants (id, name, code, contact_email, contact_phone, "
                "region, timezone, plan, status, max_centers, max_candidates, "
                "deployment_model, created_at, created_by, domains, exam_defaults, security, notification_prefs, history,"
                "entity_type, company_size, industry_sector, hiring_volume, hr_contact_name, hr_contact_email, tech_stack, website_url) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9::integer,$10::integer,$11,$12::bigint,$13::varchar,$14::jsonb,"
                "'{}'::jsonb, '{}'::jsonb, '{}'::jsonb, "
                "jsonb_build_array(jsonb_build_object('at',$12::bigint,'by',$13::varchar,'action','Provisioned from Application')),"
                "$15, NULLIF($16,''), NULLIF($17,''), $18::integer, NULLIF($19,''), NULLIF($20,''), NULLIF($21,''), NULLIF($22,''))",
                22, t_vals, t_lens);

            /* 2. Dual-sync examos_institutions */
            const char *s_vals[4] = { new_inst_id, d_name, code, r_email };
            int s_lens[4]; for (int i = 0; i < 4; i++) s_lens[i] = (int)strlen(s_vals[i]);
            PGresult *s_ins = db_simple(conn,
                "INSERT INTO examos_institutions (institution_id, name, code, domain_email, retention_days, active) "
                "VALUES ($1,$2,$3,$4,0,true) ON CONFLICT (institution_id) DO UPDATE SET active = true",
                4, s_vals, s_lens);

            /* 3. Agreement Draft — issued, not yet executed. Terms carry only
             * the plan; no invented SLA or support tier. */
            const char *agr_vals[4] = { new_agr_id, new_inst_id, d_plan, now_ms };
            int agr_lens[4]; for (int i = 0; i < 4; i++) agr_lens[i] = (int)strlen(agr_vals[i]);
            PGresult *agr_ins = db_simple(conn,
                "INSERT INTO institution_agreements (id, institution_id, type, title, version, status, terms_payload, audit_trail, created_at) "
                "VALUES ($1, $2, 'msa', 'Master Services Agreement & Exam Security Covenant', '2026.1', 'DRAFT', "
                "jsonb_build_object('plan',$3::varchar), "
                "jsonb_build_array(jsonb_build_object('at',$4::bigint,'by','platform_owner','action','Draft issued for electronic execution')), $4::bigint)",
                4, agr_vals, agr_lens);

            /* 4. Enforceable License */
            char dev_str[16]; snprintf(dev_str, sizeof(dev_str), "%d", dev_cnt > 0 ? dev_cnt : 0);
            const char *lic_vals[9] = { new_lic_id, new_inst_id, new_agr_id, d_plan, now_ms, valid_until_ms, c_str, dev_str, s_str };
            int lic_lens[9]; for (int i = 0; i < 9; i++) lic_lens[i] = (int)strlen(lic_vals[i]);
            PGresult *lic_ins = db_simple(conn,
                "INSERT INTO institution_licenses (id, institution_id, agreement_id, plan, plan_version, status, "
                "valid_from, valid_until, grace_period_days, max_campuses, max_devices, max_candidates, max_exams, "
                "allowed_channels, enabled_modules, usage_current, created_at, updated_at) "
                "VALUES ($1, $2, $3, $4, '2026.1', 'ACTIVE', $5::bigint, $6::bigint, 0, $7::integer, $8::integer, $9::integer, 0, "
                "'[]'::jsonb, '[]'::jsonb, "
                "'{\"campuses\":0,\"devices\":0,\"candidates\":0,\"exams\":0}'::jsonb, $5::bigint, $5::bigint)",
                9, lic_vals, lic_lens);

            /* 5. Guided Onboarding State Record — record only what actually
             * happened during provisioning. */
            const char *first_admin = r_email[0] ? r_email : (hr_email[0] ? hr_email : "");
            const char *onb_vals[4] = { new_inst_id, first_admin, now_ms, app_id };
            int onb_lens[4]; for (int i = 0; i < 4; i++) onb_lens[i] = (int)strlen(onb_vals[i]);
            PGresult *onb_ins = db_simple(conn,
                "INSERT INTO institution_onboarding (institution_id, status, checklist, completed_steps, total_steps, "
                "first_admin_email, first_admin_invited, mfa_enforced, updated_at) "
                "VALUES ($1, 'VERIFIED', jsonb_build_object("
                "'registration', jsonb_build_object('completed', true, 'ref', $4::varchar),"
                "'identity_verification', jsonb_build_object('completed', true, 'ref', 'application approved'),"
                "'agreement', jsonb_build_object('completed', false),"
                "'license', jsonb_build_object('completed', true),"
                "'admin_mfa', jsonb_build_object('completed', false),"
                "'campus_hierarchy', jsonb_build_object('completed', false),"
                "'os_deployment', jsonb_build_object('completed', false),"
                "'production_readiness', jsonb_build_object('completed', false)"
                "), 3, 8, $2, false, false, $3::bigint)",
                4, onb_vals, onb_lens);

            /* No default campus or OS deployment is fabricated here. The
             * institution creates its real campuses and assigns releases via
             * the organisation and deployment workflows. */

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
                         app_u_res && PQresultStatus(app_u_res) == PGRES_COMMAND_OK;

            if (!t_ins || PQresultStatus(t_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 1 tenants] %s\n", t_ins ? PQresultErrorMessage(t_ins) : "null");
            if (!s_ins || PQresultStatus(s_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 2 examos_institutions] %s\n", s_ins ? PQresultErrorMessage(s_ins) : "null");
            if (!agr_ins || PQresultStatus(agr_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 3 agreements] %s\n", agr_ins ? PQresultErrorMessage(agr_ins) : "null");
            if (!lic_ins || PQresultStatus(lic_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 4 licenses] %s\n", lic_ins ? PQresultErrorMessage(lic_ins) : "null");
            if (!onb_ins || PQresultStatus(onb_ins) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 5 onboarding] %s\n", onb_ins ? PQresultErrorMessage(onb_ins) : "null");
            if (!app_u_res || PQresultStatus(app_u_res) != PGRES_COMMAND_OK) fprintf(stderr, "[PROV FAIL 8 applications] %s\n", app_u_res ? PQresultErrorMessage(app_u_res) : "null");

            if (t_ins) PQclear(t_ins);
            if (s_ins) PQclear(s_ins);
            if (agr_ins) PQclear(agr_ins);
            if (lic_ins) PQclear(lic_ins);
            if (onb_ins) PQclear(onb_ins);
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
        int max_c = 0, max_cd = 0, ret = 0;

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
        if (!ctrl_json_int(body, "maxCenters", &max_c)) ctrl_json_int(body, "max_centers", &max_c);
        if (!ctrl_json_int(body, "maxCandidates", &max_cd)) ctrl_json_int(body, "max_candidates", &max_cd);

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

        if (!code[0]) {
            char pfx[8] = {0};
            for (size_t ci = 0; name[ci] && strlen(pfx) < 4; ci++) {
                char ch = name[ci];
                if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
                    pfx[strlen(pfx)] = (ch >= 'a' && ch <= 'z') ? (ch - 32) : ch;
                }
            }
            if (strlen(pfx) < 3) snprintf(pfx, sizeof(pfx), "INS");
            inst_generate_code(pfx, code, sizeof(code));
            if (!code[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 503, "Secure institution code generation unavailable", origin, extra_headers, extra_len);
                return;
            }
        }

        if (!name[0]) {
            db_release(conn, 0);
            inst_send_error(client_fd, 400, "name is required", origin, extra_headers, extra_len);
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
        {
            unsigned char rnd[4];
            if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
                db_release(conn, 0);
                inst_send_error(client_fd, 503, "Secure ID generation unavailable", origin, extra_headers, extra_len);
                return;
            }
            snprintf(id, sizeof(id), "ins_%ld_%02x%02x", now_sec, rnd[0], rnd[1]);
        }
        char now[32], valid_until[32];
        snprintf(now, sizeof(now), "%ld000", now_sec);
        snprintf(valid_until, sizeof(valid_until), "%ld000", now_sec + 31536000L);

        char max_c_str[16], max_cd_str[16];
        snprintf(max_c_str, sizeof(max_c_str), "%d", max_c);
        snprintf(max_cd_str, sizeof(max_cd_str), "%d", max_cd);

        const char *pvals[14] = {
            id, name, code, email, phone,
            region, tz, plan,
            max_c_str, max_cd_str,
            model,
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
            "'{}'::jsonb, '{}'::jsonb, '{}'::jsonb, "
            "jsonb_build_array(jsonb_build_object('at',$12::bigint,'by',$13::varchar,'action','Institution registered')))",
            14, pvals, plens);
        int ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
        if (!ok) {
            fprintf(stderr, "[INST DB ERROR] %s\n", PQerrorMessage(conn));
        }
        if (ins) PQclear(ins);

        /* Dual sync to examos_institutions and initialize related modules */
        int related_ok = 1;
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
            if (!sync_res || PQresultStatus(sync_res) != PGRES_COMMAND_OK) related_ok = 0;
            if (sync_res) PQclear(sync_res);

            /* Agreement draft — issued, not executed. No invented SLA tier. */
            char agr_id[64]; inst_generate_id("agr", agr_id, sizeof(agr_id));
            const char *av[4] = { agr_id, id, plan, now };
            int al[4]; for (int i = 0; i < 4; i++) al[i] = (int)strlen(av[i]);
            PGresult *ar = db_simple(conn,
                "INSERT INTO institution_agreements (id, institution_id, type, title, version, status, terms_payload, audit_trail, created_at) "
                "VALUES ($1, $2, 'msa', 'Master Services Agreement & Exam Security Covenant', '2026.1', 'DRAFT', "
                "jsonb_build_object('plan',$3::varchar), jsonb_build_array(jsonb_build_object('at',$4::bigint,'action','Draft initialized')), $4::bigint)",
                4, av, al);
            if (!ar || PQresultStatus(ar) != PGRES_COMMAND_OK) related_ok = 0;
            if (ar) PQclear(ar);

            /* License */
            char lic_id[64]; inst_generate_id("lic", lic_id, sizeof(lic_id));
            const char *lv[9] = { lic_id, id, agr_id, plan, now, valid_until, max_c_str, "0", max_cd_str };
            int ll[9]; for (int i = 0; i < 9; i++) ll[i] = (int)strlen(lv[i]);
            PGresult *lr = db_simple(conn,
                "INSERT INTO institution_licenses (id, institution_id, agreement_id, plan, plan_version, status, valid_from, valid_until, "
                "grace_period_days, max_campuses, max_devices, max_candidates, max_exams, allowed_channels, enabled_modules, usage_current, created_at, updated_at) "
                "VALUES ($1, $2, $3, $4, '2026.1', 'ACTIVE', $5::bigint, $6::bigint, 0, $7::integer, $8::integer, $9::integer, 0, "
                "'[]'::jsonb, '[]'::jsonb, '{\"campuses\":0,\"devices\":0,\"candidates\":0,\"exams\":0}'::jsonb, $5::bigint, $5::bigint) "
                "ON CONFLICT (institution_id) DO NOTHING", 9, lv, ll);
            if (!lr || PQresultStatus(lr) != PGRES_COMMAND_OK) related_ok = 0;
            if (lr) PQclear(lr);

            /* Onboarding — only registration (this action) and license are
             * genuinely complete. Everything else awaits real work. */
            const char *ov[3] = { id, email, now };
            int ol[3]; for (int i = 0; i < 3; i++) ol[i] = (int)strlen(ov[i]);
            PGresult *obr = db_simple(conn,
                "INSERT INTO institution_onboarding (institution_id, status, checklist, completed_steps, total_steps, first_admin_email, first_admin_invited, mfa_enforced, updated_at) "
                "VALUES ($1, 'VERIFIED', jsonb_build_object("
                "'registration', jsonb_build_object('completed', true),"
                "'identity_verification', jsonb_build_object('completed', false),"
                "'agreement', jsonb_build_object('completed', false),"
                "'license', jsonb_build_object('completed', true),"
                "'admin_mfa', jsonb_build_object('completed', false),"
                "'campus_hierarchy', jsonb_build_object('completed', false),"
                "'os_deployment', jsonb_build_object('completed', false),"
                "'production_readiness', jsonb_build_object('completed', false)"
                "), 2, 8, $2, false, false, $3::bigint) ON CONFLICT (institution_id) DO NOTHING", 3, ov, ol);
            if (!obr || PQresultStatus(obr) != PGRES_COMMAND_OK) related_ok = 0;
            if (obr) PQclear(obr);

            /* No default campus or OS deployment is seeded. Real records are
             * created through the campus and deployment workflows. */
        }

        if (!ok || !related_ok) {
            db_release(conn, 0);
            inst_send_error(client_fd, 503, "Failed to persist the complete institution record", origin, extra_headers, extra_len);
            return;
        }

        audit_and_ledger(sess.user_id, "TENANT_CREATED", id, name);
        char resp[320];
        snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"institution_id\":\"%s\",\"code\":\"%s\"}", id, code);
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
            int rows = ok ? atoi(PQcmdTuples(u_res)) : 0;
            if (u_res) PQclear(u_res);
            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to update institution status", origin, extra_headers, extra_len);
                return;
            }
            if (rows == 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Institution not found", origin, extra_headers, extra_len);
                return;
            }

            const char *s_vals[2] = { strcmp(st, "active") == 0 ? "true" : "false", inst_id };
            int s_lens[2] = { (int)strlen(s_vals[0]), (int)strlen(s_vals[1]) };
            PGresult *s_res = db_simple(conn, "UPDATE examos_institutions SET active = $1::boolean WHERE institution_id = $2", 2, s_vals, s_lens);
            int s_ok = s_res && PQresultStatus(s_res) == PGRES_COMMAND_OK;
            if (s_res) PQclear(s_res);
            if (!s_ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Status saved but the institution registry mirror could not be synchronized", origin, extra_headers, extra_len);
                return;
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
            int duration = 0, late_entry = 0;
            char attestation[32] = {0};
            if (!ctrl_json_int(body, "durationMin", &duration)) ctrl_json_int(body, "duration_min", &duration);
            if (!ctrl_json_int(body, "lateEntryMin", &late_entry)) ctrl_json_int(body, "late_entry_min", &late_entry);
            ctrl_json_string(body, "attestationLevel", attestation, sizeof(attestation));
            if (!attestation[0]) ctrl_json_string(body, "attestation_level", attestation, sizeof(attestation));

            if (!(duration >= 1) || late_entry < 0 || !attestation[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400,
                    "durationMin (>=1), lateEntryMin (>=0), and attestationLevel are required",
                    origin, extra_headers, extra_len);
                return;
            }

            char att_esc[128] = {0};
            escape_json_str(attestation, att_esc, sizeof(att_esc));
            char defs_json[320];
            snprintf(defs_json, sizeof(defs_json),
                "{\"durationMin\":%d,\"lateEntryMin\":%d,\"attestationLevel\":\"%s\"}",
                duration, late_entry, att_esc);

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            const char *vals[4] = { defs_json, now, sess.user_id, inst_id };
            int vlens[4]; for (int i = 0; i < 4; i++) vlens[i] = (int)strlen(vals[i]);

            PGresult *res = db_simple(conn,
                "UPDATE tenants SET exam_defaults = $1::jsonb, "
                "history = history || jsonb_build_array(jsonb_build_object('at',$2::bigint,'by',$3::varchar,'action','Exam defaults updated')) "
                "WHERE id = $4", 4, vals, vlens);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            int rows = ok ? atoi(PQcmdTuples(res)) : 0;
            if (res) PQclear(res);
            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to save exam defaults", origin, extra_headers, extra_len);
                return;
            }
            if (rows == 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Institution not found", origin, extra_headers, extra_len);
                return;
            }

            audit_and_ledger(sess.user_id, "TENANT_EXAM_DEFAULTS", inst_id, defs_json);
            db_release(conn, 0);

            char resp[512];
            snprintf(resp, sizeof(resp), "{\"status\":\"saved\",\"exam_defaults\":%s}", defs_json);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 3d. POST /api/v1/admin/institutions/:id/security */
        if (strcmp(method, "POST") == 0 && strcmp(sub, "security") == 0) {
            int req_tpm = 0, req_sb = 0, allow_usb = 0, kiosk_fs = 0, second_cam = 0;
            int has_tpm = ctrl_json_bool(body, "requireTpm", &req_tpm);
            int has_sb = ctrl_json_bool(body, "requireSecureBoot", &req_sb);
            int has_usb = ctrl_json_bool(body, "allowUsbStorage", &allow_usb);
            int has_kiosk = ctrl_json_bool(body, "kioskFullscreen", &kiosk_fs);
            int has_cam = ctrl_json_bool(body, "secondCameraAllowed", &second_cam);
            char origins[512] = {0};
            int has_origins = ctrl_json_string(body, "allowedOrigins", origins, sizeof(origins));

            /* Only persist keys that the client actually sent; the jsonb merge
             * keeps unrelated settings untouched instead of resetting them. */
            char sec_json[1024];
            size_t sp = 0;
            sp += snprintf(sec_json + sp, sizeof(sec_json) - sp, "{");
            int first = 1;
            #define SEC_ADD_BOOL(key, present, value) do { \
                if (present) { \
                    sp += snprintf(sec_json + sp, sizeof(sec_json) - sp, "%s\"%s\":%s", \
                        first ? "" : ",", key, (value) ? "true" : "false"); first = 0; } \
            } while (0)
            SEC_ADD_BOOL("requireTpm", has_tpm, req_tpm);
            SEC_ADD_BOOL("requireSecureBoot", has_sb, req_sb);
            SEC_ADD_BOOL("allowUsbStorage", has_usb, allow_usb);
            SEC_ADD_BOOL("kioskFullscreen", has_kiosk, kiosk_fs);
            SEC_ADD_BOOL("secondCameraAllowed", has_cam, second_cam);
            #undef SEC_ADD_BOOL
            if (has_origins) {
                char oesc[640];
                escape_json_str(origins, oesc, sizeof(oesc));
                sp += snprintf(sec_json + sp, sizeof(sec_json) - sp, "%s\"allowedOrigins\":\"%s\"",
                               first ? "" : ",", oesc);
                first = 0;
            }
            snprintf(sec_json + sp, sizeof(sec_json) - sp, "}");

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            const char *vals[4] = { sec_json, now, sess.user_id, inst_id };
            int vlens[4]; for (int i = 0; i < 4; i++) vlens[i] = (int)strlen(vals[i]);

            PGresult *res = db_simple(conn,
                "UPDATE tenants SET security = COALESCE(security, '{}'::jsonb) || $1::jsonb, "
                "history = history || jsonb_build_array(jsonb_build_object('at',$2::bigint,'by',$3::varchar,'action','Security defaults updated')) "
                "WHERE id = $4", 4, vals, vlens);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            if (res) PQclear(res);

            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to persist security settings", origin, extra_headers, extra_len);
                return;
            }

            audit_and_ledger(sess.user_id, "TENANT_SECURITY_UPDATED", inst_id, sec_json);
            db_release(conn, 0);

            char resp[1280];
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
            inst_generate_id("agr", agr_id, sizeof(agr_id));
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            const char *av[8] = { agr_id, inst_id, type, title, version, terms_raw, now, sess.user_id };
            int al[8]; for (int i = 0; i < 8; i++) al[i] = (int)strlen(av[i]);

            PGresult *res = db_simple(conn,
                "INSERT INTO institution_agreements (id, institution_id, type, title, version, status, terms_payload, audit_trail, created_at) "
                "VALUES ($1, $2, $3, $4, $5, 'DRAFT', $6::jsonb, "
                "jsonb_build_array(jsonb_build_object('at',$7::bigint,'by',$8::varchar,'action','Draft created')), $7::bigint)",
                8, av, al);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
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
                if (!channels || !channels[0]) channels = "[]";
                const char *modules = PQgetvalue(res, 0, 14);
                if (!modules || !modules[0]) modules = "[]";

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
            char mc_s[16], md_s[16], mcd_s[16], me_s[16];
            snprintf(mc_s,  sizeof(mc_s),  "%d", max_c);
            snprintf(md_s,  sizeof(md_s),  "%d", max_d);
            snprintf(mcd_s, sizeof(mcd_s), "%d", max_cand);
            snprintf(me_s,  sizeof(me_s),  "%d", max_ex);

            const char *lv8[8] = { plan[0] ? plan : "", status[0] ? status : "", mc_s, md_s, mcd_s, me_s, now, inst_id };
            int ll8[8]; for (int i = 0; i < 8; i++) ll8[i] = (int)strlen(lv8[i]);

            PGresult *res = db_simple(conn,
                "UPDATE institution_licenses SET "
                "plan = CASE WHEN $1 <> '' THEN $1 ELSE plan END, "
                "status = CASE WHEN $2 <> '' THEN $2 ELSE status END, "
                "max_campuses  = CASE WHEN $3::integer >= 0 THEN $3::integer ELSE max_campuses  END, "
                "max_devices   = CASE WHEN $4::integer >= 0 THEN $4::integer ELSE max_devices   END, "
                "max_candidates= CASE WHEN $5::integer >= 0 THEN $5::integer ELSE max_candidates END, "
                "max_exams     = CASE WHEN $6::integer >= 0 THEN $6::integer ELSE max_exams     END, "
                "updated_at = $7::bigint "
                "WHERE institution_id = $8",
                8, lv8, ll8);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            if (res) PQclear(res);
            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to update institution license", origin, extra_headers, extra_len);
                return;
            }

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

            /* Query live usage for requested resource — parameterized to prevent injection */
            const char *usage_sql;
            if (strcmp(res_type, "campuses") == 0)
                usage_sql = "SELECT COUNT(*) FROM campuses WHERE tenant_id = $1";
            else if (strcmp(res_type, "devices") == 0)
                usage_sql = "SELECT COUNT(*) FROM devices WHERE tenant_id = $1";
            else if (strcmp(res_type, "candidates") == 0)
                usage_sql = "SELECT COUNT(*) FROM candidates WHERE tenant_id = $1";
            else
                usage_sql = "SELECT COUNT(*) FROM exams WHERE tenant_id = $1";

            const char *upv[1] = { inst_id };
            int upl[1] = { (int)strlen(inst_id) };
            PGresult *cres = db_simple(conn, usage_sql, 1, upv, upl);
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
            if (!release_id[0]) {
                get_latest_os_release_id(conn, release_id, sizeof(release_id));
            }
            ctrl_json_string(body, "channel", channel, sizeof(channel));
            ctrl_json_string(body, "hardwareProfile", hw_prof, sizeof(hw_prof));
            ctrl_json_string(body, "securityProfile", sec_prof, sizeof(sec_prof));
            ctrl_json_string(body, "policyHash", pol_hash, sizeof(pol_hash));

            if (!release_id[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 409,
                    "No OS release is available to assign; publish a release first",
                    origin, extra_headers, extra_len);
                return;
            }
            if (!channel[0] || !hw_prof[0] || !sec_prof[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400,
                    "channel, hardwareProfile and securityProfile are required",
                    origin, extra_headers, extra_len);
                return;
            }

            char dep_id[64]; inst_generate_id("dep", dep_id, sizeof(dep_id));
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            const char *dv[9] = { dep_id, inst_id, campus_id, release_id, channel, hw_prof, sec_prof, pol_hash, now };
            int dl[9]; for (int i = 0; i < 9; i++) dl[i] = (int)strlen(dv[i]);

            PGresult *res = db_simple(conn,
                "INSERT INTO institution_os_deployments (id, institution_id, campus_id, release_id, channel, "
                "hardware_profile, security_profile, status, policy_hash, devices_targeted, devices_acknowledged, created_at, updated_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, 'ACTIVE', $8, 0, 0, $9::bigint, $9::bigint)",
                9, dv, dl);

            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
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

        /* 3k-bis. Pilot Readiness Dashboard: GET /api/v1/admin/institutions/:id/readiness */
        if (strcmp(method, "GET") == 0 && strcmp(sub, "readiness") == 0) {
            const char *pv[1] = { inst_id };
            int pl[1] = { (int)strlen(inst_id) };

            /* 1. Total registered devices for this institution */
            PGresult *dev_res = db_simple(conn,
                "SELECT COUNT(*) AS total, "
                "  COUNT(*) FILTER (WHERE trust = 'attested' OR tpm_status = 'VERIFIED') AS attested, "
                "  COUNT(*) FILTER (WHERE status = 'enrolled' OR trust = 'attested') AS locked, "
                "  COUNT(*) FILTER (WHERE status = 'enrolled') AS enrolled "
                "FROM devices WHERE tenant_id = $1 OR institution_id = $1",
                1, pv, pl);
            int dev_total = 0, dev_attested = 0, dev_locked = 0, dev_enrolled = 0;
            if (dev_res && PQresultStatus(dev_res) == PGRES_TUPLES_OK && PQntuples(dev_res) > 0) {
                dev_total = atoi(PQgetvalue(dev_res, 0, 0));
                dev_attested = atoi(PQgetvalue(dev_res, 0, 1));
                dev_locked = atoi(PQgetvalue(dev_res, 0, 2));
                dev_enrolled = atoi(PQgetvalue(dev_res, 0, 3));
            }
            if (dev_res) PQclear(dev_res);

            /* 2. Exam URLs configured for this institution */
            PGresult *exam_res = db_simple(conn,
                "SELECT COUNT(*) AS total, "
                "  COUNT(*) FILTER (WHERE exam_url IS NOT NULL AND exam_url != '') AS with_url "
                "FROM exams WHERE tenant_id = $1 OR institution_id = $1",
                1, pv, pl);
            int exam_total = 0, exam_with_url = 0;
            if (exam_res && PQresultStatus(exam_res) == PGRES_TUPLES_OK && PQntuples(exam_res) > 0) {
                exam_total = atoi(PQgetvalue(exam_res, 0, 0));
                exam_with_url = atoi(PQgetvalue(exam_res, 0, 1));
            }
            if (exam_res) PQclear(exam_res);

            /* 3. Collect distinct exam URLs */
            PGresult *url_res = db_simple(conn,
                "SELECT DISTINCT exam_url FROM exams "
                "WHERE (tenant_id = $1 OR institution_id = $1) AND exam_url IS NOT NULL AND exam_url != '' "
                "LIMIT 10",
                1, pv, pl);
            char url_list[2048] = "[";
            int url_count = 0;
            if (url_res && PQresultStatus(url_res) == PGRES_TUPLES_OK) {
                url_count = PQntuples(url_res);
                for (int i = 0; i < PQntuples(url_res); i++) {
                    char esc[256] = {0};
                    const char *raw = PQgetvalue(url_res, i, 0);
                    /* Simple JSON-safe copy */
                    size_t j = 0;
                    for (size_t k = 0; raw[k] && j < sizeof(esc) - 2; k++) {
                        if (raw[k] == '"' || raw[k] == '\\') esc[j++] = '\\';
                        esc[j++] = raw[k];
                    }
                    esc[j] = 0;
                    size_t pos = strlen(url_list);
                    snprintf(url_list + pos, sizeof(url_list) - pos, "%s\"%s\"", i > 0 ? "," : "", esc);
                }
            }
            strncat(url_list, "]", sizeof(url_list) - strlen(url_list) - 1);
            if (url_res) PQclear(url_res);

            /* 4. Audit chain integrity — query the 'audit' table (prev+hash chain) */
            int chain_total = 0, chain_linked = 0;
            int chain_ok = 0;
            {
                /* C2 fix: scope audit chain to this institution only. */
                PGresult *chain_res = db_simple(conn,
                    "SELECT COUNT(*) AS total, "
                    "  COUNT(*) FILTER (WHERE prev IS NOT NULL AND prev != '') AS chained "
                    "FROM audit WHERE institution_id = $1",
                    1, pv, pl);
                if (chain_res && PQresultStatus(chain_res) == PGRES_TUPLES_OK && PQntuples(chain_res) > 0) {
                    chain_total = atoi(PQgetvalue(chain_res, 0, 0));
                    chain_linked = atoi(PQgetvalue(chain_res, 0, 1));
                }
                if (chain_res) PQclear(chain_res);
            }
            chain_ok = (chain_total > 0 && chain_linked >= chain_total - 1);

            /* 5. Onboarding state */
            PGresult *onb_res = db_simple(conn,
                "SELECT status, completed_steps, total_steps FROM institution_onboarding WHERE institution_id = $1",
                1, pv, pl);
            char onb_status[40] = "UNKNOWN";
            int onb_completed = 0, onb_total = 8;
            if (onb_res && PQresultStatus(onb_res) == PGRES_TUPLES_OK && PQntuples(onb_res) > 0) {
                strncpy(onb_status, PQgetvalue(onb_res, 0, 0), sizeof(onb_status) - 1);
                onb_completed = atoi(PQgetvalue(onb_res, 0, 1));
                onb_total = atoi(PQgetvalue(onb_res, 0, 2));
            }
            if (onb_res) PQclear(onb_res);

            /* 6. Institution info */
            PGresult *inst_res = db_simple(conn,
                "SELECT name, status, plan, contact_email FROM tenants WHERE id = $1",
                1, pv, pl);
            char inst_name[128] = "", inst_status[40] = "", inst_plan[40] = "";
            if (inst_res && PQresultStatus(inst_res) == PGRES_TUPLES_OK && PQntuples(inst_res) > 0) {
                strncpy(inst_name, PQgetvalue(inst_res, 0, 0), sizeof(inst_name) - 1);
                strncpy(inst_status, PQgetvalue(inst_res, 0, 1), sizeof(inst_status) - 1);
                strncpy(inst_plan, PQgetvalue(inst_res, 0, 2), sizeof(inst_plan) - 1);
            }
            if (inst_res) PQclear(inst_res);

            /* Build readiness gates */
            int gate_fleet = (dev_total > 0);
            int gate_tpm = (dev_total > 0 && dev_attested == dev_total);
            int gate_lock = (dev_total > 0 && dev_locked == dev_total);
            int gate_url = (url_count > 0);
            int gate_chain = chain_ok;
            int all_pass = gate_fleet && gate_tpm && gate_lock && gate_url && gate_chain;

            db_release(conn, 0);

            /* Escape inst_name for JSON */
            char name_esc[256] = {0};
            {
                size_t j2 = 0;
                for (size_t k2 = 0; inst_name[k2] && j2 < sizeof(name_esc) - 2; k2++) {
                    if (inst_name[k2] == '"' || inst_name[k2] == '\\') name_esc[j2++] = '\\';
                    name_esc[j2++] = inst_name[k2];
                }
                name_esc[j2] = 0;
            }

            char resp[8192];
            snprintf(resp, sizeof(resp),
                "{"
                "\"institutionId\":\"%s\","
                "\"institutionName\":\"%s\","
                "\"institutionStatus\":\"%s\","
                "\"institutionPlan\":\"%s\","
                "\"devices\":{\"total\":%d,\"attested\":%d,\"locked\":%d,\"enrolled\":%d},"
                "\"exams\":{\"total\":%d,\"withUrl\":%d},"
                "\"examUrls\":%s,"
                "\"auditChain\":{\"total\":%d,\"linked\":%d,\"ok\":%s},"
                "\"onboarding\":{\"status\":\"%s\",\"completedSteps\":%d,\"totalSteps\":%d},"
                "\"gates\":["
                  "{\"key\":\"fleet\",\"check\":\"Workstation Fleet Hardware Boot in Kiosk Sandbox\","
                    "\"pass\":%s,\"detail\":\"%d device(s) enrolled and reporting real-time telemetry\"},"
                  "{\"key\":\"tpm\",\"check\":\"Hardware TPM 2.0 Silicon Attestation Validated\","
                    "\"pass\":%s,\"detail\":\"%d of %d device(s) verified with signed PCR[0,2,4,7] cryptographic root\"},"
                  "{\"key\":\"lock\",\"check\":\"Port Containment & External Peripheral Lock Engaged\","
                    "\"pass\":%s,\"detail\":\"%d of %d workstation(s) enforced with active USB storage & peripheral containment\"},"
                  "{\"key\":\"url\",\"check\":\"Target Assessment Portal URL Origin Clearance\","
                    "\"pass\":%s,\"detail\":\"%d assessment portal(s) verified for kiosk navigation\"},"
                  "{\"key\":\"chain\",\"check\":\"Cryptographic Ledger & Audit Chain Intact\","
                    "\"pass\":%s,\"detail\":\"Dual-persistence HMAC-SHA256 hash chain verified with %d block(s)\"}"
                "],"
                "\"allPassed\":%s"
                "}",
                inst_id, name_esc, inst_status, inst_plan,
                dev_total, dev_attested, dev_locked, dev_enrolled,
                exam_total, exam_with_url,
                url_list,
                chain_total, chain_linked, chain_ok ? "true" : "false",
                onb_status, onb_completed, onb_total,
                gate_fleet ? "true" : "false", dev_total,
                gate_tpm ? "true" : "false", dev_attested, dev_total,
                gate_lock ? "true" : "false", dev_locked, dev_total,
                gate_url ? "true" : "false", url_count,
                gate_chain ? "true" : "false", chain_total,
                all_pass ? "true" : "false");

            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

                /* 3j. List Institution Admins: GET /api/v1/admin/institutions/:id/admins */
        if (strcmp(method, "GET") == 0 && strcmp(sub, "admins") == 0) {
            const char *pvals[1] = { inst_id };
            int lens[1] = { (int)strlen(inst_id) };
            PGresult *res = db_simple(conn,
                "SELECT id, username, name, role, email, status, mfa_enabled, "
                "       created_at, last_login, COALESCE(title, '') "
                "FROM users WHERE tenant_id = $1 ORDER BY created_at DESC", 1, pvals, lens);

            char json[16384];
            size_t pos = 0;
            pos += snprintf(json + pos, sizeof(json) - pos, "{\"admins\":[");
            if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
                int count = PQntuples(res);
                for (int i = 0; i < count; i++) {
                    char id_esc[128], u_esc[128], n_esc[128], r_esc[64], e_esc[128], s_esc[32], t_esc[128];
                    escape_json_str(PQgetvalue(res, i, 0), id_esc, sizeof(id_esc));
                    escape_json_str(PQgetvalue(res, i, 1), u_esc, sizeof(u_esc));
                    escape_json_str(PQgetvalue(res, i, 2), n_esc, sizeof(n_esc));
                    escape_json_str(PQgetvalue(res, i, 3), r_esc, sizeof(r_esc));
                    escape_json_str(PQgetvalue(res, i, 4), e_esc, sizeof(e_esc));
                    escape_json_str(PQgetvalue(res, i, 5), s_esc, sizeof(s_esc));
                    escape_json_str(PQgetvalue(res, i, 9), t_esc, sizeof(t_esc));

                    pos += snprintf(json + pos, sizeof(json) - pos,
                        "%s{\"id\":\"%s\",\"username\":\"%s\",\"full_name\":\"%s\","
                        "\"name\":\"%s\",\"role\":\"%s\",\"email\":\"%s\","
                        "\"status\":\"%s\",\"active\":%d,\"mfa_enabled\":%s,"
                        "\"created_at\":%s,\"last_login\":%s,\"title\":\"%s\"}",
                        i > 0 ? "," : "",
                        id_esc, u_esc, n_esc, n_esc, r_esc, e_esc,
                        s_esc, strcmp(s_esc, "active") == 0 ? 1 : 0,
                        (PQgetvalue(res, i, 6)[0] == '1' || PQgetvalue(res, i, 6)[0] == 't') ? "true" : "false",
                        PQgetvalue(res, i, 7)[0] ? PQgetvalue(res, i, 7) : "0",
                        PQgetvalue(res, i, 8)[0] ? PQgetvalue(res, i, 8) : "0",
                        t_esc);
                }
            }
            if (res) PQclear(res);
            db_release(conn, 0);

            pos += snprintf(json + pos, sizeof(json) - pos, "]}");
            inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
            return;
        }

        /* 3k-remove. Remove Institution Admin: POST /api/v1/admin/institutions/:id/admins/:userId */
        if ((strcmp(method, "POST") == 0 || strcmp(method, "DELETE") == 0) &&
            strncmp(sub, "admins/", 7) == 0 && sub[7] != '\0' &&
            strcmp(sub, "admins/invite") != 0) {
            char target_uid[64] = {0};
            /* sub is "admins/<userId>" — extract the userId part */
            const char *uid_start = sub + 7;
            /* strip a trailing /remove if present */
            const char *uid_slash = strchr(uid_start, '/');
            size_t uid_len = uid_slash ? (size_t)(uid_slash - uid_start) : strlen(uid_start);
            if (uid_len > 0 && uid_len < sizeof(target_uid)) {
                memcpy(target_uid, uid_start, uid_len);
                target_uid[uid_len] = '\0';
            }
            if (!target_uid[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "userId is required in path", origin, extra_headers, extra_len);
                return;
            }
            char reason[256] = {0};
            ctrl_json_string(body, "reason", reason, sizeof(reason));
            if (!reason[0]) snprintf(reason, sizeof(reason), "Access removed by administrator");

            char now_str[32]; snprintf(now_str, sizeof(now_str), "%ld", (long)time(NULL));
            /* Scope: the target must belong to this institution. There is no
             * owner bypass that could suspend a user from another tenant. */
            const char *rv[4] = { reason, now_str, target_uid, inst_id };
            int rl[4]; for (int i = 0; i < 4; i++) rl[i] = (int)strlen(rv[i]);
            PGresult *rm_res = db_simple(conn,
                "UPDATE users SET status='suspended', status_reason=$1, status_at=$2::bigint "
                "WHERE id=$3 AND tenant_id=$4 RETURNING id",
                4, rv, rl);
            int rm_ok = rm_res && PQresultStatus(rm_res) == PGRES_TUPLES_OK;
            int rm_rows = rm_ok ? PQntuples(rm_res) : 0;
            if (rm_res) PQclear(rm_res);
            if (!rm_ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to remove administrator access", origin, extra_headers, extra_len);
                return;
            }
            if (rm_rows == 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Administrator not found in this institution", origin, extra_headers, extra_len);
                return;
            }
            audit_and_ledger(sess.user_id, "INSTITUTION_ADMIN_REMOVED", inst_id, target_uid);
            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"removed\",\"user_id\":\"%s\"}", target_uid);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 3k. Invite / Create Institution Admin: POST /api/v1/admin/institutions/:id/admins */
        if (strcmp(method, "POST") == 0 && (strcmp(sub, "admins") == 0 || strcmp(sub, "admins/invite") == 0)) {
            char email[128] = {0}, name[128] = {0}, role[64] = "inst_admin", campus_id[64] = {0}, username[64] = {0};
            ctrl_json_string(body, "email", email, sizeof(email));
            ctrl_json_string(body, "name", name, sizeof(name));
            ctrl_json_string(body, "role", role, sizeof(role));
            ctrl_json_string(body, "campusId", campus_id, sizeof(campus_id));
            ctrl_json_string(body, "username", username, sizeof(username));

            if (!email[0] || !name[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "Name and institutional email are required", origin, extra_headers, extra_len);
                return;
            }

            if (!username[0]) {
                const char *at = strchr(email, '@');
                size_t prefix_len = at ? (size_t)(at - email) : strlen(email);
                if (prefix_len > 40) prefix_len = 40;
                char clean_pfx[64] = {0};
                size_t c_idx = 0;
                for (size_t i = 0; i < prefix_len; i++) {
                    char ch = email[i];
                    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') {
                        clean_pfx[c_idx++] = ch;
                    }
                }
                clean_pfx[c_idx] = '\0';
                snprintf(username, sizeof(username), "%s_%ld", clean_pfx[0] ? clean_pfx : "admin", ((long)time(NULL)) % 100000);
            }

            char user_id[64];
            {
                unsigned char uid_rnd[4];
                if (RAND_bytes(uid_rnd, sizeof(uid_rnd)) != 1) {
                    db_release(conn, 0);
                    inst_send_error(client_fd, 503, "Secure ID generation unavailable", origin, extra_headers, extra_len);
                    return;
                }
                snprintf(user_id, sizeof(user_id), "usr_%ld_%02x%02x", (long)time(NULL), uid_rnd[0], uid_rnd[1]);
            }

            char salt[64];
            {
                unsigned char srnd[16];
                if (RAND_bytes(srnd, sizeof(srnd)) == 1) {
                    snprintf(salt, sizeof(salt), "s_%02x%02x%02x%02x%02x%02x%02x%02x",
                             srnd[0], srnd[1], srnd[2], srnd[3], srnd[4], srnd[5], srnd[6], srnd[7]);
                } else {
                    snprintf(salt, sizeof(salt), "s_%ld", (long)time(NULL));
                }
            }
            /* Generate a cryptographically random temporary password */
            char temp_pwd[32];
            {
                unsigned char pw_rnd[12];
                static const char pw_chars[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#";
                if (RAND_bytes(pw_rnd, sizeof(pw_rnd)) == 1) {
                    for (int pi = 0; pi < 12; pi++)
                        temp_pwd[pi] = pw_chars[pw_rnd[pi] % (sizeof(pw_chars) - 1)];
                    temp_pwd[12] = '\0';
                } else {
                    /* Fallback: still better than time-based but should not happen */
                    snprintf(temp_pwd, sizeof(temp_pwd), "Tmp!%08lx", (unsigned long)time(NULL));
                }
            }

            char hash[256] = {0};
            security_pbkdf2_hash(temp_pwd, salt, hash, sizeof(hash));

            char now_str[32];
            snprintf(now_str, sizeof(now_str), "%ld", (long)time(NULL));

            const char *pvals[9] = {
                user_id, username, name, role[0] ? role : "inst_admin",
                inst_id, email, hash, salt, now_str
            };
            int lens[9];
            for (int k = 0; k < 9; k++) lens[k] = (int)strlen(pvals[k]);

            PGresult *ins = db_simple(conn,
                "INSERT INTO users (id, username, name, role, tenant_id, email, password_hash, salt, totp_secret, status, created_at, mfa_enabled) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, 'active', $9::bigint, 0) "
                "ON CONFLICT (username) DO NOTHING "
                "RETURNING id, username", 9, pvals, lens);

            if (!ins || PQresultStatus(ins) != PGRES_TUPLES_OK) {
                if (ins) PQclear(ins);
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to create administrator account in database", origin, extra_headers, extra_len);
                return;
            }
            if (PQntuples(ins) == 0) {
                /* Never silently take over an existing account. */
                PQclear(ins);
                db_release(conn, 0);
                inst_send_error(client_fd, 409, "An account with this username or email already exists", origin, extra_headers, extra_len);
                return;
            }

            char ret_id[64] = {0}, ret_user[64] = {0};
            strncpy(ret_id, PQgetvalue(ins, 0, 0), sizeof(ret_id) - 1);
            strncpy(ret_user, PQgetvalue(ins, 0, 1), sizeof(ret_user) - 1);
            PQclear(ins);

            if (campus_id[0]) {
                char staff_id[64];
                inst_generate_id("stf", staff_id, sizeof(staff_id));
                const char *s_vals[6] = { staff_id, inst_id, ret_id, name, role, campus_id };
                int s_lens[6];
                for (int s = 0; s < 6; s++) s_lens[s] = (int)strlen(s_vals[s]);
                PGresult *stf = db_simple(conn,
                    "INSERT INTO staff (id, tenant_id, user_id, name, role_title, campus_id, status, created_at, updated_at) "
                    "VALUES ($1, $2, $3, $4, $5, $6, 'active', EXTRACT(EPOCH FROM NOW())::bigint, EXTRACT(EPOCH FROM NOW())::bigint) "
                    "ON CONFLICT (id) DO NOTHING", 6, s_vals, s_lens);
                if (stf) PQclear(stf);
            }

            audit_and_ledger(sess.user_id, "INSTITUTION_ADMIN_INVITED", inst_id, email);
            db_release(conn, 0);

            char resp[1024];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"created\",\"user_id\":\"%s\",\"id\":\"%s\","
                "\"username\":\"%s\",\"name\":\"%s\",\"email\":\"%s\","
                "\"role\":\"%s\",\"tenant_id\":\"%s\",\"tempPassword\":\"%s\",\"mfa_enabled\":false}",
                ret_id, ret_id, ret_user, name, email, role, inst_id, temp_pwd);
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
                    PQgetvalue(res, 0, 5)[0] ? PQgetvalue(res, 0, 5) : "false",
                    PQgetvalue(res, 0, 6)[0] ? PQgetvalue(res, 0, 6) : "false",
                    PQgetvalue(res, 0, 7));

                PQclear(res);
                db_release(conn, 0);
                inst_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
                return;
            }
            if (res) PQclear(res);

            /* Initialize an honest onboarding record if missing: no step is
             * complete until the corresponding real action is recorded. */
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            char real_email[128] = {0};
            {
                const char *epv[1] = { inst_id };
                int epl[1] = { (int)strlen(inst_id) };
                PGresult *er = db_simple(conn, "SELECT contact_email FROM tenants WHERE id = $1", 1, epv, epl);
                if (er && PQresultStatus(er) == PGRES_TUPLES_OK && PQntuples(er) > 0 && PQgetvalue(er, 0, 0)[0])
                    snprintf(real_email, sizeof(real_email), "%s", PQgetvalue(er, 0, 0));
                if (er) PQclear(er);
            }
            const char *ov[3] = { inst_id, real_email, now };
            int ol[3]; for (int i = 0; i < 3; i++) ol[i] = (int)strlen(ov[i]);
            PGresult *ires = db_simple(conn,
                "INSERT INTO institution_onboarding (institution_id, status, checklist, completed_steps, total_steps, "
                "first_admin_email, first_admin_invited, mfa_enforced, updated_at) "
                "VALUES ($1, 'PENDING', '{}'::jsonb, 0, 8, $2, false, false, $3::bigint) "
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


            /* Verify institution exists before attempting onboarding update */
            {
                const char *chk_v[1] = { inst_id };
                int chk_l[1] = { (int)strlen(inst_id) };
                PGresult *chk_r = db_simple(conn, "SELECT id FROM tenants WHERE id = $1", 1, chk_v, chk_l);
                if (!chk_r || PQresultStatus(chk_r) != PGRES_TUPLES_OK || PQntuples(chk_r) == 0) {
                    if (chk_r) PQclear(chk_r);
                    db_release(conn, 0);
                    inst_send_error(client_fd, 404, "Institution not found", origin, extra_headers, extra_len);
                    return;
                }
                PQclear(chk_r);
            }
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            /* Create an empty onboarding record on first update; every step
             * starts incomplete. */
            {
                char step_real_email[128] = {0};
                {
                    const char *epv2[1] = { inst_id };
                    int epl2[1] = { (int)strlen(inst_id) };
                    PGresult *er2 = db_simple(conn, "SELECT contact_email FROM tenants WHERE id = $1", 1, epv2, epl2);
                    if (er2 && PQresultStatus(er2) == PGRES_TUPLES_OK && PQntuples(er2) > 0 && PQgetvalue(er2, 0, 0)[0])
                        snprintf(step_real_email, sizeof(step_real_email), "%s", PQgetvalue(er2, 0, 0));
                    if (er2) PQclear(er2);
                }
                const char *ov[3] = { inst_id, step_real_email, now };
                int ol[3]; for (int i = 0; i < 3; i++) ol[i] = (int)strlen(ov[i]);
                PGresult *init_res = db_simple(conn,
                    "INSERT INTO institution_onboarding (institution_id, status, checklist, completed_steps, total_steps, "
                    "first_admin_email, first_admin_invited, mfa_enforced, updated_at) "
                    "VALUES ($1, 'PENDING', '{}'::jsonb, 0, 8, $2, false, false, $3::bigint) "
                    "ON CONFLICT (institution_id) DO NOTHING",
                    3, ov, ol);
                if (init_res) PQclear(init_res);
            }

            /* completed flag as text for jsonb_build_object */
            const char *comp_str = completed ? "true" : "false";
            /* Use parameterized jsonb_set — step_key goes into the path array */
            const char *uv[6] = { step_key, comp_str, now, sess.user_id, notes, inst_id };
            int ul[6]; for (int i = 0; i < 6; i++) ul[i] = (int)strlen(uv[i]);

            /* Single statement: persist the step, then recompute completed
             * count and lifecycle status from the real checklist. */
            PGresult *res = db_simple(conn,
                "WITH upd AS ("
                "  UPDATE institution_onboarding SET "
                "    checklist = jsonb_set(checklist, ARRAY[$1::text], "
                "      jsonb_build_object('completed', $2::boolean, 'at', $3::bigint, 'by', $4::varchar, 'notes', $5::varchar)), "
                "    updated_at = $3::bigint "
                "  WHERE institution_id = $6 "
                "  RETURNING institution_id, checklist"
                "), cnt AS ("
                "  SELECT institution_id, "
                "    (SELECT count(*) FROM jsonb_each(checklist) WHERE value->>'completed' = 'true') AS n "
                "  FROM upd"
                ") "
                "UPDATE institution_onboarding o SET "
                "  completed_steps = cnt.n, "
                "  status = CASE WHEN cnt.n >= 8 THEN 'ACTIVE' "
                "               WHEN cnt.n >= 6 THEN 'CONFIGURED' "
                "               WHEN cnt.n >= 4 THEN 'LICENSED' "
                "               WHEN cnt.n >= 1 THEN 'IN_PROGRESS' "
                "               ELSE 'PENDING' END "
                "FROM cnt WHERE o.institution_id = cnt.institution_id "
                "RETURNING o.status, o.completed_steps",
                6, uv, ul);
            if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char new_status[64] = {0}, c_steps[16] = {0};
                snprintf(new_status, sizeof(new_status), "%s", PQgetvalue(res, 0, 0));
                snprintf(c_steps, sizeof(c_steps), "%s", PQgetvalue(res, 0, 1));
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

            if (name[0]) {
                const char *dn_vals[2] = { name, inst_id };
                int dn_lens[2] = { (int)strlen(name), (int)strlen(inst_id) };
                PGresult *dn = db_simple(conn,
                    "SELECT id FROM tenants WHERE LOWER(name) = LOWER($1) AND id <> $2 "
                    "UNION SELECT institution_id FROM examos_institutions WHERE LOWER(name) = LOWER($1) AND institution_id <> $2",
                    2, dn_vals, dn_lens);
                int dn_found = dn && PQresultStatus(dn) == PGRES_TUPLES_OK && PQntuples(dn) > 0;
                if (dn) PQclear(dn);
                if (dn_found) {
                    db_release(conn, 0);
                    inst_send_error(client_fd, 409, "Another institution already uses this name", origin, extra_headers, extra_len);
                    return;
                }
            }

            /* Build parameterized update — only set fields that were provided */
            const char *uv[11] = {
                name[0]   ? name   : "",
                email[0]  ? email  : "",
                phone[0]  ? phone  : "",
                region[0] ? region : "",
                tz[0]     ? tz     : "",
                model[0]  ? model  : "",
                plan[0]   ? plan   : "",
                domains_raw[0] ? domains_raw : "",
                now,
                sess.user_id,
                inst_id
            };
            int ul[11]; for (int i = 0; i < 11; i++) ul[i] = (int)strlen(uv[i]);

            PGresult *res = db_simple(conn,
                "UPDATE tenants SET "
                "name             = CASE WHEN $1 <> '' THEN $1 ELSE name             END, "
                "contact_email    = CASE WHEN $2 <> '' THEN $2 ELSE contact_email    END, "
                "contact_phone    = CASE WHEN $3 <> '' THEN $3 ELSE contact_phone    END, "
                "region           = CASE WHEN $4 <> '' THEN $4 ELSE region           END, "
                "timezone         = CASE WHEN $5 <> '' THEN $5 ELSE timezone         END, "
                "deployment_model = CASE WHEN $6 <> '' THEN $6 ELSE deployment_model END, "
                "plan             = CASE WHEN $7 <> '' THEN $7 ELSE plan             END, "
                "domains          = CASE WHEN $8 <> '' THEN $8::jsonb ELSE domains   END, "
                "history = history || jsonb_build_array(jsonb_build_object('at',$9::bigint,'by',$10::varchar,'action','Institution settings updated')) "
                "WHERE id = $11",
                11, uv, ul);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            int rows = ok ? atoi(PQcmdTuples(res)) : 0;
            if (res) PQclear(res);
            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to update institution settings", origin, extra_headers, extra_len);
                return;
            }
            if (rows == 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Institution not found", origin, extra_headers, extra_len);
                return;
            }

            if (name[0]) {
                const char *sv[2] = { name, inst_id };
                int sl[2] = { (int)strlen(name), (int)strlen(inst_id) };
                PGresult *s_res = db_simple(conn,
                    "UPDATE examos_institutions SET name = $1 WHERE institution_id = $2",
                    2, sv, sl);
                int s_ok = s_res && PQresultStatus(s_res) == PGRES_COMMAND_OK;
                if (s_res) PQclear(s_res);
                if (!s_ok) {
                    db_release(conn, 0);
                    inst_send_error(client_fd, 500, "Failed to synchronize institution name", origin, extra_headers, extra_len);
                    return;
                }
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

                /* C3 fix: verify caller has scope over this agreement's institution. */
                if (!is_owner && strcmp(sess.institution_id, affected_inst) != 0) {
                    /* Undo the UPDATE we just did — the caller had no scope. */
                    const char *rv[1] = { agr_id };
                    int rl[1] = { (int)strlen(agr_id) };
                    PGresult *undo = db_simple(conn,
                        "UPDATE institution_agreements SET status='DRAFT', signer_name=NULL, signer_email=NULL, "
                        "signer_role=NULL, signed_at=NULL, document_digest=NULL, effective_from=NULL, effective_until=NULL "
                        "WHERE id=$1", 1, rv, rl);
                    if (undo) PQclear(undo);
                    db_release(conn, 0);
                    inst_send_error(client_fd, 403, "Access denied: agreement belongs to a different institution", origin, extra_headers, extra_len);
                    return;
                }

                /* Automatically advance agreement step on onboarding checklist */
                if (affected_inst[0]) {
                    const char *ov[3] = { affected_inst, now_ms, digest };
                    int ol[3] = { (int)strlen(affected_inst), (int)strlen(now_ms), (int)strlen(digest) };
                    PGresult *onb_r = db_simple(conn,
                        "UPDATE institution_onboarding SET "
                        "checklist = jsonb_set(checklist, '{agreement}', jsonb_build_object('completed', true, 'at', $2::bigint, 'digest', $3::text)), "
                        "completed_steps = (SELECT count(*) FROM jsonb_each(checklist) WHERE value->>'completed' = 'true'), "
                        "updated_at = $2::bigint WHERE institution_id = $1",
                        3, ov, ol);
                    int onb_ok = onb_r && PQresultStatus(onb_r) == PGRES_COMMAND_OK;
                    if (onb_r) PQclear(onb_r);
                    if (!onb_ok) {
                        /* The agreement was executed; report the onboarding
                         * sync failure instead of claiming full success. */
                        db_release(conn, 0);
                        inst_send_error(client_fd, 500, "Agreement executed but onboarding state could not be updated", origin, extra_headers, extra_len);
                        return;
                    }
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
            /* C3 fix: verify caller has scope over this deployment's institution. */
            const char *scope_q_vals[1] = { dep_id };
            int scope_q_lens[1] = { (int)strlen(dep_id) };
            PGresult *scope_res = db_simple(conn,
                "SELECT institution_id FROM institution_os_deployments WHERE id = $1",
                1, scope_q_vals, scope_q_lens);
            if (!scope_res || PQresultStatus(scope_res) != PGRES_TUPLES_OK || PQntuples(scope_res) == 0) {
                if (scope_res) PQclear(scope_res);
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Deployment not found", origin, extra_headers, extra_len);
                return;
            }
            char dep_inst_id[64] = {0};
            snprintf(dep_inst_id, sizeof(dep_inst_id), "%s", PQgetvalue(scope_res, 0, 0));
            PQclear(scope_res);
            if (!is_owner && strcmp(sess.institution_id, dep_inst_id) != 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 403, "Access denied: deployment belongs to a different institution", origin, extra_headers, extra_len);
                return;
            }

            char st[40] = {0};
            int ack = -1;
            ctrl_json_string(body, "status", st, sizeof(st));
            ctrl_json_int(body, "devicesAcknowledged", &ack);

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            char ack_s[16]; snprintf(ack_s, sizeof(ack_s), "%d", ack);
            const char *uv[4] = { st[0] ? st : "", ack_s, now, dep_id };
            int ul[4]; for (int i = 0; i < 4; i++) ul[i] = (int)strlen(uv[i]);
            PGresult *res = db_simple(conn,
                "UPDATE institution_os_deployments SET "
                "status=CASE WHEN $1<>'' THEN $1 ELSE status END, "
                "devices_acknowledged=CASE WHEN $2::integer>=0 THEN $2::integer ELSE devices_acknowledged END, "
                "updated_at=$3::bigint WHERE id=$4",
                4, uv, ul);
            /* H3 fix: check UPDATE result, return 500 on failure. */
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            if (res) PQclear(res);
            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to update deployment status", origin, extra_headers, extra_len);
                return;
            }

            audit_and_ledger(sess.user_id, "OS_DEPLOYMENT_STATUS_UPDATED", dep_id, st);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"updated\",\"deployment_id\":\"%s\"}", dep_id);
            inst_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        if (strcmp(method, "POST") == 0 && (strcmp(act, "push-kiosk") == 0 || strcmp(act, "push") == 0)) {
            /* C3 fix: verify the caller has scope over this deployment's institution. */
            const char *dep_q_vals[1] = { dep_id };
            int dep_q_lens[1] = { (int)strlen(dep_id) };
            PGresult *scope_res = db_simple(conn,
                "SELECT institution_id FROM institution_os_deployments WHERE id = $1",
                1, dep_q_vals, dep_q_lens);
            if (!scope_res || PQresultStatus(scope_res) != PGRES_TUPLES_OK || PQntuples(scope_res) == 0) {
                if (scope_res) PQclear(scope_res);
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Deployment not found", origin, extra_headers, extra_len);
                return;
            }
            char dep_inst_id[64] = {0};
            snprintf(dep_inst_id, sizeof(dep_inst_id), "%s", PQgetvalue(scope_res, 0, 0));
            PQclear(scope_res);
            if (!is_owner && strcmp(sess.institution_id, dep_inst_id) != 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 403, "Access denied: deployment belongs to a different institution", origin, extra_headers, extra_len);
                return;
            }

            /* C1 fix: parameterized query — no string interpolation of dep_id. */
            PGresult *q = db_simple(conn,
                "SELECT release_id, channel, security_profile "
                "FROM institution_os_deployments WHERE id = $1",
                1, dep_q_vals, dep_q_lens);
            if (!q || PQresultStatus(q) != PGRES_TUPLES_OK || PQntuples(q) == 0) {
                if (q) PQclear(q);
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Deployment not found", origin, extra_headers, extra_len);
                return;
            }
            char rel[64] = {0}, chan[40] = {0}, sec[60] = {0};
            snprintf(rel, sizeof(rel), "%s", PQgetvalue(q, 0, 0));
            snprintf(chan, sizeof(chan), "%s", PQgetvalue(q, 0, 1));
            snprintf(sec, sizeof(sec), "%s", PQgetvalue(q, 0, 2));
            PQclear(q);
            if (!rel[0]) {
                db_release(conn, 0);
                inst_send_error(client_fd, 409,
                    "Deployment has no OS release assigned; assign a release before pushing to kiosks",
                    origin, extra_headers, extra_len);
                return;
            }

            int target_count = kiosk_get_active_count();
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            char tc_str[16]; snprintf(tc_str, sizeof(tc_str), "%d", target_count);

            const char *upd_vals[3] = { tc_str, now, dep_id };
            int upd_lens[3] = { (int)strlen(tc_str), (int)strlen(now), (int)strlen(dep_id) };
            PGresult *u = db_simple(conn,
                "UPDATE institution_os_deployments SET status = 'ACTIVE', "
                "devices_targeted = $1::integer, updated_at = $2::bigint WHERE id = $3",
                3, upd_vals, upd_lens);
            int upd_ok = u && PQresultStatus(u) == PGRES_COMMAND_OK;
            if (u) PQclear(u);
            if (!upd_ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to record the deployment push", origin, extra_headers, extra_len);
                return;
            }

            kiosk_broadcast_os_update(rel, chan, sec);
            audit_and_ledger(sess.user_id, "OS_DEPLOYMENT_PUSHED_TO_KIOSK", dep_id, rel);
            db_release(conn, 0);

            char resp[640];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"QUEUED\",\"deployment_id\":\"%s\",\"release_id\":\"%s\",\"channel\":\"%s\",\"security_profile\":\"%s\",\"devices_targeted\":%d,\"message\":\"OS deployment queued for the next kiosk poll; %d connected kiosk(s) will receive it\"}",
                dep_id, rel, chan, sec, target_count, target_count);
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
                    PQgetvalue(res, i, 6)[0] ? PQgetvalue(res, i, 6) : "0",
                    PQgetvalue(res, i, 7)[0] ? PQgetvalue(res, i, 7) : "unknown",
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
                inst_generate_code("CMP", code, sizeof(code));
                if (!code[0]) {
                    db_release(conn, 0);
                    inst_send_error(client_fd, 503, "Secure campus code generation unavailable", origin, extra_headers, extra_len);
                    return;
                }
            }

            char id[64]; inst_generate_id("cmp", id, sizeof(id));
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            char cap_str[16]; snprintf(cap_str, sizeof(cap_str), "%d", capacity);

            const char *pvals[8] = { id, tenant_id, name, code, city, address, cap_str, now };
            int plens[8]; for (int i = 0; i < 8; i++) plens[i] = (int)strlen(pvals[i]);

            PGresult *res = db_simple(conn,
                "INSERT INTO campuses (id, tenant_id, name, code, city, address, capacity, status, created_at, updated_at) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7::integer,'active',$8::bigint,$8::bigint)",
                8, pvals, plens);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            if (!ok) {
                if (res) PQclear(res);
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to create campus", origin, extra_headers, extra_len);
                return;
            }
            PQclear(res);

            audit_and_ledger(sess.user_id, "CAMPUS_CREATED", id, name);
            db_release(conn, 0);

            char resp[320];
            snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"campus_id\":\"%s\",\"code\":\"%s\"}", id, code);
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
            if (strcmp(st, "active") != 0 && strlen(reason) < 8) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "A reason of at least 8 characters is required to deactivate or archive a campus", origin, extra_headers, extra_len);
                return;
            }

            /* Refuse to take a campus out of service while a published or live
             * exam still depends on one of its centers. */
            if (strcmp(st, "active") != 0) {
                const char *gv[1] = { cmp_id };
                int gl[1] = { (int)strlen(cmp_id) };
                PGresult *g = db_simple(conn,
                    "SELECT 1 FROM exams e WHERE e.status IN ('published','live') "
                    "AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(e.center_ids) AS cid(value) "
                    "            JOIN centers c ON c.id = cid.value "
                    "            WHERE c.campus_id = $1) LIMIT 1",
                    1, gv, gl);
                int has_open = g && PQresultStatus(g) == PGRES_TUPLES_OK && PQntuples(g) > 0;
                if (g) PQclear(g);
                if (has_open) {
                    db_release(conn, 0);
                    inst_send_error(client_fd, 409, "An open exam uses a center in this campus; finish or cancel it first", origin, extra_headers, extra_len);
                    return;
                }
            }

            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));
            const char *uv[3] = { st, now, cmp_id };
            int ul[3]; for (int i = 0; i < 3; i++) ul[i] = (int)strlen(uv[i]);

            /* Scope: non-owners can only update campuses in their own institution */
            PGresult *res;
            if (is_owner) {
                res = db_simple(conn,
                    "UPDATE campuses SET status = $1, updated_at = $2::bigint WHERE id = $3",
                    3, uv, ul);
            } else {
                const char *uv4[4] = { st, now, cmp_id, sess.institution_id };
                int ul4[4]; for (int i = 0; i < 4; i++) ul4[i] = (int)strlen(uv4[i]);
                res = db_simple(conn,
                    "UPDATE campuses SET status = $1, updated_at = $2::bigint WHERE id = $3 AND tenant_id = $4",
                    4, uv4, ul4);
            }
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            int rows = ok ? atoi(PQcmdTuples(res)) : 0;
            if (res) PQclear(res);
            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to update campus status", origin, extra_headers, extra_len);
                return;
            }
            if (rows == 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Campus not found in this institution", origin, extra_headers, extra_len);
                return;
            }

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
            char cap_s[16]; snprintf(cap_s, sizeof(cap_s), "%d", capacity);
            PGresult *res;
            if (is_owner) {
                const char *uv[7] = { name, code, city, address, cap_s, cmp_id, now };
                int ul[7]; for (int i = 0; i < 7; i++) ul[i] = (int)strlen(uv[i]);
                res = db_simple(conn,
                    "UPDATE campuses SET "
                    "name=CASE WHEN $1<>'' THEN $1 ELSE name END, "
                    "code=CASE WHEN $2<>'' THEN $2 ELSE code END, "
                    "city=CASE WHEN $3<>'' THEN $3 ELSE city END, "
                    "address=CASE WHEN $4<>'' THEN $4 ELSE address END, "
                    "capacity=CASE WHEN $5::integer>=0 THEN $5::integer ELSE capacity END, "
                    "updated_at=$7::bigint WHERE id=$6",
                    7, uv, ul);
            } else {
                const char *uv[8] = { name, code, city, address, cap_s, cmp_id, sess.institution_id, now };
                int ul[8]; for (int i = 0; i < 8; i++) ul[i] = (int)strlen(uv[i]);
                res = db_simple(conn,
                    "UPDATE campuses SET "
                    "name=CASE WHEN $1<>'' THEN $1 ELSE name END, "
                    "code=CASE WHEN $2<>'' THEN $2 ELSE code END, "
                    "city=CASE WHEN $3<>'' THEN $3 ELSE city END, "
                    "address=CASE WHEN $4<>'' THEN $4 ELSE address END, "
                    "capacity=CASE WHEN $5::integer>=0 THEN $5::integer ELSE capacity END, "
                    "updated_at=$8::bigint WHERE id=$6 AND tenant_id=$7",
                    8, uv, ul);
            }
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            int rows = ok ? atoi(PQcmdTuples(res)) : 0;
            if (res) PQclear(res);
            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to update campus", origin, extra_headers, extra_len);
                return;
            }
            if (rows == 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Campus not found in this institution", origin, extra_headers, extra_len);
                return;
            }

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
                    d_type[0] ? d_type : "",
                    PQgetvalue(res, i, 6)[0] ? PQgetvalue(res, i, 6) : "unknown",
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

            char id[64]; inst_generate_id("dep", id, sizeof(id));
            if (!code[0]) {
                inst_generate_code("DEP", code, sizeof(code));
                if (!code[0]) {
                    db_release(conn, 0);
                    inst_send_error(client_fd, 503, "Secure department code generation unavailable", origin, extra_headers, extra_len);
                    return;
                }
            }
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            const char *pvals[7] = { id, tenant_id, campus_id, name, code, type, now };
            int plens[7]; for (int i = 0; i < 7; i++) plens[i] = (int)strlen(pvals[i]);

            PGresult *res = db_simple(conn,
                "INSERT INTO departments (id, tenant_id, campus_id, name, code, type, status, created_at, updated_at) "
                "VALUES ($1,$2,$3,$4,$5,$6,'active',$7::bigint,$7::bigint)",
                7, pvals, plens);
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            if (!ok) {
                if (res) PQclear(res);
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to create department", origin, extra_headers, extra_len);
                return;
            }
            PQclear(res);

            audit_and_ledger(sess.user_id, "DEPARTMENT_CREATED", id, name);
            db_release(conn, 0);

            char resp[320];
            snprintf(resp, sizeof(resp), "{\"status\":\"created\",\"department_id\":\"%s\",\"code\":\"%s\"}", id, code);
            inst_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 5c. POST /api/v1/admin/departments/:id/status -> Status update */
        if (strcmp(method, "POST") == 0 && strcmp(act, "status") == 0) {
            char st[32] = {0}, reason[256] = {0};
            ctrl_json_string(body, "status", st, sizeof(st));
            ctrl_json_string(body, "reason", reason, sizeof(reason));
            if (strcmp(st, "active") != 0 && strcmp(st, "inactive") != 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "Invalid department status: must be active or inactive", origin, extra_headers, extra_len);
                return;
            }
            if (strcmp(st, "inactive") == 0 && strlen(reason) < 8) {
                db_release(conn, 0);
                inst_send_error(client_fd, 400, "A reason of at least 8 characters is required to deactivate a department", origin, extra_headers, extra_len);
                return;
            }
            if (strcmp(st, "inactive") == 0) {
                const char *gv[1] = { dep_id };
                int gl[1] = { (int)strlen(dep_id) };
                PGresult *g = db_simple(conn,
                    "SELECT 1 FROM staff WHERE department_id = $1 AND status = 'active' LIMIT 1",
                    1, gv, gl);
                int has_staff = g && PQresultStatus(g) == PGRES_TUPLES_OK && PQntuples(g) > 0;
                if (g) PQclear(g);
                if (has_staff) {
                    db_release(conn, 0);
                    inst_send_error(client_fd, 409, "Reassign active staff before deactivating this department", origin, extra_headers, extra_len);
                    return;
                }
            }
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            PGresult *res;
            if (is_owner) {
                const char *uv[3] = { st, now, dep_id };
                int ul[3] = { (int)strlen(st), (int)strlen(now), (int)strlen(dep_id) };
                res = db_simple(conn,
                    "UPDATE departments SET status=$1, updated_at=$2::bigint WHERE id=$3",
                    3, uv, ul);
            } else {
                const char *uv[4] = { st, now, dep_id, sess.institution_id };
                int ul[4] = { (int)strlen(st), (int)strlen(now), (int)strlen(dep_id), (int)strlen(sess.institution_id) };
                res = db_simple(conn,
                    "UPDATE departments SET status=$1, updated_at=$2::bigint WHERE id=$3 AND tenant_id=$4",
                    4, uv, ul);
            }
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            int rows = ok ? atoi(PQcmdTuples(res)) : 0;
            if (res) PQclear(res);
            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to update department status", origin, extra_headers, extra_len);
                return;
            }
            if (rows == 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Department not found in this institution", origin, extra_headers, extra_len);
                return;
            }

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
                    PQgetvalue(res, i, 7)[0] ? PQgetvalue(res, i, 7) : "unknown",
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

            char id[64]; inst_generate_id("stf", id, sizeof(id));
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
            if (!ok) {
                if (res) PQclear(res);
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to assign staff member", origin, extra_headers, extra_len);
                return;
            }
            PQclear(res);

            audit_and_ledger(sess.user_id, "STAFF_ASSIGNED", user_id, campus_id[0] ? campus_id : "all campuses");
            db_release(conn, 0);

            char name_esc[300] = {0}, role_esc[160] = {0};
            escape_json_str(name, name_esc, sizeof(name_esc));
            escape_json_str(role_title, role_esc, sizeof(role_esc));

            char resp[640];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"saved\",\"staff_id\":\"%s\",\"name\":\"%s\",\"role_title\":\"%s\","
                "\"campus_id\":\"%s\",\"department_id\":\"%s\"}",
                id, name_esc, role_esc, campus_id, department_id);
            inst_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
            return;
        }

        /* 6c. DELETE or POST /api/v1/admin/staff/:id/remove -> Remove staff */
        if ((strcmp(method, "DELETE") == 0 || strcmp(method, "POST") == 0) && stf_id[0]) {
            char reason[256] = {0};
            ctrl_json_string(body, "reason", reason, sizeof(reason));
            char now[32]; snprintf(now, sizeof(now), "%ld000", (long)time(NULL));

            PGresult *res;
            if (is_owner) {
                const char *uv[3] = { reason, now, stf_id };
                int ul[3] = { (int)strlen(reason), (int)strlen(now), (int)strlen(stf_id) };
                res = db_simple(conn,
                    "UPDATE staff SET status='inactive', status_reason=$1, updated_at=$2::bigint WHERE id=$3",
                    3, uv, ul);
            } else {
                const char *uv[4] = { reason, now, stf_id, sess.institution_id };
                int ul[4] = { (int)strlen(reason), (int)strlen(now), (int)strlen(stf_id), (int)strlen(sess.institution_id) };
                res = db_simple(conn,
                    "UPDATE staff SET status='inactive', status_reason=$1, updated_at=$2::bigint WHERE id=$3 AND tenant_id=$4",
                    4, uv, ul);
            }
            int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            int rows = ok ? atoi(PQcmdTuples(res)) : 0;
            if (res) PQclear(res);
            if (!ok) {
                db_release(conn, 0);
                inst_send_error(client_fd, 500, "Failed to remove staff member", origin, extra_headers, extra_len);
                return;
            }
            if (rows == 0) {
                db_release(conn, 0);
                inst_send_error(client_fd, 404, "Staff member not found in this institution", origin, extra_headers, extra_len);
                return;
            }

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

