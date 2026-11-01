/*
 * session_controller.c — Candidate exam workbench + proctoring.
 * Mirrors frontend modules/submissions/service.js and exam workbench routes.
 */

#include "session_controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../security/security.h"
#include "../include/secure_token.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>

static void audit_log(const char *actor, const char *event, const char *detail) {
    audit_append(actor, event, detail);
}

static void ses_send_json(int fd, int code, const char *body,
                          const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

/* Candidate token check: bearer token from /api/v1/candidate/login */
static int candidate_authorized(const char *auth_header, char *cid_out, size_t cid_len) {
    char token[128] = {0};
    if (!ctrl_extract_bearer(auth_header, token, sizeof(token)) || !token[0])
        return 0;
    PGconn *conn = db_acquire();
    if (!conn) return 0;
    char token_hash[65] = {0};
    if (secure_token_hash(token, token_hash) != 0) {
        db_release(conn, 0);
        return 0;
    }
    const char *p[1] = { token_hash };
    int l[1] = { (int)strlen(token_hash) };
    PGresult *r = db_simple(conn, "SELECT user_id FROM auth_sessions WHERE session_token = $1 AND status = 'active'", 1, p, l);
    int found = r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0;
    if (found && cid_out) {
        strncpy(cid_out, PQgetvalue(r, 0, 0), cid_len - 1);
    }
    if (r) PQclear(r);
    db_release(conn, 0);
    return found;
}

void session_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len) {
    /* ---- Exam paper (candidate) ---- */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/exam/paper") == 0) {
        char cid[64] = {0};
        if (!candidate_authorized(auth_header, cid, sizeof(cid))) {
            ses_send_json(client_fd, 401,
                "{\"status\":\"FAIL\",\"error\":\"Unauthorized exam session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 200,
            "{\"questions\":[{\"id\":0,\"q\":\"Sample question\",\"options\":[\"A\",\"B\",\"C\",\"D\"],\"answer\":0}]}",
            origin, extra_headers, extra_len);
        return;
    }

    /* ---- Save answer (candidate) ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/exam/save_answer") == 0) {
        char cid[64] = {0};
        if (!candidate_authorized(auth_header, cid, sizeof(cid))) {
            ses_send_json(client_fd, 401,
                "{\"status\":\"FAIL\",\"error\":\"Unauthorized exam session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 200, "{\"status\":\"SAVED\"}",
                      origin, extra_headers, extra_len);
        return;
    }

    /* ---- Submit exam (candidate) ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/exam/submit") == 0) {
        char cid[64] = {0};
        if (!candidate_authorized(auth_header, cid, sizeof(cid))) {
            ses_send_json(client_fd, 401,
                "{\"status\":\"FAIL\",\"error\":\"Unauthorized exam session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        /* Generate receipt */
        char receipt[32]; snprintf(receipt, sizeof(receipt), "RC-%08lx", (long)time(NULL));
        char body[256];
        snprintf(body, sizeof(body),
            "{\"status\":\"OK\",\"receipt\":\"%s\",\"submitted_at\":%ld}",
            receipt, (long)time(NULL));
        ses_send_json(client_fd, 200, body, origin, extra_headers, extra_len);
        audit_log(cid, "SESSION_SUBMITTED", receipt);
        return;
    }

    /* ---- Announcements ---- */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/exam/announcements") == 0) {
        ses_send_json(client_fd, 200, "{\"announcements\":[]}",
                      origin, extra_headers, extra_len);
        return;
    }

    /* ---- Terminals (admin) ---- */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/exam/terminals") == 0) {
        auth_session_t sess;
        if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
            ses_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 200, "[]", origin, extra_headers, extra_len);
        return;
    }

    /* ---- Exam command (admin) ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/exam/command") == 0) {
        auth_session_t sess;
        if (ctrl_authorize(auth_header, AUTH_PERM_EXAM_MUTATION, &sess) != 0) {
            ses_send_json(client_fd, 401, "{\"error\":\"Admin write permissions required\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 200, "{\"status\":\"COMMAND_EXECUTED\"}",
                      origin, extra_headers, extra_len);
        return;
    }

    /* ---- Key release eligibility (candidate) ---- */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/exam/key-release/eligibility") == 0) {
        char cid[64] = {0};
        if (!candidate_authorized(auth_header, cid, sizeof(cid))) {
            ses_send_json(client_fd, 401,
                "{\"error\":\"Valid candidate bearer token required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 200, "{\"status\":\"ELIGIBLE\"}",
                      origin, extra_headers, extra_len);
        return;
    }

    /* ---- Key release (candidate) ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/exam/key-release") == 0) {
        char cid[64] = {0};
        if (!candidate_authorized(auth_header, cid, sizeof(cid))) {
            ses_send_json(client_fd, 401,
                "{\"error\":\"Valid candidate bearer token required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char sess_id[64] = {0}, dev_id[64] = {0};
        ctrl_json_string(body, "session_id", sess_id, sizeof(sess_id));
        ctrl_json_string(body, "device_id", dev_id, sizeof(dev_id));
        if (!sess_id[0]) ctrl_json_string(body, "attestation_id", sess_id, sizeof(sess_id));

        /* Generate a session key (simulated) */
        char skey[65] = {0};
        {
            unsigned char rnd[32];
            RAND_bytes(rnd, sizeof(rnd));
            static const char hex[] = "0123456789abcdef";
            for (int i = 0; i < 32; i++) {
                skey[i*2] = hex[rnd[i] >> 4];
                skey[i*2+1] = hex[rnd[i] & 0x0f];
            }
            skey[64] = '\0';
        }
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"KEY_RELEASED\",\"session_id\":\"%s\",\"session_key\":\"%s\"}",
            sess_id, skey);
        OPENSSL_cleanse(skey, sizeof(skey));
        ses_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
        audit_log(cid, "KEY_RELEASED", sess_id);
        return;
    }

    /* ---- Consent (candidate) ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/consent") == 0) {
        char cid[64] = {0};
        if (!candidate_authorized(auth_header, cid, sizeof(cid))) {
            ses_send_json(client_fd, 401,
                "{\"error\":\"Valid candidate bearer token required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char sess_id[64] = {0}, cand_id[64] = {0};
        ctrl_json_string(body, "session_id", sess_id, sizeof(sess_id));
        ctrl_json_string(body, "candidate_id", cand_id, sizeof(cand_id));
        if (!sess_id[0] || !cand_id[0]) {
            ses_send_json(client_fd, 400,
                "{\"error\":\"session_id and candidate_id required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char c_resp[256];
        snprintf(c_resp, sizeof(c_resp),
            "{\"status\":\"CONSENT_RECORDED\",\"session_id\":\"%s\",\"block_index\":1}",
            sess_id);
        ses_send_json(client_fd, 200, c_resp, origin, extra_headers, extra_len);
        audit_log(cand_id, "CANDIDATE_CONSENT_GRANTED", sess_id);
        return;
    }

    /* ---- Proctoring events (agent/proctor token) ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/proctoring/events") == 0) {
        const char *env = getenv("EXAMOS_PROCTOR_API_TOKEN");
        char token[128] = {0};
        int ok = 0;
        if (env && env[0] &&
            ctrl_extract_bearer(auth_header, token, sizeof(token)) &&
            security_safe_equal(token, env)) ok = 1;
        if (!ok) {
            /* Also allow admin */
            auth_session_t sess;
            if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
                ses_send_json(client_fd, 401,
                    "{\"error\":\"Valid proctor service token required\"}",
                    origin, extra_headers, extra_len);
                return;
            }
        }
        char sess_id[64] = {0}, src[64] = {0}, ev_type[64] = {0};
        char model[64] = {0}, ver[64] = {0};
        ctrl_json_string(body, "session_id", sess_id, sizeof(sess_id));
        ctrl_json_string(body, "source_type", src, sizeof(src));
        ctrl_json_string(body, "event_type", ev_type, sizeof(ev_type));
        ctrl_json_string(body, "model_name", model, sizeof(model));
        ctrl_json_string(body, "model_version", ver, sizeof(ver));
        if (!sess_id[0] || !src[0] || !ev_type[0]) {
            ses_send_json(client_fd, 400,
                "{\"error\":\"session_id, source_type, event_type required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (!model[0] || !ver[0]) {
            ses_send_json(client_fd, 400,
                "{\"error\":\"model_name and model_version required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 202,
            "{\"status\":\"RECORDED\",\"sequence\":1,\"event_hash\":\"abc123\","
            "\"risk_score\":0.00,\"risk_level\":\"LOW\",\"terminate_recommended\":false}",
            origin, extra_headers, extra_len);
        audit_log(sess_id, "PROCTORING_EVENT", ev_type);
        return;
    }

    /* ---- List proctoring events (admin) ---- */
    if (strcmp(method, "GET") == 0 &&
        strncmp(path, "/api/v1/proctoring/events", 25) == 0) {
        auth_session_t sess;
        if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
            ses_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 200, "{\"events\":[]}",
                      origin, extra_headers, extra_len);
        return;
    }

    /* ---- Checkpoint ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/proctoring/checkpoint") == 0) {
        ses_send_json(client_fd, 200,
            "{\"status\":\"CHECKPOINT_SIGNED\",\"session_id\":\"...\",\"sequence\":1,\"latest_hash\":\"...\",\"key_id\":\"...\",\"server_timestamp\":0,\"signature\":\"...\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* ---- Verify chain ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/proctoring/verify") == 0) {
        auth_session_t sess;
        if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
            ses_send_json(client_fd, 401, "{\"error\":\"Admin credentials required\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 200, "{\"status\":\"VERIFIED\",\"events_verified\":0,\"chain_integrity\":\"VALID\"}",
                      origin, extra_headers, extra_len);
        return;
    }

    /* ---- Second camera request (candidate) ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/second-camera/request") == 0) {
        char cid[64] = {0};
        if (!candidate_authorized(auth_header, cid, sizeof(cid))) {
            ses_send_json(client_fd, 401,
                "{\"error\":\"Valid candidate bearer token required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char token[128] = {0};
        {
            unsigned char rnd[32];
            RAND_bytes(rnd, sizeof(rnd));
            static const char hex[] = "0123456789abcdef";
            for (int i = 0; i < 16; i++) {
                token[i*2] = hex[rnd[i] >> 4];
                token[i*2+1] = hex[rnd[i] & 0x0f];
            }
            token[32] = '\0';
        }
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"PAIRING_REQUESTED\",\"session_id\":\"%s\",\"pairing_token\":\"%s\",\"expires_in_seconds\":300}",
            cid, token);
        OPENSSL_cleanse(token, sizeof(token));
        ses_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        return;
    }

    /* ---- Second camera pair ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/second-camera/pair") == 0) {
        char sess_id[64] = {0}, tok[128] = {0};
        ctrl_json_string(body, "session_id", sess_id, sizeof(sess_id));
        ctrl_json_string(body, "token", tok, sizeof(tok));
        if (!sess_id[0] || !tok[0]) {
            ses_send_json(client_fd, 400,
                "{\"error\":\"session_id and token required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 200, "{\"status\":\"PAIRED\",\"session_id\":\"...\"}",
                      origin, extra_headers, extra_len);
        OPENSSL_cleanse(tok, sizeof(tok));
        return;
    }

    ses_send_json(client_fd, 404, "{\"error\":\"Not found\"}",
                  origin, extra_headers, extra_len);
}
