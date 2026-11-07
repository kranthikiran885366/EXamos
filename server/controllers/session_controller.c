/*
 * session_controller.c — Candidate exam workbench + proctoring.
 * Mirrors frontend modules/submissions/service.js and exam workbench routes.
 */

#include "session_controller.h"
#include "../include/attestation_service.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char candidate_id[64];
    char exam_session_id[64];
    char exam_id[64];
    char institution_id[64];
    char student_id[64];
    char device_id[64];
    char status[32];
    char deadline_at[32];
} candidate_exam_context_t;

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} runtime_json_t;

static void ses_send_json(int fd, int code, const char *body,
                          const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

/* Candidate token check: bearer token from /api/v1/candidate/login */
static int candidate_authorized(const char *auth_header, char *cid_out, size_t cid_len) {
    return ctrl_candidate_session_identity(auth_header, cid_out, cid_len);
}

static int runtime_json_reserve(runtime_json_t *json, size_t additional) {
    if (!json || additional > 4U * 1024U * 1024U - json->length) return -1;
    size_t needed = json->length + additional + 1;
    if (needed <= json->capacity) return 0;
    size_t capacity = json->capacity ? json->capacity : 1024;
    while (capacity < needed) {
        if (capacity > 2U * 1024U * 1024U) {
            capacity = 4U * 1024U * 1024U + 1;
            break;
        }
        capacity *= 2;
    }
    if (capacity > 4U * 1024U * 1024U + 1) return -1;
    char *data = realloc(json->data, capacity);
    if (!data) return -1;
    json->data = data;
    json->capacity = capacity;
    return 0;
}

static int runtime_json_text(runtime_json_t *json, const char *text) {
    if (!text) text = "";
    size_t length = strlen(text);
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)text[i];
        size_t extra = c < 0x20 ? 6 : ((c == '"' || c == '\\') ? 2 : 1);
        if (runtime_json_reserve(json, extra) != 0) return -1;
        if (c == '"' || c == '\\') {
            json->data[json->length++] = '\\';
            json->data[json->length++] = (char)c;
        } else if (c < 0x20) {
            static const char hex[] = "0123456789abcdef";
            json->data[json->length++] = '\\';
            json->data[json->length++] = 'u';
            json->data[json->length++] = '0';
            json->data[json->length++] = '0';
            json->data[json->length++] = hex[c >> 4];
            json->data[json->length++] = hex[c & 15];
        } else {
            json->data[json->length++] = (char)c;
        }
    }
    json->data[json->length] = '\0';
    return 0;
}

static int runtime_json_append(runtime_json_t *json, const char *text) {
    size_t length = strlen(text);
    if (runtime_json_reserve(json, length) != 0) return -1;
    memcpy(json->data + json->length, text, length);
    json->length += length;
    json->data[json->length] = '\0';
    return 0;
}

static int candidate_exam_context_load(const char *auth_header,
                                      candidate_exam_context_t *context) {
    if (!context) return -1;
    memset(context, 0, sizeof(*context));
    if (!ctrl_candidate_session_context(auth_header, context->candidate_id,
            sizeof(context->candidate_id), context->exam_session_id,
            sizeof(context->exam_session_id))) return 0;
    PGconn *conn = db_acquire();
    if (!conn) return -1;
    const char *params[2] = { context->exam_session_id, context->candidate_id };
    int lengths[2] = { (int)strlen(params[0]), (int)strlen(params[1]) };
    PGresult *result = db_simple(conn,
        "SELECT s.examination_id,s.institution_id,s.student_id,s.device_id,s.status,"
        "COALESCE(s.deadline_at::text,'') "
        "FROM exam_sessions s "
        "JOIN students st ON st.id=s.student_id "
        "JOIN candidates c ON c.id=$2 AND c.exam_id=s.examination_id "
        "AND c.tenant_id=s.institution_id AND c.roll_no=st.roll_no "
        "AND lower(COALESCE(c.status,'')) NOT IN "
        "('disqualified','suspended','withdrawn','cancelled','canceled','expired',"
        "'completed','submitted','blocked','inactive','revoked','ineligible') "
        "JOIN exam_student_assignments a ON a.exam_id=s.examination_id "
        "AND a.institution_id=s.institution_id AND a.roll_no=st.roll_no "
        "AND a.assigned_device_id=s.device_id AND a.eligibility_status='eligible' "
        "AND (a.student_id=st.id OR a.student_id=st.roll_no) "
        "WHERE s.id=$1",
        2, params, lengths);
    if (!result || PQresultStatus(result) != PGRES_TUPLES_OK) {
        if (result) PQclear(result);
        db_release(conn, 1);
        return -1;
    }
    if (PQntuples(result) != 1) {
        PQclear(result);
        db_release(conn, 0);
        return 0;
    }
    snprintf(context->exam_id, sizeof(context->exam_id), "%s", PQgetvalue(result, 0, 0));
    snprintf(context->institution_id, sizeof(context->institution_id), "%s", PQgetvalue(result, 0, 1));
    snprintf(context->student_id, sizeof(context->student_id), "%s", PQgetvalue(result, 0, 2));
    snprintf(context->device_id, sizeof(context->device_id), "%s", PQgetvalue(result, 0, 3));
    snprintf(context->status, sizeof(context->status), "%s", PQgetvalue(result, 0, 4));
    snprintf(context->deadline_at, sizeof(context->deadline_at), "%s", PQgetvalue(result, 0, 5));
    if (result) PQclear(result);
    db_release(conn, 0);
    return 1;
}

static int candidate_exam_trusted(const candidate_exam_context_t *context) {
    return context && context->exam_session_id[0] && context->device_id[0] &&
        attestation_check_device_binding(context->exam_session_id,
                                         context->device_id) == 0 &&
        attestation_check_exam_key_ready(context->exam_session_id,
                                         context->device_id) == 0;
}

static int parse_i64_field(const char *body, const char *key, int allow_zero,
                           long long *out) {
    if (!body || !key || !out) return -1;
    char pattern[96];
    int written = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (written < 0 || (size_t)written >= sizeof(pattern)) return -1;
    const char *p = strstr(body, pattern);
    if (!p) return -1;
    p += (size_t)written;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (*p++ != ':') return -1;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    int quoted = *p == '"';
    if (quoted) ++p;
    if (*p < '0' || *p > '9') return -1;
    errno = 0;
    char *end = NULL;
    long long value = strtoll(p, &end, 10);
    if (errno || end == p || value < (allow_zero ? 0 : 1) ||
        (quoted ? *end != '"' : (*end != ',' && *end != '}' &&
                                  *end != ' ' && *end != '\r' &&
                                  *end != '\n' && *end != '\t'))) return -1;
    *out = value;
    return 0;
}

static void encode_u64_be(uint64_t value, unsigned char output[8]) {
    for (int i = 7; i >= 0; --i) {
        output[i] = (unsigned char)(value & 0xff);
        value >>= 8;
    }
}

static int candidate_answer_digest(PGconn *conn, const char *exam_session_id,
                                   int *answer_count, char output[65]) {
    const char *params[1] = { exam_session_id };
    int lengths[1] = { (int)strlen(exam_session_id) };
    PGresult *answers = db_simple(conn,
        "SELECT question_id,answer_text FROM candidate_exam_answers "
        "WHERE exam_session_id=$1 ORDER BY question_id",
        1, params, lengths);
    if (!answers || PQresultStatus(answers) != PGRES_TUPLES_OK) {
        if (answers) PQclear(answers);
        return -1;
    }
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    unsigned int digest_len = 0;
    int ok = digest && EVP_DigestInit_ex(digest, EVP_sha256(), NULL) == 1;
    static const char domain[] = "ExamOS candidate submission v1";
    if (ok) ok = EVP_DigestUpdate(digest, domain, sizeof(domain) - 1) == 1;
    for (int row = 0; ok && row < PQntuples(answers); ++row) {
        char *end = NULL;
        errno = 0;
        unsigned long long question_id = strtoull(PQgetvalue(answers, row, 0), &end, 10);
        const char *answer = PQgetvalue(answers, row, 1);
        size_t answer_len = (size_t)PQgetlength(answers, row, 1);
        unsigned char frame[16];
        if (errno || end == PQgetvalue(answers, row, 0) || *end) {
            ok = 0;
            break;
        }
        encode_u64_be((uint64_t)question_id, frame);
        encode_u64_be((uint64_t)answer_len, frame + 8);
        ok = EVP_DigestUpdate(digest, frame, sizeof(frame)) == 1 &&
             EVP_DigestUpdate(digest, answer, answer_len) == 1;
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    if (ok) ok = EVP_DigestFinal_ex(digest, hash, &digest_len) == 1 &&
                 digest_len == 32;
    if (ok) {
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < 32; ++i) {
            output[i * 2] = hex[hash[i] >> 4];
            output[i * 2 + 1] = hex[hash[i] & 15];
        }
        output[64] = '\0';
        *answer_count = PQntuples(answers);
    }
    OPENSSL_cleanse(hash, sizeof(hash));
    if (digest) EVP_MD_CTX_free(digest);
    PQclear(answers);
    return ok ? 0 : -1;
}

void session_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len) {
    if ((strcmp(method, "GET") == 0 &&
         strcmp(path, "/api/v1/exam/paper") == 0) ||
        (strcmp(method, "POST") == 0 &&
         (strcmp(path, "/api/v1/exam/save_answer") == 0 ||
          strcmp(path, "/api/v1/exam/submit") == 0))) {
        ses_send_json(client_fd, 410,
            "{\"status\":\"EXTERNAL_ASSESSMENT\","
            "\"error\":\"Exam content and submission are handled by the assigned assessment URL\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* ---- Candidate consent ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/consent") == 0) {
        candidate_exam_context_t context;
        int context_rc = candidate_exam_context_load(auth_header, &context);
        if (context_rc != 1) {
            ses_send_json(client_fd, context_rc < 0 ? 503 : 401,
                context_rc < 0 ? "{\"status\":\"UNAVAILABLE\",\"error\":\"Could not validate candidate exam session\"}" :
                "{\"status\":\"FAIL\",\"error\":\"Unauthorized exam session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char requested_session[64] = {0}, requested_candidate[64] = {0};
        int consent = 0;
        if (!ctrl_json_string(body, "session_id", requested_session,
                              sizeof(requested_session)) ||
            !ctrl_json_string(body, "candidate_id", requested_candidate,
                              sizeof(requested_candidate)) ||
            !ctrl_json_bool(body, "consent", &consent) || !consent ||
            strcmp(requested_session, context.exam_session_id) != 0 ||
            strcmp(requested_candidate, context.candidate_id) != 0) {
            ses_send_json(client_fd, 400,
                "{\"status\":\"FAIL\",\"error\":\"Explicit consent must match the authenticated candidate exam session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if ((strcmp(context.status, "authorized") != 0 &&
             strcmp(context.status, "active") != 0) ||
            !candidate_exam_trusted(&context)) {
            ses_send_json(client_fd, 403,
                "{\"status\":\"FAIL\",\"error\":\"Consent requires a fresh TPM-verified authorized exam session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PGconn *conn = db_acquire();
        if (!conn) {
            ses_send_json(client_fd, 503, "{\"status\":\"UNAVAILABLE\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        char consented_at[32];
        snprintf(consented_at, sizeof(consented_at), "%lld",
                 (long long)time(NULL) * 1000);
        const char *params[3] = { context.exam_session_id,
            context.candidate_id, consented_at };
        int lengths[3] = { (int)strlen(params[0]), (int)strlen(params[1]),
                           (int)strlen(params[2]) };
        PGresult *saved = db_simple(conn,
            "INSERT INTO candidate_exam_consents "
            "(exam_session_id,candidate_id,consent_version,consented_at) "
            "VALUES ($1,$2,'candidate-consent-v1',$3::bigint) "
            "ON CONFLICT (exam_session_id) DO NOTHING",
            3, params, lengths);
        int save_ok = saved && PQresultStatus(saved) == PGRES_COMMAND_OK;
        if (saved) PQclear(saved);
        PGresult *verified = save_ok ? db_simple(conn,
            "SELECT 1 FROM candidate_exam_consents "
            "WHERE exam_session_id=$1 AND candidate_id=$2 "
            "AND consent_version='candidate-consent-v1'",
            2, params, lengths) : NULL;
        int consent_ok = verified && PQresultStatus(verified) == PGRES_TUPLES_OK &&
                         PQntuples(verified) == 1;
        if (verified) PQclear(verified);
        db_release(conn, consent_ok ? 0 : 1);
        if (!consent_ok) {
            ses_send_json(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Candidate consent could not be durably recorded\"}",
                origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 200,
            "{\"status\":\"CONSENT_RECORDED\",\"consent_version\":\"candidate-consent-v1\"}",
            origin, extra_headers, extra_len);
        return;
    }

    /* ---- Exam paper (candidate) ---- */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/exam/paper") == 0) {
        candidate_exam_context_t context;
        int context_rc = candidate_exam_context_load(auth_header, &context);
        if (context_rc != 1) {
            ses_send_json(client_fd, context_rc < 0 ? 503 : 401,
                context_rc < 0 ? "{\"status\":\"UNAVAILABLE\",\"error\":\"Could not validate candidate exam session\"}" :
                "{\"status\":\"FAIL\",\"error\":\"Unauthorized exam session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if ((strcmp(context.status, "authorized") != 0 &&
             strcmp(context.status, "active") != 0) ||
            !candidate_exam_trusted(&context)) {
            ses_send_json(client_fd, 403,
                "{\"status\":\"FAIL\",\"error\":\"A fresh TPM-verified authorized exam session is required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PGconn *conn = db_acquire();
        if (!conn) {
            ses_send_json(client_fd, 503, "{\"status\":\"UNAVAILABLE\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        const char *consent_params[2] = { context.exam_session_id,
                                          context.candidate_id };
        int consent_lengths[2] = { (int)strlen(context.exam_session_id),
                                   (int)strlen(context.candidate_id) };
        PGresult *consent_row = db_simple(conn,
            "SELECT 1 FROM candidate_exam_consents WHERE exam_session_id=$1 "
            "AND candidate_id=$2 AND consent_version='candidate-consent-v1'",
            2, consent_params, consent_lengths);
        int consent_exists = consent_row &&
            PQresultStatus(consent_row) == PGRES_TUPLES_OK &&
            PQntuples(consent_row) == 1;
        if (consent_row) PQclear(consent_row);
        if (!consent_exists) {
            db_release(conn, 0);
            ses_send_json(client_fd, 403,
                "{\"status\":\"FAIL\",\"error\":\"Candidate consent must be recorded before paper delivery\"}",
                origin, extra_headers, extra_len);
            return;
        }
        const char *paper_params[1] = { context.exam_id };
        int paper_lengths[1] = { (int)strlen(context.exam_id) };
        PGresult *questions = db_simple(conn,
            "SELECT question_id,question_order,section,question_text,option_a,option_b,"
            "option_c,option_d,marks,question_type,code_template,"
            "COALESCE(a.answer_text,'') FROM examos_exam_questions q "
            "LEFT JOIN candidate_exam_answers a ON a.exam_session_id=$2 "
            "AND a.question_id=q.question_id "
            "WHERE q.exam_id=$1 AND q.active=true "
            "ORDER BY question_order",
            2, (const char *[]){ paper_params[0], context.exam_session_id },
            (const int[]){ paper_lengths[0], (int)strlen(context.exam_session_id) });
        if (!questions || PQresultStatus(questions) != PGRES_TUPLES_OK ||
            PQntuples(questions) == 0) {
            if (questions) PQclear(questions);
            db_release(conn, 0);
            ses_send_json(client_fd, 503,
                "{\"status\":\"UNAVAILABLE\",\"error\":\"No active examination paper is configured\"}",
                origin, extra_headers, extra_len);
            return;
        }
        runtime_json_t response = {0};
        int json_ok = runtime_json_append(&response,
            "{\"status\":\"READY\",\"exam_session_id\":\"") == 0 &&
            runtime_json_text(&response, context.exam_session_id) == 0 &&
            runtime_json_append(&response, "\",\"questions\":[") == 0;
        for (int row = 0; json_ok && row < PQntuples(questions); ++row) {
            if (row && runtime_json_append(&response, ",") != 0) {
                json_ok = 0;
                break;
            }
            char numbers[128];
            int n = snprintf(numbers, sizeof(numbers),
                "{\"question_id\":%s,\"order\":%s,\"marks\":%s,"
                "\"section\":\"",
                PQgetvalue(questions, row, 0), PQgetvalue(questions, row, 1),
                PQgetvalue(questions, row, 8));
            json_ok = n > 0 && (size_t)n < sizeof(numbers) &&
                runtime_json_append(&response, numbers) == 0 &&
                runtime_json_text(&response, PQgetvalue(questions, row, 2)) == 0 &&
                runtime_json_append(&response, "\",\"question_text\":\"") == 0 &&
                runtime_json_text(&response, PQgetvalue(questions, row, 3)) == 0 &&
                runtime_json_append(&response, "\",\"options\":[") == 0;
            for (int option = 4; json_ok && option <= 7; ++option) {
                if (option > 4 && runtime_json_append(&response, ",") != 0) {
                    json_ok = 0;
                    break;
                }
                json_ok = runtime_json_append(&response, "\"") == 0 &&
                    runtime_json_text(&response, PQgetvalue(questions, row, option)) == 0 &&
                    runtime_json_append(&response, "\"") == 0;
            }
            json_ok = json_ok &&
                runtime_json_append(&response, "],\"question_type\":\"") == 0 &&
                runtime_json_text(&response, PQgetvalue(questions, row, 9)) == 0 &&
                runtime_json_append(&response, "\",\"code_template\":\"") == 0 &&
                runtime_json_text(&response, PQgetvalue(questions, row, 10)) == 0 &&
                runtime_json_append(&response, "\",\"answer\":\"") == 0 &&
                runtime_json_text(&response, PQgetvalue(questions, row, 11)) == 0 &&
                runtime_json_append(&response, "\"}") == 0;
        }
        PQclear(questions);
        if (json_ok) json_ok = runtime_json_append(&response, "]}") == 0;
        if (!json_ok) {
            free(response.data);
            db_release(conn, 0);
            ses_send_json(client_fd, 413,
                "{\"status\":\"FAIL\",\"error\":\"Examination paper exceeds the supported response size\"}",
                origin, extra_headers, extra_len);
            return;
        }
        const char *activate_params[1] = { context.exam_session_id };
        int activate_lengths[1] = { (int)strlen(context.exam_session_id) };
        PGresult *activated = db_simple(conn,
            "UPDATE exam_sessions s SET status='active',"
            "launched_at=COALESCE(s.launched_at,EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000),"
            "deadline_at=COALESCE(s.deadline_at,LEAST("
            "COALESCE(s.launched_at,EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000)"
            "+e.duration_minutes::bigint*60000,"
            "COALESCE((SELECT CASE WHEN schedule.end_time<10000000000 "
            "THEN schedule.end_time*1000 ELSE schedule.end_time END "
            "FROM exam_schedules schedule WHERE schedule.exam_id=s.examination_id "
            "ORDER BY schedule.start_time ASC LIMIT 1),"
            "COALESCE(s.launched_at,EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000)"
            "+e.duration_minutes::bigint*60000))),"
            "updated_at=EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000 "
            "FROM examinations e WHERE s.id=$1 AND e.id=s.examination_id "
            "AND s.status IN ('authorized','active') "
            "AND COALESCE(s.deadline_at,LEAST("
            "COALESCE(s.launched_at,EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000)"
            "+e.duration_minutes::bigint*60000,"
            "COALESCE((SELECT CASE WHEN schedule.end_time<10000000000 "
            "THEN schedule.end_time*1000 ELSE schedule.end_time END "
            "FROM exam_schedules schedule WHERE schedule.exam_id=s.examination_id "
            "ORDER BY schedule.start_time ASC LIMIT 1),"
            "COALESCE(s.launched_at,EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000)"
            "+e.duration_minutes::bigint*60000)))>"
            "EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000 "
            "RETURNING s.deadline_at",
            1, activate_params, activate_lengths);
        int activation_ok = activated &&
            PQresultStatus(activated) == PGRES_TUPLES_OK &&
            PQntuples(activated) == 1;
        char deadline_at[32] = {0};
        if (activation_ok)
            snprintf(deadline_at, sizeof(deadline_at), "%s", PQgetvalue(activated, 0, 0));
        if (activated) PQclear(activated);
        db_release(conn, activation_ok ? 0 : 1);
        if (!activation_ok) {
            free(response.data);
            ses_send_json(client_fd, 409,
                "{\"status\":\"FAIL\",\"error\":\"Exam session changed before paper delivery\"}",
                origin, extra_headers, extra_len);
            return;
        }
        response.length -= 2;
        response.data[response.length] = '\0';
        char deadline_json[128];
        long long server_time = (long long)time(NULL) * 1000;
        int deadline_json_len = snprintf(deadline_json, sizeof(deadline_json),
            "],\"deadline_at\":%s,\"server_time\":%lld}",
            deadline_at, server_time);
        if (deadline_json_len < 0 || (size_t)deadline_json_len >= sizeof(deadline_json) ||
            runtime_json_append(&response, deadline_json) != 0) {
            free(response.data);
            ses_send_json(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Could not attach the authoritative exam deadline\"}",
                origin, extra_headers, extra_len);
            return;
        }
        ses_send_json(client_fd, 200, response.data, origin, extra_headers, extra_len);
        free(response.data);
        return;
    }

    /* ---- Save answer (candidate) ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/exam/save_answer") == 0) {
        candidate_exam_context_t context;
        int context_rc = candidate_exam_context_load(auth_header, &context);
        if (context_rc != 1) {
            ses_send_json(client_fd, context_rc < 0 ? 503 : 401,
                context_rc < 0 ? "{\"status\":\"UNAVAILABLE\",\"error\":\"Could not validate candidate exam session\"}" :
                "{\"status\":\"FAIL\",\"error\":\"Unauthorized exam session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        long long question_id = 0, selected_option = 0;
        char answer[65536] = {0};
        int answer_kind = 0;
        if (parse_i64_field(body, "question_id", 0, &question_id) != 0) {
            ses_send_json(client_fd, 400,
                "{\"status\":\"FAIL\",\"error\":\"A positive question_id is required\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (ctrl_json_string(body, "text_answer", answer, sizeof(answer))) {
            answer_kind = 1;
        } else if (parse_i64_field(body, "selected_option", 1, &selected_option) == 0 &&
                   selected_option <= 3) {
            snprintf(answer, sizeof(answer), "%lld", selected_option);
            answer_kind = 2;
        }
        if (!answer_kind) {
            ses_send_json(client_fd, 400,
                "{\"status\":\"FAIL\",\"error\":\"A string text_answer or selected_option from 0 to 3 is required\"}",
                origin, extra_headers, extra_len);
            OPENSSL_cleanse(answer, sizeof(answer));
            return;
        }
        if (strcmp(context.status, "active") != 0 ||
            !candidate_exam_trusted(&context)) {
            ses_send_json(client_fd, 403,
                "{\"status\":\"FAIL\",\"error\":\"Answers require an active session with fresh TPM verification\"}",
                origin, extra_headers, extra_len);
            OPENSSL_cleanse(answer, sizeof(answer));
            return;
        }
        char question_id_text[32], now_text[32];
        snprintf(question_id_text, sizeof(question_id_text), "%lld", question_id);
        snprintf(now_text, sizeof(now_text), "%lld", (long long)time(NULL) * 1000);
        PGconn *conn = db_acquire();
        if (!conn) {
            OPENSSL_cleanse(answer, sizeof(answer));
            ses_send_json(client_fd, 503, "{\"status\":\"UNAVAILABLE\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        char answer_kind_text[8];
        snprintf(answer_kind_text, sizeof(answer_kind_text), "%d", answer_kind);
        const char *params[7] = { context.exam_session_id, question_id_text,
            context.exam_id, context.exam_id, answer, now_text,
            answer_kind_text };
        int lengths[7] = { (int)strlen(params[0]), (int)strlen(params[1]),
            (int)strlen(params[2]), (int)strlen(params[3]), (int)strlen(params[4]),
            (int)strlen(params[5]), (int)strlen(params[6]) };
        PGresult *saved = db_simple(conn,
            "INSERT INTO candidate_exam_answers "
            "(exam_session_id,question_id,answer_text,revision,saved_at) "
            "SELECT $1,$2::bigint,$5,1,$6::bigint FROM exam_sessions s "
            "JOIN examos_exam_questions q ON q.question_id=$2::bigint "
            "AND q.exam_id=$3 AND q.active=true "
            "AND (($7='1' AND q.question_type IN ('NUMERICAL','CODING')) OR "
            "($7='2' AND q.question_type='MCQ')) "
            "WHERE s.id=$1 AND s.examination_id=$4 AND s.status='active' "
            "AND s.deadline_at>EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000 "
            "ON CONFLICT (exam_session_id,question_id) DO UPDATE SET "
            "answer_text=EXCLUDED.answer_text,"
            "revision=candidate_exam_answers.revision+1,saved_at=EXCLUDED.saved_at "
            "RETURNING revision,saved_at",
            7, params, lengths);
        if (!saved || PQresultStatus(saved) != PGRES_TUPLES_OK ||
            PQntuples(saved) != 1) {
            if (saved) PQclear(saved);
            db_release(conn, 0);
            OPENSSL_cleanse(answer, sizeof(answer));
            ses_send_json(client_fd, 409,
                "{\"status\":\"FAIL\",\"error\":\"Question is not active for this exam session or the session is no longer writable\"}",
                origin, extra_headers, extra_len);
            return;
        }
        char revision[16], saved_at[32], response[128];
        snprintf(revision, sizeof(revision), "%s", PQgetvalue(saved, 0, 0));
        snprintf(saved_at, sizeof(saved_at), "%s", PQgetvalue(saved, 0, 1));
        PQclear(saved);
        db_release(conn, 0);
        snprintf(response, sizeof(response),
            "{\"status\":\"SAVED\",\"revision\":%s,\"saved_at\":%s}",
            revision, saved_at);
        OPENSSL_cleanse(answer, sizeof(answer));
        ses_send_json(client_fd, 200, response, origin, extra_headers, extra_len);
        return;
    }

    /* ---- Submit exam (candidate) ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/exam/submit") == 0) {
        candidate_exam_context_t context;
        int context_rc = candidate_exam_context_load(auth_header, &context);
        if (context_rc != 1) {
            ses_send_json(client_fd, context_rc < 0 ? 503 : 401,
                context_rc < 0 ? "{\"status\":\"UNAVAILABLE\",\"error\":\"Could not validate candidate exam session\"}" :
                "{\"status\":\"FAIL\",\"error\":\"Unauthorized exam session\"}",
                origin, extra_headers, extra_len);
            return;
        }
        if (strcmp(context.status, "closed") != 0 &&
            !candidate_exam_trusted(&context)) {
            ses_send_json(client_fd, 403,
                "{\"status\":\"FAIL\",\"error\":\"Submission requires fresh TPM verification\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PGconn *conn = db_acquire();
        if (!conn) {
            ses_send_json(client_fd, 503, "{\"status\":\"UNAVAILABLE\"}",
                          origin, extra_headers, extra_len);
            return;
        }
        PGresult *begin = PQexec(conn, "BEGIN");
        if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
            if (begin) PQclear(begin);
            db_release(conn, 1);
            ses_send_json(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Could not start submission transaction\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PQclear(begin);
        const char *existing_params[1] = { context.exam_session_id };
        int existing_lengths[1] = { (int)strlen(context.exam_session_id) };
        PGresult *existing = db_simple(conn,
            "SELECT receipt_id,answer_count,answers_sha256,submitted_at "
            "FROM candidate_exam_submissions WHERE exam_session_id=$1",
            1, existing_params, existing_lengths);
        if (existing && PQresultStatus(existing) == PGRES_TUPLES_OK &&
            PQntuples(existing) == 1) {
            char receipt[64], count[16], digest[65], submitted_at[32], response[320];
            snprintf(receipt, sizeof(receipt), "%s", PQgetvalue(existing, 0, 0));
            snprintf(count, sizeof(count), "%s", PQgetvalue(existing, 0, 1));
            snprintf(digest, sizeof(digest), "%s", PQgetvalue(existing, 0, 2));
            snprintf(submitted_at, sizeof(submitted_at), "%s", PQgetvalue(existing, 0, 3));
            PQclear(existing);
            PGresult *commit_existing = PQexec(conn, "COMMIT");
            int existing_committed = commit_existing &&
                PQresultStatus(commit_existing) == PGRES_COMMAND_OK;
            if (commit_existing) PQclear(commit_existing);
            if (!existing_committed) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 1);
                ses_send_json(client_fd, 503,
                    "{\"status\":\"FAIL\",\"error\":\"Could not confirm the existing submission receipt\"}",
                    origin, extra_headers, extra_len);
                return;
            }
            db_release(conn, 0);
            snprintf(response, sizeof(response),
                "{\"status\":\"SUBMITTED\",\"receipt_id\":\"%s\","
                "\"answer_count\":%s,\"answers_sha256\":\"%s\",\"submitted_at\":%s}",
                receipt, count, digest, submitted_at);
            ses_send_json(client_fd, 200, response, origin, extra_headers, extra_len);
            return;
        }
        if (!existing || PQresultStatus(existing) != PGRES_TUPLES_OK) {
            if (existing) PQclear(existing);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 1);
            ses_send_json(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Could not load submission receipt state\"}",
                origin, extra_headers, extra_len);
            return;
        }
        PQclear(existing);
        const char *lock_params[1] = { context.exam_session_id };
        int lock_lengths[1] = { (int)strlen(context.exam_session_id) };
        PGresult *locked = db_simple(conn,
            "SELECT status,COALESCE(deadline_at::text,''),"
            "deadline_at<=EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000 "
            "FROM exam_sessions WHERE id=$1 FOR UPDATE",
            1, lock_params, lock_lengths);
        int deadline_expired = locked &&
            PQresultStatus(locked) == PGRES_TUPLES_OK &&
            PQntuples(locked) == 1 &&
            strcmp(PQgetvalue(locked, 0, 2), "t") == 0;
        int writable = locked && PQresultStatus(locked) == PGRES_TUPLES_OK &&
            PQntuples(locked) == 1 &&
            (strcmp(PQgetvalue(locked, 0, 0), "active") == 0 ||
             (strcmp(PQgetvalue(locked, 0, 0), "interrupted") == 0 &&
              deadline_expired)) &&
            PQgetvalue(locked, 0, 1)[0] != '\0';
        long long deadline_at = writable ? atoll(PQgetvalue(locked, 0, 1)) : 0;
        if (locked) PQclear(locked);
        int answer_count = 0;
        char answers_sha256[65] = {0};
        int digest_ok = writable &&
            candidate_answer_digest(conn, context.exam_session_id,
                                    &answer_count, answers_sha256) == 0;
        if (!digest_ok) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            ses_send_json(client_fd, 409,
                "{\"status\":\"FAIL\",\"error\":\"Only an active exam session with durable answers can be submitted\"}",
                origin, extra_headers, extra_len);
            return;
        }
        unsigned char receipt_random[16];
        static const char hex[] = "0123456789abcdef";
        char receipt_id[64] = "rcpt_";
        if (RAND_bytes(receipt_random, sizeof(receipt_random)) != 1) {
            OPENSSL_cleanse(receipt_random, sizeof(receipt_random));
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            ses_send_json(client_fd, 500,
                "{\"status\":\"FAIL\",\"error\":\"Secure submission receipt generation failed\"}",
                origin, extra_headers, extra_len);
            return;
        }
        for (size_t i = 0; i < sizeof(receipt_random); ++i) {
            receipt_id[5 + i * 2] = hex[receipt_random[i] >> 4];
            receipt_id[6 + i * 2] = hex[receipt_random[i] & 15];
        }
        receipt_id[37] = '\0';
        OPENSSL_cleanse(receipt_random, sizeof(receipt_random));
        char count_text[16], submitted_text[32];
        long long submitted_ms = (long long)time(NULL) * 1000;
        snprintf(count_text, sizeof(count_text), "%d", answer_count);
        snprintf(submitted_text, sizeof(submitted_text), "%lld", submitted_ms);
        const char *insert_params[6] = { context.exam_session_id, receipt_id,
            context.candidate_id, context.exam_id, count_text, answers_sha256 };
        const char *submission_params[7] = { insert_params[0], insert_params[1],
            insert_params[2], insert_params[3], insert_params[4], insert_params[5],
            submitted_text };
        int submission_lengths[7];
        for (int i = 0; i < 7; ++i)
            submission_lengths[i] = (int)strlen(submission_params[i]);
        PGresult *inserted = db_simple(conn,
            "INSERT INTO candidate_exam_submissions "
            "(exam_session_id,receipt_id,candidate_id,examination_id,answer_count,"
            "answers_sha256,submitted_at) VALUES ($1,$2,$3,$4,$5::integer,$6,$7::bigint)",
            7, submission_params, submission_lengths);
        int insert_ok = inserted && PQresultStatus(inserted) == PGRES_COMMAND_OK;
        if (inserted) PQclear(inserted);
        const char *closure_reason = deadline_expired || deadline_at <= submitted_ms ?
            "TIME_EXPIRED_SUBMITTED" : "SUBMITTED";
        const char *close_params[3] = { context.exam_session_id, submitted_text,
                                        closure_reason };
        int close_lengths[3] = { (int)strlen(context.exam_session_id),
                                 (int)strlen(submitted_text),
                                 (int)strlen(closure_reason) };
        PGresult *closed = insert_ok ? db_simple(conn,
            "UPDATE exam_sessions SET status='closed',closure_reason=$3,"
            "closed_at=$2::bigint,updated_at=$2::bigint "
            "WHERE id=$1 AND (status='active' OR "
            "(status='interrupted' AND deadline_at<="
            "EXTRACT(EPOCH FROM statement_timestamp())::bigint*1000))",
            3, close_params, close_lengths) : NULL;
        int close_ok = closed && PQresultStatus(closed) == PGRES_COMMAND_OK &&
                       strcmp(PQcmdTuples(closed), "1") == 0;
        if (closed) PQclear(closed);
        char event_id[64], audit_id[64];
        memcpy(event_id, "subevt_", 7);
        memcpy(event_id + 7, receipt_id + 5, 32);
        event_id[39] = '\0';
        memcpy(audit_id, "subaud_", 7);
        memcpy(audit_id + 7, receipt_id + 5, 32);
        audit_id[39] = '\0';
        char event_payload[160];
        snprintf(event_payload, sizeof(event_payload),
            "{\"receipt_id\":\"%s\",\"answers_sha256\":\"%s\"}",
            receipt_id, answers_sha256);
        const char *event_params[6] = { event_id, context.exam_session_id,
            context.exam_id, context.institution_id, event_payload, submitted_text };
        int event_lengths[6];
        for (int i = 0; i < 6; ++i)
            event_lengths[i] = (int)strlen(event_params[i]);
        PGresult *event = close_ok ? db_simple(conn,
            "INSERT INTO exam_session_events "
            "(id,session_id,examination_id,institution_id,event_type,payload_json,created_at) "
            "VALUES ($1,$2,$3,$4,'closed',$5,$6::bigint)",
            6, event_params, event_lengths) : NULL;
        int event_ok = event && PQresultStatus(event) == PGRES_COMMAND_OK;
        if (event) PQclear(event);
        const char *audit_params[8] = { audit_id, context.exam_session_id,
            context.exam_id, context.institution_id, context.candidate_id,
            "SESSION_SUBMITTED", receipt_id, submitted_text };
        int audit_lengths[8];
        for (int i = 0; i < 8; ++i)
            audit_lengths[i] = (int)strlen(audit_params[i]);
        PGresult *audit = event_ok ? db_simple(conn,
            "INSERT INTO exam_session_audit_logs "
            "(id,session_id,examination_id,institution_id,actor_id,action,details,created_at) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8::bigint)",
            8, audit_params, audit_lengths) : NULL;
        int audit_ok = audit && PQresultStatus(audit) == PGRES_COMMAND_OK;
        if (audit) PQclear(audit);
        PGresult *commit = audit_ok ? PQexec(conn, "COMMIT") : NULL;
        int committed = commit && PQresultStatus(commit) == PGRES_COMMAND_OK;
        if (commit) PQclear(commit);
        if (!committed) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            ses_send_json(client_fd, 503,
                "{\"status\":\"FAIL\",\"error\":\"Could not commit the answer set and submission receipt\"}",
                origin, extra_headers, extra_len);
            return;
        }
        db_release(conn, 0);
        char response[256];
        snprintf(response, sizeof(response),
            "{\"status\":\"SUBMITTED\",\"receipt_id\":\"%s\","
            "\"answer_count\":%d,\"answers_sha256\":\"%s\",\"submitted_at\":%lld}",
            receipt_id, answer_count, answers_sha256, submitted_ms);
        ses_send_json(client_fd, 200, response, origin, extra_headers, extra_len);
        return;
    }

    /* ---- Announcements ---- */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/exam/announcements") == 0) {
        ses_send_json(client_fd, 503,
                      "{\"status\":\"UNAVAILABLE\",\"error\":\"Exam announcements are not connected to a live source.\"}",
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
        ses_send_json(client_fd, 503,
                      "{\"status\":\"UNAVAILABLE\",\"error\":\"Exam terminal status is not connected to a live source.\"}",
                      origin, extra_headers, extra_len);
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
        ses_send_json(client_fd, 503,
                      "{\"status\":\"UNAVAILABLE\",\"error\":\"Exam command execution is not connected to a live exam-session service.\"}",
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
        ses_send_json(client_fd, 503,
                      "{\"status\":\"UNAVAILABLE\",\"error\":\"Eligibility cannot be confirmed without an authorized durable exam session and verified device trust.\"}",
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
        ses_send_json(client_fd, 503,
            "{\"status\":\"UNAVAILABLE\",\"error\":\"Key release requires cryptographic authorization bound to a verified device and durable exam session.\"}",
            origin, extra_headers, extra_len);
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
        ses_send_json(client_fd, 503,
            "{\"status\":\"UNAVAILABLE\",\"error\":\"Candidate consent cannot be recorded without durable session-bound consent storage.\"}",
            origin, extra_headers, extra_len);
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
        ses_send_json(client_fd, 503,
            "{\"status\":\"UNAVAILABLE\",\"error\":\"Proctoring events are not connected to durable event-chain storage.\"}",
            origin, extra_headers, extra_len);
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
        ses_send_json(client_fd, 503,
                      "{\"status\":\"UNAVAILABLE\",\"error\":\"Proctoring event history is not connected to durable storage.\"}",
                      origin, extra_headers, extra_len);
        return;
    }

    /* ---- Checkpoint ---- */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/proctoring/checkpoint") == 0) {
        ses_send_json(client_fd, 503,
            "{\"status\":\"UNAVAILABLE\",\"error\":\"Signed proctoring checkpoints are not configured.\"}",
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
        ses_send_json(client_fd, 503,
                      "{\"status\":\"UNAVAILABLE\",\"error\":\"Proctoring chain verification is not connected to durable event-chain storage.\"}",
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
        ses_send_json(client_fd, 503,
            "{\"status\":\"UNAVAILABLE\",\"error\":\"Second-camera pairing is not connected to durable pairing state.\"}",
            origin, extra_headers, extra_len);
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
        ses_send_json(client_fd, 503,
            "{\"status\":\"UNAVAILABLE\",\"error\":\"Second-camera pairing is not connected to durable pairing state.\"}",
            origin, extra_headers, extra_len);
        OPENSSL_cleanse(tok, sizeof(tok));
        return;
    }

    ses_send_json(client_fd, 404, "{\"error\":\"Not found\"}",
                  origin, extra_headers, extra_len);
}
