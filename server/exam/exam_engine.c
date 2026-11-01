#define _GNU_SOURCE
#include "../include/exam_engine.h"
#include "../include/event_chain.h"
#include "../include/candidate_login.h"
#include "../include/ledger.h"
#include "../include/config_manager.h"
#include "../include/admin_auth_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define MAX_EXAM_SESSIONS 128

static exam_question_t g_questions[MAX_QUESTIONS];
static int g_question_count = 0;

static candidate_exam_state_t g_exam_states[MAX_EXAM_SESSIONS];
static int g_exam_state_count = 0;
static pthread_mutex_t g_engine_lock = PTHREAD_MUTEX_INITIALIZER;

static char g_broadcast_announcement[256];
static time_t g_broadcast_time = 0;

static int json_escape_field(const char *input, size_t input_capacity,
                             char *output, size_t output_capacity) {
    static const char hex[] = "0123456789abcdef";
    size_t input_length = strnlen(input, input_capacity);
    if (input_length == input_capacity) return -1;
    size_t used = 0;

    for (size_t index = 0; index < input_length; ++index) {
        unsigned char character = (unsigned char)input[index];
        char escaped[6];
        size_t escaped_length;
        switch (character) {
            case '"':  escaped[0] = '\\'; escaped[1] = '"'; escaped_length = 2; break;
            case '\\': escaped[0] = '\\'; escaped[1] = '\\'; escaped_length = 2; break;
            case '\b': escaped[0] = '\\'; escaped[1] = 'b'; escaped_length = 2; break;
            case '\f': escaped[0] = '\\'; escaped[1] = 'f'; escaped_length = 2; break;
            case '\n': escaped[0] = '\\'; escaped[1] = 'n'; escaped_length = 2; break;
            case '\r': escaped[0] = '\\'; escaped[1] = 'r'; escaped_length = 2; break;
            case '\t': escaped[0] = '\\'; escaped[1] = 't'; escaped_length = 2; break;
            default:
                if (character < 0x20) {
                    escaped[0] = '\\'; escaped[1] = 'u'; escaped[2] = '0'; escaped[3] = '0';
                    escaped[4] = hex[character >> 4]; escaped[5] = hex[character & 0x0f];
                    escaped_length = 6;
                } else {
                    escaped[0] = (char)character;
                    escaped_length = 1;
                }
                break;
        }
        if (escaped_length >= output_capacity - used) return -1;
        memcpy(output + used, escaped, escaped_length);
        used += escaped_length;
    }
    output[used] = '\0';
    return 0;
}

static int current_question_count(void) {
    if (g_question_count < 0) return 0;
    return g_question_count > MAX_QUESTIONS ? MAX_QUESTIONS : g_question_count;
}

int exam_engine_load_default_nqt_questions(void) {
    pthread_mutex_lock(&g_engine_lock);
    g_question_count = 0;

    static const struct {
        int id;
        const char *section;
        const char *text;
        const char *opts[4];
        int correct;
        int marks;
        const char *type;
        const char *tmpl;
    } nqt_bank[] = {
        {
            1,
            "Section A: Quantitative Logic",
            "In a secure testing center with 1,200 candidate workstations, 65% are connected via primary gigabit fiber (mean latency: 4.0 ms) and the remainder via cellular redundant link (mean latency: 44.0 ms). What is the weighted mean round-trip latency across the entire fleet?",
            {"18.00 ms", "14.85 ms", "20.40 ms", "16.50 ms"},
            1, 3, "MCQ", ""
        },
        {
            2,
            "Section A: Quantitative Logic",
            "A hardware security module takes 85 ms for prime generation and 15 ms for modular exponentiation. Using 4 parallel worker threads in non-blocking mode, how many complete 2048-bit key-exchange pairs can the module finalize in 60 seconds?",
            {"2,400 pairs", "1,800 pairs", "600 pairs", "1,200 pairs"},
            0, 3, "MCQ", ""
        },
        {
            3,
            "Section A: Quantitative Logic",
            "A candidate attempts 25 questions in Section A with marking +3.00 for correct answers and -0.75 for incorrect answers. If the candidate achieves a net score of 52.50 marks having attempted all questions, how many questions were answered correctly?",
            {"18", "19", "20", "21"},
            1, 3, "MCQ", ""
        },
        {
            4,
            "Section B: Systems Reasoning",
            "Which TPM 2.0 Platform Configuration Register (PCR) is specified by the TCG/UEFI standard to measure the bootloader binary (e.g., systemd-boot / shim) and UEFI drivers executed from the EFI System Partition?",
            {"PCR 0 (Core Firmware)", "PCR 4 (Boot Manager & OS Loader)", "PCR 7 (Secure Boot Policy)", "PCR 11 (OS Unified Kernel Image)"},
            1, 3, "MCQ", ""
        },
        {
            5,
            "Section B: Systems Reasoning",
            "Under Linux dm-verity root filesystem integrity protection, what occurs when an adversary or storage fault modifies a single bit in an underlying ext4 disk block during an on-demand read?",
            {"Kernel panics immediately or returns EIO per lockdown configuration", "The filesystem silently substitutes zeroed bytes", "The block is fetched from swap space", "The partition switches to read-write mode"},
            0, 3, "MCQ", ""
        },
        {
            6,
            "Section B: Systems Reasoning",
            "During an examination, a candidate process attempts an outbound socket connection to an unauthorized external IP. Which ExamOS subsystem is authoritative for evaluating and dropping this packet at the kernel network stack?",
            {"nftables default-deny egress table", "Chromium sandboxed renderer", "USBGuard device policy", "AppArmor capability filter"},
            0, 3, "MCQ", ""
        },
        {
            7,
            "Section B: Systems Reasoning",
            "Why does ExamOS launch the Chromium kiosk with an ephemeral RAM user profile (/tmp/examos_kiosk_XXXXXX) rather than standard persistent user storage?",
            {"Guarantees zero forensic residual data, cache, cookies, or history survive session termination", "Reduces RAM consumption on low-end terminals", "Enables browser bookmark synchronization across sessions", "Required by the Wayland protocol specification"},
            0, 3, "MCQ", ""
        },
        {
            8,
            "Section C: Technical Coding",
            "In an append-only audit ledger where each block B[i] contains payload P[i], previous hash H[i-1], and MAC M[i] = HMAC(K, P[i] || H[i-1]), what is the cryptographic consequence of modifying payload P[k] for k < n?",
            {"Every block from k through n fails verification unless the adversary possesses secret key K", "Only block k fails verification; downstream blocks remain valid", "The truncation anchor detects the tampering without needing HMAC", "The SHA-256 genesis hash is invalidated"},
            0, 4, "MCQ", ""
        },
        {
            9,
            "Section C: Technical Coding",
            "Consider the C function: void sanitize(char *s) { while (*s) { if (*s == '|') *s = '/'; s++; } }. What security guarantee does this routine enforce when formatting log records?",
            {"Prevents field-delimiter injection and forged audit columns in pipe-delimited records", "Prevents heap buffer overflow and bounds corruption", "Validates that the input is well-formed UTF-8", "Encrypts log payloads in transit"},
            0, 4, "MCQ", ""
        },
        {
            10,
            "Section C: Technical Coding",
            "In a multi-threaded C server with POSIX sockets, what vulnerability arises if OpenSSL session handle SSL *ssl is defined as a global variable instead of thread-local storage (__thread)?",
            {"Concurrent worker threads will interleave read/write buffers, corrupting TLS record state and causing data leaks", "The compiler will issue an undefined symbol error during linking", "The server will fail to bind port 8000", "SSL_accept will block indefinitely on all connections"},
            0, 4, "MCQ", ""
        }
    };

    int count = (int)(sizeof(nqt_bank) / sizeof(nqt_bank[0]));
    for (int i = 0; i < count && i < MAX_QUESTIONS; i++) {
        exam_question_t *q = &g_questions[i];
        memset(q, 0, sizeof(*q));
        q->id = nqt_bank[i].id;
        snprintf(q->section, sizeof(q->section), "%s", nqt_bank[i].section);
        snprintf(q->text, sizeof(q->text), "%s", nqt_bank[i].text);
        for (int opt = 0; opt < 4; opt++) {
            snprintf(q->options[opt], sizeof(q->options[opt]), "%s", nqt_bank[i].opts[opt]);
        }
        q->correct_option = nqt_bank[i].correct;
        q->marks = nqt_bank[i].marks;
        snprintf(q->question_type, sizeof(q->question_type), "%s", nqt_bank[i].type);
        snprintf(q->code_template, sizeof(q->code_template), "%s", nqt_bank[i].tmpl);
        g_question_count++;
    }

    pthread_mutex_unlock(&g_engine_lock);
    return g_question_count;
}

int exam_engine_init(void) {
    pthread_mutex_lock(&g_engine_lock);
    g_question_count = 0;
    g_exam_state_count = 0;
    g_broadcast_announcement[0] = '\0';
    g_broadcast_time = 0;
    pthread_mutex_unlock(&g_engine_lock);
    exam_engine_load_default_nqt_questions();
    return 0;
}

/*
 * exam_engine_load_questions_from_db — populate g_questions from PostgreSQL.
 *
 * Queries examos_exam_questions for the given exam_id (active questions only,
 * ordered by question_order). Fails closed: if no questions are found or the
 * database is unreachable, g_question_count stays 0 and exam_engine_is_ready()
 * returns 0, blocking paper delivery.
 *
 * Returns the number of questions loaded, or -1 on error.
 */
int exam_engine_load_questions_from_db(const char *exam_id) {
    if (!exam_id || !exam_id[0]) return -1;

    PGconn *conn = acquire_db_connection();
    if (!conn) {
        fprintf(stderr, "[ExamEngine] FATAL: database connection unavailable; "
                        "exam questions cannot be loaded.\n");
        return -1;
    }

    const char *params[1] = { exam_id };
    PGresult *res = PQexecParams(conn,
        "SELECT question_id, section, question_text, "
        "       option_a, option_b, option_c, option_d, "
        "       correct_option, marks, question_type, "
        "       COALESCE(code_template, '') "
        "FROM examos_exam_questions "
        "WHERE exam_id = $1 AND active = true "
        "ORDER BY question_order ASC "
        "LIMIT 128",
        1, NULL, params, NULL, NULL, 0);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[ExamEngine] FATAL: question query failed: %s\n",
                res ? PQresultErrorMessage(res) : "no result");
        if (res) PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    int rows = PQntuples(res);
    if (rows <= 0) {
        fprintf(stderr, "[ExamEngine] FATAL: no active questions found for exam '%s'. "
                        "Provision questions before opening the exam.\n", exam_id);
        PQclear(res);
        release_db_connection(conn, 0);
        return -1;
    }

    pthread_mutex_lock(&g_engine_lock);
    g_question_count = 0;

    for (int i = 0; i < rows && i < MAX_QUESTIONS; i++) {
        exam_question_t *q = &g_questions[i];
        memset(q, 0, sizeof(*q));

        q->id = atoi(PQgetvalue(res, i, 0));
        snprintf(q->section,       sizeof(q->section),       "%s", PQgetvalue(res, i, 1));
        snprintf(q->text,          sizeof(q->text),          "%s", PQgetvalue(res, i, 2));
        snprintf(q->options[0],    sizeof(q->options[0]),    "%s", PQgetvalue(res, i, 3));
        snprintf(q->options[1],    sizeof(q->options[1]),    "%s", PQgetvalue(res, i, 4));
        snprintf(q->options[2],    sizeof(q->options[2]),    "%s", PQgetvalue(res, i, 5));
        snprintf(q->options[3],    sizeof(q->options[3]),    "%s", PQgetvalue(res, i, 6));
        q->correct_option = atoi(PQgetvalue(res, i, 7));
        q->marks          = atoi(PQgetvalue(res, i, 8));
        snprintf(q->question_type, sizeof(q->question_type), "%s", PQgetvalue(res, i, 9));
        snprintf(q->code_template, sizeof(q->code_template), "%s", PQgetvalue(res, i, 10));

        g_question_count++;
    }

    pthread_mutex_unlock(&g_engine_lock);
    PQclear(res);
    release_db_connection(conn, 0);

    fprintf(stdout, "[ExamEngine] Loaded %d question(s) for exam '%s'.\n",
            g_question_count, exam_id);
    return g_question_count;
}

int exam_engine_is_ready(void) {
    /*
     * Fail closed: if no questions are loaded, return 0 (not ready).
     * Never fall back to the hardcoded NQT demo question bank for a production
     * exam — that would silently serve fabricated content to real candidates.
     * Questions must be explicitly provisioned via exam_engine_load_questions_from_db().
     */
    return current_question_count() > 0;
}

candidate_exam_state_t* exam_engine_get_state(const char *session_token) {
    if (!session_token || !exam_engine_is_ready()) return NULL;

    /* Resolve candidate identity outside the engine lock to avoid lock ordering issues */
    char resolved_cid[MAX_CANDIDATE_ID_LEN] = {0};
    if (!candidate_session_identity(session_token, resolved_cid, sizeof(resolved_cid)) ||
        !resolved_cid[0]) return NULL;

    pthread_mutex_lock(&g_engine_lock);
    for (int i = 0; i < g_exam_state_count; i++) {
        if (strcmp(g_exam_states[i].session_token, session_token) == 0) {
            pthread_mutex_unlock(&g_engine_lock);
            return &g_exam_states[i];
        }
    }

    if (g_exam_state_count < MAX_EXAM_SESSIONS) {
        candidate_exam_state_t *st = &g_exam_states[g_exam_state_count++];
        memset(st, 0, sizeof(*st));
        strncpy(st->session_token, session_token, sizeof(st->session_token)-1);
        snprintf(st->candidate_id, sizeof(st->candidate_id), "%s", resolved_cid);
        st->seat_number[0] = '\0';
        st->start_time = time(NULL);
        /*
         * Load real duration from the examinations table rather than using
         * the hardcoded 7200-second NQT standard.  Fall back to 7200 only
         * if the DB lookup fails so the session is not left with 0 seconds.
         */
        st->duration_seconds = 7200;
        {
            PGconn *dc = acquire_db_connection();
            if (dc) {
                /* Candidate session identity gives us candidate_id; look up
                 * which active examination this candidate is assigned to and
                 * read its configured duration. */
                const char *dp[1] = { resolved_cid };
                PGresult *dr = PQexecParams(dc,
                    "SELECT e.duration_minutes "
                    "FROM exam_student_assignments a "
                    "JOIN examinations e ON a.exam_id = e.id "
                    "WHERE a.student_id = $1 AND e.status IN ('in_progress','ready','scheduled') "
                    "ORDER BY e.created_at DESC LIMIT 1",
                    1, NULL, dp, NULL, NULL, 0);
                if (dr && PQresultStatus(dr) == PGRES_TUPLES_OK && PQntuples(dr) > 0) {
                    int dur_min = atoi(PQgetvalue(dr, 0, 0));
                    if (dur_min >= 15 && dur_min <= 300)
                        st->duration_seconds = dur_min * 60;
                }
                if (dr) PQclear(dr);
                release_db_connection(dc, 0);
            }
        }
        st->current_question = 1;
        st->is_paused = 0;
        st->is_submitted = 0;
        st->last_sync = time(NULL);
        for (int q = 0; q < MAX_QUESTIONS; q++) {
            st->selected_options[q] = -1;
            st->status[q] = Q_STATUS_NOT_VISITED;
        }
        st->status[0] = Q_STATUS_NOT_ANSWERED;
        pthread_mutex_unlock(&g_engine_lock);
        return st;
    }

    pthread_mutex_unlock(&g_engine_lock);
    return NULL;
}

const char* exam_engine_get_paper_json(const char *session_token) {
    static char buf[65536];
    candidate_exam_state_t *st = exam_engine_get_state(session_token);
    if (!st) return NULL;

    int question_count = current_question_count();
    pthread_mutex_lock(&g_engine_lock);
    size_t offset = snprintf(buf, sizeof(buf),
             "{\"candidate_id\":\"%s\",\"seat_number\":\"%s\","
             "\"duration_seconds\":%d,\"time_remaining\":%ld,\"is_paused\":%s,"
             "\"total_questions\":%d,\"questions\":[",
             st->candidate_id,
             st->seat_number,
             st->duration_seconds,
             (long)(st->duration_seconds - (time(NULL) - st->start_time)),
             st->is_paused ? "true" : "false",
             question_count);

    for (int i = 0; i < question_count; i++) {
        exam_question_t *q = &g_questions[i];
        char section[sizeof(q->section) * 6 + 1];
        char text[sizeof(q->text) * 6 + 1];
        char options[4][sizeof(q->options[0]) * 6 + 1];
        char question_type[sizeof(q->question_type) * 6 + 1];
        char code_template[sizeof(q->code_template) * 6 + 1];
        if (json_escape_field(q->section, sizeof(q->section), section, sizeof(section)) != 0 ||
            json_escape_field(q->text, sizeof(q->text), text, sizeof(text)) != 0 ||
            json_escape_field(q->options[0], sizeof(q->options[0]), options[0], sizeof(options[0])) != 0 ||
            json_escape_field(q->options[1], sizeof(q->options[1]), options[1], sizeof(options[1])) != 0 ||
            json_escape_field(q->options[2], sizeof(q->options[2]), options[2], sizeof(options[2])) != 0 ||
            json_escape_field(q->options[3], sizeof(q->options[3]), options[3], sizeof(options[3])) != 0 ||
            json_escape_field(q->question_type, sizeof(q->question_type), question_type, sizeof(question_type)) != 0 ||
            json_escape_field(q->code_template, sizeof(q->code_template),
                              code_template, sizeof(code_template)) != 0) {
            pthread_mutex_unlock(&g_engine_lock);
            return NULL;
        }
        int sel = (i < MAX_QUESTIONS) ? st->selected_options[i] : -1;
        int stat = (i < MAX_QUESTIONS) ? st->status[i] : 0;

        if (offset >= sizeof(buf)) {
            pthread_mutex_unlock(&g_engine_lock);
            return NULL;
        }
        int written = snprintf(buf + offset, sizeof(buf) - offset,
                 "%s{\"id\":%d,\"section\":\"%s\",\"text\":\"%s\","
                 "\"options\":[\"%s\",\"%s\",\"%s\",\"%s\"],"
                 "\"marks\":%d,\"type\":\"%s\",\"selected\":%d,\"status\":%d,"
                 "\"code_template\":\"%s\"}",
                 i > 0 ? "," : "",
                 q->id, section, text,
                 options[0], options[1], options[2], options[3],
                 q->marks, question_type, sel, stat, code_template);
        if (written < 0 || (size_t)written >= sizeof(buf) - offset) {
            pthread_mutex_unlock(&g_engine_lock);
            return NULL;
        }
        offset += (size_t)written;
    }

    if (offset >= sizeof(buf) || sizeof(buf) - offset < 3) {
        pthread_mutex_unlock(&g_engine_lock);
        return NULL;
    }
    snprintf(buf + offset, sizeof(buf) - offset, "]}");
    pthread_mutex_unlock(&g_engine_lock);
    return buf;
}

int exam_engine_save_answer(const char *session_token, int q_id, int selected_opt, const char *text_ans, int status) {
    candidate_exam_state_t *st = exam_engine_get_state(session_token);
    if (!st) return -1;

    int idx = q_id - 1;
    if (idx < 0 || idx >= MAX_QUESTIONS) return -1;

    pthread_mutex_lock(&g_engine_lock);
    /* Answer mutation and the submission check must be atomic with respect to
       submission publication; otherwise an answer could be accepted after the
       receipt was computed and would not be covered by that receipt. */
    if (st->is_submitted || st->is_paused || st->is_submitting) {
        pthread_mutex_unlock(&g_engine_lock);
        return -1;
    }
    st->selected_options[idx] = selected_opt;
    if (text_ans) {
        strncpy(st->text_answers[idx], text_ans, sizeof(st->text_answers[idx])-1);
    }
    st->status[idx] = (question_status_t)status;
    st->last_sync = time(NULL);
    pthread_mutex_unlock(&g_engine_lock);

    return 0;
}

int exam_engine_submit(const char *session_token, char *out_receipt, size_t max_receipt_len) {
    if (!session_token || !out_receipt || max_receipt_len < 128) return -1;
    candidate_exam_state_t *st = exam_engine_get_state(session_token);
    if (!st) return -1;

    int question_count = current_question_count();
    pthread_mutex_lock(&g_engine_lock);
    if (st->is_submitted || st->is_paused || st->is_submitting) {
        pthread_mutex_unlock(&g_engine_lock);
        return -1;
    }
    st->is_submitting = 1;

    /* Bind the receipt to every submitted answer using an unambiguous binary
     * encoding. A count and timestamp are not evidence of answer contents. */
    int answered = 0;
    for (int i = 0; i < question_count; i++) {
        if (st->selected_options[i] >= 0 || strlen(st->text_answers[i]) > 0) answered++;
    }
    EVP_MD_CTX *digest_ctx = EVP_MD_CTX_new();
    if (!digest_ctx) { pthread_mutex_unlock(&g_engine_lock); return -1; }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len = 0;
    int digest_ok = EVP_DigestInit_ex(digest_ctx, EVP_sha256(), NULL) == 1;
    static const char domain[] = "EXAMOS-SUBMISSION-V2";
    digest_ok = digest_ok && EVP_DigestUpdate(digest_ctx, domain, sizeof(domain)) == 1;
    digest_ok = digest_ok && EVP_DigestUpdate(digest_ctx, st->candidate_id, strlen(st->candidate_id) + 1) == 1;
    digest_ok = digest_ok && EVP_DigestUpdate(digest_ctx, st->session_token, strlen(st->session_token) + 1) == 1;
    for (int i = 0; i < question_count; i++) {
        uint32_t question_id = (uint32_t)g_questions[i].id;
        uint32_t selected_option = (uint32_t)(int32_t)st->selected_options[i];
        uint32_t answer_len = (uint32_t)strnlen(st->text_answers[i], sizeof(st->text_answers[i]));
        unsigned char encoded_fields[12] = {
            (unsigned char)(question_id >> 24), (unsigned char)(question_id >> 16),
            (unsigned char)(question_id >> 8), (unsigned char)question_id,
            (unsigned char)(selected_option >> 24), (unsigned char)(selected_option >> 16),
            (unsigned char)(selected_option >> 8), (unsigned char)selected_option,
            (unsigned char)(answer_len >> 24), (unsigned char)(answer_len >> 16),
            (unsigned char)(answer_len >> 8), (unsigned char)answer_len
        };
        digest_ok = digest_ok && EVP_DigestUpdate(digest_ctx, encoded_fields, sizeof(encoded_fields)) == 1;
        digest_ok = digest_ok && EVP_DigestUpdate(digest_ctx, st->text_answers[i], answer_len) == 1;
    }
    digest_ok = digest_ok && EVP_DigestFinal_ex(digest_ctx, hash, &hash_len) == 1;
    EVP_MD_CTX_free(digest_ctx);
    if (!digest_ok || hash_len != SHA256_DIGEST_LENGTH) {
        st->is_submitting = 0;
        pthread_mutex_unlock(&g_engine_lock);
        return -1;
    }

    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[sizeof(hex)-1] = '\0';

    snprintf(out_receipt, max_receipt_len,
             "{\"status\":\"SUCCESS\",\"candidate_id\":\"%s\",\"receipt_hash\":\"%s\","
             "\"timestamp\":%ld,\"total_answered\":%d,\"total_questions\":%d,"
             "\"integrity_status\":\"CONTENT_DIGEST_ONLY\",\"digest_algorithm\":\"SHA-256\"}",
             st->candidate_id, hex, (long)time(NULL), answered, question_count);

    pthread_mutex_unlock(&g_engine_lock);

    /*
     * Stage 2/3: Durable submission record.
     *
     * Write a EXAM_SUBMISSION_ACCEPTED ledger block *after* releasing
     * the engine lock (ledger has its own mutex).  The ledger is
     * fsync-durable, so this record survives a crash.  The receipt_hash
     * binds candidate_id + session_token_hash + all answers; recovery
     * logic can verify submissions against this record even if the
     * in-memory exam state was lost.
     *
     * We hash the session token rather than storing it in the audit log
     * to avoid leaking a live credential.
     */
    {
        /* SHA-256 of session token for correlation without storing the token itself */
        unsigned char tok_hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char *)session_token, strlen(session_token), tok_hash);
        char tok_hex[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            sprintf(tok_hex + i * 2, "%02x", tok_hash[i]);
        tok_hex[sizeof(tok_hex) - 1] = '\0';

        char details[512];
        snprintf(details, sizeof(details),
                 "receipt=%.64s tok_sha256=%.64s answered=%d total=%d",
                 hex, tok_hex, answered, question_count);
        ledger_block_t blk;
        if (ledger_append_event("EXAM_SUBMISSION_ACCEPTED", st->candidate_id,
                                details, &blk) != 0) {
            pthread_mutex_lock(&g_engine_lock);
            st->is_submitting = 0;
            pthread_mutex_unlock(&g_engine_lock);
            return -1;
        }
    }

    /* Publish the submission only after the receipt is durable. */
    pthread_mutex_lock(&g_engine_lock);
    memcpy(st->submission_receipt_hash, hex, sizeof(hex));
    st->is_submitted = 1;
    st->is_submitting = 0;
    pthread_mutex_unlock(&g_engine_lock);
    return 0;
}

int exam_engine_get_submitted_context(const char *session_token,
                                      const char *receipt_hash,
                                      char *out_candidate_id, size_t candidate_id_size,
                                      char *out_questions, size_t questions_size,
                                      char *out_answers, size_t answers_size) {
    if (!session_token || !receipt_hash || !out_candidate_id || !candidate_id_size ||
        !out_questions || !questions_size || !out_answers || !answers_size) return -1;
    out_candidate_id[0] = out_questions[0] = out_answers[0] = '\0';

    pthread_mutex_lock(&g_engine_lock);
    candidate_exam_state_t *st = NULL;
    for (int i = 0; i < g_exam_state_count; i++) {
        if (strcmp(g_exam_states[i].session_token, session_token) == 0) {
            st = &g_exam_states[i];
            break;
        }
    }
    if (!st || !st->is_submitted || strlen(receipt_hash) != 64 ||
        strcmp(st->submission_receipt_hash, receipt_hash) != 0) {
        pthread_mutex_unlock(&g_engine_lock);
        return -1;
    }

    snprintf(out_candidate_id, candidate_id_size, "%s", st->candidate_id);
    size_t q_used = 0, a_used = 0;
    int question_count = current_question_count();
    for (int i = 0; i < question_count; i++) {
        if (st->selected_options[i] < -1 || st->selected_options[i] >= 4) {
            pthread_mutex_unlock(&g_engine_lock);
            return -1;
        }
        if (st->selected_options[i] < 0 && st->text_answers[i][0] == '\0') continue;
        char answer[sizeof(st->text_answers[i]) + sizeof(g_questions[i].options[0]) + 32];
        answer[0] = '\0';
        if (st->selected_options[i] >= 0 && st->selected_options[i] < 4) {
            snprintf(answer, sizeof(answer), "%s", g_questions[i].options[st->selected_options[i]]);
        }
        if (st->text_answers[i][0]) {
            size_t answer_used = strlen(answer);
            int n = snprintf(answer + answer_used, sizeof(answer) - answer_used,
                             "%s%s", answer_used ? " | " : "", st->text_answers[i]);
            if (n < 0 || (size_t)n >= sizeof(answer) - answer_used) {
                pthread_mutex_unlock(&g_engine_lock);
                return -1;
            }
        }
        int qn = snprintf(out_questions + q_used, questions_size - q_used,
                          "%sQ%d: %s", q_used ? "\n" : "", g_questions[i].id,
                          g_questions[i].text);
        int an = snprintf(out_answers + a_used, answers_size - a_used,
                          "%sQ%d answer: %s", a_used ? "\n" : "", g_questions[i].id, answer);
        if (qn < 0 || an < 0 || (size_t)qn >= questions_size - q_used ||
            (size_t)an >= answers_size - a_used) {
            out_questions[0] = out_answers[0] = '\0';
            pthread_mutex_unlock(&g_engine_lock);
            return -1;
        }
        q_used += (size_t)qn;
        a_used += (size_t)an;
    }
    pthread_mutex_unlock(&g_engine_lock);
    return out_questions[0] && out_answers[0] ? 0 : -1;
}

const char* center_master_get_terminals_json(void) {
    static char buf[65536];
    pthread_mutex_lock(&g_engine_lock);

    /*
     * Stage 2/3 fix: removed hardcoded fabricated fields.
     *
     * center_name   — populated from exam config EXAM_NAME, or "UNCONFIGURED"
     * active_terminals — real count from in-memory session table
     * total_seats   — "UNAVAILABLE" until a room/seat registry is implemented (Module G)
     * ip            — "UNAVAILABLE" until agent telemetry is wired
     * battery_percent — "UNAVAILABLE" until agent telemetry is wired
     * ping_ms       — "UNAVAILABLE" until agent telemetry is wired
     * anomalies     — "UNAVAILABLE" until event-chain query is wired
     * last_ping     — real last_sync timestamp from session state
     *
     * Fields that are genuinely known from in-memory state remain real:
     *   candidate_id, seat, status (IN_PROGRESS/PAUSED/SUBMITTED),
     *   answered count, total questions, start_time.
     */
    extern int config_load(exam_config_t *);  /* already included via header */
    exam_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    config_load(&cfg);
    int question_count = current_question_count();
    const char *center_label = cfg.configured ? cfg.exam_name : "UNCONFIGURED";

    size_t offset = snprintf(buf, sizeof(buf),
             "{\"center_name\":\"%s\","
             "\"active_terminals\":%d,\"total_seats\":\"UNAVAILABLE\","
             "\"announcement\":\"%s\","
             "\"terminals\":[",
             center_label,
             g_exam_state_count,
             g_broadcast_announcement);

    for (int i = 0; i < g_exam_state_count; i++) {
        const char *cid  = g_exam_states[i].candidate_id;
        const char *seat = g_exam_states[i].seat_number;
        int is_paused = g_exam_states[i].is_paused;
        int is_sub    = g_exam_states[i].is_submitted;
        int ans = 0;
        for (int q = 0; q < question_count; q++) {
            if (g_exam_states[i].selected_options[q] >= 0) ans++;
        }
        /* last_sync is set on session creation and each answer save */
        long last_sync_ts = (long)g_exam_states[i].last_sync;
        long start_ts     = (long)g_exam_states[i].start_time;

        offset += snprintf(buf + offset, sizeof(buf) - offset,
                 "%s{"
                 "\"candidate_id\":\"%s\","
                 "\"seat\":\"%s\","
                 "\"ip\":\"UNAVAILABLE\","
                 "\"status\":\"%s\","
                 "\"battery_percent\":\"UNAVAILABLE\","
                 "\"ping_ms\":\"UNAVAILABLE\","
                 "\"answered\":%d,"
                 "\"total\":%d,"
                 "\"anomalies\":\"UNAVAILABLE\","
                 "\"last_sync\":%ld,"
                 "\"start_time\":%ld"
                 "}",
                 i > 0 ? "," : "",
                 cid, seat,
                 is_sub ? "SUBMITTED" : (is_paused ? "PAUSED" : "IN_PROGRESS"),
                 ans, question_count,
                 last_sync_ts, start_ts);
    }

    snprintf(buf + offset, sizeof(buf) - offset, "]}");
    pthread_mutex_unlock(&g_engine_lock);
    return buf;
}

int center_master_execute_command(const char *command, const char *target_candidate_id, const char *payload) {
    pthread_mutex_lock(&g_engine_lock);
    if (strcmp(command, "BROADCAST") == 0 && payload) {
        strncpy(g_broadcast_announcement, payload, sizeof(g_broadcast_announcement)-1);
        g_broadcast_time = time(NULL);
    } else if (strcmp(command, "PAUSE") == 0) {
        for (int i = 0; i < g_exam_state_count; i++) {
            if (!target_candidate_id || strcmp(g_exam_states[i].candidate_id, target_candidate_id) == 0) {
                g_exam_states[i].is_paused = 1;
            }
        }
    } else if (strcmp(command, "RESUME") == 0) {
        for (int i = 0; i < g_exam_state_count; i++) {
            if (!target_candidate_id || strcmp(g_exam_states[i].candidate_id, target_candidate_id) == 0) {
                g_exam_states[i].is_paused = 0;
            }
        }
    }
    pthread_mutex_unlock(&g_engine_lock);
    return 0;
}

const char* center_master_get_announcements_json(void) {
    static char buf[512];
    pthread_mutex_lock(&g_engine_lock);
    snprintf(buf, sizeof(buf), "{\"announcement\":\"%s\",\"timestamp\":%ld}",
             g_broadcast_announcement, (long)g_broadcast_time);
    pthread_mutex_unlock(&g_engine_lock);
    return buf;
}

const char* exam_workbench_html(const char *candidate_id, const char *session_token) {
    static char buf[65536];
    (void)candidate_id;
    (void)session_token;
    snprintf(buf, sizeof(buf),
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "  <meta charset=\"UTF-8\">\n"
    "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
    "  <title>ExamOS — Advanced Enterprise Examination Workbench</title>\n"
    "  <style>\n"
    "    :root {\n"
    "      --bg: #090d16; --panel: #111a2e; --panel-elevated: #162238; --border: #1e293b;\n"
    "      --primary: #0284c7; --primary-light: #38bdf8; --success: #10b981; --warn: #f59e0b; --danger: #ef4444; --review: #8b5cf6;\n"
    "      --text: #f8fafc; --text-muted: #94a3b8;\n"
    "    }\n"
    "    * { box-sizing: border-box; margin: 0; padding: 0; user-select: none; }\n"
    "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }\n"
    "    /* Top Exam Bar */\n"
    "    .topbar { height: 50px; background: rgba(15, 23, 42, 0.96); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; padding: 0 20px; z-index: 100; }\n"
    "    .exam-brand { font-weight: 800; font-size: 15px; color: #fff; display: flex; align-items: center; gap: 10px; }\n"
    "    .exam-badge { background: linear-gradient(135deg, #0284c7, #0ea5e9); padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 800; }\n"
    "    .candidate-info { display: flex; align-items: center; gap: 16px; font-size: 13px; color: var(--text-muted); }\n"
    "    .cand-name { color: #fff; font-weight: 700; }\n"
    "    .timer-badge { background: #1e293b; border: 1px solid #334155; padding: 6px 14px; border-radius: 6px; font-family: monospace; font-size: 16px; font-weight: 800; color: #34d399; display: flex; align-items: center; gap: 8px; }\n"
    "    /* Broadcast Ticker */\n"
    "    .ticker-bar { background: #0c4a6e; border-bottom: 1px solid #0284c7; padding: 4px 16px; font-size: 12px; color: #e0f2fe; display: flex; align-items: center; gap: 8px; }\n"
    "    .ticker-tag { background: #0284c7; color: #fff; font-weight: 800; padding: 1px 6px; border-radius: 3px; font-size: 10px; }\n"
    "    /* Main Container */\n"
    "    .main-body { flex: 1; display: flex; overflow: hidden; }\n"
    "    /* Question Area */\n"
    "    .question-pane { flex: 1; display: flex; flex-direction: column; border-right: 1px solid var(--border); background: var(--panel); }\n"
    "    .section-tabs { display: flex; background: #0b1120; border-bottom: 1px solid var(--border); padding: 0 16px; gap: 4px; }\n"
    "    .section-tab { padding: 10px 16px; font-size: 12px; font-weight: 700; color: var(--text-muted); cursor: pointer; border-bottom: 2px solid transparent; }\n"
    "    .section-tab.active { color: var(--primary-light); border-bottom-color: var(--primary-light); background: rgba(56, 189, 248, 0.05); }\n"
    "    .question-content { flex: 1; padding: 24px 32px; overflow-y: auto; }\n"
    "    .q-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 12px; }\n"
    "    .q-number { font-size: 16px; font-weight: 800; color: #f8fafc; }\n"
    "    .q-marks { font-size: 12px; background: rgba(16, 185, 129, 0.15); color: #34d399; padding: 2px 8px; border-radius: 4px; font-weight: 700; }\n"
    "    .q-text { font-size: 15px; line-height: 1.6; margin-bottom: 24px; color: #e2e8f0; }\n"
    "    .options-grid { display: flex; flex-direction: column; gap: 12px; }\n"
    "    .opt-card { background: var(--panel-elevated); border: 1px solid var(--border); padding: 14px 18px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; gap: 12px; font-size: 14px; transition: all 0.15s; }\n"
    "    .opt-card:hover { border-color: var(--primary-light); background: rgba(56, 189, 248, 0.08); }\n"
    "    .opt-card.selected { border-color: var(--primary-light); background: rgba(2, 132, 199, 0.2); box-shadow: 0 0 12px rgba(2, 132, 199, 0.3); font-weight: 600; }\n"
    "    .opt-radio { width: 18px; height: 18px; border-radius: 50%%; border: 2px solid #475569; display: flex; align-items: center; justify-content: center; }\n"
    "    .opt-card.selected .opt-radio { border-color: var(--primary-light); background: var(--primary-light); }\n"
    "    /* Action Footer */\n"
    "    .action-footer { padding: 14px 32px; background: #0b1120; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }\n"
    "    .btn { padding: 9px 18px; border-radius: 6px; font-size: 13px; font-weight: 700; cursor: pointer; border: none; display: flex; align-items: center; gap: 6px; }\n"
    "    .btn-save { background: #0284c7; color: #fff; }\n"
    "    .btn-save:hover { background: #0369a1; }\n"
    "    .btn-review { background: #6d28d9; color: #fff; }\n"
    "    .btn-clear { background: #334155; color: #cbd5e1; }\n"
    "    .btn-submit { background: linear-gradient(135deg, #16a34a, #15803d); color: #fff; padding: 10px 24px; font-size: 14px; box-shadow: 0 4px 12px rgba(22, 163, 74, 0.4); }\n"
    "    /* Right Sidebar: Palette & Proctoring */\n"
    "    .sidebar { width: 330px; background: #0b1120; display: flex; flex-direction: column; }\n"
    "    .cam-preview-box { height: 160px; background: #000; border-bottom: 1px solid var(--border); position: relative; overflow: hidden; }\n"
    "    .cam-video { width: 100%%; height: 100%%; object-fit: cover; }\n"
    "    .cam-overlay { position: absolute; inset: 0; border: 2px solid rgba(52, 211, 153, 0.5); pointer-events: none; }\n"
    "    .cam-tag { position: absolute; top: 8px; left: 8px; background: rgba(0,0,0,0.7); font-size: 10px; font-weight: 700; color: #34d399; padding: 2px 6px; border-radius: 4px; display: flex; align-items: center; gap: 4px; }\n"
    "    /* Palette Grid */\n"
    "    .palette-box { flex: 1; padding: 16px; overflow-y: auto; }\n"
    "    .palette-title { font-size: 13px; font-weight: 700; margin-bottom: 12px; color: var(--text-muted); }\n"
    "    .palette-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-bottom: 16px; }\n"
    "    .p-btn { aspect-ratio: 1; border-radius: 6px; font-size: 12px; font-weight: 800; display: flex; align-items: center; justify-content: center; cursor: pointer; border: 1px solid var(--border); background: #1e293b; color: #94a3b8; }\n"
    "    .p-btn.current { border: 2px solid #38bdf8; }\n"
    "    .p-btn.answered { background: #10b981; color: #fff; border-color: #10b981; }\n"
    "    .p-btn.not-answered { background: #ef4444; color: #fff; border-color: #ef4444; }\n"
    "    .p-btn.marked-review { background: #8b5cf6; color: #fff; border-color: #8b5cf6; border-radius: 50%%; }\n"
    "    /* Legend */\n"
    "    .legend { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; font-size: 11px; color: var(--text-muted); }\n"
    "    .leg-item { display: flex; align-items: center; gap: 6px; }\n"
    "    .leg-dot { width: 12px; height: 12px; border-radius: 3px; }\n"
    "    /* Scratchpad Modal */\n"
    "    #scratch-modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 500; align-items: center; justify-content: center; }\n"
    "    .scratch-box { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; width: 600px; padding: 20px; }\n"
    "    textarea { width: 100%%; height: 250px; background: #000; border: 1px solid var(--border); border-radius: 6px; color: #34d399; font-family: monospace; padding: 12px; font-size: 13px; outline: none; }\n"
    "    /* Accessibility: focus-visible outlines for keyboard navigation */\n    :focus-visible { outline: 3px solid #38bdf8; outline-offset: 2px; }\n    .opt-card:focus-visible { border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.5); }\n    .btn:focus-visible { box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.5); }\n    .p-btn:focus-visible { box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.5); }\n    /* High-contrast mode support */\n    @media (prefers-contrast: high) {\n      :root { --bg: #000; --panel: #111; --border: #555; --text: #fff; --text-muted: #ccc; }\n      .opt-card { border-width: 2px; }\n      .opt-card.selected { border-width: 3px; background: rgba(2, 132, 199, 0.4); }\n    }\n    /* Reduced motion support */\n    @media (prefers-reduced-motion: reduce) {\n      * { transition: none !important; animation: none !important; }\n    }\n  </style>\n"
    "</head>\n"
    "<body>\n"
    "  <!-- Top Exam Header -->\n"
    "  <div class=\"topbar\" role=\"banner\">\n"
    "    <div class=\"exam-brand\">\n"
    "      <span class=\"exam-badge\">ExamOS</span>\n"
    "      <span>Examination Workbench</span>\n"
    "    </div>\n"
    "    <div class=\"candidate-info\">\n"
    "      <div>Candidate: <span class=\"cand-name\" style=\"color:#fff;font-weight:700;\">—</span></div>\n"
    "      <div>Seat: <span id=\"seat-tag\" style=\"color: #38bdf8; font-weight: 700;\">UNASSIGNED</span></div>\n"
    "      <div class=\"timer-badge\">\n"
    "        <svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\"><circle cx=\"12\" cy=\"12\" r=\"10\"/><polyline points=\"12 6 12 12 16 14\"/></svg>\n"
    "        <span id=\"exam-timer\" aria-live=\"polite\" aria-label=\"Time remaining\">--:--</span>\n"
    "      </div>\n"
    "    </div>\n"
    "  </div>\n"
    "\n"
    "  <!-- Broadcast Announcement Bar -->\n"
    "  <div class=\"ticker-bar\">\n"
    "    <span class=\"ticker-tag\">INVIGILATOR DESK</span>\n"
    "    <span id=\"announcement-text\" role=\"status\" aria-live=\"polite\"></span>\n"
    "  </div>\n"
    "\n"
    "  <!-- Main Body -->\n"
    "  <div class=\"main-body\" role=\"main\">\n"
    "    <!-- Left Question Pane -->\n"
    "    <div class=\"question-pane\">\n"
    "      <div class=\"section-tabs\" id=\"sections-bar\" role=\"tablist\" aria-label=\"Exam sections\">\n"
    "        <div class=\"section-tab active\">Section A: Quantitative Logic</div>\n"
    "        <div class=\"section-tab\">Section B: Systems Reasoning</div>\n"
    "        <div class=\"section-tab\">Section C: Technical Coding</div>\n"
    "      </div>\n"
    "\n"
    "      <div class=\"question-content\">\n"
    "        <div class=\"q-header\">\n"
    "          <div class=\"q-number\" id=\"q-num-display\">Question 1</div>\n"
    "          <div class=\"q-marks\" id=\"q-marks-display\">+3.00 / -0.75 Marks</div>\n"
    "        </div>\n"
    "        <div class=\"q-text\" id=\"q-text-display\" aria-live=\"polite\" role=\"region\" aria-label=\"Current question\">Loading examination paper from local center vault...</div>\n"
    "        <div class=\"options-grid\" id=\"options-container\" role=\"radiogroup\" aria-label=\"Answer options\"></div>\n"
    "      </div>\n"
    "\n"
    "      <div class=\"action-footer\">\n"
    "        <div style=\"display: flex; gap: 10px;\">\n"
    "          <button class=\"btn btn-save\" onclick=\"saveAndNext()\">Save & Next</button>\n"
    "          <button class=\"btn btn-review\" onclick=\"markForReview()\">Mark for Review & Next</button>\n"
    "          <button class=\"btn btn-clear\" onclick=\"clearResponse()\">Clear Response</button>\n"
    "          <button class=\"btn btn-clear\" onclick=\"toggleScratchpad()\">Digital Scratchpad</button>\n"
    "        </div>\n"
    "        <button class=\"btn btn-submit\" onclick=\"confirmSubmit()\">Submit Final Assessment</button>\n"
    "      </div>\n"
    "    </div>\n"
    "\n"
    "    <!-- Right Sidebar -->\n"
    "    <div class=\"sidebar\">\n"
    "      <!-- WebRTC Live Proctoring -->\n"
    "      <div class=\"cam-preview-box\">\n"
    "        <video id=\"proctor-cam\" class=\"cam-video\" autoplay muted playsinline></video>\n"
    "        <div class=\"cam-overlay\"></div>\n"
    "        <div class=\"cam-tag\">Camera not activated</div>\n"
    "      </div>\n"
    "\n"
    "      <!-- Question Palette -->\n"
    "      <div class=\"palette-box\">\n"
    "        <div class=\"palette-title\">QUESTION PALETTE</div>\n"
    "        <div class=\"palette-grid\" id=\"palette-grid\" role=\"navigation\" aria-label=\"Question navigation palette\"></div>\n"
    "\n"
    "        <div class=\"legend\">\n"
    "          <div class=\"leg-item\"><div class=\"leg-dot\" style=\"background: #10b981;\"></div> Answered</div>\n"
    "          <div class=\"leg-item\"><div class=\"leg-dot\" style=\"background: #ef4444;\"></div> Not Answered</div>\n"
    "          <div class=\"leg-item\"><div class=\"leg-dot\" style=\"background: #8b5cf6; border-radius:50%%;\"></div> Review</div>\n"
    "          <div class=\"leg-item\"><div class=\"leg-dot\" style=\"background: #1e293b;\"></div> Not Visited</div>\n"
    "        </div>\n"
    "      </div>\n"
    "    </div>\n"
    "  </div>\n"
    "\n"
    "  <!-- Scratchpad Modal -->\n"
    "  <div id=\"scratch-modal\">\n"
    "    <div class=\"scratch-box\">\n"
    "      <div style=\"display:flex; justify-content:space-between; margin-bottom:10px;\">\n"
    "        <span style=\"font-weight:700;\">Rough Work / Digital Scratchpad</span>\n"
    "        <button onclick=\"toggleScratchpad()\" style=\"background:none; border:none; color:#ef4444; font-weight:800; cursor:pointer;\">✕ Close</button>\n"
    "      </div>\n"
    "      <textarea placeholder=\"Type rough calculations, logic drafts here...\"></textarea>\n"
    "    </div>\n"
    "  </div>\n"
    "\n"
    "  <script>\n"
    "    const SESSION_TOKEN = sessionStorage.getItem('examos_session_token') || '';\n"
    "    if (!SESSION_TOKEN) { window.location.href = '/'; }\n"
    "    let paperData = null;\n"
    "    let currentQIndex = 0;\n"
    "    let timeRemaining = 0;\n"
    "\n"
    "    async function initExam() {\n"
    "      try {\n"
    "        const res = await fetch('/api/v1/exam/paper', {\n"
    "          headers: { 'Authorization': 'Bearer ' + SESSION_TOKEN }\n"
    "        });\n"
    "        if (!res.ok) {\n"
    "          document.getElementById('q-text-display').innerText = 'Exam content is unavailable until an approved exam is provisioned.';\n"
    "          return;\n"
    "        }\n"
    "        paperData = await res.json();\n"
    "        if (!Array.isArray(paperData.questions) || paperData.questions.length === 0 ||\n"
    "            !Number.isFinite(paperData.time_remaining) || paperData.time_remaining <= 0) {\n"
    "          document.getElementById('q-text-display').innerText = 'The provisioned exam session is incomplete.';\n"
    "          return;\n"
    "        }\n"
    "        if (paperData.candidate_id) document.querySelector('.cand-name').innerText = paperData.candidate_id;\n"
    "        if (paperData.seat_number) document.getElementById('seat-tag').innerText = paperData.seat_number;\n"
    "        timeRemaining = paperData.time_remaining;\n"
    "        renderPalette();\n"
    "        loadQuestion(0);\n"
    "        startTimer();\n"
    "        pollAnnouncements();\n"
    "        startCamera();\n"
    "      } catch (err) {\n"
    "        document.getElementById('q-text-display').innerText = 'Unable to load the provisioned exam session.';\n"
    "      }\n"
    "    }\n"
    "\n"
    "    function renderPalette() {\n"
    "      const grid = document.getElementById('palette-grid');\n"
    "      grid.innerHTML = '';\n"
    "      paperData.questions.forEach((q, idx) => {\n"
    "        const btn = document.createElement('div');\n"
    "        btn.className = 'p-btn';\n"
    "        if (idx === currentQIndex) btn.classList.add('current');\n"
    "        if (q.status === 2) btn.classList.add('answered');\n"
    "        else if (q.status === 1) btn.classList.add('not-answered');\n"
    "        else if (q.status === 3) btn.classList.add('marked-review');\n"
    "        btn.innerText = idx + 1;\n"
    "        btn.onclick = () => loadQuestion(idx);\n"
    "        grid.appendChild(btn);\n"
    "      });\n"
    "    }\n"
    "\n"
    "    function loadQuestion(idx) {\n"
    "      if (!paperData || !paperData.questions[idx]) return;\n"
    "      currentQIndex = idx;\n"
    "      const q = paperData.questions[idx];\n"
    "      if (q.status === 0) q.status = 1; // Mark as visited\n"
    "      document.getElementById('q-num-display').innerText = 'Question ' + (idx + 1) + ' (' + q.section + ')';\n"
    "      document.getElementById('q-marks-display').innerText = q.marks + ' marks';\n"
    "      document.getElementById('q-text-display').innerText = q.text;\n"
    "\n"
    "      const optContainer = document.getElementById('options-container');\n"
    "      optContainer.innerHTML = '';\n"
    "      q.options.forEach((opt, oIdx) => {\n"
    "        const card = document.createElement('div');\n"
    "        card.className = 'opt-card' + (q.selected === oIdx ? ' selected' : '');\n"
    "        card.innerHTML = `<div class=\"opt-radio\"></div><span>${opt}</span>`;\n"
    "        card.onclick = () => {\n"
    "          q.selected = oIdx;\n"
    "          document.querySelectorAll('.opt-card').forEach(c => c.classList.remove('selected'));\n"
    "          card.classList.add('selected');\n"
    "        };\n"
    "        optContainer.appendChild(card);\n"
    "      });\n"
    "      renderPalette();\n"
    "    }\n"
    "\n"
    "    async function saveAndNext() {\n"
    "      const q = paperData.questions[currentQIndex];\n"
    "      if (q.selected >= 0) q.status = 2; // Answered\n"
    "      else q.status = 1; // Not answered\n"
    "      await syncAnswer(q);\n"
    "      if (currentQIndex < paperData.questions.length - 1) loadQuestion(currentQIndex + 1);\n"
    "      else renderPalette();\n"
    "    }\n"
    "\n"
    "    async function markForReview() {\n"
    "      const q = paperData.questions[currentQIndex];\n"
    "      q.status = 3;\n"
    "      await syncAnswer(q);\n"
    "      if (currentQIndex < paperData.questions.length - 1) loadQuestion(currentQIndex + 1);\n"
    "      else renderPalette();\n"
    "    }\n"
    "\n"
    "    function clearResponse() {\n"
    "      const q = paperData.questions[currentQIndex];\n"
    "      q.selected = -1;\n"
    "      q.status = 1;\n"
    "      syncAnswer(q);\n"
    "      loadQuestion(currentQIndex);\n"
    "    }\n"
    "\n"
    "    async function syncAnswer(q) {\n"
    "      try {\n"
    "        const response = await fetch('/api/v1/exam/save_answer', {\n"
    "          method: 'POST',\n"
    "          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + SESSION_TOKEN },\n"
    "          body: JSON.stringify({\n"
    "            question_id: q.id,\n"
    "            selected_option: q.selected,\n"
    "            status: q.status\n"
    "          })\n"
    "        });\n"
    "        if (!response.ok) throw new Error('Answer save was rejected');\n"
    "      } catch (err) {\n"
    "        document.getElementById('announcement-text').innerText = 'Answer save failed. Do not continue until the session is restored.';\n"
    "        throw err;\n"
    "      }\n"
    "    }\n"
    "\n"
    "    function startTimer() {\n"
    "      setInterval(() => {\n"
    "        if (timeRemaining > 0) {\n"
    "          timeRemaining--;\n"
    "          const hrs = String(Math.floor(timeRemaining / 3600)).padStart(2, '0');\n"
    "          const mins = String(Math.floor((timeRemaining %% 3600) / 60)).padStart(2, '0');\n"
    "          const secs = String(timeRemaining %% 60).padStart(2, '0');\n"
    "          document.getElementById('exam-timer').innerText = `${hrs}:${mins}:${secs}`;\n"
    "        }\n"
    "      }, 1000);\n"
    "    }\n"
    "\n"
    "    async function startCamera() {\n"
    "      try {\n"
    "        const stream = await navigator.mediaDevices.getUserMedia({ video: true });\n"
    "        document.getElementById('proctor-cam').srcObject = stream;\n"
    "      } catch (e) {}\n"
    "    }\n"
    "\n"
    "    async function pollAnnouncements() {\n"
    "      setInterval(async () => {\n"
    "        try {\n"
    "          const res = await fetch('/api/v1/exam/announcements');\n"
    "          const data = await res.json();\n"
    "          if (data.announcement) {\n"
    "            document.getElementById('announcement-text').innerText = data.announcement;\n"
    "          }\n"
    "        } catch (e) {}\n"
    "      }, 5000);\n"
    "    }\n"
    "\n"
    "    function toggleScratchpad() {\n"
    "      const m = document.getElementById('scratch-modal');\n"
    "      m.style.display = (m.style.display === 'flex') ? 'none' : 'flex';\n"
    "    }\n"
    "\n"
    "    async function confirmSubmit() {\n"
    "      if (confirm('Are you sure you want to end and submit your final assessment? Answers will be cryptographically locked.')) {\n"
    "        const res = await fetch('/api/v1/exam/submit', {\n"
    "          method: 'POST',\n"
    "          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + SESSION_TOKEN },\n"
    "          body: JSON.stringify({})\n"
    "        });\n"
    "        const data = await res.json();\n"
    "        alert('Assessment submitted successfully!\\nCryptographic Receipt: ' + data.receipt_hash);\n"
    "        window.location.href = '/';\n"
    "      }\n"
    "    }\n"
    "\n"
    "    /* Enterprise Anti-Cheat & Kiosk Enforcement */\n"
    "    document.addEventListener('contextmenu', e => e.preventDefault());\n"
    "    document.addEventListener('keydown', e => {\n"
    "      if (e.key === 'F12' || (e.ctrlKey && ['c','v','u','s','p','i','j','a'].includes(e.key.toLowerCase()))) {\n"
    "        e.preventDefault();\n"
    "      }\n"
    "    });\n"
    "    window.addEventListener('blur', () => {\n"
    "      const ticker = document.getElementById('announcement-text');\n"
    "      if (ticker) ticker.innerText = 'PROCTOR ALERT: Window focus lost! Deviation logged in evidence chain.';\n"
    "    });\n"
    "\n"
    "    window.onload = initExam;\n"
    "  </script>\n"
    "</body>\n"
    "</html>\n");

    return buf;
}
