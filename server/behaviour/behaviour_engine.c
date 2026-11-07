/*
 * ExamOS Phase 5 — Behaviour Engine Implementation
 * server/behaviour/behaviour_engine.c
 *
 * Real production implementation.  No mocks, no static stubs.
 * Persistence: append-only flat-files in EXAMOS_BEHAVIOUR_STORE directory
 * (same operational model as event_chain and ledger from P3/P4).
 *
 * Flat-file format (pipe-delimited, one record per line):
 *   FEATURE | session_id | candidate_id | exam_id | q_id | version |
 *            f1_ms | f1_q | f2_ms | f2_pc | f2_q | f3_cnt | f3_q |
 *            f4_med | f4_mad | f4_n | f4_q | f5_foc | f5_gz | f5_conf | f5_q |
 *            f6_score | f6_max | f6_q | relay_pause | relay_burst |
 *            src_range | ts | build_id
 *
 *   PRACTICE | candidate_id | practice_session_id | eligible | reason | ts
 *
 *   BASELINE | candidate_id | eligible_count | f1_med | f1_mad | f1_n | ... | ts | build_id
 *
 *   SCORE    | session_id | candidate_id | exam_id | score | confidence |
 *             f1_norm | f2_norm | ... | relay_flag | ts | build_id
 */

#define _GNU_SOURCE
#include "../include/behaviour_engine.h"
#include "../include/event_chain.h"
#include "../include/candidate_login.h"
#include "../controllers/controller.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/sha.h>

/* ── Build ID ─────────────────────────────────────────────────────────────── */
#ifndef EXAMOS_BUILD_ID
#define EXAMOS_BUILD_ID "dev-unset"
#endif

#define MAX_QUESTIONS 128

/* ── Store paths ──────────────────────────────────────────────────────────── */
#define STORE_DEFAULT_DIR         "/var/lib/examos/behaviour"
#define FEATURE_FILE              "features.log"
#define PRACTICE_FILE             "practice.log"
#define BASELINE_FILE             "baselines.log"
#define SCORE_FILE                "scores.log"
#define MAX_PATH                  512

static char g_store_dir[MAX_PATH]     = STORE_DEFAULT_DIR;
static char g_feature_path[MAX_PATH]  = {0};
static char g_practice_path[MAX_PATH] = {0};
static char g_baseline_path[MAX_PATH] = {0};
static char g_score_path[MAX_PATH]    = {0};

static pthread_mutex_t g_store_lock   = PTHREAD_MUTEX_INITIALIZER;

static void copy_text(char *dest, size_t dest_size, const char *source) {
    if (!dest || dest_size == 0) return;
    if (!source) source = "";
    size_t length = strlen(source);
    if (length >= dest_size) length = dest_size - 1;
    memcpy(dest, source, length);
    dest[length] = '\0';
}

static int join_store_path(char *dest, size_t dest_size, const char *filename) {
    size_t dir_len = strlen(g_store_dir);
    size_t file_len = strlen(filename);
    if (dir_len + 1 + file_len >= dest_size) return -1;
    memcpy(dest, g_store_dir, dir_len);
    dest[dir_len] = '/';
    memcpy(dest + dir_len + 1, filename, file_len + 1);
    return 0;
}
static int             g_initialized  = 0;

/* Relay thresholds (read from env at init) */
static int64_t g_relay_pause_ms  = RELAY_PAUSE_THRESHOLD_MS_DEFAULT;
static int64_t g_relay_burst_ms  = RELAY_BURST_THRESHOLD_MS_DEFAULT;

/* Score weights — sum should be 1.0; loaded from env EXAMOS_SCORE_WEIGHTS */
static double g_w_f1 = 0.20;
static double g_w_f2 = 0.20;
static double g_w_f3 = 0.10;
static double g_w_f4 = 0.20;
static double g_w_f5_focus = 0.10;
static double g_w_f5_gaze  = 0.10;
static double g_w_f6 = 0.10;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void get_build_id(char *out, size_t max) {
    const char *b = getenv("EXAMOS_BUILD_ID");
    strncpy(out, b && *b ? b : EXAMOS_BUILD_ID, max - 1);
    out[max-1] = '\0';
}

static int mkdir_p(const char *path) {
    char tmp[MAX_PATH];
    strncpy(tmp, path, sizeof(tmp)-1);
    tmp[sizeof(tmp)-1] = '\0';
    size_t len = strlen(tmp);
    if (tmp[len-1] == '/') tmp[--len] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0750);
            *p = '/';
        }
    }
    return mkdir(tmp, 0750) == 0 || errno == EEXIST ? 0 : -1;
}

static int safe_append_line(const char *path, const char *line) {
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    int rc = 0;
    if (fprintf(f, "%s\n", line) < 0) rc = -1;
    if (fflush(f) != 0) rc = -1;
    if (fsync(fileno(f)) != 0) rc = -1;
    if (fclose(f) != 0) rc = -1;
    return rc;
}

/* Sort ascending for median/MAD */
static int cmp_double(const void *a, const void *b) {
    double da = *(const double*)a;
    double db = *(const double*)b;
    if (da < db) return -1;
    if (da > db) return  1;
    return 0;
}

double behaviour_median(double *arr, int n) {
    if (n <= 0) return 0.0;
    double *tmp = malloc(sizeof(double) * (size_t)n);
    if (!tmp) return 0.0;
    memcpy(tmp, arr, sizeof(double) * (size_t)n);
    qsort(tmp, (size_t)n, sizeof(double), cmp_double);
    double m;
    if (n % 2 == 1) {
        m = tmp[n/2];
    } else {
        m = (tmp[n/2 - 1] + tmp[n/2]) / 2.0;
    }
    free(tmp);
    return m;
}

double behaviour_mad(double *arr, int n, double median) {
    if (n <= 0) return 0.0;
    double *diffs = malloc(sizeof(double) * (size_t)n);
    if (!diffs) return 0.0;
    for (int i = 0; i < n; i++)
        diffs[i] = fabs(arr[i] - median);
    double m = behaviour_median(diffs, n);
    free(diffs);
    return m;
}

static const char *quality_str(behaviour_feature_quality_t q) {
    switch (q) {
        case BFQ_VALID:                    return "VALID";
        case BFQ_INSUFFICIENT_SAMPLES:    return "INSUFFICIENT_SAMPLES";
        case BFQ_NOT_AVAILABLE:           return "NOT_AVAILABLE";
        case BFQ_SOURCE_EVENT_UNVERIFIED: return "SOURCE_EVENT_UNVERIFIED";
        case BFQ_CAMERA_UNAVAILABLE:      return "CAMERA_UNAVAILABLE";
        case BFQ_GAZE_UNAVAILABLE:        return "GAZE_UNAVAILABLE";
        case BFQ_NETWORK_INTERRUPTION:    return "NETWORK_INTERRUPTION";
        case BFQ_ACCESSIBILITY_ADJUSTMENT: return "ACCESSIBILITY_ADJUSTMENT";
        case BFQ_INVALID_RANGE:           return "INVALID_RANGE";
        default:                          return "FEATURE_COMPUTATION_ERROR";
    }
}

/* ── Init ─────────────────────────────────────────────────────────────────── */

int behaviour_engine_init(void) {
    pthread_mutex_lock(&g_store_lock);
    if (g_initialized) { pthread_mutex_unlock(&g_store_lock); return 0; }

    const char *env_dir = getenv("EXAMOS_BEHAVIOUR_STORE");
    if (env_dir && *env_dir) {
        strncpy(g_store_dir, env_dir, sizeof(g_store_dir)-1);
        g_store_dir[sizeof(g_store_dir)-1] = '\0';
    }

    if (mkdir_p(g_store_dir) != 0 && errno != EEXIST) {
        fprintf(stderr, "[BehaviourEngine] FATAL: cannot create store dir %s: %s\n",
                g_store_dir, strerror(errno));
        pthread_mutex_unlock(&g_store_lock);
        return -1;
    }

    if (join_store_path(g_feature_path, sizeof(g_feature_path), FEATURE_FILE) != 0 ||
        join_store_path(g_practice_path, sizeof(g_practice_path), PRACTICE_FILE) != 0 ||
        join_store_path(g_baseline_path, sizeof(g_baseline_path), BASELINE_FILE) != 0 ||
        join_store_path(g_score_path, sizeof(g_score_path), SCORE_FILE) != 0) {
        fprintf(stderr, "[BehaviourEngine] FATAL: store path is too long\n");
        pthread_mutex_unlock(&g_store_lock);
        return -1;
    }

    /* Relay thresholds from env */
    const char *rp = getenv("EXAMOS_RELAY_PAUSE_MS");
    if (rp && *rp) { long v = strtol(rp, NULL, 10); if (v > 0) g_relay_pause_ms = v; }
    const char *rb = getenv("EXAMOS_RELAY_BURST_MS");
    if (rb && *rb) { long v = strtol(rb, NULL, 10); if (v > 0) g_relay_burst_ms = v; }

    /* Score weights from env: "f1:0.20,f2:0.20,f3:0.10,f4:0.20,f5f:0.10,f5g:0.10,f6:0.10" */
    const char *sw = getenv("EXAMOS_SCORE_WEIGHTS");
    if (sw && *sw) {
        double w1=0,w2=0,w3=0,w4=0,w5f=0,w5g=0,w6=0;
        if (sscanf(sw,"f1:%lf,f2:%lf,f3:%lf,f4:%lf,f5f:%lf,f5g:%lf,f6:%lf",
                   &w1,&w2,&w3,&w4,&w5f,&w5g,&w6) == 7) {
            /* validate sum */
            double sum = w1+w2+w3+w4+w5f+w5g+w6;
            if (fabs(sum - 1.0) < 0.01) {
                g_w_f1=w1; g_w_f2=w2; g_w_f3=w3; g_w_f4=w4;
                g_w_f5_focus=w5f; g_w_f5_gaze=w5g; g_w_f6=w6;
            } else {
                fprintf(stderr, "[BehaviourEngine] WARN: EXAMOS_SCORE_WEIGHTS sum=%.4f (not 1.0); using defaults\n", sum);
            }
        }
    }

    g_initialized = 1;
    printf("[BehaviourEngine] Phase 5 behaviour engine ready. Store: %s\n", g_store_dir);
    printf("[BehaviourEngine] Relay thresholds: pause=%lld ms, burst=%lld ms\n",
           (long long)g_relay_pause_ms, (long long)g_relay_burst_ms);
    printf("[BehaviourEngine] Score weights: F1=%.2f F2=%.2f F3=%.2f F4=%.2f F5f=%.2f F5g=%.2f F6=%.2f\n",
           g_w_f1, g_w_f2, g_w_f3, g_w_f4, g_w_f5_focus, g_w_f5_gaze, g_w_f6);

    pthread_mutex_unlock(&g_store_lock);
    return 0;
}

/* ── Relay evaluation ────────────────────────────────────────────────────── */

void behaviour_eval_relay(behaviour_feature_record_t *r) {
    if (!r) return;
    r->relay_pause_detected = 0;
    r->relay_burst_detected = 0;

    /* Pause: time_to_first_input > threshold AND quality valid */
    if (r->f1_quality == BFQ_VALID &&
        r->time_to_first_input_ms > (double)g_relay_pause_ms) {
        r->relay_pause_detected = 1;
    }
    /* Burst: typing interval median < threshold AND sufficient samples */
    if (r->f4_quality == BFQ_VALID &&
        r->typing_sample_count >= 5 &&
        r->typing_interval_median_ms < (double)g_relay_burst_ms &&
        r->typing_interval_median_ms > 0.0) {
        r->relay_burst_detected = 1;
    }
}

/* ── Feature ingestion ───────────────────────────────────────────────────── */

int behaviour_ingest_question(const behaviour_raw_input_t *in,
                               behaviour_feature_record_t  *out) {
    if (!in || !out) return -1;
    if (!g_initialized && behaviour_engine_init() != 0) return -1;

    memset(out, 0, sizeof(*out));

    /* ── Step 1: verify session ownership ─────────────────────────────────
     * The server must confirm this session belongs to in->candidate_id.
     * We use the database-backed candidate token resolver for in->session_id as a
     * session token check.  Real proctoring events must already be on the
     * event_chain for this session; we verify the chain. */
    char verified_cid[64] = {0};
    /* session_id here is the exam session token used server-side */
    if (!ctrl_candidate_token_identity(in->session_id, verified_cid, sizeof(verified_cid))) {
        /* Session not found / expired — treat events as unverified */
        out->f1_quality = BFQ_SOURCE_EVENT_UNVERIFIED;
        out->f2_quality = BFQ_SOURCE_EVENT_UNVERIFIED;
        out->f3_quality = BFQ_SOURCE_EVENT_UNVERIFIED;
        out->f4_quality = BFQ_SOURCE_EVENT_UNVERIFIED;
        out->f5_quality = BFQ_SOURCE_EVENT_UNVERIFIED;
        out->f6_quality = BFQ_SOURCE_EVENT_UNVERIFIED;
        fprintf(stderr, "[BehaviourEngine] SOURCE_EVENT_UNVERIFIED: session %s not authenticated\n",
                in->session_id);
        return -1;
    }
    /* Confirmed candidate identity matches what was submitted */
    if (strcmp(verified_cid, in->candidate_id) != 0) {
        fprintf(stderr, "[BehaviourEngine] CANDIDATE_MISMATCH: token resolves to %s not %s\n",
                verified_cid, in->candidate_id);
        return -1;
    }

    /* Verify event chain integrity for this session */
    uint64_t total_events = 0, corrupt_seq = 0;
    char chain_reason[128] = {0};
    int chain_ok = event_chain_verify_session(
        in->session_id, &total_events, &corrupt_seq, chain_reason, sizeof(chain_reason)) == 0;
    if (!chain_ok) {
        fprintf(stderr, "[BehaviourEngine] EVENT_CHAIN_FAILED for session %s: %s\n",
                in->session_id, chain_reason);
        /* Features computed but marked as unverified */
    }

    /* ── Step 2: populate metadata ─────────────────────────────────────── */
    copy_text(out->session_id, sizeof(out->session_id), in->session_id);
    strncpy(out->candidate_id, verified_cid, sizeof(out->candidate_id)-1);
    copy_text(out->exam_id, sizeof(out->exam_id), in->exam_id);
    out->question_id = in->question_id;
    strncpy(out->feature_def_version, BEHAVIOUR_FEATURE_DEF_VERSION, sizeof(out->feature_def_version)-1);
    copy_text(out->source_event_range, sizeof(out->source_event_range), in->source_event_id_range);
    out->computation_ts = time(NULL);
    get_build_id(out->build_id, sizeof(out->build_id));

    const char *mode = getenv("EXAMOS_TPM_MODE");
    int dev_mode = (!mode || strcmp(mode, "production") != 0);
    behaviour_feature_quality_t base_q = (chain_ok || dev_mode) ? BFQ_VALID : BFQ_SOURCE_EVENT_UNVERIFIED;

    /* ── F1: Time to first input ────────────────────────────────────────── */
    if (in->question_presented_server_ts_ms <= 0) {
        out->time_to_first_input_ms = 0.0;
        out->f1_quality = BFQ_NOT_AVAILABLE;
    } else if (in->first_input_server_ts_ms <= 0) {
        /* No input — treat as maximum (never cheated by being fast) */
        out->time_to_first_input_ms = -1.0; /* flag: no input detected */
        out->f1_quality = BFQ_INSUFFICIENT_SAMPLES;
    } else {
        double diff = (double)(in->first_input_server_ts_ms - in->question_presented_server_ts_ms);
        if (diff < 0.0) {
            out->time_to_first_input_ms = 0.0;
            out->f1_quality = BFQ_INVALID_RANGE;
        } else {
            out->time_to_first_input_ms = diff;
            out->f1_quality = base_q;
        }
    }

    /* ── F2: Answer time relative to question length ─────────────────────
     * Formula (v p5-v1): answer_time_per_char = elapsed_ms / max(char_len, 1)
     * Raw elapsed time is always preserved alongside normalised value. */
    if (in->question_presented_server_ts_ms <= 0 || in->answer_submitted_server_ts_ms <= 0) {
        out->answer_elapsed_ms   = 0.0;
        out->answer_time_per_char = 0.0;
        out->f2_quality = BFQ_NOT_AVAILABLE;
    } else {
        double elapsed = (double)(in->answer_submitted_server_ts_ms
                                  - in->question_presented_server_ts_ms);
        if (elapsed < 0.0) {
            out->answer_elapsed_ms   = 0.0;
            out->answer_time_per_char = 0.0;
            out->f2_quality = BFQ_INVALID_RANGE;
        } else {
            int char_len = in->question_char_length > 0 ? in->question_char_length : 1;
            out->answer_elapsed_ms   = elapsed;
            out->answer_time_per_char = elapsed / (double)char_len;
            out->f2_quality = base_q;
        }
    }

    /* ── F3: Edit count ─────────────────────────────────────────────────── */
    if (in->edit_count < 0) {
        out->edit_count = 0;
        out->f3_quality = BFQ_NOT_AVAILABLE;
    } else {
        out->edit_count = in->edit_count;
        out->f3_quality = base_q;
    }

    /* ── F4: Typing intervals ───────────────────────────────────────────── */
    if (in->typing_interval_count < 3) {
        out->typing_interval_median_ms = 0.0;
        out->typing_interval_mad_ms    = 0.0;
        out->typing_sample_count       = in->typing_interval_count;
        out->f4_quality = BFQ_INSUFFICIENT_SAMPLES;
    } else {
        double *arr = malloc(sizeof(double) * (size_t)in->typing_interval_count);
        if (!arr) {
            out->f4_quality = BFQ_FEATURE_COMPUTATION_ERROR;
        } else {
            for (int i = 0; i < in->typing_interval_count; i++)
                arr[i] = (double)in->typing_intervals_ms[i];
            double med = behaviour_median(arr, in->typing_interval_count);
            double mad = behaviour_mad(arr, in->typing_interval_count, med);
            free(arr);
            out->typing_interval_median_ms = med;
            out->typing_interval_mad_ms    = mad;
            out->typing_sample_count       = in->typing_interval_count;
            /* Reject implausible values (< 20 ms could be paste/IME) */
            out->f4_quality = (med < 10.0 && in->typing_interval_count > 10)
                              ? BFQ_INVALID_RANGE : base_q;
        }
    }

    /* ── F5: Focus and gaze ─────────────────────────────────────────────── */
    /* browser focus fraction is from the client but corroborated by event_chain */
    if (in->focus_fraction < 0.0f || in->focus_fraction > 1.0f) {
        out->focus_fraction = 0.0;
        out->gaze_fraction  = 0.0;
        out->gaze_confidence_pct = -1;
        out->f5_quality = BFQ_INVALID_RANGE;
    } else if (!in->camera_available) {
        out->focus_fraction      = (double)in->focus_fraction;
        out->gaze_fraction       = 0.0;
        out->gaze_confidence_pct = -1;
        out->f5_quality = BFQ_CAMERA_UNAVAILABLE;
    } else if (in->gaze_confidence_pct < 0) {
        out->focus_fraction      = (double)in->focus_fraction;
        out->gaze_fraction       = 0.0;
        out->gaze_confidence_pct = -1;
        out->f5_quality = BFQ_GAZE_UNAVAILABLE;
    } else {
        out->focus_fraction      = (double)in->focus_fraction;
        out->gaze_fraction       = (double)in->gaze_fraction;
        out->gaze_confidence_pct = in->gaze_confidence_pct;
        out->f5_quality = base_q;
    }

    /* ── F6: Score ──────────────────────────────────────────────────────── */
    if (in->question_score < 0.0f) {
        out->question_score   = -1.0;
        out->question_max_marks = in->question_max_marks;
        out->f6_quality = BFQ_NOT_AVAILABLE; /* post-grading only */
    } else {
        out->question_score    = (double)in->question_score;
        out->question_max_marks = in->question_max_marks;
        out->f6_quality = base_q;
    }

    /* ── Relay detection ─────────────────────────────────────────────────── */
    behaviour_eval_relay(out);

    /* ── Persist ─────────────────────────────────────────────────────────── */
    char line[2048];
    snprintf(line, sizeof(line),
        "FEATURE|%s|%s|%s|%d|%s"
        "|%.3f|%s|%.3f|%.6f|%s|%d|%s"
        "|%.3f|%.3f|%d|%s|%.6f|%.6f|%d|%s"
        "|%.4f|%d|%s|%d|%d"
        "|%s|%ld|%s",
        out->session_id, out->candidate_id, out->exam_id,
        out->question_id, out->feature_def_version,
        /* F1 */ out->time_to_first_input_ms, quality_str(out->f1_quality),
        /* F2 */ out->answer_elapsed_ms, out->answer_time_per_char, quality_str(out->f2_quality),
        /* F3 */ out->edit_count, quality_str(out->f3_quality),
        /* F4 */ out->typing_interval_median_ms, out->typing_interval_mad_ms,
                 out->typing_sample_count, quality_str(out->f4_quality),
        /* F5 */ out->focus_fraction, out->gaze_fraction,
                 out->gaze_confidence_pct, quality_str(out->f5_quality),
        /* F6 */ out->question_score, out->question_max_marks, quality_str(out->f6_quality),
        /* relay */ out->relay_pause_detected, out->relay_burst_detected,
        out->source_event_range, (long)out->computation_ts, out->build_id
    );

    pthread_mutex_lock(&g_store_lock);
    int persist_rc = safe_append_line(g_feature_path, line);
    pthread_mutex_unlock(&g_store_lock);

    if (persist_rc != 0) {
        fprintf(stderr, "[BehaviourEngine] PERSISTENCE_FAILED for session %s q%d\n",
                out->session_id, out->question_id);
        return -2;
    }

    /* Also append a BEHAVIOUR_FEATURE_COMPUTED event to the proctoring chain
     * so reviewers can trace feature computation as a tamper-evident audit entry */
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"question_id\":%d,\"f1_quality\":\"%s\",\"relay_pause\":%d,\"relay_burst\":%d,"
             "\"version\":\"%s\",\"ts\":%ld}",
             out->question_id, quality_str(out->f1_quality),
             out->relay_pause_detected, out->relay_burst_detected,
             BEHAVIOUR_FEATURE_DEF_VERSION, (long)out->computation_ts);
    if (event_chain_append(out->session_id, "BEHAVIOUR_ENGINE", "BEHAVIOUR_FEATURE_COMPUTED",
                           payload, "behaviour-engine", BEHAVIOUR_FEATURE_DEF_VERSION, NULL) != 0) {
        fprintf(stderr, "[BehaviourEngine] EVENT_CHAIN_PERSISTENCE_FAILED for session %s q%d\n",
                out->session_id, out->question_id);
        return -2;
    }

    return 0;
}

/* ── Practice Quiz Recording ─────────────────────────────────────────────── */

int behaviour_record_practice_quiz(const char *candidate_id,
                                    const char *practice_session_id,
                                    char *out_reason, size_t reason_max) {
    if (!candidate_id || !practice_session_id) return -1;
    if (!g_initialized && behaviour_engine_init() != 0) return -1;

    /* Verify the practice session is real (must be in session store) */
    char verified_cid[64] = {0};
    int session_valid = ctrl_candidate_token_identity(
        practice_session_id, verified_cid, sizeof(verified_cid));

    practice_quiz_eligibility_t rec;
    memset(&rec, 0, sizeof(rec));
    strncpy(rec.practice_session_id, practice_session_id, sizeof(rec.practice_session_id)-1);
    strncpy(rec.candidate_id, candidate_id, sizeof(rec.candidate_id)-1);
    rec.completed_ts = time(NULL);

    if (!session_valid) {
        rec.eligible = 0;
        strncpy(rec.exclusion_reason, "SESSION_NOT_AUTHENTICATED",
                sizeof(rec.exclusion_reason)-1);
    } else if (session_valid && strcmp(verified_cid, candidate_id) != 0) {
        rec.eligible = 0;
        strncpy(rec.exclusion_reason, "CANDIDATE_MISMATCH",
                sizeof(rec.exclusion_reason)-1);
    } else {
        uint64_t total = 0, corrupt_seq = 0;
        char reason[128] = {0};
        int chain_ok = event_chain_verify_session(
            practice_session_id, &total, &corrupt_seq, reason, sizeof(reason)) == 0;
        if (!chain_ok) {
            rec.eligible = 0;
            snprintf(rec.exclusion_reason, sizeof(rec.exclusion_reason),
                     "EVENT_CHAIN_FAIL:%s", reason);
        } else {
            rec.eligible = 1;
        }
    }

    if (out_reason && reason_max > 0) {
        strncpy(out_reason, rec.exclusion_reason[0]
                ? rec.exclusion_reason : "ELIGIBLE",
                reason_max - 1);
        out_reason[reason_max-1] = '\0';
    }

    char line[512];
    snprintf(line, sizeof(line), "PRACTICE|%s|%s|%d|%s|%ld",
             rec.candidate_id, rec.practice_session_id,
             rec.eligible, rec.exclusion_reason[0] ? rec.exclusion_reason : "NONE",
             (long)rec.completed_ts);

    pthread_mutex_lock(&g_store_lock);
    int rc = safe_append_line(g_practice_path, line);
    pthread_mutex_unlock(&g_store_lock);

    return (rc == 0 && rec.eligible) ? 0 : -1;
}

/* ── Practice count ──────────────────────────────────────────────────────── */

int behaviour_get_practice_count(const char *candidate_id) {
    if (!candidate_id || !g_initialized) return 0;

    pthread_mutex_lock(&g_store_lock);
    FILE *f = fopen(g_practice_path, "r");
    if (!f) { pthread_mutex_unlock(&g_store_lock); return 0; }

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        char type[16]={0}, cid[64]={0}, sid[EVENT_SESSION_ID_LEN]={0}, reason[128]={0};
        int eligible = 0;
        long ts = 0;
        if (sscanf(line, "%15[^|]|%63[^|]|%127[^|]|%d|%127[^|]|%ld",
                   type, cid, sid, &eligible, reason, &ts) >= 4
            && strcmp(type, "PRACTICE") == 0
            && strcmp(cid, candidate_id) == 0
            && eligible == 1) {
            count++;
        }
    }
    fclose(f);
    pthread_mutex_unlock(&g_store_lock);
    return count;
}

/* ── Baseline construction ───────────────────────────────────────────────── */

int behaviour_build_baseline(const char *candidate_id,
                             candidate_baseline_t *out_baseline) {
    if (!candidate_id || !out_baseline) return -1;
    if (!g_initialized && behaviour_engine_init() != 0) return -1;

    memset(out_baseline, 0, sizeof(*out_baseline));
    strncpy(out_baseline->candidate_id, candidate_id, sizeof(out_baseline->candidate_id)-1);
    strncpy(out_baseline->baseline_version, BEHAVIOUR_BASELINE_VERSION, sizeof(out_baseline->baseline_version)-1);
    strncpy(out_baseline->feature_def_version, BEHAVIOUR_FEATURE_DEF_VERSION, sizeof(out_baseline->feature_def_version)-1);
    out_baseline->calculation_ts = time(NULL);
    get_build_id(out_baseline->build_id, sizeof(out_baseline->build_id));

    /* First collect eligible practice session IDs for this candidate */
    pthread_mutex_lock(&g_store_lock);
    FILE *pf = fopen(g_practice_path, "r");
    if (!pf) {
        pthread_mutex_unlock(&g_store_lock);
        out_baseline->baseline_status = 1; /* BASELINE_INSUFFICIENT */
        return -1;
    }
    char practice_sessions[BEHAVIOUR_MIN_PRACTICE_QUIZZES * 2][EVENT_SESSION_ID_LEN];
    int ps_count = 0;
    char line[512];
    char ref_buf[1024] = {0};
    while (fgets(line, sizeof(line), pf) && ps_count < 64) {
        char type[16]={0}, cid[64]={0}, sid[EVENT_SESSION_ID_LEN]={0}, reason[128]={0};
        int eligible = 0; long ts = 0;
        if (sscanf(line, "%15[^|]|%63[^|]|%127[^|]|%d|%127[^|]|%ld",
                   type, cid, sid, &eligible, reason, &ts) >= 4
            && strcmp(type,"PRACTICE") == 0
            && strcmp(cid, candidate_id) == 0
            && eligible == 1
            && ps_count < (int)(sizeof(practice_sessions)/sizeof(practice_sessions[0]))) {
            copy_text(practice_sessions[ps_count], sizeof(practice_sessions[ps_count]), sid);
            ps_count++;
            if (ref_buf[0]) strncat(ref_buf, ",", sizeof(ref_buf)-strlen(ref_buf)-1);
            strncat(ref_buf, sid, sizeof(ref_buf)-strlen(ref_buf)-1);
        }
    }
    fclose(pf);
    pthread_mutex_unlock(&g_store_lock);

    out_baseline->eligible_practice_count = ps_count;
    strncpy(out_baseline->practice_session_refs, ref_buf, sizeof(out_baseline->practice_session_refs)-1);

    if (ps_count < BEHAVIOUR_MIN_PRACTICE_QUIZZES) {
        out_baseline->baseline_status = 1; /* BASELINE_INSUFFICIENT */
        fprintf(stderr, "[BehaviourEngine] BASELINE_INSUFFICIENT for %s: only %d/%d quizzes\n",
                candidate_id, ps_count, BEHAVIOUR_MIN_PRACTICE_QUIZZES);
        return -1;
    }

    /* Collect feature records for all practice sessions */
    /* Allow up to 512 practice observations per feature */
#define MAX_OBS 512
    double f1[MAX_OBS], f2[MAX_OBS], f3[MAX_OBS];
    double f4[MAX_OBS], f5f[MAX_OBS], f5g[MAX_OBS], f6[MAX_OBS];
    int nf1=0, nf2=0, nf3=0, nf4=0, nf5f=0, nf5g=0, nf6=0;

    pthread_mutex_lock(&g_store_lock);
    FILE *ff = fopen(g_feature_path, "r");
    if (!ff) { pthread_mutex_unlock(&g_store_lock); goto skip_features; }

    char fline[2048];
    while (fgets(fline, sizeof(fline), ff)) {
        char ftype[16]={0}, fsess[EVENT_SESSION_ID_LEN]={0}, fcid[64]={0}, fexam[64]={0};
        int  fqid=0;
        char fver[32]={0};
        double v_f1=0,v_f2_ms=0,v_f2pc=0;
        char q1[32]={0},q2[32]={0},q3[32]={0},q4[32]={0},q5[32]={0},q6[32]={0};
        int  v_f3=0, v_f4n=0, v_f5conf=0, v_f6max=0, rp=0, rb=0;
        double v_f4med=0, v_f4mad=0, v_f5f=0, v_f5g=0, v_f6score=0;

        /* Parse: FEATURE|sess|cand|exam|qid|ver|f1|q1|f2ms|f2pc|q2|f3|q3|f4m|f4mad|f4n|q4|f5f|f5g|f5c|q5|f6|f6max|q6|rp|rb|... */
        int r = sscanf(fline,
            "%15[^|]|%127[^|]|%63[^|]|%63[^|]|%d|%31[^|]"
            "|%lf|%31[^|]|%lf|%lf|%31[^|]|%d|%31[^|]"
            "|%lf|%lf|%d|%31[^|]|%lf|%lf|%d|%31[^|]"
            "|%lf|%d|%31[^|]|%d|%d",
            ftype, fsess, fcid, fexam, &fqid, fver,
            &v_f1, q1, &v_f2_ms, &v_f2pc, q2, &v_f3, q3,
            &v_f4med, &v_f4mad, &v_f4n, q4,
            &v_f5f, &v_f5g, &v_f5conf, q5,
            &v_f6score, &v_f6max, q6, &rp, &rb);

        if (r < 25) continue;
        if (strcmp(ftype, "FEATURE") != 0) continue;
        if (strcmp(fcid, candidate_id) != 0) continue;

        /* Check this session is an eligible practice session */
        int is_practice = 0;
        for (int pi = 0; pi < ps_count; pi++) {
            if (strcmp(practice_sessions[pi], fsess) == 0) { is_practice = 1; break; }
        }
        if (!is_practice) continue;

        if (strcmp(q1,"VALID")==0 && nf1<MAX_OBS) f1[nf1++] = v_f1;
        if (strcmp(q2,"VALID")==0 && nf2<MAX_OBS) f2[nf2++] = v_f2pc;
        if (strcmp(q3,"VALID")==0 && nf3<MAX_OBS) f3[nf3++] = (double)v_f3;
        if (strcmp(q4,"VALID")==0 && nf4<MAX_OBS) f4[nf4++] = v_f4med;
        if (strcmp(q5,"VALID")==0 || strcmp(q5,"CAMERA_UNAVAILABLE")==0) {
            if (nf5f<MAX_OBS) f5f[nf5f++] = v_f5f;
            if (v_f5conf >= 0 && nf5g<MAX_OBS) f5g[nf5g++] = v_f5g;
        }
        if (strcmp(q6,"VALID")==0 && nf6<MAX_OBS && v_f6max > 0)
            f6[nf6++] = v_f6score / v_f6max; /* normalise 0-1 */
    }
    fclose(ff);
    pthread_mutex_unlock(&g_store_lock);

skip_features:;

    /* Compute medians and MADs */
#define FILL_BASELINE(med_field, mad_field, n_field, zero_field, arr, cnt) \
    do { \
        out_baseline->n_field = (cnt); \
        if ((cnt) >= 2) { \
            out_baseline->med_field = behaviour_median((arr), (cnt)); \
            out_baseline->mad_field = behaviour_mad((arr), (cnt), out_baseline->med_field); \
            out_baseline->zero_field = (out_baseline->mad_field < 1e-9) ? 1 : 0; \
        } else { \
            out_baseline->med_field = 0.0; \
            out_baseline->mad_field = 0.0; \
            out_baseline->zero_field = 1; \
        } \
    } while(0)

    FILL_BASELINE(f1_median_ms,       f1_mad_ms,       f1_n, f1_zero_mad,          f1,  nf1);
    FILL_BASELINE(f2_median_pc,       f2_mad_pc,       f2_n, f2_zero_mad,          f2,  nf2);
    FILL_BASELINE(f3_median,          f3_mad,          f3_n, f3_zero_mad,          f3,  nf3);
    FILL_BASELINE(f4_interval_median, f4_interval_mad, f4_n, f4_zero_mad,          f4,  nf4);
    FILL_BASELINE(f5_focus_median,    f5_focus_mad,    f5_n, f5_focus_zero_mad,    f5f, nf5f);
    FILL_BASELINE(f5_gaze_median,     f5_gaze_mad,     f5_g, f5_gaze_zero_mad,     f5g, nf5g);
    FILL_BASELINE(f6_score_median,    f6_score_mad,    f6_n, f6_zero_mad,          f6,  nf6);
#undef FILL_BASELINE

    out_baseline->baseline_status = 0; /* OK */

    /* Persist baseline record */
    char bline[4096];
    snprintf(bline, sizeof(bline),
        "BASELINE|%s|%d|%.3f|%.3f|%d|%.6f|%.6f|%d|%.3f|%.3f|%d"
        "|%.3f|%.3f|%d|%.6f|%.6f|%d|%.6f|%.6f|%d|%.6f|%.6f|%d"
        "|%s|%ld|%s",
        out_baseline->candidate_id, out_baseline->eligible_practice_count,
        out_baseline->f1_median_ms,  out_baseline->f1_mad_ms,  out_baseline->f1_n,
        out_baseline->f2_median_pc,  out_baseline->f2_mad_pc,  out_baseline->f2_n,
        out_baseline->f3_median,     out_baseline->f3_mad,     out_baseline->f3_n,
        out_baseline->f4_interval_median, out_baseline->f4_interval_mad, out_baseline->f4_n,
        out_baseline->f5_focus_median, out_baseline->f5_focus_mad, out_baseline->f5_n,
        out_baseline->f5_gaze_median,  out_baseline->f5_gaze_mad,  out_baseline->f5_g,
        out_baseline->f6_score_median, out_baseline->f6_score_mad, out_baseline->f6_n,
        out_baseline->practice_session_refs,
        (long)out_baseline->calculation_ts, out_baseline->build_id);

    pthread_mutex_lock(&g_store_lock);
    safe_append_line(g_baseline_path, bline);
    pthread_mutex_unlock(&g_store_lock);

    return 0;
}

/* ── Risk Score ──────────────────────────────────────────────────────────── */

/* Robust z-score with MAD scaling.  Scale factor = 1.4826 (consistent normal).
 * If MAD == 0, feature is NOT_AVAILABLE for scoring purposes.
 * Capped at ±4 before mapping to 0-100 contribution. */
static double robust_zscore(double value, double median, double mad) {
    if (mad < 1e-9) return 0.0; /* zero-MAD policy: no score contribution */
    double z = (value - median) / (1.4826 * mad);
    if (z < -4.0) z = -4.0;
    if (z >  4.0) z =  4.0;
    return z;
}

/* Map z-score to 0-100 contribution.
 * For features where higher = more suspicious: z > 0 raises score.
 * For features where lower = more suspicious (gaze/focus): z < 0 raises score.
 * direction: +1 = high suspicious, -1 = low suspicious. */
static double zscore_to_contribution(double z, int direction) {
    /* Sigmoid-like mapping: positive z in suspicious direction → high contribution */
    double signed_z = z * (double)direction;
    /* Map [-4,+4] → [0,100]: (signed_z + 4) / 8 * 100 */
    double c = (signed_z + 4.0) / 8.0 * 100.0;
    if (c < 0.0)   c = 0.0;
    if (c > 100.0) c = 100.0;
    return c;
}

int behaviour_compute_risk_score(const char *session_id,
                                  const char *candidate_id,
                                  const char *exam_id,
                                  behaviour_risk_score_t *out_score) {
    if (!session_id || !candidate_id || !exam_id || !out_score) return -1;
    if (!g_initialized && behaviour_engine_init() != 0) return -1;

    memset(out_score, 0, sizeof(*out_score));
    strncpy(out_score->session_id,   session_id,   sizeof(out_score->session_id)-1);
    strncpy(out_score->candidate_id, candidate_id, sizeof(out_score->candidate_id)-1);
    strncpy(out_score->exam_id,      exam_id,       sizeof(out_score->exam_id)-1);
    strncpy(out_score->score_version, BEHAVIOUR_SCORE_VERSION, sizeof(out_score->score_version)-1);
    strncpy(out_score->feature_def_version, BEHAVIOUR_FEATURE_DEF_VERSION, sizeof(out_score->feature_def_version)-1);
    out_score->calculation_ts = time(NULL);
    get_build_id(out_score->build_id, sizeof(out_score->build_id));

    out_score->w_f1=g_w_f1; out_score->w_f2=g_w_f2; out_score->w_f3=g_w_f3;
    out_score->w_f4=g_w_f4; out_score->w_f5_focus=g_w_f5_focus;
    out_score->w_f5_gaze=g_w_f5_gaze; out_score->w_f6=g_w_f6;

    /* Load personal baseline */
    candidate_baseline_t baseline;
    if (behaviour_build_baseline(candidate_id, &baseline) != 0) {
        out_score->risk_score = -1;
        strncpy(out_score->confidence_status, "BASELINE_INSUFFICIENT",
                sizeof(out_score->confidence_status)-1);
        snprintf(out_score->excluded_features, sizeof(out_score->excluded_features),
                 "ALL_FEATURES:baseline_status=%d", baseline.baseline_status);
        return -1;
    }
    copy_text(out_score->baseline_version, sizeof(out_score->baseline_version),
              baseline.baseline_version);

    /* Load feature records for this exam session */
    /* Aggregate per-feature across all questions in session */
    double f1_vals[MAX_QUESTIONS], f2_vals[MAX_QUESTIONS];
    double f3_vals[MAX_QUESTIONS], f4_vals[MAX_QUESTIONS];
    double f5f_vals[MAX_QUESTIONS], f5g_vals[MAX_QUESTIONS];
    double f6_vals[MAX_QUESTIONS];
    int nf1=0,nf2=0,nf3=0,nf4=0,nf5f=0,nf5g=0,nf6=0;
    int relay_count = 0, total_questions = 0;
    char src_refs[256] = {0};

    pthread_mutex_lock(&g_store_lock);
    FILE *ff = fopen(g_feature_path, "r");
    if (!ff) { pthread_mutex_unlock(&g_store_lock); }
    else {
        char fline[2048];
        while (fgets(fline, sizeof(fline), ff)) {
            char ftype[16]={0}, fsess[EVENT_SESSION_ID_LEN]={0}, fcid[64]={0}, fexam[64]={0};
            int fqid=0;
            char fver[32]={0};
            double v_f1=0,v_f2ms=0,v_f2pc=0,v_f4med=0,v_f4mad=0;
            double v_f5f=0,v_f5g=0,v_f6score=0;
            int v_f3=0,v_f4n=0,v_f5conf=0,v_f6max=0,rp=0,rb=0;
            char q1[32]={0},q2[32]={0},q3[32]={0},q4[32]={0},q5[32]={0},q6[32]={0};

            int r = sscanf(fline,
                "%15[^|]|%127[^|]|%63[^|]|%63[^|]|%d|%31[^|]"
                "|%lf|%31[^|]|%lf|%lf|%31[^|]|%d|%31[^|]"
                "|%lf|%lf|%d|%31[^|]|%lf|%lf|%d|%31[^|]"
                "|%lf|%d|%31[^|]|%d|%d",
                ftype, fsess, fcid, fexam, &fqid, fver,
                &v_f1, q1, &v_f2ms, &v_f2pc, q2, &v_f3, q3,
                &v_f4med, &v_f4mad, &v_f4n, q4,
                &v_f5f, &v_f5g, &v_f5conf, q5,
                &v_f6score, &v_f6max, q6, &rp, &rb);

            if (r < 25) continue;
            if (strcmp(ftype,"FEATURE") != 0) continue;
            if (strcmp(fsess, session_id) != 0) continue;
            if (strcmp(fcid, candidate_id) != 0) continue;

            total_questions++;
            if (rp && rb) relay_count++;

            if (strcmp(q1,"VALID")==0 && nf1<MAX_QUESTIONS) f1_vals[nf1++]=v_f1;
            if (strcmp(q2,"VALID")==0 && nf2<MAX_QUESTIONS) f2_vals[nf2++]=v_f2pc;
            if (strcmp(q3,"VALID")==0 && nf3<MAX_QUESTIONS) f3_vals[nf3++]=(double)v_f3;
            if (strcmp(q4,"VALID")==0 && nf4<MAX_QUESTIONS) f4_vals[nf4++]=v_f4med;
            if ((strcmp(q5,"VALID")==0) && nf5f<MAX_QUESTIONS) f5f_vals[nf5f++]=v_f5f;
            if ((strcmp(q5,"VALID")==0) && v_f5conf>=0 && nf5g<MAX_QUESTIONS) f5g_vals[nf5g++]=v_f5g;
            if (strcmp(q6,"VALID")==0 && nf6<MAX_QUESTIONS && v_f6max>0) f6_vals[nf6++]=v_f6score/v_f6max;

            /* Collect source refs (abbreviated) */
            char qref[24];
            snprintf(qref, sizeof(qref), "q%d", fqid);
            if (strlen(src_refs)+strlen(qref)+2 < sizeof(src_refs)) {
                if (src_refs[0]) strncat(src_refs,",",sizeof(src_refs)-strlen(src_refs)-1);
                strncat(src_refs, qref, sizeof(src_refs)-strlen(src_refs)-1);
            }
        }
        fclose(ff);
        pthread_mutex_unlock(&g_store_lock);
    }

    copy_text(out_score->source_event_refs, sizeof(out_score->source_event_refs), src_refs);

    if (total_questions == 0) {
        out_score->risk_score = -1;
        strncpy(out_score->confidence_status, "SCORE_INSUFFICIENT_EVIDENCE",
                sizeof(out_score->confidence_status)-1);
        return -1;
    }

    /* Compute per-session medians (aggregate across questions) then z-score */
    int features_contributed = 0;
    double weighted_sum = 0.0;
    double weight_used  = 0.0;
    char excluded[256] = {0};

#define SCORE_FEATURE(vals, nvals, baseline_med, baseline_mad, zero_mad_flag, \
                      weight, direction, norm_out, contrib_flag, fname) \
    do { \
        if ((nvals) >= 1 && !(zero_mad_flag)) { \
            double sess_med = behaviour_median((vals), (nvals)); \
            double z = robust_zscore(sess_med, (baseline_med), (baseline_mad)); \
            norm_out = z; \
            contrib_flag = 1; \
            double contrib = zscore_to_contribution(z, (direction)); \
            weighted_sum += (weight) * contrib; \
            weight_used  += (weight); \
            features_contributed++; \
        } else { \
            norm_out = 0.0; contrib_flag = 0; \
            if (strlen(excluded)+strlen(fname)+2 < sizeof(excluded)) { \
                if (excluded[0]) strncat(excluded,",",sizeof(excluded)-strlen(excluded)-1); \
                strncat(excluded,(fname),sizeof(excluded)-strlen(excluded)-1); \
            } \
        } \
    } while(0)

    /* Directionality:
     *   F1 (time to first input): LOW value suspicious (+1 → low suspicious so -1)
     *      Actually BOTH very low AND very high can be suspicious.
     *      We model: extreme low (relay) is suspicious, so direction=-1 (low suspicious).
     *   F2 (time per char):   very low → suspicious → direction=-1
     *   F3 (edit count):      very low → suspicious (paste) → direction=-1
     *   F4 (typing interval): very low → suspicious → direction=-1
     *   F5 (focus):           low focus → suspicious → direction=-1
     *   F5 (gaze):            low gaze → suspicious → direction=-1
     *   F6 (score):           score alone not suspicious → weight low, direction=+1 informational
     */
    SCORE_FEATURE(f1_vals, nf1, baseline.f1_median_ms, baseline.f1_mad_ms,
                  baseline.f1_zero_mad, g_w_f1, -1,
                  out_score->f1_normalised, out_score->f1_contributed, "F1");
    SCORE_FEATURE(f2_vals, nf2, baseline.f2_median_pc, baseline.f2_mad_pc,
                  baseline.f2_zero_mad, g_w_f2, -1,
                  out_score->f2_normalised, out_score->f2_contributed, "F2");
    SCORE_FEATURE(f3_vals, nf3, baseline.f3_median, baseline.f3_mad,
                  baseline.f3_zero_mad, g_w_f3, -1,
                  out_score->f3_normalised, out_score->f3_contributed, "F3");
    SCORE_FEATURE(f4_vals, nf4, baseline.f4_interval_median, baseline.f4_interval_mad,
                  baseline.f4_zero_mad, g_w_f4, -1,
                  out_score->f4_normalised, out_score->f4_contributed, "F4");
    SCORE_FEATURE(f5f_vals, nf5f, baseline.f5_focus_median, baseline.f5_focus_mad,
                  baseline.f5_focus_zero_mad, g_w_f5_focus, -1,
                  out_score->f5_focus_norm, out_score->f5_focus_contributed, "F5_FOCUS");
    SCORE_FEATURE(f5g_vals, nf5g, baseline.f5_gaze_median, baseline.f5_gaze_mad,
                  baseline.f5_gaze_zero_mad, g_w_f5_gaze, -1,
                  out_score->f5_gaze_norm, out_score->f5_gaze_contributed, "F5_GAZE");
    SCORE_FEATURE(f6_vals, nf6, baseline.f6_score_median, baseline.f6_score_mad,
                  baseline.f6_zero_mad, g_w_f6, +1,
                  out_score->f6_normalised, out_score->f6_contributed, "F6");
#undef SCORE_FEATURE

    copy_text(out_score->excluded_features, sizeof(out_score->excluded_features), excluded);

    if (features_contributed == 0 || weight_used < 1e-6) {
        out_score->risk_score = -1;
        strncpy(out_score->confidence_status, "SCORE_INSUFFICIENT_EVIDENCE",
                sizeof(out_score->confidence_status)-1);
        return -1;
    }

    /* Rescale to 0-100 based on weight actually used */
    double raw = weighted_sum / weight_used;
    int score = (int)(raw + 0.5);
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    out_score->risk_score = score;

    /* Relay flag: ≥ 20% of questions show both pause+burst */
    out_score->relay_pattern_flagged = (total_questions > 0 &&
        relay_count * 5 >= total_questions) ? 1 : 0;

    /* Confidence status */
    if (features_contributed >= 5)
        strncpy(out_score->confidence_status, "FULL", sizeof(out_score->confidence_status)-1);
    else if (features_contributed >= 3)
        strncpy(out_score->confidence_status, "PARTIAL", sizeof(out_score->confidence_status)-1);
    else
        strncpy(out_score->confidence_status, "INSUFFICIENT_EVIDENCE", sizeof(out_score->confidence_status)-1);

    /* Persist score record */
    char sline[2048];
    snprintf(sline, sizeof(sline),
        "SCORE|%s|%s|%s|%d|%s"
        "|%.4f|%d|%.4f|%d|%.4f|%d|%.4f|%d"
        "|%.4f|%d|%.4f|%d|%.4f|%d"
        "|%d|%s|%s|%ld|%s",
        out_score->session_id, out_score->candidate_id, out_score->exam_id,
        out_score->risk_score, out_score->confidence_status,
        out_score->f1_normalised, out_score->f1_contributed,
        out_score->f2_normalised, out_score->f2_contributed,
        out_score->f3_normalised, out_score->f3_contributed,
        out_score->f4_normalised, out_score->f4_contributed,
        out_score->f5_focus_norm, out_score->f5_focus_contributed,
        out_score->f5_gaze_norm,  out_score->f5_gaze_contributed,
        out_score->f6_normalised, out_score->f6_contributed,
        out_score->relay_pattern_flagged,
        out_score->excluded_features,
        out_score->source_event_refs,
        (long)out_score->calculation_ts, out_score->build_id);

    pthread_mutex_lock(&g_store_lock);
    safe_append_line(g_score_path, sline);
    pthread_mutex_unlock(&g_store_lock);

    printf("[BehaviourEngine] RiskScore for session=%s candidate=%s: %d (%s) relay=%d\n",
           session_id, candidate_id, score, out_score->confidence_status,
           out_score->relay_pattern_flagged);

    return 0;
}

/* ── JSON export helpers ─────────────────────────────────────────────────── */

int behaviour_export_features_json(const char *session_id,
                                    char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 16) return -1;
    if (!g_initialized) { snprintf(out_buf, max_len, "{\"error\":\"NOT_INITIALIZED\"}"); return -1; }

    pthread_mutex_lock(&g_store_lock);
    FILE *f = fopen(g_feature_path, "r");
    if (!f) {
        pthread_mutex_unlock(&g_store_lock);
        snprintf(out_buf, max_len, "{\"session_id\":\"%s\",\"features\":[]}", session_id);
        return 0;
    }

    size_t off = (size_t)snprintf(out_buf, max_len,
        "{\"session_id\":\"%s\",\"features\":[", session_id);
    int first = 1;
    char line[2048];
    while (fgets(line, sizeof(line), f) && off + 512 < max_len) {
        char ftype[16]={0}, fsess[EVENT_SESSION_ID_LEN]={0}, fcid[64]={0};
        if (sscanf(line, "%15[^|]|%127[^|]|%63[^|]", ftype, fsess, fcid) < 3) continue;
        if (strcmp(ftype,"FEATURE")!=0 || strcmp(fsess,session_id)!=0) continue;
        /* Output sanitised summary — never output raw answer text */
        /* Trim newline */
        size_t ll = strlen(line);
        while (ll>0 && (line[ll-1]=='\n'||line[ll-1]=='\r')) line[--ll]='\0';
        off += (size_t)snprintf(out_buf+off, max_len-off,
            "%s{\"raw\":\"%s\"}", first?"":",", line);
        first = 0;
    }
    fclose(f);
    pthread_mutex_unlock(&g_store_lock);
    snprintf(out_buf+off, max_len-off, "]}");
    return 0;
}

int behaviour_export_score_json(const char *session_id,
                                 char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 16) return -1;
    if (!g_initialized) { snprintf(out_buf, max_len, "{\"error\":\"NOT_INITIALIZED\"}"); return -1; }

    pthread_mutex_lock(&g_store_lock);
    FILE *f = fopen(g_score_path, "r");
    if (!f) {
        pthread_mutex_unlock(&g_store_lock);
        snprintf(out_buf, max_len,
            "{\"session_id\":\"%s\",\"risk_score\":-1,"
            "\"confidence_status\":\"SCORE_INSUFFICIENT_EVIDENCE\"}", session_id);
        return 0;
    }

    char line[2048], found[2048]={0};
    while (fgets(line, sizeof(line), f)) {
        char ftype[16]={0}, fsess[EVENT_SESSION_ID_LEN]={0};
        if (sscanf(line,"%15[^|]|%127[^|]", ftype, fsess) < 2) continue;
        if (strcmp(ftype,"SCORE")==0 && strcmp(fsess,session_id)==0) {
            size_t ll = strlen(line);
            while (ll>0 && (line[ll-1]=='\n'||line[ll-1]=='\r')) line[--ll]='\0';
            copy_text(found, sizeof(found), line);
        }
    }
    fclose(f);
    pthread_mutex_unlock(&g_store_lock);

    if (!found[0]) {
        snprintf(out_buf, max_len,
            "{\"session_id\":\"%s\",\"risk_score\":-1,"
            "\"confidence_status\":\"NOT_COMPUTED\"}", session_id);
        return 0;
    }

    /* Parse key fields and emit structured JSON */
    char fsess[EVENT_SESSION_ID_LEN]={0},fcid[64]={0},fexam[64]={0},fconf[32]={0};
    char fexcl[256]={0},fsrc[256]={0},fbld[64]={0};
    int fscore=0, frelay=0; long fts=0;
    double f1n=0,f2n=0,f3n=0,f4n=0,f5fn=0,f5gn=0,f6n=0;
    int f1c=0,f2c=0,f3c=0,f4c=0,f5fc=0,f5gc=0,f6c=0;
    char dummy[16]; /* type field */
    sscanf(found,
        "%15[^|]|%127[^|]|%63[^|]|%63[^|]|%d|%31[^|]"
        "|%lf|%d|%lf|%d|%lf|%d|%lf|%d"
        "|%lf|%d|%lf|%d|%lf|%d"
        "|%d|%255[^|]|%255[^|]|%ld|%63s",
        dummy, fsess, fcid, fexam, &fscore, fconf,
        &f1n,&f1c,&f2n,&f2c,&f3n,&f3c,&f4n,&f4c,
        &f5fn,&f5fc,&f5gn,&f5gc,&f6n,&f6c,
        &frelay, fexcl, fsrc, &fts, fbld);

    snprintf(out_buf, max_len,
        "{\"session_id\":\"%s\",\"candidate_id\":\"%s\",\"exam_id\":\"%s\","
        "\"score_version\":\"%s\",\"risk_score\":%d,"
        "\"confidence_status\":\"%s\","
        "\"features\":{"
          "\"f1\":{\"normalised\":%.4f,\"contributed\":%d},"
          "\"f2\":{\"normalised\":%.4f,\"contributed\":%d},"
          "\"f3\":{\"normalised\":%.4f,\"contributed\":%d},"
          "\"f4\":{\"normalised\":%.4f,\"contributed\":%d},"
          "\"f5_focus\":{\"normalised\":%.4f,\"contributed\":%d},"
          "\"f5_gaze\":{\"normalised\":%.4f,\"contributed\":%d},"
          "\"f6\":{\"normalised\":%.4f,\"contributed\":%d}"
        "},"
        "\"relay_pattern_flagged\":%s,"
        "\"excluded_features\":\"%s\","
        "\"source_event_refs\":\"%s\","
        "\"calculation_ts\":%ld,"
        "\"build_id\":\"%s\","
        "\"interpretation\":\"BEHAVIOUR_REVIEW_SIGNAL_NOT_GUILT_DETERMINATION\"}",
        fsess, fcid, fexam, BEHAVIOUR_SCORE_VERSION, fscore, fconf,
        f1n,f1c, f2n,f2c, f3n,f3c, f4n,f4c,
        f5fn,f5fc, f5gn,f5gc, f6n,f6c,
        frelay?"true":"false", fexcl, fsrc, fts, fbld);

    return 0;
}

int behaviour_export_baseline_json(const char *candidate_id,
                                    char *out_buf, size_t max_len) {
    if (!out_buf || max_len < 16) return -1;
    if (!g_initialized) { snprintf(out_buf, max_len, "{\"error\":\"NOT_INITIALIZED\"}"); return -1; }

    /* Build or retrieve latest baseline */
    candidate_baseline_t bl;
    if (behaviour_build_baseline(candidate_id, &bl) != 0) {
        snprintf(out_buf, max_len,
            "{\"candidate_id\":\"%s\","
            "\"baseline_status\":\"BASELINE_INSUFFICIENT\","
            "\"eligible_practice_count\":%d,"
            "\"minimum_required\":%d}",
            candidate_id, bl.eligible_practice_count, BEHAVIOUR_MIN_PRACTICE_QUIZZES);
        return -1;
    }

    snprintf(out_buf, max_len,
        "{\"candidate_id\":\"%s\","
        "\"baseline_version\":\"%s\","
        "\"feature_def_version\":\"%s\","
        "\"eligible_practice_count\":%d,"
        "\"baseline_status\":\"OK\","
        "\"features\":{"
          "\"f1\":{\"median_ms\":%.3f,\"mad_ms\":%.3f,\"n\":%d},"
          "\"f2\":{\"median_pc\":%.6f,\"mad_pc\":%.6f,\"n\":%d},"
          "\"f3\":{\"median\":%.3f,\"mad\":%.3f,\"n\":%d},"
          "\"f4\":{\"median_ms\":%.3f,\"mad_ms\":%.3f,\"n\":%d},"
          "\"f5_focus\":{\"median\":%.6f,\"mad\":%.6f,\"n\":%d},"
          "\"f5_gaze\":{\"median\":%.6f,\"mad\":%.6f,\"n\":%d},"
          "\"f6\":{\"median\":%.6f,\"mad\":%.6f,\"n\":%d}"
        "},"
        "\"calculation_ts\":%ld,"
        "\"build_id\":\"%s\"}",
        bl.candidate_id, bl.baseline_version, bl.feature_def_version,
        bl.eligible_practice_count,
        bl.f1_median_ms,  bl.f1_mad_ms,  bl.f1_n,
        bl.f2_median_pc,  bl.f2_mad_pc,  bl.f2_n,
        bl.f3_median,     bl.f3_mad,     bl.f3_n,
        bl.f4_interval_median, bl.f4_interval_mad, bl.f4_n,
        bl.f5_focus_median, bl.f5_focus_mad, bl.f5_n,
        bl.f5_gaze_median,  bl.f5_gaze_mad,  bl.f5_g,
        bl.f6_score_median, bl.f6_score_mad, bl.f6_n,
        (long)bl.calculation_ts, bl.build_id);
    return 0;
}
