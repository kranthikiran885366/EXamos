/*
 * ExamOS Phase 5 — Behaviour Engine
 * server/include/behaviour_engine.h
 *
 * Per-question behaviour feature collection, personal practice baselines,
 * robust z-score normalisation and 0-100 risk scoring.
 *
 * Architecture constraints:
 *   - All state persisted to append-only flat-files under EXAMOS_BEHAVIOUR_STORE
 *     (mirrors ledger/event_chain pattern already established in P4).
 *   - No feature value is accepted unless its source event session and candidate
 *     match the server-authoritative record (checked via candidate_session_identity).
 *   - Missing data is NEVER silently replaced with 0 or a mean — each feature
 *     carries an explicit quality code.
 *   - Risk score is evidence signal for human reviewer, not automated verdict.
 *   - Answer keys, baseline internals and raw typing sequences are never returned
 *     in candidate-facing API responses.
 */

#ifndef EXAMOS_BEHAVIOUR_ENGINE_H
#define EXAMOS_BEHAVIOUR_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Feature Definition Version ─────────────────────────────────────────── */
#define BEHAVIOUR_FEATURE_DEF_VERSION  "p5-v1"
#define BEHAVIOUR_SCORE_VERSION        "p5-v1"
#define BEHAVIOUR_BASELINE_VERSION     "p5-v1"
#define BEHAVIOUR_MIN_PRACTICE_QUIZZES  5          /* frozen gate requirement  */
#define BEHAVIOUR_MAX_FEATURES_PER_Q    6

/* ── Feature Quality Codes ───────────────────────────────────────────────── */
typedef enum {
    BFQ_VALID                    = 0,
    BFQ_INSUFFICIENT_SAMPLES     = 1,
    BFQ_NOT_AVAILABLE            = 2,
    BFQ_SOURCE_EVENT_UNVERIFIED  = 3,
    BFQ_CAMERA_UNAVAILABLE       = 4,
    BFQ_GAZE_UNAVAILABLE         = 5,
    BFQ_NETWORK_INTERRUPTION     = 6,
    BFQ_ACCESSIBILITY_ADJUSTMENT = 7,
    BFQ_INVALID_RANGE            = 8,
    BFQ_FEATURE_COMPUTATION_ERROR = 9
} behaviour_feature_quality_t;

/* ── Per-question Raw Input Event ────────────────────────────────────────── */
typedef struct {
    char    session_id[128];
    char    candidate_id[128];       /* resolved server-side, NOT trusted from client */
    char    exam_id[128];
    int     question_id;

    /* F1 — Time to first input (ms, server-sequence based) */
    int64_t question_presented_server_ts_ms;
    int64_t first_input_server_ts_ms;        /* 0 = no input yet */

    /* F2 — Answer time and question character length */
    int64_t answer_submitted_server_ts_ms;
    int     question_char_length;            /* measured server-side from template */

    /* F3 — Edit count (distinct answer-change events counted server-side) */
    int     edit_count;

    /* F4 — Typing intervals: inter-key delay samples (ms), up to 256 */
    int32_t typing_intervals_ms[256];
    int     typing_interval_count;

    /* F5 — Focus and gaze (from P4 event_chain, not from client directly) */
    float   focus_fraction;
    float   gaze_fraction;
    int     gaze_confidence_pct;    /* 0–100, -1 = NOT_AVAILABLE */
    int     camera_available;

    /* F6 — Score (server-side grading, populated post-submission) */
    float   question_score;         /* -1.0 = not yet graded */
    int     question_max_marks;

    char    source_event_id_range[128];
    char    calculation_version[32];
    char    build_id[64];
} behaviour_raw_input_t;

/* ── Per-question Feature Record ─────────────────────────────────────────── */
typedef struct {
    char    session_id[128];
    char    candidate_id[128];
    char    exam_id[128];
    int     question_id;
    char    feature_def_version[32];
    char    source_event_range[128];
    time_t  computation_ts;
    char    build_id[64];

    /* F1 */
    double  time_to_first_input_ms;
    behaviour_feature_quality_t f1_quality;

    /* F2 */
    double  answer_elapsed_ms;
    double  answer_time_per_char;
    behaviour_feature_quality_t f2_quality;

    /* F3 */
    int     edit_count;
    behaviour_feature_quality_t f3_quality;

    /* F4 */
    double  typing_interval_median_ms;
    double  typing_interval_mad_ms;
    int     typing_sample_count;
    behaviour_feature_quality_t f4_quality;

    /* F5 */
    double  focus_fraction;
    double  gaze_fraction;
    int     gaze_confidence_pct;
    behaviour_feature_quality_t f5_quality;

    /* F6 */
    double  question_score;
    int     question_max_marks;
    behaviour_feature_quality_t f6_quality;

    /* Relay pattern flags */
    int     relay_pause_detected;
    int     relay_burst_detected;
} behaviour_feature_record_t;

/* ── Practice Quiz Eligibility Record ───────────────────────────────────── */
typedef struct {
    char    practice_session_id[128];
    char    candidate_id[128];
    int     eligible;
    char    exclusion_reason[128];
    time_t  completed_ts;
} practice_quiz_eligibility_t;

/* ── Candidate Personal Baseline ─────────────────────────────────────────── */
typedef struct {
    char    candidate_id[128];
    char    baseline_version[32];
    char    feature_def_version[32];
    int     eligible_practice_count;

    double  f1_median_ms;        double f1_mad_ms;         int f1_n;
    double  f2_median_pc;        double f2_mad_pc;         int f2_n;
    double  f3_median;           double f3_mad;            int f3_n;
    double  f4_interval_median;  double f4_interval_mad;   int f4_n;
    double  f5_focus_median;     double f5_focus_mad;      int f5_n;
    double  f5_gaze_median;      double f5_gaze_mad;       int f5_g;
    double  f6_score_median;     double f6_score_mad;      int f6_n;

    int     f1_zero_mad;  int f2_zero_mad;  int f3_zero_mad;
    int     f4_zero_mad;  int f5_focus_zero_mad;
    int     f5_gaze_zero_mad; int f6_zero_mad;

    char    practice_session_refs[2048];
    time_t  calculation_ts;
    char    build_id[64];
    int     baseline_status; /* 0=OK, 1=BASELINE_INSUFFICIENT, 2=ERROR */
} candidate_baseline_t;

/* ── Risk Score Record ────────────────────────────────────────────────────── */
typedef struct {
    char    session_id[128];
    char    candidate_id[128];
    char    exam_id[128];
    char    score_version[32];

    int     risk_score;          /* 0–100; -1 = SCORE_INSUFFICIENT_EVIDENCE */
    char    confidence_status[32];

    double  f1_normalised;   int f1_contributed;
    double  f2_normalised;   int f2_contributed;
    double  f3_normalised;   int f3_contributed;
    double  f4_normalised;   int f4_contributed;
    double  f5_focus_norm;   int f5_focus_contributed;
    double  f5_gaze_norm;    int f5_gaze_contributed;
    double  f6_normalised;   int f6_contributed;

    double  w_f1, w_f2, w_f3, w_f4, w_f5_focus, w_f5_gaze, w_f6;

    char    excluded_features[256];
    int     relay_pattern_flagged;

    char    baseline_version[32];
    char    feature_def_version[32];
    char    source_event_refs[256];
    time_t  calculation_ts;
    char    build_id[64];

    int     review_state; /* 0=NEEDS_REVIEW,1=REVIEWED,2=NO_ACTION,3=OVERRIDDEN */
} behaviour_risk_score_t;

/* Relay detection thresholds (override via env) */
#define RELAY_PAUSE_THRESHOLD_MS_DEFAULT  120000
#define RELAY_BURST_THRESHOLD_MS_DEFAULT  80

/* ── Public API ──────────────────────────────────────────────────────────── */

int  behaviour_engine_init(void);

int  behaviour_ingest_question(const behaviour_raw_input_t *in,
                               behaviour_feature_record_t  *out_record);

int  behaviour_record_practice_quiz(const char *candidate_id,
                                    const char *practice_session_id,
                                    char *out_reason, size_t reason_max);

int  behaviour_get_practice_count(const char *candidate_id);

int  behaviour_build_baseline(const char *candidate_id,
                              candidate_baseline_t *out_baseline);

int  behaviour_compute_risk_score(const char *session_id,
                                  const char *candidate_id,
                                  const char *exam_id,
                                  behaviour_risk_score_t *out_score);

void behaviour_eval_relay(behaviour_feature_record_t *out_record);

int  behaviour_export_features_json(const char *session_id,
                                    char *out_buf, size_t max_len);

int  behaviour_export_score_json(const char *session_id,
                                 char *out_buf, size_t max_len);

int  behaviour_export_baseline_json(const char *candidate_id,
                                    char *out_buf, size_t max_len);

/* Exposed for unit tests */
double behaviour_median(double *arr, int n);
double behaviour_mad(double *arr, int n, double median);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_BEHAVIOUR_ENGINE_H */
