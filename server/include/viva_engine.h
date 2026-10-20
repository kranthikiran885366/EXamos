/*
 * ExamOS Phase 5 — Viva Engine
 * server/include/viva_engine.h
 *
 * Post-exam viva: generate 2-3 follow-up questions grounded in candidate's
 * own submitted answers.  Collection of candidate viva responses.
 * Reviewer decision/override workflow.
 *
 * LLM provider integration: uses EXAMOS_LLM_ENDPOINT + EXAMOS_LLM_API_KEY
 * env vars.  Keys never logged, never returned to candidate APIs.
 * If no provider is configured, generation returns VIVA_PROVIDER_UNAVAILABLE.
 */

#ifndef EXAMOS_VIVA_ENGINE_H
#define EXAMOS_VIVA_ENGINE_H

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VIVA_PROMPT_VERSION      "p5-v1"
#define VIVA_MAX_QUESTIONS        3
#define VIVA_MIN_QUESTIONS        2

/* ── Viva Question ─────────────────────────────────────────────────────────
 * Grounded in one specific submitted answer.  Never discloses answer key.
 */
typedef struct {
    char    question_id[64];
    char    text[1024];             /* follow-up question text          */
    char    assessment_objective[128]; /* e.g. "reasoning" or "application" */
    char    rubric_reference[64];   /* server-side rubric id (reviewer only) */
    char    source_question_id[64]; /* exam question this follows from  */
    char    source_answer_version[64]; /* submission record version      */
} viva_question_t;

/* ── Viva Generation Record ─────────────────────────────────────────────── */
typedef enum {
    VIVA_STATUS_PENDING   = 0,
    VIVA_STATUS_SUCCEEDED = 1,
    VIVA_STATUS_FAILED    = 2,
    VIVA_STATUS_INVALID   = 3       /* validation failed post-generation */
} viva_generation_status_t;

typedef struct {
    char                     viva_id[64];
    char                     session_id[64];
    char                     candidate_id[64];
    char                     exam_id[64];
    char                     submission_receipt_hash[65]; /* links to immutable submission */

    viva_generation_status_t status;
    char                     status_str[32];
    char                     failure_reason[256];        /* excludes secrets */

    /* Generated questions */
    viva_question_t          questions[VIVA_MAX_QUESTIONS];
    int                      question_count;

    char                     generation_model[128];      /* actual model ID used */
    char                     prompt_version[32];
    char                     provider_endpoint_hash[65]; /* SHA-256 of endpoint URL, not URL itself */

    time_t                   generated_ts;
    char                     build_id[64];
    int                      idempotency_key_used;       /* 1 if duplicate request deduped */
} viva_generation_t;

/* ── Viva Response (candidate answer to one follow-up question) ────────── */
typedef struct {
    char    response_id[64];
    char    viva_id[64];
    char    question_id[64];
    char    candidate_id[64];
    char    session_id[64];

    char    response_text[4096];    /* candidate's viva answer          */
    time_t  displayed_ts;
    time_t  received_ts;
    int     timed_out;              /* 1 if candidate did not respond in time */
    int     skipped;

    char    submission_receipt_hash[65]; /* ensures response not confused with exam answer */
    int     immutable;              /* set to 1 after first write; reject further edits   */
} viva_response_t;

/* ── Suggested Grade (LLM suggestion, not final decision) ──────────────── */
typedef struct {
    char    suggestion_id[64];
    char    viva_id[64];
    char    question_id[64];

    double  suggested_score;         /* 0.0–max_marks */
    char    suggested_label[32];     /* e.g. "PASS" "PARTIAL" "FAIL"     */
    char    rationale[1024];         /* reviewer-facing explanation       */
    char    model_id[128];
    char    prompt_version[32];
    time_t  generated_ts;
} viva_suggestion_t;

/* ── Reviewer Decision/Override ─────────────────────────────────────────── */
typedef enum {
    REVIEW_STATE_NEEDS_REVIEW = 0,
    REVIEW_STATE_REVIEWED     = 1,
    REVIEW_STATE_NO_ACTION    = 2,
    REVIEW_STATE_OVERRIDDEN   = 3
} review_state_t;

typedef struct {
    char          decision_id[64];
    char          viva_id[64];
    char          reviewer_id[64];       /* authorized reviewer identity     */
    review_state_t state;
    char          state_str[32];

    double        final_score;
    char          reason_code[32];       /* required when overriding         */
    char          written_rationale[1024];

    time_t        decision_ts;
    char          build_id[64];

    /* Both machine suggestion and human decision preserved: */
    char          machine_suggestion_id[64];
    double        machine_suggested_score;
} reviewer_decision_t;

/* ── Audit Record ────────────────────────────────────────────────────────── */
typedef struct {
    char   audit_id[64];
    char   event_type[64];     /* e.g. REVIEWER_OVERRIDE, VIVA_GENERATED */
    char   actor_id[64];
    char   target_id[64];      /* viva_id or decision_id                  */
    char   detail[512];
    time_t ts;
    char   build_id[64];
} audit_record_t;

/* ── API ─────────────────────────────────────────────────────────────────── */

int  viva_engine_init(void);

/* Trigger post-exam viva generation for a submitted session.
 * Idempotent: if viva already generated for submission_receipt, returns
 * existing viva_id in out_viva without calling LLM again.
 * Returns 0 on success, -1 on provider error (status stored). */
int  viva_generate(const char *session_id,
                   const char *candidate_id,
                   const char *exam_id,
                   const char *submission_receipt_hash,
                   const char *question_context,
                   const char *answer_context,
                   viva_generation_t *out_viva);

/* Retrieve a viva generation record by viva_id. */
int  viva_retrieve(const char *viva_id,
                   viva_generation_t *out_viva);

/* Submit a candidate viva response (post-exam, one question at a time).
 * Validates that viva_id belongs to candidate; rejects duplicate writes.
 * Returns 0 on success, -1 on auth failure, -2 on duplicate. */
int  viva_submit_response(const char *viva_id,
                          const char *question_id,
                          const char *candidate_id,
                          const char *response_text,
                          viva_response_t *out_response);

/* Generate suggested grade for one question+response pair (LLM call).
 * Returns 0 on success, -1 on provider error. */
int  viva_suggest_grade(const char *viva_id,
                        const char *question_id,
                        const char *response_id,
                        viva_suggestion_t *out_suggestion);

/* Reviewer: apply decision / override.
 * reviewer_id validated against EXAMOS_REVIEWER_TOKEN.
 * Appends immutable audit record.  Original suggestion preserved.
 * Returns 0 on success, -1 on auth failure. */
int  viva_reviewer_decide(const char *viva_id,
                          const char *reviewer_id,
                          review_state_t state,
                          double final_score,
                          const char *reason_code,
                          const char *written_rationale,
                          reviewer_decision_t *out_decision);

/* Candidate-facing: returns questions without rubric/keys */
int  viva_export_candidate_json(const char *viva_id,
                                const char *candidate_id,
                                char *out_buf, size_t max_len);

/* Reviewer-facing: returns all evidence including suggestions */
int  viva_export_reviewer_json(const char *viva_id,
                               char *out_buf, size_t max_len);

/* Write an immutable audit event */
int  viva_append_audit(const char *event_type, const char *actor_id,
                       const char *target_id, const char *detail);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_VIVA_ENGINE_H */
