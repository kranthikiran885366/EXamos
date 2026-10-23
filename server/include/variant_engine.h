/*
 * ExamOS Phase 5 — Variant Engine
 * server/include/variant_engine.h
 *
 * Server-side individualized question variant generation.
 * Seed derived from HMAC-SHA256(candidate_id || exam_id || template_id || version).
 * Answer keys stored server-side only, never exposed to candidate routes.
 */

#ifndef EXAMOS_VARIANT_ENGINE_H
#define EXAMOS_VARIANT_ENGINE_H

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VARIANT_GENERATOR_VERSION  "p5-v1"
#define VARIANT_MAX_PARAMS          16
#define VARIANT_PARAM_NAME_LEN      32
#define VARIANT_PARAM_VALUE_LEN     64
#define VARIANT_FINGERPRINT_LEN     65  /* SHA-256 hex */

/* ── Question Template ────────────────────────────────────────────────────── */
typedef struct {
    char    template_id[64];
    char    template_version[16];
    char    question_type[16];      /* MCQ, NUMERICAL, etc. */
    char    wording_template[2048]; /* uses {A}, {B}, {C} placeholders */
    char    watermark_footer[256];  /* {CANDIDATE_REF} placeholder       */

    /* Parameter constraints: min, max, step (integer or float) */
    struct {
        char   name[VARIANT_PARAM_NAME_LEN];
        double min_val;
        double max_val;
        double step;
        int    is_integer;
    } params[VARIANT_MAX_PARAMS];
    int param_count;

    /* Server-side solution formula tag (resolved in variant_engine.c) */
    char    solution_formula_id[64];
    char    rubric_version[32];
    int     correct_option_index;   /* -1 for non-MCQ */
    double  difficulty_min;
    double  difficulty_max;
} question_template_t;

/* ── Question Variant ────────────────────────────────────────────────────── */
typedef struct {
    char    variant_id[64];
    char    candidate_id[64];      /* server-authoritative reference   */
    char    exam_id[64];
    char    template_id[64];
    char    template_version[16];
    char    generator_version[32];

    /* Generated parameter values (parallel to template.params[]) */
    struct {
        char   name[VARIANT_PARAM_NAME_LEN];
        double value;
        char   value_str[VARIANT_PARAM_VALUE_LEN];
    } params[VARIANT_MAX_PARAMS];
    int     param_count;

    /* Rendered wording (candidate-visible, no answer) */
    char    rendered_question[2048];

    /* Visible watermark footer rendered with candidate reference */
    char    watermark_text[256];

    /* Server-side answer key — NEVER returned to candidate routes */
    double  answer_numeric;
    int     answer_option_index;   /* MCQ: 0-based, -1 if non-MCQ */
    char    answer_explanation[512]; /* reviewer-only */

    char    rubric_version[32];
    char    fingerprint[VARIANT_FINGERPRINT_LEN]; /* SHA-256 of param set */

    time_t  created_ts;
    int     constraint_validated;  /* 1 if all constraints passed */
    char    generation_status[32]; /* GENERATED / VARIANT_GENERATION_FAILED */
} question_variant_t;

/* ── Watermark Record ─────────────────────────────────────────────────────── */
typedef struct {
    char    candidate_ref[64];    /* hashed or approved display reference */
    char    exam_id[64];
    char    variant_id[64];
    char    watermark_text[256];
    char    generator_version[32];
    time_t  generated_ts;
} watermark_record_t;

/* ── API ──────────────────────────────────────────────────────────────────── */

int  variant_engine_init(void);

/* Copy a provisioned built-in template into caller storage. A NULL or empty
 * template_id selects the first built-in template. Returns 0 on success. */
int  variant_get_template(const char *template_id, question_template_t *out_template);

/* Generate a variant for candidate + exam + template.
 * Seed = HMAC-SHA256(EXAMOS_VARIANT_SECRET, canonical_id_string).
 * Returns 0 on success, -1 if constraint validation fails. */
int  variant_generate(const char *candidate_id,
                      const char *exam_id,
                      const question_template_t *tmpl,
                      question_variant_t *out_variant);

/* Retrieve a previously generated variant by variant_id (from store). */
int  variant_retrieve(const char *variant_id,
                      question_variant_t *out_variant);

/* Grade a candidate's submitted answer against the server-stored variant.
 * Returns score (0.0–max_marks).  answer_key never leaves this function. */
double variant_grade_answer(const char *variant_id,
                             int submitted_option,
                             double submitted_numeric,
                             const char *rubric_version,
                             char *out_grade_detail, size_t detail_max);

/* Candidate-facing JSON: returns rendered question + watermark, NO answer key. */
int  variant_export_candidate_json(const char *variant_id,
                                   char *out_buf, size_t max_len);

/* Reviewer-facing JSON: includes answer key under reviewer auth. */
int  variant_export_reviewer_json(const char *variant_id,
                                  char *out_buf, size_t max_len);

/* Trace a watermark reference back to candidate (authorized reviewer only).
 * Returns 0 if traceable, -1 if insufficient or no mark. */
int  variant_trace_watermark(const char *watermark_text_fragment,
                             char *out_candidate_ref, size_t max_len,
                             char *out_variant_id,    size_t vid_max);

/* Diversity test helper: compare numeric params between two variants.
 * Returns fraction of positions that differ (0.0–1.0). */
double variant_diversity_fraction(const question_variant_t *a,
                                  const question_variant_t *b);

/* Persist watermark record to EXAMOS_WATERMARK_STORE. */
int  variant_persist_watermark(const watermark_record_t *rec);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_VARIANT_ENGINE_H */
