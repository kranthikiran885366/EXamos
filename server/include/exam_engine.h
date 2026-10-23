#ifndef EXAMOS_EXAM_ENGINE_H
#define EXAMOS_EXAM_ENGINE_H

#include <stddef.h>
#include <time.h>

#define MAX_QUESTIONS 50
#define MAX_SECTIONS 4
#define MAX_CANDIDATE_ANSWERS 128

typedef enum {
    Q_STATUS_NOT_VISITED = 0,
    Q_STATUS_NOT_ANSWERED = 1,
    Q_STATUS_ANSWERED = 2,
    Q_STATUS_MARKED_REVIEW = 3,
    Q_STATUS_ANSWERED_MARKED_REVIEW = 4
} question_status_t;

typedef struct {
    int id;
    char section[32];
    char text[512];
    char options[4][256];
    int correct_option;
    int marks;
    char question_type[16]; /* MCQ, NUMERICAL, CODING */
    char code_template[512];
} exam_question_t;

typedef struct {
    char candidate_id[64];
    char session_token[65];
    int current_question;
    int selected_options[MAX_QUESTIONS];
    char text_answers[MAX_QUESTIONS][1024];
    question_status_t status[MAX_QUESTIONS];
    time_t start_time;
    int duration_seconds;
    int is_paused;
    int is_submitted;
    int is_submitting;
    char submission_receipt_hash[65];
    char seat_number[32];
    int anomaly_count;
    char last_anomaly[64];
    time_t last_sync;
} candidate_exam_state_t;

int exam_engine_init(void);
int exam_engine_is_ready(void);
int exam_engine_load_default_nqt_questions(void);
/* Load questions from PostgreSQL for the given exam_id. Returns count or -1. */
int exam_engine_load_questions_from_db(const char *exam_id);
const char* exam_engine_get_paper_json(const char *session_token);
int exam_engine_save_answer(const char *session_token, int q_id, int selected_opt, const char *text_ans, int status);
int exam_engine_submit(const char *session_token, char *out_receipt, size_t max_receipt_len);
int exam_engine_get_submitted_context(const char *session_token,
                                      const char *receipt_hash,
                                      char *out_candidate_id, size_t candidate_id_size,
                                      char *out_questions, size_t questions_size,
                                      char *out_answers, size_t answers_size);
candidate_exam_state_t* exam_engine_get_state(const char *session_token);
const char* exam_workbench_html(const char *candidate_id, const char *session_token);

/* Center Master Hub functions */
const char* center_master_get_terminals_json(void);
int center_master_execute_command(const char *command, const char *target_candidate_id, const char *payload);
const char* center_master_get_announcements_json(void);

#endif /* EXAMOS_EXAM_ENGINE_H */
