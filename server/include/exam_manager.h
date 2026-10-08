#ifndef EXAMOS_EXAM_MANAGER_H
#define EXAMOS_EXAM_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EXAM_STATE_REGISTERED = 0,
    EXAM_STATE_ATTESTED,
    EXAM_STATE_IN_PROGRESS,
    EXAM_STATE_SUBMITTED,
    EXAM_STATE_FLAGGED_TERMINATED
} exam_session_state_t;

typedef struct {
    char session_id[64];
    char candidate_id[64];
    char exam_code[32];
    exam_session_state_t state;
    long start_time;
    long max_duration_seconds;
} exam_session_t;

int exam_manager_init(void);
exam_session_t* exam_manager_create_session(const char *candidate_id, const char *exam_code);
exam_session_t* exam_manager_get_session(const char *session_id);
int exam_manager_update_state(const char *session_id, exam_session_state_t new_state);

#ifdef __cplusplus
}
#endif

#endif // EXAMOS_EXAM_MANAGER_H
