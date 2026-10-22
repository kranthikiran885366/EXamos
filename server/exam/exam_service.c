#define _GNU_SOURCE
#include "../include/exam_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <openssl/rand.h>

#define MAX_SESSIONS 128

static exam_session_t g_sessions[MAX_SESSIONS];
static int g_session_count = 0;
static pthread_mutex_t g_session_lock = PTHREAD_MUTEX_INITIALIZER;

int exam_manager_init(void) {
    pthread_mutex_lock(&g_session_lock);
    memset(g_sessions, 0, sizeof(g_sessions));
    g_session_count = 0;
    pthread_mutex_unlock(&g_session_lock);
    return 0;
}

int exam_manager_create_session(const char *candidate_id, const char *exam_code,
                                long max_duration_seconds, exam_session_t *out_session) {
    if (!candidate_id || !candidate_id[0] || strlen(candidate_id) >= sizeof(g_sessions[0].candidate_id) ||
        !exam_code || !exam_code[0] || strlen(exam_code) >= sizeof(g_sessions[0].exam_code) ||
        max_duration_seconds <= 0 || !out_session) return -1;
    unsigned char random_id[16];
    if (RAND_bytes(random_id, sizeof(random_id)) != 1) return -1;

    pthread_mutex_lock(&g_session_lock);
    if (g_session_count >= MAX_SESSIONS) {
        pthread_mutex_unlock(&g_session_lock);
        return -1;
    }

    exam_session_t *s = &g_sessions[g_session_count++];
    memset(s, 0, sizeof(*s));
    static const char hex[] = "0123456789abcdef";
    memcpy(s->session_id, "session-", 8);
    for (size_t i = 0; i < sizeof(random_id); i++) {
        s->session_id[8 + i * 2] = hex[random_id[i] >> 4];
        s->session_id[9 + i * 2] = hex[random_id[i] & 0x0f];
    }
    s->session_id[40] = '\0';
    memcpy(s->candidate_id, candidate_id, strlen(candidate_id) + 1);
    memcpy(s->exam_code, exam_code, strlen(exam_code) + 1);
    s->state = EXAM_STATE_REGISTERED;
    s->start_time = (long)time(NULL);
    s->max_duration_seconds = max_duration_seconds;
    memcpy(out_session, s, sizeof(*out_session));

    pthread_mutex_unlock(&g_session_lock);
    return 0;
}

int exam_manager_get_session(const char *session_id, exam_session_t *out_session) {
    if (!session_id || !session_id[0] || !out_session) return -1;
    pthread_mutex_lock(&g_session_lock);
    for (int i = 0; i < g_session_count; i++) {
        if (strcmp(g_sessions[i].session_id, session_id) == 0) {
            memcpy(out_session, &g_sessions[i], sizeof(*out_session));
            pthread_mutex_unlock(&g_session_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_session_lock);
    return -1;
}

int exam_manager_update_state(const char *session_id, exam_session_state_t new_state) {
    if (!session_id || !session_id[0] || new_state < EXAM_STATE_REGISTERED ||
        new_state > EXAM_STATE_FLAGGED_TERMINATED) return -1;
    pthread_mutex_lock(&g_session_lock);
    for (int i = 0; i < g_session_count; i++) {
        if (strcmp(g_sessions[i].session_id, session_id) == 0) {
            g_sessions[i].state = new_state;
            pthread_mutex_unlock(&g_session_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_session_lock);
    return -1;
}
