#define _GNU_SOURCE
#include "../include/exam_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

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

exam_session_t* exam_manager_create_session(const char *candidate_id, const char *exam_code) {
    pthread_mutex_lock(&g_session_lock);
    if (g_session_count >= MAX_SESSIONS) {
        pthread_mutex_unlock(&g_session_lock);
        return NULL;
    }

    exam_session_t *s = &g_sessions[g_session_count++];
    snprintf(s->session_id, sizeof(s->session_id), "session-%ld-%d", (long)time(NULL), g_session_count);
    strncpy(s->candidate_id, candidate_id ? candidate_id : "ANON", sizeof(s->candidate_id) - 1);
    strncpy(s->exam_code, exam_code ? exam_code : "DEFAULT", sizeof(s->exam_code) - 1);
    s->state = EXAM_STATE_REGISTERED;
    s->start_time = (long)time(NULL);
    s->max_duration_seconds = 7200;

    pthread_mutex_unlock(&g_session_lock);
    return s;
}

exam_session_t* exam_manager_get_session(const char *session_id) {
    pthread_mutex_lock(&g_session_lock);
    for (int i = 0; i < g_session_count; i++) {
        if (strcmp(g_sessions[i].session_id, session_id) == 0) {
            pthread_mutex_unlock(&g_session_lock);
            return &g_sessions[i];
        }
    }
    pthread_mutex_unlock(&g_session_lock);
    return NULL;
}

int exam_manager_update_state(const char *session_id, exam_session_state_t new_state) {
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
