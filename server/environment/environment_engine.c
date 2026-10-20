#include "../include/environment_engine.h"
#include "../include/ledger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/sha.h>

#define MAX_SESSIONS 64
#define MAX_OBS 256
#define MAX_CORR 64

typedef struct {
    char session_id[E1_ID_LEN];
    e1_capability_state_t wifi_state;
    e1_capability_state_t ble_state;
    e1_capability_state_t rf_state;
    e1_capability_state_t second_cam_state;
} session_capabilities_t;

static pthread_mutex_t g_e1_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_data_dir[256] = "/tmp/examos_e1";
static int g_initialized = 0;

static e1_consent_record_t g_consents[MAX_SESSIONS];
static int g_consent_count = 0;

static session_capabilities_t g_caps[MAX_SESSIONS];
static int g_cap_count = 0;

static e1_observation_t g_observations[MAX_OBS];
static int g_obs_count = 0;

static e1_correlation_t g_correlations[MAX_CORR];
static int g_corr_count = 0;

static void compute_sha256_hex(const char *input, char *out_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(out_hex + (i * 2), "%02x", hash[i]);
    }
    out_hex[64] = '\0';
}

int e1_engine_init(const char *data_dir) {
    pthread_mutex_lock(&g_e1_lock);
    if (data_dir && *data_dir) {
        snprintf(g_data_dir, sizeof(g_data_dir), "%s", data_dir);
    }
    mkdir(g_data_dir, 0755);
    g_initialized = 1;
    pthread_mutex_unlock(&g_e1_lock);
    return 0;
}

int e1_record_consent(const char *session_id, const char *candidate_id,
                      int wifi, int ble, int rf, int second_cam,
                      const char *version) {
    if (!session_id || !candidate_id) return -1;
    pthread_mutex_lock(&g_e1_lock);

    /* Look for existing session */
    for (int i = 0; i < g_consent_count; i++) {
        if (strcmp(g_consents[i].session_id, session_id) == 0) {
            g_consents[i].wifi_consent = wifi;
            g_consents[i].ble_consent = ble;
            g_consents[i].rf_consent = rf;
            g_consents[i].second_camera_consent = second_cam;
            snprintf(g_consents[i].consent_version, sizeof(g_consents[i].consent_version), "%s", version ? version : "1.0");
            g_consents[i].consented_at = time(NULL);
            g_consents[i].active = 1;
            pthread_mutex_unlock(&g_e1_lock);
            return 0;
        }
    }

    if (g_consent_count >= MAX_SESSIONS) {
        pthread_mutex_unlock(&g_e1_lock);
        return -1;
    }

    e1_consent_record_t *rec = &g_consents[g_consent_count++];
    memset(rec, 0, sizeof(*rec));
    snprintf(rec->session_id, sizeof(rec->session_id), "%s", session_id);
    snprintf(rec->candidate_id, sizeof(rec->candidate_id), "%s", candidate_id);
    rec->wifi_consent = wifi;
    rec->ble_consent = ble;
    rec->rf_consent = rf;
    rec->second_camera_consent = second_cam;
    snprintf(rec->consent_version, sizeof(rec->consent_version), "%s", version ? version : "1.0");
    rec->consented_at = time(NULL);
    rec->active = 1;

    /* Append to tamper-evident ledger */
    char ledger_payload[512];
    snprintf(ledger_payload, sizeof(ledger_payload),
             "E1_CONSENT|session=%s|cand=%s|wifi=%d|ble=%d|rf=%d|cam=%d|ver=%s",
             session_id, candidate_id, wifi, ble, rf, second_cam, rec->consent_version);
    ledger_append_event("E1_CONSENT_REGISTERED", session_id, ledger_payload, NULL);

    pthread_mutex_unlock(&g_e1_lock);
    return 0;
}

int e1_is_consent_active(const char *session_id, e1_source_type_t source) {
    if (!session_id) return 0;
    pthread_mutex_lock(&g_e1_lock);
    for (int i = 0; i < g_consent_count; i++) {
        if (strcmp(g_consents[i].session_id, session_id) == 0 && g_consents[i].active) {
            int ok = 0;
            switch (source) {
                case E1_SOURCE_WIFI: ok = g_consents[i].wifi_consent; break;
                case E1_SOURCE_BLE: ok = g_consents[i].ble_consent; break;
                case E1_SOURCE_RF: ok = g_consents[i].rf_consent; break;
                case E1_SOURCE_SECOND_CAMERA: ok = g_consents[i].second_camera_consent; break;
            }
            pthread_mutex_unlock(&g_e1_lock);
            return ok;
        }
    }
    pthread_mutex_unlock(&g_e1_lock);
    return 0;
}

int e1_revoke_consent(const char *session_id) {
    if (!session_id) return -1;
    pthread_mutex_lock(&g_e1_lock);
    for (int i = 0; i < g_consent_count; i++) {
        if (strcmp(g_consents[i].session_id, session_id) == 0) {
            g_consents[i].active = 0;
            ledger_append_event("E1_CONSENT_REVOKED", session_id, "Consent revoked by session termination", NULL);
            pthread_mutex_unlock(&g_e1_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_e1_lock);
    return -1;
}

int e1_set_sensor_state(const char *session_id, e1_source_type_t source,
                        e1_capability_state_t state, const char *details) {
    if (!session_id) return -1;
    pthread_mutex_lock(&g_e1_lock);
    session_capabilities_t *cap = NULL;
    for (int i = 0; i < g_cap_count; i++) {
        if (strcmp(g_caps[i].session_id, session_id) == 0) {
            cap = &g_caps[i];
            break;
        }
    }
    if (!cap && g_cap_count < MAX_SESSIONS) {
        cap = &g_caps[g_cap_count++];
        memset(cap, 0, sizeof(*cap));
        snprintf(cap->session_id, sizeof(cap->session_id), "%s", session_id);
    }
    if (cap) {
        switch (source) {
            case E1_SOURCE_WIFI: cap->wifi_state = state; break;
            case E1_SOURCE_BLE: cap->ble_state = state; break;
            case E1_SOURCE_RF: cap->rf_state = state; break;
            case E1_SOURCE_SECOND_CAMERA: cap->second_cam_state = state; break;
        }
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "E1_SENSOR_STATE|sess=%s|src=%d|st=%d|desc=%s",
                 session_id, (int)source, (int)state, details ? details : "");
        ledger_append_event("E1_CAPABILITY_UPDATE", session_id, log_msg, NULL);
    }
    pthread_mutex_unlock(&g_e1_lock);
    return 0;
}

e1_capability_state_t e1_get_sensor_state(const char *session_id, e1_source_type_t source) {
    if (!session_id) return E1_STATE_UNAVAILABLE;
    pthread_mutex_lock(&g_e1_lock);
    for (int i = 0; i < g_cap_count; i++) {
        if (strcmp(g_caps[i].session_id, session_id) == 0) {
            e1_capability_state_t st = E1_STATE_UNAVAILABLE;
            switch (source) {
                case E1_SOURCE_WIFI: st = g_caps[i].wifi_state; break;
                case E1_SOURCE_BLE: st = g_caps[i].ble_state; break;
                case E1_SOURCE_RF: st = g_caps[i].rf_state; break;
                case E1_SOURCE_SECOND_CAMERA: st = g_caps[i].second_cam_state; break;
            }
            pthread_mutex_unlock(&g_e1_lock);
            return st;
        }
    }
    pthread_mutex_unlock(&g_e1_lock);
    return E1_STATE_UNAVAILABLE;
}

int e1_ingest_observation(const e1_observation_t *obs) {
    if (!obs || !obs->session_id[0]) return -1;

    /* Fail closed if consent is not actively registered */
    if (!e1_is_consent_active(obs->session_id, obs->source_type)) {
        return -2; /* Unconsented */
    }

    pthread_mutex_lock(&g_e1_lock);
    if (g_obs_count >= MAX_OBS) {
        /* Shift buffer to keep most recent observations */
        memmove(&g_observations[0], &g_observations[1], sizeof(e1_observation_t) * (MAX_OBS - 1));
        g_obs_count = MAX_OBS - 1;
    }

    e1_observation_t *dst = &g_observations[g_obs_count++];
    memcpy(dst, obs, sizeof(e1_observation_t));
    if (!dst->received_ts) dst->received_ts = (uint64_t)time(NULL);

    /* Generate event ID if missing */
    if (!dst->event_id[0]) {
        char seed[256];
        snprintf(seed, sizeof(seed), "%s:%lu:%u:%d",
                 obs->session_id, (unsigned long)dst->observed_ts, dst->sequence, (int)dst->source_type);
        compute_sha256_hex(seed, dst->event_id);
    }

    /* Record in ledger */
    char l_buf[512];
    snprintf(l_buf, sizeof(l_buf), "E1_OBSERVATION|id=%s|sess=%s|src=%d|type=%s|tok=%.16s|sig=%d",
             dst->event_id, dst->session_id, (int)dst->source_type, dst->event_type,
             dst->device_ephemeral_token, dst->signal_level_dbm);
    ledger_append_event("E1_OBSERVATION_INGESTED", dst->session_id, l_buf, NULL);

    pthread_mutex_unlock(&g_e1_lock);
    return 0;
}

int e1_evaluate_correlations(const char *session_id, uint64_t window_ms) {
    if (!session_id) return -1;
    pthread_mutex_lock(&g_e1_lock);

    /* Temporal correlation: inspect overlapping BLE and Room Context observations */
    for (int i = 0; i < g_obs_count; i++) {
        if (strcmp(g_observations[i].session_id, session_id) != 0) continue;
        if (g_observations[i].source_type != E1_SOURCE_BLE) continue;

        for (int j = 0; j < g_obs_count; j++) {
            if (i == j) continue;
            if (strcmp(g_observations[j].session_id, session_id) != 0) continue;
            if (g_observations[j].source_type != E1_SOURCE_SECOND_CAMERA) continue;

            int64_t diff = (int64_t)g_observations[i].observed_ts - (int64_t)g_observations[j].observed_ts;
            if (diff < 0) diff = -diff;

            if ((uint64_t)diff <= window_ms && g_corr_count < MAX_CORR) {
                e1_correlation_t *corr = &g_correlations[g_corr_count++];
                memset(corr, 0, sizeof(*corr));

                char id_seed[256];
                snprintf(id_seed, sizeof(id_seed), "%s:%s:%lu",
                         g_observations[i].event_id, g_observations[j].event_id, (unsigned long)time(NULL));
                compute_sha256_hex(id_seed, corr->correlation_id);

                snprintf(corr->session_id, sizeof(corr->session_id), "%s", session_id);
                snprintf(corr->rule_id, sizeof(corr->rule_id), "CORR-BLE-ROOM-OCCLUSION");
                snprintf(corr->rule_version, sizeof(corr->rule_version), "1.0");
                corr->window_start_ts = g_observations[j].observed_ts;
                corr->window_end_ts = g_observations[i].observed_ts;
                snprintf(corr->primary_event_id, sizeof(corr->primary_event_id), "%s", g_observations[i].event_id);
                snprintf(corr->correlated_event_id, sizeof(corr->correlated_event_id), "%s", g_observations[j].event_id);
                snprintf(corr->observation_summary, sizeof(corr->observation_summary),
                         "NEW_BLE_SIGNAL_OVERLAPPED_WITH_ROOM_VIEW_CHANGE");
                corr->severity_level = 2;

                char c_buf[512];
                snprintf(c_buf, sizeof(c_buf), "E1_CORRELATION|id=%s|sess=%s|rule=%s|e1=%s|e2=%s",
                         corr->correlation_id, session_id, corr->rule_id,
                         corr->primary_event_id, corr->correlated_event_id);
                ledger_append_event("E1_CORRELATION_DETECTED", session_id, c_buf, NULL);
            }
        }
    }

    pthread_mutex_unlock(&g_e1_lock);
    return 0;
}

int e1_export_timeline_json(const char *session_id, char *out_buf, size_t max_len) {
    if (!session_id || !out_buf || max_len == 0) return -1;
    pthread_mutex_lock(&g_e1_lock);

    size_t offset = 0;
    offset += snprintf(out_buf + offset, max_len - offset,
                       "{\"session_id\":\"%s\",\"observations\":[", session_id);

    int first_obs = 1;
    for (int i = 0; i < g_obs_count && offset < max_len - 512; i++) {
        if (strcmp(g_observations[i].session_id, session_id) != 0) continue;
        offset += snprintf(out_buf + offset, max_len - offset,
                           "%s{\"event_id\":\"%s\",\"source_type\":%d,\"event_type\":\"%s\","
                           "\"observed_ts\":%lu,\"signal_level\":%d,\"device_token\":\"%s\"}",
                           first_obs ? "" : ",",
                           g_observations[i].event_id,
                           (int)g_observations[i].source_type,
                           g_observations[i].event_type,
                           (unsigned long)g_observations[i].observed_ts,
                           g_observations[i].signal_level_dbm,
                           g_observations[i].device_ephemeral_token);
        first_obs = 0;
    }

    offset += snprintf(out_buf + offset, max_len - offset, "],\"correlations\":[");

    int first_corr = 1;
    for (int i = 0; i < g_corr_count && offset < max_len - 256; i++) {
        if (strcmp(g_correlations[i].session_id, session_id) != 0) continue;
        offset += snprintf(out_buf + offset, max_len - offset,
                           "%s{\"correlation_id\":\"%s\",\"rule\":\"%s\","
                           "\"summary\":\"%s\",\"severity\":%d}",
                           first_corr ? "" : ",",
                           g_correlations[i].correlation_id,
                           g_correlations[i].rule_id,
                           g_correlations[i].observation_summary,
                           g_correlations[i].severity_level);
        first_corr = 0;
    }

    offset += snprintf(out_buf + offset, max_len - offset, "]}");
    pthread_mutex_unlock(&g_e1_lock);
    return 0;
}
