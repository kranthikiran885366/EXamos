#ifndef EXAMOS_ENVIRONMENT_ENGINE_H
#define EXAMOS_ENVIRONMENT_ENGINE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define E1_MAX_OBSERVATIONS 64
#define E1_TOKEN_LEN 64
#define E1_ID_LEN 64
#define E1_PAYLOAD_MAX 2048
#define E1_MAX_CORRELATIONS 32

/* Capability States */
typedef enum {
    E1_STATE_UNAVAILABLE = 0,
    E1_STATE_AVAILABLE = 1,
    E1_STATE_UNSUPPORTED_PLATFORM = 2,
    E1_STATE_PERMISSION_DENIED = 3,
    E1_STATE_DISABLED_BY_POLICY = 4,
    E1_STATE_INITIALIZING = 5,
    E1_STATE_DEGRADED = 6,
    E1_STATE_FAILED = 7
} e1_capability_state_t;

/* Sensor Source Types */
typedef enum {
    E1_SOURCE_WIFI = 1,
    E1_SOURCE_BLE = 2,
    E1_SOURCE_RF = 3,
    E1_SOURCE_SECOND_CAMERA = 4
} e1_source_type_t;

/* Candidate Consent Record */
typedef struct {
    char session_id[E1_ID_LEN];
    char candidate_id[E1_ID_LEN];
    int wifi_consent;
    int ble_consent;
    int rf_consent;
    int second_camera_consent;
    char consent_version[32];
    time_t consented_at;
    int active;
} e1_consent_record_t;

/* Normalized Observation Event */
typedef struct {
    char event_id[E1_ID_LEN];
    char session_id[E1_ID_LEN];
    e1_source_type_t source_type;
    char event_type[64];
    uint64_t observed_ts;
    uint64_t received_ts;
    uint32_t sequence;
    char device_ephemeral_token[E1_TOKEN_LEN];
    int signal_level_dbm;
    int count_metric;
    char payload_json[E1_PAYLOAD_MAX];
    char provenance_driver[64];
    char configuration_version[32];
} e1_observation_t;

/* Multi-Sensor Correlation Result */
typedef struct {
    char correlation_id[E1_ID_LEN];
    char session_id[E1_ID_LEN];
    char rule_id[64];
    char rule_version[32];
    uint64_t window_start_ts;
    uint64_t window_end_ts;
    char primary_event_id[E1_ID_LEN];
    char correlated_event_id[E1_ID_LEN];
    char observation_summary[256];
    int severity_level; /* 1: Info, 2: Advisory Review */
} e1_correlation_t;

/* API Initializer */
int e1_engine_init(const char *data_dir);

/* Consent Management */
int e1_record_consent(const char *session_id, const char *candidate_id,
                      int wifi, int ble, int rf, int second_cam,
                      const char *version);
int e1_is_consent_active(const char *session_id, e1_source_type_t source);
int e1_revoke_consent(const char *session_id);

/* Sensor Capability Reporting */
int e1_set_sensor_state(const char *session_id, e1_source_type_t source,
                        e1_capability_state_t state, const char *details);
e1_capability_state_t e1_get_sensor_state(const char *session_id, e1_source_type_t source);

/* Observation Ingestion */
int e1_ingest_observation(const e1_observation_t *obs);

/* Reviewer Retrieval */
int e1_export_timeline_json(const char *session_id, char *out_buf, size_t max_len);

/* Evaluation & Diagnostics */
int e1_evaluate_correlations(const char *session_id, uint64_t window_ms);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_ENVIRONMENT_ENGINE_H */
