#ifndef EXAMOS_EVENT_PIPELINE_H
#define EXAMOS_EVENT_PIPELINE_H

#include <stddef.h>
#include <time.h>
#include "enterprise_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Durable Event Pipeline for Security and Operational Events
 *
 * Provides comprehensive event ingestion, classification, alerting,
 * and incident management. Separates observed facts from inferred risks
 * and unverified suspicions. Never stores passwords, private keys,
 * session secrets, or unnecessary sensitive candidate information.
 *
 * Event Types:
 * - Authentication failures
 * - Policy changes
 * - Enrollment and revocation
 * - Failed or stale attestation
 * - Unexpected network attempts
 * - Firewall denials
 * - Kiosk process termination
 * - Unexpected service or process behavior
 * - Unauthorized removable media
 * - Device clock or synchronization problems
 * - Configuration tampering
 * - Update verification failures
 * - Exam submission failures
 * - Repeated device check-in failures
 * ----------------------------------------------------------------------- */

#define EVENT_ID_MAX_LEN              64
#define CORRELATION_ID_MAX_LEN        64
#define SOURCE_MAX_LEN               64
#define DEVICE_ID_MAX_LEN            64
#define SESSION_ID_MAX_LEN           128
#define CANDIDATE_ID_MAX_LEN         64
#define EVIDENCE_REF_MAX_LEN         256
#define POLICY_VERSION_MAX_LEN       32
#define EVENT_TYPE_MAX_LEN           64
#define EVENT_DETAILS_MAX_LEN        512
#define ALERT_RULE_ID_MAX_LEN        64
#define INVESTIGATION_NOTE_MAX_LEN   2048
#define CONTAINMENT_ACTION_MAX_LEN   128

/* Event classification: observed fact vs inferred risk vs unverified suspicion */
typedef enum {
    EVENT_CLASSIFICATION_OBSERVED_FACT = 0,    /* Directly observed, verifiable */
    EVENT_CLASSIFICATION_INFERRED_RISK,        /* Derived from patterns, probabilistic */
    EVENT_CLASSIFICATION_UNVERIFIED_SUSPICION  /* Potential issue, requires investigation */
} event_classification_t;

/* Event source types */
typedef enum {
    EVENT_SOURCE_AGENT = 0,           /* Security agent on device */
    EVENT_SOURCE_PROCTORING,          /* Vision/proctoring engine */
    EVENT_SOURCE_KIOSK,               /* Kiosk launcher/supervisor */
    EVENT_SOURCE_FIREWALL,            /* Firewall service */
    EVENT_SOURCE_SERVER,              /* ExamOS server */
    EVENT_SOURCE_PLATFORM,            /* Enterprise platform */
    EVENT_SOURCE_OPERATOR,            /* Manual operator action */
    EVENT_SOURCE_AUTOMATED           /* Automated monitoring/alerting */
} event_source_type_t;

/* Specific event types */
typedef enum {
    /* Authentication & Access */
    EVENT_AUTH_FAILURE = 1000,
    EVENT_AUTH_SUCCESS,
    EVENT_AUTH_LOCKOUT,
    EVENT_SESSION_CREATED,
    EVENT_SESSION_INVALIDATED,
    EVENT_SESSION_EXPIRED,
    
    /* Policy & Configuration */
    EVENT_POLICY_CHANGE = 2000,
    EVENT_POLICY_VIOLATION,
    EVENT_CONFIG_CHANGE,
    EVENT_CONFIG_TAMPERING,
    EVENT_CONFIG_RESTORE,
    
    /* Device Lifecycle */
    EVENT_DEVICE_ENROLLMENT = 3000,
    EVENT_DEVICE_REVOCATION,
    EVENT_DEVICE_QUARANTINE,
    EVENT_DEVICE_REPLACEMENT,
    EVENT_DEVICE_CHECKIN_FAILURE,
    EVENT_DEVICE_CHECKIN_SUCCESS,
    
    /* Attestation & Trust */
    EVENT_ATTESTATION_SUCCESS = 4000,
    EVENT_ATTESTATION_FAILED,
    EVENT_ATTESTATION_STALE,
    EVENT_ATTESTATION_TIMEOUT,
    EVENT_TRUST_LOST,
    EVENT_TRUST_REGAINED,
    
    /* Network & Firewall */
    EVENT_NETWORK_ATTEMPT_UNEXPECTED = 5000,
    EVENT_FIREWALL_DENIAL,
    EVENT_FIREWALL_RULE_CHANGE,
    EVENT_DNS_FAILURE,
    EVENT_CONNECTIVITY_LOST,
    EVENT_CONNECTIVITY_RESTORED,
    
    /* Process & Service */
    EVENT_PROCESS_TERMINATION = 6000,
    EVENT_PROCESS_CRASH,
    EVENT_SERVICE_START,
    EVENT_SERVICE_STOP,
    EVENT_SERVICE_FAILURE,
    EVENT_PROCESS_BEHAVIOR_ANOMALY,
    
    /* Hardware & Media */
    EVENT_REMOVABLE_MEDIA_CONNECTED = 7000,
    EVENT_REMOVABLE_MEDIA_DISCONNECTED,
    EVENT_EXTERNAL_DISPLAY_ACTIVE,
    EVENT_EXTERNAL_DISPLAY_INACTIVE,
    EVENT_HARDWARE_ANOMALY,
    
    /* Time & Synchronization */
    EVENT_CLOCK_DRIFT = 8000,
    EVENT_CLOCK_SKEW,
    EVENT_NTP_FAILURE,
    EVENT_TIME_SYNC_FAILURE,
    
    /* Updates & Verification */
    EVENT_UPDATE_STARTED = 9000,
    EVENT_UPDATE_SUCCESS,
    EVENT_UPDATE_FAILED,
    EVENT_UPDATE_VERIFICATION_FAILED,
    EVENT_IMAGE_DIGEST_MISMATCH,
    
    /* Exam & Submission */
    EVENT_EXAM_SUBMISSION_SUCCESS = 10000,
    EVENT_EXAM_SUBMISSION_FAILED,
    EVENT_EXAM_SESSION_START,
    EVENT_EXAM_SESSION_END,
    EVENT_EXAM_TIMEOUT,
    
    /* Proctoring & Vision */
    EVENT_FACE_ABSENT = 11000,
    EVENT_MULTIPLE_FACES,
    EVENT_GAZE_DEVIATION,
    EVENT_PHONE_DETECTED,
    EVENT_OBJECT_DETECTED,
    
    /* System Events */
    EVENT_SYSTEM_STARTUP = 12000,
    EVENT_SYSTEM_SHUTDOWN,
    EVENT_RESOURCE_EXHAUSTION,
    EVENT_DISK_SPACE_LOW,
    EVENT_MEMORY_PRESSURE,
    
    /* Operator Actions */
    EVENT_OPERATOR_LOGIN = 13000,
    EVENT_OPERATOR_LOGOUT,
    EVENT_OPERATOR_ACTION,
    EVENT_INCIDENT_CREATED,
    EVENT_INCIDENT_ASSIGNED,
    EVENT_INCIDENT_RESOLVED
    
} event_type_t;

/* -----------------------------------------------------------------------
 * Core Event Record
 * ----------------------------------------------------------------------- */
typedef struct {
    char event_id[EVENT_ID_MAX_LEN];
    time_t timestamp;
    char correlation_id[CORRELATION_ID_MAX_LEN];
    char source[SOURCE_MAX_LEN];
    event_source_type_t source_type;
    char device_id[DEVICE_ID_MAX_LEN];
    char session_id[SESSION_ID_MAX_LEN];
    char candidate_id[CANDIDATE_ID_MAX_LEN];
    event_type_t event_type;
    char event_type_str[EVENT_TYPE_MAX_LEN];
    event_severity_t severity;
    event_classification_t classification;
    char policy_version[POLICY_VERSION_MAX_LEN];
    char evidence_refs[EVIDENCE_REF_MAX_LEN];
    char details[EVENT_DETAILS_MAX_LEN];
    int processed;  /* Whether this event has been processed for alerts/incidents */
    int correlated_to_incident;
    char incident_id[64];
} security_event_t;

/* -----------------------------------------------------------------------
 * Alert Rule Configuration
 * ----------------------------------------------------------------------- */
typedef struct {
    char rule_id[ALERT_RULE_ID_MAX_LEN];
    char name[128];
    char description[256];
    event_type_t trigger_event_type;
    event_severity_t min_severity;
    int deduplication_window_sec;  /* Time window for deduplication */
    int threshold_count;           /* Number of events to trigger alert */
    int threshold_window_sec;       /* Time window for threshold counting */
    int auto_create_incident;
    event_severity_t incident_severity;
    char incident_template[512];
    int enabled;
    time_t created_at;
    char created_by[64];
} alert_rule_t;

/* -----------------------------------------------------------------------
 * Alert Record (triggered by rules)
 * ----------------------------------------------------------------------- */
typedef struct {
    char alert_id[EVENT_ID_MAX_LEN];
    char rule_id[ALERT_RULE_ID_MAX_LEN];
    time_t triggered_at;
    char correlation_id[CORRELATION_ID_MAX_LEN];
    char device_id[DEVICE_ID_MAX_LEN];
    char candidate_id[CANDIDATE_ID_MAX_LEN];
    int event_count;
    char first_event_id[EVENT_ID_MAX_LEN];
    char last_event_id[EVENT_ID_MAX_LEN];
    char details[EVENT_DETAILS_MAX_LEN];
    int incident_created;
    char incident_id[64];
    int acknowledged;
    char acknowledged_by[64];
    time_t acknowledged_at;
    int resolved;
    time_t resolved_at;
} security_alert_t;

/* -----------------------------------------------------------------------
 * Investigation Note
 * ----------------------------------------------------------------------- */
typedef struct {
    char note_id[EVENT_ID_MAX_LEN];
    char incident_id[64];
    char event_id[EVENT_ID_MAX_LEN];
    char author[64];
    time_t created_at;
    char note[INVESTIGATION_NOTE_MAX_LEN];
    char evidence_refs[EVIDENCE_REF_MAX_LEN];
} investigation_note_t;

/* -----------------------------------------------------------------------
 * Containment/Recovery Action
 * ----------------------------------------------------------------------- */
typedef struct {
    char action_id[EVENT_ID_MAX_LEN];
    char incident_id[64];
    char action_type[CONTAINMENT_ACTION_MAX_LEN];
    char description[512];
    char executed_by[64];
    time_t executed_at;
    int success;
    char result[512];
    char evidence_refs[EVIDENCE_REF_MAX_LEN];
} containment_action_t;

/* -----------------------------------------------------------------------
 * Incident Timeline Entry
 * ----------------------------------------------------------------------- */
typedef struct {
    char timeline_id[EVENT_ID_MAX_LEN];
    char incident_id[64];
    time_t timestamp;
    char entry_type[32];  /* EVENT, ALERT, NOTE, ACTION, STATUS_CHANGE */
    char reference_id[EVENT_ID_MAX_LEN];
    char description[512];
    char actor[64];
} incident_timeline_t;

/* -----------------------------------------------------------------------
 * Event Pipeline Configuration
 * ----------------------------------------------------------------------- */

typedef struct {
    /* Journal settings */
    char journal_path[512];
    size_t journal_max_size_mb;
    int journal_rotation_count;
    
    /* Cache settings */
    size_t event_cache_size;
    int cache_eviction_policy;  /* 0=FIFO, 1=LRU, 2=severity-based */
    
    /* Alert settings */
    size_t max_alert_rules;
    int default_dedup_window_sec;
    
    /* Deduplication settings */
    int deduplication_enabled;
    size_t dedup_hash_table_size;
    
    /* Performance settings */
    int flush_interval_ms;
    int batch_write_size;
    int async_writes_enabled;
    
    /* Security settings */
    int validate_sensitive_data;
    int sanitize_details;
    
    /* Runtime limits */
    size_t max_event_details_len;
    size_t max_evidence_refs_len;
    int max_concurrent_searches;
} event_pipeline_config_t;

/* Load configuration from file */
int event_pipeline_load_config(const char *config_path, event_pipeline_config_t *out_config);

/* Load configuration from environment variables */
int event_pipeline_load_config_from_env(event_pipeline_config_t *out_config);

/* Apply configuration to pipeline */
int event_pipeline_apply_config(const event_pipeline_config_t *config);

/* Get current configuration */
int event_pipeline_get_config(event_pipeline_config_t *out_config);

/* Save configuration to file */
int event_pipeline_save_config(const char *config_path, const event_pipeline_config_t *config);

/* -----------------------------------------------------------------------
 * Event Pipeline Lifecycle
 * ----------------------------------------------------------------------- */
int event_pipeline_init(const char *journal_path);
int event_pipeline_init_with_config(const event_pipeline_config_t *config);
int event_pipeline_shutdown(void);

/* -----------------------------------------------------------------------
 * Event Ingestion
 * ----------------------------------------------------------------------- */

/* Ingest a security event */
int event_pipeline_ingest(const security_event_t *event);

/* Helper functions for specific event types */
int event_ingest_auth_failure(const char *device_id, const char *candidate_id,
                               const char *username, const char *reason,
                               event_severity_t severity);

int event_ingest_policy_change(const char *device_id, const char *policy_version,
                                const char *changed_by, const char *change_description,
                                event_severity_t severity);

int event_ingest_enrollment(const char *device_id, const char *institution_id,
                            const char *enrolled_by, int success,
                            event_severity_t severity);

int event_ingest_revocation(const char *device_id, const char *revoked_by,
                            const char *reason, event_severity_t severity);

int event_ingest_attestation_failed(const char *device_id, const char *session_id,
                                    const char *candidate_id, const char *failure_reason,
                                    event_severity_t severity);

int event_ingest_attestation_stale(const char *device_id, const char *session_id,
                                   const char *candidate_id, time_t last_attestation,
                                   event_severity_t severity);

int event_ingest_network_attempt(const char *device_id, const char *source_ip,
                                  const char *dest_ip, const char *protocol,
                                  const char *reason, event_severity_t severity);

int event_ingest_firewall_denial(const char *device_id, const char *source_ip,
                                  const char *dest_port, const char *protocol,
                                  const char *rule_id, event_severity_t severity);

int event_ingest_kiosk_termination(const char *device_id, const char *session_id,
                                    const char *candidate_id, const char *termination_reason,
                                    int crash, event_severity_t severity);

int event_ingest_process_anomaly(const char *device_id, const char *process_name,
                                  const char *anomaly_type, const char *details,
                                  event_severity_t severity);

int event_ingest_removable_media(const char *device_id, const char *media_label,
                                  const char *action,  /* CONNECTED or DISCONNECTED */
                                  event_severity_t severity);

int event_ingest_clock_drift(const char *device_id, long drift_seconds,
                              const char *ntp_server, event_severity_t severity);

int event_ingest_config_tampering(const char *device_id, const char *config_path,
                                   const char *tampering_type, const char *details,
                                   event_severity_t severity);

int event_ingest_update_failure(const char *device_id, const char *release_id,
                                 const char *failure_stage, const char *error_message,
                                 event_severity_t severity);

int event_ingest_submission_failure(const char *candidate_id, const char *exam_id,
                                    const char *session_id, const char *failure_reason,
                                    event_severity_t severity);

int event_ingest_checkin_failure(const char *device_id, int consecutive_failures,
                                  const char *failure_reason, event_severity_t severity);

/* -----------------------------------------------------------------------
 * Event Search and Filtering
 * ----------------------------------------------------------------------- */

/* Search events with filters */
typedef struct {
    time_t since;
    time_t until;
    event_type_t event_type;
    event_severity_t min_severity;
    event_classification_t classification;
    char device_id[DEVICE_ID_MAX_LEN];
    char candidate_id[CANDIDATE_ID_MAX_LEN];
    char correlation_id[CORRELATION_ID_MAX_LEN];
    int include_processed;
    int limit;
    int offset;
} event_filter_t;

int event_pipeline_search(const event_filter_t *filter, security_event_t *out_events,
                          int *out_count, int max_count);

/* Get events by correlation ID */
int event_pipeline_get_by_correlation(const char *correlation_id,
                                       security_event_t *out_events,
                                       int *out_count, int max_count);

/* Get events for a specific device */
int event_pipeline_get_by_device(const char *device_id, time_t since,
                                  security_event_t *out_events,
                                  int *out_count, int max_count);

/* Get events for a specific candidate */
int event_pipeline_get_by_candidate(const char *candidate_id, time_t since,
                                     security_event_t *out_events,
                                     int *out_count, int max_count);

/* Export events as JSON */
int event_pipeline_export_json(const event_filter_t *filter, char *out_json, size_t max_len);

/* -----------------------------------------------------------------------
 * Alert Rules Management
 * ----------------------------------------------------------------------- */

int event_pipeline_create_alert_rule(const alert_rule_t *rule);
int event_pipeline_update_alert_rule(const char *rule_id, const alert_rule_t *rule);
int event_pipeline_delete_alert_rule(const char *rule_id);
int event_pipeline_get_alert_rule(const char *rule_id, alert_rule_t *out_rule);
int event_pipeline_list_alert_rules(alert_rule_t *out_rules, int *out_count, int max_count);
int event_pipeline_enable_alert_rule(const char *rule_id, int enabled);

/* -----------------------------------------------------------------------
 * Alert Management
 * ----------------------------------------------------------------------- */

int event_pipeline_get_alerts(const char *rule_id, time_t since,
                              security_alert_t *out_alerts,
                              int *out_count, int max_count);

int event_pipeline_acknowledge_alert(const char *alert_id, const char *operator_id);
int event_pipeline_resolve_alert(const char *alert_id, const char *operator_id,
                                  const char *resolution_notes);

/* -----------------------------------------------------------------------
 * Severity Classification
 * ----------------------------------------------------------------------- */

/* Auto-classify event severity based on type and context */
event_severity_t event_pipeline_classify_severity(event_type_t event_type,
                                                   const char *context);

/* Manually override event severity */
int event_pipeline_override_severity(const char *event_id, event_severity_t new_severity,
                                     const char *reason, const char *operator_id);

/* -----------------------------------------------------------------------
 * Incident Creation from Events
 * ----------------------------------------------------------------------- */

/* Create incident from event or alert */
int event_pipeline_create_incident(const char *event_id, const char *alert_id,
                                   const char *title, event_severity_t severity,
                                   const char *assigned_to, const char *created_by,
                                   char *out_incident_id);

/* Auto-create incident based on alert rule */
int event_pipeline_auto_create_incident(const security_alert_t *alert,
                                         const alert_rule_t *rule,
                                         char *out_incident_id);

/* Link event to existing incident */
int event_pipeline_link_to_incident(const char *event_id, const char *incident_id,
                                     const char *operator_id);

/* -----------------------------------------------------------------------
 * Investigation Notes
 * ----------------------------------------------------------------------- */

int event_pipeline_add_investigation_note(const char *incident_id,
                                          const char *event_id,
                                          const char *author,
                                          const char *note,
                                          const char *evidence_refs,
                                          char *out_note_id);

int event_pipeline_get_investigation_notes(const char *incident_id,
                                           investigation_note_t *out_notes,
                                           int *out_count, int max_count);

/* -----------------------------------------------------------------------
 * Containment and Recovery Actions
 * ----------------------------------------------------------------------- */

int event_pipeline_execute_containment(const char *incident_id,
                                       const char *action_type,
                                       const char *description,
                                       const char *executed_by,
                                       char *out_action_id);

int event_pipeline_execute_recovery(const char *incident_id,
                                    const char *action_type,
                                    const char *description,
                                    const char *executed_by,
                                    char *out_action_id);

int event_pipeline_get_containment_actions(const char *incident_id,
                                           containment_action_t *out_actions,
                                           int *out_count, int max_count);

/* -----------------------------------------------------------------------
 * Incident Timeline
 * ----------------------------------------------------------------------- */

int event_pipeline_get_incident_timeline(const char *incident_id,
                                        incident_timeline_t *out_timeline,
                                        int *out_count, int max_count);

/* Add timeline entry for status change */
int event_pipeline_add_status_change(const char *incident_id,
                                     const char *old_status,
                                     const char *new_status,
                                     const char *changed_by);

/* -----------------------------------------------------------------------
 * Resolution and Post-Incident Review
 * ----------------------------------------------------------------------- */

/* Mark incident as resolved with review notes */
int event_pipeline_resolve_incident(const char *incident_id,
                                    const char *resolution_notes,
                                    const char *lessons_learned,
                                    const char *resolved_by);

/* Get post-incident review data */
int event_pipeline_get_incident_review(const char *incident_id, char *out_json, size_t max_len);

/* -----------------------------------------------------------------------
 * Deduplication
 * ----------------------------------------------------------------------- */

/* Check if event is duplicate within deduplication window */
int event_pipeline_is_duplicate(const security_event_t *event, int *out_is_duplicate,
                                 char *out_original_event_id);

/* Configure deduplication settings for event type */
int event_pipeline_set_deduplication_window(event_type_t event_type, int window_seconds);

/* -----------------------------------------------------------------------
 * Statistics and Reporting
 * ----------------------------------------------------------------------- */

typedef struct {
    long total_events;
    long events_by_severity[5];  /* INFO, LOW, MEDIUM, HIGH, CRITICAL */
    long events_by_classification[3];  /* OBSERVED, INFERRED, SUSPICION */
    long events_last_hour;
    long events_last_24h;
    long open_alerts;
    long unresolved_incidents;
    time_t last_event_time;
} event_pipeline_stats_t;

int event_pipeline_get_stats(event_pipeline_stats_t *out_stats);

/* Generate event summary report */
int event_pipeline_generate_summary_report(time_t since, char *out_json, size_t max_len);

/* Generate incident correlation report */
int event_pipeline_generate_correlation_report(const char *correlation_id,
                                               char *out_json, size_t max_len);

/* -----------------------------------------------------------------------
 * Utility Functions
 * ----------------------------------------------------------------------- */

const char* event_type_to_string(event_type_t type);
const char* event_source_type_to_string(event_source_type_t type);
const char* event_classification_to_string(event_classification_t classification);

/* Generate correlation ID for related events */
int event_pipeline_generate_correlation_id(char *out_correlation_id, size_t max_len);

/* Validate event for sensitive data (returns 1 if safe, 0 if contains sensitive data) */
int event_pipeline_validate_no_sensitive_data(const security_event_t *event);

/* Sanitize event details to remove sensitive information */
int event_pipeline_sanitize_details(char *details, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_EVENT_PIPELINE_H */
