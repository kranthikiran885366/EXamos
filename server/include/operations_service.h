#ifndef EXAMOS_OPERATIONS_SERVICE_H
#define EXAMOS_OPERATIONS_SERVICE_H

#include <stddef.h>
#include <time.h>
#include "enterprise_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Module I — Central Operations Management
 *
 * Production-grade operations workspace integrating with enterprise_platform.
 * Provides real-time telemetry, stale detection, RBAC permissions, confirmation
 * workflows, and audit logging for all critical operations.
 *
 * Key Principles:
 * - No static arrays - uses enterprise_platform dynamic data
 * - Real timestamps and last-update times on all telemetry
 * - Distinguishes current status from stale telemetry
 * - Device disconnects/crashes do NOT auto-flag as cheating
 * - Critical actions require RBAC permissions, confirmation, audit logging
 * - All operations logged to ledger for audit trail
 * ----------------------------------------------------------------------- */

#define STALE_TELEMETRY_THRESHOLD_SEC  300  /* 5 minutes */
#define CRITICAL_ACTION_CONFIRMATION_TTL_SEC  60  /* Confirmation tokens expire in 60s */

/* -----------------------------------------------------------------------
 * Operations-specific extensions to platform structures
 * ----------------------------------------------------------------------- */

/* Real-time telemetry wrapper with staleness detection */
typedef struct {
    fleet_device_record_t device;
    time_t last_update;
    time_t server_received_at;
    int is_stale;
    char staleness_reason[128];
    double heartbeat_latency_ms;
    int consecutive_missed_heartbeats;
} device_telemetry_t;

/* Candidate session telemetry with real-time status */
typedef struct {
    candidate_roster_entry_t roster;
    char session_token[65];
    time_t session_start;
    time_t last_activity;
    time_t last_heartbeat;
    int is_active;
    int is_stale;
    char session_state[32];
    int security_events_count;  /* Count of security signals, NOT cheating flag */
    time_t last_security_event;
    char last_security_event_type[64];
} candidate_session_telemetry_t;

/* Room-level operations status */
typedef struct {
    room_t room;
    int total_candidates;
    int checked_in;
    int in_exam;
    int submitted;
    int devices_online;
    int devices_total;
    int open_incidents;
    int critical_incidents;
    time_t last_update;
} room_operations_status_t;

/* Exam operations status with lifecycle tracking */
typedef struct {
    enterprise_exam_t exam;
    exam_state_t current_state;
    time_t state_changed_at;
    char changed_by[64];
    time_t scheduled_start;
    time_t scheduled_end;
    time_t actual_start;
    time_t actual_end;
    int pause_count;
    time_t total_pause_duration;
    char pause_reason[256];
    int candidates_total;
    int candidates_checked_in;
    int candidates_submitted;
    int devices_compliant;
    int devices_failed;
    time_t last_update;
} exam_operations_status_t;

/* Network health with real-time metrics */
typedef struct {
    int server_healthy;
    time_t server_last_check;
    int devices_online;
    int devices_total;
    int heartbeat_failures_last_5min;
    double avg_heartbeat_latency_ms;
    int attestation_failures_last_5min;
    int proctoring_streams_active;
    int database_connected;
    time_t database_last_check;
    time_t last_update;
} network_health_t;

/* Critical action confirmation token */
typedef struct {
    char confirmation_token[65];
    char action_type[64];
    char target_id[64];
    char requested_by[64];
    char requested_by_role[32];
    time_t created_at;
    time_t expires_at;
    char confirmation_params[512];
    int confirmed;
    time_t confirmed_at;
    char confirmed_by[64];
} critical_action_confirmation_t;

/* Operations summary for dashboard */
typedef struct {
    int total_candidates;
    int checked_in;
    int in_exam;
    int submitted;
    int total_devices;
    int compliant_devices;
    int failed_devices;
    int online_devices;
    int stale_devices;
    int total_rooms;
    int active_invigilators;
    int open_incidents;
    int critical_incidents;
    exam_state_t exam_state;
    time_t last_update;
    int system_healthy;
} operations_summary_t;

/* -----------------------------------------------------------------------
 * Service lifecycle
 * ----------------------------------------------------------------------- */
int operations_service_init(void);
int operations_service_shutdown(void);

/* -----------------------------------------------------------------------
 * Real-time telemetry with staleness detection
 * ----------------------------------------------------------------------- */

/* Get device telemetry with staleness detection */
int operations_get_device_telemetry(const char *device_id, device_telemetry_t *out_telemetry);

/* Get all device telemetry for an institution/campus/room */
int operations_get_devices_telemetry_json(const char *institution_id, 
                                          const char *campus_id,
                                          const char *room_id,
                                          char *out_json, size_t max_len);

/* Update device telemetry (called from heartbeat endpoint) */
int operations_update_device_telemetry(const char *device_id,
                                        int battery_pct,
                                        int battery_charging,
                                        int disk_free_mb,
                                        int mem_used_mb,
                                        const char *network_state,
                                        unsigned int policy_version,
                                        const char *image_digest,
                                        const char *session_state,
                                        double latency_ms);

/* Mark device as stale if no heartbeat received */
int operations_check_device_staleness(const char *device_id, int *out_is_stale, char *out_reason);

/* Get candidate session telemetry */
int operations_get_candidate_telemetry(const char *candidate_id, 
                                        candidate_session_telemetry_t *out_telemetry);

/* Get all candidates telemetry for an exam */
int operations_get_candidates_telemetry_json(const char *exam_id, char *out_json, size_t max_len);

/* Record security event WITHOUT auto-flagging as cheating */
int operations_record_security_event(const char *candidate_id,
                                      const char *device_id,
                                      const char *event_type,
                                      const char *description,
                                      event_severity_t severity);

/* -----------------------------------------------------------------------
 * Exam lifecycle management with RBAC and confirmation
 * ----------------------------------------------------------------------- */

/* Get exam operations status */
int operations_get_exam_status(const char *exam_id, exam_operations_status_t *out_status);

/* Request critical action (requires confirmation) */
int operations_request_exam_state_change(const char *exam_id,
                                         exam_state_t new_state,
                                         const char *reason,
                                         const char *operator_id,
                                         char *out_confirmation_token);

/* Confirm and execute critical action */
int operations_confirm_exam_state_change(const char *confirmation_token,
                                         const char *operator_id,
                                         char *out_error);

/* Pause exam (critical action) */
int operations_pause_exam(const char *exam_id, const char *reason, const char *operator_id);

/* Resume exam (critical action) */
int operations_resume_exam(const char *exam_id, const char *reason, const char *operator_id);

/* Close exam (critical action) */
int operations_close_exam(const char *exam_id, const char *reason, const char *operator_id);

/* Start reconciliation (critical action) */
int operations_start_reconciliation(const char *exam_id, const char *operator_id);

/* -----------------------------------------------------------------------
 * Device management with proper failure handling (no auto-cheating flags)
 * ----------------------------------------------------------------------- */

/* Mark device as failed (requires confirmation) */
int operations_mark_device_failed(const char *device_id,
                                  const char *reason,
                                  const char *operator_id,
                                  char *out_confirmation_token);

/* Confirm device failure */
int operations_confirm_device_failure(const char *confirmation_token,
                                       const char *operator_id);

/* Replace device (critical action with confirmation) */
int operations_request_device_replacement(const char *failed_device_id,
                                          const char *replacement_device_id,
                                          const char *reason,
                                          const char *operator_id,
                                          char *out_confirmation_token);

/* Confirm device replacement */
int operations_confirm_device_replacement(const char *confirmation_token,
                                          const char *operator_id);

/* Get room operations status */
int operations_get_room_status(const char *room_id, room_operations_status_t *out_status);

/* Get all rooms status JSON */
int operations_get_rooms_status_json(const char *campus_id, char *out_json, size_t max_len);

/* -----------------------------------------------------------------------
 * Incident management with escalation
 * ----------------------------------------------------------------------- */

/* Create incident (automatically created for security events, manual for operators) */
int operations_create_incident(const security_incident_t *incident, const char *operator_id);

/* Acknowledge incident */
int operations_acknowledge_incident(const char *incident_id, const char *operator_id);

/* Resolve incident */
int operations_resolve_incident(const char *incident_id,
                                 const char *resolution_notes,
                                 const char *operator_id);

/* Escalate incident */
int operations_escalate_incident(const char *incident_id,
                                  const char *escalated_to,
                                  const char *reason,
                                  const char *operator_id);

/* Get incidents filtered by severity/status */
int operations_get_incidents_filtered_json(const char *institution_id,
                                           event_severity_t min_severity,
                                           const char *status_filter,
                                           char *out_json, size_t max_len);

/* -----------------------------------------------------------------------
 * Announcement and communication management
 * ----------------------------------------------------------------------- */

typedef struct {
    char announcement_id[64];
    char title[128];
    char content[1024];
    char target_type[32]; /* ALL, ROOM, CANDIDATE, EXAM */
    char target_id[64];
    time_t created_at;
    char created_by[64];
    time_t expires_at;
    int active;
} operations_announcement_t;

/* Create announcement */
int operations_create_announcement(const operations_announcement_t *announcement,
                                    const char *operator_id);

/* Deactivate announcement */
int operations_deactivate_announcement(const char *announcement_id, const char *operator_id);

/* Get active announcements */
int operations_get_active_announcements_json(const char *target_type,
                                              const char *target_id,
                                              char *out_json, size_t max_len);

/* -----------------------------------------------------------------------
 * Network health monitoring
 * ----------------------------------------------------------------------- */

/* Get current network health */
int operations_get_network_health(network_health_t *out_health);

/* Update network health metrics */
int operations_update_network_health(int devices_online,
                                      int heartbeat_failures,
                                      double avg_latency,
                                      int attestation_failures,
                                      int proctoring_streams);

/* -----------------------------------------------------------------------
 * Operations summary and dashboard data
 * ----------------------------------------------------------------------- */

/* Get operations summary */
int operations_get_summary(const char *exam_id, operations_summary_t *out_summary);

/* Get full dashboard data JSON (aggregates all telemetry) */
int operations_get_dashboard_json(const char *exam_id, char *out_json, size_t max_len);

/* -----------------------------------------------------------------------
 * Report generation
 * ----------------------------------------------------------------------- */

/* Generate submission report */
int operations_generate_submission_report(const char *exam_id,
                                          char *out_json, size_t max_len);

/* Generate incident report */
int operations_generate_incident_report(const char *exam_id,
                                        char *out_json, size_t max_len);

/* Generate device health report */
int operations_generate_device_health_report(const char *exam_id,
                                              char *out_json, size_t max_len);

/* Generate end-of-exam reconciliation report */
int operations_generate_reconciliation_report(const char *exam_id,
                                               char *out_json, size_t max_len);

/* -----------------------------------------------------------------------
 * RBAC permission checking for critical actions
 * ----------------------------------------------------------------------- */

/* Check if user has permission for critical action */
int operations_check_permission(const char *user_id,
                                 user_role_t required_role,
                                 const char *action_type,
                                 const char *target_id);

/* Check if user can perform action on specific resource */
int operations_check_resource_permission(const char *user_id,
                                          const char *resource_type,
                                          const char *resource_id,
                                          const char *action);

/* -----------------------------------------------------------------------
 * Audit logging for critical operations
 * ----------------------------------------------------------------------- */

/* Log critical operation to ledger */
int operations_audit_log(const char *action_type,
                         const char *operator_id,
                         const char *target_id,
                         const char *details,
                         const char *confirmation_token);

/* Get audit log for operations */
int operations_get_audit_log_json(const char *exam_id,
                                  time_t since,
                                  char *out_json, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_OPERATIONS_SERVICE_H */
