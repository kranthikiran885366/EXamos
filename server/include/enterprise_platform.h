#ifndef EXAMOS_ENTERPRISE_PLATFORM_H
#define EXAMOS_ENTERPRISE_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define MAX_INSTITUTIONS 32
#define MAX_CAMPUSES     64
#define MAX_ROOMS        128
#define MAX_USERS        64
#define MAX_EXAMS        64
#define MAX_ROSTER       512
#define MAX_DEVICES      256
#define MAX_POLICIES     128
#define MAX_INCIDENTS    128
#define MAX_SUBMISSIONS  1024
#define PLATFORM_MAX_RELEASES 32
#define PLATFORM_MAX_SESSIONS 128

/* -------------------------------------------------------------------------
 * Roles & RBAC (Module B)
 * ------------------------------------------------------------------------- */
typedef enum {
    ROLE_PLATFORM_OWNER = 1,
    ROLE_INSTITUTION_ADMIN,
    ROLE_EXAM_MANAGER,
    ROLE_SECURITY_ADMIN,
    ROLE_INVIGILATOR,
    ROLE_TECH_OPERATOR,
    ROLE_INCIDENT_INVESTIGATOR,
    ROLE_READONLY_AUDITOR,
    ROLE_SUPPORT_ENGINEER
} user_role_t;

const char *role_to_string(user_role_t role);
user_role_t string_to_role(const char *str);

typedef struct {
    char user_id[64];
    char username[64];
    char password_hash[256];
    char full_name[128];
    char email[128];
    char institution_id[64];
    user_role_t role;
    int  mfa_enabled;
    int  active;
    time_t created_at;
    time_t last_login;
} user_account_t;

typedef struct {
    char session_token[65];
    char user_id[64];
    char username[64];
    char institution_id[64];
    user_role_t role;
    time_t created_at;
    time_t expires_at;
} auth_session_t;

/* -------------------------------------------------------------------------
 * Multi-Tenancy & Hierarchy (Module P, Module A.2)
 * ------------------------------------------------------------------------- */
typedef struct {
    char institution_id[64];
    char name[128];
    char code[32];
    char contact_email[128];
    int  retention_days;
    int  active;
    time_t created_at;
} institution_t;

typedef struct {
    char campus_id[64];
    char institution_id[64];
    char name[128];
    char address[256];
} campus_t;

typedef struct {
    char room_id[64];
    char campus_id[64];
    char institution_id[64];
    char name[64];
    int  capacity;
    char supervisor[64];
} room_t;

/* -------------------------------------------------------------------------
 * Exam Lifecycle & Dynamic Exam (Module C, Module D)
 * ------------------------------------------------------------------------- */
typedef enum {
    EXAM_STATE_DRAFT = 0,
    EXAM_STATE_VALIDATED,
    EXAM_STATE_APPROVED,
    EXAM_STATE_SCHEDULED,
    EXAM_STATE_OPEN,
    EXAM_STATE_ACTIVE,
    EXAM_STATE_PAUSED,
    EXAM_STATE_SUBMISSION,
    EXAM_STATE_CLOSED,
    EXAM_STATE_RECONCILED
} exam_state_t;

const char *exam_state_to_string(exam_state_t state);
exam_state_t string_to_exam_state(const char *str);

typedef struct {
    char exam_id[64];
    char institution_id[64];
    char owner_user_id[64];
    char code[32];
    char title[128];
    char exam_url[512];
    char allowed_origins[512];
    char additional_apis[512];
    int  duration_minutes;
    time_t scheduled_start;
    time_t scheduled_end;
    char timezone[32];
    exam_state_t state;
    char approved_by[64];
    time_t approved_at;
    unsigned int policy_version;
    char policy_signature[65];
    char permitted_device_group[64];
    int  accommodations_allowed;
    int  network_offline_allowed;
    char browser_policy_json[1024];
    char incident_appeal_procedure[512];
    int  retention_days;
    time_t created_at;
    time_t updated_at;
} enterprise_exam_t;

typedef struct {
    unsigned int policy_version;
    char exam_id[64];
    char institution_id[64];
    char exam_url[512];
    char allowed_origins[512];
    char additional_apis[512];
    char permitted_device_group[64];
    int  network_offline_allowed;
    char browser_policy_json[1024];
    time_t expires_at;
    char signature[65];
    char approved_by[64];
    time_t created_at;
    char status[32]; /* ACTIVE, SUPERSEDED, ROLLBACK */
} signed_policy_t;

/* -------------------------------------------------------------------------
 * Candidates & Rosters (Module C, Module A.7)
 * ------------------------------------------------------------------------- */
typedef enum {
    CANDIDATE_ELIGIBLE = 0,
    CANDIDATE_CHECKED_IN,
    CANDIDATE_IN_EXAM,
    CANDIDATE_SUBMITTED,
    CANDIDATE_DISQUALIFIED
} candidate_status_t;

const char *candidate_status_to_string(candidate_status_t s);

typedef struct {
    char roster_id[64];
    char exam_id[64];
    char candidate_id[64];
    char full_name[128];
    char email[128];
    char pin_hash[128];
    char room_id[64];
    char assigned_seat[32];
    char assigned_device_id[64];
    candidate_status_t status;
    int  accommodation_extra_time_mins;
    time_t check_in_time;
    time_t submit_time;
} candidate_roster_entry_t;

/* -------------------------------------------------------------------------
 * Fleet & Device Management (Module G, Module H)
 * ------------------------------------------------------------------------- */
typedef enum {
    RING_CANARY = 0,
    RING_PILOT,
    RING_GENERAL
} deployment_ring_t;

const char *ring_to_string(deployment_ring_t r);

typedef struct {
    char device_id[64];
    char hostname[64];
    char institution_id[64];
    char campus_id[64];
    char room_id[64];
    char group_name[64];
    deployment_ring_t ring;
    char ownership_type[32];     /* INSTITUTION_OWNED, STUDENT_OWNED */
    int  student_owned;
    char hardware_platform[128];
    char enrollment_status[32];  /* PENDING_APPROVAL, ENROLLED, REJECTED, REVOKED, UNENROLLED, QUARANTINED, REPLACED */
    char crypto_identity_ref[128];
    char os_release[64];
    char image_digest[65];
    char uki_digest[65];
    unsigned int active_policy_version;
    time_t last_checkin;
    char attestation_status[32]; /* TRUSTED, FAILED, STALE, NOT_ATTESTED */
    time_t last_attestation_ts;
    char compliance_status[32];  /* COMPLIANT, NON_COMPLIANT, MAINTENANCE, QUARANTINED */
    char assigned_exam_id[64];
    char current_candidate_id[64];
    char session_state[32];      /* IDLE, CHECKED_IN, IN_EXAM, SUBMITTED */
    char update_status[32];      /* UP_TO_DATE, UPDATE_PENDING, UPDATING, UPDATE_FAILED */
    char incident_refs[128];
    char replacement_for_device_id[64];
    int  maintenance_mode;
    int  enrolled;
} fleet_device_record_t;

/* -------------------------------------------------------------------------
 * Security Events & Incidents (Module J, Module A.12)
 * ------------------------------------------------------------------------- */
typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} event_severity_t;

const char *severity_to_string(event_severity_t sev);

typedef struct {
    char incident_id[64];
    char title[128];
    event_severity_t severity;
    char status[32]; /* OPEN, INVESTIGATING, CONTAINED, RESOLVED */
    char assigned_to[64];
    char institution_id[64];
    char device_id[64];
    char candidate_id[64];
    char exam_id[64];
    char summary[512];
    char resolution_notes[512];
    time_t created_at;
    time_t updated_at;
} security_incident_t;

/* -------------------------------------------------------------------------
 * Durable Submissions (Module K)
 * ------------------------------------------------------------------------- */
typedef struct {
    char submission_id[64];
    char exam_id[64];
    char candidate_id[64];
    char session_id[64];
    char receipt_hash[65];
    size_t payload_bytes;
    time_t submitted_at;
    char status[32]; /* ACCEPTED, RECONCILED */
} durable_submission_t;

/* -------------------------------------------------------------------------
 * Software Releases (Module L)
 * ------------------------------------------------------------------------- */
typedef struct {
    char release_id[64];
    char version_name[64];
    char image_digest[65];
    char uki_digest[65];
    char sbom_digest[65];
    deployment_ring_t target_ring;
    char status[32]; /* DRAFT, PUBLISHED, ROLLED_BACK, REVOKED */
    char signed_by[64];
    time_t release_date;
} enterprise_release_t;

/* -------------------------------------------------------------------------
 * Platform Engine Lifecycle & Persistence
 * ------------------------------------------------------------------------- */
int enterprise_platform_init(const char *data_dir);
int enterprise_platform_save_all(void);

/* Authentication & Sessions */
int  platform_auth_login(const char *username, const char *password, const char *mfa_code, auth_session_t *out_session);
int  platform_auth_verify_token(const char *token, auth_session_t *out_session);
int  platform_auth_revoke_session(const char *token);
int  platform_user_create(const user_account_t *user, const char *actor_user_id);
int  platform_initial_owner_create(const user_account_t *user);

/* Multi-Tenancy */
int  platform_get_institutions_json(char *out_buf, size_t max_len);
int  platform_create_institution(const institution_t *inst);
int  platform_get_campuses_json(const char *inst_id, char *out_buf, size_t max_len);
int  platform_create_campus(const campus_t *campus);
int  platform_get_rooms_json(const char *campus_id, char *out_buf, size_t max_len);
int  platform_create_room(const room_t *room);

/* Dynamic Exams & Policy */
int  platform_get_exams_json(const char *inst_id, char *out_buf, size_t max_len);
int  platform_get_exam_by_id(const char *exam_id, enterprise_exam_t *out_exam);
int  platform_create_exam(const enterprise_exam_t *exam);
int  platform_validate_exam_config(const char *exam_id, char *err_msg, size_t err_len);
int  platform_approve_exam(const char *exam_id, const char *approver_user_id);
int  platform_schedule_exam(const char *exam_id, time_t start_time, time_t end_time, const char *timezone, const char *actor);
int  platform_check_readiness(const char *exam_id, const char *device_id, char *out_json, size_t max_len);
int  platform_update_exam_state(const char *exam_id, exam_state_t new_state, const char *actor);
int  platform_update_exam_url(const char *exam_id, const char *new_url, const char *allowed_origins, const char *actor);
int  platform_get_policies_json(const char *exam_id, char *out_buf, size_t max_len);
int  platform_get_active_signed_policy(const char *exam_id, signed_policy_t *out_policy);
int  platform_distribute_policy_bundle_json(const char *exam_id, const char *device_id, char *out_json, size_t max_len);
int  platform_verify_client_policy(const char *policy_json, const char *expected_exam_id, const char *device_id, char *err_msg, size_t err_len);
int  platform_rollback_policy(const char *exam_id, unsigned int target_version, const char *actor);
int  platform_reconcile_exam(const char *exam_id, char *out_report_json, size_t max_len);
int  platform_purge_expired_exams(int retention_days, char *out_summary_json, size_t max_len);

/* Roster */
int  platform_get_roster_json(const char *exam_id, char *out_buf, size_t max_len);
int  platform_add_candidate_roster(const candidate_roster_entry_t *entry);
int  platform_checkin_candidate(const char *exam_id, const char *candidate_id, const char *device_id);

/* Fleet & Device Management (Module G) */
int  platform_get_fleet_json(const char *inst_id, char *out_buf, size_t max_len);
int  platform_get_device_by_id(const char *device_id, fleet_device_record_t *out_dev);
int  platform_register_device(const fleet_device_record_t *dev);
int  platform_enroll_device(const fleet_device_record_t *dev, const char *actor);
int  platform_approve_device_enrollment(const char *device_id, const char *actor);
int  platform_reject_device_enrollment(const char *device_id, const char *reason, const char *actor);
int  platform_revoke_device(const char *device_id, const char *reason, const char *actor);
int  platform_quarantine_device(const char *device_id, const char *reason, const char *actor);
int  platform_unenroll_device(const char *device_id, int cleanup_data, const char *actor);
int  platform_replace_device(const char *old_device_id, const char *new_device_id, const char *actor);
int  platform_revoke_device_credentials(const char *device_id, const char *reason, const char *actor);
int  platform_update_device_checkin(const char *device_id, const char *os_release, const char *image_digest, unsigned int policy_version);
int  platform_update_device_attestation(const char *device_id, const char *attestation_status, const char *compliance_status);
int  platform_set_device_maintenance(const char *device_id, int in_maintenance);
int  platform_record_device_heartbeat(const char *device_id, int battery_pct, int battery_charging, int disk_free_mb, int mem_used_mb, const char *network_state, unsigned int policy_version, const char *image_digest, const char *session_state);
int  platform_record_agent_heartbeat(const char *device_id, const char *payload_json, size_t payload_length, long *out_record_id);
int  platform_bulk_device_action(const char *action_type, const char *target_group, const char *target_inst, const char *target_campus, const char *target_room, const char *param_val, int preview_only, const char *actor, char *out_json, size_t max_len);
int  platform_get_fleet_compliance_json(const char *inst_id, char *out_buf, size_t max_len);

/* Incidents & Events */
int  platform_get_incidents_json(const char *inst_id, char *out_buf, size_t max_len);
int  platform_create_incident(const security_incident_t *inc);
int  platform_update_incident_status(const char *incident_id, const char *new_status, const char *notes, const char *actor);

/* Durable Submissions */
int  platform_record_submission(const durable_submission_t *sub, const char *answers_payload);
int  platform_get_submissions_json(const char *exam_id, char *out_buf, size_t max_len);

/* Releases */
int  platform_get_releases_json(char *out_buf, size_t max_len);
int  platform_create_release(const enterprise_release_t *rel);

/* Health & Metrics */
int  platform_get_telemetry_json(char *out_buf, size_t max_len);
int  platform_get_reconciliation_json(const char *exam_id, char *out_buf, size_t max_len);

/* Dynamic URL Validation Utility (HTTPS required, syntax check, SSRF protection) */
int  platform_validate_exam_url(const char *url, char *err_msg, size_t err_len);
int  platform_validate_allowed_origins(const char *origins, char *err_msg, size_t err_len);

#endif /* EXAMOS_ENTERPRISE_PLATFORM_H */
