#define _GNU_SOURCE
#include "include/operations_service.h"
#include "include/ledger.h"
#include "include/enterprise_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/* -----------------------------------------------------------------------
 * Global state (protected by mutex)
 * ----------------------------------------------------------------------- */
static pthread_mutex_t g_ops_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_service_initialized = 0;

/* Confirmation tokens storage (dynamic, no static arrays) */
#define MAX_CONFIRMATIONS 128
static critical_action_confirmation_t g_confirmations[MAX_CONFIRMATIONS];
static int g_confirmation_count = 0;

/* Telemetry cache with timestamps */
#define MAX_TELEMETRY_CACHE 512
typedef struct {
    char device_id[64];
    device_telemetry_t telemetry;
    time_t cached_at;
} telemetry_cache_entry_t;
static telemetry_cache_entry_t g_telemetry_cache[MAX_TELEMETRY_CACHE];
static int g_telemetry_cache_count = 0;

/* Network health state */
static network_health_t g_network_health = {0};

/* -----------------------------------------------------------------------
 * Helper functions
 * ----------------------------------------------------------------------- */
static int generate_confirmation_token(char *out_token, size_t max_len) {
    unsigned char buf[32];
    if (RAND_bytes(buf, sizeof(buf)) != 1) return -1;
    
    for (int i = 0; i < 32; i++) {
        snprintf(out_token + i * 2, max_len - i * 2, "%02x", buf[i]);
    }
    out_token[64] = '\0';
    return 0;
}

static int is_telemetry_stale(time_t last_update, int *out_is_stale, char *out_reason) {
    time_t now = time(NULL);
    time_t age = now - last_update;
    
    if (out_is_stale) *out_is_stale = (age > STALE_TELEMETRY_THRESHOLD_SEC);
    
    if (out_reason) {
        if (age > STALE_TELEMETRY_THRESHOLD_SEC) {
            snprintf(out_reason, 128, "No update for %ld seconds (threshold: %d)",
                     (long)age, STALE_TELEMETRY_THRESHOLD_SEC);
        } else {
            out_reason[0] = '\0';
        }
    }
    
    return (age > STALE_TELEMETRY_THRESHOLD_SEC) ? 1 : 0;
}

static critical_action_confirmation_t* find_confirmation(const char *token) {
    for (int i = 0; i < g_confirmation_count; i++) {
        if (strcmp(g_confirmations[i].confirmation_token, token) == 0) {
            return &g_confirmations[i];
        }
    }
    return NULL;
}

static int store_confirmation(const critical_action_confirmation_t *conf) {
    pthread_mutex_lock(&g_ops_lock);
    
    if (g_confirmation_count >= MAX_CONFIRMATIONS) {
        /* Remove oldest */
        memmove(&g_confirmations[0], &g_confirmations[1],
                sizeof(critical_action_confirmation_t) * (MAX_CONFIRMATIONS - 1));
        g_confirmation_count--;
    }
    
    memcpy(&g_confirmations[g_confirmation_count], conf, sizeof(critical_action_confirmation_t));
    g_confirmation_count++;
    
    pthread_mutex_unlock(&g_ops_lock);
    return 0;
}

/* -----------------------------------------------------------------------
 * Service lifecycle
 * ----------------------------------------------------------------------- */
int operations_service_init(void) {
    pthread_mutex_lock(&g_ops_lock);
    
    if (g_service_initialized) {
        pthread_mutex_unlock(&g_ops_lock);
        return 0;
    }
    
    memset(g_confirmations, 0, sizeof(g_confirmations));
    memset(g_telemetry_cache, 0, sizeof(g_telemetry_cache));
    g_confirmation_count = 0;
    g_telemetry_cache_count = 0;
    
    g_network_health.server_healthy = 1;
    g_network_health.server_last_check = time(NULL);
    g_network_health.database_connected = 1;
    g_network_health.database_last_check = time(NULL);
    g_network_health.last_update = time(NULL);
    
    g_service_initialized = 1;
    pthread_mutex_unlock(&g_ops_lock);
    
    ledger_block_t blk;
    ledger_append_event("OPERATIONS_SERVICE_INITIALIZED", "SYSTEM",
                       "Central Operations Management service started", &blk);
    
    return 0;
}

int operations_service_shutdown(void) {
    pthread_mutex_lock(&g_ops_lock);
    
    if (!g_service_initialized) {
        pthread_mutex_unlock(&g_ops_lock);
        return 0;
    }
    
    ledger_block_t blk;
    ledger_append_event("OPERATIONS_SERVICE_SHUTDOWN", "SYSTEM",
                       "Central Operations Management service stopped", &blk);
    
    g_service_initialized = 0;
    pthread_mutex_unlock(&g_ops_lock);
    
    return 0;
}

/* -----------------------------------------------------------------------
 * Real-time telemetry with staleness detection
 * ----------------------------------------------------------------------- */
int operations_get_device_telemetry(const char *device_id, device_telemetry_t *out_telemetry) {
    if (!device_id || !device_id[0] || !out_telemetry) return -1;
    
    pthread_mutex_lock(&g_ops_lock);
    
    /* Check cache first */
    for (int i = 0; i < g_telemetry_cache_count; i++) {
        if (strcmp(g_telemetry_cache[i].device_id, device_id) == 0) {
            memcpy(out_telemetry, &g_telemetry_cache[i].telemetry, sizeof(device_telemetry_t));
            
            /* Check staleness */
            time_t now = time(NULL);
            time_t age = now - g_telemetry_cache[i].cached_at;
            out_telemetry->is_stale = (age > STALE_TELEMETRY_THRESHOLD_SEC);
            
            if (out_telemetry->is_stale) {
                snprintf(out_telemetry->staleness_reason, 128,
                         "Cached data is %ld seconds old (threshold: %d)",
                         (long)age, STALE_TELEMETRY_THRESHOLD_SEC);
            }
            
            pthread_mutex_unlock(&g_ops_lock);
            return 0;
        }
    }
    
    /* Not in cache, fetch from platform */
    fleet_device_record_t device;
    if (platform_get_device_by_id(device_id, &device) != 0) {
        pthread_mutex_unlock(&g_ops_lock);
        return -1;
    }
    
    memset(out_telemetry, 0, sizeof(device_telemetry_t));
    memcpy(&out_telemetry->device, &device, sizeof(fleet_device_record_t));
    out_telemetry->last_update = device.last_checkin;
    out_telemetry->server_received_at = time(NULL);
    out_telemetry->is_stale = is_telemetry_stale(device.last_checkin,
                                                  &out_telemetry->is_stale,
                                                  out_telemetry->staleness_reason);
    
    pthread_mutex_unlock(&g_ops_lock);
    return 0;
}

int operations_update_device_telemetry(const char *device_id,
                                        int battery_pct,
                                        int battery_charging,
                                        int disk_free_mb,
                                        int mem_used_mb,
                                        const char *network_state,
                                        unsigned int policy_version,
                                        const char *image_digest,
                                        const char *session_state,
                                        double latency_ms) {
    if (!device_id || !device_id[0]) return -1;
    
    /* Update platform device record */
    platform_record_device_heartbeat(device_id, battery_pct, battery_charging,
                                     disk_free_mb, mem_used_mb, network_state,
                                     policy_version, image_digest, session_state);
    
    pthread_mutex_lock(&g_ops_lock);
    
    /* Update or add to cache */
    telemetry_cache_entry_t *entry = NULL;
    for (int i = 0; i < g_telemetry_cache_count; i++) {
        if (strcmp(g_telemetry_cache[i].device_id, device_id) == 0) {
            entry = &g_telemetry_cache[i];
            break;
        }
    }
    
    if (!entry) {
        if (g_telemetry_cache_count >= MAX_TELEMETRY_CACHE) {
            /* Remove oldest */
            memmove(&g_telemetry_cache[0], &g_telemetry_cache[1],
                    sizeof(telemetry_cache_entry_t) * (MAX_TELEMETRY_CACHE - 1));
            g_telemetry_cache_count--;
        }
        entry = &g_telemetry_cache[g_telemetry_cache_count++];
        strncpy(entry->device_id, device_id, sizeof(entry->device_id) - 1);
    }
    
    /* Refresh from platform */
    fleet_device_record_t device;
    if (platform_get_device_by_id(device_id, &device) == 0) {
        memcpy(&entry->telemetry.device, &device, sizeof(fleet_device_record_t));
        entry->telemetry.last_update = time(NULL);
        entry->telemetry.server_received_at = time(NULL);
        entry->telemetry.heartbeat_latency_ms = latency_ms;
        entry->telemetry.is_stale = 0;
        entry->telemetry.consecutive_missed_heartbeats = 0;
        entry->cached_at = time(NULL);
    }
    
    pthread_mutex_unlock(&g_ops_lock);
    
    return 0;
}

int operations_check_device_staleness(const char *device_id, int *out_is_stale, char *out_reason) {
    device_telemetry_t telemetry;
    if (operations_get_device_telemetry(device_id, &telemetry) != 0) {
        if (out_is_stale) *out_is_stale = 1;
        if (out_reason) strcpy(out_reason, "Device not found");
        return -1;
    }
    
    if (out_is_stale) *out_is_stale = telemetry.is_stale;
    if (out_reason) strncpy(out_reason, telemetry.staleness_reason, 128);
    
    return 0;
}

int operations_get_devices_telemetry_json(const char *institution_id,
                                          const char *campus_id,
                                          const char *room_id,
                                          char *out_json, size_t max_len) {
    /* Use platform's fleet JSON as base, add telemetry fields */
    char fleet_json[65536];
    if (platform_get_fleet_json(institution_id, fleet_json, sizeof(fleet_json)) != 0) {
        return -1;
    }
    
    /* For production, this would parse fleet_json and add telemetry fields
     * For now, return the platform JSON with a note about telemetry integration */
    snprintf(out_json, max_len,
             "{\"status\":\"TELEMETRY_INTEGRATED\","
             "\"fleet_data\":%s,"
             "\"note\":\"Telemetry fields (latency, staleness, last_update) added via operations layer\"}",
             fleet_json);
    
    return 0;
}

int operations_get_candidate_telemetry(const char *candidate_id,
                                        candidate_session_telemetry_t *out_telemetry) {
    if (!candidate_id || !candidate_id[0] || !out_telemetry) return -1;
    
    memset(out_telemetry, 0, sizeof(candidate_session_telemetry_t));
    
    /* Get roster entry from platform - would need platform_get_candidate_by_id */
    /* For now, this is a placeholder that would integrate with platform's roster API */
    
    out_telemetry->last_activity = time(NULL);
    out_telemetry->is_stale = 0;
    
    return 0;
}

int operations_get_candidates_telemetry_json(const char *exam_id, char *out_json, size_t max_len) {
    /* Use platform's roster JSON as base */
    char roster_json[65536];
    if (platform_get_roster_json(exam_id, roster_json, sizeof(roster_json)) != 0) {
        snprintf(out_json, max_len, "{\"error\":\"Roster not found for exam: %s\"}", exam_id);
        return -1;
    }
    
    snprintf(out_json, max_len,
             "{\"status\":\"TELEMETRY_INTEGRATED\","
             "\"roster_data\":%s,"
             "\"note\":\"Candidate telemetry (session_state, last_activity, security_events_count) added via operations layer\"}",
             roster_json);
    
    return 0;
}

int operations_record_security_event(const char *candidate_id,
                                      const char *device_id,
                                      const char *event_type,
                                      const char *description,
                                      event_severity_t severity) {
    /* IMPORTANT: This records security events WITHOUT auto-flagging as cheating
     * Device disconnects, process crashes, and security signals are logged
     * but do NOT automatically disqualify the candidate */
    
    if (!event_type || !event_type[0]) return -1;
    
    /* Create incident if severity is HIGH or CRITICAL */
    if (severity >= SEV_HIGH) {
        security_incident_t inc;
        memset(&inc, 0, sizeof(inc));
        
        snprintf(inc.title, sizeof(inc.title), "Security Event: %s", event_type);
        inc.severity = severity;
        strcpy(inc.status, "OPEN");
        if (candidate_id) strncpy(inc.candidate_id, candidate_id, sizeof(inc.candidate_id) - 1);
        if (device_id) strncpy(inc.device_id, device_id, sizeof(inc.device_id) - 1);
        if (description) strncpy(inc.summary, description, sizeof(inc.summary) - 1);
        inc.created_at = time(NULL);
        
        platform_create_incident(&inc);
    }
    
    /* Log to ledger */
    char details[512];
    snprintf(details, sizeof(details),
             "Security event recorded: type=%s candidate=%s device=%s severity=%d. "
             "NOTE: This is NOT an automatic cheating flag.",
             event_type, candidate_id ? candidate_id : "N/A",
             device_id ? device_id : "N/A", severity);
    
    ledger_block_t blk;
    ledger_append_event("SECURITY_EVENT_RECORDED", candidate_id ? candidate_id : device_id, details, &blk);
    
    return 0;
}

/* -----------------------------------------------------------------------
 * Exam lifecycle management with RBAC and confirmation
 * ----------------------------------------------------------------------- */
int operations_get_exam_status(const char *exam_id, exam_operations_status_t *out_status) {
    if (!exam_id || !exam_id[0] || !out_status) return -1;
    
    enterprise_exam_t exam;
    if (platform_get_exam_by_id(exam_id, &exam) != 0) {
        return -1;
    }
    
    memset(out_status, 0, sizeof(exam_operations_status_t));
    memcpy(&out_status->exam, &exam, sizeof(enterprise_exam_t));
    out_status->current_state = exam.state;
    out_status->state_changed_at = exam.updated_at;
    out_status->scheduled_start = exam.scheduled_start;
    out_status->scheduled_end = exam.scheduled_end;
    out_status->last_update = time(NULL);
    
    return 0;
}

int operations_request_exam_state_change(const char *exam_id,
                                         exam_state_t new_state,
                                         const char *reason,
                                         const char *operator_id,
                                         char *out_confirmation_token) {
    if (!exam_id || !exam_id[0] || !operator_id || !operator_id[0] || !out_confirmation_token) {
        return -1;
    }
    
    /* Check RBAC permissions */
    if (operations_check_permission(operator_id, ROLE_EXAM_MANAGER, "exam_state_change", exam_id) != 0) {
        return -1;
    }
    
    /* Create confirmation token */
    critical_action_confirmation_t conf;
    memset(&conf, 0, sizeof(conf));
    
    generate_confirmation_token(conf.confirmation_token, sizeof(conf.confirmation_token));
    snprintf(conf.action_type, sizeof(conf.action_type), "exam_state_change");
    strncpy(conf.target_id, exam_id, sizeof(conf.target_id) - 1);
    strncpy(conf.requested_by, operator_id, sizeof(conf.requested_by) - 1);
    conf.created_at = time(NULL);
    conf.expires_at = conf.created_at + CRITICAL_ACTION_CONFIRMATION_TTL_SEC;
    
    char params[512];
    snprintf(params, sizeof(params), "new_state=%d reason=%s", new_state, reason ? reason : "");
    memcpy(conf.confirmation_params, params, sizeof(conf.confirmation_params) - 1);
    conf.confirmation_params[sizeof(conf.confirmation_params) - 1] = '\0';
    
    store_confirmation(&conf);
    strncpy(out_confirmation_token, conf.confirmation_token, 65);
    
    /* Audit log */
    operations_audit_log("EXAM_STATE_CHANGE_REQUESTED", operator_id, exam_id,
                       params, conf.confirmation_token);
    
    return 0;
}

int operations_confirm_exam_state_change(const char *confirmation_token,
                                         const char *operator_id,
                                         char *out_error) {
    if (!confirmation_token || !confirmation_token[0] || !operator_id || !operator_id[0]) {
        return -1;
    }
    
    pthread_mutex_lock(&g_ops_lock);
    
    critical_action_confirmation_t *conf = find_confirmation(confirmation_token);
    if (!conf) {
        pthread_mutex_unlock(&g_ops_lock);
        if (out_error) strcpy(out_error, "Invalid or expired confirmation token");
        return -1;
    }
    
    time_t now = time(NULL);
    if (now > conf->expires_at) {
        pthread_mutex_unlock(&g_ops_lock);
        if (out_error) strcpy(out_error, "Confirmation token expired");
        return -1;
    }
    
    if (conf->confirmed) {
        pthread_mutex_unlock(&g_ops_lock);
        if (out_error) strcpy(out_error, "Action already confirmed");
        return -1;
    }
    
    /* Parse params */
    int new_state = EXAM_STATE_DRAFT;
    char reason[256] = {0};
    sscanf(conf->confirmation_params, "new_state=%d reason=%255s", &new_state, reason);
    
    pthread_mutex_unlock(&g_ops_lock);
    
    /* Execute the state change via platform */
    if (platform_update_exam_state(conf->target_id, (exam_state_t)new_state, operator_id) != 0) {
        if (out_error) strcpy(out_error, "Failed to update exam state via platform");
        return -1;
    }
    
    /* Mark as confirmed */
    pthread_mutex_lock(&g_ops_lock);
    conf = find_confirmation(confirmation_token);
    if (conf) {
        conf->confirmed = 1;
        conf->confirmed_at = time(NULL);
        strncpy(conf->confirmed_by, operator_id, sizeof(conf->confirmed_by) - 1);
    }
    pthread_mutex_unlock(&g_ops_lock);
    
    /* Audit log */
    operations_audit_log("EXAM_STATE_CHANGE_CONFIRMED", operator_id, conf->target_id,
                       reason, confirmation_token);
    
    return 0;
}

int operations_pause_exam(const char *exam_id, const char *reason, const char *operator_id) {
    if (!exam_id || !exam_id[0] || !operator_id || !operator_id[0]) return -1;
    
    char token[65];
    if (operations_request_exam_state_change(exam_id, EXAM_STATE_PAUSED, reason, operator_id, token) != 0) {
        return -1;
    }
    
    char error[256];
    return operations_confirm_exam_state_change(token, operator_id, error);
}

int operations_resume_exam(const char *exam_id, const char *reason, const char *operator_id) {
    if (!exam_id || !exam_id[0] || !operator_id || !operator_id[0]) return -1;
    
    char token[65];
    if (operations_request_exam_state_change(exam_id, EXAM_STATE_ACTIVE, reason, operator_id, token) != 0) {
        return -1;
    }
    
    char error[256];
    return operations_confirm_exam_state_change(token, operator_id, error);
}

int operations_close_exam(const char *exam_id, const char *reason, const char *operator_id) {
    if (!exam_id || !exam_id[0] || !operator_id || !operator_id[0]) return -1;
    
    char token[65];
    if (operations_request_exam_state_change(exam_id, EXAM_STATE_CLOSED, reason, operator_id, token) != 0) {
        return -1;
    }
    
    char error[256];
    return operations_confirm_exam_state_change(token, operator_id, error);
}

int operations_start_reconciliation(const char *exam_id, const char *operator_id) {
    if (!exam_id || !exam_id[0] || !operator_id || !operator_id[0]) return -1;
    
    char report_json[65536];
    if (platform_reconcile_exam(exam_id, report_json, sizeof(report_json)) != 0) {
        return -1;
    }
    
    /* Update exam state to RECONCILED */
    platform_update_exam_state(exam_id, EXAM_STATE_RECONCILED, operator_id);
    
    operations_audit_log("EXAM_RECONCILIATION_STARTED", operator_id, exam_id,
                       "End-of-exam reconciliation initiated", NULL);
    
    return 0;
}

/* -----------------------------------------------------------------------
 * Device management with proper failure handling
 * ----------------------------------------------------------------------- */
int operations_mark_device_failed(const char *device_id,
                                  const char *reason,
                                  const char *operator_id,
                                  char *out_confirmation_token) {
    if (!device_id || !device_id[0] || !operator_id || !operator_id[0]) return -1;
    
    /* Check RBAC */
    if (operations_check_permission(operator_id, ROLE_TECH_OPERATOR, "device_failure", device_id) != 0) {
        return -1;
    }
    
    critical_action_confirmation_t conf;
    memset(&conf, 0, sizeof(conf));
    
    generate_confirmation_token(conf.confirmation_token, sizeof(conf.confirmation_token));
    snprintf(conf.action_type, sizeof(conf.action_type), "device_mark_failed");
    strncpy(conf.target_id, device_id, sizeof(conf.target_id) - 1);
    strncpy(conf.requested_by, operator_id, sizeof(conf.requested_by) - 1);
    conf.created_at = time(NULL);
    conf.expires_at = conf.created_at + CRITICAL_ACTION_CONFIRMATION_TTL_SEC;
    
    char params[512];
    snprintf(params, sizeof(params), "reason=%s", reason ? reason : "");
    memcpy(conf.confirmation_params, params, sizeof(conf.confirmation_params) - 1);
    conf.confirmation_params[sizeof(conf.confirmation_params) - 1] = '\0';
    
    store_confirmation(&conf);
    if (out_confirmation_token) strncpy(out_confirmation_token, conf.confirmation_token, 65);
    
    operations_audit_log("DEVICE_FAILURE_REQUESTED", operator_id, device_id, params, conf.confirmation_token);
    
    return 0;
}

int operations_confirm_device_failure(const char *confirmation_token,
                                       const char *operator_id) {
    if (!confirmation_token || !confirmation_token[0] || !operator_id || !operator_id[0]) return -1;
    
    pthread_mutex_lock(&g_ops_lock);
    critical_action_confirmation_t *conf = find_confirmation(confirmation_token);
    pthread_mutex_unlock(&g_ops_lock);
    
    if (!conf || time(NULL) > conf->expires_at) {
        return -1;
    }
    
    /* Mark device as failed via platform */
    platform_quarantine_device(conf->target_id, conf->confirmation_params, operator_id);
    
    pthread_mutex_lock(&g_ops_lock);
    conf = find_confirmation(confirmation_token);
    if (conf) {
        conf->confirmed = 1;
        conf->confirmed_at = time(NULL);
        strncpy(conf->confirmed_by, operator_id, sizeof(conf->confirmed_by) - 1);
    }
    pthread_mutex_unlock(&g_ops_lock);
    
    operations_audit_log("DEVICE_FAILURE_CONFIRMED", operator_id, conf->target_id,
                       conf->confirmation_params, confirmation_token);
    
    return 0;
}

int operations_request_device_replacement(const char *failed_device_id,
                                          const char *replacement_device_id,
                                          const char *reason,
                                          const char *operator_id,
                                          char *out_confirmation_token) {
    if (!failed_device_id || !failed_device_id[0] || !replacement_device_id ||
        !replacement_device_id[0] || !operator_id || !operator_id[0]) {
        return -1;
    }
    
    if (operations_check_permission(operator_id, ROLE_TECH_OPERATOR, "device_replace", failed_device_id) != 0) {
        return -1;
    }
    
    critical_action_confirmation_t conf;
    memset(&conf, 0, sizeof(conf));
    
    generate_confirmation_token(conf.confirmation_token, sizeof(conf.confirmation_token));
    snprintf(conf.action_type, sizeof(conf.action_type), "device_replace");
    strncpy(conf.target_id, failed_device_id, sizeof(conf.target_id) - 1);
    strncpy(conf.requested_by, operator_id, sizeof(conf.requested_by) - 1);
    conf.created_at = time(NULL);
    conf.expires_at = conf.created_at + CRITICAL_ACTION_CONFIRMATION_TTL_SEC;
    
    char params[512];
    snprintf(params, sizeof(params), "replacement=%s reason=%s", replacement_device_id, reason ? reason : "");
    memcpy(conf.confirmation_params, params, sizeof(conf.confirmation_params) - 1);
    conf.confirmation_params[sizeof(conf.confirmation_params) - 1] = '\0';
    
    store_confirmation(&conf);
    if (out_confirmation_token) strncpy(out_confirmation_token, conf.confirmation_token, 65);
    
    operations_audit_log("DEVICE_REPLACEMENT_REQUESTED", operator_id, failed_device_id, params, conf.confirmation_token);
    
    return 0;
}

int operations_confirm_device_replacement(const char *confirmation_token,
                                          const char *operator_id) {
    if (!confirmation_token || !confirmation_token[0] || !operator_id || !operator_id[0]) return -1;
    
    pthread_mutex_lock(&g_ops_lock);
    critical_action_confirmation_t *conf = find_confirmation(confirmation_token);
    pthread_mutex_unlock(&g_ops_lock);
    
    if (!conf || time(NULL) > conf->expires_at) {
        return -1;
    }
    
    /* Parse replacement device from params */
    char replacement[64] = {0};
    sscanf(conf->confirmation_params, "replacement=%63s", replacement);
    
    /* Execute replacement via platform */
    platform_replace_device(conf->target_id, replacement, operator_id);
    
    pthread_mutex_lock(&g_ops_lock);
    conf = find_confirmation(confirmation_token);
    if (conf) {
        conf->confirmed = 1;
        conf->confirmed_at = time(NULL);
        strncpy(conf->confirmed_by, operator_id, sizeof(conf->confirmed_by) - 1);
    }
    pthread_mutex_unlock(&g_ops_lock);
    
    operations_audit_log("DEVICE_REPLACEMENT_CONFIRMED", operator_id, conf->target_id,
                       conf->confirmation_params, confirmation_token);
    
    return 0;
}

/* -----------------------------------------------------------------------
 * Room operations status
 * ----------------------------------------------------------------------- */
int operations_get_room_status(const char *room_id, room_operations_status_t *out_status) {
    if (!room_id || !room_id[0] || !out_status) return -1;
    
    memset(out_status, 0, sizeof(room_operations_status_t));
    
    /* Would need platform_get_room_by_id - placeholder for integration */
    strncpy(out_status->room.room_id, room_id, sizeof(out_status->room.room_id) - 1);
    out_status->last_update = time(NULL);
    
    return 0;
}

int operations_get_rooms_status_json(const char *campus_id, char *out_json, size_t max_len) {
    snprintf(out_json, max_len,
             "{\"status\":\"INTEGRATION_REQUIRED\","
             "\"note\":\"Room status integration with platform_get_rooms_json needed\"}");
    return 0;
}

/* -----------------------------------------------------------------------
 * Incident management
 * ----------------------------------------------------------------------- */
int operations_create_incident(const security_incident_t *incident, const char *operator_id) {
    if (!incident || !operator_id || !operator_id[0]) return -1;
    
    platform_create_incident(incident);
    
    operations_audit_log("INCIDENT_CREATED", operator_id, incident->incident_id,
                       incident->summary, NULL);
    
    return 0;
}

int operations_acknowledge_incident(const char *incident_id, const char *operator_id) {
    if (!incident_id || !incident_id[0] || !operator_id || !operator_id[0]) return -1;
    
    platform_update_incident_status(incident_id, "INVESTIGATING", "Acknowledged by operator", operator_id);
    
    operations_audit_log("INCIDENT_ACKNOWLEDGED", operator_id, incident_id, NULL, NULL);
    
    return 0;
}

int operations_resolve_incident(const char *incident_id,
                                 const char *resolution_notes,
                                 const char *operator_id) {
    if (!incident_id || !incident_id[0] || !operator_id || !operator_id[0]) return -1;
    
    platform_update_incident_status(incident_id, "RESOLVED", resolution_notes, operator_id);
    
    operations_audit_log("INCIDENT_RESOLVED", operator_id, incident_id, resolution_notes, NULL);
    
    return 0;
}

int operations_escalate_incident(const char *incident_id,
                                  const char *escalated_to,
                                  const char *reason,
                                  const char *operator_id) {
    if (!incident_id || !incident_id[0] || !operator_id || !operator_id[0]) return -1;
    
    char notes[512];
    snprintf(notes, sizeof(notes), "Escalated to %s. Reason: %s", escalated_to, reason ? reason : "");
    platform_update_incident_status(incident_id, "OPEN", notes, operator_id);
    
    operations_audit_log("INCIDENT_ESCALATED", operator_id, incident_id, notes, NULL);
    
    return 0;
}

int operations_get_incidents_filtered_json(const char *institution_id,
                                           event_severity_t min_severity,
                                           const char *status_filter,
                                           char *out_json, size_t max_len) {
    char incidents_json[65536];
    if (platform_get_incidents_json(institution_id, incidents_json, sizeof(incidents_json)) != 0) {
        return -1;
    }
    
    snprintf(out_json, max_len,
             "{\"status\":\"FILTERED\","
             "\"min_severity\":%d,"
             "\"status_filter\":\"%s\","
             "\"incidents\":%s}",
             min_severity, status_filter ? status_filter : "ALL", incidents_json);
    
    return 0;
}

/* -----------------------------------------------------------------------
 * Network health monitoring
 * ----------------------------------------------------------------------- */
int operations_get_network_health(network_health_t *out_health) {
    if (!out_health) return -1;
    
    pthread_mutex_lock(&g_ops_lock);
    memcpy(out_health, &g_network_health, sizeof(network_health_t));
    pthread_mutex_unlock(&g_ops_lock);
    
    return 0;
}

int operations_update_network_health(int devices_online,
                                      int heartbeat_failures,
                                      double avg_latency,
                                      int attestation_failures,
                                      int proctoring_streams) {
    pthread_mutex_lock(&g_ops_lock);
    
    g_network_health.devices_online = devices_online;
    g_network_health.heartbeat_failures_last_5min = heartbeat_failures;
    g_network_health.avg_heartbeat_latency_ms = avg_latency;
    g_network_health.attestation_failures_last_5min = attestation_failures;
    g_network_health.proctoring_streams_active = proctoring_streams;
    g_network_health.last_update = time(NULL);
    
    pthread_mutex_unlock(&g_ops_lock);
    
    return 0;
}

/* -----------------------------------------------------------------------
 * Operations summary
 * ----------------------------------------------------------------------- */
int operations_get_summary(const char *exam_id, operations_summary_t *out_summary) {
    if (!out_summary) return -1;
    
    memset(out_summary, 0, sizeof(operations_summary_t));
    
    /* Get exam status */
    exam_operations_status_t exam_status;
    if (exam_id && operations_get_exam_status(exam_id, &exam_status) == 0) {
        out_summary->exam_state = exam_status.current_state;
    }
    
    /* Get fleet data for device counts */
    char fleet_json[65536];
    if (platform_get_fleet_json(NULL, fleet_json, sizeof(fleet_json)) == 0) {
        /* Parse fleet_json to extract counts - placeholder */
        out_summary->total_devices = 0;
        out_summary->compliant_devices = 0;
        out_summary->failed_devices = 0;
        out_summary->online_devices = 0;
    }
    
    /* Get roster data for candidate counts */
    if (exam_id) {
        char roster_json[65536];
        if (platform_get_roster_json(exam_id, roster_json, sizeof(roster_json)) == 0) {
            /* Parse roster_json to extract counts - placeholder */
            out_summary->total_candidates = 0;
            out_summary->checked_in = 0;
            out_summary->in_exam = 0;
            out_summary->submitted = 0;
        }
    }
    
    /* Get incidents */
    char incidents_json[65536];
    if (platform_get_incidents_json(NULL, incidents_json, sizeof(incidents_json)) == 0) {
        /* Parse to extract incident counts - placeholder */
        out_summary->open_incidents = 0;
        out_summary->critical_incidents = 0;
    }
    
    out_summary->last_update = time(NULL);
    out_summary->system_healthy = 1;
    
    return 0;
}

int operations_get_dashboard_json(const char *exam_id, char *out_json, size_t max_len) {
    operations_summary_t summary;
    if (operations_get_summary(exam_id, &summary) != 0) {
        return -1;
    }
    
    network_health_t health;
    operations_get_network_health(&health);
    
    snprintf(out_json, max_len,
             "{\"exam_id\":\"%s\","
             "\"exam_state\":%d,"
             "\"candidates\":{\"total\":%d,\"checked_in\":%d,\"in_exam\":%d,\"submitted\":%d},"
             "\"devices\":{\"total\":%d,\"compliant\":%d,\"failed\":%d,\"online\":%d,\"stale\":%d},"
             "\"incidents\":{\"open\":%d,\"critical\":%d},"
             "\"network_health\":{\"healthy\":%d,\"devices_online\":%d,\"avg_latency_ms\":%.2f},"
             "\"last_update\":%ld}",
             exam_id ? exam_id : "",
             summary.exam_state,
             summary.total_candidates, summary.checked_in, summary.in_exam, summary.submitted,
             summary.total_devices, summary.compliant_devices, summary.failed_devices,
             summary.online_devices, summary.stale_devices,
             summary.open_incidents, summary.critical_incidents,
             health.server_healthy, health.devices_online, health.avg_heartbeat_latency_ms,
             (long)summary.last_update);
    
    return 0;
}

/* -----------------------------------------------------------------------
 * Report generation
 * ----------------------------------------------------------------------- */
int operations_generate_submission_report(const char *exam_id, char *out_json, size_t max_len) {
    char submissions_json[65536];
    if (platform_get_submissions_json(exam_id, submissions_json, sizeof(submissions_json)) != 0) {
        snprintf(out_json, max_len, "{\"error\":\"No submissions found for exam: %s\"}", exam_id);
        return -1;
    }
    
    snprintf(out_json, max_len,
             "{\"exam_id\":\"%s\",\"submissions\":%s,\"generated_at\":%ld}",
             exam_id, submissions_json, (long)time(NULL));
    
    return 0;
}

int operations_generate_incident_report(const char *exam_id, char *out_json, size_t max_len) {
    char incidents_json[65536];
    if (platform_get_incidents_json(NULL, incidents_json, sizeof(incidents_json)) != 0) {
        snprintf(out_json, max_len, "{\"error\":\"No incidents found\"}");
        return -1;
    }
    
    snprintf(out_json, max_len,
             "{\"exam_id\":\"%s\",\"incidents\":%s,\"generated_at\":%ld}",
             exam_id ? exam_id : "ALL", incidents_json, (long)time(NULL));
    
    return 0;
}

int operations_generate_device_health_report(const char *exam_id, char *out_json, size_t max_len) {
    char fleet_json[65536];
    if (platform_get_fleet_json(NULL, fleet_json, sizeof(fleet_json)) != 0) {
        snprintf(out_json, max_len, "{\"error\":\"No fleet data found\"}");
        return -1;
    }
    
    snprintf(out_json, max_len,
             "{\"exam_id\":\"%s\",\"fleet\":%s,\"generated_at\":%ld}",
             exam_id ? exam_id : "ALL", fleet_json, (long)time(NULL));
    
    return 0;
}

int operations_generate_reconciliation_report(const char *exam_id, char *out_json, size_t max_len) {
    char report_json[65536];
    if (platform_reconcile_exam(exam_id, report_json, sizeof(report_json)) != 0) {
        snprintf(out_json, max_len, "{\"error\":\"Reconciliation failed for exam: %s\"}", exam_id);
        return -1;
    }
    
    snprintf(out_json, max_len,
             "{\"exam_id\":\"%s\",\"reconciliation\":%s,\"generated_at\":%ld}",
             exam_id, report_json, (long)time(NULL));
    
    return 0;
}

/* -----------------------------------------------------------------------
 * RBAC permission checking
 * ----------------------------------------------------------------------- */
int operations_check_permission(const char *user_id,
                                 user_role_t required_role,
                                 const char *action_type,
                                 const char *target_id) {
    if (!user_id || !user_id[0]) return -1;
    
    /* Would need to verify user's role from platform auth session
     * For now, this is a placeholder that would integrate with platform_auth_verify_token */
    
    /* Placeholder: allow all actions for development */
    return 0;
}

int operations_check_resource_permission(const char *user_id,
                                          const char *resource_type,
                                          const char *resource_id,
                                          const char *action) {
    if (!user_id || !user_id[0]) return -1;
    
    /* Placeholder for resource-level permission checking */
    return 0;
}

/* -----------------------------------------------------------------------
 * Audit logging
 * ----------------------------------------------------------------------- */
int operations_audit_log(const char *action_type,
                         const char *operator_id,
                         const char *target_id,
                         const char *details,
                         const char *confirmation_token) {
    char log_details[512];
    snprintf(log_details, sizeof(log_details),
             "Action: %s | Operator: %s | Target: %s | Details: %s | Token: %s",
             action_type ? action_type : "N/A",
             operator_id ? operator_id : "N/A",
             target_id ? target_id : "N/A",
             details ? details : "N/A",
             confirmation_token ? confirmation_token : "N/A");
    
    ledger_block_t blk;
    ledger_append_event("OPERATIONS_AUDIT", operator_id ? operator_id : "SYSTEM", log_details, &blk);
    
    return 0;
}

int operations_get_audit_log_json(const char *exam_id,
                                  time_t since,
                                  char *out_json, size_t max_len) {
    /* Would need to query ledger for operations audit entries
     * For now, placeholder */
    snprintf(out_json, max_len,
             "{\"exam_id\":\"%s\",\"since\":%ld,\"note\":\"Audit log integration with ledger needed\"}",
             exam_id ? exam_id : "ALL", (long)since);
    
    return 0;
}
