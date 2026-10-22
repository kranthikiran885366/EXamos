#define _GNU_SOURCE
#include "include/event_pipeline.h"
#include "include/ledger.h"
#include "include/enterprise_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/* -----------------------------------------------------------------------
 * Module State
 * ----------------------------------------------------------------------- */
static pthread_mutex_t g_pipeline_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;

/* Event journal (write-ahead log) */
static char g_journal_path[512] = "/var/log/examos/event_pipeline.log";
static FILE *g_journal_file = NULL;
static size_t g_journal_max_size = 100 * 1024 * 1024;  /* 100MB default */
static int g_journal_rotation_count = 5;

/* In-memory event cache for search (dynamic allocation) */
static security_event_t *g_event_cache = NULL;
static size_t g_event_cache_capacity = 0;
static size_t g_event_cache_count = 0;
static long g_total_events = 0;
static int g_cache_eviction_policy = 0;  /* 0=FIFO */

/* Alert rules storage (dynamic allocation) */
static alert_rule_t *g_alert_rules = NULL;
static size_t g_alert_rules_capacity = 0;
static size_t g_alert_rule_count = 0;

/* Deduplication windows (dynamic hash table) */
typedef struct {
    event_type_t event_type;
    int window_seconds;
} dedup_entry_t;

static dedup_entry_t *g_dedup_table = NULL;
static size_t g_dedup_table_capacity = 0;
static int g_dedup_enabled = 1;

/* Configuration */
static event_pipeline_config_t g_config;

/* Performance settings */
static int g_flush_interval_ms = 1000;
static int g_batch_write_size = 10;
static int g_async_writes_enabled = 0;

/* Security settings */
static int g_validate_sensitive_data = 1;
static int g_sanitize_details = 1;

/* -----------------------------------------------------------------------
 * Configuration Management
 * ----------------------------------------------------------------------- */

static void init_default_config(event_pipeline_config_t *config) {
    memset(config, 0, sizeof(*config));
    
    /* Journal settings */
    strncpy(config->journal_path, "/var/log/examos/event_pipeline.log", sizeof(config->journal_path) - 1);
    config->journal_max_size_mb = 100;
    config->journal_rotation_count = 5;
    
    /* Cache settings */
    config->event_cache_size = 10000;
    config->cache_eviction_policy = 0;
    
    /* Alert settings */
    config->max_alert_rules = 128;
    config->default_dedup_window_sec = 300;
    
    /* Deduplication settings */
    config->deduplication_enabled = 1;
    config->dedup_hash_table_size = 1024;
    
    /* Performance settings */
    config->flush_interval_ms = 1000;
    config->batch_write_size = 10;
    config->async_writes_enabled = 0;
    
    /* Security settings */
    config->validate_sensitive_data = 1;
    config->sanitize_details = 1;
    
    /* Runtime limits */
    config->max_event_details_len = EVENT_DETAILS_MAX_LEN;
    config->max_evidence_refs_len = EVIDENCE_REF_MAX_LEN;
    config->max_concurrent_searches = 10;
}

int event_pipeline_load_config_from_env(event_pipeline_config_t *out_config) {
    if (!out_config) return -1;
    
    init_default_config(out_config);
    
    const char *env_val;
    
    /* Journal settings */
    if ((env_val = getenv("EXAMOS_EVENT_JOURNAL"))) {
        strncpy(out_config->journal_path, env_val, sizeof(out_config->journal_path) - 1);
    }
    if ((env_val = getenv("EXAMOS_EVENT_JOURNAL_MAX_SIZE_MB"))) {
        out_config->journal_max_size_mb = (size_t)atoi(env_val);
    }
    if ((env_val = getenv("EXAMOS_EVENT_JOURNAL_ROTATION"))) {
        out_config->journal_rotation_count = atoi(env_val);
    }
    
    /* Cache settings */
    if ((env_val = getenv("EXAMOS_EVENT_CACHE_SIZE"))) {
        out_config->event_cache_size = (size_t)atoi(env_val);
    }
    if ((env_val = getenv("EXAMOS_EVENT_CACHE_POLICY"))) {
        out_config->cache_eviction_policy = atoi(env_val);
    }
    
    /* Alert settings */
    if ((env_val = getenv("EXAMOS_EVENT_MAX_ALERT_RULES"))) {
        out_config->max_alert_rules = (size_t)atoi(env_val);
    }
    if ((env_val = getenv("EXAMOS_EVENT_DEDUP_WINDOW"))) {
        out_config->default_dedup_window_sec = atoi(env_val);
    }
    
    /* Deduplication settings */
    if ((env_val = getenv("EXAMOS_EVENT_DEDUP_ENABLED"))) {
        out_config->deduplication_enabled = (strcmp(env_val, "1") == 0 || strcmp(env_val, "true") == 0);
    }
    if ((env_val = getenv("EXAMOS_EVENT_DEDUP_HASH_SIZE"))) {
        out_config->dedup_hash_table_size = (size_t)atoi(env_val);
    }
    
    /* Performance settings */
    if ((env_val = getenv("EXAMOS_EVENT_FLUSH_INTERVAL_MS"))) {
        out_config->flush_interval_ms = atoi(env_val);
    }
    if ((env_val = getenv("EXAMOS_EVENT_BATCH_WRITE_SIZE"))) {
        out_config->batch_write_size = atoi(env_val);
    }
    if ((env_val = getenv("EXAMOS_EVENT_ASYNC_WRITES"))) {
        out_config->async_writes_enabled = (strcmp(env_val, "1") == 0 || strcmp(env_val, "true") == 0);
    }
    
    /* Security settings */
    if ((env_val = getenv("EXAMOS_EVENT_VALIDATE_SENSITIVE"))) {
        out_config->validate_sensitive_data = (strcmp(env_val, "1") == 0 || strcmp(env_val, "true") == 0);
    }
    if ((env_val = getenv("EXAMOS_EVENT_SANITIZE_DETAILS"))) {
        out_config->sanitize_details = (strcmp(env_val, "1") == 0 || strcmp(env_val, "true") == 0);
    }
    
    /* Runtime limits */
    if ((env_val = getenv("EXAMOS_EVENT_MAX_DETAILS_LEN"))) {
        out_config->max_event_details_len = (size_t)atoi(env_val);
    }
    if ((env_val = getenv("EXAMOS_EVENT_MAX_EVIDENCE_LEN"))) {
        out_config->max_evidence_refs_len = (size_t)atoi(env_val);
    }
    if ((env_val = getenv("EXAMOS_EVENT_MAX_CONCURRENT_SEARCHES"))) {
        out_config->max_concurrent_searches = atoi(env_val);
    }
    
    return 0;
}

int event_pipeline_load_config(const char *config_path, event_pipeline_config_t *out_config) {
    if (!config_path || !out_config) return -1;
    
    init_default_config(out_config);
    
    FILE *f = fopen(config_path, "r");
    if (!f) {
        /* Fall back to environment variables */
        return event_pipeline_load_config_from_env(out_config);
    }
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') continue;
        
        /* Parse key=value */
        char *key = strtok(line, "= \t\n");
        char *value = strtok(NULL, "\n");
        if (!key || !value) continue;
        
        /* Trim whitespace */
        while (*value == ' ' || *value == '\t') value++;
        
        if (strcmp(key, "journal_path") == 0) {
            strncpy(out_config->journal_path, value, sizeof(out_config->journal_path) - 1);
        } else if (strcmp(key, "journal_max_size_mb") == 0) {
            out_config->journal_max_size_mb = (size_t)atoi(value);
        } else if (strcmp(key, "journal_rotation_count") == 0) {
            out_config->journal_rotation_count = atoi(value);
        } else if (strcmp(key, "event_cache_size") == 0) {
            out_config->event_cache_size = (size_t)atoi(value);
        } else if (strcmp(key, "cache_eviction_policy") == 0) {
            out_config->cache_eviction_policy = atoi(value);
        } else if (strcmp(key, "max_alert_rules") == 0) {
            out_config->max_alert_rules = (size_t)atoi(value);
        } else if (strcmp(key, "default_dedup_window_sec") == 0) {
            out_config->default_dedup_window_sec = atoi(value);
        } else if (strcmp(key, "deduplication_enabled") == 0) {
            out_config->deduplication_enabled = (strcmp(value, "1") == 0 || strcmp(value, "true") == 0);
        } else if (strcmp(key, "dedup_hash_table_size") == 0) {
            out_config->dedup_hash_table_size = (size_t)atoi(value);
        } else if (strcmp(key, "flush_interval_ms") == 0) {
            out_config->flush_interval_ms = atoi(value);
        } else if (strcmp(key, "batch_write_size") == 0) {
            out_config->batch_write_size = atoi(value);
        } else if (strcmp(key, "async_writes_enabled") == 0) {
            out_config->async_writes_enabled = (strcmp(value, "1") == 0 || strcmp(value, "true") == 0);
        } else if (strcmp(key, "validate_sensitive_data") == 0) {
            out_config->validate_sensitive_data = (strcmp(value, "1") == 0 || strcmp(value, "true") == 0);
        } else if (strcmp(key, "sanitize_details") == 0) {
            out_config->sanitize_details = (strcmp(value, "1") == 0 || strcmp(value, "true") == 0);
        } else if (strcmp(key, "max_event_details_len") == 0) {
            out_config->max_event_details_len = (size_t)atoi(value);
        } else if (strcmp(key, "max_evidence_refs_len") == 0) {
            out_config->max_evidence_refs_len = (size_t)atoi(value);
        } else if (strcmp(key, "max_concurrent_searches") == 0) {
            out_config->max_concurrent_searches = atoi(value);
        }
    }
    
    fclose(f);
    return 0;
}

int event_pipeline_save_config(const char *config_path, const event_pipeline_config_t *config) {
    if (!config_path || !config) return -1;
    
    FILE *f = fopen(config_path, "w");
    if (!f) return -1;
    
    fprintf(f, "# Event Pipeline Configuration\n");
    fprintf(f, "journal_path=%s\n", config->journal_path);
    fprintf(f, "journal_max_size_mb=%zu\n", config->journal_max_size_mb);
    fprintf(f, "journal_rotation_count=%d\n", config->journal_rotation_count);
    fprintf(f, "event_cache_size=%zu\n", config->event_cache_size);
    fprintf(f, "cache_eviction_policy=%d\n", config->cache_eviction_policy);
    fprintf(f, "max_alert_rules=%zu\n", config->max_alert_rules);
    fprintf(f, "default_dedup_window_sec=%d\n", config->default_dedup_window_sec);
    fprintf(f, "deduplication_enabled=%d\n", config->deduplication_enabled);
    fprintf(f, "dedup_hash_table_size=%zu\n", config->dedup_hash_table_size);
    fprintf(f, "flush_interval_ms=%d\n", config->flush_interval_ms);
    fprintf(f, "batch_write_size=%d\n", config->batch_write_size);
    fprintf(f, "async_writes_enabled=%d\n", config->async_writes_enabled);
    fprintf(f, "validate_sensitive_data=%d\n", config->validate_sensitive_data);
    fprintf(f, "sanitize_details=%d\n", config->sanitize_details);
    fprintf(f, "max_event_details_len=%zu\n", config->max_event_details_len);
    fprintf(f, "max_evidence_refs_len=%zu\n", config->max_evidence_refs_len);
    fprintf(f, "max_concurrent_searches=%d\n", config->max_concurrent_searches);
    
    fclose(f);
    return 0;
}

int event_pipeline_get_config(event_pipeline_config_t *out_config) {
    if (!out_config) return -1;
    
    pthread_mutex_lock(&g_pipeline_lock);
    memcpy(out_config, &g_config, sizeof(g_config));
    pthread_mutex_unlock(&g_pipeline_lock);
    
    return 0;
}

int event_pipeline_apply_config(const event_pipeline_config_t *config) {
    if (!config) return -1;
    
    pthread_mutex_lock(&g_pipeline_lock);
    
    /* Apply configuration to runtime state */
    strncpy(g_journal_path, config->journal_path, sizeof(g_journal_path) - 1);
    g_journal_path[sizeof(g_journal_path) - 1] = '\0';
    g_journal_max_size = config->journal_max_size_mb * 1024 * 1024;
    g_journal_rotation_count = config->journal_rotation_count;
    g_cache_eviction_policy = config->cache_eviction_policy;
    g_flush_interval_ms = config->flush_interval_ms;
    g_batch_write_size = config->batch_write_size;
    g_async_writes_enabled = config->async_writes_enabled;
    g_validate_sensitive_data = config->validate_sensitive_data;
    g_sanitize_details = config->sanitize_details;
    g_dedup_enabled = config->deduplication_enabled;
    
    /* Reallocate cache if size changed */
    if (config->event_cache_size != g_event_cache_capacity && g_event_cache_capacity > 0) {
        security_event_t *new_cache = realloc(g_event_cache, config->event_cache_size * sizeof(security_event_t));
        if (new_cache) {
            g_event_cache = new_cache;
            g_event_cache_capacity = config->event_cache_size;
            if (g_event_cache_count > g_event_cache_capacity) {
                g_event_cache_count = g_event_cache_capacity;
            }
        }
    }
    
    /* Reallocate alert rules if size changed */
    if (config->max_alert_rules != g_alert_rules_capacity && g_alert_rules_capacity > 0) {
        alert_rule_t *new_rules = realloc(g_alert_rules, config->max_alert_rules * sizeof(alert_rule_t));
        if (new_rules) {
            g_alert_rules = new_rules;
            g_alert_rules_capacity = config->max_alert_rules;
            if (g_alert_rule_count > g_alert_rules_capacity) {
                g_alert_rule_count = g_alert_rules_capacity;
            }
        }
    }
    
    memcpy(&g_config, config, sizeof(g_config));
    
    pthread_mutex_unlock(&g_pipeline_lock);
    return 0;
}

/* -----------------------------------------------------------------------
 * Dynamic Memory Management
 * ----------------------------------------------------------------------- */

static int allocate_event_cache(size_t capacity) {
    if (g_event_cache) {
        free(g_event_cache);
    }
    
    g_event_cache = calloc(capacity, sizeof(security_event_t));
    if (!g_event_cache) {
        return -1;
    }
    
    g_event_cache_capacity = capacity;
    g_event_cache_count = 0;
    return 0;
}

static int allocate_alert_rules(size_t capacity) {
    if (g_alert_rules) {
        free(g_alert_rules);
    }
    
    g_alert_rules = calloc(capacity, sizeof(alert_rule_t));
    if (!g_alert_rules) {
        return -1;
    }
    
    g_alert_rules_capacity = capacity;
    g_alert_rule_count = 0;
    return 0;
}

static int allocate_dedup_table(size_t capacity) {
    if (g_dedup_table) {
        free(g_dedup_table);
    }
    
    g_dedup_table = calloc(capacity, sizeof(dedup_entry_t));
    if (!g_dedup_table) {
        return -1;
    }
    
    g_dedup_table_capacity = capacity;
    return 0;
}

static void free_all_resources(void) {
    if (g_event_cache) {
        free(g_event_cache);
        g_event_cache = NULL;
    }
    g_event_cache_capacity = 0;
    g_event_cache_count = 0;
    
    if (g_alert_rules) {
        free(g_alert_rules);
        g_alert_rules = NULL;
    }
    g_alert_rules_capacity = 0;
    g_alert_rule_count = 0;
    
    if (g_dedup_table) {
        free(g_dedup_table);
        g_dedup_table = NULL;
    }
    g_dedup_table_capacity = 0;
    
    if (g_journal_file) {
        fclose(g_journal_file);
        g_journal_file = NULL;
    }
}

static int generate_event_id(char *out_id, size_t max_len) {
    if (!out_id || max_len < 33) return -1;
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        out_id[0] = '\0';
        return -1;
    }
    for (int i = 0; i < 16; i++) {
        snprintf(out_id + i * 2, max_len - i * 2, "%02x", buf[i]);
    }
    out_id[32] = '\0';
    return 0;
}

static int generate_correlation_id(char *out_id, size_t max_len) {
    if (!out_id || max_len < 33) return -1;
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        out_id[0] = '\0';
        return -1;
    }
    for (int i = 0; i < 16; i++) {
        snprintf(out_id + i * 2, max_len - i * 2, "%02x", buf[i]);
    }
    out_id[32] = '\0';
    return 0;
}

static const char* event_type_to_string_internal(event_type_t type) {
    switch (type) {
        case EVENT_AUTH_FAILURE: return "AUTH_FAILURE";
        case EVENT_AUTH_SUCCESS: return "AUTH_SUCCESS";
        case EVENT_AUTH_LOCKOUT: return "AUTH_LOCKOUT";
        case EVENT_SESSION_CREATED: return "SESSION_CREATED";
        case EVENT_SESSION_INVALIDATED: return "SESSION_INVALIDATED";
        case EVENT_SESSION_EXPIRED: return "SESSION_EXPIRED";
        case EVENT_POLICY_CHANGE: return "POLICY_CHANGE";
        case EVENT_POLICY_VIOLATION: return "POLICY_VIOLATION";
        case EVENT_CONFIG_CHANGE: return "CONFIG_CHANGE";
        case EVENT_CONFIG_TAMPERING: return "CONFIG_TAMPERING";
        case EVENT_CONFIG_RESTORE: return "CONFIG_RESTORE";
        case EVENT_DEVICE_ENROLLMENT: return "DEVICE_ENROLLMENT";
        case EVENT_DEVICE_REVOCATION: return "DEVICE_REVOCATION";
        case EVENT_DEVICE_QUARANTINE: return "DEVICE_QUARANTINE";
        case EVENT_DEVICE_REPLACEMENT: return "DEVICE_REPLACEMENT";
        case EVENT_DEVICE_CHECKIN_FAILURE: return "DEVICE_CHECKIN_FAILURE";
        case EVENT_DEVICE_CHECKIN_SUCCESS: return "DEVICE_CHECKIN_SUCCESS";
        case EVENT_ATTESTATION_SUCCESS: return "ATTESTATION_SUCCESS";
        case EVENT_ATTESTATION_FAILED: return "ATTESTATION_FAILED";
        case EVENT_ATTESTATION_STALE: return "ATTESTATION_STALE";
        case EVENT_ATTESTATION_TIMEOUT: return "ATTESTATION_TIMEOUT";
        case EVENT_TRUST_LOST: return "TRUST_LOST";
        case EVENT_TRUST_REGAINED: return "TRUST_REGAINED";
        case EVENT_NETWORK_ATTEMPT_UNEXPECTED: return "NETWORK_ATTEMPT_UNEXPECTED";
        case EVENT_FIREWALL_DENIAL: return "FIREWALL_DENIAL";
        case EVENT_FIREWALL_RULE_CHANGE: return "FIREWALL_RULE_CHANGE";
        case EVENT_DNS_FAILURE: return "DNS_FAILURE";
        case EVENT_CONNECTIVITY_LOST: return "CONNECTIVITY_LOST";
        case EVENT_CONNECTIVITY_RESTORED: return "CONNECTIVITY_RESTORED";
        case EVENT_PROCESS_TERMINATION: return "PROCESS_TERMINATION";
        case EVENT_PROCESS_CRASH: return "PROCESS_CRASH";
        case EVENT_SERVICE_START: return "SERVICE_START";
        case EVENT_SERVICE_STOP: return "SERVICE_STOP";
        case EVENT_SERVICE_FAILURE: return "SERVICE_FAILURE";
        case EVENT_PROCESS_BEHAVIOR_ANOMALY: return "PROCESS_BEHAVIOR_ANOMALY";
        case EVENT_REMOVABLE_MEDIA_CONNECTED: return "REMOVABLE_MEDIA_CONNECTED";
        case EVENT_REMOVABLE_MEDIA_DISCONNECTED: return "REMOVABLE_MEDIA_DISCONNECTED";
        case EVENT_EXTERNAL_DISPLAY_ACTIVE: return "EXTERNAL_DISPLAY_ACTIVE";
        case EVENT_EXTERNAL_DISPLAY_INACTIVE: return "EXTERNAL_DISPLAY_INACTIVE";
        case EVENT_HARDWARE_ANOMALY: return "HARDWARE_ANOMALY";
        case EVENT_CLOCK_DRIFT: return "CLOCK_DRIFT";
        case EVENT_CLOCK_SKEW: return "CLOCK_SKEW";
        case EVENT_NTP_FAILURE: return "NTP_FAILURE";
        case EVENT_TIME_SYNC_FAILURE: return "TIME_SYNC_FAILURE";
        case EVENT_UPDATE_STARTED: return "UPDATE_STARTED";
        case EVENT_UPDATE_SUCCESS: return "UPDATE_SUCCESS";
        case EVENT_UPDATE_FAILED: return "UPDATE_FAILED";
        case EVENT_UPDATE_VERIFICATION_FAILED: return "UPDATE_VERIFICATION_FAILED";
        case EVENT_IMAGE_DIGEST_MISMATCH: return "IMAGE_DIGEST_MISMATCH";
        case EVENT_EXAM_SUBMISSION_SUCCESS: return "EXAM_SUBMISSION_SUCCESS";
        case EVENT_EXAM_SUBMISSION_FAILED: return "EXAM_SUBMISSION_FAILED";
        case EVENT_EXAM_SESSION_START: return "EXAM_SESSION_START";
        case EVENT_EXAM_SESSION_END: return "EXAM_SESSION_END";
        case EVENT_EXAM_TIMEOUT: return "EXAM_TIMEOUT";
        case EVENT_FACE_ABSENT: return "FACE_ABSENT";
        case EVENT_MULTIPLE_FACES: return "MULTIPLE_FACES";
        case EVENT_GAZE_DEVIATION: return "GAZE_DEVIATION";
        case EVENT_PHONE_DETECTED: return "PHONE_DETECTED";
        case EVENT_OBJECT_DETECTED: return "OBJECT_DETECTED";
        case EVENT_SYSTEM_STARTUP: return "SYSTEM_STARTUP";
        case EVENT_SYSTEM_SHUTDOWN: return "SYSTEM_SHUTDOWN";
        case EVENT_RESOURCE_EXHAUSTION: return "RESOURCE_EXHAUSTION";
        case EVENT_DISK_SPACE_LOW: return "DISK_SPACE_LOW";
        case EVENT_MEMORY_PRESSURE: return "MEMORY_PRESSURE";
        case EVENT_OPERATOR_LOGIN: return "OPERATOR_LOGIN";
        case EVENT_OPERATOR_LOGOUT: return "OPERATOR_LOGOUT";
        case EVENT_OPERATOR_ACTION: return "OPERATOR_ACTION";
        case EVENT_INCIDENT_CREATED: return "INCIDENT_CREATED";
        case EVENT_INCIDENT_ASSIGNED: return "INCIDENT_ASSIGNED";
        case EVENT_INCIDENT_RESOLVED: return "INCIDENT_RESOLVED";
        default: return "UNKNOWN";
    }
}

static const char* event_source_type_to_string_internal(event_source_type_t type) {
    switch (type) {
        case EVENT_SOURCE_AGENT: return "AGENT";
        case EVENT_SOURCE_PROCTORING: return "PROCTORING";
        case EVENT_SOURCE_KIOSK: return "KIOSK";
        case EVENT_SOURCE_FIREWALL: return "FIREWALL";
        case EVENT_SOURCE_SERVER: return "SERVER";
        case EVENT_SOURCE_PLATFORM: return "PLATFORM";
        case EVENT_SOURCE_OPERATOR: return "OPERATOR";
        case EVENT_SOURCE_AUTOMATED: return "AUTOMATED";
        default: return "UNKNOWN";
    }
}

static const char* event_classification_to_string_internal(event_classification_t classification) {
    switch (classification) {
        case EVENT_CLASSIFICATION_OBSERVED_FACT: return "OBSERVED_FACT";
        case EVENT_CLASSIFICATION_INFERRED_RISK: return "INFERRED_RISK";
        case EVENT_CLASSIFICATION_UNVERIFIED_SUSPICION: return "UNVERIFIED_SUSPICION";
        default: return "UNKNOWN";
    }
}

/* Validate event contains no sensitive data (passwords, keys, secrets) */
static int validate_no_sensitive_data(const security_event_t *event) {
    const char *sensitive_patterns[] = {
        "password", "passwd", "pwd", "secret", "key", "token", "credential",
        "private_key", "private", "session_secret", "auth_token"
    };
    
    /* Check details field */
    for (size_t i = 0; i < sizeof(sensitive_patterns) / sizeof(sensitive_patterns[0]); i++) {
        if (strstr(event->details, sensitive_patterns[i]) != NULL) {
            return 0;  /* Contains sensitive data */
        }
    }
    
    return 1;  /* Safe */
}

/* Sanitize details to remove sensitive information */
static void sanitize_details(char *details, size_t max_len) {
    if (!details || max_len == 0) return;
    details[max_len - 1] = '\0';
    const char *sensitive_patterns[] = {
        "password=", "passwd=", "pwd=", "secret=", "key=", "token=",
        "credential=", "private_key=", "private=", "session_secret=", "auth_token="
    };
    
    for (size_t i = 0; i < sizeof(sensitive_patterns) / sizeof(sensitive_patterns[0]); i++) {
        char *pos = strstr(details, sensitive_patterns[i]);
        if (pos) {
            /* Replace value with REDACTED */
            char *value_start = pos + strlen(sensitive_patterns[i]);
            char *value_end = strchr(value_start, '&');
            if (!value_end) value_end = strchr(value_start, ' ');
            if (!value_end) value_end = strchr(value_start, '\0');
            
            if (value_end) {
                size_t redact_len = value_end - value_start;
                memset(value_start, '*', redact_len);
            }
        }
    }
}

/* -----------------------------------------------------------------------
 * Journal Storage (Write-Ahead Log)
 * ----------------------------------------------------------------------- */

typedef struct {
    char event_id[EVENT_ID_MAX_LEN];
    long timestamp;
    char correlation_id[CORRELATION_ID_MAX_LEN];
    char source[SOURCE_MAX_LEN];
    int source_type;
    char device_id[DEVICE_ID_MAX_LEN];
    char session_id[SESSION_ID_MAX_LEN];
    char candidate_id[CANDIDATE_ID_MAX_LEN];
    int event_type;
    char event_type_str[EVENT_TYPE_MAX_LEN];
    int severity;
    int classification;
    char policy_version[POLICY_VERSION_MAX_LEN];
    char evidence_refs[EVIDENCE_REF_MAX_LEN];
    char details[EVENT_DETAILS_MAX_LEN];
    int processed;
    int correlated_to_incident;
    char incident_id[64];
} journal_record_t;

static int write_journal_record(const security_event_t *event) {
    if (!g_journal_file) return -1;
    
    journal_record_t rec;
    memset(&rec, 0, sizeof(rec));
    
    memcpy(rec.event_id, event->event_id, sizeof(rec.event_id));
    rec.event_id[sizeof(rec.event_id) - 1] = '\0';
    rec.timestamp = event->timestamp;
    memcpy(rec.correlation_id, event->correlation_id, sizeof(rec.correlation_id));
    rec.correlation_id[sizeof(rec.correlation_id) - 1] = '\0';
    memcpy(rec.source, event->source, sizeof(rec.source));
    rec.source[sizeof(rec.source) - 1] = '\0';
    rec.source_type = (int)event->source_type;
    memcpy(rec.device_id, event->device_id, sizeof(rec.device_id));
    rec.device_id[sizeof(rec.device_id) - 1] = '\0';
    memcpy(rec.session_id, event->session_id, sizeof(rec.session_id));
    rec.session_id[sizeof(rec.session_id) - 1] = '\0';
    memcpy(rec.candidate_id, event->candidate_id, sizeof(rec.candidate_id));
    rec.candidate_id[sizeof(rec.candidate_id) - 1] = '\0';
    rec.event_type = (int)event->event_type;
    memcpy(rec.event_type_str, event->event_type_str, sizeof(rec.event_type_str));
    rec.event_type_str[sizeof(rec.event_type_str) - 1] = '\0';
    rec.severity = (int)event->severity;
    rec.classification = (int)event->classification;
    memcpy(rec.policy_version, event->policy_version, sizeof(rec.policy_version));
    rec.policy_version[sizeof(rec.policy_version) - 1] = '\0';
    memcpy(rec.evidence_refs, event->evidence_refs, sizeof(rec.evidence_refs));
    rec.evidence_refs[sizeof(rec.evidence_refs) - 1] = '\0';
    memcpy(rec.details, event->details, sizeof(rec.details));
    rec.details[sizeof(rec.details) - 1] = '\0';
    rec.processed = event->processed;
    rec.correlated_to_incident = event->correlated_to_incident;
    memcpy(rec.incident_id, event->incident_id, sizeof(rec.incident_id));
    rec.incident_id[sizeof(rec.incident_id) - 1] = '\0';
    
    /* Write to journal as binary record */
    size_t written = fwrite(&rec, sizeof(journal_record_t), 1, g_journal_file);
    fflush(g_journal_file);
    fsync(fileno(g_journal_file));
    
    return (written == 1) ? 0 : -1;
}

/* -----------------------------------------------------------------------
 * Event Pipeline Lifecycle
 * ----------------------------------------------------------------------- */

int event_pipeline_init_with_config(const event_pipeline_config_t *config) {
    pthread_mutex_lock(&g_pipeline_lock);
    
    if (g_initialized) {
        pthread_mutex_unlock(&g_pipeline_lock);
        return 0;
    }
    
    if (config) {
        memcpy(&g_config, config, sizeof(g_config));
        strncpy(g_journal_path, g_config.journal_path, sizeof(g_journal_path) - 1);
        g_journal_path[sizeof(g_journal_path) - 1] = '\0';
        g_journal_max_size = g_config.journal_max_size_mb * 1024 * 1024;
        g_journal_rotation_count = g_config.journal_rotation_count;
        g_cache_eviction_policy = g_config.cache_eviction_policy;
        g_flush_interval_ms = g_config.flush_interval_ms;
        g_batch_write_size = g_config.batch_write_size;
        g_async_writes_enabled = g_config.async_writes_enabled;
        g_validate_sensitive_data = g_config.validate_sensitive_data;
        g_sanitize_details = g_config.sanitize_details;
        g_dedup_enabled = g_config.deduplication_enabled;
    } else {
        /* Load from environment if no config provided */
        event_pipeline_load_config_from_env(&g_config);
    }
    
    /* Allocate dynamic resources */
    if (allocate_event_cache(g_config.event_cache_size) != 0) {
        pthread_mutex_unlock(&g_pipeline_lock);
        return -1;
    }
    
    if (allocate_alert_rules(g_config.max_alert_rules) != 0) {
        free_all_resources();
        pthread_mutex_unlock(&g_pipeline_lock);
        return -1;
    }
    
    if (g_dedup_enabled && allocate_dedup_table(g_config.dedup_hash_table_size) != 0) {
        free_all_resources();
        pthread_mutex_unlock(&g_pipeline_lock);
        return -1;
    }
    
    /* Open journal file */
    g_journal_file = fopen(g_journal_path, "a+");
    if (!g_journal_file) {
        /* Ensure journal directory exists */
        char dir_path[512];
        strncpy(dir_path, g_journal_path, sizeof(dir_path) - 1);
        dir_path[sizeof(dir_path) - 1] = '\0';
        char *last_slash = strrchr(dir_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            mkdir(dir_path, 0755);
        }
        g_journal_file = fopen(g_journal_path, "a+");
    }
    
    if (!g_journal_file) {
        free_all_resources();
        pthread_mutex_unlock(&g_pipeline_lock);
        return -1;
    }
    
    /* Initialize deduplication table with default windows */
    if (g_dedup_table) {
        for (size_t i = 0; i < g_dedup_table_capacity; i++) {
            g_dedup_table[i].event_type = (event_type_t)-1;
            g_dedup_table[i].window_seconds = g_config.default_dedup_window_sec;
        }
    }
    
    g_initialized = 1;
    pthread_mutex_unlock(&g_pipeline_lock);
    
    /* Log to ledger */
    ledger_block_t blk;
    ledger_append_event("EVENT_PIPELINE_INITIALIZED", "SYSTEM",
                       "Durable event pipeline started", &blk);
    
    return 0;
}

int event_pipeline_init(const char *journal_path) {
    event_pipeline_config_t config;
    init_default_config(&config);
    
    if (journal_path && journal_path[0]) {
        strncpy(config.journal_path, journal_path, sizeof(config.journal_path) - 1);
    }
    
    return event_pipeline_init_with_config(&config);
}

int event_pipeline_shutdown(void) {
    pthread_mutex_lock(&g_pipeline_lock);
    
    if (!g_initialized) {
        pthread_mutex_unlock(&g_pipeline_lock);
        return 0;
    }
    
    if (g_journal_file) {
        fclose(g_journal_file);
        g_journal_file = NULL;
    }
    
    ledger_block_t blk;
    ledger_append_event("EVENT_PIPELINE_SHUTDOWN", "SYSTEM",
                       "Durable event pipeline stopped", &blk);
    
    free_all_resources();
    
    g_initialized = 0;
    pthread_mutex_unlock(&g_pipeline_lock);
    
    return 0;
}

/* -----------------------------------------------------------------------
 * Event Ingestion
 * ----------------------------------------------------------------------- */
int event_pipeline_ingest(const security_event_t *event) {
    if (!event || !event->event_id[0] || !event->correlation_id[0]) return -1;
    
    pthread_mutex_lock(&g_pipeline_lock);
    
    if (!g_initialized) {
        pthread_mutex_unlock(&g_pipeline_lock);
        return -1;
    }
    
    /* Write to journal first (durable) */
    if (write_journal_record(event) != 0) {
        pthread_mutex_unlock(&g_pipeline_lock);
        return -1;
    }
    
    /* Add to in-memory cache */
    if (g_event_cache && g_event_cache_capacity > 0) {
        /* Evict oldest if cache full (FIFO) */
        if (g_event_cache_count >= g_event_cache_capacity) {
            memmove(&g_event_cache[0], &g_event_cache[1], 
                   (g_event_cache_capacity - 1) * sizeof(security_event_t));
            g_event_cache_count = g_event_cache_capacity - 1;
        }
        
        memcpy(&g_event_cache[g_event_cache_count], event, sizeof(security_event_t));
        g_event_cache_count++;
    }
    
    g_total_events++;
    
    pthread_mutex_unlock(&g_pipeline_lock);
    return 0;
}

/* Helper ingestion functions */
int event_ingest_auth_failure(const char *device_id, const char *candidate_id,
                               const char *username, const char *reason,
                               event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "AUTH_SERVICE", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_SERVER;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    if (candidate_id) strncpy(event.candidate_id, candidate_id, sizeof(event.candidate_id) - 1);
    event.event_type = EVENT_AUTH_FAILURE;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Username: %s | Reason: %s",
             username ? username : "N/A", reason ? reason : "Unknown");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_policy_change(const char *device_id, const char *policy_version,
                                const char *changed_by, const char *change_description,
                                event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "POLICY_ENGINE", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_SERVER;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    if (policy_version) strncpy(event.policy_version, policy_version, sizeof(event.policy_version) - 1);
    event.event_type = EVENT_POLICY_CHANGE;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Changed by: %s | Description: %s",
             changed_by ? changed_by : "N/A", change_description ? change_description : "Unknown");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_enrollment(const char *device_id, const char *institution_id,
                            const char *enrolled_by, int success,
                            event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "ATTESTATION_SERVICE", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_SERVER;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    event.event_type = EVENT_DEVICE_ENROLLMENT;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Institution: %s | Enrolled by: %s | Success: %d",
             institution_id ? institution_id : "N/A", enrolled_by ? enrolled_by : "N/A", success);
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_revocation(const char *device_id, const char *revoked_by,
                            const char *reason, event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "ATTESTATION_SERVICE", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_SERVER;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    event.event_type = EVENT_DEVICE_REVOCATION;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Revoked by: %s | Reason: %s",
             revoked_by ? revoked_by : "N/A", reason ? reason : "Unknown");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_attestation_failed(const char *device_id, const char *session_id,
                                    const char *candidate_id, const char *failure_reason,
                                    event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "ATTESTATION_AGENT", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_AGENT;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    if (session_id) strncpy(event.session_id, session_id, sizeof(event.session_id) - 1);
    if (candidate_id) strncpy(event.candidate_id, candidate_id, sizeof(event.candidate_id) - 1);
    event.event_type = EVENT_ATTESTATION_FAILED;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Failure reason: %s | NOTE: This is NOT automatic cheating flag",
             failure_reason ? failure_reason : "Unknown");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_attestation_stale(const char *device_id, const char *session_id,
                                   const char *candidate_id, time_t last_attestation,
                                   event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "ATTESTATION_AGENT", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_AGENT;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    if (session_id) strncpy(event.session_id, session_id, sizeof(event.session_id) - 1);
    if (candidate_id) strncpy(event.candidate_id, candidate_id, sizeof(event.candidate_id) - 1);
    event.event_type = EVENT_ATTESTATION_STALE;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    time_t age = time(NULL) - last_attestation;
    snprintf(details, sizeof(details), "Last attestation: %ld seconds ago | NOTE: Stale telemetry, not cheating",
             (long)age);
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_network_attempt(const char *device_id, const char *source_ip,
                                  const char *dest_ip, const char *protocol,
                                  const char *reason, event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "FIREWALL_SERVICE", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_FIREWALL;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    event.event_type = EVENT_NETWORK_ATTEMPT_UNEXPECTED;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Source: %s | Dest: %s | Protocol: %s | Reason: %s",
             source_ip ? source_ip : "N/A", dest_ip ? dest_ip : "N/A",
             protocol ? protocol : "N/A", reason ? reason : "Unknown");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_firewall_denial(const char *device_id, const char *source_ip,
                                  const char *dest_port, const char *protocol,
                                  const char *rule_id, event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "FIREWALL_SERVICE", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_FIREWALL;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    event.event_type = EVENT_FIREWALL_DENIAL;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Source: %s | Port: %s | Protocol: %s | Rule: %s",
             source_ip ? source_ip : "N/A", dest_port ? dest_port : "N/A",
             protocol ? protocol : "N/A", rule_id ? rule_id : "N/A");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_kiosk_termination(const char *device_id, const char *session_id,
                                    const char *candidate_id, const char *termination_reason,
                                    int crash, event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "KIOSK_LAUNCHER", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_KIOSK;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    if (session_id) strncpy(event.session_id, session_id, sizeof(event.session_id) - 1);
    if (candidate_id) strncpy(event.candidate_id, candidate_id, sizeof(event.candidate_id) - 1);
    event.event_type = crash ? EVENT_PROCESS_CRASH : EVENT_PROCESS_TERMINATION;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Reason: %s | Crash: %d | NOTE: Process termination is NOT automatic cheating flag",
             termination_reason ? termination_reason : "Unknown", crash);
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_process_anomaly(const char *device_id, const char *process_name,
                                  const char *anomaly_type, const char *details_param,
                                  event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "AGENT", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_AGENT;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    event.event_type = EVENT_PROCESS_BEHAVIOR_ANOMALY;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_INFERRED_RISK;
    
    char details[512];
    snprintf(details, sizeof(details), "Process: %s | Anomaly: %s | Details: %s",
             process_name ? process_name : "N/A", anomaly_type ? anomaly_type : "Unknown",
             details_param ? details_param : "N/A");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_removable_media(const char *device_id, const char *media_label,
                                  const char *action, event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "AGENT", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_AGENT;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    event.event_type = (strcmp(action, "CONNECTED") == 0) ? 
                       EVENT_REMOVABLE_MEDIA_CONNECTED : EVENT_REMOVABLE_MEDIA_DISCONNECTED;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Media: %s | Action: %s",
             media_label ? media_label : "Unknown", action ? action : "Unknown");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_clock_drift(const char *device_id, long drift_seconds,
                              const char *ntp_server, event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "AGENT", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_AGENT;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    event.event_type = EVENT_CLOCK_DRIFT;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Drift: %ld seconds | NTP Server: %s",
             drift_seconds, ntp_server ? ntp_server : "N/A");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_config_tampering(const char *device_id, const char *config_path,
                                   const char *tampering_type, const char *details_param,
                                   event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "AGENT", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_AGENT;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    event.event_type = EVENT_CONFIG_TAMPERING;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Path: %s | Type: %s | Details: %s",
             config_path ? config_path : "N/A", tampering_type ? tampering_type : "Unknown",
             details_param ? details_param : "N/A");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_update_failure(const char *device_id, const char *release_id,
                                 const char *failure_stage, const char *error_message,
                                 event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "UPDATE_SERVICE", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_SERVER;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    event.event_type = EVENT_UPDATE_FAILED;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Release: %s | Stage: %s | Error: %s",
             release_id ? release_id : "N/A", failure_stage ? failure_stage : "Unknown",
             error_message ? error_message : "Unknown");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_submission_failure(const char *candidate_id, const char *exam_id,
                                    const char *session_id, const char *failure_reason,
                                    event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "EXAM_ENGINE", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_SERVER;
    if (candidate_id) strncpy(event.candidate_id, candidate_id, sizeof(event.candidate_id) - 1);
    if (session_id) strncpy(event.session_id, session_id, sizeof(event.session_id) - 1);
    event.event_type = EVENT_EXAM_SUBMISSION_FAILED;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Exam: %s | Reason: %s",
             exam_id ? exam_id : "N/A", failure_reason ? failure_reason : "Unknown");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

int event_ingest_checkin_failure(const char *device_id, int consecutive_failures,
                                  const char *failure_reason, event_severity_t severity) {
    security_event_t event;
    memset(&event, 0, sizeof(event));
    
    generate_event_id(event.event_id, sizeof(event.event_id));
    event.timestamp = time(NULL);
    generate_correlation_id(event.correlation_id, sizeof(event.correlation_id));
    strncpy(event.source, "AGENT", sizeof(event.source) - 1);
    event.source_type = EVENT_SOURCE_AGENT;
    if (device_id) strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    event.event_type = EVENT_DEVICE_CHECKIN_FAILURE;
    strncpy(event.event_type_str, event_type_to_string_internal(event.event_type), sizeof(event.event_type_str) - 1);
    event.severity = severity;
    event.classification = EVENT_CLASSIFICATION_OBSERVED_FACT;
    
    char details[512];
    snprintf(details, sizeof(details), "Consecutive failures: %d | Reason: %s",
             consecutive_failures, failure_reason ? failure_reason : "Unknown");
    memcpy(event.details, details, sizeof(event.details) - 1);
    event.details[sizeof(event.details) - 1] = '\0';
    
    return event_pipeline_ingest(&event);
}

/* -----------------------------------------------------------------------
 * Event Search and Filtering
 * ----------------------------------------------------------------------- */
int event_pipeline_search(const event_filter_t *filter, security_event_t *out_events,
                          int *out_count, int max_count) {
    if (!out_events || !out_count) return -1;
    
    pthread_mutex_lock(&g_pipeline_lock);
    
    *out_count = 0;
    int local_offset = filter ? filter->offset : 0;
    
    for (size_t i = 0; i < g_event_cache_count && *out_count < max_count; i++) {
        security_event_t *ev = &g_event_cache[i];
        
        /* Apply filters */
        if (filter) {
            if (filter->since > 0 && ev->timestamp < filter->since) continue;
            if (filter->until > 0 && ev->timestamp > filter->until) continue;
            if (filter->event_type > 0 && ev->event_type != filter->event_type) continue;
            if (filter->min_severity > 0 && ev->severity < filter->min_severity) continue;
            if (filter->classification >= 0 && ev->classification != filter->classification) continue;
            if (filter->device_id[0] && strcmp(ev->device_id, filter->device_id) != 0) continue;
            if (filter->candidate_id[0] && strcmp(ev->candidate_id, filter->candidate_id) != 0) continue;
            if (filter->correlation_id[0] && strcmp(ev->correlation_id, filter->correlation_id) != 0) continue;
            if (!filter->include_processed && ev->processed) continue;
        }
        
        /* Apply offset */
        if (local_offset > 0) {
            local_offset--;
            continue;
        }
        
        memcpy(&out_events[*out_count], ev, sizeof(security_event_t));
        (*out_count)++;
        
        if (filter && filter->limit > 0 && *out_count >= filter->limit) break;
    }
    
    pthread_mutex_unlock(&g_pipeline_lock);
    return 0;
}

int event_pipeline_get_by_correlation(const char *correlation_id,
                                       security_event_t *out_events,
                                       int *out_count, int max_count) {
    if (!correlation_id || !correlation_id[0]) return -1;
    
    event_filter_t filter;
    memset(&filter, 0, sizeof(filter));
    strncpy(filter.correlation_id, correlation_id, sizeof(filter.correlation_id) - 1);
    
    return event_pipeline_search(&filter, out_events, out_count, max_count);
}

int event_pipeline_get_by_device(const char *device_id, time_t since,
                                  security_event_t *out_events,
                                  int *out_count, int max_count) {
    if (!device_id || !device_id[0]) return -1;
    
    event_filter_t filter;
    memset(&filter, 0, sizeof(filter));
    strncpy(filter.device_id, device_id, sizeof(filter.device_id) - 1);
    filter.since = since;
    
    return event_pipeline_search(&filter, out_events, out_count, max_count);
}

int event_pipeline_get_by_candidate(const char *candidate_id, time_t since,
                                     security_event_t *out_events,
                                     int *out_count, int max_count) {
    if (!candidate_id || !candidate_id[0]) return -1;
    
    event_filter_t filter;
    memset(&filter, 0, sizeof(filter));
    strncpy(filter.candidate_id, candidate_id, sizeof(filter.candidate_id) - 1);
    filter.since = since;
    
    return event_pipeline_search(&filter, out_events, out_count, max_count);
}

int event_pipeline_export_json(const event_filter_t *filter, char *out_json, size_t max_len) {
    security_event_t events[100];
    int count = 0;
    
    if (event_pipeline_search(filter, events, &count, 100) != 0) {
        return -1;
    }
    
    /* Build JSON */
    snprintf(out_json, max_len, "{\"events\":[");
    size_t offset = strlen(out_json);
    
    for (int i = 0; i < count; i++) {
        char event_json[2048];
        int written = snprintf(event_json, sizeof(event_json),
                 "%s{\"event_id\":\"%s\",\"timestamp\":%ld,\"correlation_id\":\"%s\","
                 "\"source\":\"%s\",\"device_id\":\"%s\",\"candidate_id\":\"%s\","
                 "\"event_type\":\"%s\",\"severity\":%d,\"classification\":\"%s\","
                 "\"details\":\"%s\"}",
                 (i > 0) ? "," : "",
                 events[i].event_id, (long)events[i].timestamp, events[i].correlation_id,
                 events[i].source, events[i].device_id, events[i].candidate_id,
                 events[i].event_type_str, events[i].severity,
                 event_classification_to_string_internal(events[i].classification),
                 events[i].details);
        
        if (written < 0 || written >= (int)sizeof(event_json)) {
            continue;  /* Skip if truncated */
        }
        
        if (offset + strlen(event_json) < max_len - 10) {
            strcat(out_json, event_json);
            offset += strlen(event_json);
        }
    }
    
    strcat(out_json, "]}");
    return 0;
}

/* -----------------------------------------------------------------------
 * Severity Classification
 * ----------------------------------------------------------------------- */
event_severity_t event_pipeline_classify_severity(event_type_t event_type,
                                                   const char *context) {
    (void)context;  /* Context can be used for future enhancements */
    
    switch (event_type) {
        case EVENT_AUTH_FAILURE:
            return SEV_LOW;
        case EVENT_AUTH_LOCKOUT:
            return SEV_MEDIUM;
        case EVENT_CONFIG_TAMPERING:
            return SEV_CRITICAL;
        case EVENT_ATTESTATION_FAILED:
            return SEV_HIGH;
        case EVENT_ATTESTATION_STALE:
            return SEV_MEDIUM;
        case EVENT_FIREWALL_DENIAL:
            return SEV_MEDIUM;
        case EVENT_NETWORK_ATTEMPT_UNEXPECTED:
            return SEV_HIGH;
        case EVENT_PROCESS_CRASH:
            return SEV_MEDIUM;
        case EVENT_REMOVABLE_MEDIA_CONNECTED:
            return SEV_HIGH;
        case EVENT_CLOCK_DRIFT:
            return SEV_LOW;
        case EVENT_UPDATE_VERIFICATION_FAILED:
            return SEV_HIGH;
        case EVENT_EXAM_SUBMISSION_FAILED:
            return SEV_HIGH;
        case EVENT_DEVICE_CHECKIN_FAILURE:
            return SEV_MEDIUM;
        default:
            return SEV_INFO;
    }
}

int event_pipeline_override_severity(const char *event_id, event_severity_t new_severity,
                                     const char *reason, const char *operator_id) {
    if (!event_id || !event_id[0]) return -1;
    
    pthread_mutex_lock(&g_pipeline_lock);
    
    for (size_t i = 0; i < g_event_cache_count; i++) {
        if (strcmp(g_event_cache[i].event_id, event_id) == 0) {
            g_event_cache[i].severity = new_severity;
            
            /* Log to ledger */
            char details[512];
            snprintf(details, sizeof(details),
                     "Severity override for event %s: new_severity=%d reason=%s operator=%s",
                     event_id, new_severity, reason ? reason : "N/A", operator_id ? operator_id : "N/A");
            
            ledger_block_t blk;
            ledger_append_event("SEVERITY_OVERRIDE", operator_id ? operator_id : "SYSTEM", details, &blk);
            
            pthread_mutex_unlock(&g_pipeline_lock);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&g_pipeline_lock);
    return -1;
}

/* -----------------------------------------------------------------------
 * Alert Rules Management
 * ----------------------------------------------------------------------- */
int event_pipeline_create_alert_rule(const alert_rule_t *rule) {
    if (!rule || !g_initialized) return -1;
    
    pthread_mutex_lock(&g_pipeline_lock);
    
    if (!g_alert_rules || g_alert_rule_count >= g_alert_rules_capacity) {
        pthread_mutex_unlock(&g_pipeline_lock);
        return -1;
    }
    
    memcpy(&g_alert_rules[g_alert_rule_count], rule, sizeof(alert_rule_t));
    g_alert_rule_count++;
    
    pthread_mutex_unlock(&g_pipeline_lock);
    return 0;
}

int event_pipeline_get_alert_rule(const char *rule_id, alert_rule_t *out_rule) {
    if (!rule_id || !rule_id[0] || !out_rule) return -1;
    
    pthread_mutex_lock(&g_pipeline_lock);
    
    for (size_t i = 0; i < g_alert_rule_count; i++) {
        if (strcmp(g_alert_rules[i].rule_id, rule_id) == 0) {
            memcpy(out_rule, &g_alert_rules[i], sizeof(alert_rule_t));
            pthread_mutex_unlock(&g_pipeline_lock);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&g_pipeline_lock);
    return -1;
}

int event_pipeline_list_alert_rules(alert_rule_t *out_rules, int *out_count, int max_count) {
    if (!out_rules || !out_count) return -1;
    
    pthread_mutex_lock(&g_pipeline_lock);
    
    int copy_count = (int)g_alert_rule_count;
    if (copy_count > max_count) copy_count = max_count;
    
    if (g_alert_rules && copy_count > 0) {
        memcpy(out_rules, g_alert_rules, copy_count * sizeof(alert_rule_t));
    }
    *out_count = copy_count;
    
    pthread_mutex_unlock(&g_pipeline_lock);
    return 0;
}

/* -----------------------------------------------------------------------
 * Deduplication
 * ----------------------------------------------------------------------- */
int event_pipeline_is_duplicate(const security_event_t *event, int *out_is_duplicate,
                                 char *out_original_event_id) {
    if (!event || !out_is_duplicate) return -1;
    
    pthread_mutex_lock(&g_pipeline_lock);
    
    /* Find dedup window for this event type */
    int window = g_config.default_dedup_window_sec;
    if (g_dedup_table) {
        for (size_t i = 0; i < g_dedup_table_capacity; i++) {
            if (g_dedup_table[i].event_type == event->event_type) {
                window = g_dedup_table[i].window_seconds;
                break;
            }
        }
    }
    
    time_t now = time(NULL);
    
    *out_is_duplicate = 0;
    if (out_original_event_id) out_original_event_id[0] = '\0';
    
    /* Search for similar events within window */
    for (size_t i = 0; i < g_event_cache_count; i++) {
        security_event_t *ev = &g_event_cache[i];
        
        if (ev->event_type == event->event_type &&
            strcmp(ev->device_id, event->device_id) == 0 &&
            (now - ev->timestamp) <= window) {
            *out_is_duplicate = 1;
            if (out_original_event_id) {
                strncpy(out_original_event_id, ev->event_id, EVENT_ID_MAX_LEN - 1);
                out_original_event_id[EVENT_ID_MAX_LEN - 1] = '\0';
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&g_pipeline_lock);
    return 0;
}

int event_pipeline_set_deduplication_window(event_type_t event_type, int window_seconds) {
    pthread_mutex_lock(&g_pipeline_lock);
    
    if (!g_dedup_table || g_dedup_table_capacity == 0) {
        pthread_mutex_unlock(&g_pipeline_lock);
        return -1;
    }
    
    /* Find existing entry or find empty slot */
    size_t empty_slot = g_dedup_table_capacity;
    for (size_t i = 0; i < g_dedup_table_capacity; i++) {
        if (g_dedup_table[i].event_type == event_type) {
            g_dedup_table[i].window_seconds = window_seconds;
            pthread_mutex_unlock(&g_pipeline_lock);
            return 0;
        }
        if (g_dedup_table[i].event_type == (event_type_t)-1 && empty_slot == g_dedup_table_capacity) {
            empty_slot = i;
        }
    }
    
    /* Add new entry if slot found */
    if (empty_slot < g_dedup_table_capacity) {
        g_dedup_table[empty_slot].event_type = event_type;
        g_dedup_table[empty_slot].window_seconds = window_seconds;
        pthread_mutex_unlock(&g_pipeline_lock);
        return 0;
    }
    
    pthread_mutex_unlock(&g_pipeline_lock);
    return -1;
}

/* -----------------------------------------------------------------------
 * Statistics
 * ----------------------------------------------------------------------- */
int event_pipeline_get_stats(event_pipeline_stats_t *out_stats) {
    if (!out_stats) return -1;
    
    pthread_mutex_lock(&g_pipeline_lock);
    
    memset(out_stats, 0, sizeof(event_pipeline_stats_t));
    out_stats->total_events = g_total_events;
    
    time_t now = time(NULL);
    time_t hour_ago = now - 3600;
    time_t day_ago = now - 86400;
    
    for (size_t i = 0; i < g_event_cache_count; i++) {
        security_event_t *ev = &g_event_cache[i];
        
        if (ev->severity >= 0 && ev->severity <= 4) {
            out_stats->events_by_severity[ev->severity]++;
        }
        
        if (ev->classification >= 0 && ev->classification <= 2) {
            out_stats->events_by_classification[ev->classification]++;
        }
        
        if (ev->timestamp >= hour_ago) {
            out_stats->events_last_hour++;
        }
        if (ev->timestamp >= day_ago) {
            out_stats->events_last_24h++;
        }
        
        if (ev->timestamp > out_stats->last_event_time) {
            out_stats->last_event_time = ev->timestamp;
        }
    }
    
    out_stats->open_alerts = -1;
    out_stats->unresolved_incidents = -1;
    
    pthread_mutex_unlock(&g_pipeline_lock);
    return -1;
}

/* -----------------------------------------------------------------------
 * Utility Functions (Public API)
 * ----------------------------------------------------------------------- */
const char* event_type_to_string(event_type_t type) {
    return event_type_to_string_internal(type);
}

const char* event_source_type_to_string(event_source_type_t type) {
    return event_source_type_to_string_internal(type);
}

const char* event_classification_to_string(event_classification_t classification) {
    return event_classification_to_string_internal(classification);
}

int event_pipeline_generate_correlation_id(char *out_correlation_id, size_t max_len) {
    return generate_correlation_id(out_correlation_id, max_len);
}

int event_pipeline_validate_no_sensitive_data(const security_event_t *event) {
    return validate_no_sensitive_data(event);
}

int event_pipeline_sanitize_details(char *details, size_t max_len) {
    sanitize_details(details, max_len);
    return 0;
}

/* -----------------------------------------------------------------------
 * Placeholder implementations for features not yet fully implemented
 * ----------------------------------------------------------------------- */
int event_pipeline_update_alert_rule(const char *rule_id, const alert_rule_t *rule) {
    (void)rule_id; (void)rule;
    return -1;  /* TODO: Implement */
}

int event_pipeline_delete_alert_rule(const char *rule_id) {
    (void)rule_id;
    return -1;  /* TODO: Implement */
}

int event_pipeline_enable_alert_rule(const char *rule_id, int enabled) {
    (void)rule_id; (void)enabled;
    return -1;  /* TODO: Implement */
}

int event_pipeline_get_alerts(const char *rule_id, time_t since,
                              security_alert_t *out_alerts,
                              int *out_count, int max_count) {
    (void)rule_id; (void)since; (void)out_alerts; (void)out_count; (void)max_count;
    return -1;  /* TODO: Implement */
}

int event_pipeline_acknowledge_alert(const char *alert_id, const char *operator_id) {
    (void)alert_id; (void)operator_id;
    return -1;  /* TODO: Implement */
}

int event_pipeline_resolve_alert(const char *alert_id, const char *operator_id,
                                  const char *resolution_notes) {
    (void)alert_id; (void)operator_id; (void)resolution_notes;
    return -1;  /* TODO: Implement */
}

int event_pipeline_create_incident(const char *event_id, const char *alert_id,
                                   const char *title, event_severity_t severity,
                                   const char *assigned_to, const char *created_by,
                                   char *out_incident_id) {
    (void)event_id; (void)alert_id; (void)title; (void)severity;
    (void)assigned_to; (void)created_by; (void)out_incident_id;
    return -1;  /* TODO: Implement - integrate with enterprise_platform */
}

int event_pipeline_auto_create_incident(const security_alert_t *alert,
                                         const alert_rule_t *rule,
                                         char *out_incident_id) {
    (void)alert; (void)rule; (void)out_incident_id;
    return -1;  /* TODO: Implement */
}

int event_pipeline_link_to_incident(const char *event_id, const char *incident_id,
                                     const char *operator_id) {
    (void)event_id; (void)incident_id; (void)operator_id;
    return -1;  /* TODO: Implement */
}

int event_pipeline_add_investigation_note(const char *incident_id,
                                          const char *event_id,
                                          const char *author,
                                          const char *note,
                                          const char *evidence_refs,
                                          char *out_note_id) {
    (void)incident_id; (void)event_id; (void)author; (void)note;
    (void)evidence_refs; (void)out_note_id;
    return -1;  /* TODO: Implement */
}

int event_pipeline_get_investigation_notes(const char *incident_id,
                                           investigation_note_t *out_notes,
                                           int *out_count, int max_count) {
    (void)incident_id; (void)out_notes; (void)out_count; (void)max_count;
    return -1;  /* TODO: Implement */
}

int event_pipeline_execute_containment(const char *incident_id,
                                       const char *action_type,
                                       const char *description,
                                       const char *executed_by,
                                       char *out_action_id) {
    (void)incident_id; (void)action_type; (void)description; (void)executed_by; (void)out_action_id;
    return -1;  /* TODO: Implement */
}

int event_pipeline_execute_recovery(const char *incident_id,
                                    const char *action_type,
                                    const char *description,
                                    const char *executed_by,
                                    char *out_action_id) {
    (void)incident_id; (void)action_type; (void)description; (void)executed_by; (void)out_action_id;
    return -1;  /* TODO: Implement */
}

int event_pipeline_get_containment_actions(const char *incident_id,
                                           containment_action_t *out_actions,
                                           int *out_count, int max_count) {
    (void)incident_id; (void)out_actions; (void)out_count; (void)max_count;
    return -1;  /* TODO: Implement */
}

int event_pipeline_get_incident_timeline(const char *incident_id,
                                        incident_timeline_t *out_timeline,
                                        int *out_count, int max_count) {
    (void)incident_id; (void)out_timeline; (void)out_count; (void)max_count;
    return -1;  /* TODO: Implement */
}

int event_pipeline_add_status_change(const char *incident_id,
                                     const char *old_status,
                                     const char *new_status,
                                     const char *changed_by) {
    (void)incident_id; (void)old_status; (void)new_status; (void)changed_by;
    return -1;  /* TODO: Implement */
}

int event_pipeline_resolve_incident(const char *incident_id,
                                    const char *resolution_notes,
                                    const char *lessons_learned,
                                    const char *resolved_by) {
    (void)incident_id; (void)resolution_notes; (void)lessons_learned; (void)resolved_by;
    return -1;  /* TODO: Implement - integrate with enterprise_platform */
}

int event_pipeline_get_incident_review(const char *incident_id, char *out_json, size_t max_len) {
    (void)incident_id; (void)out_json; (void)max_len;
    return -1;  /* TODO: Implement */
}

int event_pipeline_generate_summary_report(time_t since, char *out_json, size_t max_len) {
    (void)since; (void)out_json; (void)max_len;
    return -1;  /* TODO: Implement */
}

int event_pipeline_generate_correlation_report(const char *correlation_id,
                                               char *out_json, size_t max_len) {
    (void)correlation_id; (void)out_json; (void)max_len;
    return -1;  /* TODO: Implement */
}
