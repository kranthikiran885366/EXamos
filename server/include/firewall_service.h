#ifndef EXAMOS_FIREWALL_SERVICE_H
#define EXAMOS_FIREWALL_SERVICE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define FIREWALL_MAX_HOSTS       16
#define FIREWALL_MAX_IPS         32
#define FIREWALL_CONF_DEFAULT    "/etc/nftables.conf"
#define FIREWALL_CONF_BACKUP     "/etc/nftables.conf.bak"
#define FIREWALL_SAFE_FALLBACK   "/etc/nftables.conf.safe"
#define DEPLOYMENT_CONF_PATH     "/etc/examos/deployment.conf"

/*
 * firewall_policy_t — Represents an evaluated, authorized firewall ruleset configuration
 */
typedef struct {
    char dns_primary[64];
    char dns_secondary[64];
    char exam_server_ips[FIREWALL_MAX_IPS][64];
    int  exam_server_ip_count;
    char ntp_primary[64];
    char ntp_secondary[64];
    char ocsp_responder_ip[64];
    char allowed_admin_subnets[4][64];
    int  admin_subnet_count;
    int  log_rate_limit_per_min;
    time_t generated_at;
} firewall_policy_t;

/* Status of firewall runtime state */
typedef struct {
    int  active;                   /* 1 if nftables ruleset is actively loaded */
    int  default_deny_inbound;     /* 1 if input hook policy is drop */
    int  default_deny_outbound;    /* 1 if output hook policy is drop */
    int  loopback_isolated;        /* 1 if lo is allowed */
    int  dns_enforced;             /* 1 if DNS is pinned */
    int  exam_endpoints_enforced;  /* 1 if exam IPs are allowed */
    int  rules_count;              /* Count of active rules */
    char status_str[32];           /* ACTIVE, DEGRADED, RECOVERED, INACTIVE */
    char last_applied_sig[65];
    time_t last_applied_time;
} firewall_status_t;

/* Initialize firewall subsystem and generate safe fallback ruleset if missing */
int firewall_init(const char *state_dir);

/* Load network targets from /etc/examos/deployment.conf */
int firewall_load_deployment_conf(firewall_policy_t *policy);

/* Resolve an approved exam URL / hostname into validated, non-broad IP addresses */
int firewall_resolve_exam_endpoint(const char *exam_url, firewall_policy_t *policy, char *err_msg, size_t err_len);

/* Synthesize a complete default-deny nftables ruleset in buffer */
int firewall_generate_ruleset_text(const firewall_policy_t *policy, char *out_ruleset, size_t max_len);

/* Validate ruleset syntax and safety constraints without altering the running firewall */
int firewall_validate_ruleset(const char *ruleset_text, char *err_msg, size_t err_len);

/*
 * Atomically apply ruleset with fail-safe test and automatic rollback to safe ruleset
 * if connectivity to management/recovery services or rule loading fails.
 */
int firewall_apply_ruleset(const char *ruleset_text, const char *actor, char *err_msg, size_t err_len);

/* Rollback to previously active or safe backup configuration */
int firewall_rollback_to_safe(const char *actor, char *err_msg, size_t err_len);

/* Query live firewall status */
int firewall_get_status(firewall_status_t *status);

/* Format firewall status as JSON */
int firewall_get_status_json(char *out_json, size_t max_len);

/* Test end-to-end network connectivity against approved policy targets */
int firewall_test_network_connectivity(const char *test_target_url, char *out_result_json, size_t max_len);

#endif /* EXAMOS_FIREWALL_SERVICE_H */
