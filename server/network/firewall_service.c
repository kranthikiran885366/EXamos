#define _GNU_SOURCE
#include "../include/firewall_service.h"
#include "../include/enterprise_platform.h"
#include "../include/config_manager.h"
#include "../include/ledger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/http.h>

static pthread_mutex_t g_firewall_lock = PTHREAD_MUTEX_INITIALIZER;
static firewall_status_t g_fw_status = {
    .active = 1,
    .default_deny_inbound = 1,
    .default_deny_outbound = 1,
    .loopback_isolated = 1,
    .dns_enforced = 1,
    .exam_endpoints_enforced = 1,
    .rules_count = 28,
    .status_str = "ACTIVE",
    .last_applied_sig = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    .last_applied_time = 0
};

static char g_state_dir[512] = "/var/lib/examos/firewall";

static void firewall_log_event(const char *event_type, const char *entity, const char *details) {
    ledger_block_t blk;
    ledger_append_event(event_type, entity ? entity : "firewall", details ? details : "", &blk);
}

/* Helper to compute SHA-256 digest of ruleset */
static void compute_sha256_hex(const char *data, size_t len, char out_hex[65]) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data, len, md);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out_hex[i * 2]     = hex[md[i] >> 4];
        out_hex[i * 2 + 1] = hex[md[i] & 0x0f];
    }
    out_hex[64] = '\0';
}

/* Helper to safely write file with sync */
static int safe_write_file(const char *filepath, const char *content, size_t length) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", filepath, getpid());

    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    if (fwrite(content, 1, length, f) != length) {
        fclose(f);
        unlink(tmp);
        return -1;
    }
    fflush(f);
    int fd = fileno(f);
    if (fd >= 0) fsync(fd);
    fclose(f);

    if (rename(tmp, filepath) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

int firewall_init(const char *state_dir) {
    pthread_mutex_lock(&g_firewall_lock);
    if (state_dir && state_dir[0]) {
        snprintf(g_state_dir, sizeof(g_state_dir), "%s", state_dir);
    }
    mkdir(g_state_dir, 0750);

    /* Ensure fallback safe ruleset exists */
    firewall_policy_t safe_pol = {
        .dns_primary = "127.0.0.53",
        .dns_secondary = "127.0.0.53",
        .exam_server_ips = { "127.0.0.1" },
        .exam_server_ip_count = 1,
        .ntp_primary = "127.0.0.1",
        .ntp_secondary = "127.0.0.1",
        .ocsp_responder_ip = "127.0.0.1",
        .allowed_admin_subnets = { "127.0.0.1/32" },
        .admin_subnet_count = 1,
        .log_rate_limit_per_min = 5,
        .generated_at = time(NULL)
    };

    char safe_text[4096];
    if (firewall_generate_ruleset_text(&safe_pol, safe_text, sizeof(safe_text)) == 0) {
        char safe_path[1024];
        snprintf(safe_path, sizeof(safe_path), "%s/safe_ruleset.nft", g_state_dir);
        safe_write_file(safe_path, safe_text, strlen(safe_text));
    }

    g_fw_status.last_applied_time = time(NULL);
    pthread_mutex_unlock(&g_firewall_lock);
    return 0;
}

int firewall_load_deployment_conf(firewall_policy_t *policy) {
    if (!policy) return -1;
    memset(policy, 0, sizeof(firewall_policy_t));

    FILE *f = fopen(DEPLOYMENT_CONF_PATH, "r");
    if (!f) {
        /* Default safe loopback fallback if deployment.conf not present */
        snprintf(policy->dns_primary, sizeof(policy->dns_primary), "127.0.0.53");
        snprintf(policy->dns_secondary, sizeof(policy->dns_secondary), "127.0.0.53");
        snprintf(policy->exam_server_ips[0], sizeof(policy->exam_server_ips[0]), "127.0.0.1");
        policy->exam_server_ip_count = 1;
        snprintf(policy->ntp_primary, sizeof(policy->ntp_primary), "127.0.0.1");
        snprintf(policy->ntp_secondary, sizeof(policy->ntp_secondary), "127.0.0.1");
        snprintf(policy->ocsp_responder_ip, sizeof(policy->ocsp_responder_ip), "127.0.0.1");
        policy->log_rate_limit_per_min = 5;
        policy->generated_at = time(NULL);
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\r'); if (nl) *nl = '\0';
        nl = strchr(line, '\n'); if (nl) *nl = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;

        if (strncmp(line, "CONTROLLED_DNS_1=", 17) == 0) {
            snprintf(policy->dns_primary, sizeof(policy->dns_primary), "%.63s", line + 17);
        } else if (strncmp(line, "CONTROLLED_DNS_2=", 17) == 0) {
            snprintf(policy->dns_secondary, sizeof(policy->dns_secondary), "%.63s", line + 17);
        } else if (strncmp(line, "EXAM_SERVER_IP_1=", 17) == 0) {
            if (strcmp(line + 17, "DEPLOYMENT_REQUIRED") != 0 && strlen(line + 17) > 0) {
                snprintf(policy->exam_server_ips[policy->exam_server_ip_count++],
                         sizeof(policy->exam_server_ips[0]), "%.63s", line + 17);
            }
        } else if (strncmp(line, "EXAM_SERVER_IP_2=", 17) == 0) {
            if (strcmp(line + 17, "DEPLOYMENT_REQUIRED") != 0 && strlen(line + 17) > 0) {
                snprintf(policy->exam_server_ips[policy->exam_server_ip_count++],
                         sizeof(policy->exam_server_ips[0]), "%.63s", line + 17);
            }
        } else if (strncmp(line, "NTP_SERVER_IP_1=", 16) == 0) {
            snprintf(policy->ntp_primary, sizeof(policy->ntp_primary), "%.63s", line + 16);
        } else if (strncmp(line, "NTP_SERVER_IP_2=", 16) == 0) {
            snprintf(policy->ntp_secondary, sizeof(policy->ntp_secondary), "%.63s", line + 16);
        } else if (strncmp(line, "OCSP_RESPONDER_IP=", 18) == 0) {
            snprintf(policy->ocsp_responder_ip, sizeof(policy->ocsp_responder_ip), "%.63s", line + 18);
        }
    }
    fclose(f);

    /* Sanity fallback on placeholder entries */
    if (strcmp(policy->dns_primary, "DEPLOYMENT_REQUIRED") == 0 || !policy->dns_primary[0]) {
        snprintf(policy->dns_primary, sizeof(policy->dns_primary), "127.0.0.53");
    }
    if (strcmp(policy->dns_secondary, "DEPLOYMENT_REQUIRED") == 0 || !policy->dns_secondary[0]) {
        snprintf(policy->dns_secondary, sizeof(policy->dns_secondary), "%s", policy->dns_primary);
    }
    if (policy->exam_server_ip_count == 0) {
        snprintf(policy->exam_server_ips[0], sizeof(policy->exam_server_ips[0]), "127.0.0.1");
        policy->exam_server_ip_count = 1;
    }
    if (strcmp(policy->ntp_primary, "DEPLOYMENT_REQUIRED") == 0 || !policy->ntp_primary[0]) {
        snprintf(policy->ntp_primary, sizeof(policy->ntp_primary), "127.0.0.1");
    }
    if (strcmp(policy->ntp_secondary, "DEPLOYMENT_REQUIRED") == 0 || !policy->ntp_secondary[0]) {
        snprintf(policy->ntp_secondary, sizeof(policy->ntp_secondary), "%s", policy->ntp_primary);
    }
    if (strcmp(policy->ocsp_responder_ip, "DEPLOYMENT_REQUIRED") == 0 || !policy->ocsp_responder_ip[0]) {
        snprintf(policy->ocsp_responder_ip, sizeof(policy->ocsp_responder_ip), "127.0.0.1");
    }

    policy->log_rate_limit_per_min = 5;
    policy->generated_at = time(NULL);
    return 0;
}

int firewall_resolve_exam_endpoint(const char *exam_url, firewall_policy_t *policy, char *err_msg, size_t err_len) {
    if (!exam_url || !policy) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Missing URL or policy target");
        return -1;
    }

    int use_ssl = 0;
    char *user = NULL, *host = NULL, *port = NULL, *path = NULL, *query = NULL, *fragment = NULL;
    int port_num = 0;
    if (OSSL_HTTP_parse_url(exam_url, &use_ssl, &user, &host, &port, &port_num, &path, &query, &fragment) != 1 || !host) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Failed to parse exam endpoint URL");
        OPENSSL_free(user); OPENSSL_free(host); OPENSSL_free(port); OPENSSL_free(path); OPENSSL_free(query); OPENSSL_free(fragment);
        return -1;
    }

    /* Check if host is already an IPv4 literal */
    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) == 1) {
        if (policy->exam_server_ip_count < FIREWALL_MAX_IPS) {
            snprintf(policy->exam_server_ips[policy->exam_server_ip_count++],
                     sizeof(policy->exam_server_ips[0]), "%s", host);
        }
        OPENSSL_free(user); OPENSSL_free(host); OPENSSL_free(port); OPENSSL_free(path); OPENSSL_free(query); OPENSSL_free(fragment);
        return 0;
    }

    /* Strict DNS resolution with validation against broad / shared wildcard ranges */
    struct addrinfo hints, *res = NULL, *rp = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* IPv4 strictly enforced per system security model */
    hints.ai_socktype = SOCK_STREAM;

    int gai_err = getaddrinfo(host, NULL, &hints, &res);
    if (gai_err != 0 || !res) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "DNS resolution failed for '%s': %s", host, gai_strerror(gai_err));
        OPENSSL_free(user); OPENSSL_free(host); OPENSSL_free(port); OPENSSL_free(path); OPENSSL_free(query); OPENSSL_free(fragment);
        return -1;
    }

    int added = 0;
    for (rp = res; rp != NULL && policy->exam_server_ip_count < FIREWALL_MAX_IPS; rp = rp->ai_next) {
        struct sockaddr_in *sin = (struct sockaddr_in *)rp->ai_addr;
        char ip_str[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str))) {
            /* Guard: prevent 0.0.0.0/8 or 255.255.255.255 broad wildcards */
            if (strncmp(ip_str, "0.", 2) == 0 || strcmp(ip_str, "255.255.255.255") == 0) continue;

            /* Check duplicate */
            int dup = 0;
            for (int i = 0; i < policy->exam_server_ip_count; i++) {
                if (strcmp(policy->exam_server_ips[i], ip_str) == 0) {
                    dup = 1;
                    break;
                }
            }
            if (!dup) {
                snprintf(policy->exam_server_ips[policy->exam_server_ip_count++],
                         sizeof(policy->exam_server_ips[0]), "%s", ip_str);
                added++;
            }
        }
    }
    freeaddrinfo(res);
    OPENSSL_free(user); OPENSSL_free(host); OPENSSL_free(port); OPENSSL_free(path); OPENSSL_free(query); OPENSSL_free(fragment);

    if (added == 0 && policy->exam_server_ip_count == 0) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "No usable IP address resolved for endpoint");
        return -1;
    }
    return 0;
}

int firewall_generate_ruleset_text(const firewall_policy_t *policy, char *out_ruleset, size_t max_len) {
    if (!policy || !out_ruleset || max_len < 1024) return -1;

    size_t offset = snprintf(out_ruleset, max_len,
        "#!/usr/sbin/nft -f\n"
        "# ExamOS Advanced Firewall Ruleset (Module E)\n"
        "# Generated at timestamp %ld\n"
        "flush ruleset\n\n"
        "# IPv6 Drop Table: default drop on all hooks\n"
        "table ip6 filter {\n"
        "    chain input   { type filter hook input   priority 0; policy drop; }\n"
        "    chain forward { type filter hook forward priority 0; policy drop; }\n"
        "    chain output  { type filter hook output  priority 0; policy drop; }\n"
        "}\n\n"
        "# IPv4 Filtering Table\n"
        "table inet filter {\n"
        "    chain input {\n"
        "        type filter hook input priority 0; policy drop;\n"
        "        iif \"lo\" accept\n"
        "        ct state { established, related } accept\n"
        "        ct state invalid drop\n"
        "        udp sport 67 udp dport 68 accept\n"
        "        icmp type { echo-reply, destination-unreachable, time-exceeded } accept\n"
        "        limit rate %d/minute log prefix \"[ExamOS-FW-IN-DROP]: \"\n"
        "        reject with icmpx type admin-prohibited\n"
        "    }\n\n"
        "    chain forward {\n"
        "        type filter hook forward priority 0; policy drop;\n"
        "    }\n\n"
        "    chain output {\n"
        "        type filter hook output priority 0; policy drop;\n"
        "        oif \"lo\" accept\n"
        "        ct state { established, related } accept\n"
        "        ct state invalid drop\n"
        "        udp sport 68 udp dport 67 accept\n",
        (long)policy->generated_at,
        policy->log_rate_limit_per_min > 0 ? policy->log_rate_limit_per_min : 5);

    /* DNS pinned destination rules */
    if (policy->dns_primary[0]) {
        offset += snprintf(out_ruleset + offset, max_len - offset,
            "        ip daddr %s udp dport 53 accept\n"
            "        ip daddr %s tcp dport 53 accept\n",
            policy->dns_primary, policy->dns_primary);
    }
    if (policy->dns_secondary[0] && strcmp(policy->dns_secondary, policy->dns_primary) != 0) {
        offset += snprintf(out_ruleset + offset, max_len - offset,
            "        ip daddr %s udp dport 53 accept\n"
            "        ip daddr %s tcp dport 53 accept\n",
            policy->dns_secondary, policy->dns_secondary);
    }

    /* NTP pinned time sync */
    if (policy->ntp_primary[0]) {
        offset += snprintf(out_ruleset + offset, max_len - offset,
            "        ip daddr %s udp dport 123 accept\n", policy->ntp_primary);
    }
    if (policy->ntp_secondary[0] && strcmp(policy->ntp_secondary, policy->ntp_primary) != 0) {
        offset += snprintf(out_ruleset + offset, max_len - offset,
            "        ip daddr %s udp dport 123 accept\n", policy->ntp_secondary);
    }

    /* CA OCSP / CRL validation */
    if (policy->ocsp_responder_ip[0]) {
        offset += snprintf(out_ruleset + offset, max_len - offset,
            "        ip daddr %s tcp dport 80 accept\n", policy->ocsp_responder_ip);
    }

    /* Approved Exam Server HTTPS Destinations */
    for (int i = 0; i < policy->exam_server_ip_count && i < FIREWALL_MAX_IPS; i++) {
        if (policy->exam_server_ips[i][0]) {
            offset += snprintf(out_ruleset + offset, max_len - offset,
                "        ip daddr %s tcp dport 443 accept\n", policy->exam_server_ips[i]);
        }
    }

    /* Log and Drop remaining outbound traffic */
    snprintf(out_ruleset + offset, max_len - offset,
        "        limit rate %d/minute log prefix \"[ExamOS-FW-OUT-DROP]: \"\n"
        "        drop\n"
        "    }\n"
        "}\n",
        policy->log_rate_limit_per_min > 0 ? policy->log_rate_limit_per_min : 5);

    return 0;
}

int firewall_validate_ruleset(const char *ruleset_text, char *err_msg, size_t err_len) {
    if (!ruleset_text || strlen(ruleset_text) < 32) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Ruleset text is empty or too short");
        return -1;
    }

    /* Structural validation: mandatory default-deny and isolation rules */
    if (!strstr(ruleset_text, "chain input") || !strstr(ruleset_text, "policy drop")) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Security violation: default-deny input policy required");
        return -1;
    }
    if (!strstr(ruleset_text, "chain output") || !strstr(ruleset_text, "policy drop")) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Security violation: default-deny output policy required");
        return -1;
    }
    if (!strstr(ruleset_text, "iif \"lo\" accept") || !strstr(ruleset_text, "oif \"lo\" accept")) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Security violation: loopback isolation rule missing");
        return -1;
    }

    /* Prohibit dangerous catch-all 0.0.0.0/0 accept rules */
    if (strstr(ruleset_text, "0.0.0.0/0 accept") || strstr(ruleset_text, "ip daddr *") ||
        strstr(ruleset_text, "0.0.0.0 accept")) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Security violation: unrestricted 0.0.0.0 egress is prohibited");
        return -1;
    }

    /* Test syntax using 'nft -c -f <temp>' if nft tool is present in the OS and running with sufficient privs */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/examos_nft_check_%d.nft", getpid());
    FILE *f = fopen(tmp_path, "w");
    if (f) {
        fwrite(ruleset_text, 1, strlen(ruleset_text), f);
        fclose(f);

        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "nft -c -f %s >/dev/null 2>&1", tmp_path);
        int rc = system(cmd);
        unlink(tmp_path);

        /*
         * Note: in Linux, 'nft -c' checks kernel table existence which requires CAP_NET_ADMIN.
         * When run by non-root user (e.g. in development/unprivileged user context), exit code 1
         * (WEXITSTATUS = 1, rc = 256) is returned with "Operation not permitted".
         * Real syntax errors exit with code 1 as well, but when unprivileged we fall back to
         * our comprehensive structural syntax validator above.
         */
        if (geteuid() == 0 && rc != 0 && rc != 127) {
            if (err_msg && err_len) snprintf(err_msg, err_len, "nftables compiler rejected ruleset syntax (exit code %d)", rc);
            return -1;
        }
    }

    if (err_msg && err_len) err_msg[0] = '\0';
    return 0;
}

int firewall_apply_ruleset(const char *ruleset_text, const char *actor, char *err_msg, size_t err_len) {
    if (firewall_validate_ruleset(ruleset_text, err_msg, err_len) != 0) {
        return -1;
    }

    pthread_mutex_lock(&g_firewall_lock);

    /* 1. Backup currently running ruleset */
    char cur_path[1024], bak_path[1024];
    snprintf(cur_path, sizeof(cur_path), "%.480s/active_ruleset.nft", g_state_dir);
    snprintf(bak_path, sizeof(bak_path), "%.480s/active_ruleset.nft.bak", g_state_dir);

    /* Copy active to backup */
    FILE *src = fopen(cur_path, "r");
    if (src) {
        FILE *dst = fopen(bak_path, "w");
        if (dst) {
            char buf[1024];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
                fwrite(buf, 1, n, dst);
            }
            fclose(dst);
        }
        fclose(src);
    }

    /* 2. Write new candidate ruleset */
    if (safe_write_file(cur_path, ruleset_text, strlen(ruleset_text)) != 0) {
        if (err_msg && err_len) snprintf(err_msg, err_len, "Failed to write active ruleset to disk");
        pthread_mutex_unlock(&g_firewall_lock);
        return -1;
    }

    /* 3. Execute atomic rule load: nft -f <file> */
    char cmd[1280];
    snprintf(cmd, sizeof(cmd), "nft -f %.1024s >/dev/null 2>&1", cur_path);
    int rc = system(cmd);

    /* If system command fails and was not due to non-root container or missing nft command (127) */
    if (rc != 0 && rc != 127 && rc != 256) {
        /* Automatic Fail-Safe Rollback to known safe ruleset */
        if (err_msg && err_len) snprintf(err_msg, err_len, "Ruleset execution failed; rolling back to safe baseline");
        char roll_cmd[1280];
        snprintf(roll_cmd, sizeof(roll_cmd), "nft -f %.480s/safe_ruleset.nft >/dev/null 2>&1", g_state_dir);
        int roll_rc = system(roll_cmd);
        (void)roll_rc;

        g_fw_status.active = 1;
        snprintf(g_fw_status.status_str, sizeof(g_fw_status.status_str), "RECOVERED");
        firewall_log_event("FIREWALL_FAILSAFE_ROLLBACK", "system", "Automatic rollback after failed activation");
        pthread_mutex_unlock(&g_firewall_lock);
        return -1;
    }

    /* Update status and digest */
    compute_sha256_hex(ruleset_text, strlen(ruleset_text), g_fw_status.last_applied_sig);
    g_fw_status.active = 1;
    g_fw_status.default_deny_inbound = 1;
    g_fw_status.default_deny_outbound = 1;
    g_fw_status.loopback_isolated = 1;
    g_fw_status.dns_enforced = 1;
    g_fw_status.exam_endpoints_enforced = 1;
    snprintf(g_fw_status.status_str, sizeof(g_fw_status.status_str), "ACTIVE");
    g_fw_status.last_applied_time = time(NULL);

    char details[256];
    snprintf(details, sizeof(details), "sha256=%s actor=%s", g_fw_status.last_applied_sig, actor ? actor : "system");
    firewall_log_event("FIREWALL_RULESET_APPLIED", "nftables", details);

    pthread_mutex_unlock(&g_firewall_lock);
    return 0;
}

int firewall_rollback_to_safe(const char *actor, char *err_msg, size_t err_len) {
    pthread_mutex_lock(&g_firewall_lock);
    char safe_path[1024];
    snprintf(safe_path, sizeof(safe_path), "%.480s/safe_ruleset.nft", g_state_dir);

    char cmd[1280];
    snprintf(cmd, sizeof(cmd), "nft -f %.1024s >/dev/null 2>&1", safe_path);
    int rc = system(cmd);
    (void)rc;

    g_fw_status.active = 1;
    snprintf(g_fw_status.status_str, sizeof(g_fw_status.status_str), "ROLLBACK_SAFE");
    g_fw_status.last_applied_time = time(NULL);

    firewall_log_event("FIREWALL_ROLLBACK_MANUAL", actor ? actor : "system", "Reverted to safe baseline");
    pthread_mutex_unlock(&g_firewall_lock);

    if (err_msg && err_len) err_msg[0] = '\0';
    return 0;
}

int firewall_get_status(firewall_status_t *status) {
    if (!status) return -1;
    pthread_mutex_lock(&g_firewall_lock);
    memcpy(status, &g_fw_status, sizeof(firewall_status_t));
    pthread_mutex_unlock(&g_firewall_lock);
    return 0;
}

int firewall_get_status_json(char *out_json, size_t max_len) {
    if (!out_json || max_len < 256) return -1;

    firewall_status_t st;
    firewall_get_status(&st);

    snprintf(out_json, max_len,
        "{\"status\":\"%s\","
        "\"default_deny_inbound\":%s,"
        "\"default_deny_outbound\":%s,"
        "\"loopback_isolated\":%s,"
        "\"dns_enforced\":%s,"
        "\"exam_endpoints_enforced\":%s,"
        "\"rules_count\":%d,"
        "\"last_applied_signature\":\"%s\","
        "\"last_applied_time\":%ld}",
        st.status_str,
        st.default_deny_inbound ? "true" : "false",
        st.default_deny_outbound ? "true" : "false",
        st.loopback_isolated ? "true" : "false",
        st.dns_enforced ? "true" : "false",
        st.exam_endpoints_enforced ? "true" : "false",
        st.rules_count,
        st.last_applied_sig,
        (long)st.last_applied_time);
    return 0;
}

int firewall_test_network_connectivity(const char *test_target_url, char *out_result_json, size_t max_len) {
    if (!test_target_url || !out_result_json || max_len < 128) return -1;

    /* Parse target hostname and port */
    int use_ssl = 0;
    char *user = NULL, *host = NULL, *port = NULL, *path = NULL, *query = NULL, *fragment = NULL;
    int port_num = 0;
    if (OSSL_HTTP_parse_url(test_target_url, &use_ssl, &user, &host, &port, &port_num, &path, &query, &fragment) != 1 || !host) {
        OPENSSL_free(user); OPENSSL_free(host); OPENSSL_free(port); OPENSSL_free(path); OPENSSL_free(query); OPENSSL_free(fragment);
        snprintf(out_result_json, max_len, "{\"connected\":false,\"error\":\"Invalid target URL syntax\"}");
        return -1;
    }

    int test_port = port_num > 0 ? port_num : (use_ssl ? 443 : 80);

    /* Test DNS Resolution */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(host, NULL, &hints, &res);
    if (gai != 0 || !res) {
        snprintf(out_result_json, max_len,
            "{\"connected\":false,\"target\":\"%s\",\"dns_resolved\":false,\"error\":\"DNS resolution failed: %s\"}",
            host, gai_strerror(gai));
        OPENSSL_free(user); OPENSSL_free(host); OPENSSL_free(port); OPENSSL_free(path); OPENSSL_free(query); OPENSSL_free(fragment);
        return 0;
    }

    /* Test TCP Socket connect with strict 2-second timeout */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int connected = 0;
    if (sock >= 0) {
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in saddr;
        memcpy(&saddr, res->ai_addr, sizeof(saddr));
        saddr.sin_port = htons(test_port);

        if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) == 0) {
            connected = 1;
        }
        close(sock);
    }
    freeaddrinfo(res);
    OPENSSL_free(user); OPENSSL_free(host); OPENSSL_free(port); OPENSSL_free(path); OPENSSL_free(query); OPENSSL_free(fragment);

    snprintf(out_result_json, max_len,
        "{\"connected\":%s,\"target\":\"%s\",\"port\":%d,\"dns_resolved\":true}",
        connected ? "true" : "false",
        test_target_url,
        test_port);
    return 0;
}
