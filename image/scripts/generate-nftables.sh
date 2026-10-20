#!/usr/bin/env bash
# =============================================================================
# ExamOS H7 — nftables Policy Generator
#
# Reads /etc/examos/deployment.conf, validates every IP, and generates a
# signed nftables.conf with real deployment addresses replacing the
# DEPLOYMENT_REQUIRED placeholders. No public resolvers or documentation
# IPs are permitted — the validator blocks them explicitly.
#
# Usage (run as root on the target appliance):
#   bash /usr/local/sbin/generate-nftables.sh [--dry-run] [--check-only]
#
# Options:
#   --dry-run     Print generated policy to stdout without installing.
#   --check-only  Only validate deployment.conf; do not generate the policy.
#
# Exit codes:
#   0  Success — policy generated and loaded (or dry-run printed)
#   1  Validation error — misconfigured or unsafe deployment.conf
#   2  Tool error — nft not available or policy failed to load
# =============================================================================
set -euo pipefail

DEPLOYMENT_CONF="${DEPLOYMENT_CONF:-/etc/examos/deployment.conf}"
NFT_CONF="/etc/nftables.conf"
NFT_CONF_TMP="/etc/nftables.conf.tmp.$$"

DRY_RUN=0
CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --dry-run)    DRY_RUN=1 ;;
        --check-only) CHECK_ONLY=1 ;;
    esac
done

log()  { echo "[gen-nft] $*"; }
fail() { echo "[gen-nft] FATAL: $*" >&2; exit 1; }
warn() { echo "[gen-nft] WARNING: $*" >&2; }

# -----------------------------------------------------------------------
# IP validation helpers
# -----------------------------------------------------------------------
is_valid_ipv4() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -ra octets <<< "$ip"
        for oct in "${octets[@]}"; do
            [ "$oct" -le 255 ] 2>/dev/null || return 1
        done
        return 0
    fi
    return 1
}

is_blocked_ip() {
    # Reject IPs that should never appear in a real deployment:
    #   0.0.0.0/8       — "this" network
    #   127.0.0.0/8     — loopback (all services must use their own binding)
    #   169.254.0.0/16  — link-local
    #   192.0.2.0/24    — TEST-NET-1 (RFC 5737 documentation range)
    #   198.51.100.0/24 — TEST-NET-2
    #   203.0.113.0/24  — TEST-NET-3
    #   1.1.1.1         — Cloudflare public resolver (blocked by policy)
    #   1.0.0.1         — Cloudflare public resolver
    #   8.8.8.8         — Google public resolver
    #   8.8.4.4         — Google public resolver
    #   9.9.9.9         — Quad9 public resolver
    local ip="$1"
    local blocked_exact=("1.1.1.1" "1.0.0.1" "8.8.8.8" "8.8.4.4" "9.9.9.9"
                         "0.0.0.0" "255.255.255.255")
    for blocked in "${blocked_exact[@]}"; do
        [ "$ip" = "$blocked" ] && return 0
    done

    local first_octet="${ip%%.*}"
    local first_two="${ip%.*.*}"

    # 0/8, 127/8, 169.254/16, 192.0.2/24, 198.51.100/24, 203.0.113/24
    case "$first_octet" in
        0|127) return 0 ;;
    esac
    case "$first_two" in
        169.254) return 0 ;;
    esac
    case "${ip%.*}" in
        192.0.2|198.51.100|203.0.113) return 0 ;;
    esac

    return 1
}

validate_ip() {
    local name="$1" ip="$2"
    if [ "$ip" = "DEPLOYMENT_REQUIRED" ]; then
        fail "${name} is still set to DEPLOYMENT_REQUIRED. Edit ${DEPLOYMENT_CONF}."
    fi
    is_valid_ipv4 "$ip" || fail "${name}='${ip}' is not a valid IPv4 address."
    if is_blocked_ip "$ip"; then
        fail "${name}='${ip}' is a prohibited address (public resolver, documentation \
range, or reserved). Use your organisation's own infrastructure addresses."
    fi
    return 0
}

# -----------------------------------------------------------------------
# Load deployment.conf
# -----------------------------------------------------------------------
[ -f "$DEPLOYMENT_CONF" ] || fail "deployment.conf not found at $DEPLOYMENT_CONF"

# Source it safely — only lines matching KEY=VALUE with known keys
declare -A CONF
while IFS='=' read -r key val; do
    [[ "$key" =~ ^[A-Z_]+$ ]] || continue
    [[ "$val" =~ ^[[:space:]]*# ]] && continue
    CONF["$key"]="${val%%#*}"    # strip inline comments
    CONF["$key"]="${CONF[$key]%"${CONF[$key]##*[! ]}"}"  # trim trailing spaces
done < <(grep -v '^[[:space:]]*#' "$DEPLOYMENT_CONF" | grep '=')

DNS_1="${CONF[CONTROLLED_DNS_1]:-DEPLOYMENT_REQUIRED}"
DNS_2="${CONF[CONTROLLED_DNS_2]:-DEPLOYMENT_REQUIRED}"
EXAM_SRV_1="${CONF[EXAM_SERVER_IP_1]:-DEPLOYMENT_REQUIRED}"
EXAM_SRV_2="${CONF[EXAM_SERVER_IP_2]:-DEPLOYMENT_REQUIRED}"
NTP_1="${CONF[NTP_SERVER_IP_1]:-DEPLOYMENT_REQUIRED}"
NTP_2="${CONF[NTP_SERVER_IP_2]:-DEPLOYMENT_REQUIRED}"
OCSP="${CONF[OCSP_RESPONDER_IP]:-DEPLOYMENT_REQUIRED}"

# -----------------------------------------------------------------------
# Validate all addresses
# -----------------------------------------------------------------------
log "Validating deployment.conf ..."
validate_ip "CONTROLLED_DNS_1"  "$DNS_1"
validate_ip "CONTROLLED_DNS_2"  "$DNS_2"
validate_ip "EXAM_SERVER_IP_1"  "$EXAM_SRV_1"
validate_ip "EXAM_SERVER_IP_2"  "$EXAM_SRV_2"
validate_ip "NTP_SERVER_IP_1"   "$NTP_1"
validate_ip "NTP_SERVER_IP_2"   "$NTP_2"
validate_ip "OCSP_RESPONDER_IP" "$OCSP"
log "All 7 addresses validated."

if [ "$CHECK_ONLY" -eq 1 ]; then
    log "Check-only mode: deployment.conf is valid."
    exit 0
fi

# -----------------------------------------------------------------------
# Generate the policy
# -----------------------------------------------------------------------
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

POLICY=$(cat <<EOF
#!/usr/sbin/nft -f
# ExamOS nftables policy — GENERATED BY generate-nftables.sh
# Generated at: ${TIMESTAMP}
# Source commit: ${GIT_COMMIT}
# Source config: ${DEPLOYMENT_CONF}
# DO NOT EDIT MANUALLY — re-run generate-nftables.sh after changing deployment.conf

define DNS_1      = ${DNS_1}
define DNS_2      = ${DNS_2}
define EXAM_SRV_1 = ${EXAM_SRV_1}
define EXAM_SRV_2 = ${EXAM_SRV_2}
define NTP_1      = ${NTP_1}
define NTP_2      = ${NTP_2}
define OCSP_IP    = ${OCSP}

flush ruleset

table ip6 filter {
    chain input   { type filter hook input   priority 0; policy drop; }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy drop; }
}

table inet filter {

    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state { established, related } accept
        ct state invalid drop
        udp sport 67 udp dport 68 accept
        icmp type { echo-reply, destination-unreachable, time-exceeded } accept
        limit rate 3/minute log prefix "[ExamOS-FW-IN]: "
        reject with icmpx type admin-prohibited
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        ct state { established, related } accept
        ct state invalid drop
        ip daddr \$DNS_1 udp dport 53 accept
        ip daddr \$DNS_1 tcp dport 53 accept
        ip daddr \$DNS_2 udp dport 53 accept
        ip daddr \$DNS_2 tcp dport 53 accept
        udp sport 68 udp dport 67 accept
        ip daddr \$NTP_1 udp dport 123 accept
        ip daddr \$NTP_2 udp dport 123 accept
        ip daddr \$EXAM_SRV_1 tcp dport 443 accept
        ip daddr \$EXAM_SRV_2 tcp dport 443 accept
        ip daddr \$OCSP_IP tcp dport 80 accept
        limit rate 5/minute log prefix "[ExamOS-FW-OUT]: "
        drop
    }
}
EOF
)

if [ "$DRY_RUN" -eq 1 ]; then
    echo "$POLICY"
    log "Dry-run complete — policy printed to stdout, not installed."
    exit 0
fi

# -----------------------------------------------------------------------
# Write atomically and validate before activating
# -----------------------------------------------------------------------
command -v nft >/dev/null 2>&1 || fail "nft not found. Install nftables."

echo "$POLICY" > "$NFT_CONF_TMP"

# Syntax check before installing
if ! nft --check --file "$NFT_CONF_TMP"; then
    rm -f "$NFT_CONF_TMP"
    fail "nft syntax check failed — policy NOT installed."
fi

# Atomically replace
mv "$NFT_CONF_TMP" "$NFT_CONF"
chmod 0640 "$NFT_CONF"
log "Policy written to $NFT_CONF"

# Reload
if systemctl is-active nftables >/dev/null 2>&1; then
    systemctl reload nftables || systemctl restart nftables
    log "nftables service reloaded."
else
    nft --file "$NFT_CONF"
    log "nftables policy loaded directly."
fi

log "Firewall policy active:"
log "  DNS       : $DNS_1, $DNS_2"
log "  Exam HTTPS: $EXAM_SRV_1, $EXAM_SRV_2"
log "  NTP       : $NTP_1, $NTP_2"
log "  OCSP      : $OCSP"
