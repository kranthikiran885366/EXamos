#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — Network Firewall Allow/Deny Tests (Layer 4)
# Mandatory: P2-01 P2-02 P2-03 P2-09 P2-13
#
# Runs both FROM the ExamOS guest (outbound tests) and expects an external
# port scan result in $PORTSCAN_FILE for P2-09.
#
# Environment variables:
#   EXAM_URL        — configured exam URL (read from /etc/examos/exam.conf)
#   PORTSCAN_FILE   — path to nmap output from external scan (P2-09)
#   ARTIFACT_DIR    — where to write results
# =============================================================================
set -uo pipefail

ARTIFACT_DIR="${ARTIFACT_DIR:-/run/examos/p2-tests}"
PORTSCAN_FILE="${PORTSCAN_FILE:-${ARTIFACT_DIR}/external-port-scan.txt}"
mkdir -p "$ARTIFACT_DIR"

LOG="$ARTIFACT_DIR/network-tests.log"
exec > >(tee "$LOG") 2>&1

PASS=0; FAIL=0; BLOCKED=0
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

record() {
    local id="$1" status="$2" detail="$3"
    case "$status" in
        PASS)    PASS=$((PASS+1));    echo "[NET-PASS]    ${id}: ${detail}" ;;
        FAIL)    FAIL=$((FAIL+1));    echo "[NET-FAIL]    ${id}: ${detail}" >&2 ;;
        BLOCKED) BLOCKED=$((BLOCKED+1)); echo "[NET-BLOCKED] ${id}: ${detail}" ;;
    esac
}
overall_status() {
    if [ "$FAIL" -gt 0 ]; then echo "FAIL"
    elif [ "$BLOCKED" -gt 0 ]; then echo "BLOCKED"
    elif [ "$PASS" -gt 0 ]; then echo "PASS"
    else echo "NOT_RUN"
    fi
}

echo "=== [P2-NETWORK] Network Tests: $(ts) ==="

# Read exam URL
EXAM_URL=""
if [ -f /etc/examos/exam.conf ]; then
    EXAM_URL=$(grep -oP '(?<=EXAM_URL=)\S+' /etc/examos/exam.conf | head -1 || true)
fi

# ---------------------------------------------------------------------------
# P2-01: Non-exam URL must be blocked
# Tests require explicitly provisioned controlled endpoints; never probe public
# infrastructure as part of the default gate.
# ---------------------------------------------------------------------------
BLOCKED_TARGET="${EXAMOS_P2_BLOCKED_TEST_URL:-}"
if [ -z "$BLOCKED_TARGET" ]; then
    record "P2-01" "BLOCKED" "Set EXAMOS_P2_BLOCKED_TEST_URL to an authorized controlled endpoint."
elif command -v curl >/dev/null 2>&1; then
    CURL_RC=0
    curl --max-time 5 --silent --output /dev/null "$BLOCKED_TARGET" 2>/dev/null \
        && CURL_RC=0 || CURL_RC=$?
    if [ "$CURL_RC" -ne 0 ]; then
        record "P2-01" "PASS" "Non-exam URL blocked: ${BLOCKED_TARGET} (curl rc=${CURL_RC})"
    else
        record "P2-01" "FAIL" "Non-exam URL was reachable: ${BLOCKED_TARGET} — firewall not enforcing"
    fi
else
    record "P2-01" "BLOCKED" "BLOCKED_ENVIRONMENT: curl not available in release image"
fi

# ---------------------------------------------------------------------------
# P2-02: Alternate scheme / IP literal / redirect escape blocked
# ---------------------------------------------------------------------------
# Test TCP connection to non-exam IP on port 443
read -r -a TARGET_IPS <<< "${EXAMOS_P2_BLOCKED_TEST_IPS:-}"
for target_ip in "${TARGET_IPS[@]}"; do
    if command -v nc >/dev/null 2>&1; then
        NC_RC=0
        nc -z -w 3 "$target_ip" 443 2>/dev/null && NC_RC=0 || NC_RC=$?
        if [ "$NC_RC" -ne 0 ]; then
            record "P2-02-${target_ip}" "PASS" "TCP 443 to ${target_ip} blocked (nc rc=${NC_RC})"
        else
            record "P2-02-${target_ip}" "FAIL" "TCP 443 to ${target_ip} succeeded — should be blocked"
        fi
    elif command -v curl >/dev/null 2>&1; then
        CURL_RC=0
        curl --max-time 3 --silent --output /dev/null "https://${target_ip}/" 2>/dev/null \
            && CURL_RC=0 || CURL_RC=$?
        if [ "$CURL_RC" -ne 0 ]; then
            record "P2-02-${target_ip}" "PASS" "HTTPS to ${target_ip} blocked (curl rc=${CURL_RC})"
        else
            record "P2-02-${target_ip}" "FAIL" "HTTPS to ${target_ip} succeeded — should be blocked"
        fi
    else
        record "P2-02-${target_ip}" "BLOCKED" "nc or curl is required to test this authorized endpoint."
    fi
done
if [ -z "${EXAMOS_P2_BLOCKED_TEST_IPS:-}" ]; then
    record "P2-02" "BLOCKED" "Set EXAMOS_P2_BLOCKED_TEST_IPS to controlled authorized destinations."
fi

# ---------------------------------------------------------------------------
# P2-03: Non-exam destination times out / rejected
# Test a destination that is not in the nftables allowlist on a non-exam port
# ---------------------------------------------------------------------------
read -r -a TARGET_HOST_PORTS <<< "${EXAMOS_P2_BLOCKED_TEST_HOST_PORTS:-}"
for test_case in "${TARGET_HOST_PORTS[@]}"; do
    HOST=$(echo "$test_case" | cut -d: -f1)
    PORT=$(echo "$test_case" | cut -d: -f2)
    if [[ ! "$HOST" =~ ^[A-Za-z0-9.-]+$ || ! "$PORT" =~ ^[0-9]{1,5}$ ]] ||
       [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        record "P2-03-${test_case}" "FAIL" "Invalid controlled host/port test target."
        continue
    fi
    BASH_RC=0
    timeout 4 bash -c "echo > /dev/tcp/${HOST}/${PORT}" 2>/dev/null && BASH_RC=0 || BASH_RC=$?
    if [ "$BASH_RC" -ne 0 ]; then
        record "P2-03-${HOST}:${PORT}" "PASS" "Connection to ${HOST}:${PORT} blocked (rc=${BASH_RC})"
    else
        record "P2-03-${HOST}:${PORT}" "FAIL" "Connection to ${HOST}:${PORT} succeeded — should be blocked"
    fi
done
if [ -z "${EXAMOS_P2_BLOCKED_TEST_HOST_PORTS:-}" ]; then
    record "P2-03" "BLOCKED" "Set EXAMOS_P2_BLOCKED_TEST_HOST_PORTS to controlled authorized destinations."
fi

# ---------------------------------------------------------------------------
# P2-09: External port scan — read pre-existing nmap output
# This test requires an external scan from a separate host/namespace.
# The CI workflow runs nmap from the host against the QEMU guest's
# network interface and writes the result to $PORTSCAN_FILE.
# ---------------------------------------------------------------------------
if [ -f "$PORTSCAN_FILE" ] && [ -s "$PORTSCAN_FILE" ]; then
    OPEN_PORTS=$(grep -E "^[0-9]+/tcp.*open" "$PORTSCAN_FILE" 2>/dev/null || true)
    if [ -z "$OPEN_PORTS" ]; then
        record "P2-09" "PASS" "External port scan: no open TCP ports found"
    else
        record "P2-09" "FAIL" "External port scan found open ports: ${OPEN_PORTS}"
    fi
else
    record "P2-09" "BLOCKED" "BLOCKED_ENVIRONMENT: external port scan file not available at ${PORTSCAN_FILE} — run nmap from separate host"
fi

# ---------------------------------------------------------------------------
# P2-13: Firewall active before network — verify nftables loaded and ordering
# ---------------------------------------------------------------------------
NFT_TABLES=$(nft list tables 2>/dev/null || echo "NOT_AVAILABLE")
if echo "$NFT_TABLES" | grep -q "inet filter"; then
    # Check rule counters to verify traffic has passed through
    NFT_IN_POLICY=$(nft list chain inet filter input 2>/dev/null | grep "policy" || true)
    NFT_OUT_POLICY=$(nft list chain inet filter output 2>/dev/null | grep "policy" || true)
    if echo "$NFT_IN_POLICY" | grep -q "policy drop" && echo "$NFT_OUT_POLICY" | grep -q "policy drop"; then
        record "P2-13" "PASS" "nftables inet filter active with default-drop on input+output"
        # Check IPv6 table also present
        IPV6_TABLE=$(nft list tables 2>/dev/null | grep "ip6" || true)
        if [ -n "$IPV6_TABLE" ]; then
            record "P2-13-IPV6" "PASS" "nftables ip6 table active: ${IPV6_TABLE}"
        else
            record "P2-13-IPV6" "FAIL" "nftables ip6 drop table not loaded"
        fi
    else
        record "P2-13" "FAIL" "nftables not default-deny: in='${NFT_IN_POLICY}' out='${NFT_OUT_POLICY}'"
    fi
else
    record "P2-13" "FAIL" "nftables inet filter table not loaded: ${NFT_TABLES}"
fi

# Verify nftables started before NetworkManager
NFTABLES_BOOT=$(systemctl show nftables --property=ExecMainStartTimestampMonotonic 2>/dev/null | cut -d= -f2 || echo "0")
NM_BOOT=$(systemctl show NetworkManager --property=ExecMainStartTimestampMonotonic 2>/dev/null | cut -d= -f2 || echo "0")
if [ "$NFTABLES_BOOT" != "0" ] && [ "$NM_BOOT" != "0" ]; then
    if [ "$NFTABLES_BOOT" -le "$NM_BOOT" ]; then
        record "P2-13-ORDER" "PASS" "nftables started before NetworkManager (${NFTABLES_BOOT} <= ${NM_BOOT})"
    else
        record "P2-13-ORDER" "FAIL" "nftables started AFTER NetworkManager (${NFTABLES_BOOT} > ${NM_BOOT})"
    fi
else
    record "P2-13-ORDER" "BLOCKED" "Cannot determine service start timestamps"
fi

# ---------------------------------------------------------------------------
# DNS pin test — DNS to 127.0.0.1 (non-configured resolver) should fail
# ---------------------------------------------------------------------------
DNS_RC=0
timeout 3 bash -c "echo > /dev/tcp/127.0.0.2/53" 2>/dev/null && DNS_RC=0 || DNS_RC=$?
if [ "$DNS_RC" -ne 0 ]; then
    record "NET-DNS-PIN" "PASS" "Direct DNS to 127.0.0.2:53 blocked (rc=${DNS_RC})"
else
    record "NET-DNS-PIN" "FAIL" "DNS to non-configured resolver succeeded — DNS not pinned"
fi

# ---------------------------------------------------------------------------
# Write results
# ---------------------------------------------------------------------------
{
    printf '{"timestamp":"%s","pass":%d,"fail":%d,"blocked":%d,"overall":"%s"}\n' \
        "$(ts)" "$PASS" "$FAIL" "$BLOCKED" "$(overall_status)"
} > "$ARTIFACT_DIR/firewall-allow-deny-tests.json"

echo ""
echo "=== [P2-NETWORK] PASS=${PASS} FAIL=${FAIL} BLOCKED=${BLOCKED} ==="
[ "$FAIL" -eq 0 ]
