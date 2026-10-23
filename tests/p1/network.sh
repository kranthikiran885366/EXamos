#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="${EXAMOS_P1_ARTIFACT_DIR:-$WORKSPACE/artifacts/p1}"
mkdir -p "$ARTIFACT_DIR"

LOG_FILE="$ARTIFACT_DIR/network.log"
exec > >(tee "$LOG_FILE") 2>&1

echo "=== [P1-NETWORK] Static Network Security & Firewall Verification ==="

NFT_CONF="$WORKSPACE/image/overlay/etc/nftables.conf"
if [ ! -f "$NFT_CONF" ]; then
    echo "[NETWORK-CHECK] FAIL: nftables.conf is missing"
    exit 1
fi

if grep -q "policy drop" "$NFT_CONF"; then
    echo "[NETWORK-CHECK] PASS: Firewall implements strict default-deny (policy drop)"
else
    echo "[NETWORK-CHECK] FAIL: Firewall does not enforce default-deny"
    exit 1
fi

if grep -q "tcp dport 443 accept" "$NFT_CONF"; then
    echo "[NETWORK-CHECK] PASS: HTTPS port 443 outbound allowed for exam server"
else
    echo "[NETWORK-CHECK] FAIL: Port 443 outbound rule missing"
    exit 1
fi

if grep -q "udp dport 53 accept" "$NFT_CONF"; then
    echo "[NETWORK-CHECK] PASS: DNS resolution (UDP 53) allowed"
else
    echo "[NETWORK-CHECK] FAIL: DNS rule missing"
    exit 1
fi

# PG-08: Verify no inbound rules accept unexpected ports
# Strip comments, check no broad inbound accept rules exist
INBOUND_WILDCARDS=$(sed 's/#.*//' "$NFT_CONF" | \
    grep -E 'iif.*accept|iifname.*accept' | \
    grep -vE 'lo|loopback' || true)
if [ -n "$INBOUND_WILDCARDS" ]; then
    echo "[NETWORK-CHECK] FAIL: nftables has broad inbound accept rules: $INBOUND_WILDCARDS"
    exit 1
fi
echo "[NETWORK-CHECK] PASS: No broad inbound accept rules found"

# PG-08: Verify IPv6 is disabled in nftables (no IPv6 accept rules)
IPV6_ACCEPTS=$(sed 's/#.*//' "$NFT_CONF" | grep -E 'ip6|::/0' | grep 'accept' || true)
if [ -n "$IPV6_ACCEPTS" ]; then
    echo "[NETWORK-CHECK] FAIL: nftables has IPv6 accept rules: $IPV6_ACCEPTS"
    exit 1
fi
echo "[NETWORK-CHECK] PASS: No IPv6 accept rules in nftables"

# PG-08: Verify admin port (8000) is loopback-only — no external accept for port 8000
EXT_ADMIN=$(sed 's/#.*//' "$NFT_CONF" | grep '8000' | grep 'accept' | grep -v '127\.0\.0\.1\|lo\|loopback' || true)
if [ -n "$EXT_ADMIN" ]; then
    echo "[NETWORK-CHECK] FAIL: port 8000 is externally accessible in nftables: $EXT_ADMIN"
    exit 1
fi
echo "[NETWORK-CHECK] PASS: Admin port 8000 not exposed externally in nftables"

# PG-08: Verify all three chains have policy drop (input, output, forward)
DROP_COUNT=$(grep -c 'policy drop' "$NFT_CONF" 2>/dev/null || echo 0)
if [ "$DROP_COUNT" -lt 3 ]; then
    echo "[NETWORK-CHECK] FAIL: nftables has only $DROP_COUNT policy drop chains (need >=3 for input/output/forward)"
    exit 1
fi
echo "[NETWORK-CHECK] PASS: nftables has $DROP_COUNT policy drop chains"

echo "[P1-NETWORK] PASS: Firewall and network security definitions verified"
exit 0
