#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="$WORKSPACE/artifacts/p1"
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

echo "[P1-NETWORK] PASS: Firewall and network security definitions verified"
exit 0
