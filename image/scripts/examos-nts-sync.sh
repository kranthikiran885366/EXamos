#!/usr/bin/env bash
# ExamOS — Authenticated Time Sync (NTS / TLS-Verified Server Clock)
# Synchronizes system clock before TPM attestation so weak CMOS batteries do
# not break TLS certificate validation or attestation nonce freshness.
set -euo pipefail

SERVER_URL="${EXAMOS_SERVER_URL:-https://sppio-core.onrender.com}"
MAX_DRIFT_SEC="${EXAMOS_MAX_CLOCK_DRIFT_SEC:-5}"

sync_via_chrony_nts() {
    command -v chronyc >/dev/null 2>&1 || return 1
    chronyc -a waitsync 10 0.5 0.0 1 >/dev/null 2>&1 || return 1
    chronyc tracking 2>/dev/null | grep -qiE "Leap status\s*:\s*Normal" || return 1
    echo "[ExamOS-NTS] Clock synchronized via chrony NTS"
    return 0
}

sync_via_authenticated_https() {
    local hdr_date remote_epoch local_epoch drift
    hdr_date=$(curl -sSI --proto '=https' --tlsv1.2 --max-time 8 "${SERVER_URL%/}/api/v1/health" \
        | grep -i '^date:' | head -n1 | sed -E 's/^[Dd]ate:[[:space:]]*//; s/\r$//')
    [ -n "$hdr_date" ] || return 1
    remote_epoch=$(date -u -d "$hdr_date" +%s 2>/dev/null) || return 1
    local_epoch=$(date -u +%s)
    drift=$(( remote_epoch - local_epoch ))
    [ "$drift" -lt 0 ] && drift=$(( -drift ))
    if [ "$drift" -gt "$MAX_DRIFT_SEC" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            date -u -s "@${remote_epoch}" >/dev/null
            hwclock --systohc >/dev/null 2>&1 || true
            echo "[ExamOS-NTS] Adjusted clock by ${drift}s from TLS-verified server time"
        else
            echo "[ExamOS-NTS] WARNING: clock drift ${drift}s exceeds ${MAX_DRIFT_SEC}s (root required to step clock)" >&2
            return 1
        fi
    else
        echo "[ExamOS-NTS] Clock within ${drift}s of TLS-verified server time"
    fi
    return 0
}

if sync_via_chrony_nts; then
    exit 0
fi

if sync_via_authenticated_https; then
    exit 0
fi

echo "[ExamOS-NTS] ERROR: Failed to synchronize clock via NTS or TLS-verified server" >&2
exit 1
