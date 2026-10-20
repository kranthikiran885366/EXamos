#!/usr/bin/env bash
# Fail if production units still contain fake hostnames or mock recovery keys.
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0
scan() {
    local pattern="$1" desc="$2"
    if git -C "$WORKSPACE" grep -nE "$pattern" -- \
        image/overlay/etc/systemd/system \
        tools/examos-operator-recovery.c \
        kiosk/launcher/launcher.c \
        agent/main.c \
        >/dev/null 2>&1; then
        echo "FAIL: $desc" >&2
        git -C "$WORKSPACE" grep -nE "$pattern" -- \
            image/overlay/etc/systemd/system \
            tools/examos-operator-recovery.c \
            kiosk/launcher/launcher.c \
            agent/main.c >&2 || true
        fail=1
    else
        echo "PASS: $desc"
    fi
}
scan 'example\.(edu|com)' "no example.* documentation URLs in production units/agent/recovery"
scan 'OPERATOR-SECURE-' "no clock/pid mock operator keys"
scan 'tpm2_createek' "hardware-trust path must not create transient EK in this scan set"
if grep -n 'tpm2_createek' "$WORKSPACE/tests/production/hardware-trust-gate.sh" >/dev/null 2>&1; then
    echo "FAIL: hardware-trust-gate.sh still calls tpm2_createek" >&2
    fail=1
else
    echo "PASS: hardware-trust-gate.sh does not create a transient EK"
fi
exit "$fail"
