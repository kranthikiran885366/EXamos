#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
UNIT="$WORKSPACE/image/overlay/etc/systemd/system/examos-agent.service"
CONFIG="$WORKSPACE/image/overlay/etc/examos/agent.conf"
WINDOWS_LAUNCHER="$WORKSPACE/scripts/launch-windows.bat"

fail() {
    echo "[P0-AGENT-CONFIG] FAIL: $*" >&2
    exit 1
}

[ -f "$UNIT" ] || fail "agent systemd unit is missing"
[ -f "$CONFIG" ] || fail "agent deployment configuration is missing"

grep -Fxq 'EnvironmentFile=/etc/examos/agent.conf' "$UNIT" ||
    fail "agent identity and TPM handles must come from the deployment configuration"
grep -Fxq 'Environment=EXAMOS_TPM_MODE=production' "$UNIT" ||
    fail "the packaged agent must remain in explicit production TPM mode"
! grep -Eq '^Environment=EXAMOS_TPM_(EK|AK)_HANDLE=' "$UNIT" ||
    fail "TPM handles must not be hardcoded in the service unit"

for key in EXAMOS_TPM_EK_HANDLE EXAMOS_TPM_AK_HANDLE; do
    grep -Fxq "$key=NOT_PROVISIONED" "$CONFIG" ||
        fail "$key must require explicit device enrollment"
    grep -Fxq "ExecStartPre=/usr/bin/test -n \"\${$key}\"" "$UNIT" ||
        fail "$key must be required before the agent starts"
    grep -Fxq "ExecStartPre=/usr/bin/test \"\${$key}\" != NOT_PROVISIONED" "$UNIT" ||
        fail "$key placeholder must block agent startup"
done

if grep -Fq 'ExamOS@Admin2025!' "$WINDOWS_LAUNCHER"; then
    fail "the Windows development launcher must not publish a default admin password"
fi
grep -Fq 'No default admin credentials are installed.' "$WINDOWS_LAUNCHER" ||
    fail "the Windows development launcher must state that no default admin credential exists"

echo "[P0-AGENT-CONFIG] PASS: no baked-in TPM handles; enrollment is required at startup"
