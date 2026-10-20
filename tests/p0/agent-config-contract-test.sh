#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
UNIT="$WORKSPACE/image/overlay/etc/systemd/system/examos-agent.service"
CONFIG="$WORKSPACE/image/overlay/etc/examos/agent.conf"
PROCTOR_CONFIG="$WORKSPACE/image/overlay/etc/examos/proctor.env"
WINDOWS_LAUNCHER="$WORKSPACE/scripts/launch-windows.bat"
SERVER_LAUNCHER="$WORKSPACE/scripts/launch-server.sh"
AGENT_MAIN="$WORKSPACE/agent/main.c"
TPM_IMPLEMENTATION="$WORKSPACE/agent/attestation/tpm_attestation.c"

fail() {
    echo "[P0-AGENT-CONFIG] FAIL: $*" >&2
    exit 1
}

[ -f "$UNIT" ] || fail "agent systemd unit is missing"
[ -f "$CONFIG" ] || fail "agent deployment configuration is missing"
[ -f "$PROCTOR_CONFIG" ] || fail "agent token deployment configuration is missing"

grep -Fq 'EnvironmentFile=/etc/examos/agent.conf' "$UNIT" || fail "agent identity must be supplied from deployment configuration"
grep -Fq 'EnvironmentFile=/etc/examos/proctor.env' "$UNIT" || fail "agent token must be supplied from deployment configuration"
grep -Fxq 'EXAMOS_SERVER_BASE_URL=NOT_PROVISIONED' "$CONFIG" || fail "server endpoint must require deployment provisioning"
grep -Fxq 'EXAMOS_DEVICE_ID=NOT_PROVISIONED' "$CONFIG" || fail "device identity must require deployment provisioning"
grep -Fq 'EXAMOS_AGENT_API_TOKEN=NOT_PROVISIONED' "$PROCTOR_CONFIG" || fail "agent bearer token must require deployment provisioning"
grep -Fq '${EXAMOS_SERVER_BASE_URL}' "$UNIT" || fail "service must pass the configured server endpoint"
grep -Fq '${EXAMOS_DEVICE_ID}' "$UNIT" || fail "service must pass the configured device identity"
grep -Fq 'ExecStartPre=/usr/bin/test "${EXAMOS_SERVER_BASE_URL}" != NOT_PROVISIONED' "$UNIT" || fail "server endpoint placeholder must block startup"
grep -Fq 'ExecStartPre=/usr/bin/test "${EXAMOS_DEVICE_ID}" != NOT_PROVISIONED' "$UNIT" || fail "device identity placeholder must block startup"
grep -Fq 'ExecStartPre=/usr/bin/test "${EXAMOS_AGENT_API_TOKEN}" != NOT_PROVISIONED' "$UNIT" || fail "agent token placeholder must block startup"

if grep -Fq 'ExamOS@Admin2025!' "$WINDOWS_LAUNCHER"; then
    fail "the Windows development launcher must not publish a default admin password"
fi
grep -Fq 'No default admin credentials are installed.' "$WINDOWS_LAUNCHER" ||
    fail "the Windows development launcher must state that no default admin credential exists"
! grep -Fq 'ExamOS@Admin2025!' "$SERVER_LAUNCHER" ||
    fail "the WSL server launcher must not create or publish a default admin password"
grep -Fq 'Agent requires a provisioned server URL and device identity.' "$AGENT_MAIN" ||
    fail "agent must reject absent deployment identity instead of selecting a baked-in default"
grep -Fq 'TPM quote and event-log attestation are not established; refusing to start.' "$AGENT_MAIN" ||
    fail "agent must fail closed when key-backed TPM attestation cannot be established"
! grep -Eq 'INITIAL-BOOT-NONCE|EXAMOS-TPM2-(EK|AK)-|golden_pcrs|synthetic log hash' "$TPM_IMPLEMENTATION" ||
    fail "TPM identity, PCR, nonce, and event log values must not be fabricated"

echo "[P0-AGENT-CONFIG] PASS: no baked-in TPM handles; enrollment is required at startup"
