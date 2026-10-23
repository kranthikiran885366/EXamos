#!/usr/bin/env bash
# Real hardware trust gate. This script deliberately has no swtpm fallback.
set -euo pipefail

ARTIFACT_DIR=${EXAMOS_PRODUCTION_ARTIFACT_DIR:-artifacts/production}
mkdir -p "$ARTIFACT_DIR"
REPORT="$ARTIFACT_DIR/hardware-trust.json"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/examos-hardware-trust.XXXXXX")
cleanup() {
    if [ -n "${AK_CONTEXT:-}" ] && [ -f "$AK_CONTEXT" ]; then
        tpm2_flushcontext "$AK_CONTEXT" >/dev/null 2>&1 || true
    fi
    if [ -n "${EK_CONTEXT:-}" ] && [ -f "$EK_CONTEXT" ]; then
        tpm2_flushcontext "$EK_CONTEXT" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

status=PASS
reasons=()
block() { status=BLOCKED; reasons+=("$1"); echo "[HARDWARE] BLOCKED: $1" >&2; }
fail() { status=FAIL; reasons+=("$1"); echo "[HARDWARE] FAIL: $1" >&2; }

for tool in tpm2_getcap tpm2_pcrread tpm2_readpublic tpm2_quote \
            tpm2_checkquote tpm2_eventlog openssl xxd python3 curl; do
    command -v "$tool" >/dev/null 2>&1 || block "missing required tool: $tool"
done

TPM_DEVICE=""
if [ -c /dev/tpmrm0 ] && [ -r /dev/tpmrm0 ] && [ -w /dev/tpmrm0 ]; then
    TPM_DEVICE=/dev/tpmrm0
elif [ -c /dev/tpm0 ] && [ -r /dev/tpm0 ] && [ -w /dev/tpm0 ]; then
    TPM_DEVICE=/dev/tpm0
else
    block "no accessible physical TPM character device"
fi

EVENT_LOG=/sys/kernel/security/tpm0/binary_bios_measurements
[ -r "$EVENT_LOG" ] || block "TCG firmware event log is unavailable"

SECURE_BOOT_VAR=$(find /sys/firmware/efi/efivars -maxdepth 1 \
    -name 'SecureBoot-*' -type f -print -quit 2>/dev/null || true)
if [ -z "$SECURE_BOOT_VAR" ]; then
    block "UEFI Secure Boot variable is unavailable"
else
    SECURE_BOOT_VALUE=$(od -An -t u1 -j 4 -N 1 "$SECURE_BOOT_VAR" 2>/dev/null | tr -d ' ')
    [ "$SECURE_BOOT_VALUE" = "1" ] || fail "UEFI Secure Boot is not enabled"
fi

if [ "$status" = PASS ]; then
    export TPM2TOOLS_TCTI="device:$TPM_DEVICE"
    tpm2_getcap properties-fixed >"$WORK_DIR/properties.txt" || fail "cannot query TPM properties"
    tpm2_pcrread -o "$WORK_DIR/pcrs.bin" sha256:0,4,7,11 \
        >"$WORK_DIR/pcrs.yaml" || fail "cannot read required SHA-256 PCRs"
    tpm2_eventlog "$EVENT_LOG" >"$WORK_DIR/eventlog.yaml" || fail "TCG event log cannot be parsed"
fi

EK_HANDLE="${EXAMOS_TPM_EK_HANDLE:-}"
AK_HANDLE="${EXAMOS_TPM_AK_HANDLE:-}"
if [ -z "$EK_HANDLE" ] || [ "$EK_HANDLE" = "NOT_PROVISIONED" ] ||
   [ -z "$AK_HANDLE" ] || [ "$AK_HANDLE" = "NOT_PROVISIONED" ]; then
    block "enrolled persistent EK/AK handles are not provisioned; refusing transient EK creation"
fi
SERVER="${EXAMOS_SERVER_BASE_URL:-}"
TOKEN="${EXAMOS_AGENT_API_TOKEN:-}"
DEVICE="${EXAMOS_DEVICE_ID:-}"
RELEASE="${EXAMOS_RELEASE_ID:-}"
if [ -z "$SERVER" ] || [ -z "$TOKEN" ] || [ -z "$DEVICE" ] || [ -z "$RELEASE" ]; then
    block "server-issued nonce requires EXAMOS_SERVER_BASE_URL, EXAMOS_AGENT_API_TOKEN, EXAMOS_DEVICE_ID, EXAMOS_RELEASE_ID"
fi

if [ "$status" = PASS ]; then
    tpm2_readpublic -c "$EK_HANDLE" >/dev/null || fail "enrolled EK handle is not readable"
    tpm2_readpublic -c "$AK_HANDLE" -f pem -o "$WORK_DIR/ak.pem" \
        >/dev/null || fail "enrolled AK handle is not readable"
    NONCE="$(curl -fsS -X POST "$SERVER/api/v1/attestation/nonce" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"device_id\":\"$DEVICE\",\"release_id\":\"$RELEASE\"}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("nonce",""))')"
    if [ "${#NONCE}" -ne 64 ]; then
        fail "server did not issue a 32-byte hex nonce"
    else
        tpm2_quote -c "$AK_HANDLE" -l sha256:0,4,7,11 -q "$NONCE" \
            -m "$WORK_DIR/quote.msg" -s "$WORK_DIR/quote.sig" \
            -o "$WORK_DIR/quote.pcr" >/dev/null || fail "physical TPM quote failed"
        tpm2_checkquote -u "$WORK_DIR/ak.pem" -m "$WORK_DIR/quote.msg" \
            -s "$WORK_DIR/quote.sig" -f "$WORK_DIR/pcrs.bin" \
            -l sha256:0,4,7,11 -q "$NONCE" >/dev/null || fail "physical TPM quote verification failed"
    fi
fi

export EXAMOS_HW_STATUS="$status"
export EXAMOS_HW_REASONS="$(printf '%s\n' "${reasons[@]:-}")"
export EXAMOS_HW_TPM_DEVICE="$TPM_DEVICE"
export EXAMOS_HW_SECURE_BOOT="${SECURE_BOOT_VALUE:-unknown}"
python3 - "$REPORT" <<'PY'
import json, os, pathlib, sys
reasons = [line for line in os.environ.get("EXAMOS_HW_REASONS", "").splitlines() if line]
report = {
    "schema": "examos-hardware-trust-v1",
    "status": os.environ["EXAMOS_HW_STATUS"],
    "synthetic_tpm_allowed": False,
    "tpm_device": os.environ.get("EXAMOS_HW_TPM_DEVICE") or None,
    "secure_boot_enabled": os.environ.get("EXAMOS_HW_SECURE_BOOT") == "1",
    "required_pcrs": [0, 4, 7, 11],
    "reasons": reasons,
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
PY

cat "$REPORT"
[ "$status" = PASS ] && exit 0
[ "$status" = BLOCKED ] && exit 2
exit 1
