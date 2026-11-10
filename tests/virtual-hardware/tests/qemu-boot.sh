#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../scripts" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RUN_DIR="${EXAMOS_VH_RUN_DIR:-}"
[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || {
    echo "[VH-QEMU] BLOCKED: set EXAMOS_VH_RUN_DIR to an existing evidence run." >&2
    exit 2
}
for tool in tpm2_getcap tpm2_pcrread tpm2_createek tpm2_createak \
            tpm2_readpublic tpm2_quote tpm2_checkquote openssl python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[VH-QEMU] BLOCKED: required tool not installed: $tool" >&2
        exit 2
    }
done

if bash "$SCRIPT_DIR/start-vm.sh"; then
    :
else
    result=$?
    exit "$result"
fi

VM_STARTED=1
cleanup() {
    local rc=$?
    if [[ "$VM_STARTED" -eq 1 ]]; then
        bash "$SCRIPT_DIR/stop-vm.sh" || rc=1
        VM_STARTED=0
    fi
    return "$rc"
}
trap cleanup EXIT

EPOCH_NAME="$(cat "$RUN_DIR/active-epoch")"
EPOCH_DIR="$RUN_DIR/$EPOCH_NAME"
SERIAL_LOG="$EPOCH_DIR/serial.log"
TIMEOUT_SECONDS="${EXAMOS_VH_BOOT_TIMEOUT_SECONDS:-600}"
[[ "$TIMEOUT_SECONDS" =~ ^[0-9]+$ && "$TIMEOUT_SECONDS" -ge 30 && "$TIMEOUT_SECONDS" -le 900 ]] || {
    echo "[VH-QEMU] FAIL: boot timeout must be between 30 and 900 seconds." >&2
    exit 1
}
STABILITY_SECONDS="${EXAMOS_VH_KIOSK_STABILITY_SECONDS:-30}"
[[ "$STABILITY_SECONDS" =~ ^[0-9]+$ && "$STABILITY_SECONDS" -ge 10 && "$STABILITY_SECONDS" -le 120 ]] || {
    echo "[VH-QEMU] FAIL: kiosk stability interval must be between 10 and 120 seconds." >&2
    exit 1
}

# The readiness helper only reports READY after it has observed the same
# Chromium PID alive for ten seconds. Require that marker here as well: an
# older helper that reported a single snapshot must not satisfy the boot gate.
READY_PATTERN='EXAMOS_KIOSK_READY cage=1 chromium=1 wayland_socket=1 stable_seconds=10 chromium_pid=[0-9]+'

kiosk_ready=0
for _ in $(seq 1 "$TIMEOUT_SECONDS"); do
    sync "$SERIAL_LOG" 2>/dev/null || true
    if ! bash "$SCRIPT_DIR/check-vm.sh" >/dev/null 2>&1; then
        bash "$SCRIPT_DIR/check-vm.sh" > "$EPOCH_DIR/health-check.log" 2>&1 || true
        echo "[VH-QEMU] FAIL: VM lifecycle check failed; inspect $EPOCH_DIR/health-check.log." >&2
        cat "$EPOCH_DIR/health-check.log" >&2
        exit 1
    fi
    if [[ -s "$SERIAL_LOG" ]] &&
       grep -Fq 'Security Violation: Kiosk supervisor running as root (UID 0)' "$SERIAL_LOG"; then
        echo "[VH-QEMU] FAIL: guest kiosk launcher ran as root; the security guard correctly refused to start it." >&2
        tail -n 40 "$SERIAL_LOG" >&2
        exit 1
    fi
    if [[ -s "$SERIAL_LOG" ]] &&
       grep -qiE 'examos-kiosk\.service: (Control process exited|Main process exited|Failed with result)' "$SERIAL_LOG"; then
        echo "[VH-QEMU] FAIL: guest kiosk service reported a startup or runtime failure." >&2
        tail -n 40 "$SERIAL_LOG" >&2
        exit 1
    fi
    if [[ -s "$SERIAL_LOG" ]] &&
       grep -qiE '(examos-preflight\.service: (Job .* failed|Main process exited|Failed with result)|usbguard\.service: (Main process exited|Failed with result))' "$SERIAL_LOG"; then
        echo "[VH-QEMU] FAIL: mandatory startup preflight or USBGuard failed; kiosk readiness cannot qualify this boot." >&2
        tail -n 60 "$SERIAL_LOG" >&2
        exit 1
    fi
    if [[ -s "$SERIAL_LOG" ]] &&
       grep -qiE '((dev-tpm0|dev-tpmrm0)\.device: (Job .* failed|Job .* timed out|Failed with result)|tpm2-abrmd\.service: Job .* failed|examos-agent\.service: Job .* failed)' "$SERIAL_LOG"; then
        echo "[VH-QEMU] FAIL: guest TPM device, TPM resource manager, or attestation agent failed; kiosk readiness cannot qualify this boot." >&2
        tail -n 60 "$SERIAL_LOG" >&2
        exit 1
    fi
    if [[ -s "$SERIAL_LOG" ]] &&
       grep -qiE 'apparmor\.service: (Main process exited|Failed with result)' "$SERIAL_LOG"; then
        echo "[VH-QEMU] FAIL: guest could not load its mandatory AppArmor profiles." >&2
        tail -n 60 "$SERIAL_LOG" >&2
        exit 1
    fi
    if [[ -s "$SERIAL_LOG" ]] &&
       grep -E "$READY_PATTERN" "$SERIAL_LOG" >/dev/null; then
        kiosk_ready=1
        READY_LINE="$(grep -nE "$READY_PATTERN" "$SERIAL_LOG" | tail -n 1 | cut -d: -f1)"
        break
    fi
    if [[ -s "$SERIAL_LOG" ]] &&
       grep -qiE 'examos-kiosk-readiness\.service: (Main process exited|Failed with result|start operation timed out)' "$SERIAL_LOG"; then
        diagnostics_complete=0
        for _ in $(seq 1 15); do
            if grep -Fq 'EXAMOS_KIOSK_DIAGNOSTICS_COMPLETE' "$SERIAL_LOG"; then
                diagnostics_complete=1
                break
            fi
            sleep 1
        done
        if [[ "$diagnostics_complete" -eq 1 ]]; then
            echo "[VH-QEMU] FAIL: guest readiness gate rejected the Cage, Wayland socket, or Chromium process; diagnostics completed." >&2
        else
            echo "[VH-QEMU] FAIL: guest readiness gate failed before diagnostics completed." >&2
        fi
        tail -n 60 "$SERIAL_LOG" >&2
        exit 1
    fi
    sleep 1
done
if [[ "$kiosk_ready" -ne 1 ]]; then
    if [[ -s "$SERIAL_LOG" ]]; then
        echo "[VH-QEMU] FAIL: guest did not report Cage, Wayland socket, and Chromium readiness within ${TIMEOUT_SECONDS}s." >&2
        tail -n 80 "$SERIAL_LOG" >&2
        exit 1
    fi
    echo "[VH-QEMU] BLOCKED: QEMU remained running, but no serial output was captured; guest boot state cannot be determined." >&2
    exit 2
fi

printf '[VH-QEMU] Readiness observed; checking kiosk stability for %s seconds.\n' "$STABILITY_SECONDS"
for _ in $(seq 1 "$STABILITY_SECONDS"); do
    if ! bash "$SCRIPT_DIR/check-vm.sh" >/dev/null 2>&1; then
        echo "[VH-QEMU] FAIL: VM lifecycle check failed during the kiosk stability interval." >&2
        tail -n 60 "$SERIAL_LOG" >&2
        exit 1
    fi
    if tail -n "+$((READY_LINE + 1))" "$SERIAL_LOG" |
       grep -qiE 'Chromium exited|No usable sandbox|EXAMOS_KIOSK_NOT_READY|examos-kiosk\.service: (Main process exited|Failed with result|Scheduled restart job|Deactivated successfully)|SECURITY ALERT: Chromium killed by signal|chrome_crashpad_handler.*--database is required|third_party/crashpad.*Connection reset by peer'; then
        echo "[VH-QEMU] FAIL: Chromium, Crashpad, or the kiosk service failed during the stability interval." >&2
        tail -n 60 "$SERIAL_LOG" >&2
        exit 1
    fi
    sleep 1
done
printf '[VH-QEMU] PASS: Chromium and Crashpad remained free of startup failures or signal exits for %s seconds.\n' "$STABILITY_SECONDS"

EVIDENCE="$RUN_DIR/qemu-boot"
mkdir -m 700 -- "$EVIDENCE"
# Release QEMU's TPM connection so TPM tools can query the same virtual device
# without racing the guest's active TPM interface.
bash "$SCRIPT_DIR/vm-lifecycle.sh" stop-qemu
read -r TPM_SERVER_SOCKET < <(python3 - "$EPOCH_DIR/vm-runtime.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["tpm_server_socket"])
PY
)
[[ -S "$TPM_SERVER_SOCKET" ]] || {
    echo "[VH-QEMU] FAIL: recorded virtual TPM Unix socket is unavailable." >&2
    echo "[VH-QEMU] DEBUG: TPM_SERVER_SOCKET=$TPM_SERVER_SOCKET" >&2
    echo "[VH-QEMU] DEBUG: swtpm.pid=$(cat "$EPOCH_DIR/swtpm.pid" 2>/dev/null || echo missing)" >&2
    local_sw_pid="$(cat "$EPOCH_DIR/swtpm.pid" 2>/dev/null || true)"
    if [[ -n "$local_sw_pid" ]] && kill -0 "$local_sw_pid" 2>/dev/null; then
        echo "[VH-QEMU] DEBUG: swtpm process IS ALIVE (PID $local_sw_pid)" >&2
    else
        echo "[VH-QEMU] DEBUG: swtpm process IS DEAD" >&2
    fi
    echo "[VH-QEMU] DEBUG: socket dir listing:" >&2
    ls -la "$(dirname "$TPM_SERVER_SOCKET")" >&2 2>&1 || true
    echo "[VH-QEMU] DEBUG: swtpm.log tail:" >&2
    tail -n 20 "$EPOCH_DIR/swtpm.log" >&2 2>&1 || true
    exit 1
}
export TPM2TOOLS_TCTI="swtpm:path=$TPM_SERVER_SOCKET"
tpm2_getcap pcrs > "$EVIDENCE/tpm-pcr-banks.txt"
tpm2_pcrread -o "$EVIDENCE/pcr-values.bin" sha256:0,2,4,7,11 \
    > "$EVIDENCE/pcr-values.yaml"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sppio-vh-qemu-quote.XXXXXX")"
cleanup_tpm_objects() { rm -rf -- "$TMP_DIR"; }
trap 'cleanup_tpm_objects; cleanup' EXIT
tpm2_createek -c "$TMP_DIR/ek.ctx" -G rsa -R > "$EVIDENCE/ek-create.log" 2>&1
tpm2_createak -C "$TMP_DIR/ek.ctx" -c "$TMP_DIR/ak.ctx" \
    -G rsa -g sha256 -s rsassa -u "$TMP_DIR/ak.pub" \
    -n "$TMP_DIR/ak.name" -R > "$EVIDENCE/ak-create.log" 2>&1
tpm2_flushcontext -t
tpm2_readpublic -c "$TMP_DIR/ak.ctx" -f pem \
    -o "$EVIDENCE/ak-public.pem" -q "$TMP_DIR/ak-qualified-name" \
    > "$EVIDENCE/ak-read.log" 2>&1
tpm2_flushcontext -t

NONCE="$(openssl rand -hex 32)"
tpm2_quote -c "$TMP_DIR/ak.ctx" -l sha256:0,2,4,7,11 -q "$NONCE" \
    -m "$EVIDENCE/quote.attest" -s "$EVIDENCE/quote.signature" \
    -o "$EVIDENCE/quote.pcr" > "$EVIDENCE/quote-generation.log" 2>&1
tpm2_checkquote -u "$EVIDENCE/ak-public.pem" -m "$EVIDENCE/quote.attest" \
    -s "$EVIDENCE/quote.signature" -f "$EVIDENCE/pcr-values.bin" \
    -l sha256:0,2,4,7,11 -q "$NONCE" > "$EVIDENCE/quote-verification.txt"
cp -- "$TMP_DIR/ak.name" "$EVIDENCE/ak-name.bin"

python3 - "$EVIDENCE" "$NONCE" "$EPOCH_DIR/vm.json" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
from datetime import datetime, timezone

directory = pathlib.Path(sys.argv[1])
def digest(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

pcr_text = (directory / "pcr-values.yaml").read_text(encoding="utf-8", errors="replace")
pcrs = {}
for index, value in re.findall(r"^\s*(\d+)\s*:\s*0x([0-9a-fA-F]{64})\s*$", pcr_text, re.M):
    pcrs[index] = value.lower()
with open(sys.argv[3], encoding="utf-8") as stream:
    vm = json.load(stream)
runtime_file = pathlib.Path(sys.argv[3]).parent / "vm-runtime.json"
if not runtime_file.is_file():
    runtime_file = directory.parent / "vm-runtime.json"
runtime = json.loads(runtime_file.read_text(encoding="utf-8"))
record = {
    "schema": "sppio.virtual-hardware.qemu-boot.v1",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "evidence_type": "qemu-uefi-with-swtpm",
    "hardware_acceleration": runtime["acceleration"],
    "network": "none",
    "virtual_tpm": True,
    "physical_tpm": False,
    "base_image": vm["base_image"],
    "booted_disk": "read-only raw base image through qcow2 copy-on-write overlay",
    "base_image_sha256": vm["base_image_sha256"],
    "pcr_selection": "sha256:0,2,4,7,11",
    "pcr_values": pcrs,
    "quote_nonce": sys.argv[2],
    "quote_sha256": digest(directory / "quote.attest"),
    "signature_sha256": digest(directory / "quote.signature"),
    "tpm2_checkquote": "PASS",
    "tcg_event_log_reconstruction": "BLOCKED: guest TCG event log is not exported by the current image harness",
    "measured_boot_evidence": (
        "PASS: selected boot PCR contains non-zero values"
        if any(pcrs.get(index, "0" * 64) != "0" * 64 for index in ("0", "2", "4", "7"))
        else "BLOCKED: selected boot PCRs were zero or not parsed"
    ),
}
with (directory / "qemu-boot-evidence.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

printf '[VH-QEMU] PASS: QEMU booted the existing disk through OVMF with an isolated swtpm and verified a fresh quote over post-boot PCRs.\n'
