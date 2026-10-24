#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="${EXAMOS_P1_ARTIFACT_DIR:-$WORKSPACE/artifacts/p1}"
mkdir -p "$ARTIFACT_DIR"

echo "=== [P1-BOOT] QEMU / OVMF / swtpm Boot Verification ==="

OVMF_CODE=""
for cand in "/usr/share/OVMF/OVMF_CODE_4M.fd" \
            "/usr/share/OVMF/OVMF_CODE.fd" \
            "/usr/share/ovmf/OVMF.fd"; do
    if [ -f "$cand" ]; then
        OVMF_CODE="$cand"
        break
    fi
done

if [ -z "$OVMF_CODE" ]; then
    echo "[P1-BOOT] BLOCKED: OVMF firmware code not found"
    exit 2
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "[P1-BOOT] BLOCKED: qemu-system-x86_64 is unavailable"
    exit 2
fi

IMAGE_FILE=""
for cand in "$WORKSPACE/image/examos.raw.raw" "$WORKSPACE/image/examos.raw"; do
    if [ -f "$cand" ]; then
        IMAGE_FILE="$cand"
        break
    fi
done

if [ -z "$IMAGE_FILE" ]; then
    echo "[P1-BOOT] BLOCKED: No disk image found"
    exit 2
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

SWTPM_PID=""
if command -v swtpm >/dev/null 2>&1; then
    mkdir -p "$TMP_DIR/tpm"
    swtpm socket --tpmstate dir="$TMP_DIR/tpm" --ctrl type=unixio,path="$TMP_DIR/tpm/swtpm-sock" --tpm2 &
    SWTPM_PID=$!
    sleep 1
fi

ACCEL="-accel kvm"
if [ ! -w /dev/kvm ]; then
    ACCEL="-accel tcg"
fi

# PG-42: Support production mode testing by checking EXAMOS_P1_PRODUCTION_MODE
# Default to dev mode for backward compatibility
PRODUCTION_MODE="${EXAMOS_P1_PRODUCTION_MODE:-0}"
if [ "$PRODUCTION_MODE" = "1" ]; then
    echo "[P1-BOOT] INFO: Running in production mode test (EXAMOS_P1_PRODUCTION_MODE=1)"
    PRODUCTION_MODE_ARGS="-append EXAMOS_TPM_MODE=production"
else
    PRODUCTION_MODE_ARGS=""
fi

BOOT_LOG="$ARTIFACT_DIR/boot.log"
: > "$BOOT_LOG"
echo "[P1-BOOT] Launching QEMU with image $IMAGE_FILE..."
IMAGE_SHA256=$(sha256sum "$IMAGE_FILE" | cut -d' ' -f1)
START_SEC=$(date +%s)

# Run QEMU in background so we can poll for boot markers without hanging
# on a kiosk that never exits. Snapshot mode prevents image modification.
qemu-system-x86_64 \
    -M q35 $ACCEL \
    -m 2048 \
    -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive file="$IMAGE_FILE",format=raw,if=virtio,snapshot=on \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -nographic \
    $PRODUCTION_MODE_ARGS \
    -serial file:"$BOOT_LOG" >/dev/null 2>&1 &
QEMU_PID=$!

BOOT_TIMEOUT="${EXAMOS_P1_BOOT_TIMEOUT:-90}"
BOOT_READY=false
ELAPSED_SEC=0
while kill -0 "$QEMU_PID" 2>/dev/null; do
    NOW_SEC=$(date +%s)
    ELAPSED_SEC=$((NOW_SEC - START_SEC))
    if [ "$ELAPSED_SEC" -ge "$BOOT_TIMEOUT" ]; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
        QEMU_RET=124
        break
    fi
    if grep -q -E "systemd|Welcome to|Linux version" "$BOOT_LOG" 2>/dev/null; then
        BOOT_READY=true
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
        QEMU_RET=0
        break
    fi
    sleep 1
done
if [ -z "$QEMU_RET" ]; then
    wait "$QEMU_PID" 2>/dev/null || true
    QEMU_RET=$?
fi

if [ -n "$SWTPM_PID" ]; then
    kill "$SWTPM_PID" 2>/dev/null || true
fi

if grep -q -E "systemd|Welcome to|Linux version" "$BOOT_LOG" 2>/dev/null; then
    # PG-07: Verify kiosk service actually started (runtime verification)
    KIOSK_STARTED=false
    if grep -q "Starting examos-kiosk.service" "$BOOT_LOG" 2>/dev/null; then
        KIOSK_STARTED=true
    fi
    if grep -q "cage" "$BOOT_LOG" 2>/dev/null; then
        KIOSK_STARTED=true
    fi
    if grep -q "chromium" "$BOOT_LOG" 2>/dev/null; then
        KIOSK_STARTED=true
    fi

    python3 - "$ARTIFACT_DIR/boot-result.json" "$WORKSPACE" "$IMAGE_FILE" \
        "$IMAGE_SHA256" "$QEMU_RET" "$ELAPSED_SEC" "$ACCEL" "$OVMF_CODE" "$KIOSK_STARTED" <<'PY'
import datetime, hashlib, json, pathlib, subprocess, sys
out, workspace, image, digest, qemu_exit, elapsed, accel, ovmf, kiosk_started = sys.argv[1:]
current = hashlib.sha256(pathlib.Path(image).read_bytes()).hexdigest()
report = {
    "phase": "P1",
    "result": "PASS" if current == digest else "FAIL",
    "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": subprocess.check_output(["git", "-C", workspace, "rev-parse", "HEAD"], text=True).strip(),
    "image_path": str(pathlib.Path(image).resolve()),
    "image_sha256": current,
    "boot_marker": "systemd|Welcome to|Linux version",
    "kiosk_service_started": kiosk_started == "true",
    "qemu_exit_code": int(qemu_exit),
    "elapsed_sec": int(elapsed),
    "acceleration": accel,
    "ovmf_firmware": ovmf,
}
pathlib.Path(out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
sys.exit(0 if report["result"] == "PASS" else 1)
PY
    BOOT_RECORD_RC=$?
    if [ "$BOOT_RECORD_RC" -ne 0 ]; then
        echo "[P1-BOOT] FAIL: Boot evidence could not be bound to the current image"
        exit 1
    fi
    if [ "$KIOSK_STARTED" = true ]; then
        echo "[P1-BOOT] PASS: ExamOS booted successfully with kiosk service started"
    else
        echo "[P1-BOOT] WARN: ExamOS booted but kiosk service start not detected (PG-07)"
    fi
    exit 0
else
    python3 - "$ARTIFACT_DIR/boot-result.json" "$WORKSPACE" "$IMAGE_SHA256" \
        "$QEMU_RET" "$ELAPSED_SEC" "$ACCEL" <<'PY'
import datetime, json, pathlib, subprocess, sys
out, workspace, digest, qemu_exit, elapsed, accel = sys.argv[1:]
report = {
    "phase": "P1", "result": "FAIL",
    "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": subprocess.check_output(["git", "-C", workspace, "rev-parse", "HEAD"], text=True).strip(),
    "image_sha256": digest, "boot_marker": None,
    "qemu_exit_code": int(qemu_exit), "elapsed_sec": int(elapsed), "acceleration": accel,
}
pathlib.Path(out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
PY
    echo "[P1-BOOT] FAIL: Boot signature not detected in $BOOT_LOG"
    exit 1
fi
