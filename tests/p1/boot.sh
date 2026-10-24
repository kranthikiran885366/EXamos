#!/usr/bin/env bash
# Verify a P1 disk image reaches the kiosk-ready state under QEMU/OVMF.
# A message from systemd while it is still in the initramfs is not boot success.
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${EXAMOS_P1_ARTIFACT_DIR:-}" ]; then
    mkdir -p "$WORKSPACE/artifacts/p1/runs"
    EXAMOS_P1_ARTIFACT_DIR="$(mktemp -d "$WORKSPACE/artifacts/p1/runs/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
fi
ARTIFACT_DIR="$EXAMOS_P1_ARTIFACT_DIR"
export EXAMOS_P1_ARTIFACT_DIR
mkdir -p "$ARTIFACT_DIR"

source "$WORKSPACE/scripts/examos-lib.sh"

BOOT_LOG="$ARTIFACT_DIR/boot.log"
BOOT_RESULT="$ARTIFACT_DIR/boot-result.json"
SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
SOURCE_TREE_STATE="CLEAN"
if [ -n "$(git -C "$WORKSPACE" status --porcelain=v1 --untracked-files=all -- . \
    ':(exclude)artifacts/**' ':(exclude)image/p0/output/**' \
    ':(exclude)build/**' ':(exclude)cache/**' 2>/dev/null || true)" ]; then
    SOURCE_TREE_STATE="DIRTY"
fi

IMAGE_FILE="NOT_AVAILABLE"
IMAGE_HASH="NOT_AVAILABLE"
IMAGE_HASH_AFTER="NOT_AVAILABLE"
OVMF_CODE="NOT_AVAILABLE"
ACCELERATION="NOT_AVAILABLE"
QEMU_EXIT=125
ELAPSED_SEC=0
STOP_REASON="not_started"
INITRD_SYSTEMD=false
POST_INITRD_TARGET=false
KIOSK_READY=false
IMAGE_UNCHANGED=false
QEMU_PID=""
TMP_DIR=""

write_result() {
    local status="$1" reason="$2"
    EXAMOS_BOOT_STATUS="$status" \
    EXAMOS_BOOT_REASON="$reason" \
    EXAMOS_BOOT_SOURCE_COMMIT="$SOURCE_COMMIT" \
    EXAMOS_BOOT_SOURCE_TREE_STATE="$SOURCE_TREE_STATE" \
    EXAMOS_BOOT_IMAGE_FILE="$IMAGE_FILE" \
    EXAMOS_BOOT_IMAGE_HASH="$IMAGE_HASH" \
    EXAMOS_BOOT_IMAGE_HASH_AFTER="$IMAGE_HASH_AFTER" \
    EXAMOS_BOOT_OVMF="$OVMF_CODE" \
    EXAMOS_BOOT_ACCELERATION="$ACCELERATION" \
    EXAMOS_BOOT_QEMU_EXIT="$QEMU_EXIT" \
    EXAMOS_BOOT_ELAPSED="$ELAPSED_SEC" \
    EXAMOS_BOOT_STOP_REASON="$STOP_REASON" \
    EXAMOS_BOOT_INITRD_SYSTEMD="$INITRD_SYSTEMD" \
    EXAMOS_BOOT_POST_INITRD_TARGET="$POST_INITRD_TARGET" \
    EXAMOS_BOOT_KIOSK_READY="$KIOSK_READY" \
    EXAMOS_BOOT_IMAGE_UNCHANGED="$IMAGE_UNCHANGED" \
    python3 - "$BOOT_RESULT" <<'PY'
import datetime
import json
import os
import pathlib
import sys

def as_bool(name):
    return os.environ[name] == "true"

report = {
    "phase": "P1",
    "result": os.environ["EXAMOS_BOOT_STATUS"],
    "reason": os.environ["EXAMOS_BOOT_REASON"],
    "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": os.environ["EXAMOS_BOOT_SOURCE_COMMIT"],
    "source_tree_state_at_start": os.environ["EXAMOS_BOOT_SOURCE_TREE_STATE"],
    "image_path": os.environ["EXAMOS_BOOT_IMAGE_FILE"],
    "image_sha256": os.environ["EXAMOS_BOOT_IMAGE_HASH"],
    "image_sha256_after_boot": os.environ["EXAMOS_BOOT_IMAGE_HASH_AFTER"],
    "qemu_exit_code": int(os.environ["EXAMOS_BOOT_QEMU_EXIT"]),
    "elapsed_sec": int(os.environ["EXAMOS_BOOT_ELAPSED"]),
    "stop_reason": os.environ["EXAMOS_BOOT_STOP_REASON"],
    "acceleration": os.environ["EXAMOS_BOOT_ACCELERATION"],
    "ovmf_firmware": os.environ["EXAMOS_BOOT_OVMF"],
    "markers": {
        "initramfs_systemd": as_bool("EXAMOS_BOOT_INITRD_SYSTEMD"),
        "post_initrd_target": as_bool("EXAMOS_BOOT_POST_INITRD_TARGET"),
        "kiosk_ready": as_bool("EXAMOS_BOOT_KIOSK_READY"),
        "image_unchanged": as_bool("EXAMOS_BOOT_IMAGE_UNCHANGED"),
    },
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
PY
}

blocked() {
    local reason="$1"
    echo "[P1-BOOT] BLOCKED: $reason" >&2
    write_result "BLOCKED" "$reason"
    exit 2
}

failed() {
    local reason="$1"
    echo "[P1-BOOT] FAIL: $reason" >&2
    write_result "FAIL" "$reason"
    exit 1
}

stop_qemu() {
    [ -n "$QEMU_PID" ] || return 0
    if kill -0 "$QEMU_PID" 2>/dev/null; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        local deadline=$((SECONDS + 10))
        while kill -0 "$QEMU_PID" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
            sleep 1
        done
        if kill -0 "$QEMU_PID" 2>/dev/null; then
            kill -KILL "$QEMU_PID" 2>/dev/null || true
        fi
    fi
    wait "$QEMU_PID" 2>/dev/null
    QEMU_EXIT=$?
    QEMU_PID=""
}

cleanup() {
    stop_qemu || true
    [ -z "$TMP_DIR" ] || rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT

echo "=== [P1-BOOT] QEMU / OVMF Kiosk-Readiness Verification ==="
if [ -e "$BOOT_LOG" ] || [ -L "$BOOT_LOG" ] || [ -e "$BOOT_RESULT" ] || [ -L "$BOOT_RESULT" ]; then
    echo "[P1-BOOT] BLOCKED: refusing to overwrite existing boot evidence in $ARTIFACT_DIR" >&2
    exit 2
fi
: > "$BOOT_LOG"

for tool in qemu-system-x86_64 python3 sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || blocked "required tool is unavailable: $tool"
done

for candidate in "$WORKSPACE/image/examos.raw.raw" "$WORKSPACE/image/examos.raw"; do
    if [ -f "$candidate" ] && [ -s "$candidate" ] && [ ! -L "$candidate" ]; then
        IMAGE_FILE="$(realpath -e -- "$candidate")"
        break
    fi
done
[ "$IMAGE_FILE" != "NOT_AVAILABLE" ] || blocked "no non-empty disk image found"
echo "[P1-BOOT] Hashing candidate image before boot: $IMAGE_FILE"
IMAGE_HASH="$(sha256sum "$IMAGE_FILE" | awk '{print $1}')" || failed "unable to hash disk image"

OVMF_CODE="$(examos_find_ovmf_code)" || blocked "OVMF firmware code was not found"
OVMF_VARS_TEMPLATE="$(examos_find_ovmf_vars || true)"
QEMU_ACCEL="$(examos_qemu_accel)" || blocked "requested QEMU acceleration is unavailable or invalid"
read -r -a QEMU_ACCEL_ARGS <<< "$QEMU_ACCEL"
case "$QEMU_ACCEL" in *"-accel kvm"*) ACCELERATION="KVM" ;; *) ACCELERATION="TCG" ;; esac
QEMU_RESOURCES="$(examos_qemu_resources)" || blocked "host does not have safe resources for a P1 guest"
IFS=$'\t' read -r QEMU_MEMORY_MIB QEMU_CPUS <<< "$QEMU_RESOURCES"

BOOT_TIMEOUT="${EXAMOS_P1_BOOT_TIMEOUT:-180}"
case "$BOOT_TIMEOUT" in ''|*[!0-9]*) blocked "EXAMOS_P1_BOOT_TIMEOUT must be an integer" ;; esac
[ "$BOOT_TIMEOUT" -ge 30 ] && [ "$BOOT_TIMEOUT" -le 600 ] ||
    blocked "EXAMOS_P1_BOOT_TIMEOUT must be between 30 and 600 seconds"

TMP_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/examos-p1-boot.XXXXXX")" || blocked "unable to create temporary directory"
TMP_VARS="$TMP_DIR/OVMF_VARS.fd"
NORMALIZED_LOG="$TMP_DIR/boot.normalized.log"
if [ -n "$OVMF_VARS_TEMPLATE" ]; then
    cp -- "$OVMF_VARS_TEMPLATE" "$TMP_VARS" || failed "unable to create ephemeral OVMF variables"
else
    truncate -s 4M "$TMP_VARS" || failed "unable to initialize ephemeral OVMF variables"
fi

guest_ready() {
    examos_normalize_serial_log "$BOOT_LOG" "$NORMALIZED_LOG" || return 1
    grep -qE 'systemd [0-9]+(\.[0-9]+)?[^[:cntrl:]]* running in system mode|systemd\[1\]' "$NORMALIZED_LOG" &&
        grep -qiE 'Reached target (Graphical Interface|Multi-User System|graphical\.target|multi-user\.target)' "$NORMALIZED_LOG" &&
        grep -Fq 'EXAMOS_KIOSK_READY cage=1 chromium=1 wayland_socket=1' "$NORMALIZED_LOG"
}

echo "[P1-BOOT] Image: $IMAGE_FILE"
echo "[P1-BOOT] Starting QEMU (${ACCELERATION}, ${QEMU_MEMORY_MIB} MiB, ${QEMU_CPUS} vCPU, ${BOOT_TIMEOUT}s deadline)..."
START_SEC=$SECONDS
qemu-system-x86_64 \
    -M q35 "${QEMU_ACCEL_ARGS[@]}" \
    -m "$QEMU_MEMORY_MIB" -smp "$QEMU_CPUS" -snapshot -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$TMP_VARS" \
    -drive file="$IMAGE_FILE",format=raw,if=virtio,snapshot=on \
    -net none -display none -monitor none -serial file:"$BOOT_LOG" \
    >"$TMP_DIR/qemu.log" 2>&1 &
QEMU_PID=$!

BOOT_READY=false
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if guest_ready; then
        BOOT_READY=true
        STOP_REASON="kiosk_ready"
        stop_qemu || true
        break
    fi
    if [ $((SECONDS - START_SEC)) -ge "$BOOT_TIMEOUT" ]; then
        STOP_REASON="readiness_timeout"
        stop_qemu || true
        break
    fi
    sleep 1
done
if [ -n "$QEMU_PID" ]; then
    wait "$QEMU_PID" 2>/dev/null
    QEMU_EXIT=$?
    QEMU_PID=""
    STOP_REASON="qemu_exited"
fi
ELAPSED_SEC=$((SECONDS - START_SEC))

examos_normalize_serial_log "$BOOT_LOG" "$NORMALIZED_LOG" || true
grep -qE 'systemd [0-9]+(\.[0-9]+)?[^[:cntrl:]]* running in system mode|systemd\[1\]' "$NORMALIZED_LOG" 2>/dev/null && INITRD_SYSTEMD=true
grep -qiE 'Reached target (Graphical Interface|Multi-User System|graphical\.target|multi-user\.target)' "$NORMALIZED_LOG" 2>/dev/null && POST_INITRD_TARGET=true
grep -Fq 'EXAMOS_KIOSK_READY cage=1 chromium=1 wayland_socket=1' "$NORMALIZED_LOG" 2>/dev/null && KIOSK_READY=true
IMAGE_HASH_AFTER="$(sha256sum "$IMAGE_FILE" | awk '{print $1}')" || failed "unable to hash disk image after QEMU"
[ "$IMAGE_HASH_AFTER" = "$IMAGE_HASH" ] && IMAGE_UNCHANGED=true

if [ "$BOOT_READY" = true ] && [ "$POST_INITRD_TARGET" = true ] && \
    [ "$KIOSK_READY" = true ] && [ "$IMAGE_UNCHANGED" = true ]; then
    write_result "PASS" "guest reached post-initramfs target and reported live kiosk readiness"
    echo "[P1-BOOT] PASS: post-initramfs kiosk readiness was observed"
    exit 0
fi

failed "guest did not prove a post-initramfs target and live Cage/Chromium kiosk readiness (stop=${STOP_REASON}, qemu_exit=${QEMU_EXIT})"
