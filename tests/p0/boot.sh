#!/usr/bin/env bash
# Boot the exact, checksummed disk image produced in this P0 evidence run.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P0_ARTIFACT_DIR:?Run scripts/p0.sh or set EXAMOS_P0_ARTIFACT_DIR to the evidence directory for this run}"
source "$WORKSPACE/scripts/examos-lib.sh"

fail() {
    local message="$1"
    echo "[P0-BOOT] FATAL: $message" >&2
    if [ -n "${BOOT_RESULT:-}" ] && [ -n "${BOOT_RESULT_TMP:-}" ]; then
        jq -n --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --arg reason "$message" --arg commit "${SOURCE_COMMIT:-UNKNOWN}" \
            --arg image_hash "${IMAGE_HASH:-UNKNOWN}" \
            '{phase:"P0", check:"disk_boot", status:"FAIL", timestamp:$timestamp,
              reason:$reason, source_commit:$commit, image_sha256:$image_hash}' \
            > "$BOOT_RESULT_TMP" && mv -- "$BOOT_RESULT_TMP" "$BOOT_RESULT"
    fi
    exit 1
}

examos_p0_validate_run_dir "$WORKSPACE" "$ARTIFACT_DIR" || {
    echo "[P0-BOOT] FATAL: evidence path is not an isolated P0 run directory." >&2
    exit 2
}
for tool in qemu-system-x86_64 timeout sha256sum jq git; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[P0-BOOT] FATAL: required disk boot test tool is missing: $tool" >&2
        exit 2
    }
done

BOOT_LOG="$ARTIFACT_DIR/boot.log"
BOOT_RESULT="$ARTIFACT_DIR/boot-result.json"
BOOT_RESULT_TMP="$ARTIFACT_DIR/.boot-result.json.tmp"
for output in "$BOOT_LOG" "$BOOT_RESULT" "$BOOT_RESULT_TMP"; do
    [ ! -e "$output" ] && [ ! -L "$output" ] || {
        echo "[P0-BOOT] FATAL: evidence output already exists; refusing to overwrite: $output" >&2
        exit 2
    }
done

SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)" || exit 2
SOURCE_STATUS="$(examos_p0_source_status "$WORKSPACE")" || exit 2
[ -z "$SOURCE_STATUS" ] || {
    echo "[P0-BOOT] BLOCKED: disk boot evidence requires a clean source tree." >&2
    printf '%s\n' "$SOURCE_STATUS" >&2
    exit 2
}

EXPECTED_RELATIVE="$(realpath --relative-to="$WORKSPACE" "$ARTIFACT_DIR/examos-p0.raw")" || exit 2
IMAGE_RELATIVE=""
[ -s "$ARTIFACT_DIR/image-path.txt" ] && IFS= read -r IMAGE_RELATIVE < "$ARTIFACT_DIR/image-path.txt"
[ "$IMAGE_RELATIVE" = "$EXPECTED_RELATIVE" ] || {
    echo "[P0-BOOT] FATAL: run-bound image path is absent or does not identify this P0 run." >&2
    exit 1
}
IMAGE_FILE="$WORKSPACE/$IMAGE_RELATIVE"
[ -f "$IMAGE_FILE" ] && [ -s "$IMAGE_FILE" ] && [ ! -L "$IMAGE_FILE" ] || {
    echo "[P0-BOOT] FATAL: the disk image for this run is missing or invalid." >&2
    exit 1
}
[ -s "$ARTIFACT_DIR/image.sha256" ] || {
    echo "[P0-BOOT] FATAL: the disk checksum for this run is missing." >&2
    exit 1
}
sha256sum --check "$ARTIFACT_DIR/image.sha256" || {
    echo "[P0-BOOT] FATAL: the run-bound disk checksum did not verify." >&2
    exit 1
}
IMAGE_HASH="$(cut -d' ' -f1 "$ARTIFACT_DIR/image.sha256")"
[[ "$IMAGE_HASH" =~ ^[0-9a-f]{64}$ ]] || {
    echo "[P0-BOOT] FATAL: disk checksum is not a SHA-256 digest." >&2
    exit 1
}

OVMF_CODE="$(examos_find_ovmf_code)" || {
    echo "[P0-BOOT] FATAL: OVMF code firmware was not found." >&2
    exit 2
}
OVMF_VARS_TEMPLATE="$(examos_find_ovmf_vars || true)"
QEMU_ACCEL="$(examos_qemu_accel)"
QEMU_RESOURCES="$(examos_qemu_resources)" || {
    echo "[P0-BOOT] FATAL: unable to derive safe QEMU resources from the host." >&2
    exit 2
}
IFS=$'\t' read -r QEMU_MEMORY_MIB QEMU_CPUS <<< "$QEMU_RESOURCES"
QEMU_ACCELERATION="TCG"
case "$QEMU_ACCEL" in *"-accel kvm"*) QEMU_ACCELERATION="KVM" ;; esac
BOOT_TIMEOUT="${EXAMOS_P0_DISK_BOOT_TIMEOUT:-240}"
case "$BOOT_TIMEOUT" in ''|*[!0-9]*) echo "[P0-BOOT] FATAL: EXAMOS_P0_DISK_BOOT_TIMEOUT must be an integer." >&2; exit 2 ;; esac
[ "$BOOT_TIMEOUT" -ge 30 ] && [ "$BOOT_TIMEOUT" -le 600 ] || {
    echo "[P0-BOOT] FATAL: EXAMOS_P0_DISK_BOOT_TIMEOUT must be between 30 and 600 seconds." >&2
    exit 2
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/examos-p0-disk-boot.XXXXXX")" || exit 2
QEMU_PID=""
boot_cleanup() {
    local exit_code=$?
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    if [ "$exit_code" -ne 0 ] && [ -s "$BOOT_RESULT" ] &&
        jq -e '.status == "IN_PROGRESS"' "$BOOT_RESULT" >/dev/null 2>&1; then
        jq -n --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --arg commit "${SOURCE_COMMIT:-UNKNOWN}" --arg image_hash "${IMAGE_HASH:-UNKNOWN}" \
            --argjson exit_code "$exit_code" \
            '{phase:"P0",check:"disk_boot",status:"FAIL",timestamp:$timestamp,
              reason:"disk boot validator exited before completing evidence",exit_code:$exit_code,
              source_commit:$commit,image_sha256:$image_hash}' \
            > "$BOOT_RESULT_TMP" && mv -- "$BOOT_RESULT_TMP" "$BOOT_RESULT" || true
    fi
    rm -rf -- "$TMP_DIR"
}
trap boot_cleanup EXIT
TMP_VARS="$TMP_DIR/OVMF_VARS.fd"
if [ -n "$OVMF_VARS_TEMPLATE" ]; then
    cp -- "$OVMF_VARS_TEMPLATE" "$TMP_VARS" || fail "Unable to create ephemeral OVMF variables."
else
    truncate -s 4M "$TMP_VARS" || fail "Unable to initialize ephemeral OVMF variables."
fi
: > "$BOOT_LOG"
BOOT_RESULT_TMP="$ARTIFACT_DIR/.boot-result.json.tmp"
jq -n --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg commit "$SOURCE_COMMIT" --arg image_hash "$IMAGE_HASH" \
    '{phase:"P0", check:"disk_boot", status:"IN_PROGRESS", timestamp:$timestamp,
      source_commit:$commit, image_sha256:$image_hash}' > "$BOOT_RESULT_TMP" || exit 2
mv -- "$BOOT_RESULT_TMP" "$BOOT_RESULT" || exit 2

echo "[P0-BOOT] Image: $IMAGE_RELATIVE"
echo "[P0-BOOT] Image SHA-256: $IMAGE_HASH"
echo "[P0-BOOT] OVMF: $OVMF_CODE"
echo "[P0-BOOT] Runtime allocation: ${QEMU_MEMORY_MIB} MiB RAM, ${QEMU_CPUS} vCPUs, $QEMU_ACCELERATION"
echo "[P0-BOOT] Starting disk boot with a ${BOOT_TIMEOUT}s readiness deadline."
# The QEMU snapshot overlay preserves the canonical run artifact.
# shellcheck disable=SC2086
qemu-system-x86_64 -M q35 $QEMU_ACCEL \
    -m "$QEMU_MEMORY_MIB" -smp "$QEMU_CPUS" -snapshot \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$TMP_VARS" \
    -drive file="$IMAGE_FILE",format=raw,if=virtio \
    -net none -display none -serial file:"$BOOT_LOG" \
    > "$TMP_DIR/qemu.log" 2>&1 &
QEMU_PID=$!

disk_boot_ready() {
    grep -qE 'Linux version [0-9]' "$BOOT_LOG" &&
        grep -qE 'systemd [0-9]+(\.[0-9]+)?[^[:cntrl:]]* running in system mode|systemd\[1\]' "$BOOT_LOG" &&
        grep -qiE 'Reached target.*(Multi-User System|multi-user\.target)' "$BOOT_LOG" &&
        grep -qE '^[[:alnum:]_.-]+ login:' "$BOOT_LOG"
}

BOOT_START=$SECONDS
BOOT_READY=false
QEMU_STATUS=0
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if disk_boot_ready; then
        BOOT_READY=true
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        set +e
        wait "$QEMU_PID"
        QEMU_STATUS=$?
        set -e
        QEMU_PID=""
        break
    fi
    if [ "$((SECONDS - BOOT_START))" -ge "$BOOT_TIMEOUT" ]; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        set +e
        wait "$QEMU_PID"
        set -e
        QEMU_STATUS=124
        QEMU_PID=""
        break
    fi
    sleep 1
done
if [ -n "$QEMU_PID" ]; then
    set +e
    wait "$QEMU_PID"
    QEMU_STATUS=$?
    set -e
    QEMU_PID=""
fi

IMAGE_HASH_AFTER="$(sha256sum "$IMAGE_FILE" | cut -d' ' -f1)" || fail "Unable to verify the disk image after boot."
IMAGE_UNCHANGED=false
[ "$IMAGE_HASH_AFTER" = "$IMAGE_HASH" ] && IMAGE_UNCHANGED=true
KERNEL=false
SYSTEMD=false
MULTIUSER=false
LOGIN_PROMPT=false
grep -qE 'Linux version [0-9]' "$BOOT_LOG" && KERNEL=true
grep -qE 'systemd [0-9]+(\.[0-9]+)?[^[:cntrl:]]* running in system mode|systemd\[1\]' "$BOOT_LOG" && SYSTEMD=true
grep -qiE 'Reached target (Multi-User System|multi-user\.target)([[:space:].]|$)' "$BOOT_LOG" && MULTIUSER=true
grep -qE '^[[:alnum:]_.-]+ login:' "$BOOT_LOG" && LOGIN_PROMPT=true
STATUS="FAIL"
if [ "$BOOT_READY" = true ] && [ "$KERNEL" = true ] && [ "$SYSTEMD" = true ] && \
    [ "$MULTIUSER" = true ] && [ "$LOGIN_PROMPT" = true ] && [ "$IMAGE_UNCHANGED" = true ]; then
    STATUS="PASS"
fi

SOURCE_COMMIT_AFTER="$(git -C "$WORKSPACE" rev-parse HEAD)" || fail "Unable to recheck source commit."
SOURCE_STATUS_AFTER="$(examos_p0_source_status "$WORKSPACE")" || fail "Unable to recheck source worktree state."
[ "$SOURCE_COMMIT_AFTER" = "$SOURCE_COMMIT" ] && [ -z "$SOURCE_STATUS_AFTER" ] ||
    fail "Source commit or worktree changed during disk boot validation."
jq -n --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg status "$STATUS" --arg commit "$SOURCE_COMMIT" \
    --arg image_path "$IMAGE_RELATIVE" --arg image_hash "$IMAGE_HASH" \
    --arg image_hash_after "$IMAGE_HASH_AFTER" --arg acceleration "$QEMU_ACCELERATION" \
    --argjson memory_mib "$QEMU_MEMORY_MIB" --argjson vcpus "$QEMU_CPUS" \
    --argjson timeout_seconds "$BOOT_TIMEOUT" --argjson qemu_exit_status "$QEMU_STATUS" \
    --argjson boot_ready "$BOOT_READY" --argjson image_unchanged "$IMAGE_UNCHANGED" \
    --argjson kernel "$KERNEL" --argjson systemd "$SYSTEMD" \
    --argjson multiuser "$MULTIUSER" --argjson login_prompt "$LOGIN_PROMPT" \
    '{phase:"P0", check:"disk_boot", status:$status, timestamp:$timestamp,
      source_commit:$commit, image_path:$image_path, image_sha256:$image_hash,
      image_sha256_after_boot:$image_hash_after, source_image_unchanged:$image_unchanged,
      qemu_acceleration:$acceleration, qemu_memory_mib:$memory_mib, qemu_vcpus:$vcpus,
      readiness_timeout_seconds:$timeout_seconds, qemu_exit_status:$qemu_exit_status,
      readiness_observed:$boot_ready,
      markers:{kernel:$kernel,systemd:$systemd,multi_user_target:$multiuser,serial_login_prompt:$login_prompt}}' \
    > "$BOOT_RESULT_TMP" || fail "Unable to serialize disk boot evidence."
mv -- "$BOOT_RESULT_TMP" "$BOOT_RESULT" || fail "Unable to publish disk boot evidence."

echo "[P0-BOOT] Kernel=$KERNEL systemd=$SYSTEMD multi_user=$MULTIUSER login_prompt=$LOGIN_PROMPT image_unchanged=$IMAGE_UNCHANGED"
if [ "$STATUS" = "PASS" ]; then
    echo "[P0-BOOT] OVERALL DISK BOOT RESULT: PASS"
    exit 0
fi
echo "[P0-BOOT] FAIL: the guest did not prove kernel, systemd, multi-user, and serial login readiness."
tail -40 "$BOOT_LOG" 2>/dev/null || true
tail -30 "$TMP_DIR/qemu.log" 2>/dev/null || true
exit 1
