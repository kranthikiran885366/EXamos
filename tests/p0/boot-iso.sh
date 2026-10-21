#!/usr/bin/env bash
# Boot and verify the hybrid P0 ISO as a raw USB/disk device under OVMF/QEMU.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P0_ARTIFACT_DIR:?Run scripts/p0.sh or set EXAMOS_P0_ARTIFACT_DIR to a unique evidence run directory}"
source "$WORKSPACE/scripts/examos-lib.sh"
examos_p0_validate_run_dir "$WORKSPACE" "$ARTIFACT_DIR" || {
    echo "[P0-ISO-BOOT] FATAL: evidence path is not an isolated P0 run directory." >&2
    exit 2
}
ISO_FILE="$ARTIFACT_DIR/examos-p0.iso"
ISO_RESULT="$ARTIFACT_DIR/iso-build-result.json"
BOOT_LOG="$ARTIFACT_DIR/iso-boot.log"
BOOT_RESULT="$ARTIFACT_DIR/iso-boot-result.json"
for output in "$BOOT_LOG" "$BOOT_RESULT"; do
    if [ -e "$output" ] || [ -L "$output" ]; then
        echo "[P0-ISO-BOOT] FATAL: evidence output already exists; refusing to overwrite: $output" >&2
        exit 2
    fi
done
mkdir -p "$ARTIFACT_DIR"
: > "$BOOT_LOG"
cat > "$BOOT_RESULT" <<EOF
{
  "phase": "P0",
  "check": "iso_boot",
  "status": "IN_PROGRESS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

fail() {
    local message="$1"
    echo "[P0-ISO-BOOT] FATAL: $message" >&2
    cat > "$BOOT_RESULT" <<EOF
{
  "phase": "P0",
  "check": "iso_boot",
  "status": "FAIL",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "reason": "$message"
}
EOF
    exit 1
}

for tool in qemu-system-x86_64 timeout sha256sum jq git; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required ISO boot test tool is missing: $tool"
done
[ -s "$ISO_FILE" ] || fail "P0 ISO is missing or empty"
[ -s "$ARTIFACT_DIR/iso.sha256" ] || fail "P0 ISO checksum is missing"
[ -s "$ISO_RESULT" ] || fail "P0 ISO build evidence is missing"
[ -s "$ARTIFACT_DIR/image.sha256" ] || fail "Canonical P0 disk checksum is missing"
sha256sum --check "$ARTIFACT_DIR/iso.sha256" || fail "P0 ISO checksum verification failed"
sha256sum --check "$ARTIFACT_DIR/image.sha256" || fail "Canonical P0 disk checksum verification failed"
ISO_HASH="$(cut -d' ' -f1 "$ARTIFACT_DIR/iso.sha256")"
SOURCE_DISK_HASH="$(cut -d' ' -f1 "$ARTIFACT_DIR/image.sha256")"
BUILD_BINDINGS="$(jq -er \
    --arg iso_hash "$ISO_HASH" \
    --arg disk_hash "$SOURCE_DISK_HASH" '
    def is_sha256: type == "string" and test("^[0-9a-f]{64}$");
    select(.status == "PASS")
    | select(.iso_sha256 == $iso_hash and .source_disk_sha256 == $disk_hash)
    | select(.iso_sha256 | is_sha256)
    | select(.source_disk_sha256 | is_sha256)
    | select(.uki_sha256 | is_sha256)
    | select(.source_uki_sha256 | is_sha256)
    | select(.source_initrd_sha256 | is_sha256)
    | select(.root_filesystem_sha256 | is_sha256)
    | select(.root_filesystem_uuid | type == "string" and test("^[0-9a-f-]{36}$"))
    | select(.root_filesystem_label == "root-x86-64")
    | select(.source_commit | type == "string" and test("^[0-9a-f]{40,64}$"))
    | select(.source_tree_state_at_start == "CLEAN")
    | select((.dirty_path_count_at_start | type) == "number")
    | select((.dirty_path_count_at_start | floor) == .dirty_path_count_at_start and .dirty_path_count_at_start >= 0)
    | [
        .source_disk_sha256,
        .uki_sha256,
        .root_filesystem_sha256,
        .root_filesystem_uuid,
        .source_uki_sha256,
        .source_initrd_sha256,
        .source_commit,
        .source_tree_state_at_start,
        (.dirty_path_count_at_start | tostring)
      ]
    | @tsv
    ' "$ISO_RESULT")" ||
    fail "ISO build evidence is missing, stale, or not bound to the canonical artifacts"
IFS=$'\t' read -r SOURCE_DISK_HASH UKI_HASH ROOT_FILESYSTEM_HASH ROOT_FILESYSTEM_UUID \
    SOURCE_UKI_HASH SOURCE_INITRD_HASH SOURCE_COMMIT SOURCE_TREE_STATE DIRTY_PATH_COUNT <<< "$BUILD_BINDINGS"
CURRENT_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)" ||
    fail "Unable to resolve the current source commit"
[ "$SOURCE_COMMIT" = "$CURRENT_COMMIT" ] ||
    fail "ISO build evidence is bound to a different source commit"
if ! SOURCE_STATUS_NOW="$(examos_p0_source_status "$WORKSPACE")"; then
    fail "Unable to determine source tree state before ISO boot"
fi
[ -z "$SOURCE_STATUS_NOW" ] ||
    fail "ISO boot evidence requires a clean source tree"

OVMF_CODE="$(source "$WORKSPACE/scripts/examos-lib.sh"; examos_find_ovmf_code)" ||
    fail "OVMF code firmware was not found"
OVMF_VARS_TMPL="$(source "$WORKSPACE/scripts/examos-lib.sh"; examos_find_ovmf_vars || true)"
TMP_DIR="$(mktemp -d)"
NORMALIZED_LOG="$TMP_DIR/iso-boot.normalized.log"
QEMU_PID=""
cleanup() {
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT
TMP_VARS="$TMP_DIR/OVMF_VARS.fd"
if [ -n "$OVMF_VARS_TMPL" ]; then
    cp "$OVMF_VARS_TMPL" "$TMP_VARS"
else
    truncate -s 4M "$TMP_VARS"
fi

ACCEL="$(source "$WORKSPACE/scripts/examos-lib.sh"; examos_qemu_accel)" ||
    fail "Requested QEMU acceleration is unavailable or invalid"
QEMU_RESOURCES="$(source "$WORKSPACE/scripts/examos-lib.sh"; examos_qemu_resources)" ||
    fail "Unable to derive a safe QEMU memory/CPU allocation from current host resources"
IFS=$'\t' read -r QEMU_MEMORY_MB QEMU_CPUS <<< "$QEMU_RESOURCES"
QEMU_ACCELERATION="TCG"
case "$ACCEL" in
    *"-accel kvm"*) QEMU_ACCELERATION="KVM" ;;
esac
BOOT_TIMEOUT="${EXAMOS_P0_ISO_BOOT_TIMEOUT:-240}"
case "$BOOT_TIMEOUT" in
    ''|*[!0-9]*) fail "EXAMOS_P0_ISO_BOOT_TIMEOUT must be an integer" ;;
esac
if [ "$BOOT_TIMEOUT" -lt 30 ] || [ "$BOOT_TIMEOUT" -gt 600 ]; then
    fail "EXAMOS_P0_ISO_BOOT_TIMEOUT must be between 30 and 600 seconds"
fi
echo "[P0-ISO-BOOT] OVMF: $OVMF_CODE"
echo "[P0-ISO-BOOT] ISO SHA-256: $ISO_HASH"
echo "[P0-ISO-BOOT] Runtime allocation: ${QEMU_MEMORY_MB} MiB RAM, ${QEMU_CPUS} vCPU(s)"
echo "[P0-ISO-BOOT] Starting UEFI optical-media boot (readiness deadline ${BOOT_TIMEOUT}s)..."

# shellcheck disable=SC2086
qemu-system-x86_64 \
    -M q35 $ACCEL \
    -m "$QEMU_MEMORY_MB" \
    -smp "$QEMU_CPUS" \
    -snapshot \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$TMP_VARS" \
    -drive file="$ISO_FILE",media=cdrom,readonly=on \
    -boot order=d \
    -net none \
    -monitor none \
    -display none \
    -serial file:"$BOOT_LOG" 2>&1 &
QEMU_PID=$!

iso_boot_ready() {
    examos_normalize_serial_log "$BOOT_LOG" "$NORMALIZED_LOG" || return 1
    grep -qE "Linux version [0-9]" "$NORMALIZED_LOG" &&
        grep -qE "systemd [0-9]+(\.[0-9]+)?[^[:cntrl:]]* running in system mode|systemd\[1\]" "$NORMALIZED_LOG" &&
        grep -qiE "Reached target.*(Multi-User System|multi-user\.target)" "$NORMALIZED_LOG" &&
        grep -qE "^[[:alnum:]_.-]+ login:" "$NORMALIZED_LOG" &&
        grep -Fq "ExamOS ISO init: mounted canonical root filesystem $ROOT_FILESYSTEM_UUID read-only with volatile overlay" "$NORMALIZED_LOG"
}

QEMU_START=$SECONDS
BOOT_READY=false
QEMU_STATUS=0
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if iso_boot_ready; then
        BOOT_READY=true
        echo "[P0-ISO-BOOT] All optical-root readiness markers observed; stopping the snapshot VM."
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        set +e
        wait "$QEMU_PID"
        QEMU_STATUS=$?
        set -e
        QEMU_PID=""
        break
    fi
    if [ "$((SECONDS - QEMU_START))" -ge "$BOOT_TIMEOUT" ]; then
        echo "[P0-ISO-BOOT] Guest readiness deadline reached."
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

POST_BOOT_HASH="$(sha256sum "$ISO_FILE" | cut -d' ' -f1)"
ISO_UNCHANGED=false
[ "$POST_BOOT_HASH" = "$ISO_HASH" ] && ISO_UNCHANGED=true

examos_normalize_serial_log "$BOOT_LOG" "$NORMALIZED_LOG" ||
    fail "Unable to normalize the optical guest serial log"

KERNEL=false
SYSTEMD=false
MULTIUSER=false
LOGIN_PROMPT=false
ROOT_FILESYSTEM_MOUNTED=false
ROOT_SELECTOR=false
VOLATILE_OVERLAY=false
grep -qE "Linux version [0-9]" "$NORMALIZED_LOG" && KERNEL=true
grep -qE "systemd [0-9]+(\.[0-9]+)?[^[:cntrl:]]* running in system mode|systemd\[1\]" "$NORMALIZED_LOG" && SYSTEMD=true
grep -qiE "Reached target (Multi-User System|multi-user\.target)([[:space:].]|$)" "$NORMALIZED_LOG" && MULTIUSER=true
grep -qE "^[[:alnum:]_.-]+ login:" "$NORMALIZED_LOG" && LOGIN_PROMPT=true
grep -qE "Kernel command line:.*examos\.media=optical([[:space:]]|$)" "$NORMALIZED_LOG" && ROOT_SELECTOR=true
grep -Fq "ExamOS ISO init: mounted canonical root filesystem $ROOT_FILESYSTEM_UUID read-only with volatile overlay" "$NORMALIZED_LOG" && ROOT_FILESYSTEM_MOUNTED=true
grep -Fq "ExamOS ISO init: mounted canonical root filesystem $ROOT_FILESYSTEM_UUID read-only with volatile overlay" "$NORMALIZED_LOG" && VOLATILE_OVERLAY=true

echo "[P0-ISO-BOOT] Kernel=$KERNEL systemd=$SYSTEMD root_selector=$ROOT_SELECTOR volatile_overlay=$VOLATILE_OVERLAY root_mounted=$ROOT_FILESYSTEM_MOUNTED multi_user=$MULTIUSER login_prompt=$LOGIN_PROMPT"
echo "[P0-ISO-BOOT] QEMU exit=$QEMU_STATUS ISO unchanged=$ISO_UNCHANGED"

STATUS="FAIL"
if [ "$KERNEL" = true ] && [ "$SYSTEMD" = true ] && [ "$ROOT_SELECTOR" = true ] && \
    [ "$VOLATILE_OVERLAY" = true ] && \
    [ "$ROOT_FILESYSTEM_MOUNTED" = true ] && \
    [ "$MULTIUSER" = true ] && \
    [ "$LOGIN_PROMPT" = true ] && [ "$ISO_UNCHANGED" = true ] && \
    [ "$BOOT_READY" = true ]; then
    STATUS="PASS"
fi

cat > "$BOOT_RESULT" <<EOF
{
  "phase": "P0",
  "check": "iso_boot",
  "status": "$STATUS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "iso_sha256": "$ISO_HASH",
  "source_disk_sha256": "$SOURCE_DISK_HASH",
  "uki_sha256": "$UKI_HASH",
  "root_filesystem_sha256": "$ROOT_FILESYSTEM_HASH",
  "root_filesystem_uuid": "$ROOT_FILESYSTEM_UUID",
  "root_filesystem_label": "root-x86-64",
  "source_uki_sha256": "$SOURCE_UKI_HASH",
  "source_initrd_sha256": "$SOURCE_INITRD_HASH",
  "source_commit": "$SOURCE_COMMIT",
  "source_tree_state_at_start": "$SOURCE_TREE_STATE",
  "dirty_path_count_at_start": $DIRTY_PATH_COUNT,
  "boot_mode": "UEFI optical media (CD/DVD)",
  "qemu_acceleration": "$QEMU_ACCELERATION",
  "qemu_memory_mib": $QEMU_MEMORY_MB,
  "qemu_vcpus": $QEMU_CPUS,
  "qemu_stopped_after_readiness": $BOOT_READY,
  "iso_sha256_after_boot": "$POST_BOOT_HASH",
  "source_iso_unchanged": $ISO_UNCHANGED,
  "qemu_exit_status": $QEMU_STATUS,
  "markers": {
    "kernel": $KERNEL,
    "systemd": $SYSTEMD,
    "canonical_root_selected": $ROOT_SELECTOR,
    "volatile_overlay_selected": $VOLATILE_OVERLAY,
    "canonical_root_mounted": $ROOT_FILESYSTEM_MOUNTED,
    "multi_user_target": $MULTIUSER,
    "serial_login_prompt": $LOGIN_PROMPT
  }
}
EOF

if [ "$STATUS" = "PASS" ]; then
    echo "[P0-ISO-BOOT] OVERALL ISO BOOT RESULT: PASS"
    exit 0
fi

echo "[P0-ISO-BOOT] FAIL: ISO did not prove a complete guest boot."
tail -40 "$BOOT_LOG" 2>/dev/null || true
exit 1
