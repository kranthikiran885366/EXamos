#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P0_ARTIFACT_DIR:?Run scripts/p0.sh or set EXAMOS_P0_ARTIFACT_DIR to a unique evidence run directory}"
SERIAL_LOG="$ARTIFACT_DIR/first-boot.log"
QEMU_LOG="$ARTIFACT_DIR/first-boot-qemu.log"
RESULT_FILE="$ARTIFACT_DIR/first-boot-result.json"
for output in "$SERIAL_LOG" "$QEMU_LOG" "$RESULT_FILE"; do
    if [ -e "$output" ] || [ -L "$output" ]; then
        echo "[P0-FIRST-BOOT] FATAL: evidence output already exists; refusing to overwrite: $output" >&2
        exit 2
    fi
done

# shellcheck source=scripts/examos-lib.sh
source "$WORKSPACE/scripts/examos-lib.sh"
examos_p0_validate_run_dir "$WORKSPACE" "$ARTIFACT_DIR" || {
    echo "[P0-FIRST-BOOT] FATAL: evidence path is not an isolated P0 run directory." >&2
    exit 2
}
IMAGE_RELATIVE="$(cat "$ARTIFACT_DIR/image-path.txt" 2>/dev/null || true)"
EXPECTED_IMAGE_RELATIVE="$(realpath --relative-to="$WORKSPACE" "$ARTIFACT_DIR/examos-p0.raw")"
[ "$IMAGE_RELATIVE" = "$EXPECTED_IMAGE_RELATIVE" ] || {
    echo "[P0-FIRST-BOOT] FATAL: image path does not identify this run's build artifact." >&2
    exit 1
}
IMAGE_FILE="$WORKSPACE/$IMAGE_RELATIVE"

if [ ! -s "$IMAGE_FILE" ] || [ -L "$IMAGE_FILE" ]; then
    echo "[P0-FIRST-BOOT] FATAL: P0 disk image is missing or invalid: $IMAGE_FILE" >&2
    exit 1
fi
if [ -n "${EXAMOS_P0_IMAGE_FILE:-}" ] &&
    [ "$(realpath -e -- "$EXAMOS_P0_IMAGE_FILE")" != "$(realpath -e -- "$IMAGE_FILE")" ]; then
    echo "[P0-FIRST-BOOT] FATAL: alternate image sources are not permitted in an evidence run." >&2
    exit 1
fi
EXPECTED_IMAGE_HASH=$(cut -d' ' -f1 "$ARTIFACT_DIR/image.sha256" 2>/dev/null || true)
if [ -z "$EXPECTED_IMAGE_HASH" ] ||
    [ "$(sha256sum "$IMAGE_FILE" | cut -d' ' -f1)" != "$EXPECTED_IMAGE_HASH" ]; then
    echo "[P0-FIRST-BOOT] FATAL: source image does not match the recorded build digest." >&2
    exit 1
fi
IMAGE_HASH_BEFORE="$EXPECTED_IMAGE_HASH"

cat > "$RESULT_FILE" <<EOF
{
  "phase": "P0",
  "check": "first_boot_account",
  "status": "IN_PROGRESS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "image_sha256": "$IMAGE_HASH_BEFORE"
}
EOF

OVMF_CODE=$(examos_find_ovmf_code) || {
    echo "[P0-FIRST-BOOT] FATAL: OVMF firmware not found." >&2
    exit 1
}
OVMF_VARS_TMPL=$(examos_find_ovmf_vars || true)
ACCEL=$(examos_qemu_accel) || {
    echo "[P0-FIRST-BOOT] FATAL: requested QEMU acceleration is unavailable or invalid." >&2
    exit 2
}
QEMU_ACCELERATION="TCG"
case "$ACCEL" in
    *"-accel kvm"*) QEMU_ACCELERATION="KVM" ;;
esac
QEMU_RESOURCES=$(examos_qemu_resources) || {
    echo "[P0-FIRST-BOOT] FATAL: unable to derive a safe QEMU memory/CPU allocation from current host resources." >&2
    exit 1
}
IFS=$'\t' read -r QEMU_MEMORY_MB QEMU_CPUS <<< "$QEMU_RESOURCES"

mkdir -p "$ARTIFACT_DIR"
TMP_DIR=$(mktemp -d)
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

TEST_BINARY="$TMP_DIR/examos-p0-first-boot-test"
if ! c++ -std=c++17 -O2 -Wall -Wextra -Werror \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat=2 \
    -Werror=format-security "$WORKSPACE/tests/p0/first-boot-test.cpp" \
    -o "$TEST_BINARY"; then
    echo "[P0-FIRST-BOOT] FATAL: unable to build the native serial test driver." >&2
    exit 1
fi
"$TEST_BINARY" --self-test-login-result || {
    echo "[P0-FIRST-BOOT] FATAL: serial login result parser self-test failed." >&2
    exit 1
}
SERIAL_PORT=$("$TEST_BINARY" --allocate-port) || {
    echo "[P0-FIRST-BOOT] FATAL: unable to select an available loopback serial port." >&2
    exit 1
}
case "$SERIAL_PORT" in
    ''|*[!0-9]*)
        echo "[P0-FIRST-BOOT] FATAL: native port allocator returned invalid output." >&2
        exit 1
        ;;
esac

: > "$SERIAL_LOG"
: > "$QEMU_LOG"
echo "[P0-FIRST-BOOT] Starting snapshot boot on serial TCP port $SERIAL_PORT (${QEMU_MEMORY_MB} MiB RAM, ${QEMU_CPUS} vCPU(s))."
# shellcheck disable=SC2086
qemu-system-x86_64 -M q35 $ACCEL -m "$QEMU_MEMORY_MB" -smp "$QEMU_CPUS" -snapshot \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$TMP_VARS" \
    -drive file="$IMAGE_FILE",format=raw,if=virtio \
    -net none -display none \
    -serial "tcp:127.0.0.1:$SERIAL_PORT,server=on,wait=off" \
    > "$QEMU_LOG" 2>&1 &
QEMU_PID=$!

if ! "$TEST_BINARY" "$SERIAL_PORT" "$SERIAL_LOG"; then
    echo "[P0-FIRST-BOOT] FAIL: account setup and serial login were not completed."
    tail -30 "$SERIAL_LOG" 2>/dev/null || true
    tail -20 "$QEMU_LOG" 2>/dev/null || true
    exit 1
fi
IMAGE_HASH_AFTER=$(sha256sum "$IMAGE_FILE" | cut -d' ' -f1)
if [ "$IMAGE_HASH_AFTER" != "$IMAGE_HASH_BEFORE" ]; then
    echo "[P0-FIRST-BOOT] FAIL: snapshot test changed the canonical source image." >&2
    exit 1
fi
cat > "$RESULT_FILE" <<EOF
{
  "phase": "P0",
  "check": "first_boot_account",
  "status": "PASS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "image_sha256": "$IMAGE_HASH_BEFORE",
  "image_sha256_after_test": "$IMAGE_HASH_AFTER",
  "source_image_unchanged": true,
  "qemu_acceleration": "$QEMU_ACCELERATION",
  "qemu_memory_mib": $QEMU_MEMORY_MB,
  "qemu_vcpus": $QEMU_CPUS,
  "snapshot_isolated": true,
  "guest_account_created": true,
  "authenticated_serial_login": true,
  "non_root_uid_and_sudo_group_verified": true,
  "setup_executable_owner_mode_verified": true
}
EOF
echo "[P0-FIRST-BOOT] First-boot account creation and authenticated login: PASS"
