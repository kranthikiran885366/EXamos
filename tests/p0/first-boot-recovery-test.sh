#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P0_ARTIFACT_DIR:?Run scripts/p0.sh or set EXAMOS_P0_ARTIFACT_DIR to a unique evidence run directory}"
source "$WORKSPACE/scripts/examos-lib.sh"
examos_p0_validate_run_dir "$WORKSPACE" "$ARTIFACT_DIR" || {
    echo "[P0-FIRST-BOOT-RECOVERY] FATAL: evidence path is not an isolated P0 run directory." >&2
    exit 2
}

SERIAL_LOG="$ARTIFACT_DIR/first-boot-recovery.log"
QEMU_LOG="$ARTIFACT_DIR/first-boot-recovery-qemu.log"
BUILD_LOG="$ARTIFACT_DIR/first-boot-recovery-build.log"
RESULT_FILE="$ARTIFACT_DIR/first-boot-recovery-result.json"
TEST_IMAGE="$ARTIFACT_DIR/recovery-test-image.raw"
TEST_IMAGE_HASH_FILE="$ARTIFACT_DIR/recovery-test-image.sha256"
for output in "$SERIAL_LOG" "$QEMU_LOG" "$BUILD_LOG" "$RESULT_FILE" \
    "$TEST_IMAGE" "$TEST_IMAGE_HASH_FILE"; do
    if [ -e "$output" ] || [ -L "$output" ]; then
        echo "[P0-FIRST-BOOT-RECOVERY] FATAL: refusing to overwrite evidence output: $output" >&2
        exit 2
    fi
done

SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)"
SOURCE_STATE="$(examos_p0_source_status "$WORKSPACE")"
[ -z "$SOURCE_STATE" ] || {
    echo "[P0-FIRST-BOOT-RECOVERY] BLOCKED: recovery evidence requires a clean source tree." >&2
    printf '%s\n' "$SOURCE_STATE" >&2
    exit 2
}
CANONICAL_IMAGE="$ARTIFACT_DIR/examos-p0.raw"
CANONICAL_HASH="$(cut -d' ' -f1 "$ARTIFACT_DIR/image.sha256" 2>/dev/null || true)"
[ -s "$CANONICAL_IMAGE" ] && [ -n "$CANONICAL_HASH" ] &&
    [ "$(sha256sum "$CANONICAL_IMAGE" | cut -d' ' -f1)" = "$CANONICAL_HASH" ] || {
    echo "[P0-FIRST-BOOT-RECOVERY] FATAL: canonical disk image is absent or has changed." >&2
    exit 1
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/examos-p0-recovery.XXXXXX")"
QEMU_PID=""
cleanup() {
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT

TEST_BINARY="$TMP_DIR/examos-p0-first-boot-test"
if ! c++ -std=c++17 -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong -Wformat=2 -Werror=format-security \
    "$WORKSPACE/tests/p0/first-boot-test.cpp" -o "$TEST_BINARY"; then
    echo "[P0-FIRST-BOOT-RECOVERY] FATAL: unable to build the serial recovery driver." >&2
    exit 1
fi
USERNAME="$("$TEST_BINARY" --make-username)" || {
    echo "[P0-FIRST-BOOT-RECOVERY] FATAL: unable to generate a recovery fixture account." >&2
    exit 1
}
case "$USERNAME" in
    ''|*[!a-z0-9_-]*|[!a-z_]*|root)
        echo "[P0-FIRST-BOOT-RECOVERY] FATAL: recovery driver returned an invalid username." >&2
        exit 1
        ;;
esac

# Build an isolated fixture image with a valid completion marker but no account.
# This exercises the real guest executable and avoids modifying the canonical image.
EXTRA_DIR="$TMP_DIR/extra-tree"
mkdir -p "$EXTRA_DIR/var/lib/examos"
printf '%s' "complete:$USERNAME" > "$EXTRA_DIR/var/lib/examos/dev-console-user-created"
chmod 0600 "$EXTRA_DIR/var/lib/examos/dev-console-user-created"
if ! examos_p0_mkosi_build "$WORKSPACE" "$TMP_DIR/out" "$TMP_DIR/cache" \
    "$TMP_DIR/build" "$EXTRA_DIR" "$BUILD_LOG"; then
    echo "[P0-FIRST-BOOT-RECOVERY] FAIL: unable to build the isolated recovery fixture." >&2
    exit 1
fi
mapfile -d '' -t IMAGES < <(find "$TMP_DIR/out" -maxdepth 2 -type f \
    -name '*.raw' -size +0c -print0)
[ "${#IMAGES[@]}" -eq 1 ] && [ ! -L "${IMAGES[0]}" ] || {
    echo "[P0-FIRST-BOOT-RECOVERY] FAIL: expected exactly one recovery fixture image." >&2
    exit 1
}
cp -- "${IMAGES[0]}" "$TEST_IMAGE"
cmp -s -- "${IMAGES[0]}" "$TEST_IMAGE" || {
    echo "[P0-FIRST-BOOT-RECOVERY] FAIL: retained fixture image differs from its build output." >&2
    exit 1
}
sha256sum "$TEST_IMAGE" > "$TEST_IMAGE_HASH_FILE"
TEST_IMAGE_HASH="$(cut -d' ' -f1 "$TEST_IMAGE_HASH_FILE")"

[ "$(git -C "$WORKSPACE" rev-parse HEAD)" = "$SOURCE_COMMIT" ] &&
    [ -z "$(examos_p0_source_status "$WORKSPACE")" ] || {
    echo "[P0-FIRST-BOOT-RECOVERY] FAIL: source changed while building the fixture." >&2
    exit 1
}

OVMF_CODE="$(examos_find_ovmf_code)" || {
    echo "[P0-FIRST-BOOT-RECOVERY] FATAL: OVMF firmware not found." >&2
    exit 1
}
OVMF_VARS_TEMPLATE="$(examos_find_ovmf_vars || true)"
ACCEL="$(examos_qemu_accel)" || {
    echo "[P0-FIRST-BOOT-RECOVERY] FATAL: selected QEMU acceleration is unavailable." >&2
    exit 2
}
QEMU_ACCELERATION="TCG"
case "$ACCEL" in *"-accel kvm"*) QEMU_ACCELERATION="KVM" ;; esac
QEMU_RESOURCES="$(examos_qemu_resources)" || {
    echo "[P0-FIRST-BOOT-RECOVERY] FATAL: unable to derive safe QEMU resources." >&2
    exit 1
}
IFS=$'\t' read -r QEMU_MEMORY_MB QEMU_CPUS <<< "$QEMU_RESOURCES"
TMP_VARS="$TMP_DIR/OVMF_VARS.fd"
if [ -n "$OVMF_VARS_TEMPLATE" ]; then
    cp -- "$OVMF_VARS_TEMPLATE" "$TMP_VARS"
else
    truncate -s 4M "$TMP_VARS"
fi
SERIAL_PORT="$("$TEST_BINARY" --allocate-port)" || {
    echo "[P0-FIRST-BOOT-RECOVERY] FATAL: unable to allocate a serial test port." >&2
    exit 1
}
case "$SERIAL_PORT" in ''|*[!0-9]*) echo "[P0-FIRST-BOOT-RECOVERY] FATAL: invalid serial test port." >&2; exit 1 ;; esac
: > "$SERIAL_LOG"
: > "$QEMU_LOG"
echo "[P0-FIRST-BOOT-RECOVERY] Booting isolated missing-account fixture with $QEMU_ACCELERATION."
# shellcheck disable=SC2086
qemu-system-x86_64 -M q35 $ACCEL -m "$QEMU_MEMORY_MB" -smp "$QEMU_CPUS" -snapshot \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$TMP_VARS" \
    -drive file="$TEST_IMAGE",format=raw,if=virtio \
    -net none -display none -serial "tcp:127.0.0.1:$SERIAL_PORT,server=on,wait=off" \
    > "$QEMU_LOG" 2>&1 &
QEMU_PID=$!
if ! "$TEST_BINARY" --resume "$SERIAL_PORT" "$USERNAME" "$SERIAL_LOG"; then
    echo "[P0-FIRST-BOOT-RECOVERY] FAIL: missing-account reconciliation or authenticated login failed." >&2
    tail -40 "$SERIAL_LOG" >&2 || true
    tail -20 "$QEMU_LOG" >&2 || true
    exit 1
fi
[ "$(sha256sum "$CANONICAL_IMAGE" | cut -d' ' -f1)" = "$CANONICAL_HASH" ] || {
    echo "[P0-FIRST-BOOT-RECOVERY] FAIL: canonical image changed during snapshot recovery test." >&2
    exit 1
}

cat > "$RESULT_FILE" <<EOF
{
  "schema": "examos.p0.first-boot-recovery.v1",
  "phase": "P0",
  "check": "first_boot_recovery",
  "status": "PASS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "source_commit": "$SOURCE_COMMIT",
  "canonical_image_sha256": "$CANONICAL_HASH",
  "fixture_image_sha256": "$TEST_IMAGE_HASH",
  "scenario": "complete_marker_missing_account",
  "qemu_acceleration": "$QEMU_ACCELERATION",
  "qemu_memory_mib": $QEMU_MEMORY_MB,
  "qemu_vcpus": $QEMU_CPUS,
  "snapshot_isolated": true,
  "missing_account_reconciled": true,
  "pending_setup_resumed": true,
  "interrupted_password_setup_recovered": true,
  "recovery_state_completed": true,
  "authenticated_serial_login": true
}
EOF
echo "[P0-FIRST-BOOT-RECOVERY] Missing-account and interrupted-password recovery with authenticated login: PASS"
