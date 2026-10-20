#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — dm-verity Corruption Test (P2-06)
#
# Validates that a single byte flip in the verity-protected data image causes
# dm-verity to reject the image, and that the unmodified image passes.
#
# CRITICAL RULE: This script operates ONLY on a COPY of the artifact.
# It never modifies the known-good build artifact.
#
# Usage:
#   SQUASHFS_CLEAN=artifacts/phase2/examos-root.squashfs \
#   VERITY_HASH=artifacts/phase2/examos-root.verity \
#   VERITY_ROOT_HASH=<hash from manifest> \
#   bash image/scripts/dm-verity-corruption-test.sh
#
# Outputs:
#   artifacts/phase2/dm-verity-clean-boot.txt       — clean verification result
#   artifacts/phase2/dm-verity-corruption-test.txt  — corruption result with evidence
#
# Exit codes:
#   0  Both tests pass (clean verifies OK, corrupted verifies FAIL)
#   1  Test failed (unexpected result)
# =============================================================================
set -uo pipefail

SQUASHFS_CLEAN="${SQUASHFS_CLEAN:-artifacts/phase2/examos-root.squashfs}"
VERITY_HASH_FILE="${VERITY_HASH_FILE:-artifacts/phase2/examos-root.verity}"
VERITY_ROOT_HASH="${VERITY_ROOT_HASH:-}"
ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts/phase2}"
WORK_DIR="${WORK_DIR:-/tmp/examos-verity-test-$$}"

log()  { echo "[verity-test] $*"; }
fail() { echo "[verity-test] FAIL: $*" >&2; exit 1; }

cleanup() {
    # Deactivate any dm-verity device left open
    if [ -n "${VERITY_DEV:-}" ]; then
        dmsetup remove "$VERITY_DEV" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# -----------------------------------------------------------------------
# Validate prerequisites
# -----------------------------------------------------------------------
for tool in veritysetup sha256sum dd python3; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required tool not found: $tool"
done

[ -f "$SQUASHFS_CLEAN" ]    || fail "Clean SquashFS not found: $SQUASHFS_CLEAN"
[ -f "$VERITY_HASH_FILE" ]  || fail "Verity hash file not found: $VERITY_HASH_FILE"
[ -n "$VERITY_ROOT_HASH" ]  || fail "VERITY_ROOT_HASH is not set (read from manifest)"

mkdir -p "$WORK_DIR" "$ARTIFACT_DIR"

CLEAN_LOG="$ARTIFACT_DIR/dm-verity-clean-boot.txt"
CORRUPT_LOG="$ARTIFACT_DIR/dm-verity-corruption-test.txt"

# -----------------------------------------------------------------------
# Compute and record the clean image checksum
# -----------------------------------------------------------------------
CLEAN_SHA=$(sha256sum "$SQUASHFS_CLEAN" | awk '{print $1}')
CLEAN_SIZE=$(stat -c %s "$SQUASHFS_CLEAN")
log "Clean image SHA-256: $CLEAN_SHA"
log "Clean image size:    $CLEAN_SIZE bytes"

# -----------------------------------------------------------------------
# TEST 1 — Clean image must verify PASS
# -----------------------------------------------------------------------
log "--- TEST 1: Verifying clean image ---"
{
    echo "ExamOS dm-verity Clean Image Verification"
    echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Image:      $SQUASHFS_CLEAN"
    echo "SHA-256:    $CLEAN_SHA"
    echo "Root hash:  $VERITY_ROOT_HASH"
    echo ""
    echo "--- veritysetup verify output ---"
} > "$CLEAN_LOG"

CLEAN_VERIFY_RC=0
veritysetup verify \
    "$SQUASHFS_CLEAN" \
    "$VERITY_HASH_FILE" \
    "$VERITY_ROOT_HASH" \
    >> "$CLEAN_LOG" 2>&1 || CLEAN_VERIFY_RC=$?

if [ "$CLEAN_VERIFY_RC" -eq 0 ]; then
    echo "Result: PASS — clean image verifies successfully" >> "$CLEAN_LOG"
    log "TEST 1 PASS: clean image verified"
else
    echo "Result: FAIL — clean image failed verification (exit $CLEAN_VERIFY_RC)" >> "$CLEAN_LOG"
    log "TEST 1 FAIL: clean image failed verification (unexpected)"
    cat "$CLEAN_LOG" >&2
    fail "Clean image failed dm-verity verification — check build pipeline"
fi

# -----------------------------------------------------------------------
# TEST 2 — Corrupted image must verify FAIL
# -----------------------------------------------------------------------
log "--- TEST 2: Corruption test ---"
log "Copying clean image to disposable test location..."

CORRUPT_COPY="$WORK_DIR/examos-root-CORRUPTED.squashfs"
cp "$SQUASHFS_CLEAN" "$CORRUPT_COPY"

# Flip one byte at offset 65537 (well within the data region, past the
# SquashFS superblock which is at bytes 0-95, to ensure we corrupt actual
# filesystem data not just metadata that might be ignored).
# We use python3 for precise, reproducible byte manipulation.
CORRUPT_OFFSET=65537
log "Flipping byte at offset $CORRUPT_OFFSET..."
python3 - "$CORRUPT_COPY" "$CORRUPT_OFFSET" <<'PYEOF'
import sys, os
path = sys.argv[1]
offset = int(sys.argv[2])
with open(path, 'r+b') as f:
    f.seek(offset)
    original = f.read(1)
    flipped = bytes([original[0] ^ 0xFF])
    f.seek(offset)
    f.write(flipped)
    print(f"[verity-test] Byte at {offset}: 0x{original[0]:02x} -> 0x{flipped[0]:02x}")
PYEOF

CORRUPT_SHA=$(sha256sum "$CORRUPT_COPY" | awk '{print $1}')
log "Corrupted image SHA-256: $CORRUPT_SHA"

{
    echo "ExamOS dm-verity Corruption Test"
    echo "Timestamp:         $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Source (clean):    $SQUASHFS_CLEAN"
    echo "Clean SHA-256:     $CLEAN_SHA"
    echo "Corrupted copy:    $CORRUPT_COPY"
    echo "Corrupted SHA-256: $CORRUPT_SHA"
    echo "Corruption method: single byte XOR 0xFF at offset $CORRUPT_OFFSET"
    echo "Root hash used:    $VERITY_ROOT_HASH"
    echo ""
    echo "Expected result:   FAIL (verification must reject corrupted image)"
    echo ""
    echo "--- veritysetup verify output ---"
} > "$CORRUPT_LOG"

CORRUPT_VERIFY_RC=0
veritysetup verify \
    "$CORRUPT_COPY" \
    "$VERITY_HASH_FILE" \
    "$VERITY_ROOT_HASH" \
    >> "$CORRUPT_LOG" 2>&1 || CORRUPT_VERIFY_RC=$?

if [ "$CORRUPT_VERIFY_RC" -ne 0 ]; then
    {
        echo ""
        echo "Result: PASS (expected failure) — verification correctly REJECTED corrupted image"
        echo "Exit code: $CORRUPT_VERIFY_RC"
    } >> "$CORRUPT_LOG"
    log "TEST 2 PASS: corrupted image correctly rejected by dm-verity (exit $CORRUPT_VERIFY_RC)"
else
    {
        echo ""
        echo "Result: FAIL — verification incorrectly ACCEPTED corrupted image (this is a security failure)"
        echo "Exit code: $CORRUPT_VERIFY_RC"
    } >> "$CORRUPT_LOG"
    log "TEST 2 FAIL: corrupted image was NOT rejected — dm-verity integrity check is broken"
    cat "$CORRUPT_LOG" >&2
    fail "dm-verity corruption test FAILED: corrupted image was accepted"
fi

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
echo "=== dm-verity Corruption Test Summary ==="
echo "TEST-1 (clean verify):        PASS"
echo "TEST-2 (corruption rejected): PASS"
echo "Clean image hash:             $CLEAN_SHA"
echo "Corrupted image hash:         $CORRUPT_SHA"
echo "Root hash:                    $VERITY_ROOT_HASH"
echo "Clean log:                    $CLEAN_LOG"
echo "Corruption log:               $CORRUPT_LOG"
echo "========================================="

log "All dm-verity tests PASS"
exit 0
