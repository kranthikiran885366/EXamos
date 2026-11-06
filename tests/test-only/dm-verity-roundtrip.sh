#!/usr/bin/env bash
# Exercise verity metadata generation and corruption rejection on disposable
# regular files. This never opens a device-mapper target or modifies an image.
set -euo pipefail

for tool in veritysetup sha256sum dd python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[TEST-ONLY-VERITY] BLOCKED: missing tool: $tool" >&2
        exit 2
    }
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-test-verity.XXXXXX")"
cleanup() { rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT

DATA="$WORK_DIR/data.bin"
HASH="$WORK_DIR/hash.bin"
CORRUPT="$WORK_DIR/corrupt.bin"
dd if=/dev/urandom of="$DATA" bs=1M count=4 status=none
FORMAT_OUTPUT="$(veritysetup format --hash=sha256 "$DATA" "$HASH")"
ROOT_HASH="$(printf '%s\n' "$FORMAT_OUTPUT" | awk -F: '/Root hash:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')"

if ! [[ "$ROOT_HASH" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "[TEST-ONLY-VERITY] FAIL: veritysetup did not return a SHA-256 root hash" >&2
    exit 1
fi

veritysetup verify "$DATA" "$HASH" "$ROOT_HASH" >/dev/null
cp -- "$DATA" "$CORRUPT"
printf '\x00' | dd of="$CORRUPT" bs=1 seek=128 conv=notrunc status=none

if veritysetup verify "$CORRUPT" "$HASH" "$ROOT_HASH" >/dev/null 2>&1; then
    echo "[TEST-ONLY-VERITY] FAIL: corrupted data was accepted" >&2
    exit 1
fi

echo "[TEST-ONLY-VERITY] PASS: generated and verified a disposable hash tree; corruption was rejected"
