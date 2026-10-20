#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
source "$WORKSPACE/scripts/examos-lib.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

git -C "$TMP_DIR" init -q
git -C "$TMP_DIR" config user.name "ExamOS P0 test"
git -C "$TMP_DIR" config user.email "p0-test@example.invalid"
mkdir -p "$TMP_DIR/artifacts/p0" "$TMP_DIR/image/p0/output" \
    "$TMP_DIR/build/p0" "$TMP_DIR/cache/p0"
printf 'source\n' > "$TMP_DIR/source.c"
printf 'evidence\n' > "$TMP_DIR/artifacts/p0/results.json"
printf 'image\n' > "$TMP_DIR/image/p0/output/image.raw"
printf 'build\n' > "$TMP_DIR/build/p0/state"
printf 'cache\n' > "$TMP_DIR/cache/p0/state"
git -C "$TMP_DIR" add .
git -C "$TMP_DIR" commit -qm "fixture baseline"

printf 'regenerated evidence\n' >> "$TMP_DIR/artifacts/p0/results.json"
printf 'regenerated image\n' >> "$TMP_DIR/image/p0/output/image.raw"
printf 'regenerated build\n' >> "$TMP_DIR/build/p0/state"
printf 'regenerated cache\n' >> "$TMP_DIR/cache/p0/state"
if [ -n "$(examos_p0_source_status "$TMP_DIR")" ]; then
    echo "[P0-PROVENANCE-TEST] FAIL: generated P0 outputs contaminated source status" >&2
    exit 1
fi

printf 'uncommitted source change\n' >> "$TMP_DIR/source.c"
if [ -z "$(examos_p0_source_status "$TMP_DIR")" ]; then
    echo "[P0-PROVENANCE-TEST] FAIL: source change was not detected" >&2
    exit 1
fi

echo "[P0-PROVENANCE-TEST] PASS: generated outputs excluded; source changes detected"
