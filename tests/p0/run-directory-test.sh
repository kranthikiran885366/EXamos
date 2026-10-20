#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/examos-p0-run-directory.XXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT
source "$WORKSPACE/scripts/examos-lib.sh"

RUN_DIR="$TMP_ROOT/artifacts/p0/runs/run-test"
mkdir -p "$RUN_DIR"
printf '%s\n' "run-test" > "$RUN_DIR/.run-id"
examos_p0_validate_run_dir "$TMP_ROOT" "$RUN_DIR"

if examos_p0_validate_run_dir "$TMP_ROOT" "$TMP_ROOT/artifacts/p0"; then
    echo "Accepted a shared legacy artifact directory." >&2
    exit 1
fi

printf '%s\n' "different-run" > "$RUN_DIR/.run-id"
if examos_p0_validate_run_dir "$TMP_ROOT" "$RUN_DIR"; then
    echo "Accepted a run directory with a mismatched marker." >&2
    exit 1
fi

printf '%s\n' "run-test" > "$RUN_DIR/.run-id"
ln -s "$RUN_DIR" "$TMP_ROOT/artifacts/p0/runs/run-link"
if examos_p0_validate_run_dir "$TMP_ROOT" "$TMP_ROOT/artifacts/p0/runs/run-link"; then
    echo "Accepted a symlinked run directory." >&2
    exit 1
fi

mkdir "$RUN_DIR/child"
printf '%s\n' "child" > "$RUN_DIR/child/.run-id"
if examos_p0_validate_run_dir "$TMP_ROOT" "$RUN_DIR/child"; then
    echo "Accepted a nested run directory." >&2
    exit 1
fi

echo "P0 run-directory validation: PASS"
