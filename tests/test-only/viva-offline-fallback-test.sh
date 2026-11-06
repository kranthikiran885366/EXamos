#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
for tool in cc openssl; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[TEST-ONLY-VIVA] BLOCKED: missing tool: $tool" >&2
        exit 2
    }
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-test-viva.XXXXXX")"
cleanup() { rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT

cc -std=c11 -Wall -Wextra -Werror \
    -I"$WORKSPACE/server/include" \
    "$WORKSPACE/tests/test-only/viva-offline-fallback-test.c" \
    "$WORKSPACE/server/behaviour/viva_engine.c" \
    -lssl -lcrypto -lpthread -lm -o "$WORK_DIR/viva-offline-fallback-test"

"$WORK_DIR/viva-offline-fallback-test" "$WORK_DIR/store"
