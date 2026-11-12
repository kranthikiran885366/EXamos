#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_BIN="$(mktemp "${TMPDIR:-/tmp}/examos-ek-ak-provenance.XXXXXX")"
trap 'rm -f "$TEST_BIN"' EXIT

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    "$ROOT/tests/server/ek_ak_provenance_test.c" \
    "$ROOT/server/attestation/credential_activation.c" \
    -lcrypto -o "$TEST_BIN"
"$TEST_BIN"
