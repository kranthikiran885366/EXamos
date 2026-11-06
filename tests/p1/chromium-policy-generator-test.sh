#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
GENERATOR="$WORKSPACE/image/scripts/generate-chromium-policy.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

pass() {
    printf '[PASS] %s\n' "$1"
}

fail() {
    printf '[FAIL] %s\n' "$1" >&2
    exit 1
}

assert_valid_origin() {
    local url="$1"
    local expected_origin="$2"
    local label="$3"

    printf 'EXAM_URL=%s\n' "$url" > "$TEMP_DIR/exam.conf"
    if ! EXAM_CONF="$TEMP_DIR/exam.conf" bash "$GENERATOR" --dry-run \
        > "$TEMP_DIR/policy.json" 2> "$TEMP_DIR/generator.log"; then
        fail "$label: valid URL was rejected: $(cat "$TEMP_DIR/generator.log")"
    fi

    if ! python3 - "$TEMP_DIR/policy.json" "$expected_origin" <<'PYEOF'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as policy_file:
    policy = json.load(policy_file)

expected = {
    sys.argv[2] + "/*",
}
for key in ("URLAllowlist", "VideoCaptureAllowedUrls", "AudioCaptureAllowedUrls"):
    actual = policy.get(key)
    if not isinstance(actual, list) or set(actual) != expected:
        raise SystemExit(f"{key} mismatch: {actual!r}")
    if any("*." in entry for entry in actual):
        raise SystemExit(f"{key} grants an implicit subdomain wildcard: {actual!r}")
if policy.get("URLBlocklist") != ["*"]:
    raise SystemExit("URLBlocklist is not default-deny")
PYEOF
    then
        fail "$label: generated policy did not contain only the exact configured origin"
    fi

    pass "$label"
}

assert_rejected() {
    local url="$1"
    local label="$2"

    printf 'EXAM_URL=%s\n' "$url" > "$TEMP_DIR/exam.conf"
    if EXAM_CONF="$TEMP_DIR/exam.conf" bash "$GENERATOR" --check-only \
        > /dev/null 2>&1; then
        fail "$label: invalid URL was accepted"
    fi

    pass "$label"
}

assert_valid_origin \
    'https://exam.alpha.edu/exam/start' \
    'https://exam.alpha.edu' \
    'distinct institution origin'
assert_valid_origin \
    'https://portal.beta.edu:8443/session' \
    'https://portal.beta.edu:8443' \
    'alternate origin and port'
assert_rejected 'https://user:secret@exam.alpha.edu/exam' 'reject URL credentials'
assert_rejected 'https://exam.alpha.edu:99999/exam' 'reject invalid port'
assert_rejected 'http://exam.alpha.edu/exam' 'reject external HTTP'
assert_rejected 'http://localhost:8000/exam' 'reject loopback HTTP admin endpoint'
assert_rejected 'http://127.0.0.1:8000/exam' 'reject loopback IPv4 HTTP admin endpoint'
assert_rejected 'http://localhost/exam' 'reject loopback HTTP without TLS'
assert_rejected 'http://127.0.0.1/exam' 'reject loopback IPv4 HTTP without TLS'
assert_rejected 'http://localhost:8001/exam' 'reject non-TLS loopback endpoint'
assert_rejected 'http://127.0.0.1:8001/exam' 'reject non-TLS loopback IPv4 endpoint'
assert_rejected 'https:///missing-host' 'reject missing hostname'
assert_rejected 'NOT_CONFIGURED' 'reject unconfigured endpoint'

printf 'Chromium policy generator checks passed.\n'
