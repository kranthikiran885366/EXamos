#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/examos-e1-http.XXXXXX")"
ARTIFACT_DIR="${EXAMOS_E1_ARTIFACT_DIR:-$WORKSPACE/artifacts/e1}"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

BUILD_DIR="$TEST_ROOT/build"
SERVER_BIN="$BUILD_DIR/examos-server"
mkdir -p "$BUILD_DIR" "$TEST_ROOT/behaviour" "$TEST_ROOT/variants" "$TEST_ROOT/viva"

echo "[E1-HTTP] Building the complete native server into an isolated temporary directory."
make -C "$WORKSPACE/server" BUILD_DIR="$BUILD_DIR" all

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
CANDIDATE_ID="e1-http-$(openssl rand -hex 8)"
CANDIDATE_PIN="$(openssl rand -hex 16)"
CANDIDATE_SALT="$(openssl rand -hex 32)"
CANDIDATE_HASH="$(printf '%s' "$CANDIDATE_PIN" |
    python3 -c 'import hashlib,sys; print(hashlib.pbkdf2_hmac("sha256", sys.stdin.buffer.read(), bytes.fromhex(sys.argv[1]), 600000).hex())' "$CANDIDATE_SALT")"
printf '%s:600000:%s:%s\n' "$CANDIDATE_ID" "$CANDIDATE_SALT" "$CANDIDATE_HASH" \
    > "$TEST_ROOT/candidates.conf"
chmod 0600 "$TEST_ROOT/candidates.conf"

DEVICE_FINGERPRINT="$(openssl rand -hex 32)"
RELEASE_ID="e1-http-$(openssl rand -hex 8)"
PCR0="$(openssl rand -hex 32)"
PCR4="$(openssl rand -hex 32)"
PCR7="$(openssl rand -hex 32)"
PCR11="$(openssl rand -hex 32)"
UKI_HASH="$(openssl rand -hex 32)"
cat > "$TEST_ROOT/devices.json" <<EOF
{"devices":[{"device_id":"e1-http-device","ek_fingerprint":"$DEVICE_FINGERPRINT","allowed_release":"$RELEASE_ID"}]}
EOF
cat > "$TEST_ROOT/releases.json" <<EOF
{"releases":[{"release_id":"$RELEASE_ID","uki_hash":"$UKI_HASH","pcr0":"$PCR0","pcr4":"$PCR4","pcr7":"$PCR7","pcr11":"$PCR11","revoked":false}]}
EOF

AGENT_TOKEN="$(openssl rand -hex 32)"
PROCTOR_TOKEN="$(openssl rand -hex 32)"
EVENT_SIGNING_KEY="$(openssl rand -hex 32)"
VARIANT_SECRET="$(openssl rand -hex 32)"
LEDGER_HMAC_KEY="$(openssl rand -hex 32)"
SESSION_TOKEN=""

EXAMOS_SERVER_PORT="$PORT" \
EXAMOS_SERVER_BIND=127.0.0.1 \
EXAMOS_TPM_MODE=development \
EXAMOS_LEDGER_PATH="$TEST_ROOT/ledger.log" \
EXAMOS_EVENT_CHAIN_PATH="$TEST_ROOT/events.jsonl" \
EXAMOS_LEDGER_HMAC_KEY="$LEDGER_HMAC_KEY" \
EXAMOS_SESSION_JOURNAL="$TEST_ROOT/sessions.log" \
EXAMOS_CANDIDATE_STORE="$TEST_ROOT/candidates.conf" \
EXAMOS_DEVICES_CONFIG="$TEST_ROOT/devices.json" \
EXAMOS_RELEASES_CONFIG="$TEST_ROOT/releases.json" \
EXAMOS_AGENT_API_TOKEN="$AGENT_TOKEN" \
EXAMOS_PROCTOR_API_TOKEN="$PROCTOR_TOKEN" \
EXAMOS_EVENT_SIGNING_KEY="$EVENT_SIGNING_KEY" \
EXAMOS_VARIANT_SECRET="$VARIANT_SECRET" \
EXAMOS_BEHAVIOUR_STORE="$TEST_ROOT/behaviour" \
EXAMOS_VARIANT_STORE="$TEST_ROOT/variants" \
EXAMOS_VIVA_STORE="$TEST_ROOT/viva" \
"$SERVER_BIN" >"$TEST_ROOT/server.log" 2>&1 &
SERVER_PID=$!

BASE_URL="http://127.0.0.1:$PORT"
for _ in $(seq 1 100); do
    if [ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 1 "$BASE_URL/api/v1/health" 2>/dev/null || true)" = "200" ]; then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        cat "$TEST_ROOT/server.log" >&2
        echo "[E1-HTTP] FAIL: server exited before becoming ready." >&2
        exit 1
    fi
    sleep 0.1
done
if [ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "$BASE_URL/api/v1/health" 2>/dev/null || true)" != "200" ]; then
    cat "$TEST_ROOT/server.log" >&2
    echo "[E1-HTTP] FAIL: server did not become ready." >&2
    exit 1
fi

expect_status() {
    local label="$1" expected="$2" body="$3" auth="${4:-}"
    local actual
    local -a args
    args=(curl -sS -o "$TEST_ROOT/response.json" -w '%{http_code}' --max-time 5
          -H 'Content-Type: application/json')
    if [ -n "$auth" ]; then
        args+=(-H "Authorization: Bearer $auth")
    fi
    args+=(-d "$body" "$BASE_URL/api/v1/e1/consent")
    actual="$("${args[@]}")"
    if [ "$actual" != "$expected" ]; then
        echo "[E1-HTTP] FAIL: $label returned HTTP $actual (expected $expected)." >&2
        cat "$TEST_ROOT/response.json" >&2
        exit 1
    fi
    echo "[E1-HTTP] PASS: $label returned HTTP $expected."
}

expect_status "unauthenticated consent rejected" 401 \
    '{"session_id":"no-session","wifi":false,"ble":false,"rf":false,"second_camera":false}'

LOGIN_CODE="$(curl -sS -o "$TEST_ROOT/login.json" -w '%{http_code}' --max-time 5 \
    -H 'Content-Type: application/json' \
    -d "{\"candidate_id\":\"$CANDIDATE_ID\",\"pin\":\"$CANDIDATE_PIN\"}" \
    "$BASE_URL/api/v1/candidate/login")"
if [ "$LOGIN_CODE" != "200" ]; then
    echo "[E1-HTTP] FAIL: dynamically provisioned candidate login returned HTTP $LOGIN_CODE." >&2
    cat "$TEST_ROOT/login.json" >&2
    exit 1
fi
SESSION_TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' "$TEST_ROOT/login.json")"
if [ "${#SESSION_TOKEN}" -ne 64 ]; then
    echo "[E1-HTTP] FAIL: login did not return a session token of the required length." >&2
    exit 1
fi
echo "[E1-HTTP] PASS: candidate authenticated through the real login/session implementation."

OTHER_SESSION="$(openssl rand -hex 32)"
expect_status "session mismatch rejected" 403 \
    "{\"session_id\":\"$OTHER_SESSION\",\"wifi\":false,\"ble\":false,\"rf\":false,\"second_camera\":false}" \
    "$SESSION_TOKEN"
expect_status "incomplete scope rejected" 400 \
    "{\"session_id\":\"$SESSION_TOKEN\",\"wifi\":false,\"ble\":false,\"second_camera\":false}" \
    "$SESSION_TOKEN"
expect_status "duplicate scope rejected" 400 \
    "{\"session_id\":\"$SESSION_TOKEN\",\"wifi\":false,\"wifi\":true,\"ble\":false,\"rf\":false,\"second_camera\":false}" \
    "$SESSION_TOKEN"
expect_status "unknown scope rejected" 400 \
    "{\"session_id\":\"$SESSION_TOKEN\",\"wifi\":false,\"ble\":false,\"rf\":false,\"second_camera\":false,\"extra\":true}" \
    "$SESSION_TOKEN"

expect_status "valid consent durably accepted" 201 \
    "{\"session_id\":\"$SESSION_TOKEN\",\"wifi\":false,\"ble\":true,\"rf\":false,\"second_camera\":false}" \
    "$SESSION_TOKEN"
python3 - "$TEST_ROOT/events.jsonl" "$SESSION_TOKEN" "$TEST_ROOT/response.json" <<'PY'
import json
import sys

events_path, session_id, response_path = sys.argv[1:]
with open(response_path, encoding="utf-8") as response_file:
    response = json.load(response_file)
if response.get("status") != "CONSENT_RECORDED" or \
        response.get("collection_status") != "DISABLED_BY_POLICY":
    raise SystemExit("E1 response did not preserve the disabled-collection policy")
with open(events_path, encoding="utf-8") as events_file:
    events = [json.loads(line) for line in events_file if line.strip()]
if len(events) != 1:
    raise SystemExit(f"expected exactly one persisted event, found {len(events)}")
event = events[0]
if event.get("session_id") != session_id or \
        event.get("event_type") != "E1_CONSENT_RECORDED":
    raise SystemExit("persisted consent event was not bound to the authenticated session")
payload = event.get("payload", {})
if payload.get("ble") is not True or payload.get("wifi") is not False or \
        payload.get("rf") is not False or payload.get("second_camera") is not False or \
        payload.get("collection_status") != "DISABLED_BY_POLICY":
    raise SystemExit("persisted consent scopes or collection policy were incorrect")
print("[E1-HTTP] PASS: one session-bound consent event is durably persisted; collection remains disabled.")
PY

COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)"
DIRTY_COUNT="$(git -C "$WORKSPACE" status --porcelain=v1 | wc -l | tr -d '[:space:]')"
TREE_STATE="CLEAN"
[ "$DIRTY_COUNT" -eq 0 ] || TREE_STATE="DIRTY"
mkdir -p "$ARTIFACT_DIR"
python3 - "$WORKSPACE" "$ARTIFACT_DIR/e1-consent-http-test.json" "$COMMIT" \
    "$TREE_STATE" "$DIRTY_COUNT" "$PORT" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

root = pathlib.Path(sys.argv[1])
artifact_path = pathlib.Path(sys.argv[2])
commit, tree_state, dirty_count, port = sys.argv[3:]
sources = [
    "server/Makefile",
    "server/main.c",
    "server/environment/e1_consent.c",
    "server/events/event_chain.c",
    "tests/e1/e1-consent-http-test.sh",
]
artifact = {
    "phase": "E1",
    "check": "candidate_authenticated_consent_http_and_event_chain",
    "status": "PASS",
    "evidence_class": "development_http_integration_test_with_ephemeral_fixtures",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "source_commit": commit,
    "source_tree_state": tree_state,
    "dirty_path_count": int(dirty_count),
    "loopback_port": int(port),
    "server_build": "complete native server built out-of-tree using server/Makefile",
    "credential_and_trust_fixtures": "ephemeral test-only values in a private temporary directory",
    "covered_behaviors": [
        "candidate login and bearer session authentication",
        "unauthenticated request rejection",
        "session mismatch rejection",
        "missing, duplicate, and unknown consent scope rejection",
        "valid preference recorded against authenticated session",
        "HTTP response and durable event both keep collection disabled",
    ],
    "collection_authorized_or_started": False,
    "sensor_hardware_test": "NOT_RUN",
    "source_sha256": {
        source: hashlib.sha256((root / source).read_bytes()).hexdigest()
        for source in sources
    },
}
artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
PY

echo "[E1-HTTP] PASS: live HTTP consent integration test completed. This is not sensor or production acceptance."
