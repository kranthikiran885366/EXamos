#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
SERVER_BIN=${EXAMOS_P3_SERVER_BIN:-"$WORKSPACE/server/examos-server"}
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/examos-p3-production-registry.XXXXXX")

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [ ! -x "$SERVER_BIN" ]; then
    echo "[P3-PRODUCTION] FAIL: server binary is missing or not executable: $SERVER_BIN" >&2
    exit 1
fi
for command_name in openssl python3; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "[P3-PRODUCTION] FAIL: required command is missing: $command_name" >&2
        exit 1
    fi
done

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$TMP_DIR/release-registry-test.key" 2>/dev/null
openssl pkey -in "$TMP_DIR/release-registry-test.key" -pubout \
    -out "$TMP_DIR/release-registry-test.pub" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$TMP_DIR/device-registry-test.key" 2>/dev/null
openssl pkey -in "$TMP_DIR/device-registry-test.key" -pubout \
    -out "$TMP_DIR/device-registry-test.pub" 2>/dev/null
DEVICE_PUBLIC_HASH=$(openssl pkey -pubin -in "$TMP_DIR/device-registry-test.pub" \
    -outform DER | sha256sum | cut -d' ' -f1)
AGENT_TEST_TOKEN=$(openssl rand -hex 32)
PROCTOR_TEST_TOKEN=$(openssl rand -hex 32)
EVENT_TEST_KEY=$(openssl rand -hex 32)
VARIANT_TEST_SECRET=$(openssl rand -hex 32)
LEDGER_TEST_KEY=$(openssl rand -hex 32)
export EXAMOS_AGENT_API_TOKEN="$AGENT_TEST_TOKEN"
export EXAMOS_PROCTOR_API_TOKEN="$PROCTOR_TEST_TOKEN"
export EXAMOS_EVENT_SIGNING_KEY="$EVENT_TEST_KEY"
export EXAMOS_VARIANT_SECRET="$VARIANT_TEST_SECRET"
export EXAMOS_LEDGER_HMAC_KEY="$LEDGER_TEST_KEY"

python3 - "$TMP_DIR" "$DEVICE_PUBLIC_HASH" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
ak_pub_sha256 = sys.argv[2]
release = {
    "_schema": "examos-release-registry-v1",
    "environment": "production",
    "version": "1",
    "releases": [{
        "release_id": "examos-test-production",
        "uki_hash": "a" * 64,
        "pcr0": "1" * 64,
        "pcr4": "2" * 64,
        "pcr7": "3" * 64,
        "pcr11": "4" * 64,
        "approval_status": "APPROVED_PRODUCTION",
        "pcr_bank": "SHA256",
        "revoked": False,
    }],
}
devices = {
    "_schema": "examos-device-registry-v1",
    "environment": "production",
    "version": "1",
    "devices": [{
        "device_id": "production-registry-test-device",
        "ek_fingerprint": "b" * 64,
        "ak_name": "000b" + "c" * 64,
        "ak_pub_sha256": ak_pub_sha256,
        "status": "ENROLLED",
        "allowed_release": "examos-test-production",
    }],
}
(root / "releases.json").write_text(
    json.dumps(release, separators=(",", ":")) + "\n", encoding="utf-8"
)
(root / "devices.json").write_text(
    json.dumps(devices, separators=(",", ":")) + "\n", encoding="utf-8"
)
PY

openssl dgst -sha256 -sign "$TMP_DIR/release-registry-test.key" \
    -out "$TMP_DIR/releases.json.sig" "$TMP_DIR/releases.json"
openssl dgst -sha256 -sign "$TMP_DIR/device-registry-test.key" \
    -out "$TMP_DIR/devices.json.sig" "$TMP_DIR/devices.json"
cp "$TMP_DIR/devices.json" "$TMP_DIR/valid-devices.json"

next_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

production_env() {
    env \
        EXAMOS_TPM_MODE=production \
        EXAMOS_SERVER_PORT="$1" \
        EXAMOS_LEDGER_PATH="$TMP_DIR/ledger-$1.log" \
        EXAMOS_SESSION_JOURNAL="$TMP_DIR/session-$1.log" \
        EXAMOS_AGENT_API_TOKEN="$AGENT_TEST_TOKEN" \
        EXAMOS_PROCTOR_API_TOKEN="$PROCTOR_TEST_TOKEN" \
        EXAMOS_EVENT_SIGNING_KEY="$EVENT_TEST_KEY" \
        EXAMOS_VARIANT_SECRET="$VARIANT_TEST_SECRET" \
        EXAMOS_LEDGER_HMAC_KEY="$LEDGER_TEST_KEY" \
        EXAMOS_DEVICES_CONFIG="${EXAMOS_DEVICES_CONFIG:-$TMP_DIR/devices.json}" \
        EXAMOS_RELEASES_CONFIG="${EXAMOS_RELEASES_CONFIG:-$TMP_DIR/releases.json}" \
        EXAMOS_DEVICES_SIGNATURE="${EXAMOS_DEVICES_SIGNATURE:-$TMP_DIR/devices.json.sig}" \
        EXAMOS_RELEASES_SIGNATURE="${EXAMOS_RELEASES_SIGNATURE:-$TMP_DIR/releases.json.sig}" \
        EXAMOS_DEVICES_PUBLIC_KEY="$TMP_DIR/device-registry-test.pub" \
        EXAMOS_RELEASES_PUBLIC_KEY="$TMP_DIR/release-registry-test.pub" \
        "$SERVER_BIN"
}

echo "[P3-PRODUCTION] Checking signed production manifests..."
if ! python3 - "$SERVER_BIN" "$TMP_DIR" <<'PY'
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

server = sys.argv[1]
root = pathlib.Path(sys.argv[2])
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

env = os.environ.copy()
env.update({
    "EXAMOS_TPM_MODE": "production",
    "EXAMOS_SERVER_PORT": str(port),
    "EXAMOS_LEDGER_PATH": str(root / "valid-ledger.log"),
    "EXAMOS_SESSION_JOURNAL": str(root / "valid-session.log"),
    "EXAMOS_AGENT_API_TOKEN": os.environ["EXAMOS_AGENT_API_TOKEN"],
    "EXAMOS_PROCTOR_API_TOKEN": os.environ["EXAMOS_PROCTOR_API_TOKEN"],
    "EXAMOS_EVENT_SIGNING_KEY": os.environ["EXAMOS_EVENT_SIGNING_KEY"],
    "EXAMOS_VARIANT_SECRET": os.environ["EXAMOS_VARIANT_SECRET"],
    "EXAMOS_LEDGER_HMAC_KEY": os.environ["EXAMOS_LEDGER_HMAC_KEY"],
    "EXAMOS_DEVICES_CONFIG": str(root / "devices.json"),
    "EXAMOS_RELEASES_CONFIG": str(root / "releases.json"),
    "EXAMOS_DEVICES_SIGNATURE": str(root / "devices.json.sig"),
    "EXAMOS_RELEASES_SIGNATURE": str(root / "releases.json.sig"),
    "EXAMOS_DEVICES_PUBLIC_KEY": str(root / "device-registry-test.pub"),
    "EXAMOS_RELEASES_PUBLIC_KEY": str(root / "release-registry-test.pub"),
})
with (root / "valid-startup.log").open("w", encoding="utf-8") as log:
    process = subprocess.Popen([server], env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        ready = False
        for _ in range(15):
            if process.poll() is not None:
                break
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/api/v1/health", timeout=1
                ) as response:
                    ready = response.status == 200
                    break
            except (urllib.error.URLError, TimeoutError):
                time.sleep(0.2)
        if not ready:
            raise SystemExit("valid signed production registries did not reach healthy startup")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
if not ready:
    raise SystemExit("valid signed production registries did not start")
PY
then
    cat "$TMP_DIR/valid-startup.log" >&2
    echo "[P3-PRODUCTION] FAIL: valid signed production registries did not reach healthy startup." >&2
    exit 1
fi
echo "[P3-PRODUCTION] PASS: valid signed production registries accepted."

expect_rejection() {
    local label=$1
    local port
    port=$(next_port)
    if production_env "$port" >"$TMP_DIR/$label.log" 2>&1; then
        echo "[P3-PRODUCTION] FAIL: $label unexpectedly started successfully." >&2
        exit 1
    fi
    if ! grep -Eq 'FATAL:|Refusing unsigned|signature verification failed|lacks approved identity|device entry is incomplete' \
        "$TMP_DIR/$label.log"; then
        cat "$TMP_DIR/$label.log" >&2
        echo "[P3-PRODUCTION] FAIL: $label exited without an explicit trust rejection." >&2
        exit 1
    fi
    echo "[P3-PRODUCTION] PASS: $label rejected."
}

cp "$TMP_DIR/releases.json" "$TMP_DIR/tampered-releases.json"
python3 - "$TMP_DIR/tampered-releases.json" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(path.read_text(encoding="utf-8").replace('"uki_hash":"' + "a" * 64,
                                                         '"uki_hash":"' + "c" * 64),
                encoding="utf-8")
PY
EXAMOS_RELEASES_CONFIG="$TMP_DIR/tampered-releases.json" \
    expect_rejection tampered-production-release-registry

python3 - "$TMP_DIR/releases.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["releases"][0]["approval_status"] = "APPROVED_DEV"
path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
PY
openssl dgst -sha256 -sign "$TMP_DIR/release-registry-test.key" \
    -out "$TMP_DIR/releases.json.sig" "$TMP_DIR/releases.json"
expect_rejection signed-development-release

python3 - "$TMP_DIR/releases.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["releases"][0]["approval_status"] = "APPROVED_PRODUCTION"
data["releases"][0]["uki_hash"] = "0" * 64
path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
PY
openssl dgst -sha256 -sign "$TMP_DIR/release-registry-test.key" \
    -out "$TMP_DIR/releases.json.sig" "$TMP_DIR/releases.json"
expect_rejection signed-placeholder-uki-hash

python3 - "$TMP_DIR/devices.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["devices"][0]["ek_fingerprint"] = "0" * 64
path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
PY
openssl dgst -sha256 -sign "$TMP_DIR/device-registry-test.key" \
    -out "$TMP_DIR/devices.json.sig" "$TMP_DIR/devices.json"
expect_rejection signed-placeholder-device-fingerprint

cp "$TMP_DIR/valid-devices.json" "$TMP_DIR/devices.json"
python3 - "$TMP_DIR/devices.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["devices"][0].pop("ak_pub_sha256")
path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
PY
openssl dgst -sha256 -sign "$TMP_DIR/device-registry-test.key" \
    -out "$TMP_DIR/devices.json.sig" "$TMP_DIR/devices.json"
expect_rejection signed-device-missing-ak-public-key-binding

EXAMOS_DEVICES_CONFIG="$WORKSPACE/server/config/devices.json" \
EXAMOS_RELEASES_CONFIG="$WORKSPACE/server/config/releases.json" \
    expect_rejection committed-development-registries

echo "[P3-PRODUCTION] All signed-registry acceptance/rejection checks passed."
