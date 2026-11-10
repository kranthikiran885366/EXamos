#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/examos-p3-production-registry.XXXXXX")
REGISTRY_CHECK="$TMP_DIR/attestation-config-check"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

for command_name in cc openssl python3; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "[P3-PRODUCTION] FAIL: required command is missing: $command_name" >&2
        exit 1
    fi
done
cc -Wall -Wextra -Werror -I"$WORKSPACE/server/include" \
    "$WORKSPACE/tests/server/attestation_config_test.c" \
    "$WORKSPACE/server/attestation/attestation_config.c" \
    -lssl -lcrypto -o "$REGISTRY_CHECK"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$TMP_DIR/release-registry-test.key" 2>/dev/null
openssl pkey -in "$TMP_DIR/release-registry-test.key" -pubout \
    -out "$TMP_DIR/release-registry-test.pub" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$TMP_DIR/device-registry-test.key" 2>/dev/null
openssl pkey -in "$TMP_DIR/device-registry-test.key" -pubout \
    -out "$TMP_DIR/device-registry-test.pub" 2>/dev/null
EXAMOS_DEVICES_PUBLIC_KEY_SHA256=$(openssl pkey -pubin -in "$TMP_DIR/device-registry-test.pub" \
    -outform DER | sha256sum | cut -d' ' -f1)
EXAMOS_RELEASES_PUBLIC_KEY_SHA256=$(openssl pkey -pubin -in "$TMP_DIR/release-registry-test.pub" \
    -outform DER | sha256sum | cut -d' ' -f1)
export EXAMOS_DEVICES_PUBLIC_KEY_SHA256 EXAMOS_RELEASES_PUBLIC_KEY_SHA256
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
        "institution_id": "production-registry-test-institution",
        "ek_fingerprint": "b" * 64,
        "ak_qualified_name": "000b" + "c" * 64,
        "ak_pub_sha256": ak_pub_sha256,
        "ak_public_pem": (root / "device-registry-test.pub").read_text(encoding="ascii"),
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
python3 - "$TMP_DIR/empty-devices.json" <<'PY'
import json
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "_schema": "examos-device-registry-v1",
    "environment": "production",
    "version": "1",
    "devices": [],
}, separators=(",", ":")) + "\n", encoding="utf-8")
PY
openssl dgst -sha256 -sign "$TMP_DIR/device-registry-test.key" \
    -out "$TMP_DIR/empty-devices.json.sig" "$TMP_DIR/empty-devices.json"

production_env() {
    env \
        EXAMOS_TPM_MODE=production \
        EXAMOS_DEVICES_CONFIG="${EXAMOS_DEVICES_CONFIG:-$TMP_DIR/devices.json}" \
        EXAMOS_RELEASES_CONFIG="${EXAMOS_RELEASES_CONFIG:-$TMP_DIR/releases.json}" \
        EXAMOS_DEVICES_SIGNATURE="${EXAMOS_DEVICES_SIGNATURE:-$TMP_DIR/devices.json.sig}" \
        EXAMOS_RELEASES_SIGNATURE="${EXAMOS_RELEASES_SIGNATURE:-$TMP_DIR/releases.json.sig}" \
        EXAMOS_DEVICES_PUBLIC_KEY="$TMP_DIR/device-registry-test.pub" \
        EXAMOS_RELEASES_PUBLIC_KEY="$TMP_DIR/release-registry-test.pub" \
        EXAMOS_DEVICES_PUBLIC_KEY_SHA256="$EXAMOS_DEVICES_PUBLIC_KEY_SHA256" \
        EXAMOS_RELEASES_PUBLIC_KEY_SHA256="$EXAMOS_RELEASES_PUBLIC_KEY_SHA256" \
        EXAMOS_EXPECT_DEVICE_INSTITUTION_ID="production-registry-test-institution" \
        "$REGISTRY_CHECK"
}

echo "[P3-PRODUCTION] Checking signed production manifests..."
if ! production_env >"$TMP_DIR/valid-startup.log" 2>&1; then
    cat "$TMP_DIR/valid-startup.log" >&2
    echo "[P3-PRODUCTION] FAIL: valid signed production registries were rejected." >&2
    exit 1
fi
echo "[P3-PRODUCTION] PASS: valid signed production registries accepted."

expect_rejection() {
    local label=$1
    if production_env >"$TMP_DIR/$label.log" 2>&1; then
        echo "[P3-PRODUCTION] FAIL: $label unexpectedly passed verification." >&2
        exit 1
    fi
    if ! grep -Eq 'FATAL:|Refusing unsigned|signature verification failed|pinned SHA-256 fingerprint|trusted-key fingerprint|lacks approved identity|device entry is incomplete' \
        "$TMP_DIR/$label.log"; then
        cat "$TMP_DIR/$label.log" >&2
        echo "[P3-PRODUCTION] FAIL: $label exited without an explicit trust rejection." >&2
        exit 1
    fi
    echo "[P3-PRODUCTION] PASS: $label rejected."
}

EXAMOS_RELEASES_PUBLIC_KEY_SHA256=$(printf '%064d' 0) \
    expect_rejection mismatched-external-release-key-pin
EXAMOS_DEVICES_CONFIG="$TMP_DIR/empty-devices.json" \
EXAMOS_DEVICES_SIGNATURE="$TMP_DIR/empty-devices.json.sig" \
    expect_rejection signed-empty-production-device-registry

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

cp "$TMP_DIR/valid-devices.json" "$TMP_DIR/devices.json"
python3 - "$TMP_DIR/devices.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["devices"][0].pop("institution_id")
path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
PY
openssl dgst -sha256 -sign "$TMP_DIR/device-registry-test.key" \
    -out "$TMP_DIR/devices.json.sig" "$TMP_DIR/devices.json"
expect_rejection signed-device-missing-institution-binding

EXAMOS_DEVICES_CONFIG="$WORKSPACE/server/config/devices.json" \
EXAMOS_RELEASES_CONFIG="$WORKSPACE/server/config/releases.json" \
    expect_rejection committed-development-registries

echo "[P3-PRODUCTION] All signed-registry acceptance/rejection checks passed."
