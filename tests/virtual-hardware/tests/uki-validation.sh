#!/usr/bin/env bash
set -euo pipefail
umask 077

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN_DIR="${EXAMOS_VH_RUN_DIR:-}"
[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || {
    echo "[VH-UKI] BLOCKED: set EXAMOS_VH_RUN_DIR to an existing evidence run." >&2
    exit 2
}
for tool in ukify sbsign sbverify openssl python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[VH-UKI] BLOCKED: required tool not installed: $tool" >&2
        exit 2
    }
done

KERNEL="$WORKSPACE/image/examos.vmlinuz"
INITRD="$WORKSPACE/image/examos.initrd"
OS_RELEASE="$WORKSPACE/image/overlay/etc/os-release"
for input in "$KERNEL" "$INITRD" "$OS_RELEASE"; do
    [[ -f "$input" && ! -L "$input" ]] || {
        echo "[VH-UKI] BLOCKED: required existing build input is unavailable: $input" >&2
        exit 2
    }
done

EVIDENCE="$RUN_DIR/uki"
mkdir -m 700 -- "$EVIDENCE"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sppio-vh-uki.XXXXXX")"
cleanup() { rm -rf -- "$TMP_DIR"; }
trap cleanup EXIT

openssl req -new -x509 -newkey rsa:3072 -nodes -sha256 -days 2 \
    -subj "/CN=SPPIO Virtual Hardware Test Signing Key/" \
    -keyout "$TMP_DIR/test-signing.key" -out "$EVIDENCE/test-signing.crt" \
    > "$EVIDENCE/key-generation.log" 2>&1
openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
    -subj "/CN=SPPIO Untrusted Test Key/" \
    -keyout "$TMP_DIR/wrong-signing.key" -out "$TMP_DIR/wrong-signing.crt" \
    > "$TMP_DIR/wrong-key-generation.log" 2>&1

ukify build --linux="$KERNEL" --initrd="$INITRD" \
    --os-release="@$OS_RELEASE" \
    --cmdline="console=ttyS0 quiet lockdown=confidentiality" \
    --output="$TMP_DIR/unsigned.efi" > "$EVIDENCE/ukify-build.log" 2>&1
[[ -s "$TMP_DIR/unsigned.efi" ]] || {
    echo "[VH-UKI] FAIL: ukify did not produce an unsigned UKI." >&2
    exit 1
}
sbsign --key "$TMP_DIR/test-signing.key" --cert "$EVIDENCE/test-signing.crt" \
    --output "$EVIDENCE/signed-test.efi" "$TMP_DIR/unsigned.efi" \
    > "$EVIDENCE/sbsign.log" 2>&1
sbverify --cert "$EVIDENCE/test-signing.crt" "$EVIDENCE/signed-test.efi" \
    > "$EVIDENCE/valid-signature-check.txt" 2>&1
sbverify --list "$EVIDENCE/signed-test.efi" \
    > "$EVIDENCE/signature-list.txt" 2>&1
ukify inspect "$EVIDENCE/signed-test.efi" \
    > "$EVIDENCE/uki-inspection.txt" 2>&1

if sbverify --cert "$EVIDENCE/test-signing.crt" "$TMP_DIR/unsigned.efi" \
    > "$EVIDENCE/unsigned-rejection.txt" 2>&1; then
    echo "[VH-UKI] FAIL: signature verifier accepted the unsigned UKI." >&2
    exit 1
fi
if sbverify --cert "$TMP_DIR/wrong-signing.crt" "$EVIDENCE/signed-test.efi" \
    > "$EVIDENCE/wrong-certificate-rejection.txt" 2>&1; then
    echo "[VH-UKI] FAIL: signature verifier accepted an unrelated certificate." >&2
    exit 1
fi

python3 - "$EVIDENCE/signed-test.efi" "$TMP_DIR/tampered.efi" <<'PY'
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:])
data = bytearray(source.read_bytes())
if len(data) < 8192:
    raise SystemExit("signed UKI is unexpectedly short")
data[4096] ^= 0x01
target.write_bytes(data)
PY
if sbverify --cert "$EVIDENCE/test-signing.crt" "$TMP_DIR/tampered.efi" \
    > "$EVIDENCE/modified-artifact-rejection.txt" 2>&1; then
    echo "[VH-UKI] FAIL: signature verifier accepted a modified UKI." >&2
    exit 1
fi

python3 - "$EVIDENCE" "$KERNEL" "$INITRD" "$OS_RELEASE" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
from datetime import datetime, timezone

directory = pathlib.Path(sys.argv[1])
def digest(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

certificate = subprocess.run(
    ["openssl", "x509", "-in", str(directory / "test-signing.crt"),
     "-noout", "-fingerprint", "-sha256"],
    capture_output=True, text=True, check=True,
).stdout.strip()
signature_algorithm = subprocess.run(
    ["openssl", "x509", "-in", str(directory / "test-signing.crt"),
     "-noout", "-text"],
    capture_output=True, text=True, check=True,
).stdout
signature_algorithm = next(
    (line.strip() for line in signature_algorithm.splitlines()
     if "Signature Algorithm:" in line),
    "unknown",
)
record = {
    "schema": "sppio.virtual-hardware.uki.v1",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "artifact": "signed-test.efi",
    "artifact_sha256": digest(directory / "signed-test.efi"),
    "kernel_sha256": digest(sys.argv[2]),
    "initrd_sha256": digest(sys.argv[3]),
    "os_release_sha256": digest(sys.argv[4]),
    "signing_certificate_sha256_fingerprint": certificate,
    "signature_algorithm": signature_algorithm,
    "test_signing_key_private_material_retained": False,
    "tests": {
        "ukify_build": "PASS",
        "signature_verification": "PASS",
        "unsigned_artifact_rejected": "PASS",
        "modified_artifact_rejected": "PASS",
        "untrusted_certificate_rejected": "PASS",
        "actual_ovmf_boot_enforcement": "BLOCKED: test certificate was not enrolled into disposable UEFI variables",
        "reproducible_build": "NOT TESTED",
    },
    "trust_scope": "ephemeral local test key; not organization-approved or production trust",
}
with (directory / "uki-manifest.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

printf '[VH-UKI] PASS: built and signed a test UKI; valid signature accepted and unsigned, modified, and untrusted-key artifacts rejected.\n'
