#!/usr/bin/env bash
# Organization-owned Secure Boot / registry evidence. Development keys fail.
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${EXAMOS_PRODUCTION_ARTIFACT_DIR:-$WORKSPACE/artifacts/production}"
mkdir -p "$OUT"

python3 - "$OUT/trust-provisioning.json" "$WORKSPACE" <<'PY'
import json, os, sys, datetime, pathlib, subprocess
import hashlib, re
out, workspace = sys.argv[1:3]
commit = subprocess.check_output(["git", "-C", workspace, "rev-parse", "HEAD"], text=True).strip()
required = [
    "EXAMOS_PROD_DB_CERT",
    "EXAMOS_PROD_UKI",
    "EXAMOS_PROD_RELEASE_MANIFEST",
    "EXAMOS_PROD_RELEASE_SIGNATURE",
    "EXAMOS_PROD_RELEASE_PUBKEY",
    "EXAMOS_PROD_DEVICE_MANIFEST",
    "EXAMOS_PROD_DEVICE_SIGNATURE",
    "EXAMOS_PROD_DEVICE_PUBKEY",
    "EXAMOS_TPM_CA_STORE",
    "EXAMOS_PROD_TPM_EK_CERT",
    "EXAMOS_PROD_SECUREBOOT_CERT",
    "EXAMOS_PROD_DB_CA_STORE",
]
reasons = []
present = {}
for name in required:
    path = os.environ.get(name, "")
    present[name] = path or None
    if not path:
        reasons.append(f"{name} is unset")
    elif not os.path.isfile(path):
        reasons.append(f"{name} path does not exist: {path}")
    elif os.path.getsize(path) == 0:
        reasons.append(f"{name} is empty")

dev_trust = (pathlib.Path(workspace) / "image" / "trust").resolve()
for env_name, path in list(present.items()):
    if path and env_name not in {"EXAMOS_RELEASES_PUBLIC_KEY_SHA256", "EXAMOS_DEVICES_PUBLIC_KEY_SHA256"}:
        candidate = pathlib.Path(path).resolve()
        if candidate == dev_trust or dev_trust in candidate.parents:
            reasons.append(f"{env_name} points at development trust material; production keys are required")

pin_names = ("EXAMOS_RELEASES_PUBLIC_KEY_SHA256", "EXAMOS_DEVICES_PUBLIC_KEY_SHA256",
             "EXAMOS_TPM_CA_STORE_SHA256", "EXAMOS_PROD_SECUREBOOT_CERT_SHA256",
             "EXAMOS_PROD_DB_CA_STORE_SHA256")
for name in pin_names:
    value = os.environ.get(name, "")
    present[name] = value or None
    if not value:
        reasons.append(f"{name} is unset; approved public-key pins must come from protected organization configuration")
    if value and (len(value) != 64 or any(c not in "0123456789abcdefABCDEF" for c in value)):
        reasons.append(f"{name} must be a protected external SHA-256 pin")

result = "BLOCKED"
if reasons:
    result = "BLOCKED"
else:
    # Pins must come from protected organization configuration, not the
    # manifests or files being checked. Verify every artifact the gate names.
    try:
        for key_name, pin_name in (("EXAMOS_PROD_RELEASE_PUBKEY", "EXAMOS_RELEASES_PUBLIC_KEY_SHA256"),
                                   ("EXAMOS_PROD_DEVICE_PUBKEY", "EXAMOS_DEVICES_PUBLIC_KEY_SHA256")):
            der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", os.environ[key_name], "-outform", "DER"])
            if hashlib.sha256(der).hexdigest().lower() != os.environ[pin_name].lower():
                raise ValueError(f"{key_name} does not match its externally pinned fingerprint")
        for file_name, pin_name in (("EXAMOS_TPM_CA_STORE", "EXAMOS_TPM_CA_STORE_SHA256"),
                                    ("EXAMOS_PROD_SECUREBOOT_CERT", "EXAMOS_PROD_SECUREBOOT_CERT_SHA256"),
                                    ("EXAMOS_PROD_DB_CA_STORE", "EXAMOS_PROD_DB_CA_STORE_SHA256")):
            if hashlib.sha256(pathlib.Path(os.environ[file_name]).read_bytes()).hexdigest().lower() != os.environ[pin_name].lower():
                raise ValueError(f"{file_name} does not match its externally pinned fingerprint")
        subprocess.check_call([
            "openssl", "dgst", "-sha256", "-verify", os.environ["EXAMOS_PROD_RELEASE_PUBKEY"],
            "-signature", os.environ["EXAMOS_PROD_RELEASE_SIGNATURE"],
            os.environ["EXAMOS_PROD_RELEASE_MANIFEST"],
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call([
            "openssl", "dgst", "-sha256", "-verify", os.environ["EXAMOS_PROD_DEVICE_PUBKEY"],
            "-signature", os.environ["EXAMOS_PROD_DEVICE_SIGNATURE"],
            os.environ["EXAMOS_PROD_DEVICE_MANIFEST"],
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call([
            "openssl", "crl2pkcs7", "-nocrl", "-certfile", os.environ["EXAMOS_TPM_CA_STORE"],
            "-outform", "DER", "-out", os.devnull,
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call([
            "openssl", "verify", "-CAfile", os.environ["EXAMOS_TPM_CA_STORE"],
            os.environ["EXAMOS_PROD_TPM_EK_CERT"],
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ek_public = subprocess.check_output([
            "openssl", "x509", "-in", os.environ["EXAMOS_PROD_TPM_EK_CERT"],
            "-pubkey", "-noout",
        ])
        ek_public_der = subprocess.check_output([
            "openssl", "pkey", "-pubin", "-inform", "PEM", "-outform", "DER",
        ], input=ek_public)
        ek_fingerprint = hashlib.sha256(ek_public_der).hexdigest()
        release_registry = json.loads(pathlib.Path(os.environ["EXAMOS_PROD_RELEASE_MANIFEST"]).read_text(encoding="utf-8"))
        if release_registry.get("_schema") != "examos-release-registry-v1" or release_registry.get("environment") != "production":
            raise ValueError("release manifest is not a production ExamOS release registry")
        uki_hash = hashlib.sha256(pathlib.Path(os.environ["EXAMOS_PROD_UKI"]).read_bytes()).hexdigest()
        qualified_releases = set()
        for entry in release_registry.get("releases", []):
            if not isinstance(entry, dict) or entry.get("approval_status") != "APPROVED_PRODUCTION":
                continue
            if entry.get("revoked") is not False or entry.get("pcr_bank", "").lower() != "sha256":
                continue
            measurements = [entry.get(key, "") for key in ("uki_hash", "pcr0", "pcr4", "pcr7", "pcr11")]
            if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value) or not re.search(r"[1-9a-fA-F]", value) for value in measurements):
                continue
            release_id = entry.get("release_id", "")
            if not isinstance(release_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,63}", release_id):
                continue
            if entry["uki_hash"].lower() == uki_hash:
                qualified_releases.add(release_id)
        if not qualified_releases:
            raise ValueError("signed release registry does not approve this UKI with complete SHA-256 PCR measurements")
        device_registry = json.loads(pathlib.Path(os.environ["EXAMOS_PROD_DEVICE_MANIFEST"]).read_text(encoding="utf-8"))
        if device_registry.get("_schema") != "examos-device-registry-v1" or device_registry.get("environment") != "production":
            raise ValueError("device manifest is not a production ExamOS device registry")
        enrolled = any(
            isinstance(entry, dict) and
            str(entry.get("ek_fingerprint", "")).lower() == ek_fingerprint and
            isinstance(entry.get("device_id"), str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,63}", entry["device_id"]) and
            isinstance(entry.get("ak_qualified_name"), str) and re.fullmatch(r"000b[0-9a-fA-F]{64}", entry["ak_qualified_name"]) and
            isinstance(entry.get("ak_pub_sha256"), str) and re.fullmatch(r"[0-9a-fA-F]{64}", entry["ak_pub_sha256"]) and
            re.search(r"[1-9a-fA-F]", entry["ak_pub_sha256"]) and
            isinstance(entry.get("ak_public_pem"), str) and "BEGIN PUBLIC KEY" in entry["ak_public_pem"] and
            entry.get("status") in {"ENROLLED", "TRUSTED"} and
            entry.get("allowed_release") in qualified_releases
            for entry in device_registry.get("devices", [])
        )
        if not enrolled:
            raise ValueError("pinned EK certificate is not enrolled for the approved UKI in the signed device manifest")
        subprocess.check_call([
            "openssl", "verify", "-purpose", "sslserver", "-CAfile",
            os.environ["EXAMOS_PROD_DB_CA_STORE"], os.environ["EXAMOS_PROD_DB_CERT"],
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call([
            "sbverify", "--cert", os.environ["EXAMOS_PROD_SECUREBOOT_CERT"],
            os.environ["EXAMOS_PROD_UKI"],
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = "PASS"
    except FileNotFoundError as exc:
        result = "BLOCKED"
        reasons.append(f"required trust verification tool is unavailable: {exc}")
    except (subprocess.CalledProcessError, ValueError) as exc:
        result = "FAIL"
        reasons.append(f"organization manifest signature verification failed: {exc}")

report = {
    "schema": "examos.production.trust-provisioning.v1",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "result": result,
    "inputs": present,
    "reasons": reasons,
    "development_keys_accepted": False,
}
pathlib.Path(out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
sys.exit(0 if result == "PASS" else 2 if result == "BLOCKED" else 1)
PY
