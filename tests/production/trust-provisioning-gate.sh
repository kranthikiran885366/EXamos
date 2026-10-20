#!/usr/bin/env bash
# Organization-owned Secure Boot / registry evidence. Development keys fail.
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${EXAMOS_PRODUCTION_ARTIFACT_DIR:-$WORKSPACE/artifacts/production}"
mkdir -p "$OUT"

python3 - "$OUT/trust-provisioning.json" "$WORKSPACE" <<'PY'
import json, os, sys, datetime, pathlib, subprocess
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

dev_trust = pathlib.Path(workspace) / "image" / "trust"
for env_name, path in list(present.items()):
    if path and path.startswith(str(dev_trust)):
        reasons.append(f"{env_name} points at development trust material; production keys are required")

result = "BLOCKED"
if reasons:
    result = "BLOCKED"
else:
    # Files exist: still require openssl verify of manifests.
    try:
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
        result = "PASS"
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
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
