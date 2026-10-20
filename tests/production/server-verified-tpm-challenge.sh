#!/usr/bin/env bash
# Server-issued nonce + enrolled physical TPM quote. No swtpm fallback.
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${EXAMOS_PRODUCTION_ARTIFACT_DIR:-$WORKSPACE/artifacts/production}"
mkdir -p "$OUT"

python3 - "$OUT/physical-tpm-challenge.json" "$WORKSPACE" <<'PY'
import json, os, sys, datetime, pathlib, subprocess, urllib.request, urllib.error
out, workspace = sys.argv[1:3]
commit = subprocess.check_output(["git", "-C", workspace, "rev-parse", "HEAD"], text=True).strip()
reasons = []
result = "BLOCKED"

tpm = None
for candidate in ("/dev/tpmrm0", "/dev/tpm0"):
    if os.path.exists(candidate):
        tpm = candidate
        break
if tpm is None:
    reasons.append("no physical TPM character device")

enrollment = os.environ.get("EXAMOS_ENROLLMENT_RECORD", "")
if not enrollment:
    reasons.append("EXAMOS_ENROLLMENT_RECORD is unset; persistent EK/AK enrollment was not supplied")
elif not os.path.isfile(enrollment):
    result = "FAIL"
    reasons.append(f"enrollment record does not exist: {enrollment}")

server = os.environ.get("EXAMOS_SERVER_BASE_URL", "")
token = os.environ.get("EXAMOS_AGENT_API_TOKEN", "")
device = os.environ.get("EXAMOS_DEVICE_ID", "")
release = os.environ.get("EXAMOS_RELEASE_ID", "")
if not server or not token or not device or not release:
    reasons.append("server URL, agent token, device id, and release id are required for a live challenge")
elif tpm and enrollment and os.path.isfile(enrollment):
    req = urllib.request.Request(
        server.rstrip("/") + "/api/v1/attestation/nonce",
        data=json.dumps({"device_id": device, "release_id": release}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.load(resp)
        if not body.get("nonce"):
            result = "FAIL"
            reasons.append("server nonce response did not include a nonce")
        else:
            reasons.append("server issued a nonce, but this gate does not fabricate a quote; hardware quote/verify must be attached via EXAMOS_TPM_QUOTE_EVIDENCE")
            quote = os.environ.get("EXAMOS_TPM_QUOTE_EVIDENCE", "")
            if not quote or not os.path.isfile(quote):
                result = "BLOCKED"
            else:
                reasons.append("quote evidence file present; independent verifier output is still required")
                result = "BLOCKED"
    except Exception as exc:
        reasons.append(f"server challenge failed: {exc}")
        result = "BLOCKED"

report = {
    "schema": "examos.production.physical-tpm-challenge.v1",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "result": result,
    "tpm_device": tpm,
    "software_tpm_accepted": False,
    "reasons": reasons,
}
pathlib.Path(out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
sys.exit(0 if result == "PASS" else 2 if result == "BLOCKED" else 1)
PY
