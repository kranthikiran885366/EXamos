#!/usr/bin/env bash
# Fail closed unless a completed per-device qualification record is supplied.
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${EXAMOS_PRODUCTION_ARTIFACT_DIR:-$WORKSPACE/artifacts/production}"
mkdir -p "$OUT"
RECORD="${EXAMOS_HARDWARE_QUALIFICATION_RECORD:-}"

python3 - "$OUT/hardware-qualification.json" "$RECORD" "$WORKSPACE" <<'PY'
import json, os, sys, datetime, pathlib, subprocess
out, record, workspace = sys.argv[1:4]
commit = subprocess.check_output(["git", "-C", workspace, "rev-parse", "HEAD"], text=True).strip()
reasons = []
result = "BLOCKED"
model_scope = []
if not record:
    reasons.append("EXAMOS_HARDWARE_QUALIFICATION_RECORD is unset; no device is qualified")
elif not os.path.isfile(record):
    result = "FAIL"
    reasons.append(f"qualification record path does not exist: {record}")
else:
    text = pathlib.Path(record).read_text(encoding="utf-8", errors="replace")
    values = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    model_scope.append({
        "manufacturer": values.get("MANUFACTURER"),
        "model": values.get("MODEL"),
        "firmware": values.get("FIRMWARE"),
        "tpm": values.get("TPM_MANUFACTURER"),
        "qualification": "NOT_QUALIFIED",
    })
    required = ("MODEL=", "SERIAL=", "FIRMWARE=", "TPM_MANUFACTURER=",
                "SECURE_BOOT=ENABLED", "INTERNAL_DISK_WRITES=NONE",
                "QUALIFIED=YES", "RECOVERY_PLAN=DOCUMENTED")
    missing = [item for item in required if item not in text]
    if missing:
        reasons.append("qualification record is incomplete: " + ", ".join(missing))
    else:
        reasons.append("record claims qualification, but countersigned hardware evidence is not attached")
        result = "BLOCKED"
report = {
    "schema": "examos.production.hardware-qualification.v1",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "result": result,
    "in_scope_candidates": model_scope,
    "qualified_devices": [],
    "reasons": reasons,
    "internal_disk_or_firmware_changes": False,
}
pathlib.Path(out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
sys.exit(0 if result == "PASS" else 2 if result == "BLOCKED" else 1)
PY
