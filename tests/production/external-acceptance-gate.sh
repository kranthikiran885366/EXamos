#!/usr/bin/env bash
# Independent security/operations assessment. Missing files stay BLOCKED.
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${EXAMOS_PRODUCTION_ARTIFACT_DIR:-$WORKSPACE/artifacts/production}"
mkdir -p "$OUT"
ASSESSMENT="${EXAMOS_INDEPENDENT_ASSESSMENT_PATH:-}"
commit="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"

python3 - "$OUT/independent-assessment.json" "$ASSESSMENT" "$commit" <<'PY'
import json, os, sys, datetime, pathlib
out, path, commit = sys.argv[1:4]
reasons = []
result = "BLOCKED"
fields = {}
if not path:
    reasons.append("EXAMOS_INDEPENDENT_ASSESSMENT_PATH is unset")
elif not os.path.isfile(path):
    result = "FAIL"
    reasons.append(f"assessment path does not exist: {path}")
else:
    text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    for key in ("ASSESSMENT_STATUS", "ASSESSOR_NAME", "ASSESSOR_ROLE", "SCOPE", "SOURCE_COMMIT"):
        marker = key + "="
        line = next((ln[len(marker):].strip() for ln in text.splitlines() if ln.startswith(marker)), "")
        fields[key] = line
        if not line:
            reasons.append(f"assessment missing {key}")
    if fields.get("ASSESSOR_ROLE") != "independent":
        reasons.append("ASSESSOR_ROLE must be independent")
    if fields.get("SOURCE_COMMIT") and fields["SOURCE_COMMIT"] != commit:
        reasons.append("assessment SOURCE_COMMIT does not match the current git HEAD")
    if fields.get("ASSESSMENT_STATUS") == "APPROVED" and not reasons:
        result = "PASS"
    elif fields.get("ASSESSMENT_STATUS") == "REJECTED":
        result = "FAIL"
        reasons.append("independent assessment rejected production use")
    else:
        result = "BLOCKED"
report = {
    "schema": "examos.production.independent-assessment.v1",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "result": result,
    "fields": fields,
    "reasons": reasons,
}
pathlib.Path(out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
sys.exit(0 if result == "PASS" else 2 if result == "BLOCKED" else 1)
PY
