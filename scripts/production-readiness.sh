#!/usr/bin/env bash
# Aggregate the seven production blockers. Missing evidence stays BLOCKED.
# P0, P3, and production certification remain separate results.
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
export EXAMOS_PRODUCTION_ARTIFACT_DIR="${EXAMOS_PRODUCTION_ARTIFACT_DIR:-$WORKSPACE/artifacts/production}"
export EXAMOS_P0_REPRO_MODE="${EXAMOS_P0_REPRO_MODE:-pins}"
mkdir -p "$EXAMOS_PRODUCTION_ARTIFACT_DIR"
RC_FILE="$(mktemp)"
trap 'rm -f "$RC_FILE"' EXIT

run_gate() {
    local name="$1" script="$2" rc=0
    bash "$script" || rc=$?
    printf '%s:%s\n' "$name" "$rc" >>"$RC_FILE"
}

run_gate EXT-01-clean-source "$WORKSPACE/tests/production/clean-source-gate.sh"
run_gate EXT-02-reproducibility "$WORKSPACE/tests/p0/reproducible-build.sh"
run_gate EXT-03-vmware "$WORKSPACE/tests/p0/vmware-optical-boot.sh"
run_gate EXT-04-hardware "$WORKSPACE/tests/production/hardware-qualification-gate.sh"
run_gate EXT-05-trust "$WORKSPACE/tests/production/trust-provisioning-gate.sh"
run_gate EXT-06-tpm "$WORKSPACE/tests/production/server-verified-tpm-challenge.sh"
run_gate EXT-07-assessment "$WORKSPACE/tests/production/external-acceptance-gate.sh"

python3 - "$EXAMOS_PRODUCTION_ARTIFACT_DIR/blocker-status.json" "$WORKSPACE" "$RC_FILE" <<'PY'
import json, os, subprocess, sys, datetime
out, workspace, rc_file = sys.argv[1:4]
commit = subprocess.check_output(["git", "-C", workspace, "rev-parse", "HEAD"], text=True).strip()
dirty = subprocess.check_output(
    ["git", "-C", workspace, "status", "--porcelain", "--untracked-files=all"],
    text=True,
)
tree = "DIRTY" if dirty.strip() else "CLEAN"
titles = {
    "EXT-01-clean-source": "Clean identifiable source commit",
    "EXT-02-reproducibility": "Pinned sources and two isolated builds",
    "EXT-03-vmware": "VMware Workstation UEFI ISO boot",
    "EXT-04-hardware": "Qualified physical device models",
    "EXT-05-trust": "Organization-owned Secure Boot and registries",
    "EXT-06-tpm": "Enrolled physical TPM server challenge",
    "EXT-07-assessment": "Independent security/operations assessment",
}
classes = {
    "EXT-01-clean-source": "source",
    "EXT-02-reproducibility": "software-build",
    "EXT-03-vmware": "vmware",
    "EXT-04-hardware": "physical-hardware",
    "EXT-05-trust": "organization-trust",
    "EXT-06-tpm": "physical-hardware",
    "EXT-07-assessment": "independent-assessment",
}
rc_map = {"0": "PASS", "1": "FAIL", "2": "BLOCKED"}
blockers = []
overall = "PASS"
with open(rc_file, encoding="utf-8") as fh:
    pairs = [line.strip() for line in fh if line.strip()]
for item in pairs:
    name, rc = item.split(":", 1)
    result = rc_map.get(rc, "BLOCKED")
    reason = {
        "PASS": "gate returned PASS",
        "FAIL": "gate returned FAIL",
        "BLOCKED": "required evidence is missing or not executable here",
    }[result]
    blockers.append({
        "id": name,
        "title": titles[name],
        "result": result,
        "evidence_class": classes[name],
        "reason": reason,
    })
    if result == "FAIL":
        overall = "FAIL"
    elif result != "PASS" and overall != "FAIL":
        overall = "BLOCKED"
report = {
    "schema": "examos.production.blocker-status.v1",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "source_tree_state": tree,
    "overall": overall,
    "p0_separate": True,
    "p3_separate": True,
    "production_separate": True,
    "blockers": blockers,
}
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")
print(json.dumps(report, indent=2))
sys.exit(0 if overall == "PASS" else 2 if overall == "BLOCKED" else 1)
PY
