#!/usr/bin/env python3
"""Create truthful, commit-bound P6 prerequisite evidence from existing gates."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "artifacts" / "phase6"
DOCS = ROOT / "docs" / "phase6"
OUT.mkdir(parents=True, exist_ok=True)
DOCS.mkdir(parents=True, exist_ok=True)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout.strip()


def load(relative: str) -> dict:
    path = ROOT / relative
    if not path.is_file():
        return {"_missing": True}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"_invalid": str(exc)}


def digest(relative: str) -> str | None:
    path = ROOT / relative
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def phase_status(phase: str, evidence: str, raw: dict) -> dict:
    candidates = [raw.get("overall"), raw.get("overall_gate"), raw.get("gate"), raw.get("status")]
    status = next((str(v).upper() for v in candidates if v is not None), "NOT_RUN")
    if raw.get("_missing") or raw.get("_invalid"):
        status = "NOT_RUN"
    if status not in {
        "PASS", "PARTIAL", "FAIL", "BLOCKED", "NOT_RUN",
        "INVALIDATED", "NOT_APPLICABLE",
    }:
        status = "FAIL"
    dirty = raw.get("source_tree_state_at_start") == "DIRTY"
    current_commit = git("rev-parse", "HEAD")
    artifact_commit = raw.get("source_commit") or raw.get("git_commit") or raw.get("gitCommit")
    release_eligible = status == "PASS" and not dirty and artifact_commit == current_commit
    reasons: list[str] = []
    if dirty:
        reasons.append("Evidence was produced from a dirty working tree.")
    if artifact_commit and artifact_commit != current_commit:
        reasons.append("Evidence is not bound to the current commit.")
    if not artifact_commit:
        reasons.append("Evidence has no source commit binding.")
    if status != "PASS":
        reasons.append(f"Gate status is {status}.")
    return {
        "phase": phase,
        "status": status,
        "releaseEligible": release_eligible,
        "evidence": evidence,
        "sha256": digest(evidence),
        "artifactCommit": artifact_commit,
        "reasons": reasons,
    }


commit = git("rev-parse", "HEAD")
branch = git("branch", "--show-current")
porcelain = git("status", "--porcelain=v1")
now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

sources = {
    "P0": "artifacts/p0/results.json",
    "P1": "artifacts/p1/results.json",
    "P2": "artifacts/phase2/phase2-manifest.json",
    "P3": "artifacts/p3/results.json",
    "P4": "artifacts/phase4/phase4-manifest.json",
    "P5": "artifacts/phase5/manifest.json",
}
phases = {name: phase_status(name, path, load(path)) for name, path in sources.items()}

# A missing aggregate P0 result does not mean no P0 activity occurred. Preserve
# the split records while keeping the phase partial and release-ineligible.
if phases["P0"]["status"] == "NOT_RUN":
    p0_paths = [
        "artifacts/p0/build-result.json",
        "artifacts/p0/boot-result.json",
    ]
    evidence_root = ROOT / "artifacts" / "evidence"
    for name in ("iso-build-result.json", "iso-boot-result.json"):
        candidates = sorted(evidence_root.glob(f"p0-*/{name}"), reverse=True)
        if candidates:
            p0_paths.append(candidates[0].relative_to(ROOT).as_posix())

    split_evidence = []
    for path in p0_paths:
        raw = load(path)
        if raw.get("_missing") or raw.get("_invalid"):
            continue
        split_evidence.append({
            "evidence": path,
            "status": str(raw.get("status", "NOT_RUN")).upper(),
            "sourceCommit": raw.get("source_commit"),
            "sourceTreeState": raw.get("source_tree_state_at_start")
                or raw.get("source_tree_state"),
        })
    if split_evidence:
        phases["P0"]["status"] = "PARTIAL"
        phases["P0"]["splitEvidence"] = split_evidence
        phases["P0"]["reasons"] = [
            "Split P0 build/boot records exist, but the consolidated "
            "artifacts/p0/results.json gate result is missing.",
            "Split evidence does not establish a complete P0 PASS.",
        ]
        if any(item["sourceTreeState"] == "DIRTY" for item in split_evidence):
            phases["P0"]["reasons"].append(
                "At least one split P0 artifact was produced from a dirty tree."
            )

stack = {
    "implemented": ["native C/C++ server and agents", "flat-file journals", "development Go TPM verifier"],
    "requiredByP6PromptButAbsent": [
        "Node.js backend", "MongoDB", "Redis streams", "Python inference workers",
        "WebRTC SFU", "Docker deployment",
    ],
    "decision": "BLOCKED",
    "reason": "The frozen architecture named by the P6 prompt does not match this repository. "
              "Adding it would be an architectural replacement prohibited by the same prompt.",
}

blockers = [f"{p}: {', '.join(v['reasons']) or 'not release eligible'}"
            for p, v in phases.items() if not v["releaseEligible"]]
blockers += [
    "Physical matrix: three distinct laptop models have not supplied evidence.",
    "Authorized red-team execution: written owner authorization and executed findings evidence are absent.",
    "Pilot: no authorized 10-20 volunteer pilot evidence exists.",
    "Production key custody and production signature ceremony evidence are absent.",
    "P4 real labelled media dataset is absent.",
    "P5 viva provider is unavailable; the fresh gate reports P5-F/G/H BLOCKED.",
]

report = {
    "schema": "examos-phase6-prerequisite-v1",
    "generatedAt": now,
    "sourceCommit": commit,
    "branch": branch,
    "workingTree": "DIRTY" if porcelain else "CLEAN",
    "workingTreeEntryCount": len(porcelain.splitlines()) if porcelain else 0,
    "decision": "BLOCKED",
    "phases": phases,
    "architectureDiscrepancy": stack,
    "mandatoryBlockers": blockers,
}
(OUT / "prerequisite-status.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

rows = [
    "# ExamOS Phase 6 prerequisite status",
    "",
    f"Generated: `{now}`  ",
    f"Commit: `{commit}`  ",
    f"Working tree: **{report['workingTree']}** ({report['workingTreeEntryCount']} entries)  ",
    "Decision: **BLOCKED**",
    "",
    "## Phase evidence",
    "",
    "| Phase | Recorded status | Release eligible | Evidence |",
    "|---|---:|---:|---|",
]
for name, item in phases.items():
    rows.append(f"| {name} | {item['status']} | {'YES' if item['releaseEligible'] else 'NO'} | `{item['evidence']}` |")
rows += [
    "", "## Architecture discrepancy", "", stack["reason"], "",
    "Absent prompt-mandated components: " + ", ".join(stack["requiredByP6PromptButAbsent"]) + ".",
    "", "## Mandatory blockers", "",
]
rows += [f"- {item}" for item in blockers]
rows += ["", "This report does not convert BLOCKED, NOT_RUN, stale, dirty-tree, or invalidated evidence into PASS.", ""]
(DOCS / "prerequisite-status.md").write_text("\n".join(rows), encoding="utf-8")
print(json.dumps({"decision": "BLOCKED", "output": str(OUT / 'prerequisite-status.json'), "phases": phases}))
