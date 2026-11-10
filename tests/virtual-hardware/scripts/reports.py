#!/usr/bin/env python3
"""Record test outcomes and generate evidence-bound Phase 3 reports."""

import argparse
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone


STATUSES = ("PASS", "FAIL", "BLOCKED", "NOT TESTED", "NOT APPLICABLE")
ROOT = pathlib.Path(__file__).resolve().parents[3]


def load_json(path):
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    temporary.replace(path)


def record(args):
    run_dir = pathlib.Path(args.run_dir).resolve()
    result_path = run_dir / "reports" / "phase3-test-results.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    if result_path.exists():
        result = load_json(result_path)
    else:
        result = {
            "schema": "sppio.virtual-hardware.test-results.v1",
            "run_id": run_dir.name,
            "source_commit": args.source_commit,
            "tests": [],
        }
    if any(item["test_id"] == args.test_id for item in result["tests"]):
        raise SystemExit(f"duplicate test id: {args.test_id}")
    result["tests"].append(
        {
            "test_id": args.test_id,
            "name": args.name,
            "objective": args.objective,
            "preconditions": args.preconditions,
            "command": args.command,
            "expected_result": args.expected,
            "actual_result": args.actual,
            "status": args.status,
            "evidence_location": args.evidence,
            "log_location": args.log,
            "failure_details": args.details,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    )
    write_json(result_path, result)


def combine(statuses):
    if "FAIL" in statuses:
        return "FAIL"
    if "BLOCKED" in statuses:
        return "BLOCKED"
    if "NOT TESTED" in statuses:
        return "NOT TESTED"
    if "NOT APPLICABLE" in statuses:
        return "NOT APPLICABLE"
    return "PASS" if statuses and all(status == "PASS" for status in statuses) else "NOT TESTED"


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def finalize(args):
    run_dir = pathlib.Path(args.run_dir).resolve()
    if (run_dir / "evidence-sha256.txt").exists():
        raise SystemExit("evidence manifest already exists; refusing to rewrite a finalized run")
    reports = run_dir / "reports"
    inventory = load_json(reports / "toolchain-inventory.json")
    test_results = load_json(reports / "phase3-test-results.json")
    tests = {item["test_id"]: item for item in test_results["tests"]}
    for item in test_results["tests"]:
        item["tool_versions"] = {
            name: value.get("version")
            for name, value in inventory["tools"].items()
            if value.get("available")
        }

    def status(test_id):
        item = tests.get(test_id)
        return item["status"] if item else "NOT TESTED"

    qemu = status("QEMU_BOOT")
    quote = status("SWTPM_QUOTE")
    uki = status("UKI_ARTIFACT")
    verity = status("DM_VERITY_ARTIFACT")
    postgres = status("POSTGRES_INTEGRATION")
    credential_audit = status("CREDENTIAL_AUDIT")
    registry = status("SIGNED_REGISTRY_TEST")
    ceremony = status("PHYSICAL_CEREMONY_SWTPM")

    gates = [
        {
            "id": "VH-01",
            "requirement": "Toolchain and host preflight",
            "status": status("TOOLCHAIN_PREFLIGHT"),
            "evidence": "reports/toolchain-inventory.json",
        },
        {
            "id": "VH-02",
            "requirement": "Isolated QEMU VM",
            "status": combine([status("VM_CREATE"), qemu]),
            "evidence": "epoch-*/vm.json and qemu-boot/",
        },
        {
            "id": "VH-03",
            "requirement": "Virtual TPM 2.0",
            "status": quote,
            "evidence": "tpm-quote/: software TPM capability, PCR quote, and backend verifier checks",
        },
        {
            "id": "VH-04",
            "requirement": "UEFI boot",
            "status": qemu,
            "evidence": "epoch-*/serial.log and qemu-boot/",
        },
        {
            "id": "VH-05",
            "requirement": "Secure Boot enforcement",
            "status": "BLOCKED",
            "evidence": "OVMF Secure Boot enforcement and test-key enrollment were not independently exercised",
        },
        {
            "id": "VH-06",
            "requirement": "Signed UKI artifact verification",
            "status": uki,
            "evidence": "uki/: valid signatures pass; unsigned, modified, and untrusted-key artifacts are rejected",
        },
        {
            "id": "VH-07",
            "requirement": "PCR measurement validation",
            "status": "BLOCKED",
            "evidence": "qemu-boot/: post-boot PCR quote may be recorded; event-log reconstruction is not",
        },
        {
            "id": "VH-08",
            "requirement": "TPM quote verification",
            "status": quote,
            "evidence": "tpm-quote/ and qemu-boot/",
        },
        {
            "id": "VH-09",
            "requirement": "Replay and tampering rejection",
            "status": combine([quote, postgres, registry, ceremony]),
            "evidence": "TPM quote negative cases, PostgreSQL challenge test, registry and ceremony logs",
        },
        {
            "id": "VH-10",
            "requirement": "dm-verity data and hash-tree integrity",
            "status": verity,
            "evidence": "dm-verity/: regular-file data, hash-tree, and root-hash tampering tests",
        },
        {
            "id": "VH-11",
            "requirement": "Backend attestation integration",
            "status": "BLOCKED",
            "evidence": "No API-level virtual institution-device enrollment/attestation test was run",
        },
        {
            "id": "VH-12",
            "requirement": "PostgreSQL persistence integration",
            "status": postgres,
            "evidence": "postgres/: disposable local TLS database, migrations, CRUD/update/restart checks",
        },
        {
            "id": "VH-13",
            "requirement": "Security regression suite",
            "status": combine(
                [quote, uki, verity, postgres, credential_audit, registry, ceremony]
            ),
            "evidence": "Individual software-only test logs under this run",
        },
        {
            "id": "VH-14",
            "requirement": "Evidence and reproducibility",
            "status": "PASS",
            "evidence": "reports/ and evidence-sha256.txt",
        },
        {
            "id": "VH-15",
            "requirement": "Physical hardware readiness",
            "status": "BLOCKED",
            "evidence": "No physical TPM or organization-controlled hardware signing was accessed",
        },
        {
            "id": "VH-16",
            "requirement": "dm-verity read-only root and boot integration",
            "status": "BLOCKED",
            "evidence": "Only disposable regular files were tested; production image boot-chain integration is not configured",
        },
    ]

    software = [gate for gate in gates if gate["id"] != "VH-15"]
    if any(gate["status"] == "FAIL" for gate in software):
        decision = "SOFTWARE VALIDATION FAILED — SECURITY OR FUNCTIONAL TESTS FAILED."
    elif all(gate["status"] == "PASS" for gate in software):
        decision = "SOFTWARE VALIDATION PASSED — PHYSICAL HARDWARE VALIDATION PENDING."
    elif any(gate["status"] == "PASS" for gate in software if gate["id"] != "VH-14"):
        decision = "SOFTWARE VALIDATION PARTIALLY PASSED — REMEDIATION REQUIRED."
    else:
        decision = "SOFTWARE VALIDATION BLOCKED — PREREQUISITES UNAVAILABLE."

    finding_rows = []
    image = inventory["images"]
    for name in ("examos.raw", "examos.iso"):
        record = image.get(name, {})
        if record.get("present") and record.get("sidecar_matches") is False:
            finding_rows.append(
                {
                    "severity": "LOW",
                    "finding": f"{name} checksum sidecar does not match the current file",
                    "evidence": f"toolchain-inventory.json: computed {record['sha256']}, sidecar {record['sidecar_sha256']}",
                    "recommendation": "Reconcile the artifact with its source/build record before distributing or relying on the sidecar.",
                }
            )
    implementation = inventory["source_implementation"]
    if not implementation["image_build"]["declares_uki_or_secureboot"]:
        finding_rows.append(
            {
                "severity": "MEDIUM",
                "finding": "The current mkosi profile does not declare a signed UKI or Secure Boot integration.",
                "evidence": implementation["image_build"]["configuration"],
                "recommendation": "Keep production boot unchanged until a separately reviewed, test-key-only UKI/Secure Boot integration is implemented and firmware-enforced.",
            }
        )
    if implementation["dm_verity"]["descriptor_only_boot_integration"]:
        finding_rows.append(
            {
                "severity": "MEDIUM",
                "finding": "The dm-verity setup generates host-side artifacts and a descriptor but does not bind them into the existing boot path.",
                "evidence": implementation["dm_verity"]["post_build_setup_script"],
                "recommendation": "Implement and validate the signed boot-chain/root-hash binding before claiming a verified root filesystem.",
            }
        )

    limitations = [
        "WSL/QEMU/swtpm/OVMF results are software-emulated and do not establish physical TPM or host firmware behavior.",
        "A successful artifact-level UKI signature check does not prove that the configured OVMF firmware enforced Secure Boot.",
        "A dm-verity regular-file check does not prove read-only device-mapper mounting or boot-chain integration.",
        "TPM PCR values without a TCG event log do not prove which firmware or boot events produced the measurements.",
        "The separate institution device-registration/attestation HTTP workflow is not passed by the current database-only integration test.",
        "A local disposable PostgreSQL test is not a production database connectivity, backup, or deployment test.",
        "The PostgreSQL rollback check covers a failed SQL transaction only; this migration runner has no down-migration operation, so schema rollback is not tested.",
        "Checksums make evidence tamper-evident for later comparison, not cryptographically immutable.",
    ]
    if not postgres == "PASS":
        limitations.append("PostgreSQL migrations, user persistence, and attestation-table integration did not all complete in this run.")

    checklist = [
        "Obtain explicit approval for the specific physical test device and test window.",
        "Record TPM manufacturer, firmware version, EK certificate chain, and device identity without clearing or taking ownership of the TPM.",
        "Capture the firmware-provided TCG event log and reconstruct selected PCRs independently.",
        "Verify Secure Boot state and enrolled PK/KEK/db ownership on the actual device; do not enroll test keys without a reviewed procedure.",
        "Bind the TPM-backed AK to the approved, institution-bound production registry through the organization's dual-control signing ceremony.",
        "Run the server-issued nonce/quote flow against the approved backend and confirm server-side signature, identity, PCR policy, expiry, replay, and revocation enforcement.",
        "Verify read-only dm-verity root mounting and corruption failure on a disposable physical test image before any production rollout.",
        "Exercise cold boot, warm reboot, power-cycle, TPM persistence, firmware update, recovery, revocation, and re-enrollment procedures.",
        "Retain the complete signed approval, device configuration, test results, logs, checksums, and recovery records.",
        "Do not clear or reset the physical TPM, alter firmware keys, or change physical disk partitions as part of automated tests.",
    ]

    records = test_results["tests"]
    test_results["gates"] = gates
    test_results["final_decision"] = decision
    test_results["physical_hardware_is_not_a_software_failure"] = True
    write_json(reports / "phase3-test-results.json", test_results)

    summary = {
        "schema": "sppio.virtual-hardware.phase3-summary.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_dir.name,
        "source_commit": inventory.get("git_commit"),
        "source_branch": inventory.get("git_branch"),
        "overall_decision": decision,
        "software_gate_counts": {
            status_name: sum(1 for gate in software if gate["status"] == status_name)
            for status_name in STATUSES
        },
        "gates": gates,
        "test_count": len(records),
        "host_summary": {
            "platform": inventory["host"]["platform"],
            "wsl": inventory["host"]["wsl"],
            "cpu_count": inventory["host"]["cpu_count"],
            "qemu_accelerators_reported": inventory["host"]["qemu_accelerators_reported"],
            "kvm_device": inventory["host"]["kvm"],
            "physical_tpm_nodes_present": inventory["host"]["physical_tpm_device_nodes_present"],
        },
        "safety": inventory["safety"],
        "limitations": limitations,
    }
    write_json(reports / "phase3-summary.json", summary)

    md = [
        "# SPPIO Virtual Hardware Phase 3 Summary",
        "",
        f"- Run: `{run_dir.name}`",
        f"- Generated: `{summary['generated_at_utc']}`",
        f"- Source commit: `{summary['source_commit']}`",
        f"- Host: `{inventory['host']['platform']}`",
        f"- WSL: `{inventory['host']['wsl']}`",
        f"- Decision: **{decision}**",
        "",
        "## Release gates",
        "",
        "| Gate | Requirement | Status | Evidence / limitation |",
        "|---|---|---|---|",
    ]
    for gate in gates:
        md.append(
            f"| {gate['id']} | {gate['requirement']} | **{gate['status']}** | {gate['evidence']} |"
        )
    md.extend(
        [
            "",
            "## Safety boundaries",
            "",
            "- No production PostgreSQL database or production credentials were used.",
            "- The existing raw image was only opened as a read-only qcow2 backing image; VM writes went to a separate overlay.",
            "- Virtual TPM state and UEFI variables are isolated per run and retained.",
            "- No physical TPM, physical disk, host firmware setting, production key, commit, push, or deployment was used.",
            "- A software TPM or test signing certificate is never production trust evidence.",
            "",
            "## Limitations",
            "",
        ]
    )
    md.extend(f"- {item}" for item in limitations)
    md.extend(
        [
            "",
            "## Related reports",
            "",
            "- [Toolchain inventory](./toolchain-inventory.md)",
            "- [Test results](./phase3-test-results.json)",
            "- [Security findings](./phase3-security-findings.md)",
            "- [Limitations](./phase3-limitations.md)",
            "- [Physical validation checklist](./phase3-physical-validation-checklist.md)",
            "",
        ]
    )
    (reports / "phase3-summary.md").write_text("\n".join(md), encoding="utf-8")

    findings = [
        "# Phase 3 Security Findings",
        "",
        "| Severity | Finding | Evidence | Recommended action |",
        "|---|---|---|---|",
    ]
    if finding_rows:
        for finding in finding_rows:
            findings.append(
                f"| {finding['severity']} | {finding['finding']} | {finding['evidence']} | {finding['recommendation']} |"
            )
    else:
        findings.append("| None confirmed | No additional inventory finding was confirmed by this run. | Current run evidence | Continue physical validation. |")
    findings.extend(
        [
            "",
            "A missing physical prerequisite is reported as BLOCKED, not as a fabricated PASS or an exploit finding.",
            "",
        ]
    )
    (reports / "phase3-security-findings.md").write_text("\n".join(findings), encoding="utf-8")

    limitation_text = [
        "# Phase 3 Limitations",
        "",
        *[f"- {item}" for item in limitations],
        "",
        "No physical TPM operations, production database writes, production key use, or deployment occurred.",
        "",
    ]
    (reports / "phase3-limitations.md").write_text("\n".join(limitation_text), encoding="utf-8")
    (reports / "phase3-physical-validation-checklist.md").write_text(
        "# Physical Hardware Validation Checklist\n\n"
        + "\n".join(f"- [ ] {item}" for item in checklist)
        + "\n",
        encoding="utf-8",
    )

    print(json.dumps({"decision": decision, "summary": str(reports / "phase3-summary.md")}))


def create_manifest(args):
    run_dir = pathlib.Path(args.run_dir).resolve()
    manifest_path = run_dir / "evidence-sha256.txt"
    if manifest_path.exists():
        raise SystemExit("evidence manifest already exists; refusing to rewrite a finalized run")
    entries = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path != manifest_path and not path.is_symlink():
            entries.append(f"{file_hash(path)}  {path.relative_to(run_dir).as_posix()}")
    with manifest_path.open("x", encoding="utf-8") as stream:
        stream.write("\n".join(entries) + "\n")
    print(json.dumps({"evidence_manifest": str(manifest_path)}))


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    add_record = subparsers.add_parser("record")
    for name in (
        "run_dir", "test_id", "name", "objective", "preconditions",
        "command", "expected", "actual", "status", "evidence", "log",
        "details", "source_commit",
    ):
        add_record.add_argument(f"--{name.replace('_', '-')}", required=True)
    add_record.set_defaults(function=record)

    add_finalize = subparsers.add_parser("finalize")
    add_finalize.add_argument("--run-dir", required=True)
    add_finalize.set_defaults(function=finalize)

    add_manifest = subparsers.add_parser("manifest")
    add_manifest.add_argument("--run-dir", required=True)
    add_manifest.set_defaults(function=create_manifest)

    args = parser.parse_args()
    if hasattr(args, "status") and args.status not in STATUSES:
        parser.error(f"--status must be one of {', '.join(STATUSES)}")
    args.function(args)


if __name__ == "__main__":
    main()
