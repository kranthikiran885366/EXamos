#!/usr/bin/env python3
"""Fail-closed evaluator for signed ExamOS P3 release evidence."""

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


WORKSPACE = Path(__file__).resolve().parents[2]
ARTIFACT_DIR = Path(
    os.environ.get("EXAMOS_P3_ARTIFACT_DIR", WORKSPACE / "artifacts" / "p3")
)
MANIFEST = os.environ.get("EXAMOS_RELEASE_EVIDENCE_MANIFEST", "")
SIGNATURE = os.environ.get("EXAMOS_RELEASE_EVIDENCE_SIGNATURE", "")
PUBLIC_KEY = os.environ.get("EXAMOS_RELEASE_EVIDENCE_PUBLIC_KEY", "")
REPORT = os.environ.get("EXAMOS_RELEASE_GATE_REPORT", "")

REQUIRED_EVIDENCE = (
    "reproducible_build",
    "physical_tpm_quote",
    "ek_chain_validation",
    "credential_activation",
    "event_log_replay",
    "secure_boot",
    "dm_verity_corruption_rejection",
    "runtime_lockdown",
    "key_release_binding",
    "independent_approval",
)
REQUIRED_DIGESTS = (
    "image_sha256",
    "uki_sha256",
    "rootfs_sha256",
    "verity_root_hash",
    "sbom_sha256",
)
P3_EVIDENCE_DIGESTS = (
    "p3_gate_results_sha256",
    "p3_suite_results_sha256",
)
DIGEST = re.compile(r"^[0-9a-fA-F]{64}$")
APPROVED_EC_CURVES = {"prime256v1", "secp384r1", "secp521r1"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=unique_object)


def signing_key_is_approved(path):
    try:
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(path), "-text", "-noout"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    if result.returncode != 0:
        return False
    key_description = result.stdout + result.stderr
    rsa_bits = re.search(r"Public-Key:\s*\((\d+) bit\)", key_description)
    if rsa_bits and int(rsa_bits.group(1)) >= 3072:
        return True
    curve = re.search(r"ASN1 OID:\s*([A-Za-z0-9-]+)", key_description)
    return bool(curve and curve.group(1) in APPROVED_EC_CURVES)


def is_unexpired_utc(value):
    if not isinstance(value, str):
        return False
    try:
        expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return expiry.tzinfo is not None and expiry.astimezone(timezone.utc) > datetime.now(timezone.utc)


def audit_credential_image_inputs():
    errors = []
    examos_config = WORKSPACE / "image" / "overlay" / "etc" / "examos"
    admin_path = examos_config / "admin.conf"
    candidate_path = examos_config / "candidates.conf"
    proctor_path = examos_config / "proctor.env"
    service_path = (
        WORKSPACE
        / "image"
        / "overlay"
        / "etc"
        / "systemd"
        / "system"
        / "examos-server.service"
    )
    device_registry_path = WORKSPACE / "server" / "config" / "devices.json"

    try:
        admin_values = [
            line.strip()
            for line in admin_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if admin_values != [
            "ADMIN_USERNAME=NOT_PROVISIONED",
            "ADMIN_PASSWORD_PBKDF2=NOT_PROVISIONED",
        ]:
            errors.append("image admin config must contain only the unprovisioned placeholder")

        candidates = [
            line.strip()
            for line in candidate_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if candidates:
            errors.append("release image candidate store must contain no candidate records")

        proctor_values = {
            line.partition("=")[0].strip(): line.partition("=")[2].strip()
            for line in proctor_path.read_text(encoding="utf-8").splitlines()
            if "=" in line and not line.lstrip().startswith("#")
        }
        if proctor_values != {
            "EXAMOS_PROCTOR_API_TOKEN": "NOT_PROVISIONED",
            "EXAMOS_EVENT_SIGNING_KEY": "NOT_PROVISIONED",
            "EXAMOS_VARIANT_SECRET": "NOT_PROVISIONED",
        }:
            errors.append("image proctor config must contain all unprovisioned secret placeholders")

        service = service_path.read_text(encoding="utf-8")
        required_service_settings = (
            "Environment=EXAMOS_TPM_MODE=production",
            "EnvironmentFile=/run/examos/secrets/runtime.env",
            "EnvironmentFile=/run/examos/secrets/agent.env",
            "EnvironmentFile=/etc/examos/proctor.env",
            "EnvironmentFile=/run/examos/secrets/proctor.env",
            'ExecStartPre=/usr/bin/test "${EXAMOS_TPM_MODE}" = production',
        )
        if any(setting not in service for setting in required_service_settings):
            errors.append("server unit must require production mode and TPM-unsealed runtime secrets")

        if (examos_config / "agent.env").exists():
            errors.append("agent.env must not be baked into the release image")

        device_registry = read_json(device_registry_path)
        if not isinstance(device_registry, dict) or device_registry.get("devices") != []:
            errors.append("committed device registry must not enroll devices")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        errors.append(f"cannot verify credential-free image inputs: {error}")

    forbidden_values = (
        "ExamOS@Admin2025!",
        "ExamOS@2026!",
        "CAND-2026-001",
        "ADMIN_PASSWORD_SHA256=",
        "examos-p3-ci-agent-token",
        "examos-p3-ci-proctor-token",
        "examos-p3-test-agent-token",
        "examos-p3-test-proctor-token",
        "production-registry-test-agent-token",
        "production-registry-test-proctor-token",
    )
    release_inputs = (
        WORKSPACE / ".github" / "workflows" / "p3.yml",
        WORKSPACE / "image" / "config" / "p3.conf",
        WORKSPACE / "scripts" / "setup-demo-candidate.sh",
        WORKSPACE / "scripts" / "launch-server.sh",
        WORKSPACE / "scripts" / "apply-ui-and-splash.sh",
        WORKSPACE / "scripts" / "build-and-sync-desktop.sh",
        WORKSPACE / "scripts" / "build-full-image.sh",
        WORKSPACE / "tests" / "p0" / "server-smoke-test.sh",
        WORKSPACE / "tests" / "p3" / "attestation-suite.sh",
        WORKSPACE / "tests" / "p3" / "production-registry.sh",
    )
    for path in release_inputs:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as error:
            errors.append(f"cannot inspect release credential input {path}: {error}")
            continue
        for value in forbidden_values:
            if value in content:
                errors.append(f"forbidden credential/default {value!r} found in {path}")
    return errors


def output(verdict, checks):
    report = {
        "phase": "P3_RELEASE",
        "gate": verdict,
        "evidence_class": "PRODUCTION_RELEASE_CANDIDATE",
        "checks": checks,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if REPORT:
        report_path = Path(REPORT)
        try:
            report_path.resolve().relative_to(WORKSPACE)
        except ValueError:
            pass
        else:
            print("ERROR: EXAMOS_RELEASE_GATE_REPORT must be outside the source tree", file=sys.stderr)
            return 1
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(rendered, encoding="utf-8")
        except OSError as error:
            print(f"ERROR: cannot write release gate report: {error}", file=sys.stderr)
            return 1
    print(rendered, end="")
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[verdict]


def main():
    if sys.argv[1:] == ["--credential-audit"]:
        errors = audit_credential_image_inputs()
        print(json.dumps({
            "audit": "CREDENTIAL_FREE_IMAGE_INPUTS",
            "gate": "FAIL" if errors else "PASS",
            "errors": errors,
        }, indent=2, sort_keys=True))
        return 1 if errors else 0
    if len(sys.argv) != 1:
        print("Usage: release-gate.py [--credential-audit]", file=sys.stderr)
        return 2

    checks = {}
    failures = []
    blocked = []
    credential_errors = audit_credential_image_inputs()
    checks["credential_free_image_inputs"] = "FAIL" if credential_errors else "PASS"
    failures.extend(credential_errors)
    try:
        commit_result = subprocess.run(
            ["git", "-C", str(WORKSPACE), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        commit_result = None
        commit = ""
        checks["source_commit"] = "FAIL"
        failures.append(f"cannot execute git to resolve repository commit: {error}")
    if commit_result is not None and commit_result.returncode != 0:
        checks["source_commit"] = "FAIL"
        failures.append("cannot resolve repository commit")
        commit = ""
    elif commit_result is not None:
        commit = commit_result.stdout.strip()
        checks["source_commit"] = commit

    try:
        status_result = subprocess.run(
            ["git", "-C", str(WORKSPACE), "status", "--porcelain", "--untracked-files=all"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        status_result = None
        checks["source_tree"] = "FAIL"
        failures.append(f"cannot execute git to determine worktree state: {error}")
    if status_result is not None and status_result.returncode != 0:
        checks["source_tree"] = "FAIL"
        failures.append("cannot determine source worktree state")
    elif status_result is not None and status_result.stdout:
        checks["source_tree"] = "DIRTY"
        failures.append("production release gate requires a clean source worktree")
    elif status_result is not None:
        checks["source_tree"] = "CLEAN"

    p3_results_path = ARTIFACT_DIR / "results.json"
    try:
        p3_results = read_json(p3_results_path)
    except FileNotFoundError as error:
        p3_results = None
        checks["development_p3_gate"] = "BLOCKED"
        blocked.append(f"required P3 test evidence is missing: {error.filename}")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        p3_results = None
        checks["development_p3_gate"] = "FAIL"
        failures.append(f"cannot parse P3 test evidence: {error}")

    if p3_results is not None and not isinstance(p3_results, dict):
        checks["development_p3_gate"] = "FAIL"
        failures.append("P3 test evidence must be a JSON object")
    elif p3_results is not None:
        bound_to_clean_commit = (
            p3_results.get("source_commit") == commit
            and p3_results.get("source_tree_state_at_start") == "CLEAN"
        )
        if not bound_to_clean_commit:
            checks["development_p3_gate"] = "FAIL"
            failures.append("P3 software-check evidence is not bound to the current clean commit")
        elif p3_results.get("gate") == "FAIL":
            checks["development_p3_gate"] = "FAIL"
            failures.append("P3 software checks reported a failure")
        elif p3_results.get("gate") == "PASS":
            checks["development_p3_gate"] = "PASS"
        elif p3_results.get("gate") == "BLOCKED":
            checks["development_p3_gate"] = "BLOCKED"
            blocked.append("P3 software checks are blocked")
        else:
            checks["development_p3_gate"] = "FAIL"
            failures.append("P3 software-check evidence has an invalid gate verdict")

    if not MANIFEST or not SIGNATURE or not PUBLIC_KEY:
        checks["signed_production_manifest"] = "BLOCKED"
        blocked.append(
            "set EXAMOS_RELEASE_EVIDENCE_MANIFEST, "
            "EXAMOS_RELEASE_EVIDENCE_SIGNATURE, and "
            "EXAMOS_RELEASE_EVIDENCE_PUBLIC_KEY"
        )
    else:
        manifest_path = Path(MANIFEST)
        signature_path = Path(SIGNATURE)
        key_path = Path(PUBLIC_KEY)
        if not manifest_path.is_file() or not signature_path.is_file() or not key_path.is_file():
            checks["signed_production_manifest"] = "BLOCKED"
            blocked.append("signed production manifest, detached signature, or public key is unavailable")
        else:
            try:
                signature_result = subprocess.run(
                    [
                        "openssl", "dgst", "-sha256", "-verify", str(key_path),
                        "-signature", str(signature_path), str(manifest_path),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            except OSError as error:
                signature_result = None
                checks["signed_production_manifest"] = "FAIL"
                failures.append(f"cannot execute OpenSSL signature verification: {error}")
            approved_key = signing_key_is_approved(key_path)
            try:
                manifest = read_json(manifest_path)
            except (OSError, ValueError, json.JSONDecodeError) as error:
                manifest = None
                checks["signed_production_manifest"] = "FAIL"
                failures.append(f"production manifest is malformed: {error}")

            if manifest is not None and not isinstance(manifest, dict):
                manifest = None
                checks["signed_production_manifest"] = "FAIL"
                failures.append("production manifest must contain a JSON object")

            if manifest is not None:
                manifest_evidence = manifest.get("evidence", {})
                valid_digests = True
                for field in REQUIRED_DIGESTS + P3_EVIDENCE_DIGESTS:
                    value = manifest.get(field)
                    if not isinstance(value, str) or not DIGEST.fullmatch(value) or not any(
                        char != "0" for char in value
                    ):
                        valid_digests = False
                        failures.append(f"production manifest has invalid {field}")

                p3_digest_bindings_match = (
                    manifest.get("p3_gate_results_sha256")
                    == hashlib.sha256(p3_results_path.read_bytes()).hexdigest()
                    if p3_results is not None and p3_results_path.is_file()
                    else False
                ) and (
                    manifest.get("p3_suite_results_sha256")
                    == hashlib.sha256(suite_results_path.read_bytes()).hexdigest()
                    if suite_results is not None and suite_results_path.is_file()
                    else False
                )
                evidence_pass = isinstance(manifest_evidence, dict) and all(
                    manifest_evidence.get(field) == "PASS"
                    for field in REQUIRED_EVIDENCE
                )
                metadata_pass = (
                    manifest.get("_schema") == "examos-release-evidence-v1"
                    and manifest.get("environment") == "production"
                    and manifest.get("approval_status") == "APPROVED_PRODUCTION"
                    and manifest.get("source_tree_state") == "CLEAN"
                    and manifest.get("source_commit") == commit
                    and manifest.get("production_release_id")
                    and manifest.get("revocation_status") == "ACTIVE"
                    and is_unexpired_utc(manifest.get("expires_at"))
                    and approved_key
                    and valid_digests
                    and p3_digest_bindings_match
                    and evidence_pass
                )
                if signature_result is None:
                    pass
                elif signature_result.returncode != 0:
                    checks["signed_production_manifest"] = "FAIL"
                    failures.append("production manifest detached signature verification failed")
                elif not approved_key:
                    checks["signed_production_manifest"] = "FAIL"
                    failures.append("manifest signing key must be RSA-3072+ or approved NIST P-256/384/521")
                elif not metadata_pass:
                    checks["signed_production_manifest"] = "FAIL"
                    failures.append(
                        "production manifest metadata, required evidence, P3 evidence hashes, "
                        "or source binding is incomplete"
                    )
                else:
                    checks["signed_production_manifest"] = "PASS"

    if failures:
        verdict = "FAIL"
    elif blocked:
        verdict = "BLOCKED"
    else:
        verdict = "PASS"
    checks["failure_reasons"] = failures
    checks["blocked_reasons"] = blocked
    checks["manifest_sha256"] = (
        hashlib.sha256(Path(MANIFEST).read_bytes()).hexdigest()
        if MANIFEST and Path(MANIFEST).is_file()
        else None
    )
    return output(verdict, checks)


if __name__ == "__main__":
    sys.exit(main())
