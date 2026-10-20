#!/usr/bin/env python3
"""Validate the P0 aggregate report against its versioned JSON Schema."""
import json
import pathlib
import re
import sys
from datetime import datetime


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: validate-results.py SCHEMA RESULT", file=sys.stderr)
        return 2
    schema_path, result_path = map(pathlib.Path, sys.argv[1:])
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[P0-SCHEMA] FAIL: cannot load schema or result: {exc}", file=sys.stderr)
        return 1
    errors = []
    required = schema.get("required", [])
    for key in required:
        if key not in result:
            errors.append(f"missing required field: {key}")
    if result.get("schema") != "examos.p0.results.v1":
        errors.append("schema must be examos.p0.results.v1")
    if result.get("phase") != "P0":
        errors.append("phase must be P0")
    if result.get("status") not in {"IN_PROGRESS", "PASS", "FAIL", "BLOCKED"}:
        errors.append("status must be IN_PROGRESS, PASS, FAIL, or BLOCKED")
    if not isinstance(result.get("version"), str) or not result["version"].strip():
        errors.append("version must be a non-empty string")
    if not isinstance(result.get("evidence_environment"), str) or not result["evidence_environment"].strip():
        errors.append("evidence_environment must be a non-empty string")
    host = result.get("host")
    if not isinstance(host, dict):
        errors.append("host must be an object")
    else:
        for key in ("os", "kernel", "architecture", "virtualization", "target_architecture"):
            if not isinstance(host.get(key), str) or not host[key].strip():
                errors.append(f"host.{key} must be a non-empty string")
        for key in ("cpu_count", "memory_bytes"):
            if not isinstance(host.get(key), int) or isinstance(host.get(key), bool) or host[key] < 1:
                errors.append(f"host.{key} must be a positive integer")
    if result.get("source_tree_state") not in {"CLEAN", "DIRTY"}:
        errors.append("source_tree_state must be CLEAN or DIRTY")
    dirty_count = result.get("source_dirty_path_count_at_start")
    if not isinstance(dirty_count, int) or dirty_count < 0:
        errors.append("source_dirty_path_count_at_start must be a non-negative integer")
    elif (result.get("source_tree_state") == "CLEAN") != (dirty_count == 0):
        errors.append("source_tree_state and dirty path count disagree")
    try:
        datetime.fromisoformat(result.get("timestamp", "").replace("Z", "+00:00"))
    except (TypeError, ValueError):
        errors.append("timestamp must be an ISO 8601 date-time")
    if not re.fullmatch(r"[0-9a-f]{64}", str(result.get("build_config_sha256", ""))):
        errors.append("build_config_sha256 must be a lowercase SHA-256 digest")
    commit = result.get("git_commit", "")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        errors.append("git_commit must be a full hexadecimal object ID")
    checks = result.get("checks")
    check_schema = schema.get("properties", {}).get("checks", {})
    expected_checks = set(check_schema.get("required", []))
    allowed_statuses = {"PASS", "FAIL", "BLOCKED"}
    if not isinstance(checks, dict):
        errors.append("checks must be an object")
    else:
        missing_checks = expected_checks - checks.keys()
        extra_checks = checks.keys() - expected_checks
        if missing_checks:
            errors.append("missing check IDs: " + ", ".join(sorted(missing_checks)))
        if extra_checks:
            errors.append("unknown check IDs: " + ", ".join(sorted(extra_checks)))
        for name in expected_checks - {"swtpm_ready", "artifact_checksum", "iso_checksum", "reproducibility_sha256"}:
            if checks.get(name) not in allowed_statuses:
                errors.append(f"checks.{name} must be PASS, FAIL, or BLOCKED")
        if checks.get("swtpm_ready") not in {"AVAILABLE", "NOT_REQUIRED"}:
            errors.append("checks.swtpm_ready must be AVAILABLE or NOT_REQUIRED")
        for name in ("artifact_checksum", "iso_checksum", "reproducibility_sha256"):
            digest = checks.get(name)
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}|UNKNOWN", digest):
                errors.append(f"checks.{name} must be a lowercase SHA-256 digest or UNKNOWN")
        if checks.get("reproducible_build") == "PASS" and checks.get("reproducibility_sha256") == "UNKNOWN":
            errors.append("a reproducibility PASS must bind its report digest")
        statuses = [value for name, value in checks.items()
                    if name not in {"swtpm_ready", "artifact_checksum", "iso_checksum", "reproducibility_sha256"}]
        expected_status = "FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses else "PASS"
        if result.get("status") != "IN_PROGRESS" and result.get("status") != expected_status:
            errors.append(f"aggregate status must be {expected_status} for the check statuses")
        if result.get("source_tree_state") == "DIRTY" and result.get("status") in {"PASS", "IN_PROGRESS"}:
            errors.append("a result from a dirty source tree cannot have status PASS")
        if result.get("source_tree_state") == "CLEAN" and dirty_count != 0:
            errors.append("clean source state must have zero dirty paths")
        if result.get("status") in {"PASS", "IN_PROGRESS"} and result.get("release_classification") != "DEVELOPMENT_CANDIDATE":
            errors.append("unexpected release classification")
    for artifact_name in ("disk_artifact", "iso_artifact"):
        artifact = result.get(artifact_name)
        if not isinstance(artifact, dict):
            errors.append(f"{artifact_name} must be an object")
            continue
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}|UNKNOWN", digest):
            errors.append(f"{artifact_name}.sha256 must be a lowercase SHA-256 digest or UNKNOWN")
        if not isinstance(artifact.get("path"), str) or not artifact["path"].strip():
            errors.append(f"{artifact_name}.path must be a non-empty string")
        size = artifact.get("size_bytes")
        if not isinstance(size, str) or not re.fullmatch(r"[0-9]+|UNKNOWN", size):
            errors.append(f"{artifact_name}.size_bytes must be a non-negative integer string or UNKNOWN")
    if result.get("status") == "PASS":
        if result.get("source_tree_state") != "CLEAN" or dirty_count != 0:
            errors.append("PASS requires a clean source tree with zero dirty paths")
        if not isinstance(checks, dict) or any(
            value != "PASS" for name, value in checks.items()
            if name not in {"swtpm_ready", "artifact_checksum", "iso_checksum", "reproducibility_sha256"}
        ):
            errors.append("PASS requires every required check to be PASS")
        for artifact_name in ("disk_artifact", "iso_artifact"):
            artifact = result.get(artifact_name, {})
            if artifact.get("sha256") == "UNKNOWN" or artifact.get("size_bytes") == "UNKNOWN":
                errors.append(f"PASS requires known {artifact_name} digest and size")
        if checks.get("reproducibility_sha256") == "UNKNOWN":
            errors.append("PASS requires a bound reproducibility report digest")
    if errors:
        for error in errors:
            print(f"[P0-SCHEMA] FAIL: {error}", file=sys.stderr)
        return 1
    print("[P0-SCHEMA] PASS: result matches examos.p0.results.v1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
