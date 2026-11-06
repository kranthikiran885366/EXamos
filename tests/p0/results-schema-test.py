#!/usr/bin/env python3
"""Positive and negative contract checks for the P0 result validator."""
import json
import hashlib
import pathlib
import subprocess
import sys
import tempfile


def main() -> int:
    workspace = pathlib.Path(__file__).resolve().parents[2]
    schema = workspace / "schemas" / "p0-results-v1.schema.json"
    validator = workspace / "tests" / "p0" / "validate-results.py"
    checks = json.loads(schema.read_text(encoding="utf-8"))["properties"]["checks"]["required"]
    if "enterprise_validation" not in checks:
        print("FAIL: P0 result schema omits enterprise_validation", file=sys.stderr)
        return 1
    values = {name: "PASS" for name in checks}
    values.update({
        "swtpm_ready": "NOT_REQUIRED",
        "artifact_checksum": "a" * 64,
        "iso_checksum": "b" * 64,
        "reproducibility_sha256": "d" * 64,
    })
    result = {
        "schema": "examos.p0.results.v1",
        "phase": "P0",
        "version": "test",
        "timestamp": "2026-10-20T00:00:00Z",
        "git_commit": "a" * 40,
        "source_tree_state": "CLEAN",
        "source_dirty_path_count_at_start": 0,
        "build_config_sha256": "c" * 64,
        "evidence_environment": "test",
        "host": {
            "os": "test", "kernel": "test", "architecture": "x86_64",
            "virtualization": "none", "cpu_count": 2, "memory_bytes": 4096,
            "target_architecture": "x86-64",
        },
        "release_classification": "DEVELOPMENT_CANDIDATE",
        "status": "PASS",
        "disk_artifact": {"path": "disk.raw", "sha256": "a" * 64, "size_bytes": "1"},
        "iso_artifact": {"path": "disk.iso", "sha256": "b" * 64, "size_bytes": "1"},
        "checks": values,
    }
    with tempfile.TemporaryDirectory(prefix="p0-schema-test-") as temp:
        path = pathlib.Path(temp) / "results.json"
        path.write_text(json.dumps(result), encoding="utf-8")
        good = subprocess.run([sys.executable, str(validator), str(schema), str(path)], check=False)
        if good.returncode != 0:
            return 1
        in_progress = dict(result)
        in_progress["status"] = "IN_PROGRESS"
        in_progress["checks"] = dict(values)
        in_progress["checks"].update({name: "BLOCKED" for name in checks
                                       if name not in {"swtpm_ready", "artifact_checksum", "iso_checksum", "reproducibility_sha256"}})
        path.write_text(json.dumps(in_progress), encoding="utf-8")
        partial = subprocess.run([sys.executable, str(validator), str(schema), str(path)], check=False)
        if partial.returncode != 0:
            print("FAIL: validator rejected the in-progress run state", file=sys.stderr)
            return 1
        invalid = dict(result)
        invalid["checks"] = dict(values)
        invalid["checks"].pop("iso_boot")
        path.write_text(json.dumps(invalid), encoding="utf-8")
        bad = subprocess.run([sys.executable, str(validator), str(schema), str(path)], check=False)
        if bad.returncode == 0:
            print("FAIL: validator accepted a missing check ID", file=sys.stderr)
            return 1
        dirty_pass = dict(result)
        dirty_pass["source_tree_state"] = "DIRTY"
        dirty_pass["source_dirty_path_count_at_start"] = 1
        path.write_text(json.dumps(dirty_pass), encoding="utf-8")
        bad_dirty = subprocess.run([sys.executable, str(validator), str(schema), str(path)], check=False)
        if bad_dirty.returncode == 0:
            print("FAIL: validator accepted PASS evidence from a dirty source tree", file=sys.stderr)
            return 1
        dirty_build = dict(result)
        dirty_build["source_tree_state"] = "DIRTY"
        dirty_build["source_dirty_path_count_at_start"] = 1
        dirty_build["status"] = "IN_PROGRESS"
        dirty_build["checks"] = dict(values)
        dirty_build["checks"].update({name: "BLOCKED" for name in checks
                                      if name not in {"swtpm_ready", "artifact_checksum", "iso_checksum", "reproducibility_sha256"}})
        path.write_text(json.dumps(dirty_build), encoding="utf-8")
        bad_dirty_build = subprocess.run([sys.executable, str(validator), str(schema), str(path)], check=False)
        if bad_dirty_build.returncode == 0:
            print("FAIL: validator accepted an in-progress release report from a dirty source tree", file=sys.stderr)
            return 1
        incomplete_pass = dict(result)
        incomplete_pass["checks"] = dict(values)
        incomplete_pass["checks"]["kvm_access"] = "BLOCKED"
        path.write_text(json.dumps(incomplete_pass), encoding="utf-8")
        bad_incomplete_pass = subprocess.run([sys.executable, str(validator), str(schema), str(path)], check=False)
        if bad_incomplete_pass.returncode == 0:
            print("FAIL: validator accepted PASS with a blocked required check", file=sys.stderr)
            return 1
        unbound_repro_pass = dict(result)
        unbound_repro_pass["checks"] = dict(values)
        unbound_repro_pass["checks"]["reproducibility_sha256"] = "UNKNOWN"
        path.write_text(json.dumps(unbound_repro_pass), encoding="utf-8")
        bad_unbound_repro = subprocess.run([sys.executable, str(validator), str(schema), str(path)], check=False)
        if bad_unbound_repro.returncode == 0:
            print("FAIL: validator accepted reproducibility PASS without a report digest", file=sys.stderr)
            return 1
        interrupted = dict(result)
        interrupted["status"] = "FAIL"
        interrupted["disk_artifact"] = {"path": "UNKNOWN", "sha256": "UNKNOWN", "size_bytes": "UNKNOWN"}
        interrupted["iso_artifact"] = {"path": "UNKNOWN", "sha256": "UNKNOWN", "size_bytes": "UNKNOWN"}
        interrupted["checks"] = dict(values)
        interrupted["checks"].update({name: "BLOCKED" for name in checks
                                      if name not in {"swtpm_ready", "artifact_checksum", "iso_checksum", "reproducibility_sha256"}})
        interrupted["checks"]["build_pipeline"] = "FAIL"
        interrupted["checks"]["artifact_checksum"] = "UNKNOWN"
        interrupted["checks"]["iso_checksum"] = "UNKNOWN"
        interrupted["checks"]["reproducibility_sha256"] = "UNKNOWN"
        path.write_text(json.dumps(interrupted), encoding="utf-8")
        interrupted_report = subprocess.run([sys.executable, str(validator), str(schema), str(path)], check=False)
        if interrupted_report.returncode != 0:
            print("FAIL: validator rejected a structurally valid interrupted-run report", file=sys.stderr)
            return 1
        build_a = pathlib.Path(temp) / "build-a.sha256"
        build_b = pathlib.Path(temp) / "build-b.sha256"
        report_path = pathlib.Path(temp) / "reproducibility.json"
        image_a = pathlib.Path(temp) / "build-a.raw"
        image_b = pathlib.Path(temp) / "build-b.raw"
        image_bytes = b"deterministic P0 image fixture"
        image_hash = hashlib.sha256(image_bytes).hexdigest()
        image_a.write_bytes(image_bytes)
        image_b.write_bytes(image_bytes)
        manifest = image_hash + " p0-disk\n"
        build_a.write_bytes(manifest.encode("utf-8"))
        build_b.write_bytes(manifest.encode("utf-8"))
        reproducibility = {
            "schema": "examos.p0.reproducibility.v1",
            "result": "PASS",
            "release_eligible": True,
            "mode": "image",
            "source_tree_state": "CLEAN",
            "source_commit": "a" * 40,
            "source_date_epoch": 1792454400,
            "build_a": [{"sha256": image_hash, "label": "p0-disk"}],
            "build_b": [{"sha256": image_hash, "label": "p0-disk"}],
            "build_a_manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
            "build_b_manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
            "build_a_image": {"path": "build-a.raw", "sha256": image_hash,
                              "size_bytes": len(image_bytes)},
            "build_b_image": {"path": "build-b.raw", "sha256": image_hash,
                              "size_bytes": len(image_bytes)},
        }
        report_path.write_text(json.dumps(reproducibility), encoding="utf-8")
        evidence_validator = workspace / "tests" / "p0" / "validate-reproducibility.py"
        bound = subprocess.run([sys.executable, str(evidence_validator), str(report_path),
                                str(build_a), str(build_b), "a" * 40, "1792454400"], check=False)
        if bound.returncode != 0:
            print("FAIL: reproducibility evidence validator rejected valid paired manifests", file=sys.stderr)
            return 1
        build_b.write_bytes((("f" * 64) + " p0-disk\n").encode("utf-8"))
        unbound = subprocess.run([sys.executable, str(evidence_validator), str(report_path),
                                  str(build_a), str(build_b), "a" * 40, "1792454400"], check=False)
        if unbound.returncode == 0:
            print("FAIL: reproducibility evidence validator accepted mismatched manifests", file=sys.stderr)
            return 1
    print("PASS: P0 results schema accepts a valid report and rejects missing check IDs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
