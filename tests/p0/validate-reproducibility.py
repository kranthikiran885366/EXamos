#!/usr/bin/env python3
"""Verify two-build P0 image reproducibility evidence and its manifests."""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys


def fail(message: str) -> int:
    print(f"[P0-REPRO-VALIDATE] FAIL: {message}", file=sys.stderr)
    return 1


def read_manifest(path: pathlib.Path) -> list[dict[str, str]]:
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) (.+)", line)
        if not match:
            raise ValueError(f"invalid manifest row in {path}")
        entries.append({"sha256": match.group(1), "label": match.group(2)})
    return entries


def main() -> int:
    if len(sys.argv) != 6:
        print("usage: validate-reproducibility.py REPORT BUILD_A BUILD_B COMMIT SOURCE_DATE_EPOCH", file=sys.stderr)
        return 2
    report_path, build_a_path, build_b_path = map(pathlib.Path, sys.argv[1:4])
    expected_commit = sys.argv[4]
    expected_epoch = sys.argv[5]
    if not re.fullmatch(r"[0-9]+", expected_epoch):
        return fail("expected source-date epoch is not an integer")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        raw_a = build_a_path.read_bytes()
        raw_b = build_b_path.read_bytes()
        build_a = read_manifest(build_a_path)
        build_b = read_manifest(build_b_path)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        return fail(f"cannot read reproducibility evidence: {exc}")

    if report.get("schema") != "examos.p0.reproducibility.v1":
        return fail("unknown report schema")
    if report.get("result") != "PASS" or report.get("release_eligible") is not True:
        return fail("report does not declare release-eligible PASS")
    if report.get("mode") != "image" or report.get("source_tree_state") != "CLEAN":
        return fail("report is not from a clean image reproducibility run")
    if report.get("source_commit") != expected_commit:
        return fail("report commit differs from the canonical P0 commit")
    if report.get("source_date_epoch") != int(expected_epoch):
        return fail("report source-date epoch differs from the source commit timestamp")
    if not build_a or build_a != build_b or raw_a != raw_b:
        return fail("two build manifests are empty or differ")
    if build_a != report.get("build_a") or build_b != report.get("build_b"):
        return fail("report manifest entries differ from manifest files")
    if len(build_a) != 1 or build_a[0]["label"] != "p0-disk":
        return fail("expected exactly one P0 disk artifact in each build")
    if hashlib.sha256(raw_a).hexdigest() != report.get("build_a_manifest_sha256"):
        return fail("build A manifest digest mismatch")
    if hashlib.sha256(raw_b).hexdigest() != report.get("build_b_manifest_sha256"):
        return fail("build B manifest digest mismatch")
    evidence_root = report_path.resolve().parent
    for name, expected in (("build_a_image", "build-a.raw"), ("build_b_image", "build-b.raw")):
        artifact = report.get(name)
        if not isinstance(artifact, dict) or artifact.get("path") != expected:
            return fail(f"{name} path is missing or is not run-relative")
        image_path = evidence_root / expected
        try:
            image_path.resolve(strict=True).relative_to(evidence_root)
            image_bytes = image_path.read_bytes()
        except (OSError, ValueError) as exc:
            return fail(f"cannot read retained {name} artifact: {exc}")
        if image_path.is_symlink():
            return fail(f"retained {name} artifact must not be a symlink")
        if hashlib.sha256(image_bytes).hexdigest() != artifact.get("sha256"):
            return fail(f"retained {name} artifact digest differs from the report")
        if len(image_bytes) != artifact.get("size_bytes"):
            return fail(f"retained {name} artifact size differs from the report")
        expected_hash = build_a[0]["sha256"] if name == "build_a_image" else build_b[0]["sha256"]
        if artifact.get("sha256") != expected_hash:
            return fail(f"retained {name} digest differs from its manifest")
    print("[P0-REPRO-VALIDATE] PASS: report, source commit, retained images, and manifests are bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
