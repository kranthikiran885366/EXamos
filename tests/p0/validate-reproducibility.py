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
    if len(sys.argv) != 5:
        print("usage: validate-reproducibility.py REPORT BUILD_A BUILD_B COMMIT", file=sys.stderr)
        return 2
    report_path, build_a_path, build_b_path = map(pathlib.Path, sys.argv[1:4])
    expected_commit = sys.argv[4]
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
    print("[P0-REPRO-VALIDATE] PASS: report, source commit, manifests, and image digests are bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
