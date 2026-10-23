#!/usr/bin/env python3
"""Report repository changes without masking tracked edits or deletions.

Only untracked files under known generated-output roots are omitted. Tracked
changes under those paths remain dirty because they may be modified sources or
committed evidence and require review.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys


GENERATED_UNTRACKED_ROOTS = (
    "artifacts/",
    "image/overlay/etc/apparmor.d/",
    "image/p0/output/",
    "build/",
    "cache/",
    "server/examos-",
    "server/tests/",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("workspace", type=pathlib.Path)
    parser.add_argument("--format", choices=("json", "porcelain"), default="json")
    args = parser.parse_args()
    root = args.workspace.resolve()
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(root), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.decode("utf-8", "replace"), file=sys.stderr)
        return 2

    changes = []
    records = raw.split(b"\0")
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        status = record[:2].decode("ascii", "replace")
        path_bytes = record[3:]
        path = path_bytes.decode("utf-8", "surrogateescape").replace("\\", "/")
        # Porcelain v1 -z uses a second NUL field for the source of a rename.
        if "R" in status or "C" in status:
            if index < len(records):
                index += 1
        if status == "??" and path.startswith(GENERATED_UNTRACKED_ROOTS):
            continue
        changes.append({"status": status, "path": path})

    if args.format == "porcelain":
        for change in changes:
            print(f"{change['status']} {change['path']}")
        return 0

    report = {
        "schema": "examos.source-state.v1",
        "workspace": str(root),
        "state": "CLEAN" if not changes else "DIRTY",
        "dirty_path_count": len(changes),
        "changes": changes,
    }
    json.dump(report, sys.stdout, indent=2, ensure_ascii=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
