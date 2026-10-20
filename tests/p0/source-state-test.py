#!/usr/bin/env python3
"""Regression test: generated outputs are ignored, tracked edits are not."""
import json
import pathlib
import subprocess
import sys
import tempfile


def run(*args: str, cwd: pathlib.Path) -> None:
    subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.DEVNULL)


def main() -> int:
    workspace = pathlib.Path(__file__).resolve().parents[2]
    checker = workspace / "scripts" / "source-state.py"
    with tempfile.TemporaryDirectory(prefix="examos-source-state-test-") as temp:
        root = pathlib.Path(temp)
        run("git", "init", cwd=root)
        run("git", "config", "user.email", "source-state-test@example.invalid", cwd=root)
        run("git", "config", "user.name", "Source State Test", cwd=root)
        artifact = root / "artifacts" / "p0" / "historical.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("baseline\n", encoding="utf-8")
        run("git", "add", "artifacts/p0/historical.json", cwd=root)
        run("git", "commit", "-m", "baseline", cwd=root)

        artifact.write_text("modified historical evidence\n", encoding="utf-8")
        generated = root / "artifacts" / "p0" / "runs" / "run-fixture" / "boot.log"
        generated.parent.mkdir(parents=True)
        generated.write_text("generated run output\n", encoding="utf-8")
        source = root / "tests" / "new-test.sh"
        source.parent.mkdir()
        source.write_text("#!/bin/sh\n", encoding="utf-8")

        output = subprocess.check_output(
            [sys.executable, str(checker), str(root)], text=True
        )
        report = json.loads(output)
        paths = {item["path"] for item in report["changes"]}
        if report["state"] != "DIRTY" or report["dirty_path_count"] != 2:
            raise AssertionError(f"unexpected source report: {report}")
        if "artifacts/p0/historical.json" not in paths or "tests/new-test.sh" not in paths:
            raise AssertionError(f"tracked edits or source files were hidden: {paths}")
        if any(path.startswith("artifacts/p0/runs/") for path in paths):
            raise AssertionError(f"generated run output was counted as source: {paths}")
    print("PASS: tracked evidence edits and source changes count; generated run output is excluded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
