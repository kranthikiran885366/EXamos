#!/usr/bin/env python3
"""Exercise the intended USB policy decisions without a physical USB device.

This is deliberately a policy simulator, not USBGuard runtime evidence.  Its
output is consumed only by tests/test-only and is marked test_only=true.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable


def active_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def first_index(lines: Iterable[str], fragment: str) -> int | None:
    for index, line in enumerate(lines):
        if fragment in line:
            return index
    return None


def decision(interfaces: set[str], rules: list[str]) -> str:
    # The production policy intentionally evaluates explicit deny rules before
    # any allow rule. Match the declared interface classes, then the default
    # deny rule. This does not attempt to imitate the USBGuard daemon.
    blocked_classes = {"08", "02", "0a", "0b", "e0", "ff"}
    if interfaces & blocked_classes or "fe:01" in interfaces:
        return "block"
    if interfaces == {"03"}:
        return "allow"
    if interfaces == {"09"}:
        return "allow"
    if interfaces <= {"01", "0e"} and "0e" in interfaces:
        return "allow"
    if interfaces == {"01"} or interfaces == {"01", "03"}:
        return "allow"
    return "block"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--daemon-conf", required=True, type=Path)
    parser.add_argument("--udev-rule", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    required = (args.rules, args.daemon_conf, args.udev_rule)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        report = {
            "schema": "examos.test-only.usb-policy-simulation.v1",
            "test_only": True,
            "production_evidence": False,
            "status": "FAIL",
            "reason": "Required policy file is missing",
            "missing": missing,
        }
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 1

    rules = active_lines(args.rules)
    daemon = args.daemon_conf.read_text(encoding="utf-8")
    udev = args.udev_rule.read_text(encoding="utf-8")
    storage_block = first_index(rules, "block with-interface match-all { 08:*:* }")
    hid_allow = first_index(rules, "allow with-interface match-all { 03:*:* }")
    final_block = bool(rules) and rules[-1] == "block"
    structural_checks = {
        "storage_block_rule": storage_block is not None,
        "storage_precedes_hid_allow": storage_block is not None and hid_allow is not None and storage_block < hid_allow,
        "implicit_default_deny": "ImplicitPolicyTarget=block" in daemon,
        "terminal_block_rule": final_block,
        "udev_storage_deauthorizes": 'ATTR{bInterfaceClass}=="08"' in udev and 'ATTR{authorized}="0"' in udev,
    }
    fixtures = {
        "mass_storage": ({"08"}, "block"),
        "hid_keyboard": ({"03"}, "allow"),
        "hid_storage_composite": ({"03", "08"}, "block"),
        "camera_microphone": ({"0e", "01"}, "allow"),
        "vendor_specific": ({"ff"}, "block"),
    }
    fixture_results = []
    for name, (interfaces, expected) in fixtures.items():
        actual = decision(interfaces, rules)
        fixture_results.append({
            "fixture": name,
            "interfaces": sorted(interfaces),
            "expected": expected,
            "actual": actual,
            "status": "PASS" if actual == expected else "FAIL",
        })

    passed = all(structural_checks.values()) and all(item["status"] == "PASS" for item in fixture_results)
    report = {
        "schema": "examos.test-only.usb-policy-simulation.v1",
        "test_only": True,
        "production_evidence": False,
        "hardware_device_observed": False,
        "status": "SIMULATED_PASS" if passed else "FAIL",
        "structural_checks": structural_checks,
        "fixtures": fixture_results,
        "note": "A physical USB mass-storage test with USBGuard running remains required for release evidence.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
