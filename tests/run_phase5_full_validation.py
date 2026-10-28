#!/usr/bin/env python3
"""
tests/run_phase5_full_validation.py
Master test runner for ExamOS / SPPIO Phase 5 Release Gate Validation & Adversarial Testing.
Runs the complete suite deterministically, recording exact commands, exit codes, and categorized inventory.
"""

import os
import subprocess
import sys
import time

SUITES = [
    ("Phase 3 E2E Workflow", "tests/test_phase3_e2e.py"),
    ("Phase 4 Security & Failures", "tests/test_phase4_security_failures.py"),
    ("Stage B & C Disposable VM Audit", "tests/test_phase5_stage_bc_vm.py"),
    ("Stage D Secure Boot & UKI Release Gates", "tests/test_phase5_stage_d_release_gates.py"),
    ("Stage E Adversarial Session Resilience", "tests/test_phase5_stage_e_resilience.py"),
    ("Session Recovery & Resilience Regression", "tests/test_session_recovery_resilience.py")
]

def main():
    print("=" * 80)
    print("EXAMOS / SPPIO PHASE 5: MASTER RELEASE GATE VALIDATION SUITE")
    print("=" * 80)

    overall_start = time.time()
    suite_results = []

    for name, script_path in SUITES:
        print(f"\n▶ RUNNING SUITE: {name} ({script_path})")
        start_t = time.time()
        p = subprocess.run([sys.executable, "-u", script_path], capture_output=True, text=True)
        dur = time.time() - start_t
        print(p.stdout)
        if p.stderr:
            print("STDERR:", p.stderr)
        status = "PASS" if p.returncode == 0 else "FAIL"
        suite_results.append({
            "name": name,
            "script": script_path,
            "rc": p.returncode,
            "duration": dur,
            "status": status,
            "output": p.stdout
        })

    print("\n" + "=" * 80)
    print("EXAMOS PHASE 5 MASTER VALIDATION SUMMARY")
    print("=" * 80)
    all_passed = True
    for s in suite_results:
        badge = "✔ PASS" if s["status"] == "PASS" else "✘ FAIL"
        if s["status"] != "PASS":
            all_passed = False
        print(f"[{badge}] {s['name']:<42} (rc={s['rc']}, time={s['duration']:.2f}s)")

    total_time = time.time() - overall_start
    print("-" * 80)
    print(f"Total Execution Time: {total_time:.2f} seconds")
    print(f"Overall Result: {'ALL SUITES PASSED' if all_passed else 'FAILURES DETECTED'}")
    print("=" * 80)

    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
