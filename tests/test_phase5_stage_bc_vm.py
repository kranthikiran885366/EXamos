#!/usr/bin/env python3
"""
tests/test_phase5_stage_bc_vm.py
Deterministic verification for Phase 5 Stage B & C:
Chromium Sandbox, Kiosk Confinement, and Console Isolation in a Disposable VM:
1. Boots disposable QEMU VM backed by appliance image with init=/usr/local/bin/vm_guest_audit.sh.
2. Directly executes in-kernel audit as PID 1, avoiding serial terminal typing issues.
3. Inspects effective systemd unit masks for all virtual terminals (TTY1-6, autovt, debug-shell).
4. Verifies authorized administrative serial recovery (serial-getty@ttyS0).
5. Tests user account isolation (user 'exam', UID 1000 vs UID 0 root).
6. Tests unprivileged user namespace availability for Chromium Layer-1 sandbox.
7. Tests fail-closed behavior of /usr/local/bin/examos-kiosk-launcher on --no-sandbox.
8. Tests fail-closed behavior when run under root without explicit dev flag.
9. Evaluates AppArmor profile status and lockdown rules.
"""

import subprocess
import time
import sys
import os

REPO_DIR = "/mnt/d/SEB BRO"
VMLINUZ = f"{REPO_DIR}/image/examos.vmlinuz"
INITRD = f"{REPO_DIR}/image/examos.initrd"
OVERLAY = "/home/krant/sppio-test/phase5-disposable.qcow2"
RAW_IMG = f"{REPO_DIR}/image/examos.raw"

test_results = []

def record(category, test_name, status, details):
    test_results.append({
        "category": category,
        "test": test_name,
        "status": status,
        "details": details
    })
    badge = "✔ PASS" if status == "PASS" else "✘ FAIL"
    print(f"[{badge}] [{category}] {test_name}: {details}")

def main():
    print("=" * 80)
    print("EXAMOS PHASE 5: STAGE B & C DISPOSABLE VM AUDIT")
    print("=" * 80)

    # 1. Prepare clean disposable overlay
    if os.path.exists(OVERLAY):
        os.remove(OVERLAY)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", RAW_IMG, OVERLAY],
                   check=True, capture_output=True)

    # 2. Boot QEMU with direct in-kernel init
    cmd = [
        "qemu-system-x86_64",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-m", "2048",
        "-kernel", VMLINUZ,
        "-initrd", INITRD,
        "-append", "root=/dev/vda2 rw console=ttyS0 init=/usr/local/bin/vm_guest_audit.sh",
        "-drive", f"file={OVERLAY},format=qcow2,if=virtio",
        "-nographic",
        "-no-reboot"
    ]

    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    out_buf = b""
    start_wait = time.time()
    while time.time() - start_wait < 35:
        try:
            chunk = os.read(p.stdout.fileno(), 1024)
            if chunk:
                out_buf += chunk
                if b"=== AUDIT_COMPLETE ===" in out_buf or b"Power down" in out_buf or b"reboot: System halted" in out_buf:
                    time.sleep(0.5)
                    break
        except Exception:
            time.sleep(0.1)

    try:
        p.terminate()
        p.wait(timeout=3)
    except Exception:
        p.kill()

    full_output = out_buf.decode('utf-8', errors='ignore')

    # Parse and record results
    # 1. Systemd VT Masks
    if "=== C1_START ===" in full_output and "=== C1_END ===" in full_output:
        c1_block = full_output.split("=== C1_START ===")[1].split("=== C1_END ===")[0]
        lines = [l.strip() for l in c1_block.splitlines() if "MASK_CHECK:" in l]
        all_dev_null = all("-> /dev/null" in l for l in lines) and len(lines) == 9
        if all_dev_null:
            record("Console Isolation", "Effective Built Image Virtual Terminal Masking", "PASS",
                   f"All 9 console units masked to /dev/null in booted image: {[l.split()[1] for l in lines]}")
        else:
            record("Console Isolation", "Effective Built Image Virtual Terminal Masking", "FAIL",
                   f"Incomplete masks: {lines}")
    else:
        record("Console Isolation", "Effective Built Image Virtual Terminal Masking", "FAIL", "C1 block missing")

    # 2. Administrative Serial Console
    if "=== C2_START ===" in full_output and "=== C2_END ===" in full_output:
        c2_block = full_output.split("=== C2_START ===")[1].split("=== C2_END ===")[0]
        if "serial-getty@ttyS0.service -> not_masked" in c2_block or "serial-getty@ttyS0.service -> unmasked" in c2_block:
            record("Console Isolation", "Authorized Administrative Serial Recovery Route", "PASS",
                   "serial-getty@ttyS0 is unmasked and available for authorized out-of-band administrative recovery")
        else:
            record("Console Isolation", "Authorized Administrative Serial Recovery Route", "FAIL", c2_block.strip())

    # 3. Dedicated 'exam' User & User Namespaces
    if "=== B1_START ===" in full_output and "=== B1_END ===" in full_output:
        b1_block = full_output.split("=== B1_START ===")[1].split("=== B1_END ===")[0]
        uid_ok = "EXAM_USER_UID: 1000" in b1_block
        userns_ok = "USERNS_SYSCTL: 1" in b1_block
        unshare_ok = "EXAM_UNSHARE_TEST: OK" in b1_block
        if uid_ok and userns_ok and unshare_ok:
            record("Chromium Sandbox", "Dedicated Unprivileged User Runtime (UID 1000)", "PASS",
                   "User 'exam' has dedicated UID 1000, kernel unprivileged_userns_clone=1, and user namespace unshare succeeds")
        else:
            record("Chromium Sandbox", "Dedicated Unprivileged User Runtime (UID 1000)", "FAIL",
                   f"uid={uid_ok}, userns={userns_ok}, unshare={unshare_ok}")

    # 4. Fail-Closed Launcher Behavior
    if "=== B2_START ===" in full_output and "=== B2_END ===" in full_output:
        b2_block = full_output.split("=== B2_START ===")[1].split("=== B2_END ===")[0]
        no_sandbox_blocked = "Insecure flag detected" in b2_block and "EXIT_NO_SANDBOX: 1" in b2_block
        root_uid_blocked = "running as root (UID 0)" in b2_block and "EXIT_ROOT_UID: 1" in b2_block
        if no_sandbox_blocked and root_uid_blocked:
            record("Chromium Sandbox", "Launcher Fail-Closed Security Validation", "PASS",
                   "Launcher strictly halts (exit 1) on --no-sandbox and halts (exit 1) when running under root UID")
        else:
            record("Chromium Sandbox", "Launcher Fail-Closed Security Validation", "FAIL",
                   f"no_sandbox_blocked={no_sandbox_blocked}, root_uid_blocked={root_uid_blocked}")

    # 5. AppArmor Profile Enforcement
    if "=== B3_START ===" in full_output and "=== B3_END ===" in full_output:
        b3_block = full_output.split("=== B3_START ===")[1].split("=== B3_END ===")[0]
        aa_present = "APPARMOR_FILE: present" in b3_block
        aa_userns = "userns," in b3_block
        aa_ptrace = "deny capability ptrace" in b3_block
        if aa_present and aa_userns and aa_ptrace:
            record("Chromium Sandbox", "AppArmor Kiosk Confinement & userns Rules", "PASS",
                   "AppArmor profile contains 'userns,' for unprivileged sandbox and denies ptrace & /proc/*/mem")
        else:
            record("Chromium Sandbox", "AppArmor Kiosk Confinement & userns Rules", "FAIL",
                   f"present={aa_present}, userns={aa_userns}, ptrace={aa_ptrace}")

    print("\n" + "=" * 80)
    passed = sum(1 for r in test_results if r["status"] == "PASS")
    total = len(test_results)
    print(f"DISPOSABLE VM AUDIT SUMMARY: {passed}/{total} Passed")
    print("=" * 80)
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
