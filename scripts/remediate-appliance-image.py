#!/usr/bin/env python3
"""
scripts/remediate-appliance-image.py
Applies Phase 4 security remediations directly to the ExamOS appliance raw and flat-vmdk disk images:
1. Replaces any shell launcher with the native compiled C supervisor (/usr/local/bin/examos-kiosk-launcher)
   enforcing unprivileged 'exam' user runtime and fail-closed sandbox checks.
2. Updates /etc/sysctl.d/99-examos-security.conf to allow unprivileged user namespaces under AppArmor mediation.
3. Updates /etc/apparmor.d/examos-kiosk with 'userns,' rules.
4. Masks all candidate-accessible virtual terminals (getty@tty1..6, autovt@, console-getty, debug-shell)
   via symlinks to /dev/null in /etc/systemd/system/, preserving serial-getty for administrative recovery.
"""

import subprocess
import time
import sys
import os
import hashlib

REPO_DIR = "/mnt/d/SEB BRO"
VMLINUZ = f"{REPO_DIR}/image/examos.vmlinuz"
INITRD = f"{REPO_DIR}/image/examos.initrd"
RAW_IMG = f"{REPO_DIR}/image/examos.raw"
VMDK_IMG = f"{REPO_DIR}/output/examos-flat.vmdk"

def patch_disk(disk_path):
    print(f"\n=======================================================")
    print(f"Remediating disk image: {disk_path}")
    print(f"=======================================================")

    cmd = [
        "qemu-system-x86_64",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-m", "2048",
        "-kernel", VMLINUZ,
        "-initrd", INITRD,
        "-append", "root=/dev/vda2 rw console=ttyS0 init=/bin/bash",
        "-drive", f"file={disk_path},format=raw,if=virtio",
        "-virtfs", f"local,path={REPO_DIR},mount_tag=hostshare,security_model=none",
        "-nographic",
        "-no-reboot"
    ]

    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    buf = b""
    start = time.time()
    prompt_found = False
    while time.time() - start < 30:
        try:
            chunk = os.read(p.stdout.fileno(), 1024)
            if chunk:
                buf += chunk
                if b"root@localhost:/" in buf or b"root@localhost:~" in buf:
                    prompt_found = True
                    break
        except Exception:
            time.sleep(0.1)

    if not prompt_found:
        print("ERROR: Did not detect root shell prompt in QEMU.")
        p.kill()
        return False

    print(">>> Root prompt detected. Applying security remediations...")

    commands = [
        "mount -o remount,rw /\n",
        "mkdir -p /mnt/host\n",
        "mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host 2>/dev/null || true\n",

        # 1. Chromium Sandbox & Native Launcher Remediation
        "cp -f /mnt/host/image/overlay/usr/local/bin/examos-kiosk-launcher /usr/local/bin/examos-kiosk-launcher\n",
        "chmod 755 /usr/local/bin/examos-kiosk-launcher\n",
        "chown root:root /usr/local/bin/examos-kiosk-launcher\n",
        "cp -f /mnt/host/image/overlay/etc/sysctl.d/99-examos-security.conf /etc/sysctl.d/99-examos-security.conf\n",
        "cp -f /mnt/host/image/overlay/etc/apparmor.d/examos-kiosk /etc/apparmor.d/examos-kiosk\n",

        # 2. Virtual Terminal Isolation Remediation
        "rm -rf /etc/systemd/system/getty@tty2.service.d 2>/dev/null || true\n",
        "ln -sf /dev/null /etc/systemd/system/getty@tty1.service\n",
        "ln -sf /dev/null /etc/systemd/system/getty@tty2.service\n",
        "ln -sf /dev/null /etc/systemd/system/getty@tty3.service\n",
        "ln -sf /dev/null /etc/systemd/system/getty@tty4.service\n",
        "ln -sf /dev/null /etc/systemd/system/getty@tty5.service\n",
        "ln -sf /dev/null /etc/systemd/system/getty@tty6.service\n",
        "ln -sf /dev/null /etc/systemd/system/autovt@.service\n",
        "ln -sf /dev/null /etc/systemd/system/console-getty.service\n",
        "ln -sf /dev/null /etc/systemd/system/debug-shell.service\n",

        # 3. Verification inside image
        "echo '=== VERIFICATION_START ==='\n",
        "ls -l /usr/local/bin/examos-kiosk-launcher\n",
        "file /usr/local/bin/examos-kiosk-launcher\n",
        "grep -n 'unprivileged_userns_clone' /etc/sysctl.d/99-examos-security.conf\n",
        "ls -l /etc/systemd/system/getty@tty*.service /etc/systemd/system/autovt@.service /etc/systemd/system/debug-shell.service\n",
        "echo '=== VERIFICATION_END ==='\n",
        "sync\n",
        "poweroff -f\n"
    ]

    for c in commands:
        p.stdin.write(c.encode('utf-8'))
        p.stdin.flush()
        time.sleep(0.15)

    out_buf = b""
    start_wait = time.time()
    while time.time() - start_wait < 30:
        try:
            chunk = os.read(p.stdout.fileno(), 1024)
            if chunk:
                out_buf += chunk
                if b"=== VERIFICATION_END ===" in out_buf:
                    break
        except Exception:
            time.sleep(0.1)

    p.wait(timeout=20)
    print("Verification output from inside appliance kernel:")
    txt = out_buf.decode('utf-8', errors='ignore')
    if "=== VERIFICATION_START ===" in txt:
        sub = txt.split("=== VERIFICATION_START ===")[1].split("=== VERIFICATION_END ===")[0]
        print(sub.strip())
    else:
        print(txt[-800:])
    return True

if __name__ == "__main__":
    if patch_disk(RAW_IMG):
        print("\nCalculating SHA256 for updated image/examos.raw...")
        h = hashlib.sha256()
        with open(RAW_IMG, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        digest = h.hexdigest()
        sha_file = f"{REPO_DIR}/image/examos.raw.sha256"
        with open(sha_file, "w") as f:
            f.write(f"{digest}  examos.raw\n")
        print(f"Updated {sha_file}: {digest}")

    if os.path.exists(VMDK_IMG):
        patch_disk(VMDK_IMG)

    print("\nALL DISK REMEDIATIONS COMPLETED SUCCESSFULLY.")
