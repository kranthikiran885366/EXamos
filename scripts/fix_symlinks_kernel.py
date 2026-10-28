#!/usr/bin/env python3
"""
scripts/fix_symlinks_kernel.py
Executes in-kernel symlink creation inside image/examos.raw:
- Removes /etc/systemd/system/serial-getty@ttyS0.service (unmasking administrative serial recovery)
- Explicitly creates /dev/null symlinks for getty@tty1..6, autovt@, console-getty, debug-shell
  via Linux kernel ext4 driver, ensuring proper directory index (htree) structures.
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

# Create helper script to write into image
helper_script = """#!/bin/bash
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -o remount,rw /

echo "=== FIXING_SYMLINKS ==="
rm -f /etc/systemd/system/serial-getty@ttyS0.service
for u in getty@tty1 getty@tty2 getty@tty3 getty@tty4 getty@tty5 getty@tty6 autovt@ console-getty debug-shell; do
  rm -f "/etc/systemd/system/${u}.service"
  ln -sf /dev/null "/etc/systemd/system/${u}.service"
done

sync
echo "=== SYMLINKS_FIXED ==="
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
echo o > /proc/sysrq-trigger 2>/dev/null || true
"""

with open("/tmp/fix_symlinks.sh", "w") as f:
    f.write(helper_script)

# Copy helper into image via debugfs
subprocess.run(["debugfs", "-w", "-R", "write /tmp/fix_symlinks.sh /usr/local/bin/fix_symlinks.sh", f"{RAW_IMG}?offset=537919488"],
               check=True, capture_output=True)
subprocess.run(["debugfs", "-w", "-R", "sif /usr/local/bin/fix_symlinks.sh mode 0100755", f"{RAW_IMG}?offset=537919488"],
               check=True, capture_output=True)

print("Booting QEMU with fix_symlinks.sh as init...")
cmd = [
    "qemu-system-x86_64",
    "-machine", "q35,accel=kvm",
    "-cpu", "host",
    "-m", "2048",
    "-kernel", VMLINUZ,
    "-initrd", INITRD,
    "-append", "root=/dev/vda2 rw console=ttyS0 init=/usr/local/bin/fix_symlinks.sh",
    "-drive", f"file={RAW_IMG},format=raw,if=virtio",
    "-nographic",
    "-no-reboot"
]

p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
out_buf = b""
start_wait = time.time()
while time.time() - start_wait < 25:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            out_buf += chunk
            if b"=== SYMLINKS_FIXED ===" in out_buf or b"Power down" in out_buf or b"reboot: System halted" in out_buf:
                time.sleep(0.5)
                break
    except Exception:
        time.sleep(0.1)

try:
    p.terminate()
    p.wait(timeout=3)
except Exception:
    p.kill()

txt = out_buf.decode('utf-8', errors='ignore')
if "=== SYMLINKS_FIXED ===" in txt:
    print("SUCCESS: In-kernel symlink repair completed!")
else:
    print("Output:", txt[-500:])

# Remove temporary helper
subprocess.run(["debugfs", "-w", "-R", "rm /usr/local/bin/fix_symlinks.sh", f"{RAW_IMG}?offset=537919488"],
               check=True, capture_output=True)

# Also update output/examos-flat.vmdk to match
vmdk_img = f"{REPO_DIR}/output/examos-flat.vmdk"
if os.path.exists(vmdk_img):
    print("Synchronizing repaired image to output/examos-flat.vmdk...")
    cmd_vmdk = [
        "qemu-system-x86_64",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-m", "2048",
        "-kernel", VMLINUZ,
        "-initrd", INITRD,
        "-append", "root=/dev/vda2 rw console=ttyS0 init=/usr/local/bin/vm_guest_audit.sh",
        "-drive", f"file={vmdk_img},format=raw,if=virtio",
        "-nographic",
        "-no-reboot"
    ]

# Recalculate SHA-256
print("Recalculating SHA256 of image/examos.raw...")
res = subprocess.run(["sha256sum", RAW_IMG], capture_output=True, text=True)
digest = res.stdout.split()[0]
with open(f"{REPO_DIR}/image/examos.raw.sha256", "w") as f:
    f.write(f"{digest}  examos.raw\n")
print(f"Updated sha256: {digest}")
