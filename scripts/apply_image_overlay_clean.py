#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import time

REPO_DIR = "/mnt/d/SEB BRO"
VMLINUZ = f"{REPO_DIR}/image/examos.vmlinuz"
INITRD = f"{REPO_DIR}/image/examos.initrd"
RAW_IMG = f"{REPO_DIR}/image/examos.raw"
PAYLOAD_DIR = "/tmp/sync_payload"
PAYLOAD_IMG = "/tmp/sync_payload.ext4"

# 1. Clean and build sync_payload
if os.path.exists(PAYLOAD_DIR):
    shutil.rmtree(PAYLOAD_DIR)
os.makedirs(f"{PAYLOAD_DIR}/overlay", exist_ok=True)
subprocess.run(["cp", "-a", f"{REPO_DIR}/image/overlay/.", f"{PAYLOAD_DIR}/overlay/"], check=True)
subprocess.run(["cp", f"{REPO_DIR}/tests/vm_guest_audit.sh", f"{PAYLOAD_DIR}/overlay/usr/local/bin/vm_guest_audit.sh"], check=True)

# Create init script
init_script = """#!/bin/bash
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

echo "=== APPLYING OVERLAY VIA LINUX KERNEL ==="
mkdir -p /mnt/root /mnt/payload
mount /dev/vdb /mnt/payload
mount /dev/vda2 /mnt/root

# Copy overlay files
cp -a /mnt/payload/overlay/* /mnt/root/

# Ensure launcher and audit script permissions
chmod 0755 /mnt/root/usr/local/bin/examos-kiosk-launcher
chmod 0755 /mnt/root/usr/local/bin/vm_guest_audit.sh

# Mask VTs and unmask serial recovery
for u in getty@tty1 getty@tty2 getty@tty3 getty@tty4 getty@tty5 getty@tty6 autovt@ console-getty debug-shell; do
  rm -f "/mnt/root/etc/systemd/system/${u}.service"
  ln -sf /dev/null "/mnt/root/etc/systemd/system/${u}.service"
done
rm -f /mnt/root/etc/systemd/system/serial-getty@ttyS0.service

sync
umount /mnt/payload
umount /mnt/root

echo "=== RUNNING E2FSCK ON REPAIRED PARTITION ==="
fsck.ext4 -f -y /dev/vda2
echo "=== FSCK COMPLETED ==="

sync
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
echo o > /proc/sysrq-trigger 2>/dev/null || true
"""

with open(f"{PAYLOAD_DIR}/init.sh", "w") as f:
    f.write(init_script)
os.chmod(f"{PAYLOAD_DIR}/init.sh", 0o755)

# Create ext4 payload image using mke2fs
if os.path.exists(PAYLOAD_IMG):
    os.remove(PAYLOAD_IMG)
subprocess.run(["mke2fs", "-q", "-t", "ext4", "-d", PAYLOAD_DIR, PAYLOAD_IMG, "100M"], check=True)

# Boot QEMU with payload image attached as vdb and init=/init.sh from vdb
print("Booting QEMU to apply overlay and repair ext4 filesystem...")
cmd = [
    "qemu-system-x86_64",
    "-machine", "q35,accel=kvm",
    "-cpu", "host",
    "-m", "2048",
    "-kernel", VMLINUZ,
    "-initrd", INITRD,
    "-append", "root=/dev/vdb rw console=ttyS0 init=/init.sh",
    "-drive", f"file={RAW_IMG},format=raw,if=virtio",
    "-drive", f"file={PAYLOAD_IMG},format=raw,if=virtio",
    "-nographic",
    "-no-reboot"
]

p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
out_buf = b""
start_time = time.time()
while time.time() - start_time < 30:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            out_buf += chunk
            if b"=== FSCK COMPLETED ===" in out_buf or b"Power down" in out_buf or b"reboot: System halted" in out_buf:
                time.sleep(0.5)
                break
    except Exception:
        time.sleep(0.1)

try:
    p.terminate()
    p.wait(timeout=3)
except Exception:
    p.kill()

print("QEMU overlay sync execution finished.")
full_log = out_buf.decode('utf-8', errors='ignore')
for line in full_log.splitlines():
    if "APPLYING OVERLAY" in line or "FSCK COMPLETED" in line or "Pass " in line or "Free " in line:
        print(line)

# Clean up temporary payload image
if os.path.exists(PAYLOAD_IMG):
    os.remove(PAYLOAD_IMG)

print("Overlay synchronization and filesystem check complete.")
