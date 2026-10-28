#!/usr/bin/env python3
import subprocess
import time
import sys
import os

repo_dir = "/mnt/d/SEB BRO"
overlay = "/home/krant/sppio-test/examos-gui-test.qcow2"
vmlinuz = f"{repo_dir}/image/examos.vmlinuz"
initrd = f"{repo_dir}/image/examos.initrd"

cmd = [
    "qemu-system-x86_64",
    "-machine", "q35,accel=kvm",
    "-cpu", "host",
    "-m", "2048",
    "-kernel", vmlinuz,
    "-initrd", initrd,
    "-append", "root=/dev/vda2 rw console=ttyS0 init=/bin/bash",
    "-drive", f"file={overlay},format=qcow2,if=virtio",
    "-nographic",
    "-no-reboot"
]

print("=== 1. Spawning QEMU to read persistent journal ===")
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

buf = b""
print("=== 2. Waiting for root prompt ===")
start = time.time()
while time.time() - start < 30:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            buf += chunk
            if b"root@localhost:/" in buf or b"root@localhost:~" in buf:
                print("\n>>> ROOT PROMPT DETECTED! <<<")
                break
    except Exception:
        time.sleep(0.1)

time.sleep(0.5)

cmds = [
    "journalctl -u examos-kiosk -n 80 --no-pager\n",
    "echo '=== JOURNAL_READ_END ==='\n",
    "poweroff -f\n"
]

for c in cmds:
    p.stdin.write(c.encode('utf-8'))
    p.stdin.flush()
    time.sleep(0.3)

start_wait = time.time()
while time.time() - start_wait < 25:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            if b"=== JOURNAL_READ_END ===" in chunk:
                break
    except Exception:
        time.sleep(0.1)

p.wait(timeout=15)
print(f"\nExited with code {p.returncode}")
