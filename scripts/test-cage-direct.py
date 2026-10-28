#!/usr/bin/env python3
import subprocess
import time
import os
import sys

repo_dir = "/mnt/d/SEB BRO"
overlay = "/home/krant/sppio-test/test-cage-direct.qcow2"
vmlinuz = f"{repo_dir}/image/examos.vmlinuz"
initrd = f"{repo_dir}/image/examos.initrd"
vmdk = f"{repo_dir}/output/examos-flat.vmdk"

if os.path.exists(overlay):
    os.remove(overlay)
subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", vmdk, overlay], check=True)

cmd = [
    "qemu-system-x86_64",
    "-machine", "q35,accel=kvm",
    "-cpu", "host",
    "-m", "2048",
    "-kernel", vmlinuz,
    "-initrd", initrd,
    "-append", "root=/dev/vda2 rw console=ttyS0 init=/bin/bash",
    "-drive", f"file={overlay},format=qcow2,if=virtio",
    "-vga", "virtio",
    "-qmp", "unix:/home/krant/sppio-test/qmp-direct.sock,server,nowait",
    "-display", "none",
    "-serial", "stdio",
    "-no-reboot"
]

print("=== Starting QEMU with direct bash console ===")
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

buf = b""
start = time.time()
while time.time() - start < 30:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            buf += chunk
            if b"root@localhost:/" in buf:
                print("\n>>> ROOT PROMPT DETECTED! <<<")
                break
    except Exception:
        time.sleep(0.1)

time.sleep(0.5)

test_cmds = [
    "mount -t devtmpfs devtmpfs /dev 2>/dev/null || true\n",
    "mount -t proc proc /proc 2>/dev/null || true\n",
    "mount -t sysfs sysfs /sys 2>/dev/null || true\n",
    "ls -la /dev/dri\n",
    "export XDG_RUNTIME_DIR=/run/user/0\n",
    "mkdir -p $XDG_RUNTIME_DIR\n",
    "chmod 0700 $XDG_RUNTIME_DIR\n",
    "export WLR_RENDERER=pixman\n",
    "export WLR_NO_HARDWARE_CURSORS=1\n",
    "export LIBSEAT_BACKEND=builtin\n",
    "export WLR_LIBINPUT_NO_DEVICES=1\n",
    "cage --version\n",
    "chromium --version 2>/dev/null || /usr/lib/chromium/chromium --version\n",
    # Launch cage with chromium rendering onboarding.html in background
    "/usr/bin/cage -s -- /usr/local/bin/examos-kiosk-launcher & \n",
    "sleep 6\n",
    "ps aux | grep -E 'cage|chromium'\n",
    "poweroff -f\n"
]

print("=== Running Cage test commands ===")
for c in test_cmds:
    p.stdin.write(c.encode())
    p.stdin.flush()
    time.sleep(0.5)

out_wait = time.time()
while time.time() - out_wait < 25:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
    except Exception:
        time.sleep(0.1)

p.wait(timeout=10)
print("\nTest completed.")
