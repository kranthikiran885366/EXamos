#!/usr/bin/env python3
import subprocess
import time
import sys
import os

repo_dir = "/mnt/d/SEB BRO"
overlay = "/home/krant/sppio-test/examos-gui-test.qcow2"
vmlinuz = f"{repo_dir}/image/examos.vmlinuz"
initrd = f"{repo_dir}/image/examos.initrd"
vmdk = f"{repo_dir}/output/examos-flat.vmdk"

cmd = [
    "qemu-system-x86_64",
    "-machine", "q35,accel=kvm",
    "-cpu", "host",
    "-m", "2048",
    "-kernel", vmlinuz,
    "-initrd", initrd,
    "-append", "root=/dev/vda2 rw console=ttyS0 init=/bin/bash",
    "-drive", f"file={overlay},format=qcow2,if=virtio",
    "-device", "virtio-vga",
    "-nographic",
    "-no-reboot"
]

print("=== 1. Spawning QEMU with virtio-vga & bash shell ===")
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

buf = b""
print("=== 2. Waiting for root@localhost prompt ===")
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

test_commands = [
    "mount -o remount,rw /\n",
    "ls -la /etc/systemd/system/examos-kiosk.service /etc/systemd/system/graphical.target.wants/examos-kiosk.service\n",
    "cat /etc/systemd/system/examos-kiosk.service\n",
    "ls -ld /home/exam /run/user/1000 /usr/share/examos/onboarding.html /usr/local/bin/examos-kiosk-launcher\n",
    "mkdir -p /run/user/1000 && chown -R exam:exam /run/user/1000 && chmod 0700 /run/user/1000\n",
    "echo '--- TESTING CAGE EXECUTION AS ROOT ---'\n",
    "WLR_RENDERER=pixman WLR_NO_HARDWARE_CURSORS=1 WLR_LIBINPUT_NO_DEVICES=1 LIBSEAT_BACKEND=builtin XDG_RUNTIME_DIR=/run/user/1000 /usr/bin/cage -s -- echo 'CAGE_STARTED_SUCCESSFULLY'\n",
    "echo '--- TESTING CAGE EXECUTION AS EXAM USER ---'\n",
    "su -s /bin/bash exam -c 'WLR_RENDERER=pixman WLR_NO_HARDWARE_CURSORS=1 WLR_LIBINPUT_NO_DEVICES=1 LIBSEAT_BACKEND=builtin XDG_RUNTIME_DIR=/run/user/1000 /usr/bin/cage -s -- echo CAGE_AS_EXAM_SUCCESS'\n",
    "echo '=== ALL DIAGNOSTICS COMPLETED ==='\n",
    "poweroff -f\n"
]

print("=== 3. Sending test commands ===")
for cmd_str in test_commands:
    p.stdin.write(cmd_str.encode('utf-8'))
    p.stdin.flush()
    time.sleep(0.3)

start_wait = time.time()
while time.time() - start_wait < 30:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            if b"=== ALL DIAGNOSTICS COMPLETED ===" in chunk:
                break
    except Exception:
        time.sleep(0.1)

p.wait(timeout=15)
print(f"\nQEMU exited with code {p.returncode}")
