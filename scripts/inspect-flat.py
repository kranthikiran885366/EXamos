#!/usr/bin/env python3
import subprocess
import time
import os
import sys

cmd = [
    "qemu-system-x86_64",
    "-machine", "q35,accel=kvm",
    "-cpu", "host",
    "-m", "1024",
    "-kernel", "/mnt/d/SEB BRO/image/examos.vmlinuz",
    "-initrd", "/mnt/d/SEB BRO/image/examos.initrd",
    "-append", "root=/dev/vda2 ro console=ttyS0 init=/bin/bash",
    "-drive", "file=/mnt/d/SEB BRO/output/examos-flat.vmdk,format=raw,if=virtio,readonly=on",
    "-nographic",
    "-no-reboot"
]

p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
buf = b""
start = time.time()
while time.time() - start < 20:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            buf += chunk
            if b"root@localhost:" in buf:
                break
    except Exception:
        time.sleep(0.1)

check_cmds = [
    "echo '--- GRAPHICAL WANTS ---'\n",
    "ls -la /etc/systemd/system/graphical.target.wants/ 2>/dev/null || echo 'NONE'\n",
    "echo '--- MULTI-USER WANTS ---'\n",
    "ls -la /etc/systemd/system/multi-user.target.wants/ 2>/dev/null || echo 'NONE'\n",
    "echo '--- KIOSK SERVICE ---'\n",
    "cat /etc/systemd/system/examos-kiosk.service 2>/dev/null || echo 'NO_SERVICE'\n",
    "echo '--- KIOSK LAUNCHER ---'\n",
    "head -n 20 /usr/local/bin/examos-kiosk-launcher 2>/dev/null || echo 'NO_LAUNCHER'\n",
    "echo '--- USR SHARE EXAMOS ---'\n",
    "ls -la /usr/share/examos/ 2>/dev/null || echo 'NO_SHARE'\n",
    "echo '--- DEFAULT TARGET ---'\n",
    "ls -la /etc/systemd/system/default.target 2>/dev/null || echo 'NO_DEFAULT'\n",
    "echo '--- DONE ---'\n",
    "poweroff -f\n"
]

for c in check_cmds:
    p.stdin.write(c.encode())
    p.stdin.flush()
    time.sleep(0.3)

out, _ = p.communicate(timeout=10)
print(out.decode(errors="replace"))
