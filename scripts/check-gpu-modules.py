#!/usr/bin/env python3
import subprocess, time, os

cmd = [
    'qemu-system-x86_64',
    '-machine', 'q35,accel=kvm',
    '-cpu', 'host',
    '-m', '1024',
    '-kernel', '/mnt/d/SEB BRO/image/examos.vmlinuz',
    '-initrd', '/mnt/d/SEB BRO/image/examos.initrd',
    '-append', 'root=/dev/vda2 ro console=ttyS0 init=/bin/bash',
    '-drive', 'file=/mnt/d/SEB BRO/output/examos-flat.vmdk,format=raw,if=virtio,readonly=on',
    '-nographic',
    '-no-reboot'
]

p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
buf = b''
start = time.time()
while time.time() - start < 20:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            buf += chunk
            if b'root@localhost:' in buf:
                break
    except Exception:
        time.sleep(0.1)

cmds = [
    'echo "=== GPU MODULES ==="\n',
    'find /lib/modules -name "*.ko*" | grep -E "i915|amdgpu|xe\\.|nouveau" | head -n 15\n',
    'echo "=== FIRMWARE DIRS ==="\n',
    'ls -d /lib/firmware/* 2>/dev/null | head -n 20\n',
    'echo "=== DONE ==="\n',
    'poweroff -f\n'
]
for c in cmds:
    p.stdin.write(c.encode())
    p.stdin.flush()
    time.sleep(0.3)

out_wait = time.time()
while time.time() - out_wait < 15:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            if b'=== DONE ===' in chunk:
                break
    except Exception:
        time.sleep(0.1)

p.wait(timeout=5)
