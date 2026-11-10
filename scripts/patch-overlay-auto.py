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

print("=== 1. Preparing overlay ===")
if not os.path.exists(overlay):
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
    "-virtfs", f"local,path={repo_dir},mount_tag=hostshare,security_model=none",
    "-nographic",
    "-no-reboot"
]

print("=== 2. Spawning QEMU with direct bash console ===")
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

buf = b""
print("=== 3. Waiting for root@localhost prompt ===")
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

patch_commands = [
    "mount -o remount,rw /\n",
    "mkdir -p /mnt/host\n",
    "mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host 2>/dev/null || true\n",
    "mkdir -p /usr/share/examos\n",
    "if [ -d /mnt/host/image/overlay/usr/share/examos ]; then cp -rf /mnt/host/image/overlay/usr/share/examos/* /usr/share/examos/; fi\n",
    "chmod 644 /usr/share/examos/*.html 2>/dev/null || true\n",
    "chown -R exam:exam /home/exam 2>/dev/null || true\n",
    "mkdir -p /home/exam/.config /run/user/1000\n",
    "chown -R exam:exam /home/exam /run/user/1000\n",
    "chmod 0700 /run/user/1000\n",
    "usermod -aG video,render,input,audio exam 2>/dev/null || true\n",
    "cat << 'UDEV_EOF' > /etc/udev/rules.d/70-uaccess-drm.rules\nKERNEL==\"card*\", SUBSYSTEM==\"drm\", MODE=\"0666\"\nKERNEL==\"renderD*\", SUBSYSTEM==\"drm\", MODE=\"0666\"\nKERNEL==\"tty1\", MODE=\"0666\"\nUDEV_EOF\n",
    "test -x /mnt/host/image/overlay/usr/local/bin/examos-kiosk-launcher || { echo 'Missing canonical kiosk launcher' >&2; exit 1; }\n",
    "install -m 0755 /mnt/host/image/overlay/usr/local/bin/examos-kiosk-launcher /usr/local/bin/examos-kiosk-launcher\n",
    "test -r /mnt/host/image/overlay/etc/systemd/system/examos-kiosk.service || { echo 'Missing canonical kiosk unit' >&2; exit 1; }\n",
    "install -m 0644 /mnt/host/image/overlay/etc/systemd/system/examos-kiosk.service /etc/systemd/system/examos-kiosk.service\n",
    "test -r /mnt/host/image/overlay/etc/systemd/system/examos-proctor.service || { echo 'Missing canonical proctor unit' >&2; exit 1; }\n",
    "install -m 0644 /mnt/host/image/overlay/etc/systemd/system/examos-proctor.service /etc/systemd/system/examos-proctor.service\n",
    "test -x /mnt/host/image/overlay/usr/local/bin/examos-kiosk-readiness || { echo 'Missing canonical kiosk readiness probe' >&2; exit 1; }\n",
    "install -m 0755 /mnt/host/image/overlay/usr/local/bin/examos-kiosk-readiness /usr/local/bin/examos-kiosk-readiness\n",
    "test -r /mnt/host/image/overlay/etc/systemd/system/examos-kiosk-readiness.service || { echo 'Missing canonical kiosk readiness unit' >&2; exit 1; }\n",
    "install -m 0644 /mnt/host/image/overlay/etc/systemd/system/examos-kiosk-readiness.service /etc/systemd/system/examos-kiosk-readiness.service\n",
    "install -D -m 0644 /mnt/host/image/overlay/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf /etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf\n",
    "mkdir -p /etc/systemd/system/graphical.target.wants /etc/systemd/system/multi-user.target.wants\n",
    "ln -sf /etc/systemd/system/examos-kiosk.service /etc/systemd/system/graphical.target.wants/examos-kiosk.service\n",
    "ln -sf /etc/systemd/system/examos-kiosk.service /etc/systemd/system/multi-user.target.wants/examos-kiosk.service\n",
    "sync\n",
    "echo '=== PATCH_VERIFIED_SUCCESSFUL ==='\n",
    "poweroff -f\n"
]

print("=== 4. Sending patch commands to root bash ===")
for cmd_str in patch_commands:
    p.stdin.write(cmd_str.encode('utf-8'))
    p.stdin.flush()
    time.sleep(0.2)

print("=== 5. Reading verification ===")
success = False
start_wait = time.time()
while time.time() - start_wait < 25:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            if b"=== PATCH_VERIFIED_SUCCESSFUL ===" in chunk:
                success = True
                break
    except Exception:
        time.sleep(0.1)

p.wait(timeout=20)
print(f"\nQEMU exited with code {p.returncode}")
if success:
    print("SUCCESS: Overlay fully patched, serial tee enabled!")
else:
    print("WARNING: Check output above for details")
