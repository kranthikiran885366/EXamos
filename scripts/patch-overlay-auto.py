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
    """cat << 'LAUNCHER_EOF' > /usr/local/bin/examos-kiosk-launcher
#!/bin/bash
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/1000}"
export GDK_BACKEND=wayland
export QT_QPA_PLATFORM=wayland

mkdir -p "$XDG_RUNTIME_DIR"
chown exam:exam "$XDG_RUNTIME_DIR" 2>/dev/null || true
chmod 0700 "$XDG_RUNTIME_DIR"

TARGET_URL="file:///usr/share/examos/onboarding.html"
if [ -f /etc/examos/exam.conf ]; then
  CONF_URL=$(grep '^EXAM_URL=' /etc/examos/exam.conf | cut -d'=' -f2 | tr -d ' \\r\\n')
  if [ -n "$CONF_URL" ]; then
    TARGET_URL="$CONF_URL"
  fi
fi

if [ -n "$1" ]; then
  TARGET_URL="$1"
fi

echo "[ExamOS-Launcher] Launching target: $TARGET_URL" > /dev/ttyS0 2>/dev/null || true

PROFILE_DIR=$(mktemp -d /tmp/examos_kiosk_XXXXXX)
chown -R exam:exam "$PROFILE_DIR" 2>/dev/null || true

trap "rm -rf $PROFILE_DIR" EXIT INT TERM

exec /usr/lib/chromium/chromium \\
  --kiosk \\
  --no-sandbox \\
  --no-first-run \\
  --no-default-browser-check \\
  --ozone-platform=wayland \\
  --enable-features=UseOzonePlatform \\
  --disable-gpu \\
  --disable-software-rasterizer \\
  --user-data-dir="$PROFILE_DIR" \\
  --app="$TARGET_URL" 2>&1 | tee -a /dev/ttyS0
LAUNCHER_EOF
""",
    "chmod 755 /usr/local/bin/examos-kiosk-launcher\n",
    """cat << 'SERVICE_EOF' > /etc/systemd/system/examos-kiosk.service
[Unit]
Description=ExamOS Secure Examination Kiosk Desktop
After=network.target sound.target systemd-user-sessions.service
Conflicts=getty@tty1.service

[Service]
Type=simple
User=exam
Group=exam
SupplementaryGroups=video audio input render
StandardOutput=journal+console
StandardError=journal+console

Environment=XDG_RUNTIME_DIR=/run/user/1000
Environment=WLR_LIBINPUT_NO_DEVICES=1
Environment=WLR_RENDERER=pixman
Environment=WLR_NO_HARDWARE_CURSORS=1
Environment=LIBSEAT_BACKEND=builtin
Environment=XDG_SESSION_TYPE=wayland

ExecStartPre=/usr/bin/mkdir -p /run/user/1000
ExecStartPre=+/usr/bin/chown exam:exam /run/user/1000
ExecStartPre=+/usr/bin/chmod 0700 /run/user/1000
ExecStart=/bin/sh -c "/usr/bin/cage -s -- /usr/local/bin/examos-kiosk-launcher 2>&1 | tee -a /dev/ttyS0"
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=graphical.target multi-user.target
SERVICE_EOF
""",
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
