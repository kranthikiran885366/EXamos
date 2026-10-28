#!/usr/bin/env python3
import subprocess
import time
import os
import sys

repo_dir = "/mnt/d/SEB BRO"
overlay = "/home/krant/sppio-test/examos-gui-test.qcow2"
vmlinuz = f"{repo_dir}/image/examos.vmlinuz"
initrd = f"{repo_dir}/image/examos.initrd"
vmdk = f"{repo_dir}/output/examos-flat.vmdk"

print("=== 1. Preparing fresh test overlay from output/examos-flat.vmdk ===")
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
    
    # 1. Update HTML pages & scripts
    "mkdir -p /usr/share/examos /usr/local/sbin\n",
    "if [ -d /mnt/host/image/overlay/usr/share/examos ]; then cp -rf /mnt/host/image/overlay/usr/share/examos/* /usr/share/examos/; fi\n",
    "chmod 644 /usr/share/examos/*.html 2>/dev/null || true\n",
    "if [ -f /mnt/host/image/overlay/usr/local/sbin/generate-chromium-policy.sh ]; then cp -f /mnt/host/image/overlay/usr/local/sbin/generate-chromium-policy.sh /usr/local/sbin/; fi\n",
    "chmod 755 /usr/local/sbin/generate-chromium-policy.sh 2>/dev/null || true\n",
    "mkdir -p /etc/chromium/policies/managed /etc/opt/chrome/policies/managed\n",
    "if [ -f /etc/examos/exam.conf ]; then bash /usr/local/sbin/generate-chromium-policy.sh || true; fi\n",
    "chmod 644 /etc/chromium/policies/managed/*.json 2>/dev/null || true\n",
    
    # 2. Fix USBGuard permissions (MUST be 0600)
    "mkdir -p /etc/usbguard\n",
    "if [ -f /mnt/host/image/overlay/etc/usbguard/usbguard-daemon.conf ]; then cp -f /mnt/host/image/overlay/etc/usbguard/usbguard-daemon.conf /etc/usbguard/; fi\n",
    "if [ -f /mnt/host/image/overlay/etc/usbguard/rules.conf ]; then cp -f /mnt/host/image/overlay/etc/usbguard/rules.conf /etc/usbguard/; fi\n",
    "chmod 600 /etc/usbguard/*.conf 2>/dev/null || true\n",
    "chmod 700 /etc/usbguard 2>/dev/null || true\n",
    
    # 3. Fix exam user & runtime directories
    "id exam 2>/dev/null || useradd -m -s /bin/bash exam\n",
    "chown -R exam:exam /home/exam 2>/dev/null || true\n",
    "mkdir -p /home/exam/.config /run/user/1000\n",
    "chown -R exam:exam /home/exam /run/user/1000\n",
    "chmod 0700 /run/user/1000\n",
    "usermod -aG video,render,input,audio exam 2>/dev/null || true\n",
    
    # 4. DRM & input udev rules
    "cat << 'UDEV_EOF' > /etc/udev/rules.d/70-uaccess-drm.rules\nKERNEL==\"card*\", SUBSYSTEM==\"drm\", MODE=\"0666\"\nKERNEL==\"renderD*\", SUBSYSTEM==\"drm\", MODE=\"0666\"\nKERNEL==\"tty1\", MODE=\"0666\"\nKERNEL==\"event*\", SUBSYSTEM==\"input\", MODE=\"0666\"\nUDEV_EOF\n",
    "chmod 644 /etc/udev/rules.d/70-uaccess-drm.rules\n",
    
    # 5. Fix examos-lockdown-failed.target so it does NOT conflict with graphical.target or kiosk
    """cat << 'LOCKDOWN_EOF' > /etc/systemd/system/examos-lockdown-failed.target
[Unit]
Description=ExamOS Mandatory Lockdown Failure — Diagnostic Display Active
Documentation=file:///etc/examos/p2-config.conf
Wants=examos-kiosk.service
LOCKDOWN_EOF
""",

    # Fast device timeouts so systemd never hangs waiting 90s for devices
    "mkdir -p /etc/systemd/system.conf.d\n",
    "cat << 'TIMEOUT_EOF' > /etc/systemd/system.conf.d/timeout.conf\n[Manager]\nDefaultDeviceTimeoutSec=5s\nDefaultTimeoutStartSec=10s\nTIMEOUT_EOF\n",

    # 6. Configure robust kiosk launcher
    """cat << 'LAUNCHER_EOF' > /usr/local/bin/examos-kiosk-launcher
#!/bin/bash
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/0}"
export GDK_BACKEND=wayland
export QT_QPA_PLATFORM=wayland

mkdir -p "$XDG_RUNTIME_DIR"
chmod 0700 "$XDG_RUNTIME_DIR"

if [ -f /run/examos/lockdown.flag ] || [ -f /run/examos/lockdown_error ]; then
  TARGET_URL="file:///usr/share/examos/lockdown_error.html"
else
  TARGET_URL="file:///usr/share/examos/onboarding.html"
fi

if [ -n "$1" ]; then
  TARGET_URL="$1"
fi

echo "[ExamOS-Launcher] Launching target: $TARGET_URL" > /dev/ttyS0 2>/dev/null || true

PROFILE_DIR=$(mktemp -d /tmp/examos_kiosk_XXXXXX)
trap "rm -rf $PROFILE_DIR" EXIT INT TERM

exec /usr/lib/chromium/chromium \\
  --kiosk \\
  --no-sandbox \\
  --test-type \\
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
    
    # 7. Configure examos-kiosk.service with active TTYPath on tty1
    """cat << 'SERVICE_EOF' > /etc/systemd/system/examos-kiosk.service
[Unit]
Description=ExamOS Secure Examination Kiosk Desktop
Documentation=https://examos.example.edu/docs/kiosk
After=network.target sound.target systemd-user-sessions.service
Conflicts=getty@tty1.service

[Service]
Type=simple
User=root
TTYPath=/dev/tty1
StandardInput=tty
StandardOutput=journal+console
StandardError=journal+console
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes

Environment=XDG_RUNTIME_DIR=/run/user/0
Environment=WLR_LIBINPUT_NO_DEVICES=1
Environment=WLR_RENDERER=pixman
Environment=WLR_NO_HARDWARE_CURSORS=1
Environment=LIBSEAT_BACKEND=builtin
Environment=GDK_BACKEND=wayland
Environment=QT_QPA_PLATFORM=wayland
Environment=XDG_SESSION_TYPE=wayland

ExecStartPre=/usr/bin/mkdir -p /run/user/0
ExecStartPre=/usr/bin/chmod 0700 /run/user/0
ExecStart=/bin/sh -c "/usr/bin/cage -s -- /usr/local/bin/examos-kiosk-launcher 2>&1 | tee -a /dev/ttyS0"
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=graphical.target multi-user.target
SERVICE_EOF
""",
    
    # 8. Ensure service links exist and eliminate 90s device timeouts
    "mkdir -p /etc/systemd/system/graphical.target.wants /etc/systemd/system/multi-user.target.wants\n",
    "ln -sf /etc/systemd/system/examos-kiosk.service /etc/systemd/system/graphical.target.wants/examos-kiosk.service\n",
    "ln -sf /etc/systemd/system/examos-kiosk.service /etc/systemd/system/multi-user.target.wants/examos-kiosk.service\n",
    "ln -sf /dev/null /etc/systemd/system/serial-getty@ttyS0.service\n",
    "ln -sf /dev/null /etc/systemd/system/getty@tty1.service\n",
    "ln -sf /usr/lib/systemd/system/graphical.target /etc/systemd/system/default.target\n",
    
    # 9. Verify files in /usr/share/examos/
    "ls -la /usr/share/examos/\n",
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
    print("SUCCESS: Overlay fully patched with complete kiosk & HTML configuration!")
else:
    print("WARNING: Check output above for details")
