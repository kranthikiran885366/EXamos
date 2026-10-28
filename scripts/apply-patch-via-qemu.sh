#!/usr/bin/env bash
set -e

cd "/mnt/d/SEB BRO" || exit 1

OVERLAY="/home/krant/sppio-test/examos-gui-test.qcow2"

echo "=== 1. Ensuring disposable overlay exists backed by output/examos-flat.vmdk ==="
if [ ! -f "$OVERLAY" ]; then
  qemu-img create -f qcow2 -F raw -b "$PWD/output/examos-flat.vmdk" "$OVERLAY"
fi

echo "=== 2. Creating VM in-guest patch script ==="
cat << 'IN_GUEST_EOF' > /tmp/in-guest-fix.sh
#!/bin/bash
set -x

echo "=== IN-GUEST PATCHING START ==="
mount -o remount,rw /

# 1. Mount host share if available
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host 2>/dev/null || true

# 2. Update HTML pages from repo
mkdir -p /usr/share/examos
if [ -d /mnt/host/image/overlay/usr/share/examos ]; then
  cp -rf /mnt/host/image/overlay/usr/share/examos/* /usr/share/examos/
fi
chmod 644 /usr/share/examos/*.html 2>/dev/null || true

# 3. Fix exam user & home
chown -R exam:exam /home/exam 2>/dev/null || true
mkdir -p /home/exam/.config /run/user/1000
chown -R exam:exam /home/exam /run/user/1000
chmod 0700 /run/user/1000

# 4. Install updated kiosk launcher
cat << 'LAUNCHER_EOF' > /usr/local/bin/examos-kiosk-launcher
#!/bin/bash
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/1000}"
export GDK_BACKEND=wayland
export QT_QPA_PLATFORM=wayland

mkdir -p "$XDG_RUNTIME_DIR"
chown exam:exam "$XDG_RUNTIME_DIR" 2>/dev/null || true
chmod 0700 "$XDG_RUNTIME_DIR"

# Determine target URL: check exam.conf, then fallback to onboarding.html
TARGET_URL="file:///usr/share/examos/onboarding.html"
if [ -f /etc/examos/exam.conf ]; then
  CONF_URL=$(grep '^EXAM_URL=' /etc/examos/exam.conf | cut -d'=' -f2 | tr -d ' \r\n')
  if [ -n "$CONF_URL" ]; then
    TARGET_URL="$CONF_URL"
  fi
fi

# Allow command line override
if [ -n "$1" ]; then
  TARGET_URL="$1"
fi

echo "[ExamOS-Launcher] Launching target: $TARGET_URL"

# Ephemeral user profile
PROFILE_DIR=$(mktemp -d /tmp/examos_kiosk_XXXXXX)
chown -R exam:exam "$PROFILE_DIR" 2>/dev/null || true

trap "rm -rf $PROFILE_DIR" EXIT INT TERM

exec /usr/lib/chromium/chromium \
  --kiosk \
  --no-first-run \
  --no-default-browser-check \
  --ozone-platform=wayland \
  --enable-features=UseOzonePlatform \
  --disable-gpu \
  --disable-software-rasterizer \
  --user-data-dir="$PROFILE_DIR" \
  --app="$TARGET_URL"
LAUNCHER_EOF
chmod 755 /usr/local/bin/examos-kiosk-launcher

# 5. Write corrected examos-kiosk.service
cat << 'SERVICE_EOF' > /etc/systemd/system/examos-kiosk.service
[Unit]
Description=ExamOS Secure Examination Kiosk Desktop
After=network.target sound.target systemd-user-sessions.service
Conflicts=getty@tty1.service

[Service]
Type=simple
User=exam
Group=exam
SupplementaryGroups=video audio input render
TTYPath=/dev/tty1
StandardInput=tty
StandardOutput=journal+console
StandardError=journal+console
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes

Environment=XDG_RUNTIME_DIR=/run/user/1000
Environment=WLR_LIBINPUT_NO_DEVICES=1
Environment=WLR_RENDERER=pixman
Environment=WLR_NO_HARDWARE_CURSORS=1
Environment=LIBSEAT_BACKEND=builtin
Environment=XDG_SESSION_TYPE=wayland

ExecStartPre=/usr/bin/mkdir -p /run/user/1000
ExecStartPre=+/usr/bin/chown exam:exam /run/user/1000
ExecStartPre=+/usr/bin/chmod 0700 /run/user/1000
ExecStart=/usr/bin/cage -s -- /usr/local/bin/examos-kiosk-launcher
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=graphical.target multi-user.target
SERVICE_EOF

# Enable the service
systemctl enable examos-kiosk.service 2>/dev/null || true

# 6. Ensure root can login on tty2 for diagnostics
mkdir -p /etc/systemd/system/getty@tty2.service.d
cat << 'GETTY_EOF' > /etc/systemd/system/getty@tty2.service.d/override.conf
[Service]
ExecStart=
ExecStart=-/bin/bash
StandardInput=tty
StandardOutput=tty
GETTY_EOF

sync
echo "=== IN-GUEST PATCHING COMPLETE ==="
poweroff -f
IN_GUEST_EOF
chmod 755 /tmp/in-guest-fix.sh

echo "=== 3. Executing patch inside VM via QEMU direct kernel boot ==="
qemu-system-x86_64 \
  -machine q35,accel=kvm \
  -cpu host \
  -m 2048 \
  -kernel "/mnt/d/SEB BRO/image/examos.vmlinuz" \
  -initrd "/mnt/d/SEB BRO/image/examos.initrd" \
  -append "root=/dev/vda2 rw console=ttyS0 init=/bin/bash" \
  -drive file="$OVERLAY",format=qcow2,if=virtio \
  -virtfs local,path="/mnt/d/SEB BRO",mount_tag=hostshare,security_model=none \
  -nographic \
  -no-reboot < /tmp/in-guest-fix.sh

echo "=== 4. Overlay successfully patched! ==="
