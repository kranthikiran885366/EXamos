#!/usr/bin/env bash
set -euo pipefail

IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"
LAUNCHER_SRC="/mnt/d/SEB BRO/kiosk/launcher/examos-kiosk-launcher"

losetup -D
LOOP=$(losetup -fP --show "$IMG")
echo "Attached: $LOOP"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== 1. Copying updated kiosk launcher ==="
cp -f "$LAUNCHER_SRC" "$MNT/usr/local/bin/examos-kiosk-launcher"
chmod 755 "$MNT/usr/local/bin/examos-kiosk-launcher"

echo "=== 2. Updating /etc/systemd/system/examos-kiosk.service ==="
cat << 'SERVICE' > "$MNT/etc/systemd/system/examos-kiosk.service"
[Unit]
Description=ExamOS Secure Graphical Kiosk Desktop
Documentation=https://examos.example.edu/docs/kiosk
After=network.target systemd-user-sessions.service
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
Environment=WAYLAND_DISPLAY=wayland-0
Environment=WLR_LIBINPUT_NO_DEVICES=1
Environment=WLR_RENDERER=pixman
Environment=WLR_NO_HARDWARE_CURSORS=1
Environment=LIBSEAT_BACKEND=builtin
Environment=GDK_BACKEND=wayland
Environment=QT_QPA_PLATFORM=wayland
Environment=XDG_SESSION_TYPE=wayland
Environment=EXAMOS_ALLOWED_EXAM_HOSTS=staging.examos.example.edu,exam.university.edu,exam.alpha.edu,portal.beta.edu,localhost,127.0.0.1,192.168.19.1

ExecStartPre=/usr/bin/mkdir -p /run/user/0
ExecStartPre=/usr/bin/chmod 0700 /run/user/0
ExecStart=/usr/bin/cage -s -- /usr/local/bin/examos-kiosk-launcher
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=graphical.target multi-user.target
SERVICE

echo "=== 3. Blacklisting problematic VMware kernel modules ==="
mkdir -p "$MNT/etc/modprobe.d"
cat << 'CONF' > "$MNT/etc/modprobe.d/blacklist-vmware.conf"
blacklist i2c_piix4
blacklist piix4_smbus
CONF

echo "=== 4. Setting up diagnostic auto-login on tty2 ==="
mkdir -p "$MNT/etc/systemd/system/getty@tty2.service.d"
cat << 'CONF' > "$MNT/etc/systemd/system/getty@tty2.service.d/override.conf"
[Service]
ExecStart=
ExecStart=-/sbin/agetty -o '-p -- \\u' --noclear -a root tty2 linux
Type=idle
StandardInput=tty
StandardOutput=tty
TTYVTDisallocate=no
CONF

mkdir -p "$MNT/etc/systemd/system/getty.target.wants"
ln -sf /usr/lib/systemd/system/getty@.service "$MNT/etc/systemd/system/getty.target.wants/getty@tty2.service"

echo "=== 5. Enabling seatd service if binary exists or ensure fallback ==="
if [ ! -f "$MNT/usr/bin/seatd" ]; then
    echo "seatd binary not present; LIBSEAT_BACKEND=builtin will handle direct DRM/input access"
    rm -f "$MNT/etc/systemd/system/multi-user.target.wants/seatd.service" || true
fi

sync
umount "$MNT"
losetup -d "$LOOP"
echo "=== VMDK successfully patched and synced! ==="
