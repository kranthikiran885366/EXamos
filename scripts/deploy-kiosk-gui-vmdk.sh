#!/bin/bash
set -euo pipefail

RAW="/mnt/d/SEB BRO/image/examos.raw"
VMDK="/mnt/d/SEB BRO/image/examos.vmdk"
MNT="/mnt/examos"

echo "=== [1/5] Building all ExamOS binaries on host ==="
cd "/mnt/d/SEB BRO"
make clean || true
make all

echo "Binaries generated:"
ls -lh server/examos-server agent/examos-agent kiosk/launcher/examos-kiosk-launcher

echo "=== [2/5] Mounting RootFS ==="
sudo umount -R "$MNT" 2>/dev/null || true
sudo losetup -D 2>/dev/null || true
sleep 1

sudo losetup -fP "$RAW"
LOOP=$(losetup -j "$RAW" | head -n 1 | cut -d: -f1)
echo "Attached loop: $LOOP"

sudo mkdir -p "$MNT"
sudo mount "${LOOP}p2" "$MNT"

echo "=== [3/5] Installing Binaries & Overlay Configurations ==="
sudo cp server/examos-server "$MNT/usr/local/bin/"
sudo cp agent/examos-agent "$MNT/usr/local/bin/"
sudo cp kiosk/launcher/examos-kiosk-launcher "$MNT/usr/local/bin/"
sudo chmod 755 "$MNT/usr/local/bin/examos-"*

# Ensure exam config exists
sudo mkdir -p "$MNT/etc/examos"
cat << 'EOF' | sudo tee "$MNT/etc/examos/exam.conf" > /dev/null
EXAM_URL=http://localhost:8000
EOF
sudo chmod 644 "$MNT/etc/examos/exam.conf"

# Ensure proctor env exists
cat << 'EOF' | sudo tee "$MNT/etc/examos/proctor.env" > /dev/null
EXAMOS_SERVER_PORT=8000
EXAMOS_LEDGER_PATH=/var/log/examos/event_ledger.log
EOF
sudo chmod 644 "$MNT/etc/examos/proctor.env"

# Setup examos-kiosk.service directly on /dev/tty1
cat << 'EOF' | sudo tee "$MNT/etc/systemd/system/examos-kiosk.service" > /dev/null
[Unit]
Description=ExamOS Secure Graphical Kiosk Desktop
Documentation=https://examos.example.edu/docs/kiosk
After=network.target sound.target systemd-user-sessions.service examos-server.service
Wants=examos-server.service
Conflicts=getty@tty1.service

[Service]
Type=simple
User=root
PAMName=login
TTYPath=/dev/tty1
StandardInput=tty
StandardOutput=journal
StandardError=journal
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes

Environment=XDG_RUNTIME_DIR=/run/user/0
Environment=WAYLAND_DISPLAY=wayland-0
Environment=WLR_LIBINPUT_NO_DEVICES=0
Environment=WLR_RENDERER=auto
Environment=GDK_BACKEND=wayland
Environment=QT_QPA_PLATFORM=wayland
Environment=XDG_SESSION_TYPE=wayland

ExecStartPre=/usr/bin/mkdir -p /run/user/0
ExecStartPre=/usr/bin/chmod 0700 /run/user/0
ExecStart=/usr/bin/cage -s -- /usr/local/bin/examos-kiosk-launcher
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=graphical.target multi-user.target
EOF

# Ensure services are enabled in graphical.target and multi-user.target
sudo mkdir -p "$MNT/etc/systemd/system/graphical.target.wants"
sudo mkdir -p "$MNT/etc/systemd/system/multi-user.target.wants"

sudo ln -sf /etc/systemd/system/examos-server.service "$MNT/etc/systemd/system/multi-user.target.wants/examos-server.service"
sudo ln -sf /etc/systemd/system/examos-server.service "$MNT/etc/systemd/system/graphical.target.wants/examos-server.service"

sudo ln -sf /etc/systemd/system/examos-agent.service "$MNT/etc/systemd/system/multi-user.target.wants/examos-agent.service"
sudo ln -sf /etc/systemd/system/examos-agent.service "$MNT/etc/systemd/system/graphical.target.wants/examos-agent.service"

sudo ln -sf /etc/systemd/system/examos-kiosk.service "$MNT/etc/systemd/system/graphical.target.wants/examos-kiosk.service"
sudo ln -sf /etc/systemd/system/examos-kiosk.service "$MNT/etc/systemd/system/multi-user.target.wants/examos-kiosk.service"

# Disable getty@tty1 so cage owns tty1
sudo rm -f "$MNT/etc/systemd/system/getty.target.wants/getty@tty1.service" 2>/dev/null || true
sudo rm -rf "$MNT/etc/systemd/system/getty@tty1.service.d" 2>/dev/null || true

# Set default target to graphical.target
sudo ln -sf /usr/lib/systemd/system/graphical.target "$MNT/etc/systemd/system/default.target"

# Setup root password hash for root/root
SALT="5p.1337s4lt"
ROOT_HASH='$6$5p.1337s4lt$7.v8Ea3v40Z4Bv5aC9P8vO3Yj1q4K2fE8sL3vO3Yj1q4K2fE8sL3vO3Yj1q4K2fE8sL3vO3Yj1q4K2fE8sL3v.'
if [ -f "$MNT/etc/shadow" ]; then
    # Generate fresh SHA-512 hash of 'root'
    NEW_HASH=$(openssl passwd -6 -salt "$SALT" "root")
    sudo sed -i "s|^root:[^:]*:|root:${NEW_HASH}:|" "$MNT/etc/shadow"
fi

echo "=== [4/5] Filesystem Check ==="
sudo umount "$MNT" 2>/dev/null || true
sudo e2fsck -f -y "${LOOP}p2" || true
sudo losetup -d "$LOOP"

echo "=== [5/5] Converting raw image to VMware VMDK (monolithicFlat, lsilogic) ==="
rm -f "$VMDK" "/mnt/d/SEB BRO/image/examos-flat.vmdk"
qemu-img convert -f raw -O vmdk -o subformat=monolithicFlat,adapter_type=lsilogic,compat6 "$RAW" "$VMDK"

echo "=== SUCCESS: VMDK Generated ==="
ls -lh "$VMDK" "/mnt/d/SEB BRO/image/examos-flat.vmdk"
