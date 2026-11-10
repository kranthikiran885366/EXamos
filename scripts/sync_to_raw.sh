#!/bin/bash
set -ex

RAW="/mnt/d/SEB BRO/image/examos.raw"
OVERLAY="/mnt/d/SEB BRO/image/overlay"

echo "=== Attaching loop device ==="
LOOPDEV=$(losetup -fP --show "$RAW")
echo "Loop device: $LOOPDEV"

mkdir -p /mnt/examos_root
mount "${LOOPDEV}p2" /mnt/examos_root

echo "=== Copying updated files to appliance filesystem ==="
cp -f "$OVERLAY/usr/local/bin/examos-server" /mnt/examos_root/usr/local/bin/examos-server
chmod 755 /mnt/examos_root/usr/local/bin/examos-server

cp -f "$OVERLAY/usr/share/examos/kiosk-sync.js" /mnt/examos_root/usr/share/examos/kiosk-sync.js
chmod 644 /mnt/examos_root/usr/share/examos/kiosk-sync.js

cp -f "$OVERLAY/usr/share/examos/waiting.html" /mnt/examos_root/usr/share/examos/waiting.html
chmod 644 /mnt/examos_root/usr/share/examos/waiting.html

cp -f "$OVERLAY/usr/share/examos/onboarding.html" /mnt/examos_root/usr/share/examos/onboarding.html
chmod 644 /mnt/examos_root/usr/share/examos/onboarding.html

cp -f "$OVERLAY/etc/examos/exam.conf" /mnt/examos_root/etc/examos/exam.conf
chmod 644 /mnt/examos_root/etc/examos/exam.conf

# Keep the compositor and Wayland client on the same kiosk-owned runtime directory.
install -m 0644 "$OVERLAY/etc/systemd/system/examos-kiosk.service" /mnt/examos_root/etc/systemd/system/examos-kiosk.service
install -m 0644 "$OVERLAY/etc/systemd/system/examos-proctor.service" /mnt/examos_root/etc/systemd/system/examos-proctor.service
install -m 0755 "$OVERLAY/usr/local/bin/examos-kiosk-readiness" /mnt/examos_root/usr/local/bin/examos-kiosk-readiness
install -m 0644 "$OVERLAY/etc/systemd/system/examos-kiosk-readiness.service" /mnt/examos_root/etc/systemd/system/examos-kiosk-readiness.service
install -D -m 0644 "$OVERLAY/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf" /mnt/examos_root/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf

# Ensure permanent graphical target
ln -sf /usr/lib/systemd/system/graphical.target /mnt/examos_root/etc/systemd/system/default.target
ln -sf /dev/null /mnt/examos_root/etc/systemd/system/getty@tty1.service
mkdir -p /mnt/examos_root/etc/systemd/system/graphical.target.wants
ln -sf /etc/systemd/system/examos-kiosk.service /mnt/examos_root/etc/systemd/system/graphical.target.wants/examos-kiosk.service

sync
umount /mnt/examos_root
losetup -d "$LOOPDEV"
echo "=== Appliance root filesystem successfully synchronized ==="
