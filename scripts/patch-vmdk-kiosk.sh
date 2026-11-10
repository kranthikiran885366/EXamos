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
cp -f "/mnt/d/SEB BRO/image/overlay/etc/systemd/system/examos-kiosk.service" \
  "$MNT/etc/systemd/system/examos-kiosk.service"
chmod 0644 "$MNT/etc/systemd/system/examos-kiosk.service"
cp -f "/mnt/d/SEB BRO/image/overlay/etc/systemd/system/examos-proctor.service" \
  "$MNT/etc/systemd/system/examos-proctor.service"
chmod 0644 "$MNT/etc/systemd/system/examos-proctor.service"
install -m 0755 "/mnt/d/SEB BRO/image/overlay/usr/local/bin/examos-kiosk-readiness" \
  "$MNT/usr/local/bin/examos-kiosk-readiness"
install -m 0644 "/mnt/d/SEB BRO/image/overlay/etc/systemd/system/examos-kiosk-readiness.service" \
  "$MNT/etc/systemd/system/examos-kiosk-readiness.service"
install -D -m 0644 "/mnt/d/SEB BRO/image/overlay/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf" \
  "$MNT/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf"

echo "=== 3. Blacklisting problematic VMware kernel modules ==="
mkdir -p "$MNT/etc/modprobe.d"
cat << 'CONF' > "$MNT/etc/modprobe.d/blacklist-vmware.conf"
blacklist i2c_piix4
blacklist piix4_smbus
CONF

echo "=== 4. Enabling seatd service if binary exists or ensure fallback ==="
if [ ! -f "$MNT/usr/bin/seatd" ]; then
    echo "seatd binary not present; LIBSEAT_BACKEND=builtin will handle direct DRM/input access"
    rm -f "$MNT/etc/systemd/system/multi-user.target.wants/seatd.service" || true
fi

sync
umount "$MNT"
losetup -d "$LOOP"
echo "=== VMDK successfully patched and synced! ==="
