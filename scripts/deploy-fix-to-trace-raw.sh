#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
LAUNCHER="/mnt/d/SEB BRO/image/overlay/usr/local/bin/examos-kiosk-launcher"
MNT="/mnt/trace_deploy"

LOOP=$(losetup -fP --show "$RAW")
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== 1. Deploy new launcher binary and service ==="
cp "$LAUNCHER" "$MNT/usr/local/bin/examos-kiosk-launcher"
chmod 755 "$MNT/usr/local/bin/examos-kiosk-launcher"
chown root:root "$MNT/usr/local/bin/examos-kiosk-launcher"
ls -la "$MNT/usr/local/bin/examos-kiosk-launcher"

READINESS="/mnt/d/SEB BRO/image/overlay/usr/local/bin/examos-kiosk-readiness"
if [ -f "$READINESS" ]; then
    cp "$READINESS" "$MNT/usr/local/bin/examos-kiosk-readiness"
    chmod 755 "$MNT/usr/local/bin/examos-kiosk-readiness"
    chown root:root "$MNT/usr/local/bin/examos-kiosk-readiness"
    ls -la "$MNT/usr/local/bin/examos-kiosk-readiness"
fi

SERVICE="/mnt/d/SEB BRO/image/overlay/etc/systemd/system/examos-kiosk.service"
cp "$SERVICE" "$MNT/etc/systemd/system/examos-kiosk.service"
chmod 644 "$MNT/etc/systemd/system/examos-kiosk.service"
chown root:root "$MNT/etc/systemd/system/examos-kiosk.service"

echo "=== 2. Restore original real Crashpad handler binary ==="
if [ -f "$MNT/usr/lib/chromium/chrome_crashpad_handler.real" ]; then
    mv -f "$MNT/usr/lib/chromium/chrome_crashpad_handler.real" "$MNT/usr/lib/chromium/chrome_crashpad_handler"
    chmod 755 "$MNT/usr/lib/chromium/chrome_crashpad_handler"
    chown root:root "$MNT/usr/lib/chromium/chrome_crashpad_handler"
fi
ls -la "$MNT/usr/lib/chromium/chrome_crashpad_handler"

echo "=== 3. Deploy updated AppArmor profile ==="
APPARMOR_SRC="/mnt/d/SEB BRO/image/overlay/etc/apparmor.d/examos-kiosk"
PROFILE="$MNT/etc/apparmor.d/examos-kiosk"
cp "$APPARMOR_SRC" "$PROFILE"
chmod 644 "$PROFILE"
chown root:root "$PROFILE"
apparmor_parser -q -p "$PROFILE"
echo "APPARMOR PROFILE VALIDATED SUCCESSFULLY"

echo "=== 4. Deploy updated sysctl security configuration ==="
SYSCTL_SRC="/mnt/d/SEB BRO/image/overlay/etc/sysctl.d/99-examos-security.conf"
SYSCTL_DST="$MNT/etc/sysctl.d/99-examos-security.conf"
cp "$SYSCTL_SRC" "$SYSCTL_DST"
chmod 644 "$SYSCTL_DST"
chown root:root "$SYSCTL_DST"
echo "SYSCTL SECURITY CONFIG DEPLOYED"

sync
umount "$MNT"
losetup -d "$LOOP"
echo "IMAGE DEPLOYMENT COMPLETED CLEANLY"
