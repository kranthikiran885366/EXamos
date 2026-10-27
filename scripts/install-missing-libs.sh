#!/usr/bin/env bash
set -euo pipefail

IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"
DL_DIR="/tmp/trixie-debs"

echo "=== 1. Downloading required Debian packages ==="
rm -rf "$DL_DIR"
mkdir -p "$DL_DIR"
cd "$DL_DIR"

URL1="http://deb.debian.org/debian/pool/main/o/openh264/libopenh264-8_2.6.0+dfsg-2_amd64.deb"
URL2="http://deb.debian.org/debian/pool/main/libj/libjpeg-turbo/libjpeg62-turbo_3.1.3-4_amd64.deb"
URL3="http://deb.debian.org/debian/pool/main/h/harfbuzz/libharfbuzz-subset0_12.3.2-2+b2_amd64.deb"

echo "Downloading libopenh264-8..."
curl -s -L -o openh264.deb "$URL1"
echo "Downloading libjpeg62-turbo..."
curl -s -L -o libjpeg.deb "$URL2"
echo "Downloading libharfbuzz-subset0..."
curl -s -L -o harfbuzz.deb "$URL3"

echo "=== 2. Mounting target rootfs ==="
losetup -D
LOOP=$(losetup -fP --show "$IMG")
echo "Attached: $LOOP"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== 3. Extracting libraries into rootfs ==="
dpkg-deb -x openh264.deb "$MNT/"
dpkg-deb -x libjpeg.deb "$MNT/"
dpkg-deb -x harfbuzz.deb "$MNT/"

echo "=== 4. Updating ldconfig cache ==="
chroot "$MNT" ldconfig 2>/dev/null || true

echo "=== 5. Copying updated kiosk launcher ==="
cp -f "/mnt/d/SEB BRO/kiosk/launcher/examos-kiosk-launcher" "$MNT/usr/local/bin/examos-kiosk-launcher"
chmod 755 "$MNT/usr/local/bin/examos-kiosk-launcher"

echo "=== 6. Verifying all Chromium libraries ==="
MISSING=$(chroot "$MNT" ldd /usr/lib/chromium/chromium 2>&1 | grep "not found" || true)
if [ -n "$MISSING" ]; then
    echo "WARNING: Still missing libraries:"
    echo "$MISSING"
else
    echo "SUCCESS: ALL Chromium libraries are 100% resolved!"
fi

echo "=== 7. Testing launcher execution in chroot ==="
timeout 3 chroot "$MNT" /usr/local/bin/examos-kiosk-launcher 2>&1 || true

sync
umount "$MNT"
losetup -d "$LOOP"
echo "=== Done! ==="
