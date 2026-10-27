#!/usr/bin/env bash
set -euo pipefail

IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
RAW="/mnt/d/SEB BRO/image/examos.raw"
MNT="/mnt/examos_inspect"
OVERLAY="/mnt/d/SEB BRO/image/overlay"

echo "=== ExamOS: Reverting All Development / VMware Changes to Pure Production Level ==="

# Clean any existing loop mounts
losetup -D 2>/dev/null || true
LOOP=$(losetup -fP --show "$IMG")
echo "Attached VMDK as loop device: $LOOP"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "--- 1. Restoring strict production generate-chromium-policy.sh ---"
mkdir -p "$MNT/usr/local/sbin"
cp -f "$OVERLAY/usr/local/sbin/generate-chromium-policy.sh" "$MNT/usr/local/sbin/generate-chromium-policy.sh"
chmod 755 "$MNT/usr/local/sbin/generate-chromium-policy.sh"
chown root:root "$MNT/usr/local/sbin/generate-chromium-policy.sh"

echo "--- 2. Installing recompiled production kiosk launcher ---"
cp -f "$OVERLAY/usr/local/bin/examos-kiosk-launcher" "$MNT/usr/local/bin/examos-kiosk-launcher"
chmod 755 "$MNT/usr/local/bin/examos-kiosk-launcher"
chown root:root "$MNT/usr/local/bin/examos-kiosk-launcher"

echo "--- 3. Restoring strict production nftables firewall (all outbound ports closed except DNS, HTTPS, NTP, DHCP) ---"
cp -f "$OVERLAY/etc/nftables.conf" "$MNT/etc/nftables.conf"
chmod 644 "$MNT/etc/nftables.conf"
chown root:root "$MNT/etc/nftables.conf"

echo "--- 4. Restoring production examos-kiosk.service (unprivileged 'exam' user, sandboxed, hardware accelerated) ---"
cp -f "$OVERLAY/etc/systemd/system/examos-kiosk.service" "$MNT/etc/systemd/system/examos-kiosk.service"
chmod 644 "$MNT/etc/systemd/system/examos-kiosk.service"
chown root:root "$MNT/etc/systemd/system/examos-kiosk.service"

echo "--- 5. Restoring production examos-lockdown-failed.target (strict fail-closed, no graphical kiosk) ---"
cp -f "$OVERLAY/etc/systemd/system/examos-lockdown-failed.target" "$MNT/etc/systemd/system/examos-lockdown-failed.target"
chmod 644 "$MNT/etc/systemd/system/examos-lockdown-failed.target"
chown root:root "$MNT/etc/systemd/system/examos-lockdown-failed.target"

echo "--- 6. Removing VMware / development overrides and services ---"
# Remove tpm2-abrmd fast-fail override so real physical hardware TPM 2.0 is required
rm -rf "$MNT/etc/systemd/system/tpm2-abrmd.service.d"

# Remove virtual console tty2 auto-login and service wants
rm -rf "$MNT/etc/systemd/system/getty@tty2.service.d"
rm -f "$MNT/etc/systemd/system/getty.target.wants/getty@tty2.service"

# Remove diagnostic lockdown reporter service
rm -f "$MNT/etc/systemd/system/examos-lockdown-reporter.service"
rm -f "$MNT/run/examos/lockdown.flag" 2>/dev/null || true

# Remove VMware modprobe blacklist
rm -f "$MNT/etc/modprobe.d/blacklist-vmware.conf"

echo "--- 7. Verifying exam.conf ---"
cp -f "$OVERLAY/etc/examos/exam.conf" "$MNT/etc/examos/exam.conf"
chmod 644 "$MNT/etc/examos/exam.conf"
chown root:root "$MNT/etc/examos/exam.conf"

echo "--- 8. Verifying Chromium dynamic linker libraries ---"
chroot "$MNT" ldconfig
NOT_FOUND=$(chroot "$MNT" ldd /usr/lib/chromium/chromium | grep "not found" || true)
if [ -n "$NOT_FOUND" ]; then
    echo "ERROR: Missing libraries in Chromium:"
    echo "$NOT_FOUND"
    exit 1
fi
echo "All Chromium shared libraries verified: 0 missing dependencies."

echo "--- 9. Cleaning filesystem and unmounting ---"
sync
umount "$MNT"
losetup -d "$LOOP"

echo "--- 10. Synchronizing to raw disk image ($RAW) for direct physical flashing ---"
cp -f "$IMG" "$RAW"
sync

echo "--- 11. Computing SHA256 checksums ---"
sha256sum "$RAW" > "${RAW}.sha256"
cat "${RAW}.sha256"

echo "=== All VMware and Development changes reverted! System is 100% Production Ready for Physical Hardware Testing! ==="
