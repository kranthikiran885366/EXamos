#!/usr/bin/env bash
set -euo pipefail

IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"
OVERLAY="/mnt/d/SEB BRO/image/overlay"

echo "=== Applying Full ExamOS Production & Diagnostic Fix to VMDK ==="

losetup -D
LOOP=$(losetup -fP --show "$IMG")
echo "Attached: $LOOP"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "--- 1. Installing generate-chromium-policy.sh ---"
mkdir -p "$MNT/usr/local/sbin"
cp -f "$OVERLAY/usr/local/sbin/generate-chromium-policy.sh" "$MNT/usr/local/sbin/generate-chromium-policy.sh"
chmod 755 "$MNT/usr/local/sbin/generate-chromium-policy.sh"

echo "--- 2. Installing updated kiosk launcher binary ---"
cp -f "$OVERLAY/usr/local/bin/examos-kiosk-launcher" "$MNT/usr/local/bin/examos-kiosk-launcher"
chmod 755 "$MNT/usr/local/bin/examos-kiosk-launcher"

echo "--- 3. Installing HTML Lockdown Diagnostic Screen & Guides ---"
mkdir -p "$MNT/usr/share/examos"
cp -f "$OVERLAY/usr/share/examos/lockdown_error.html" "$MNT/usr/share/examos/lockdown_error.html"
cp -f "$OVERLAY/usr/share/examos/waiting.html" "$MNT/usr/share/examos/waiting.html" 2>/dev/null || true
cp -f "$OVERLAY/usr/share/examos/onboarding.html" "$MNT/usr/share/examos/onboarding.html" 2>/dev/null || true
chmod 644 "$MNT/usr/share/examos/"*.html

echo "--- 4. Updating examos-kiosk.service ---"
cp -f "$OVERLAY/etc/systemd/system/examos-kiosk.service" \
  "$MNT/etc/systemd/system/examos-kiosk.service"
chmod 0644 "$MNT/etc/systemd/system/examos-kiosk.service"
cp -f "$OVERLAY/etc/systemd/system/examos-proctor.service" \
  "$MNT/etc/systemd/system/examos-proctor.service"
chmod 0644 "$MNT/etc/systemd/system/examos-proctor.service"
install -m 0755 "$OVERLAY/usr/local/bin/examos-kiosk-readiness" \
  "$MNT/usr/local/bin/examos-kiosk-readiness"
install -m 0644 "$OVERLAY/etc/systemd/system/examos-kiosk-readiness.service" \
  "$MNT/etc/systemd/system/examos-kiosk-readiness.service"
install -D -m 0644 "$OVERLAY/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf" \
  "$MNT/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf"

echo "--- 5. Configuring Lockdown Failure Diagnostic Display ---"
cat << 'TARGET' > "$MNT/etc/systemd/system/examos-lockdown-failed.target"
[Unit]
Description=ExamOS Mandatory Lockdown Failure — Diagnostic Display Active
Documentation=file:///etc/examos/p2-config.conf
Wants=examos-lockdown-reporter.service examos-kiosk.service
After=examos-lockdown-reporter.service
TARGET

cat << 'SERVICE' > "$MNT/etc/systemd/system/examos-lockdown-reporter.service"
[Unit]
Description=ExamOS Lockdown Failure Reporter
Before=examos-kiosk.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'mkdir -p /run/examos && touch /run/examos/lockdown.flag'
RemainAfterExit=yes

[Install]
WantedBy=examos-lockdown-failed.target
SERVICE

echo "--- 6. Blacklisting problematic SMBus driver ---"
mkdir -p "$MNT/etc/modprobe.d"
cat << 'CONF' > "$MNT/etc/modprobe.d/blacklist-vmware.conf"
blacklist i2c_piix4
blacklist piix4_smbus
CONF

echo "--- 7. Fast-fail TPM 2.0 when absent in VM, preserving full security on Hardware ---"
mkdir -p "$MNT/etc/systemd/system/tpm2-abrmd.service.d"
cat << 'CONF' > "$MNT/etc/systemd/system/tpm2-abrmd.service.d/override.conf"
[Unit]
JobTimeoutSec=5s
CONF

echo "--- 8. Initializing USBGuard rules for standard keyboard and mouse ---"
mkdir -p "$MNT/etc/usbguard"
cat << 'CONF' > "$MNT/etc/usbguard/rules.conf"
# ExamOS Base Input Authorization
allow with-interface equals { 03:*:* }
allow with-interface equals { 09:*:* }
CONF
chmod 600 "$MNT/etc/usbguard/rules.conf"

echo "--- 9. Diagnostic Auto-Login on tty2 ---"
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

sync
umount "$MNT"
losetup -d "$LOOP"
echo "=== Full Fix Successfully Applied to VMDK! ==="
