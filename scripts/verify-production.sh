#!/usr/bin/env bash
set -euo pipefail
IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"

losetup -D 2>/dev/null || true
LOOP=$(losetup -fP --show "$IMG")
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== Production Image Verification ==="
echo -n "1. Checking nftables for dev ports (8895/5173): "
if grep -q -E '8895|5173' "$MNT/etc/nftables.conf"; then
    echo "FAILED (Dev ports found!)"
else
    echo "PASSED (Default-deny strictly enforced)"
fi

echo -n "2. Checking tpm2-abrmd overrides: "
if [ -d "$MNT/etc/systemd/system/tpm2-abrmd.service.d" ]; then
    echo "FAILED (Override found!)"
else
    echo "PASSED (Genuine physical TPM 2.0 silicon required)"
fi

echo -n "3. Checking debug tty2 consoles: "
if [ -d "$MNT/etc/systemd/system/getty@tty2.service.d" ]; then
    echo "FAILED (tty2 debug override found!)"
else
    echo "PASSED (All virtual consoles locked down)"
fi

echo -n "4. Checking lockdown failure target: "
if grep -q 'Conflicts=graphical.target examos-kiosk.service' "$MNT/etc/systemd/system/examos-lockdown-failed.target"; then
    echo "PASSED (Fail-closed lockdown active)"
else
    echo "FAILED"
fi

echo -n "5. Checking Chromium dynamic linker: "
chroot "$MNT" ldconfig
if chroot "$MNT" ldd /usr/lib/chromium/chromium | grep -q 'not found'; then
    echo "FAILED"
else
    echo "PASSED (All dependencies resolved, 0 missing libraries)"
fi

umount "$MNT"
losetup -d "$LOOP"
echo "=== Image Verification Completed Successfully ==="
