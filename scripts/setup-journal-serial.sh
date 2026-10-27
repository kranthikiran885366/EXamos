#!/usr/bin/env bash
set -euo pipefail

IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"

losetup -D
LOOP=$(losetup -fP --show "$IMG")
echo "Attached: $LOOP"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== Configuring journald to forward all logs to serial ttyS0 ==="
mkdir -p "$MNT/etc/systemd/journald.conf.d"
cat << 'CONF' > "$MNT/etc/systemd/journald.conf.d/serial.conf"
[Journal]
ForwardToConsole=yes
TTYPath=/dev/ttyS0
MaxLevelConsole=debug
MaxLevelStore=debug
CONF

cat << 'CONF' > "$MNT/etc/systemd/journald.conf"
[Journal]
Storage=volatile
ForwardToConsole=yes
TTYPath=/dev/ttyS0
MaxLevelConsole=debug
CONF

echo "=== Ensuring /etc/issue prints diagnostic on tty1 ==="
echo "ExamOS Kiosk Initializing..." > "$MNT/etc/issue"

sync
umount "$MNT"
losetup -d "$LOOP"
echo "=== Done! ==="
