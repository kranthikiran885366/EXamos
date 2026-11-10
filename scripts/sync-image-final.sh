#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="/mnt/d/SEB BRO"
RAW_IMG="$WORKSPACE/image/examos.raw"

echo "=== Syncing Clean Filesystem and Service Units to Image ==="

LOOPDEV=$(sudo losetup -fP --show "$RAW_IMG")
trap 'sudo umount /mnt/examos_esp /mnt/examos_root 2>/dev/null || true; sudo losetup -d "$LOOPDEV" 2>/dev/null || true' EXIT

sudo mkdir -p /mnt/examos_esp /mnt/examos_root
sudo mount "${LOOPDEV}p1" /mnt/examos_esp
sudo mount "${LOOPDEV}p2" /mnt/examos_root

# Install binaries
sudo install -d /mnt/examos_root/usr/local/bin
sudo install -m 755 "$WORKSPACE/server/examos-server" /mnt/examos_root/usr/local/bin/
sudo install -m 755 "$WORKSPACE/server/examos-db-migrate" /mnt/examos_root/usr/local/bin/
sudo install -D -m 755 "$WORKSPACE/image/scripts/tpm-seal-secrets.sh" /mnt/examos_root/usr/local/sbin/tpm-seal-secrets.sh
sudo install -D -m 755 "$WORKSPACE/scripts/setup-postgres-tls.sh" /mnt/examos_root/usr/local/sbin/examos-setup-postgres-tls
sudo install -D -m 755 "$WORKSPACE/scripts/provision-remote-postgres.sh" /mnt/examos_root/usr/local/sbin/examos-provision-remote-postgres
sudo install -d /mnt/examos_root/usr/share/examos/migrations
sudo install -m 644 "$WORKSPACE"/server/migrations/*.sql /mnt/examos_root/usr/share/examos/migrations/
sudo install -m 755 "$WORKSPACE/agent/examos-agent" /mnt/examos_root/usr/local/bin/
sudo install -m 755 "$WORKSPACE/kiosk/launcher/examos-kiosk-launcher" /mnt/examos_root/usr/local/bin/
sudo install -m 755 "$WORKSPACE/proctoring/examos-proctor" /mnt/examos_root/usr/local/bin/

# Install configs
sudo mkdir -p /mnt/examos_root/etc/examos
sudo touch /mnt/examos_root/etc/examos/proctor.env
sudo chmod 640 /mnt/examos_root/etc/examos/proctor.env

# Install updated service files
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-server.service" /mnt/examos_root/etc/systemd/system/
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-agent.service" /mnt/examos_root/etc/systemd/system/
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service" /mnt/examos_root/etc/systemd/system/
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-proctor.service" /mnt/examos_root/etc/systemd/system/
sudo install -m 755 "$WORKSPACE/image/overlay/usr/local/bin/examos-kiosk-readiness" /mnt/examos_root/usr/local/bin/
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk-readiness.service" /mnt/examos_root/etc/systemd/system/
sudo install -D -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf" /mnt/examos_root/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf

sudo mkdir -p /mnt/examos_root/etc/systemd/system/multi-user.target.wants
sudo ln -sf /etc/systemd/system/examos-server.service /mnt/examos_root/etc/systemd/system/multi-user.target.wants/examos-server.service
sudo ln -sf /etc/systemd/system/examos-agent.service /mnt/examos_root/etc/systemd/system/multi-user.target.wants/examos-agent.service

sudo sync
sudo umount /mnt/examos_esp /mnt/examos_root
sudo losetup -d "$LOOPDEV"

echo "=== Running e2fsck filesystem integrity check ==="
sudo losetup -fP "$RAW_IMG"
sudo e2fsck -f -y /dev/loop0p2
sudo losetup -d /dev/loop0

echo "=== Filesystem Clean & Ready ==="
