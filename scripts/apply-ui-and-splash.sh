#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="/mnt/d/SEB BRO"
cd "$WORKSPACE"

echo "=== 1. Building Native Subsystems ==="
make clean
make all

echo "=== 2. Mounting Raw Image Filesystem ==="
RAW_IMG="$WORKSPACE/image/examos.raw"
LOOPDEV=$(sudo losetup -fP --show "$RAW_IMG")
trap 'sudo umount /mnt/examos_rw 2>/dev/null || true; sudo losetup -d "$LOOPDEV" 2>/dev/null || true' EXIT

sudo mkdir -p /mnt/examos_rw
sudo mount "${LOOPDEV}p2" /mnt/examos_rw

echo "=== 3. Installing Binaries to Image ==="
sudo install -d /mnt/examos_rw/usr/local/bin
sudo install -m 755 "$WORKSPACE/server/examos-server" /mnt/examos_rw/usr/local/bin/
sudo install -m 755 "$WORKSPACE/server/examos-db-migrate" /mnt/examos_rw/usr/local/bin/
sudo install -D -m 755 "$WORKSPACE/image/scripts/tpm-seal-secrets.sh" /mnt/examos_rw/usr/local/sbin/tpm-seal-secrets.sh
sudo install -D -m 755 "$WORKSPACE/scripts/setup-postgres-tls.sh" /mnt/examos_rw/usr/local/sbin/examos-setup-postgres-tls
sudo install -D -m 755 "$WORKSPACE/scripts/provision-remote-postgres.sh" /mnt/examos_rw/usr/local/sbin/examos-provision-remote-postgres
sudo install -d /mnt/examos_rw/usr/share/examos/migrations
sudo install -m 644 "$WORKSPACE"/server/migrations/*.sql /mnt/examos_rw/usr/share/examos/migrations/
sudo install -m 755 "$WORKSPACE/agent/examos-agent" /mnt/examos_rw/usr/local/bin/
sudo install -m 755 "$WORKSPACE/kiosk/launcher/examos-kiosk-launcher" /mnt/examos_rw/usr/local/bin/
sudo install -m 755 "$WORKSPACE/proctoring/examos-proctor" /mnt/examos_rw/usr/local/bin/

echo "=== 4. Setting Up /etc/issue and /etc/motd Splash Banners ==="
cat << 'SPLASH' | sudo tee /mnt/examos_rw/etc/issue > /dev/null
\033[1;36m
  _____                         ____   _____ 
 | ____|_  ____ _ _ __ ___     / __ \ / ____|
 |  _| \ \/ / _` | '_ ` _ \   | |  | | (___  
 | |___ >  < (_| | | | | | |  | |  | |\___ \ 
 |_____/_/\_\__,_|_| |_| |_|   \____/ |_____/ 
\033[0m
\033[1;32m Secure Examination Operating System Appliance (v0.4.0)\033[0m
 \033[0;33mUEFI Measured Boot | TPM 2.0 Policy | Wayland Kiosk Mode\033[0m

 \033[1;37mCandidate Portal:\033[0m http://localhost:8000/
 \033[1;37mAdmin Dashboard:\033[0m  http://localhost:8000/admin
 \033[1;37mCredentials:\033[0m      Provisioned by the deployment authority

SPLASH

sudo cp /mnt/examos_rw/etc/issue /mnt/examos_rw/etc/motd

echo "=== 5. Setting up /etc/examos config files in Image ==="
sudo mkdir -p /mnt/examos_rw/etc/examos
sudo install -m 0640 "$WORKSPACE/image/overlay/etc/examos/candidates.conf" /mnt/examos_rw/etc/examos/candidates.conf
sudo cp "$WORKSPACE/image/overlay/etc/examos/exam.conf" /mnt/examos_rw/etc/examos/
sudo install -m 0600 "$WORKSPACE/image/overlay/etc/examos/admin.conf" /mnt/examos_rw/etc/examos/admin.conf
sudo install -m 0640 "$WORKSPACE/image/overlay/etc/examos/proctor.env" /mnt/examos_rw/etc/examos/proctor.env

echo "=== 6. Installing & Enabling systemd Service Units in Image ==="
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-server.service" /mnt/examos_rw/etc/systemd/system/
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-agent.service" /mnt/examos_rw/etc/systemd/system/
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service" /mnt/examos_rw/etc/systemd/system/

sudo mkdir -p /mnt/examos_rw/etc/systemd/system/multi-user.target.wants
sudo mkdir -p /mnt/examos_rw/etc/systemd/system/graphical.target.wants
sudo ln -sf /etc/systemd/system/examos-server.service /mnt/examos_rw/etc/systemd/system/multi-user.target.wants/examos-server.service
sudo ln -sf /etc/systemd/system/examos-agent.service /mnt/examos_rw/etc/systemd/system/multi-user.target.wants/examos-agent.service
sudo ln -sf /etc/systemd/system/examos-kiosk.service /mnt/examos_rw/etc/systemd/system/graphical.target.wants/examos-kiosk.service

sudo sync
echo "=== Image Filesystem Updated Successfully ==="
