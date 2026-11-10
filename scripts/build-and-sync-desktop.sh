#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="/mnt/d/SEB BRO"
cd "$WORKSPACE"

echo "=== 1. Building All Native Subsystems ==="
make clean
make all

echo "=== 2. Mounting Raw Image ==="
RAW_IMG="$WORKSPACE/image/examos.raw"
LOOPDEV=$(sudo losetup -fP --show "$RAW_IMG")
trap 'sudo umount /mnt/examos_esp /mnt/examos_root 2>/dev/null || true; sudo losetup -d "$LOOPDEV" 2>/dev/null || true' EXIT

sudo mkdir -p /mnt/examos_esp /mnt/examos_root
sudo mount "${LOOPDEV}p1" /mnt/examos_esp
sudo mount "${LOOPDEV}p2" /mnt/examos_root

echo "=== 3. Installing Rebuilt Binaries ==="
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

echo "=== 4. Setting Clean /etc/issue Banner (Clean ASCII) ==="
cat << 'ISSUE_EOF' | sudo tee /mnt/examos_root/etc/issue > /dev/null

  _____                         ____   _____ 
 | ____|_  ____ _ _ __ ___     / __ \ / ____|
 |  _| \ \/ / _` | '_ ` _ \   | |  | | (___  
 | |___ >  < (_| | | | | | |  | |  | |\___ \ 
 |_____/_/\_\__,_|_| |_| |_|   \____/ |_____/ 

 Secure Examination Operating System Appliance (v0.4.0)
 UEFI Measured Boot | TPM 2.0 Policy | Wayland Kiosk Active

 Candidate Portal: http://localhost:8000/
 Admin Dashboard:  http://localhost:8000/admin
 Credentials:      Provisioned by the deployment authority

ISSUE_EOF

sudo cp /mnt/examos_root/etc/issue /mnt/examos_root/etc/motd

echo "=== 5. Setting up Non-Looping Clean Auto-Login on tty1 ==="
sudo mkdir -p /mnt/examos_root/etc/systemd/system/getty@tty1.service.d
sudo tee /mnt/examos_root/etc/systemd/system/getty@tty1.service.d/override.conf > /dev/null << 'GETTY_CONF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I 38400 linux
Type=idle
StandardInput=tty
StandardOutput=tty
TTYVTDisallocate=no
Restart=no
GETTY_CONF

echo "=== 6. Installing & Enabling Kiosk, Server, and Agent Services ==="
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-server.service" /mnt/examos_root/etc/systemd/system/
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-agent.service" /mnt/examos_root/etc/systemd/system/
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service" /mnt/examos_root/etc/systemd/system/
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-proctor.service" /mnt/examos_root/etc/systemd/system/
sudo install -m 755 "$WORKSPACE/image/overlay/usr/local/bin/examos-kiosk-readiness" /mnt/examos_root/usr/local/bin/
sudo install -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk-readiness.service" /mnt/examos_root/etc/systemd/system/
sudo install -D -m 644 "$WORKSPACE/image/overlay/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf" /mnt/examos_root/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf

sudo ln -sf /usr/lib/systemd/system/graphical.target /mnt/examos_root/etc/systemd/system/default.target
sudo mkdir -p /mnt/examos_root/etc/systemd/system/graphical.target.wants
sudo ln -sf /etc/systemd/system/examos-server.service /mnt/examos_root/etc/systemd/system/graphical.target.wants/examos-server.service
sudo ln -sf /etc/systemd/system/examos-agent.service /mnt/examos_root/etc/systemd/system/graphical.target.wants/examos-agent.service
sudo ln -sf /etc/systemd/system/examos-kiosk.service /mnt/examos_root/etc/systemd/system/graphical.target.wants/examos-kiosk.service

# Remove any bad .bashrc that might cause agetty to exit immediately
sudo tee /mnt/examos_root/root/.bashrc > /dev/null << 'BASHRC'
# ExamOS Root Shell
export PS1='\[\033[1;36m\]ExamOS\[\033[0m\]:\[\033[1;34m\]\w\[\033[0m\]# '
BASHRC

sudo sync
sudo umount /mnt/examos_esp /mnt/examos_root
sudo losetup -d "$LOOPDEV"

echo "=== 7. Running e2fsck filesystem integrity check ==="
sudo losetup -fP "$RAW_IMG"
sudo e2fsck -f -y /dev/loop0p2
sudo losetup -d /dev/loop0

echo "=== Image Ready for VMDK conversion ==="
