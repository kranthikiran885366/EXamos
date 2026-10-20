#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="/mnt/d/SEB BRO"
RAW_IMG="$WORKSPACE/image/examos.raw"

echo "=== Fixing Console, Autologin, and VMware Display in ExamOS Image ==="

LOOPDEV=$(sudo losetup -fP --show "$RAW_IMG")
trap 'sudo umount /mnt/examos_esp /mnt/examos_root 2>/dev/null || true; sudo losetup -d "$LOOPDEV" 2>/dev/null || true' EXIT

sudo mkdir -p /mnt/examos_esp /mnt/examos_root
sudo mount "${LOOPDEV}p1" /mnt/examos_esp
sudo mount "${LOOPDEV}p2" /mnt/examos_root

echo "--- 1. Blacklisting i2c_piix4 and problematic VMware modules ---"
sudo tee /mnt/examos_root/etc/modprobe.d/blacklist-vmware.conf > /dev/null << 'CONF'
blacklist i2c_piix4
blacklist piix4_smbus
CONF

echo "--- 2. Setting loader.conf timeout and console mode ---"
sudo tee /mnt/examos_esp/loader/loader.conf > /dev/null << 'CONF'
timeout 2
console-mode auto
CONF

echo "--- 3. Configuring Auto-login on tty1 for instant access ---"
sudo mkdir -p /mnt/examos_root/etc/systemd/system/getty@tty1.service.d
sudo tee /mnt/examos_root/etc/systemd/system/getty@tty1.service.d/override.conf > /dev/null << 'CONF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty -o '-p -- \\u' --noclear -a root tty1 linux
Type=idle
StandardInput=tty
StandardOutput=tty
TTYVTDisallocate=no
CONF

sudo mkdir -p /mnt/examos_root/etc/systemd/system/getty.target.wants
sudo ln -sf /usr/lib/systemd/system/getty@.service /mnt/examos_root/etc/systemd/system/getty.target.wants/getty@tty1.service

echo "--- 4. Creating beautiful terminal welcome splash on login ---"
sudo tee /mnt/examos_root/root/.bashrc > /dev/null << 'BASHRC'
# ExamOS Root Shell Environment
clear
cat /etc/issue 2>/dev/null || true
echo ""
echo "Type 'systemctl status' or 'ip a' to inspect system status."
echo ""
export PS1='\[\033[1;36m\]ExamOS\[\033[0m\]:\[\033[1;34m\]\w\[\033[0m\]# '
BASHRC

sudo cp /mnt/examos_root/root/.bashrc /mnt/examos_root/home/exam/.bashrc 2>/dev/null || true
sudo chown 1000:1000 /mnt/examos_root/home/exam/.bashrc 2>/dev/null || true

sudo sync
echo "=== Modifications Applied Successfully to Image Filesystem ==="
