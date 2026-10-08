#!/usr/bin/env bash
set -euo pipefail

echo "=== [ExamOS Build] Applying Enterprise OS Hardening ==="

# 1. Enable security services
systemctl enable apparmor 2>/dev/null || true
systemctl enable nftables 2>/dev/null || true
systemctl enable examos-server 2>/dev/null || true
systemctl enable examos-agent 2>/dev/null || true
systemctl enable examos-kiosk 2>/dev/null || true

# 2. Disable proctoring in P1 (P4 scope)
systemctl disable examos-proctor 2>/dev/null || true

# 3. Disable getty/login consoles on tty1 through tty6
for i in 1 2 3 4 5 6; do
    systemctl mask getty@tty${i}.service 2>/dev/null || true
done

# 4. Disable remote access services
systemctl disable ssh 2>/dev/null || true
systemctl disable sshd 2>/dev/null || true
systemctl mask ssh.service 2>/dev/null || true
systemctl mask sshd.service 2>/dev/null || true

# 5. Disable cron
systemctl disable cron 2>/dev/null || true

# 6. Set system identity
echo "examos-device" > /etc/hostname
echo "ExamOS Secure Examination Appliance v0.2.0" > /etc/issue
rm -f /etc/motd

# 7. Create log directory
mkdir -p /var/log/examos
chmod 0750 /var/log/examos

echo "=== [ExamOS Build] OS Hardening complete ==="
