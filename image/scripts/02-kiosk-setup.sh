#!/usr/bin/env bash
set -euo pipefail

echo "=== [ExamOS Build] Setting up Chromium Enterprise Kiosk Policies ==="

mkdir -p /etc/chromium/policies/managed
mkdir -p /etc/opt/chrome/policies/managed

if [ -f /opt/examos/kiosk/policies/managed_policies.json ]; then
  cp -f /opt/examos/kiosk/policies/managed_policies.json /etc/chromium/policies/managed/examos_policies.json
  cp -f /opt/examos/kiosk/policies/managed_policies.json /etc/opt/chrome/policies/managed/examos_policies.json
fi

chmod 0644 /etc/chromium/policies/managed/*.json 2>/dev/null || true
chown root:exam /etc/examos/proctor.env /etc/examos/candidates.conf
chmod 0640 /etc/examos/proctor.env /etc/examos/candidates.conf

echo "=== [ExamOS Build] Kiosk policies configured ==="
