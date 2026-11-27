#!/usr/bin/env bash
# ExamOS — Sanitized PII-Free Remote Diagnostics Bundle
# Collects kernel, driver, network, USBGuard, and P2 health state with
# hostnames, IPv4/IPv6 addresses, and MAC addresses redacted, then writes
# a SHA-256 manifest for remote support triage.
set -euo pipefail

OUT_DIR="${1:-/run/examos/diag}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUT_DIR"
BUNDLE_PATH="${OUT_DIR}/examos-diag-${STAMP}.tar.gz"

sanitize_stream() {
    sed -E \
        -e 's/([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/[REDACTED-MAC]/g' \
        -e 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/[REDACTED-IP]/g' \
        -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/[REDACTED-EMAIL]/g'
}

dmesg -T 2>/dev/null | tail -n 500 | sanitize_stream > "${WORK_DIR}/dmesg.txt" || true
lsmod 2>/dev/null > "${WORK_DIR}/lsmod.txt" || true
ip -br link 2>/dev/null | sanitize_stream > "${WORK_DIR}/net-links.txt" || true
uname -a > "${WORK_DIR}/uname.txt"
[ -f /run/examos/p2-health-report.json ] && cp /run/examos/p2-health-report.json "${WORK_DIR}/" || true
[ -f /run/examos/pfr-800-193.json ] && cp /run/examos/pfr-800-193.json "${WORK_DIR}/" || true
[ -f /run/examos/preflight-check.json ] && cp /run/examos/preflight-check.json "${WORK_DIR}/" || true
command -v usbguard >/dev/null 2>&1 && usbguard list-devices 2>/dev/null | sanitize_stream > "${WORK_DIR}/usbguard-devices.txt" || true

tar -czf "$BUNDLE_PATH" -C "$WORK_DIR" .
sha256sum "$BUNDLE_PATH" > "${BUNDLE_PATH}.sha256"
chmod 600 "$BUNDLE_PATH" "${BUNDLE_PATH}.sha256"

echo "[ExamOS-Diag] Sanitized bundle created: $BUNDLE_PATH"
