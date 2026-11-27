#!/usr/bin/env bash
# ExamOS — TPM 2.0 Bound Full-Disk Encryption (LUKS2) Enrollment
# Binds LUKS2 volume keys to TPM 2.0 PCRs 0, 2, 4, 7, 11 so pulling the NVMe/SSD
# out of a lab workstation yields zero readable exam files, configs, or logs.
set -euo pipefail

DEVICE="${1:-}"
PCRS="${EXAMOS_LUKS_TPM_PCRS:-0+2+4+7+11}"
WIPE_PASSWORD_SLOT="${EXAMOS_LUKS_WIPE_PASSWORD:-0}"

usage() {
    echo "Usage: $0 <block-device>" >&2
    echo "Example: $0 /dev/nvme0n1p6" >&2
    exit 2
}

[ -n "$DEVICE" ] || usage
[ -b "$DEVICE" ] || { echo "[LUKS2-TPM] ERROR: $DEVICE is not a block device" >&2; exit 1; }

command -v cryptsetup >/dev/null 2>&1 || { echo "[LUKS2-TPM] ERROR: cryptsetup not installed" >&2; exit 1; }
command -v systemd-cryptenroll >/dev/null 2>&1 || { echo "[LUKS2-TPM] ERROR: systemd-cryptenroll not installed" >&2; exit 1; }

if ! cryptsetup isLuks --type luks2 "$DEVICE"; then
    echo "[LUKS2-TPM] ERROR: $DEVICE is not a LUKS2 volume" >&2
    exit 1
fi

if [ ! -e /dev/tpmrm0 ] && [ ! -e /dev/tpm0 ]; then
    echo "[LUKS2-TPM] ERROR: No TPM 2.0 device (/dev/tpmrm0 or /dev/tpm0) found" >&2
    exit 1
fi

echo "[LUKS2-TPM] Enrolling $DEVICE with TPM2 PCRs: $PCRS"
systemd-cryptenroll \
    --tpm2-device=auto \
    --tpm2-pcrs="$PCRS" \
    "$DEVICE"

if [ "$WIPE_PASSWORD_SLOT" = "1" ]; then
    echo "[LUKS2-TPM] Wiping fallback password keyslots (sealed appliance mode)"
    systemd-cryptenroll --wipe-slot=password "$DEVICE"
fi

echo "[LUKS2-TPM] Verifying LUKS2 TPM2 token metadata on $DEVICE:"
cryptsetup luksDump "$DEVICE" | grep -E "systemd-tpm2|pcrs" || {
    echo "[LUKS2-TPM] ERROR: TPM2 token not found in LUKS2 header after enrollment" >&2
    exit 1
}

echo "[LUKS2-TPM] OK: $DEVICE bound to TPM2 PCRs ($PCRS)"
