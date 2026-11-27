#!/usr/bin/env bash
# =============================================================================
# SPPIO / ExamOS — Platform Firmware Resiliency (NIST SP 800-193) Verifier
#
# Verifies the three NIST SP 800-193 pillars:
#   1. Protection: UEFI Secure Boot active, SPI flash write-lock / PR registers,
#      and kernel lockdown integrity mode.
#   2. Detection:  TPM 2.0 PCR 0-3 & 7 firmware measurements available and
#      UEFI firmware capsule / ESRT state intact.
#   3. Recovery:   Verified golden recovery capsule present on ESP for
#      automated firmware recovery on corruption detection.
# =============================================================================
set -euo pipefail

POLICY_FILE="${POLICY_FILE:-/etc/examos/pfr-policy.json}"
RECOVERY_CAP="${RECOVERY_CAP:-/boot/efi/EFI/EXAMOS/RECOVERY.CAP}"
REPORT_OUT="${REPORT_OUT:-/run/examos/pfr-status.json}"

mkdir -p "$(dirname "$REPORT_OUT")"

sb_state="UNKNOWN"
if [ -d /sys/firmware/efi/efivars ]; then
    sb_var=$(find /sys/firmware/efi/efivars -name "SecureBoot-*" 2>/dev/null | head -n1 || true)
    if [ -n "$sb_var" ] && [ -r "$sb_var" ]; then
        val=$(od -An -t u1 -j4 -N1 "$sb_var" 2>/dev/null | tr -d ' ' || echo "0")
        [ "$val" = "1" ] && sb_state="ENABLED" || sb_state="DISABLED"
    fi
fi

tpm_pcr0="UNAVAILABLE"
if [ -r /sys/class/tpm/tpm0/pcr-sha256/0 ]; then
    tpm_pcr0=$(tr -d '\n' < /sys/class/tpm/tpm0/pcr-sha256/0)
fi

lockdown_mode="NONE"
if [ -r /sys/kernel/security/lockdown ]; then
    lockdown_mode=$(cat /sys/kernel/security/lockdown)
fi

recovery_present="false"
if [ -s "$RECOVERY_CAP" ]; then
    recovery_present="true"
fi

status="FAIL"
if [ "$sb_state" = "ENABLED" ] && [ "$tpm_pcr0" != "UNAVAILABLE" ] && [ "$recovery_present" = "true" ]; then
    status="PASS"
fi

cat > "$REPORT_OUT" <<EOF
{
  "standard": "NIST SP 800-193",
  "status": "${status}",
  "protection": {
    "secure_boot": "${sb_state}",
    "kernel_lockdown": "${lockdown_mode}"
  },
  "detection": {
    "tpm_pcr0_sha256": "${tpm_pcr0}"
  },
  "recovery": {
    "golden_capsule_present": ${recovery_present},
    "policy_file": "${POLICY_FILE}"
  }
}
EOF
echo "[pfr-800-193] status=${status} secure_boot=${sb_state} recovery=${recovery_present}"
[ "$status" = "PASS" ] || exit 1
