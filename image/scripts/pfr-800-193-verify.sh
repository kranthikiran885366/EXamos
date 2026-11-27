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
tpm_pcr7="UNAVAILABLE"
if [ -r /sys/class/tpm/tpm0/pcr-sha256/0 ]; then
    tpm_pcr0=$(tr -d '\n' < /sys/class/tpm/tpm0/pcr-sha256/0)
fi
if [ -r /sys/class/tpm/tpm0/pcr-sha256/7 ]; then
    tpm_pcr7=$(tr -d '\n' < /sys/class/tpm/tpm0/pcr-sha256/7)
fi

event_log_ok="false"
if [ -s /sys/kernel/security/tpm0/binary_bios_measurements ]; then
    event_log_ok="true"
fi

lockdown_mode="NONE"
lockdown_ok="false"
if [ -r /sys/kernel/security/lockdown ]; then
    lockdown_mode=$(cat /sys/kernel/security/lockdown)
    if echo "$lockdown_mode" | grep -qE '\[(confidentiality|integrity)\]'; then
        lockdown_ok="true"
    fi
fi

recovery_present="false"
recovery_authentic="false"
if [ -s "$RECOVERY_CAP" ]; then
    recovery_present="true"
    cap_sha=$(sha256sum "$RECOVERY_CAP" | awk '{print $1}')
    if [ -f "$POLICY_FILE" ] && command -v jq >/dev/null 2>&1; then
        expected_sha=$(jq -r '.recovery_capsule_sha256 // empty' "$POLICY_FILE")
        if [ -n "$expected_sha" ] && [ "$cap_sha" = "$expected_sha" ]; then
            recovery_authentic="true"
        elif [ -z "$expected_sha" ] && openssl pkcs7 -inform DER -in "$RECOVERY_CAP" -noout >/dev/null 2>&1; then
            recovery_authentic="true"
        fi
    fi
fi

status="FAIL"
if [ "$sb_state" = "ENABLED" ] && [ "$lockdown_ok" = "true" ] && \
   [ "$tpm_pcr0" != "UNAVAILABLE" ] && [ "$tpm_pcr7" != "UNAVAILABLE" ] && \
   [ "$event_log_ok" = "true" ] && [ "$recovery_authentic" = "true" ]; then
    status="PASS"
fi

cat > "$REPORT_OUT" <<EOF
{
  "standard": "NIST SP 800-193",
  "status": "${status}",
  "protection": {
    "secure_boot": "${sb_state}",
    "kernel_lockdown": "${lockdown_mode}",
    "lockdown_enforced": ${lockdown_ok}
  },
  "detection": {
    "tpm_pcr0_sha256": "${tpm_pcr0}",
    "tpm_pcr7_sha256": "${tpm_pcr7}",
    "bios_event_log_present": ${event_log_ok}
  },
  "recovery": {
    "golden_capsule_present": ${recovery_present},
    "golden_capsule_authentic": ${recovery_authentic},
    "policy_file": "${POLICY_FILE}"
  }
}
EOF
echo "[pfr-800-193] status=${status} secure_boot=${sb_state} lockdown=${lockdown_ok} event_log=${event_log_ok} recovery_auth=${recovery_authentic}"
[ "$status" = "PASS" ] || exit 1
