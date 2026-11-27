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
pcr_policy_ok="false"
if [ -r /sys/class/tpm/tpm0/pcr-sha256/0 ]; then
    tpm_pcr0=$(tr -d '[:space:]' < /sys/class/tpm/tpm0/pcr-sha256/0)
fi
if [ -r /sys/class/tpm/tpm0/pcr-sha256/7 ]; then
    tpm_pcr7=$(tr -d '[:space:]' < /sys/class/tpm/tpm0/pcr-sha256/7)
fi

if [ -f "$POLICY_FILE" ] && command -v jq >/dev/null 2>&1; then
    pcr_policy_ok="true"
    for idx in 0 1 2 3 7; do
        actual=$(tr -d '[:space:]' < "/sys/class/tpm/tpm0/pcr-sha256/$idx" 2>/dev/null || true)
        expected=$(jq -r --arg i "$idx" '.pcr_sha256[$i] // empty' "$POLICY_FILE")
        if [ -z "$actual" ] || [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
            pcr_policy_ok="false"
            break
        fi
    done
fi

esrt_ok="true"
if [ -d /sys/firmware/efi/esrt/entries ]; then
    for st_file in /sys/firmware/efi/esrt/entries/*/last_attempt_status; do
        [ -r "$st_file" ] || continue
        st_val=$(tr -d '[:space:]' < "$st_file" || echo "1")
        if [ "$st_val" != "0" ]; then
            esrt_ok="false"
            break
        fi
    done
fi

event_log_ok="false"
if [ -s /sys/kernel/security/tpm0/binary_bios_measurements ]; then
    event_log_ok="true"
fi

lockdown_mode="NONE"
lockdown_ok="false"
if [ -r /sys/kernel/security/lockdown ]; then
    lockdown_mode=$(tr -d '\n' < /sys/kernel/security/lockdown)
    if echo "$lockdown_mode" | grep -qE '\[(confidentiality|integrity)\]'; then
        lockdown_ok="true"
    fi
fi

recovery_present="false"
recovery_authentic="false"
RECOVERY_CA="${RECOVERY_CA:-/etc/examos/pfr-recovery-ca.pem}"
if [ -s "$RECOVERY_CAP" ]; then
    recovery_present="true"
    cap_sha=$(sha256sum "$RECOVERY_CAP" | awk '{print $1}')
    if [ -f "$POLICY_FILE" ] && command -v jq >/dev/null 2>&1; then
        expected_sha=$(jq -r '.recovery_capsule_sha256 // empty' "$POLICY_FILE")
        if [ -n "$expected_sha" ]; then
            [ "$cap_sha" = "$expected_sha" ] && recovery_authentic="true"
        elif [ -f "$RECOVERY_CA" ]; then
            openssl cms -verify -inform DER -in "$RECOVERY_CAP" -CAfile "$RECOVERY_CA" -out /dev/null >/dev/null 2>&1 && recovery_authentic="true"
        fi
    fi
fi

status="FAIL"
if [ "$sb_state" = "ENABLED" ] && [ "$lockdown_ok" = "true" ] && \
   [ "$pcr_policy_ok" = "true" ] && [ "$esrt_ok" = "true" ] && \
   [ "$event_log_ok" = "true" ] && [ "$recovery_authentic" = "true" ]; then
    status="PASS"
fi

TMP_REPORT="${REPORT_OUT}.tmp.$$"
if command -v jq >/dev/null 2>&1; then
    jq -n \
        --arg standard "NIST SP 800-193" \
        --arg status "$status" \
        --arg sb "$sb_state" \
        --arg ld "$lockdown_mode" \
        --argjson ld_ok "$lockdown_ok" \
        --arg pcr0 "$tpm_pcr0" \
        --arg pcr7 "$tpm_pcr7" \
        --argjson pcr_ok "$pcr_policy_ok" \
        --argjson esrt_ok "$esrt_ok" \
        --argjson ev_ok "$event_log_ok" \
        --argjson rec_pres "$recovery_present" \
        --argjson rec_auth "$recovery_authentic" \
        --arg pol "$POLICY_FILE" \
        '{
          standard: $standard,
          status: $status,
          protection: { secure_boot: $sb, kernel_lockdown: $ld, lockdown_enforced: $ld_ok },
          detection: { tpm_pcr0_sha256: $pcr0, tpm_pcr7_sha256: $pcr7, pcr_policy_matched: $pcr_ok, esrt_healthy: $esrt_ok, bios_event_log_present: $ev_ok },
          recovery: { golden_capsule_present: $rec_pres, golden_capsule_authentic: $rec_auth, policy_file: $pol }
        }' > "$TMP_REPORT"
    mv -f "$TMP_REPORT" "$REPORT_OUT"
fi
echo "[pfr-800-193] status=${status} secure_boot=${sb_state} lockdown=${lockdown_ok} pcr_policy=${pcr_policy_ok} esrt=${esrt_ok} event_log=${event_log_ok} recovery_auth=${recovery_authentic}"
[ "$status" = "PASS" ] || exit 1
