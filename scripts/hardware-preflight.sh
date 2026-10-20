#!/usr/bin/env bash
# =============================================================================
# ExamOS — Hardware Preflight Checklist
#
# Runs on a physical laptop booted from the ExamOS USB drive.
# Verifies all hardware subsystems required for secure examination:
#   - UEFI Secure Boot status
#   - TPM 2.0 presence and PCR measurements
#   - Network interface detection
#   - Camera (V4L2) availability
#   - Audio device availability
#   - dm-verity root filesystem status
#   - Firewall (nftables) active
#   - AppArmor enforcement
#   - USBGuard active
#   - Kiosk mode (no shell access)
#   - Attestation agent running
#   - Exam server reachable
#
# All checks use real /sys, /proc, and device paths — no QEMU markers.
# =============================================================================
set -uo pipefail

PASS=0; FAIL=0; WARN=0; BLOCKED=0

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

check() {
    local name="$1" status="$2" detail="$3"
    case "$status" in
        PASS)    PASS=$((PASS+1));    echo "  [✓ PASS]    $name: $detail" ;;
        FAIL)    FAIL=$((FAIL+1));    echo "  [✗ FAIL]    $name: $detail" ;;
        WARN)    WARN=$((WARN+1));    echo "  [! WARN]    $name: $detail" ;;
        BLOCKED) BLOCKED=$((BLOCKED+1)); echo "  [- BLOCKED] $name: $detail" ;;
    esac
}

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   ExamOS Hardware Preflight Checklist                        ║"
echo "║   $(ts)                                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# -----------------------------------------------------------------------
# 1. UEFI Secure Boot
# -----------------------------------------------------------------------
echo "━━━ Boot Security ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SB_STATUS=$(mokutil --sb-state 2>/dev/null || echo "UNKNOWN")
case "$SB_STATUS" in
    *SecureBoot*enabled*) check "UEFI Secure Boot" "PASS" "Enabled" ;;
    *disabled*)           check "UEFI Secure Boot" "FAIL" "Disabled — enable in UEFI setup" ;;
    *)                    check "UEFI Secure Boot" "WARN" "Cannot determine: $SB_STATUS" ;;
esac

# -----------------------------------------------------------------------
# 2. TPM 2.0
# -----------------------------------------------------------------------
if [ -e /dev/tpmrm0 ] || [ -e /dev/tpm0 ]; then
    TPM_DEV=$(ls /dev/tpmrm0 /dev/tpm0 2>/dev/null | head -1)
    if command -v tpm2_pcrread >/dev/null 2>&1; then
        if tpm2_pcrread sha256:0,4,7,11 >/dev/null 2>&1; then
            PCR0=$(tpm2_pcrread sha256:0 2>/dev/null | grep '0x' | head -1 | awk '{print $NF}')
            check "TPM 2.0 Device" "PASS" "$TPM_DEV — PCR read OK"
            check "TPM PCR 0 (Firmware)" "PASS" "${PCR0:0:16}..."
        else
            check "TPM 2.0 Device" "FAIL" "$TPM_DEV found but PCR read failed"
        fi
    else
        check "TPM 2.0 Device" "WARN" "$TPM_DEV present but tpm2-tools not installed"
    fi
else
    check "TPM 2.0 Device" "FAIL" "No TPM device found — required for attestation"
fi

# -----------------------------------------------------------------------
# 3. dm-verity root filesystem
# -----------------------------------------------------------------------
if [ -e /sys/class/block/dm-0/uevent ]; then
    DM_TYPE=$(cat /sys/class/block/dm-0/dm/name 2>/dev/null || echo "unknown")
    if echo "$DM_TYPE" | grep -qi verity; then
        check "dm-verity Root" "PASS" "verity device active: dm-0"
    else
        check "dm-verity Root" "WARN" "dm-0 exists but not verity: $DM_TYPE"
    fi
else
    check "dm-verity Root" "WARN" "No dm-0 device — may be direct mount"
fi

# -----------------------------------------------------------------------
# 4. Network
# -----------------------------------------------------------------------
echo ""
echo "━━━ Network ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

NET_INTERFACES=$(ls /sys/class/net/ 2>/dev/null | grep -v lo | tr '\n' ' ')
if [ -n "$NET_INTERFACES" ]; then
    check "Network Interfaces" "PASS" "$NET_INTERFACES"
else
    check "Network Interfaces" "FAIL" "No network interfaces detected"
fi

# Check for Wi-Fi
for iface in /sys/class/net/wl* /sys/class/net/wlan*; do
    [ -e "$iface" ] && check "Wi-Fi Interface" "PASS" "$(basename "$iface")" && break
done

# Check for Ethernet
for iface in /sys/class/net/en* /sys/class/net/eth*; do
    [ -e "$iface" ] && check "Ethernet Interface" "PASS" "$(basename "$iface")" && break
done

# Check link state
for iface in /sys/class/net/*/operstate; do
    IFACE=$(echo "$iface" | sed 's|.*/net/||;s|/operstate||')
    STATE=$(cat "$iface" 2>/dev/null || echo "unknown")
    [ "$IFACE" = "lo" ] && continue
    if [ "$STATE" = "up" ]; then
        check "Link: $IFACE" "PASS" "Connected"
    else
        check "Link: $IFACE" "WARN" "State: $STATE"
    fi
done

# -----------------------------------------------------------------------
# 5. Camera
# -----------------------------------------------------------------------
echo ""
echo "━━━ Camera ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

CAM_COUNT=$(ls /dev/video* 2>/dev/null | wc -l)
if [ "$CAM_COUNT" -gt 0 ]; then
    check "Camera (V4L2)" "PASS" "$CAM_COUNT device(s): $(ls /dev/video* 2>/dev/null | tr '\n' ' ')"
    # Check if camera is accessible
    if command -v v4l2-ctl >/dev/null 2>&1; then
        CAM_INFO=$(v4l2-ctl --list-formats --device /dev/video0 2>/dev/null | head -5 || echo "")
        [ -n "$CAM_INFO" ] && check "Camera Capabilities" "PASS" "V4L2 query OK"
    fi
else
    check "Camera (V4L2)" "FAIL" "No /dev/video* devices — camera required for proctoring"
fi

# -----------------------------------------------------------------------
# 6. Audio
# -----------------------------------------------------------------------
if [ -d /proc/asound/cards ] || ls /proc/asound/card* >/dev/null 2>&1; then
    SOUND_CARDS=$(cat /proc/asound/cards 2>/dev/null | grep -c '^ [0-9]' || echo 0)
    if [ "$SOUND_CARDS" -gt 0 ]; then
        check "Audio Device" "PASS" "$SOUND_CARDS ALSA card(s)"
    else
        check "Audio Device" "WARN" "ALSA present but no cards"
    fi
else
    check "Audio Device" "WARN" "No ALSA cards detected"
fi

# -----------------------------------------------------------------------
# 7. Security Controls
# -----------------------------------------------------------------------
echo ""
echo "━━━ Security Controls ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Firewall
if command -v nft >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -q "policy drop"; then
        check "nftables Firewall" "PASS" "Default-deny policy active"
    else
        check "nftables Firewall" "WARN" "nft available but no drop policy"
    fi
else
    check "nftables Firewall" "WARN" "nft not available"
fi

# AppArmor
AA_STATUS=$(aa-status 2>/dev/null || echo "unavailable")
if echo "$AA_STATUS" | grep -q "profiles are loaded"; then
    check "AppArmor" "PASS" "Profiles loaded"
elif echo "$AA_STATUS" | grep -q "enforce"; then
    check "AppArmor" "PASS" "Enforce mode"
else
    check "AppArmor" "WARN" "Status: $AA_STATUS"
fi

# USBGuard
if systemctl is-active usbguard >/dev/null 2>&1; then
    check "USBGuard" "PASS" "Service active"
else
    check "USBGuard" "WARN" "Service not active"
fi

# Kernel lockdown
LOCKDOWN=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "unknown")
if echo "$LOCKDOWN" | grep -q "confidentiality"; then
    check "Kernel Lockdown" "PASS" "confidentiality mode"
elif echo "$LOCKDOWN" | grep -q "integrity"; then
    check "Kernel Lockdown" "WARN" "integrity mode (should be confidentiality)"
else
    check "Kernel Lockdown" "WARN" "Status: $LOCKDOWN"
fi

# Module signature enforcement
if [ -f /proc/sys/kernel/module_sig_enforce ]; then
    if [ "$(cat /proc/sys/kernel/module_sig_enforce)" = "1" ]; then
        check "Module Signing" "PASS" "Enforced"
    else
        check "Module Signing" "WARN" "Not enforced"
    fi
fi

# No swap
SWAP_COUNT=$(swapon --show 2>/dev/null | tail -n +2 | wc -l || echo 0)
if [ "$SWAP_COUNT" -eq 0 ]; then
    check "No Swap" "PASS" "No swap devices active"
else
    check "No Swap" "WARN" "$SWAP_COUNT swap device(s) active"
fi

# -----------------------------------------------------------------------
# 8. ExamOS Services
# -----------------------------------------------------------------------
echo ""
echo "━━━ ExamOS Services ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for svc in examos-server examos-agent examos-kiosk; do
    if systemctl is-active "$svc" >/dev/null 2>&1; then
        check "Service: $svc" "PASS" "Running"
    else
        check "Service: $svc" "FAIL" "Not running"
    fi
done

# Exam server health
if curl -sf http://127.0.0.1:8000/api/v1/health >/dev/null 2>&1; then
    check "Exam Server Health" "PASS" "200 OK"
else
    check "Exam Server Health" "FAIL" "Not responding on localhost:8000"
fi

# -----------------------------------------------------------------------
# 9. Hardware Info
# -----------------------------------------------------------------------
echo ""
echo "━━━ Hardware Information ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

DMI_VENDOR=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo "Unknown")
DMI_PRODUCT=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "Unknown")
CPU_MODEL=$(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "Unknown")
CPU_CORES=$(nproc 2>/dev/null || echo "?")
RAM_MB=$(awk '/^MemTotal:/ { printf "%.0f", $2/1024 }' /proc/meminfo 2>/dev/null || echo "?")

echo "  Manufacturer: $DMI_VENDOR"
echo "  Product:      $DMI_PRODUCT"
echo "  CPU:          $CPU_MODEL ($CPU_CORES cores)"
echo "  RAM:          ${RAM_MB} MB"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
TOTAL=$((PASS + FAIL + WARN + BLOCKED))
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
printf "║  Hardware Preflight: %d/%d PASS, %d FAIL, %d WARN, %d BLOCKED     ║\n" \
    "$PASS" "$TOTAL" "$FAIL" "$WARN" "$BLOCKED"
echo "╚══════════════════════════════════════════════════════════════╝"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "FAILURES MUST BE RESOLVED BEFORE RUNNING EXAM"
    exit 1
fi

echo ""
echo "All critical checks passed. Laptop is ready for examination."
exit 0
