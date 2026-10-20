#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — Startup Configuration Validator
# Runs at boot before the kiosk starts.  Checks every mandatory P2 control
# is active.  On any failure: logs structured reason code and exits non-zero,
# which causes the calling systemd service (examos-preflight.service) to fail
# and trigger examos-lockdown-failed.target, preventing kiosk startup.
#
# This script reads REAL runtime state — /proc, /sys, sysctl, mount tables,
# service state — not just config files.  It does not claim PASS from a
# file existing alone.
#
# Exit codes:
#   0  All mandatory checks PASS — kiosk may start
#   1  One or more mandatory checks FAIL — kiosk must not start
#   2  Required evidence is BLOCKED or NOT_RUN — kiosk must not start
# =============================================================================
set -uo pipefail

RESULT_FILE="${RESULT_FILE:-/run/examos/p2-startup-results.json}"
mkdir -p /run/examos
mkdir -p /run/log

PASS=0
FAIL=0
BLOCKED=0
TOTAL=0
EXPECTED_CHECKS=18
declare -a RESULTS=()

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

record() {
    local id="$1" status="$2" detail="$3"
    TOTAL=$((TOTAL+1))
    RESULTS+=("{\"id\":\"${id}\",\"status\":\"${status}\",\"detail\":\"${detail}\",\"ts\":\"$(ts)\"}")
    case "$status" in
        PASS)    PASS=$((PASS+1))   ; echo "[P2-VALIDATOR] PASS    ${id}: ${detail}" ;;
        FAIL)    FAIL=$((FAIL+1))   ; echo "[P2-VALIDATOR] FAIL    ${id}: ${detail}" >&2 ;;
        BLOCKED) BLOCKED=$((BLOCKED+1)); echo "[P2-VALIDATOR] BLOCKED ${id}: ${detail}" ;;
        *)       echo "[P2-VALIDATOR] ${status}    ${id}: ${detail}" ;;
    esac
}

# ---------------------------------------------------------------------------
# Helper: read a sysctl value from /proc/sys (not via sysctl binary)
# ---------------------------------------------------------------------------
read_sysctl() {
    local key="$1"
    local path="/proc/sys/${key//.//}"
    [ -f "$path" ] && cat "$path" 2>/dev/null || echo "NOT_FOUND"
}

echo "=== [ExamOS P2] Startup Validator ==="

# ---------------------------------------------------------------------------
# V-01: EXAM_URL configured and non-placeholder
# ---------------------------------------------------------------------------
EXAM_CONF="/etc/examos/exam.conf"
EXAM_URL=""
if [ -f "$EXAM_CONF" ]; then
    EXAM_URL=$(grep -oP '(?<=EXAM_URL=)\S+' "$EXAM_CONF" | head -1 || true)
fi
if [ -z "$EXAM_URL" ] || [ "$EXAM_URL" = "NOT_CONFIGURED" ]; then
    record "V-01-EXAM-URL" "FAIL" "EXAM_URL=NOT_CONFIGURED — set before candidate deployment"
else
    record "V-01-EXAM-URL" "PASS" "EXAM_URL=${EXAM_URL}"
fi

# ---------------------------------------------------------------------------
# V-02: lockdown mode — must be confidentiality
# ---------------------------------------------------------------------------
CMDLINE=$(cat /proc/cmdline 2>/dev/null || echo "")
if echo "$CMDLINE" | grep -q "lockdown=confidentiality"; then
    record "V-02-LOCKDOWN" "PASS" "lockdown=confidentiality active in cmdline"
elif echo "$CMDLINE" | grep -q "lockdown=integrity"; then
    record "V-02-LOCKDOWN" "FAIL" "lockdown=integrity — must be confidentiality for P2 release"
else
    # Check /sys/kernel/security/lockdown if available
    LOCKDOWN_STATE=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "NOT_AVAILABLE")
    if echo "$LOCKDOWN_STATE" | grep -qi "confidentiality"; then
        record "V-02-LOCKDOWN" "PASS" "lockdown=confidentiality via /sys/kernel/security/lockdown"
    elif echo "$LOCKDOWN_STATE" | grep -qi "integrity"; then
        record "V-02-LOCKDOWN" "FAIL" "lockdown=integrity only — must be confidentiality"
    else
        record "V-02-LOCKDOWN" "BLOCKED" "lockdown state unknown: ${LOCKDOWN_STATE}"
    fi
fi

# ---------------------------------------------------------------------------
# V-03: IPv6 disabled
# ---------------------------------------------------------------------------
IPV6_ALL=$(read_sysctl "net.ipv6.conf.all.disable_ipv6")
IPV6_DEF=$(read_sysctl "net.ipv6.conf.default.disable_ipv6")
if [ "$IPV6_ALL" = "1" ] && [ "$IPV6_DEF" = "1" ]; then
    record "V-03-IPV6" "PASS" "net.ipv6.conf.all/default.disable_ipv6=1"
else
    record "V-03-IPV6" "FAIL" "IPv6 not disabled: all=${IPV6_ALL} default=${IPV6_DEF}"
fi

# ---------------------------------------------------------------------------
# V-04: swap disabled — /proc/swaps must be empty
# ---------------------------------------------------------------------------
SWAP_LINES=$(tail -n +2 /proc/swaps 2>/dev/null | wc -l | tr -d ' ')
if [ "$SWAP_LINES" = "0" ]; then
    record "V-04-SWAP" "PASS" "/proc/swaps empty (no active swap)"
else
    record "V-04-SWAP" "FAIL" "Active swap detected: $(tail -n +2 /proc/swaps)"
fi

# ---------------------------------------------------------------------------
# V-05: core dump disabled — kernel.core_pattern and suid_dumpable
# ---------------------------------------------------------------------------
CORE_PAT=$(read_sysctl "kernel.core_pattern")
SUID_DUMP=$(read_sysctl "fs.suid_dumpable")
if echo "$CORE_PAT" | grep -q "|/bin/false" && [ "$SUID_DUMP" = "0" ]; then
    record "V-05-COREDUMP" "PASS" "core_pattern=|/bin/false suid_dumpable=0"
else
    record "V-05-COREDUMP" "FAIL" "core_pattern=${CORE_PAT} suid_dumpable=${SUID_DUMP}"
fi

# ---------------------------------------------------------------------------
# V-06: SysRq disabled
# ---------------------------------------------------------------------------
SYSRQ=$(read_sysctl "kernel.sysrq")
if [ "$SYSRQ" = "0" ]; then
    record "V-06-SYSRQ" "PASS" "kernel.sysrq=0"
else
    record "V-06-SYSRQ" "FAIL" "kernel.sysrq=${SYSRQ} (must be 0)"
fi

# ---------------------------------------------------------------------------
# V-07: ptrace restricted
# ---------------------------------------------------------------------------
PTRACE=$(read_sysctl "kernel.yama.ptrace_scope")
if [ "$PTRACE" = "3" ]; then
    record "V-07-PTRACE" "PASS" "kernel.yama.ptrace_scope=3"
elif [ "$PTRACE" = "2" ] || [ "$PTRACE" = "1" ]; then
    record "V-07-PTRACE" "FAIL" "ptrace_scope=${PTRACE} — must be 3 for ExamOS"
else
    record "V-07-PTRACE" "BLOCKED" "YAMA ptrace_scope not available: ${PTRACE}"
fi

# ---------------------------------------------------------------------------
# V-08: unprivileged BPF disabled
# ---------------------------------------------------------------------------
UBPF=$(read_sysctl "kernel.unprivileged_bpf_disabled")
if [ "$UBPF" = "1" ]; then
    record "V-08-BPF" "PASS" "kernel.unprivileged_bpf_disabled=1"
else
    record "V-08-BPF" "FAIL" "kernel.unprivileged_bpf_disabled=${UBPF}"
fi

# ---------------------------------------------------------------------------
# V-09: kernel module loading disabled
# ---------------------------------------------------------------------------
MOD_DISABLED=$(read_sysctl "kernel.modules_disabled")
if [ "$MOD_DISABLED" = "1" ]; then
    record "V-09-MODULES" "PASS" "kernel.modules_disabled=1"
elif [ "$MOD_DISABLED" = "0" ]; then
    # May not have locked yet if this validator runs before examos-module-lock
    # Check if the service is active
    if systemctl is-active --quiet examos-module-lock.service 2>/dev/null; then
        record "V-09-MODULES" "FAIL" "modules_disabled=0 even though examos-module-lock.service is active"
    else
        record "V-09-MODULES" "BLOCKED" "examos-module-lock.service not yet active — modules_disabled=0"
    fi
else
    record "V-09-MODULES" "BLOCKED" "modules_disabled not available: ${MOD_DISABLED}"
fi

# ---------------------------------------------------------------------------
# V-10: /tmp mounted noexec,nosuid,nodev
# ---------------------------------------------------------------------------
TMP_MOUNT=$(grep -w '/tmp' /proc/mounts 2>/dev/null | head -1 || true)
if echo "$TMP_MOUNT" | grep -q "tmpfs"; then
    if echo "$TMP_MOUNT" | grep -q "noexec" && \
       echo "$TMP_MOUNT" | grep -q "nosuid" && \
       echo "$TMP_MOUNT" | grep -q "nodev"; then
        record "V-10-TMP" "PASS" "/tmp is tmpfs noexec,nosuid,nodev"
    else
        record "V-10-TMP" "FAIL" "/tmp tmpfs flags missing: ${TMP_MOUNT}"
    fi
else
    record "V-10-TMP" "FAIL" "/tmp is not a tmpfs mount: ${TMP_MOUNT:-not mounted}"
fi

# ---------------------------------------------------------------------------
# V-11: /home/exam mounted noexec,nosuid,nodev
# ---------------------------------------------------------------------------
HOME_MOUNT=$(grep -w '/home/exam' /proc/mounts 2>/dev/null | head -1 || true)
if echo "$HOME_MOUNT" | grep -q "tmpfs"; then
    if echo "$HOME_MOUNT" | grep -q "noexec" && \
       echo "$HOME_MOUNT" | grep -q "nosuid" && \
       echo "$HOME_MOUNT" | grep -q "nodev"; then
        record "V-11-HOME" "PASS" "/home/exam is tmpfs noexec,nosuid,nodev"
    else
        record "V-11-HOME" "FAIL" "/home/exam tmpfs flags missing: ${HOME_MOUNT}"
    fi
else
    record "V-11-HOME" "FAIL" "/home/exam is not a tmpfs: ${HOME_MOUNT:-not mounted}"
fi

# ---------------------------------------------------------------------------
# V-12: nftables loaded and default-deny active
# ---------------------------------------------------------------------------
if command -v nft >/dev/null 2>&1; then
    NFT_INPUT_POLICY=$(nft list chain inet filter input 2>/dev/null | grep "policy" || true)
    NFT_OUTPUT_POLICY=$(nft list chain inet filter output 2>/dev/null | grep "policy" || true)
    if echo "$NFT_INPUT_POLICY" | grep -q "policy drop" && \
       echo "$NFT_OUTPUT_POLICY" | grep -q "policy drop"; then
        record "V-12-FIREWALL" "PASS" "nftables default-deny active on input+output"
    else
        record "V-12-FIREWALL" "FAIL" "nftables not default-deny: in='${NFT_INPUT_POLICY}' out='${NFT_OUTPUT_POLICY}'"
    fi
else
    record "V-12-FIREWALL" "BLOCKED" "nft binary not available — cannot verify firewall"
fi

# ---------------------------------------------------------------------------
# V-13: AppArmor in enforce mode
# ---------------------------------------------------------------------------
AA_STATUS=$(cat /sys/kernel/security/apparmor/profiles 2>/dev/null | grep chromium | head -1 || true)
if echo "$AA_STATUS" | grep -q "(enforce)"; then
    record "V-13-APPARMOR" "PASS" "Chromium AppArmor profile in enforce mode"
elif echo "$AA_STATUS" | grep -q "(complain)"; then
    record "V-13-APPARMOR" "FAIL" "Chromium AppArmor profile in COMPLAIN mode — not enforced"
elif [ -z "$AA_STATUS" ]; then
    # Check if apparmor is enabled at all
    AA_ENABLED=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "N")
    if [ "$AA_ENABLED" = "Y" ]; then
        record "V-13-APPARMOR" "BLOCKED" "AppArmor enabled but chromium profile not loaded"
    else
        record "V-13-APPARMOR" "BLOCKED" "AppArmor not enabled on this kernel"
    fi
else
    record "V-13-APPARMOR" "FAIL" "Unexpected AppArmor state: ${AA_STATUS}"
fi

# ---------------------------------------------------------------------------
# V-14: No SSH listener
# ---------------------------------------------------------------------------
SSH_LISTEN=$(ss -tlnp 2>/dev/null | grep ':22 ' || true)
if [ -z "$SSH_LISTEN" ]; then
    record "V-14-SSH" "PASS" "No SSH listener on port 22"
else
    record "V-14-SSH" "FAIL" "SSH listener detected: ${SSH_LISTEN}"
fi

# ---------------------------------------------------------------------------
# V-15: No internal disk partitions mounted
# ---------------------------------------------------------------------------
# Enumerate block devices; flag any non-loop, non-USB device that is mounted
# and is not the boot medium (check for internal SATA/NVMe devices)
INTERNAL_MOUNTS=$(grep -E '^/dev/(sd[a-z]|nvme[0-9]|hd[a-z])' /proc/mounts 2>/dev/null | \
    grep -v '\bnoauto\b' || true)
if [ -z "$INTERNAL_MOUNTS" ]; then
    record "V-15-DISK" "PASS" "No internal disk partitions mounted"
else
    record "V-15-DISK" "FAIL" "Internal disk mount detected: ${INTERNAL_MOUNTS}"
fi

# ---------------------------------------------------------------------------
# V-16: root filesystem mounted read-only
# ---------------------------------------------------------------------------
ROOT_MOUNT=$(grep ' / ' /proc/mounts 2>/dev/null | head -1 || true)
if echo "$ROOT_MOUNT" | grep -qE '\bro\b'; then
    record "V-16-ROOTRO" "PASS" "Root filesystem is read-only"
elif echo "$ROOT_MOUNT" | grep -qE '\brw\b'; then
    # Development image — document but don't hard-fail (dm-verity comes post-build)
    record "V-16-ROOTRO" "BLOCKED" "Root is rw — dm-verity post-build conversion not yet applied in this environment"
else
    record "V-16-ROOTRO" "BLOCKED" "Cannot determine root mount flags: ${ROOT_MOUNT}"
fi

# ---------------------------------------------------------------------------
# V-17: Chromium URLAllowlist does not contain https://*
# ---------------------------------------------------------------------------
POLICY="/etc/chromium/policies/managed/examos_policies.json"
if [ -f "$POLICY" ]; then
    if grep -q '"https://\*"' "$POLICY"; then
        record "V-17-POLICY" "FAIL" "URLAllowlist contains https://* — all HTTPS allowed"
    elif python3 -c "
import json,sys
d=json.load(open('$POLICY'))
al=d.get('URLAllowlist',[])
bl=d.get('URLBlocklist',[])
sys.exit(0 if '*' in bl and 'https://*' not in al else 1)
" 2>/dev/null; then
        record "V-17-POLICY" "PASS" "URLBlocklist=* and no wildcard HTTPS in URLAllowlist"
    else
        record "V-17-POLICY" "FAIL" "Chromium policy misconfigured (URLBlocklist or URLAllowlist)"
    fi
else
    record "V-17-POLICY" "FAIL" "Chromium policy file not found: ${POLICY}"
fi

# ---------------------------------------------------------------------------
# V-18: USBGuard daemon and active policy interface
# ---------------------------------------------------------------------------
if ! command -v usbguard >/dev/null 2>&1; then
    record "V-18-USBGUARD" "FAIL" "usbguard CLI is not installed"
elif ! systemctl is-active --quiet usbguard.service; then
    USBGUARD_STATE=$(systemctl is-active usbguard.service 2>/dev/null || echo "inactive")
    record "V-18-USBGUARD" "FAIL" "usbguard.service is ${USBGUARD_STATE}"
elif ! usbguard list-rules >/dev/null 2>&1; then
    record "V-18-USBGUARD" "FAIL" "USBGuard is active but its policy interface is not responsive"
else
    record "V-18-USBGUARD" "PASS" "USBGuard service is active and its policy interface responds"
fi

CHECK_COUNT=$((PASS+FAIL+BLOCKED))
if [ "$FAIL" -gt 0 ]; then
    GATE_RESULT="FAIL"
elif [ "$BLOCKED" -gt 0 ]; then
    GATE_RESULT="BLOCKED"
elif [ "$CHECK_COUNT" -ne "$EXPECTED_CHECKS" ] || [ "$TOTAL" -ne "$EXPECTED_CHECKS" ]; then
    GATE_RESULT="NOT_RUN"
else
    GATE_RESULT="PASS"
fi

# ---------------------------------------------------------------------------
# Write results JSON
# ---------------------------------------------------------------------------
{
    printf '{\n'
    printf '  "validator": "p2-startup-validator",\n'
    printf '  "timestamp": "%s",\n' "$(ts)"
    printf '  "pass": %d,\n' "$PASS"
    printf '  "fail": %d,\n' "$FAIL"
    printf '  "blocked": %d,\n' "$BLOCKED"
    printf '  "total": %d,\n' "$TOTAL"
    printf '  "expected": %d,\n' "$EXPECTED_CHECKS"
    printf '  "overall": "%s",\n' "$GATE_RESULT"
    printf '  "results": [\n'
    for i in "${!RESULTS[@]}"; do
        if [ "$i" -lt $((${#RESULTS[@]}-1)) ]; then
            printf '    %s,\n' "${RESULTS[$i]}"
        else
            printf '    %s\n' "${RESULTS[$i]}"
        fi
    done
    printf '  ]\n'
    printf '}\n'
} > "$RESULT_FILE"

echo ""
echo "=== [P2-VALIDATOR] Summary: PASS=${PASS} FAIL=${FAIL} BLOCKED=${BLOCKED} TOTAL=${TOTAL}/${EXPECTED_CHECKS} ==="

if [ "$GATE_RESULT" = "FAIL" ]; then
    echo "[P2-VALIDATOR] RESULT: FAIL — mandatory controls not met, kiosk must not start"
    cat "$RESULT_FILE" >&2
    exit 1
fi

if [ "$GATE_RESULT" != "PASS" ]; then
    echo "[P2-VALIDATOR] RESULT: ${GATE_RESULT} — mandatory evidence is incomplete, kiosk must not start"
    cat "$RESULT_FILE" >&2
    exit 2
fi

echo "[P2-VALIDATOR] RESULT: PASS — all mandatory controls verified"
exit 0
