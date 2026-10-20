#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — Health and Diagnostics Reporter
# Collects real runtime state for every P2 control domain.
# Outputs a structured JSON report to REPORT_OUT.
#
# This script probes real /proc, /sys, mount tables, service state.
# It does NOT infer enforcement from config file existence alone.
# Every field is labelled PASS / FAIL / BLOCKED / NOT_AVAILABLE / NOT_RUN.
#
# Usage (inside running ExamOS guest or CI boot environment):
#   REPORT_OUT=artifacts/phase2/kernel-hardening-audit.json \
#   bash image/scripts/p2-health-report.sh
# =============================================================================
set -uo pipefail

REPORT_OUT="${REPORT_OUT:-/run/examos/p2-health-report.json}"
LOG_OUT="${LOG_OUT:-/run/examos/p2-health-report.log}"

exec > >(tee "$LOG_OUT") 2>&1

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

read_sysctl() {
    local key="$1"
    local path="/proc/sys/${key//.//}"
    [ -f "$path" ] && cat "$path" 2>/dev/null | tr -d '[:space:]' || echo "NOT_AVAILABLE"
}

sysctl_status() {
    local key="$1" want="$2"
    local got
    got=$(read_sysctl "$key")
    if [ "$got" = "NOT_AVAILABLE" ]; then echo "NOT_AVAILABLE"
    elif [ "$got" = "$want" ]; then echo "PASS"
    else echo "FAIL:got=${got}:want=${want}"
    fi
}

echo "=== [ExamOS P2] Health Report: $(ts) ==="

# ---------------------------------------------------------------------------
# Collect build identity
# ---------------------------------------------------------------------------
BUILD_ID=$(grep '^BUILD_ID=' /etc/os-release 2>/dev/null | cut -d= -f2 || echo "unknown")
VERSION=$(grep '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d= -f2 || echo "unknown")
KERNEL=$(uname -r 2>/dev/null || echo "unknown")
CMDLINE=$(cat /proc/cmdline 2>/dev/null || echo "")

# Chromium version
CHROMIUM_VER=$(chromium --version 2>/dev/null | head -1 || echo "NOT_AVAILABLE")

# Git commit (if available)
GIT_COMMIT=$(cat /etc/examos/git-commit 2>/dev/null || echo "UNKNOWN")

# ---------------------------------------------------------------------------
# Domain probes
# ---------------------------------------------------------------------------

# --- Image identity ---
IMG_BUILD_ID="${BUILD_ID}"
IMG_KERNEL="${KERNEL}"
IMG_CHROMIUM="${CHROMIUM_VER}"

# --- Cmdline flags ---
CMDLINE_LOCKDOWN="NOT_AVAILABLE"
if echo "$CMDLINE" | grep -q "lockdown=confidentiality"; then
    CMDLINE_LOCKDOWN="PASS:confidentiality"
elif echo "$CMDLINE" | grep -q "lockdown=integrity"; then
    CMDLINE_LOCKDOWN="FAIL:integrity_not_confidentiality"
else
    CMDLINE_LOCKDOWN="FAIL:lockdown_flag_absent"
fi

CMDLINE_IOMMU="NOT_AVAILABLE"
if echo "$CMDLINE" | grep -qE "intel_iommu=on|amd_iommu=on"; then
    CMDLINE_IOMMU="PASS:iommu_cmdline_present"
    # Verify IOMMU is actually active
    if [ -d /sys/class/iommu ] && ls /sys/class/iommu/ 2>/dev/null | grep -q .; then
        CMDLINE_IOMMU="PASS:iommu_active"
    elif dmesg 2>/dev/null | grep -qi "iommu.*enabled\|DMAR.*remapping"; then
        CMDLINE_IOMMU="PASS:iommu_active_from_dmesg"
    else
        CMDLINE_IOMMU="BLOCKED:iommu_cmdline_set_but_no_dmar_table_found"
    fi
fi

CMDLINE_MODSIG="NOT_AVAILABLE"
if echo "$CMDLINE" | grep -q "module.sig_enforce=1"; then
    CMDLINE_MODSIG="PASS:sig_enforce_in_cmdline"
fi

# --- Sysctl values ---
SCTL_PTRACE=$(sysctl_status "kernel.yama.ptrace_scope" "3")
SCTL_BPF=$(sysctl_status "kernel.unprivileged_bpf_disabled" "1")
SCTL_SYSRQ=$(sysctl_status "kernel.sysrq" "0")
SCTL_KPTR=$(sysctl_status "kernel.kptr_restrict" "2")
SCTL_CORE_PAT_RAW=$(read_sysctl "kernel.core_pattern")
SCTL_CORE_PAT="FAIL:${SCTL_CORE_PAT_RAW}"
echo "$SCTL_CORE_PAT_RAW" | grep -q "|/bin/false" && SCTL_CORE_PAT="PASS"
SCTL_SUID_DUMP=$(sysctl_status "fs.suid_dumpable" "0")
SCTL_SWAP=$(sysctl_status "vm.swappiness" "0")
SCTL_IPV6_ALL=$(sysctl_status "net.ipv6.conf.all.disable_ipv6" "1")
SCTL_IPV6_DEF=$(sysctl_status "net.ipv6.conf.default.disable_ipv6" "1")
SCTL_DMESG=$(sysctl_status "kernel.dmesg_restrict" "1")
SCTL_PERF=$(sysctl_status "kernel.perf_event_paranoid" "3")

# --- Module lock ---
MOD_DISABLED_VAL=$(read_sysctl "kernel.modules_disabled")
if [ "$MOD_DISABLED_VAL" = "1" ]; then
    MOD_LOCK_STATUS="PASS"
elif [ "$MOD_DISABLED_VAL" = "0" ]; then
    MOD_LOCK_STATUS="FAIL:modules_loading_still_enabled"
else
    MOD_LOCK_STATUS="NOT_AVAILABLE"
fi

# --- Lockdown state from /sys ---
LOCKDOWN_SYS=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "NOT_AVAILABLE")

# --- Swap runtime ---
SWAP_LINES=$(tail -n +2 /proc/swaps 2>/dev/null | wc -l | tr -d ' ')
SWAP_STATUS="FAIL:${SWAP_LINES}_active_swap_devices"
[ "$SWAP_LINES" = "0" ] && SWAP_STATUS="PASS:no_swap_active"

# --- /proc/swaps raw ---
SWAP_RAW=$(cat /proc/swaps 2>/dev/null || echo "NOT_AVAILABLE")

# --- Root filesystem mount ---
ROOT_MOUNT=$(grep ' / ' /proc/mounts 2>/dev/null | head -1 || true)
ROOT_RO="NOT_AVAILABLE"
echo "$ROOT_MOUNT" | grep -qE '\bro\b'  && ROOT_RO="PASS:read_only"
echo "$ROOT_MOUNT" | grep -qE '\brw\b'  && ROOT_RO="FAIL:read_write"

# --- tmpfs mounts ---
TMP_MOUNT_LINE=$(grep -w '/tmp' /proc/mounts 2>/dev/null | head -1 || true)
HOME_MOUNT_LINE=$(grep -w '/home/exam' /proc/mounts 2>/dev/null | head -1 || true)
SHM_MOUNT_LINE=$(grep -w '/dev/shm' /proc/mounts 2>/dev/null | head -1 || true)
VARLOG_MOUNT_LINE=$(grep -w '/var/log' /proc/mounts 2>/dev/null | head -1 || true)

check_tmpfs_flags() {
    local line="$1" path="$2"
    if [ -z "$line" ]; then echo "FAIL:not_mounted"; return; fi
    if ! echo "$line" | grep -q "tmpfs"; then echo "FAIL:not_tmpfs"; return; fi
    local flags=""
    echo "$line" | grep -q "noexec" && flags="${flags}noexec,"
    echo "$line" | grep -q "nosuid" && flags="${flags}nosuid,"
    echo "$line" | grep -q "nodev"  && flags="${flags}nodev,"
    if echo "$line" | grep -q "noexec" && echo "$line" | grep -q "nosuid" && echo "$line" | grep -q "nodev"; then
        echo "PASS:${flags%,}"
    else
        echo "FAIL:missing_flags:${flags}:full_opts=$(echo "$line" | awk '{print $4}')"
    fi
}

TMP_STATUS=$(check_tmpfs_flags "$TMP_MOUNT_LINE" "/tmp")
HOME_STATUS=$(check_tmpfs_flags "$HOME_MOUNT_LINE" "/home/exam")
# /dev/shm is an API tmpfs: require nosuid,nodev and verify noexec is absent
SHM_STATUS="NOT_AVAILABLE"
if echo "$SHM_MOUNT_LINE" | grep -q "tmpfs"; then
    if echo "$SHM_MOUNT_LINE" | grep -q "nosuid" && \
       echo "$SHM_MOUNT_LINE" | grep -q "nodev" && \
       ! echo "$SHM_MOUNT_LINE" | grep -q "noexec"; then
        SHM_STATUS="PASS:nosuid,nodev (noexec omitted per §5 Chromium exception)"
    else
        SHM_STATUS="FAIL:/dev/shm must have nosuid,nodev and keep exec enabled"
    fi
else
    SHM_STATUS="FAIL:/dev/shm not mounted as tmpfs"
fi
VARLOG_STATUS="NOT_AVAILABLE"
echo "$VARLOG_MOUNT_LINE" | grep -q "tmpfs" && \
    VARLOG_STATUS="PASS:/var/log is tmpfs" || \
    VARLOG_STATUS="FAIL:/var/log not tmpfs"

# --- Internal disk ---
INTERNAL_MOUNTS=$(grep -E '^/dev/(sd[a-z]|nvme[0-9]|hd[a-z])' /proc/mounts 2>/dev/null | \
    grep -v '\bnoauto\b' || true)
DISK_STATUS="FAIL:internal_mounts_found:${INTERNAL_MOUNTS}"
[ -z "$INTERNAL_MOUNTS" ] && DISK_STATUS="PASS:no_internal_mounts"

# --- Firewall ---
FW_STATUS="NOT_AVAILABLE"
if command -v nft >/dev/null 2>&1; then
    NFT_IN=$(nft list chain inet filter input 2>/dev/null | grep "policy" || true)
    NFT_OUT=$(nft list chain inet filter output 2>/dev/null | grep "policy" || true)
    if echo "$NFT_IN" | grep -q "policy drop" && echo "$NFT_OUT" | grep -q "policy drop"; then
        FW_STATUS="PASS:default-deny on input+output"
    else
        FW_STATUS="FAIL:nftables not default-deny"
    fi
fi

# --- AppArmor ---
AA_CHROMIUM="NOT_AVAILABLE"
AA_STATE=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "N")
if [ "$AA_STATE" = "Y" ]; then
    AA_PROFILE=$(cat /sys/kernel/security/apparmor/profiles 2>/dev/null | grep "chromium" | head -1 || true)
    if echo "$AA_PROFILE" | grep -q "(enforce)"; then
        AA_CHROMIUM="PASS:enforce"
    elif echo "$AA_PROFILE" | grep -q "(complain)"; then
        AA_CHROMIUM="FAIL:complain_mode"
    else
        AA_CHROMIUM="BLOCKED:profile_not_loaded"
    fi
fi

# --- SSH listener ---
SSH_STATUS="NOT_AVAILABLE"
if command -v ss >/dev/null 2>&1; then
    SSH_LISTEN=$(ss -tlnp 2>/dev/null | grep ':22 ' || true)
    [ -z "$SSH_LISTEN" ] && SSH_STATUS="PASS:no_sshd_listening" || \
        SSH_STATUS="FAIL:sshd_listening:${SSH_LISTEN}"
fi

# --- USB authorization default ---
USB_DEFAULT="NOT_AVAILABLE"
USB_BLOCK=0; USB_TOTAL=0
for ctrl in /sys/bus/usb/devices/usb*; do
    [ -f "$ctrl/authorized_default" ] || continue
    USB_TOTAL=$((USB_TOTAL+1))
    VAL=$(cat "$ctrl/authorized_default" 2>/dev/null || echo "-1")
    [ "$VAL" = "0" ] && USB_BLOCK=$((USB_BLOCK+1))
done
if [ "$USB_TOTAL" -eq 0 ]; then
    USB_DEFAULT="BLOCKED:no_usb_controllers_found"
elif [ "$USB_BLOCK" -eq "$USB_TOTAL" ]; then
    USB_DEFAULT="PASS:all_${USB_TOTAL}_controllers_set_authorized_default=0"
else
    USB_DEFAULT="FAIL:only_${USB_BLOCK}_of_${USB_TOTAL}_controllers_set_to_0"
fi
USBGUARD_STATUS="NOT_AVAILABLE"
if command -v usbguard >/dev/null 2>&1; then
    if systemctl is-active --quiet usbguard.service && usbguard list-rules >/dev/null 2>&1; then
        USBGUARD_STATUS="PASS:service_active_and_policy_interface_responsive"
    else
        USBGUARD_STATE=$(systemctl is-active usbguard.service 2>/dev/null || echo "inactive")
        USBGUARD_STATUS="FAIL:service_${USBGUARD_STATE}_or_policy_interface_unresponsive"
    fi
fi

# --- Chromium policy ---
POLICY_FILE="/etc/chromium/policies/managed/examos_policies.json"
POLICY_STATUS="NOT_AVAILABLE"
if [ -f "$POLICY_FILE" ]; then
    if python3 -c "
import json,sys
d=json.load(open('$POLICY_FILE'))
bl=d.get('URLBlocklist',[])
al=d.get('URLAllowlist',[])
ok = ('*' in bl) and ('https://*' not in al) and (d.get('DeveloperToolsAvailability')==2) and (d.get('DownloadRestrictions')==3)
sys.exit(0 if ok else 1)
" 2>/dev/null; then
        POLICY_STATUS="PASS"
    else
        POLICY_STATUS="FAIL:policy_misconfigured"
    fi
fi

# ---------------------------------------------------------------------------
# Write JSON report
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$REPORT_OUT")"
cat > "$REPORT_OUT" <<JSONEOF
{
  "tool": "p2-health-report",
  "timestamp": "$(ts)",
  "buildId": "${IMG_BUILD_ID}",
  "kernelVersion": "${IMG_KERNEL}",
  "chromiumVersion": "${IMG_CHROMIUM}",
  "gitCommit": "${GIT_COMMIT}",
  "cmdline": "$(echo "$CMDLINE" | head -c 512)",
  "domains": {
    "lockdown": {
      "cmdline_lockdown": "${CMDLINE_LOCKDOWN}",
      "lockdown_sys": "${LOCKDOWN_SYS}",
      "cmdline_module_sig_enforce": "${CMDLINE_MODSIG}",
      "cmdline_iommu": "${CMDLINE_IOMMU}"
    },
    "sysctl": {
      "ptrace_scope": "${SCTL_PTRACE}",
      "unprivileged_bpf_disabled": "${SCTL_BPF}",
      "sysrq": "${SCTL_SYSRQ}",
      "kptr_restrict": "${SCTL_KPTR}",
      "core_pattern": "${SCTL_CORE_PAT}",
      "suid_dumpable": "${SCTL_SUID_DUMP}",
      "swappiness": "${SCTL_SWAP}",
      "ipv6_disabled_all": "${SCTL_IPV6_ALL}",
      "ipv6_disabled_default": "${SCTL_IPV6_DEF}",
      "dmesg_restrict": "${SCTL_DMESG}",
      "perf_event_paranoid": "${SCTL_PERF}"
    },
    "modulelock": {
      "modules_disabled": "${MOD_LOCK_STATUS}",
      "modules_disabled_raw": "${MOD_DISABLED_VAL}"
    },
    "swap": {
      "status": "${SWAP_STATUS}",
      "proc_swaps": "$(echo "$SWAP_RAW" | head -5 | tr '\n' '|')"
    },
    "coredump": {
      "core_pattern": "${SCTL_CORE_PAT}",
      "suid_dumpable": "${SCTL_SUID_DUMP}"
    },
    "filesystem": {
      "root_readonly": "${ROOT_RO}",
      "tmp_noexec": "${TMP_STATUS}",
      "home_exam_noexec": "${HOME_STATUS}",
      "dev_shm": "${SHM_STATUS}",
      "var_log_tmpfs": "${VARLOG_STATUS}",
      "internal_disk": "${DISK_STATUS}"
    },
    "firewall": {
      "nftables_default_deny": "${FW_STATUS}"
    },
    "apparmor": {
      "chromium_profile": "${AA_CHROMIUM}"
    },
    "ssh": {
      "no_sshd_listener": "${SSH_STATUS}"
    },
    "usb": {
      "authorized_default_zero": "${USB_DEFAULT}",
      "usbguard_runtime": "${USBGUARD_STATUS}"
    },
    "chromium_policy": {
      "policy_file_valid": "${POLICY_STATUS}"
    }
  }
}
JSONEOF

echo "=== [P2-HEALTH] Report written: ${REPORT_OUT} ==="
cat "$REPORT_OUT"
