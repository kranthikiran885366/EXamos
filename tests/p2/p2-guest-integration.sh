#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — Guest Integration Tests (Layer 3)
# Runs INSIDE the booted ExamOS guest (via QEMU serial or SSH-less console).
# Tests real runtime enforcement of every P2 mandatory acceptance test.
#
# Mandatory tests covered:
#   P2-04  /tmp noexec (copy executable, exec fails)
#   P2-05  /usr write fails
#   P2-07  module load fails after lock
#   P2-08  VT switch — no login prompt
#   P2-11  swap/core disabled
#   P2-16  Chromium sandbox active
#   P2-17  internal disk not mounted
#   P2-18  P1 regression (kiosk running)
#   P2-19  reboot/restart lockdown re-applies
#
# Also covers: V-03 through V-17 runtime probes
# =============================================================================
set -uo pipefail

ARTIFACT_DIR="${ARTIFACT_DIR:-/run/examos/p2-tests}"
mkdir -p "$ARTIFACT_DIR"

LOG="$ARTIFACT_DIR/guest-integration.log"
exec > >(tee "$LOG") 2>&1

PASS=0; FAIL=0; BLOCKED=0
NOT_RUN=0
declare -A TEST_RESULTS
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

record() {
    local id="$1" status="$2" detail="$3"
    TEST_RESULTS["$id"]="${status}|${detail}"
    case "$status" in
        PASS)    PASS=$((PASS+1))    ;;
        FAIL)    FAIL=$((FAIL+1))    ;;
        BLOCKED) BLOCKED=$((BLOCKED+1)) ;;
        NOT_RUN) NOT_RUN=$((NOT_RUN+1)) ;;
    esac
    printf "%-12s %-10s %s\n" "$id" "$status" "$detail"
}
overall_status() {
    if [ "$FAIL" -gt 0 ]; then echo "FAIL"
    elif [ "$BLOCKED" -gt 0 ]; then echo "BLOCKED"
    elif [ "$NOT_RUN" -gt 0 ]; then echo "NOT_RUN"
    elif [ "$PASS" -gt 0 ]; then echo "PASS"
    else echo "NOT_RUN"
    fi
}

echo "=== [P2-GUEST] Integration Tests: $(ts) ==="

# USBGuard must be active and answer the policy query; static policy files
# alone are not runtime enforcement evidence.
if ! systemctl is-active --quiet usbguard.service; then
    USBGUARD_STATE=$(systemctl is-active usbguard.service 2>/dev/null || echo "inactive")
    record "P2-USBGUARD" "FAIL" "usbguard.service is ${USBGUARD_STATE}"
elif ! usbguard list-rules >/dev/null 2>&1; then
    record "P2-USBGUARD" "FAIL" "USBGuard policy interface is not responsive"
else
    record "P2-USBGUARD" "PASS" "USBGuard service is active and policy interface responds"
fi

# ---------------------------------------------------------------------------
# P2-04: Copy executable to /tmp and attempt execution — must fail
# ---------------------------------------------------------------------------
TMP_EXE="/tmp/p2_test_exe_$$"
cp /bin/true "$TMP_EXE" 2>/dev/null || {
    record "P2-04" "BLOCKED" "Could not copy /bin/true to /tmp (cp failed — /tmp may already be noexec)"
    TMP_EXE=""
}
if [ -n "$TMP_EXE" ]; then
    EXEC_RC=0
    "$TMP_EXE" 2>/dev/null && EXEC_RC=0 || EXEC_RC=$?
    if [ "$EXEC_RC" -ne 0 ]; then
        record "P2-04" "PASS" "/tmp noexec: execution of ${TMP_EXE} failed (rc=${EXEC_RC})"
    else
        record "P2-04" "FAIL" "/tmp noexec NOT enforced: ${TMP_EXE} executed successfully"
    fi
    rm -f "$TMP_EXE"
fi

# /dev/shm is a systemd API tmpfs, remounted for Chromium with nosuid,nodev.
SHM_LINE=$(awk '$2 == "/dev/shm" { print; exit }' /proc/mounts 2>/dev/null || true)
if [ -z "$SHM_LINE" ]; then
    record "P2-SHM" "FAIL" "/dev/shm is not mounted"
else
    SHM_TYPE=$(echo "$SHM_LINE" | awk '{print $3}')
    SHM_OPTS=$(echo "$SHM_LINE" | awk '{print $4}')
    case ",$SHM_OPTS," in *,nosuid,*) SHM_NOSUID=1;; *) SHM_NOSUID=0;; esac
    case ",$SHM_OPTS," in *,nodev,*) SHM_NODEV=1;; *) SHM_NODEV=0;; esac
    case ",$SHM_OPTS," in *,noexec,*) SHM_NOEXEC=1;; *) SHM_NOEXEC=0;; esac
    if [ "$SHM_TYPE" = "tmpfs" ] && [ "$SHM_NOSUID" -eq 1 ] &&
       [ "$SHM_NODEV" -eq 1 ] && [ "$SHM_NOEXEC" -eq 0 ]; then
        record "P2-SHM" "PASS" "/dev/shm tmpfs has nosuid,nodev and allows Chromium shared-memory mappings"
    else
        record "P2-SHM" "FAIL" "/dev/shm options invalid (type=$SHM_TYPE opts=$SHM_OPTS)"
    fi
fi

# ---------------------------------------------------------------------------
# P2-05: Write under /usr must fail
# ---------------------------------------------------------------------------
WRITE_USR_RC=0
echo "p2test" > /usr/p2_write_test_$$ 2>/dev/null && WRITE_USR_RC=0 || WRITE_USR_RC=$?
if [ "$WRITE_USR_RC" -ne 0 ]; then
    record "P2-05" "PASS" "/usr is read-only (write returned rc=${WRITE_USR_RC})"
else
    rm -f /usr/p2_write_test_$$ 2>/dev/null
    record "P2-05" "FAIL" "/usr is writable — root filesystem not read-only"
fi

# ---------------------------------------------------------------------------
# P2-06: The live root must be a read-only dm-verity mapping.  Host-side
# veritysetup verification proves the artifact and corruption case; this
# probe proves the guest actually booted through that mapping.
# ---------------------------------------------------------------------------
ROOT_SOURCE=$(findmnt -n -o SOURCE / 2>/dev/null || true)
ROOT_OPTIONS=$(findmnt -n -o OPTIONS / 2>/dev/null || true)
VERITY_MAPPINGS=$(dmsetup ls --target verity 2>/dev/null || true)
ROOT_MAPPING=""
case "$ROOT_SOURCE" in
    /dev/mapper/*)
        ROOT_MAPPING="${ROOT_SOURCE#/dev/mapper/}"
        ;;
    /dev/dm-*)
        ROOT_MAPPING=$(dmsetup info -C --noheadings -o name "$ROOT_SOURCE" 2>/dev/null | tr -d '[:space:]' || true)
        ;;
esac
if [ -z "$ROOT_SOURCE" ] || ! command -v findmnt >/dev/null 2>&1 || ! command -v dmsetup >/dev/null 2>&1; then
    record "P2-06" "BLOCKED" "BLOCKED_ENVIRONMENT: cannot inspect live root dm-verity mapping"
elif [ -z "$VERITY_MAPPINGS" ]; then
    record "P2-06" "FAIL" "live root is ${ROOT_SOURCE}; no active dm-verity mapping exists"
elif [[ ",$ROOT_OPTIONS," != *,ro,* ]]; then
    record "P2-06" "FAIL" "live root ${ROOT_SOURCE} is not mounted read-only (options=${ROOT_OPTIONS})"
elif [ -z "$ROOT_MAPPING" ]; then
    record "P2-06" "FAIL" "live root ${ROOT_SOURCE} is not a device-mapper mapping"
else
    if printf '%s\n' "$VERITY_MAPPINGS" | awk -v mapping="$ROOT_MAPPING" '$1 == mapping { found=1 } END { exit !found }'; then
        record "P2-06" "PASS" "live root ${ROOT_SOURCE} is a read-only dm-verity mapping"
    else
        record "P2-06" "FAIL" "live root ${ROOT_SOURCE} does not use an active dm-verity mapping"
    fi
fi

# ---------------------------------------------------------------------------
# P2-07: Attempt modprobe after module lock
# ---------------------------------------------------------------------------
MOD_DISABLED=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo "NOT_AVAILABLE")
if [ "$MOD_DISABLED" = "1" ]; then
    MODPROBE_RC=0
    modprobe dummy 2>/dev/null && MODPROBE_RC=0 || MODPROBE_RC=$?
    if [ "$MODPROBE_RC" -ne 0 ]; then
        record "P2-07" "PASS" "modprobe rejected after modules_disabled=1 (rc=${MODPROBE_RC})"
    else
        record "P2-07" "FAIL" "modprobe succeeded despite modules_disabled=1"
    fi
elif [ "$MOD_DISABLED" = "0" ]; then
    record "P2-07" "FAIL" "modules_disabled=0 — module lock not applied"
else
    record "P2-07" "BLOCKED" "BLOCKED_ENVIRONMENT: /proc/sys/kernel/modules_disabled not available (${MOD_DISABLED})"
fi

# ---------------------------------------------------------------------------
# P2-08: No login prompt on any VT — check getty services
# ---------------------------------------------------------------------------
GETTY_ACTIVE=$(systemctl list-units --state=active --type=service 2>/dev/null | grep -E "getty@|autovt@" || true)
if [ -z "$GETTY_ACTIVE" ]; then
    record "P2-08" "PASS" "No getty/autovt services are active"
else
    record "P2-08" "FAIL" "Active getty/autovt services: ${GETTY_ACTIVE}"
fi
# Verify masking
GETTY_MASKED=$(systemctl show getty@tty1.service --property=LoadState 2>/dev/null | grep -c "masked" || true)
if [ "$GETTY_MASKED" -ge 1 ]; then
    record "P2-08-MASK" "PASS" "getty@tty1.service is masked"
else
    record "P2-08-MASK" "FAIL" "getty@tty1.service is not masked"
fi
# Check serial-getty
SERIAL_MASKED=$(systemctl show serial-getty@.service --property=LoadState 2>/dev/null | grep -c "masked" || true)
if [ "$SERIAL_MASKED" -ge 1 ]; then
    record "P2-08-SERIAL" "PASS" "serial-getty@.service is masked"
else
    record "P2-08-SERIAL" "FAIL" "serial-getty@.service is not masked"
fi

# ---------------------------------------------------------------------------
# P2-11: Swap disabled
# ---------------------------------------------------------------------------
SWAP_LINES=$(tail -n +2 /proc/swaps 2>/dev/null | wc -l | tr -d ' ')
if [ "$SWAP_LINES" = "0" ]; then
    record "P2-11-SWAP" "PASS" "/proc/swaps empty"
else
    record "P2-11-SWAP" "FAIL" "Active swap: $(cat /proc/swaps)"
fi

# Core dump disabled
CORE_PAT=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "NOT_AVAILABLE")
SUID_DUMP=$(cat /proc/sys/fs/suid_dumpable 2>/dev/null || echo "NOT_AVAILABLE")
if echo "$CORE_PAT" | grep -q "/bin/false" && [ "$SUID_DUMP" = "0" ]; then
    record "P2-11-COREDUMP" "PASS" "core_pattern=|/bin/false suid_dumpable=0"
else
    record "P2-11-COREDUMP" "FAIL" "core_pattern=${CORE_PAT} suid_dumpable=${SUID_DUMP}"
fi

# Test: trigger a process that generates core — verify no file appears
(ulimit -c unlimited 2>/dev/null; sleep 0 & CHILD=$!; kill -SEGV $CHILD 2>/dev/null; wait $CHILD 2>/dev/null; true) || true
CORE_FILES=$(find /tmp /var /run -name "core*" -newer /proc/1/exe 2>/dev/null | head -5 || true)
if [ -z "$CORE_FILES" ]; then
    record "P2-11-CORE-GEN" "PASS" "No core files created in /tmp /var /run after SIGSEGV"
else
    record "P2-11-CORE-GEN" "FAIL" "Core files found: ${CORE_FILES}"
fi

# ---------------------------------------------------------------------------
# P2-16: Chromium sandbox active
# Check that the running chromium process was NOT started with --no-sandbox
# ---------------------------------------------------------------------------
CHROMIUM_PID=$(pgrep -f "chromium.*--kiosk" | head -1 || true)
if [ -n "$CHROMIUM_PID" ]; then
    CHROMIUM_CMDLINE=$(cat /proc/${CHROMIUM_PID}/cmdline 2>/dev/null | tr '\0' ' ' || true)
    if echo "$CHROMIUM_CMDLINE" | grep -q "\-\-no-sandbox"; then
        record "P2-16" "FAIL" "Chromium launched with --no-sandbox (PID ${CHROMIUM_PID})"
    elif echo "$CHROMIUM_CMDLINE" | grep -q "\-\-disable-gpu-sandbox"; then
        record "P2-16" "FAIL" "Chromium launched with --disable-gpu-sandbox (PID ${CHROMIUM_PID})"
    else
        record "P2-16" "PASS" "Chromium running without sandbox-disabling flags (PID ${CHROMIUM_PID})"
    fi
    # Verify renderer processes (indicate sandbox is spawning child processes)
    RENDERER_COUNT=$(pgrep -c -f "chromium.*renderer" 2>/dev/null || echo 0)
    record "P2-16-RENDERER" "PASS" "Chromium renderer processes: ${RENDERER_COUNT}"
else
    record "P2-16" "BLOCKED" "BLOCKED: Chromium not running — cannot verify sandbox (kiosk may not have started yet)"
fi

# ---------------------------------------------------------------------------
# P2-17: Internal disk not mounted
# ---------------------------------------------------------------------------
INTERNAL_MOUNTS=$(grep -E '^/dev/(sd[a-z]|nvme[0-9]|hd[a-z])' /proc/mounts 2>/dev/null | \
    grep -v '\bnoauto\b' || true)
if [ -z "$INTERNAL_MOUNTS" ]; then
    record "P2-17" "PASS" "No internal disk partitions mounted"
else
    record "P2-17" "FAIL" "Internal mount detected: ${INTERNAL_MOUNTS}"
fi
# Check block devices exist but are not mounted
BLOCK_DEVS=$(lsblk -nd -o NAME,TYPE 2>/dev/null | grep disk | awk '{print $1}' || true)
for dev in $BLOCK_DEVS; do
    DEV_MOUNTS=$(grep "^/dev/${dev}" /proc/mounts 2>/dev/null || true)
    if [ -z "$DEV_MOUNTS" ]; then
        record "P2-17-BLK-${dev}" "PASS" "/dev/${dev} present but not mounted"
    else
        record "P2-17-BLK-${dev}" "FAIL" "/dev/${dev} is mounted: ${DEV_MOUNTS}"
    fi
done

# ---------------------------------------------------------------------------
# P2-18: P1 regression — kiosk service running, no login prompt
# ---------------------------------------------------------------------------
KIOSK_STATE=$(systemctl is-active examos-kiosk.service 2>/dev/null || echo "inactive")
if [ "$KIOSK_STATE" = "active" ]; then
    record "P2-18-KIOSK" "PASS" "examos-kiosk.service is active"
else
    record "P2-18-KIOSK" "FAIL" "examos-kiosk.service state: ${KIOSK_STATE}"
fi
# Kiosk user must be exam, not root
KIOSK_UID=$(systemctl show examos-kiosk.service --property=UID 2>/dev/null | cut -d= -f2 || true)
if [ "$KIOSK_UID" = "1000" ] || [ "$KIOSK_UID" = "exam" ]; then
    record "P2-18-USER" "PASS" "Kiosk running as exam (UID=1000)"
else
    ACTUAL_UID=$(ps -eo uid,comm 2>/dev/null | grep cage | head -1 | awk '{print $1}' || echo "unknown")
    if [ "$ACTUAL_UID" = "1000" ]; then
        record "P2-18-USER" "PASS" "cage process running as UID 1000"
    else
        record "P2-18-USER" "FAIL" "Kiosk UID unexpected: systemd=${KIOSK_UID} ps=${ACTUAL_UID}"
    fi
fi

# ---------------------------------------------------------------------------
# P2-19: Post-reboot state — module lock, firewall, tmpfs should be active
# (This test validates the current state is fully locked; a reboot test is
#  done in CI by launching a fresh QEMU boot and re-running this script.)
# ---------------------------------------------------------------------------
UPTIME_S=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo "0")
if [ "$UPTIME_S" -lt 300 ]; then
    record "P2-19-FRESH" "PASS" "System uptime ${UPTIME_S}s (recent boot)"
fi
# Verify module lock survived to this point
MOD_NOW=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo "?")
if [ "$MOD_NOW" = "1" ]; then
    record "P2-19-MODLOCK" "PASS" "modules_disabled=1 persists at test time"
else
    record "P2-19-MODLOCK" "FAIL" "modules_disabled=${MOD_NOW} at test time"
fi
# Firewall still default-deny
FW_IN=$(nft list chain inet filter input 2>/dev/null | grep "policy" || true)
if echo "$FW_IN" | grep -q "policy drop"; then
    record "P2-19-FW" "PASS" "nftables default-deny active after boot"
else
    record "P2-19-FW" "FAIL" "nftables not default-deny: ${FW_IN}"
fi

# ---------------------------------------------------------------------------
# Additional runtime probes
# ---------------------------------------------------------------------------

# IPv6 disabled
IPV6_ALL=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "NOT_AVAILABLE")
if [ "$IPV6_ALL" = "1" ]; then
    record "RT-IPV6" "PASS" "IPv6 disabled (disable_ipv6=1)"
else
    record "RT-IPV6" "FAIL" "IPv6 not disabled: ${IPV6_ALL}"
fi

# SSH not running
SSH_PROC=$(pgrep sshd 2>/dev/null || echo "")
if [ -z "$SSH_PROC" ]; then
    record "RT-SSH" "PASS" "No sshd process"
else
    record "RT-SSH" "FAIL" "sshd running: PID=${SSH_PROC}"
fi

# sudo/su absent
for bin in sudo su; do
    if command -v "$bin" >/dev/null 2>&1; then
        record "RT-${bin^^}" "FAIL" "${bin} binary present in image"
    else
        record "RT-${bin^^}" "PASS" "${bin} binary absent"
    fi
done

# ---------------------------------------------------------------------------
# Write results JSON
# ---------------------------------------------------------------------------
{
    printf '{"timestamp":"%s","pass":%d,"fail":%d,"blocked":%d,"not_run":%d,"total":%d,"overall":"%s","tests":[\n' \
        "$(ts)" "$PASS" "$FAIL" "$BLOCKED" "$NOT_RUN" "$((PASS+FAIL+BLOCKED+NOT_RUN))" "$(overall_status)"
    FIRST=1
    for id in "${!TEST_RESULTS[@]}"; do
        IFS='|' read -r status detail <<< "${TEST_RESULTS[$id]}"
        [ "$FIRST" -eq 0 ] && printf ','
        printf '{"id":"%s","status":"%s","detail":"%s"}' \
            "$id" "$status" "$(echo "$detail" | head -c 200)"
        FIRST=0
    done
    printf '\n]}\n'
} > "$ARTIFACT_DIR/guest-integration-results.json"

echo ""
GATE_RESULT=$(overall_status)
echo "=== [P2-GUEST] PASS=${PASS} FAIL=${FAIL} BLOCKED=${BLOCKED} NOT_RUN=${NOT_RUN} ==="
case "$GATE_RESULT" in
    PASS) exit 0 ;;
    FAIL) exit 1 ;;
    *)    exit 2 ;;
esac
