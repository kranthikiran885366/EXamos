#!/usr/bin/env bash
# =============================================================================
# SPPIO / ExamOS — A/B Slot Health Commit & Automatic Rollback Gate
#
# Executed by examos-ab-commit.service after dm-verity, BPF-LSM, PFR, and
# sppio-securityd reach healthy state.
# If verification fails and the standby slot is marked healthy, decrements
# tries_remaining or triggers immediate rollback to the standby slot.
# =============================================================================
set -euo pipefail

SLOTS_FILE="${SLOTS_FILE:-/etc/examos/ab-slots.json}"
PFR_STATUS="${PFR_STATUS:-/run/examos/pfr-status.json}"

log()  { echo "[ab-commit] $*"; }
fail() { echo "[ab-commit] FAIL: $*" >&2; exit 1; }

[ -f "$SLOTS_FILE" ] || fail "Missing A/B slot state: $SLOTS_FILE"
command -v jq >/dev/null 2>&1 || fail "jq is required"

ACTIVE_SLOT=$(jq -r '.active_slot' "$SLOTS_FILE")
STANDBY_SLOT=$([ "$ACTIVE_SLOT" = "A" ] && echo "B" || echo "A")
TRIES_LEFT=$(jq -r --arg s "$ACTIVE_SLOT" '.slots[$s].tries_remaining // 0' "$SLOTS_FILE")

switch_bootloader_slot() {
    local target_slot="$1"
    local entry="examos-slot-${target_slot,,}"
    if command -v bootctl >/dev/null 2>&1 && [ -d /boot/efi/loader/entries ]; then
        bootctl set-default "${entry}.conf" || true
    elif command -v grub-editenv >/dev/null 2>&1 && [ -f /boot/grub/grubenv ]; then
        grub-editenv /boot/grub/grubenv set next_entry="$entry" saved_entry="$entry" || true
    elif command -v efibootmgr >/dev/null 2>&1; then
        local bootnum
        bootnum=$(efibootmgr | awk -v pat="ExamOS.*Slot ${target_slot}" '$0 ~ pat {gsub(/[^0-9A-Fa-f]/,"",$1); print substr($1,1,4); exit}')
        [ -n "$bootnum" ] && efibootmgr --bootnext "$bootnum" >/dev/null 2>&1 || true
    fi
}

trigger_rollback() {
    local why="$1"
    log "Health gate failed on slot $ACTIVE_SLOT ($why); switching bootloader to $STANDBY_SLOT"
    jq --arg a "$ACTIVE_SLOT" --arg s "$STANDBY_SLOT" \
        '.slots[$a].boot_successful = false | .slots[$a].tries_remaining = 0 | .active_slot = $s' \
        "$SLOTS_FILE" > "${SLOTS_FILE}.tmp" && mv "${SLOTS_FILE}.tmp" "$SLOTS_FILE"
    switch_bootloader_slot "$STANDBY_SLOT"
    systemctl reboot || true
    exit 1
}

if [ "$TRIES_LEFT" -le 0 ]; then
    trigger_rollback "boot attempt budget exhausted"
fi

# Decrement remaining tries before verification completes
jq --arg s "$ACTIVE_SLOT" '.slots[$s].tries_remaining = ((.slots[$s].tries_remaining // 1) - 1)' \
    "$SLOTS_FILE" > "${SLOTS_FILE}.tmp" && mv "${SLOTS_FILE}.tmp" "$SLOTS_FILE"

# 1. Verify dm-verity active device is clean (mandatory)
if ! command -v veritysetup >/dev/null 2>&1 || ! dmsetup info root_verity >/dev/null 2>&1; then
    trigger_rollback "dm-verity root_verity device missing"
fi
veritysetup status root_verity | grep -q "status:.*verified" || trigger_rollback "dm-verity corruption detected"

# 2. Verify BPF-LSM pinned maps and attached program exist (mandatory)
if [ ! -d /sys/fs/bpf/examos ] || ! bpftool prog show pinned /sys/fs/bpf/examos >/dev/null 2>&1; then
    trigger_rollback "BPF-LSM runtime hooks not attached"
fi

# 3. Verify sppio-securityd is active (mandatory)
if ! systemctl is-active --quiet sppio-securityd.service; then
    trigger_rollback "sppio-securityd is not active"
fi

# 4. Verify PFR SP 800-193 status is PASS (mandatory)
[ -f "$PFR_STATUS" ] || trigger_rollback "Missing PFR SP 800-193 report"
PFR_OK=$(jq -r '.status' "$PFR_STATUS")
[ "$PFR_OK" = "PASS" ] || trigger_rollback "NIST SP 800-193 PFR check failed ($PFR_OK)"

# Mark active slot boot_successful, reset tries_remaining, and pin bootloader entry
MAX_TRIES=$(jq -r '.max_boot_tries // 3' "$SLOTS_FILE")
jq --arg s "$ACTIVE_SLOT" --argjson m "$MAX_TRIES" \
    '.slots[$s].boot_successful = true | .slots[$s].tries_remaining = $m' \
    "$SLOTS_FILE" > "${SLOTS_FILE}.tmp" && mv "${SLOTS_FILE}.tmp" "$SLOTS_FILE"
switch_bootloader_slot "$ACTIVE_SLOT"

log "Slot $ACTIVE_SLOT committed as verified and healthy."
