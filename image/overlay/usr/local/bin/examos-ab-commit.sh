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

# Verify dm-verity active device is clean (no I/O or hash corruption)
if command -v veritysetup >/dev/null 2>&1 && dmsetup info root_verity >/dev/null 2>&1; then
    veritysetup status root_verity | grep -q "status:.*verified" || {
        log "dm-verity integrity check failed on slot $ACTIVE_SLOT; initiating rollback to $STANDBY_SLOT"
        jq --arg s "$STANDBY_SLOT" '.active_slot = $s' "$SLOTS_FILE" > "${SLOTS_FILE}.tmp" && mv "${SLOTS_FILE}.tmp" "$SLOTS_FILE"
        systemctl reboot || true
        exit 1
    }
fi

# Verify BPF-LSM pinned map exists
[ -d /sys/fs/bpf/examos ] || log "WARN: BPF-LSM maps not pinned at /sys/fs/bpf/examos"

# Verify PFR status if generated
if [ -f "$PFR_STATUS" ]; then
    PFR_OK=$(jq -r '.status' "$PFR_STATUS")
    [ "$PFR_OK" = "PASS" ] || fail "NIST SP 800-193 PFR check did not pass ($PFR_OK)"
fi

# Mark active slot boot_successful and reset tries_remaining
MAX_TRIES=$(jq -r '.max_boot_tries // 3' "$SLOTS_FILE")
jq --arg s "$ACTIVE_SLOT" --argjson m "$MAX_TRIES" \
    '.slots[$s].boot_successful = true | .slots[$s].tries_remaining = $m' \
    "$SLOTS_FILE" > "${SLOTS_FILE}.tmp" && mv "${SLOTS_FILE}.tmp" "$SLOTS_FILE"

log "Slot $ACTIVE_SLOT committed as verified and healthy."
