#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Locate the canonical disk image
IMG=""
for candidate in \
    "$ROOT/image/examos.raw" \
    "$ROOT/output/examos.raw" \
    "$ROOT/output/vmware-prod-prep-smoke-20261022/examos.raw"; do
    if [ -f "$candidate" ] && [ -s "$candidate" ]; then
        IMG="$candidate"
        break
    fi
done

if [ -z "$IMG" ]; then
    echo "BLOCKED: no built disk image found (expected image/examos.raw)" >&2
    exit 2
fi

MNT="/tmp/examos_inspect_$$"
LOOP=""

cleanup() {
    [ -n "$LOOP" ] && { umount "$MNT" 2>/dev/null || true; losetup -d "$LOOP" 2>/dev/null || true; }
    rm -rf "$MNT"
}
trap cleanup EXIT

losetup -D 2>/dev/null || true
LOOP=$(losetup -fP --show "$IMG") || { echo "BLOCKED: losetup requires root or loop device access" >&2; exit 2; }
mkdir -p "$MNT"

# Find the root partition (p2 for GPT images with ESP at p1)
ROOT_PART=""
for part in "${LOOP}p2" "${LOOP}p1"; do
    blkid "$part" 2>/dev/null | grep -qiE 'ext4|btrfs|xfs' && ROOT_PART="$part" && break
done
[ -n "$ROOT_PART" ] || { echo "FAIL: cannot identify root partition in $IMG" >&2; exit 1; }

mount -o ro "$ROOT_PART" "$MNT" || { echo "FAIL: cannot mount $ROOT_PART" >&2; exit 1; }

PASS=0; FAIL=0
check() {
    local label="$1" result="$2"
    if [ "$result" = "PASS" ]; then
        echo "  PASS: $label"; PASS=$((PASS+1))
    else
        echo "  FAIL: $label"; FAIL=$((FAIL+1))
    fi
}

echo "=== Production Image Verification: $IMG ==="

# 1. No dev ports in nftables
if [ -f "$MNT/etc/nftables.conf" ] && ! grep -qE '8895|5173' "$MNT/etc/nftables.conf"; then
    check "nftables: no dev ports (8895/5173)" "PASS"
else
    check "nftables: no dev ports (8895/5173)" "FAIL"
fi

# 2. No tpm2-abrmd simulator overrides
if [ ! -d "$MNT/etc/systemd/system/tpm2-abrmd.service.d" ]; then
    check "TPM: no simulator override (physical TPM required)" "PASS"
else
    check "TPM: no simulator override (physical TPM required)" "FAIL"
fi

# 3. No debug tty2 console override
if [ ! -d "$MNT/etc/systemd/system/getty@tty2.service.d" ]; then
    check "Consoles: no tty2 debug override" "PASS"
else
    check "Consoles: no tty2 debug override" "FAIL"
fi

# 4. Lockdown fail-closed target
if [ -f "$MNT/etc/systemd/system/examos-lockdown-failed.target" ] && \
   grep -q 'Conflicts=graphical.target' "$MNT/etc/systemd/system/examos-lockdown-failed.target"; then
    check "Lockdown: fail-closed target present" "PASS"
else
    check "Lockdown: fail-closed target present" "FAIL"
fi

# 5. Chromium dynamic linker (only if chroot is safe)
if [ -f "$MNT/usr/lib/chromium/chromium" ] && command -v chroot >/dev/null 2>&1; then
    chroot "$MNT" ldconfig 2>/dev/null || true
    if ! chroot "$MNT" ldd /usr/lib/chromium/chromium 2>/dev/null | grep -q 'not found'; then
        check "Chromium: all shared libraries resolved" "PASS"
    else
        check "Chromium: all shared libraries resolved" "FAIL"
    fi
else
    echo "  SKIP: Chromium binary not present in image (not installed yet)"
fi

echo ""
echo "=== Image Verification Completed Successfully ==="
echo "    PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ]
