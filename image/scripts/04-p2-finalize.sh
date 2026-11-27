#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — deferred systemd unit masks
#
# mkosi applies "systemctl preset-all" after the post-install script. Masking a
# unit before that step makes preset-all fail whenever a vendor preset still
# tries to enable the unit, which aborts the image build. The post-install
# script therefore only records the units that must be masked and disables
# them; this finalize script applies the real mask symlinks afterwards.
#
# Finalize scripts run after preset-all, depmod, firstboot and hwdb, so the
# masks are still baked into the image and active from the very first boot.
# =============================================================================
set -euo pipefail

BR="${BUILDROOT:-/buildroot}"
MASK_LIST="${BR}/etc/examos/p2-mask.list"

echo "=== [ExamOS P2] Applying deferred unit masks after preset-all ==="

if [ ! -s "$MASK_LIST" ]; then
    echo "[P2-FINALIZE] FAIL: deferred mask list is missing: ${MASK_LIST}" >&2
    exit 1
fi

masked=0
while IFS= read -r unit; do
    [ -n "$unit" ] || continue
    if systemctl --root="${BR}" mask "$unit" >/dev/null 2>&1; then
        masked=$((masked + 1))
    else
        echo "[P2-FINALIZE] WARN: could not mask ${unit}" >&2
    fi
done < "$MASK_LIST"

# These paths are the difference between "no login" and "a login prompt on the
# console". Verify the symlinks explicitly instead of trusting systemctl's exit
# status alone.
for unit in \
    getty@tty1.service getty@tty2.service getty@tty3.service \
    getty@tty4.service getty@tty5.service getty@tty6.service \
    getty@tty7.service getty@tty8.service getty@tty9.service \
    autovt@.service serial-getty@.service \
    emergency.service emergency.target rescue.service rescue.target \
    systemd-debug-shell.service; do
    link="${BR}/etc/systemd/system/${unit}"
    if [ ! -L "$link" ]; then
        echo "[P2-FINALIZE] FAIL: required login path is not masked: ${unit}" >&2
        exit 1
    fi
    if [ "$(readlink "$link")" != "/dev/null" ]; then
        echo "[P2-FINALIZE] FAIL: mask for ${unit} does not point to /dev/null" >&2
        exit 1
    fi
done

# The list is build-time state only; do not ship it as runtime configuration.
rm -f "$MASK_LIST"

echo "[P2-FINALIZE] ${masked} unit masks applied; all console login paths verified masked"

# Verify that every shipped native binary resolves all shared libraries inside the image
echo "=== [ExamOS P2] Verifying shipped binary shared-library linkage ==="
for bin in /usr/local/bin/examos-proctor /usr/local/bin/examos-server /usr/local/bin/examos-agent /usr/local/bin/examos-kiosk-launcher; do
    if [ ! -x "${BR}${bin}" ]; then
        echo "[P2-FINALIZE] FAIL: missing shipped binary ${bin}" >&2
        exit 1
    fi
    missing_libs="$(chroot "${BR}" /usr/bin/ldd "${bin}" 2>&1 | grep 'not found' || true)"
    if [ -n "$missing_libs" ]; then
        echo "[P2-FINALIZE] FAIL: ${bin} has unresolved shared libraries in image:" >&2
        echo "$missing_libs" >&2
        exit 1
    fi
done
echo "[P2-FINALIZE] All shipped binaries have complete shared-library linkage in image"
