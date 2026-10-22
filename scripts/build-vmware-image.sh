#!/usr/bin/env bash
# ExamOS VMware Image — inline build (runs as root in WSL)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Every invocation gets a new workspace and output directory. Never detach
# unrelated loop devices or remove another build's files.
WORKSPACE_PARENT="${EXAMOS_BUILD_WORKSPACE_ROOT:-${HOME:?HOME must be set}/.local/state/examos/build}"
PKG_CACHE="${EXAMOS_PACKAGE_CACHE_DIR:-${HOME:?HOME must be set}/.cache/examos/mkosi-packages}"
OUTPUT_PARENT="${EXAMOS_BUILD_OUTPUT_ROOT:-$ROOT/output}"
RUN_ID="${EXAMOS_BUILD_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
VMWARE_DEV_MODE="${EXAMOS_VMWARE_DEV_MODE:-0}"
if [[ "$VMWARE_DEV_MODE" != 0 && "$VMWARE_DEV_MODE" != 1 ]]; then
    echo "FATAL: EXAMOS_VMWARE_DEV_MODE must be 0 or 1." >&2
    exit 1
fi
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "FATAL: EXAMOS_BUILD_RUN_ID must be a filename-safe identifier." >&2
    exit 1
fi
mkdir -p "$WORKSPACE_PARENT" "$PKG_CACHE" "$OUTPUT_PARENT"
MKOSI_WS="$(mktemp -d "${WORKSPACE_PARENT%/}/examos-mkosi.XXXXXXXX")"
TMPDIR="$MKOSI_WS/tmp"
VMWARE_OUTPUT_DIR="${EXAMOS_VMWARE_OUTPUT_DIR:-$OUTPUT_PARENT/vmware-$RUN_ID}"
mkdir -p "$MKOSI_WS"/{build,cache,output} "$TMPDIR"
if [ -e "$VMWARE_OUTPUT_DIR" ]; then
    echo "FATAL: output path already exists; choose a new EXAMOS_BUILD_RUN_ID or EXAMOS_VMWARE_OUTPUT_DIR: $VMWARE_OUTPUT_DIR" >&2
    exit 1
fi
mkdir -p "$VMWARE_OUTPUT_DIR"
export TMPDIR TMP="$TMPDIR" TEMP="$TMPDIR"

MNT=""
LOOP=""
cleanup() {
    if [ -n "$MNT" ] && mountpoint -q "$MNT"; then
        umount "$MNT" || echo "WARNING: could not unmount this run's mount: $MNT" >&2
    fi
    if [ -n "$LOOP" ] && [ -b "$LOOP" ]; then
        losetup -d "$LOOP" || echo "WARNING: could not detach this run's loop device: $LOOP" >&2
    fi
}
trap cleanup EXIT

# ── Step 1: Compile binaries ────────────────────────────────────────
echo "=== Step 1/5: Compiling binaries ==="
make -C "$ROOT" all 2>&1 | tail -5
echo "  Done."

# ── Step 2: Stage overlay ───────────────────────────────────────────
echo "=== Step 2/5: Staging overlay ==="
STAGE="$MKOSI_WS/stage"
mkdir -p "$STAGE"
cp -a "$ROOT/image/overlay/." "$STAGE/"
# Remove static .wants directories from overlay so systemctl preset-all succeeds
rm -rf "$STAGE"/etc/systemd/system/*.wants

# Install compiled binaries
mkdir -p "$STAGE/usr/local/bin"
for bin in server/examos-server server/examos-db-migrate agent/examos-agent \
           kiosk/launcher/examos-kiosk-launcher proctoring/examos-proctor; do
    if [ -f "$ROOT/$bin" ]; then
        install -m 0755 "$ROOT/$bin" "$STAGE/usr/local/bin/"
        echo "  Installed $(basename "$bin")"
    fi
done
install -D -m 0755 "$ROOT/image/scripts/tpm-seal-secrets.sh" "$STAGE/usr/local/sbin/tpm-seal-secrets.sh"
install -D -m 0755 "$ROOT/image/scripts/generate-chromium-policy.sh" "$STAGE/usr/local/sbin/generate-chromium-policy.sh"
install -D -m 0755 "$ROOT/scripts/setup-postgres-tls.sh" "$STAGE/usr/local/sbin/examos-setup-postgres-tls"
install -D -m 0755 "$ROOT/scripts/provision-remote-postgres.sh" "$STAGE/usr/local/sbin/examos-provision-remote-postgres"
install -d "$STAGE/usr/share/examos/migrations"
install -m 0644 "$ROOT"/server/migrations/*.sql "$STAGE/usr/share/examos/migrations/"

# Optional local-only test profile. It never provisions credentials or trusts
# device/release evidence. The service remains bound to loopback and every
# production identity/attestation API remains unavailable until real setup.
if [[ "$VMWARE_DEV_MODE" == 1 ]]; then
    cat > "$STAGE/etc/systemd/system/examos-server.service" <<'UNIT'
[Unit]
Description=ExamOS VMware Development Server (loopback-only, unprovisioned)
ConditionPathExists=/etc/examos/vmware-development-mode
After=network.target
Before=examos-kiosk.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/examos-server
Restart=on-failure
RestartSec=3
Environment=EXAMOS_SERVER_PORT=8000
Environment=EXAMOS_LEDGER_PATH=/var/log/examos/event_ledger.log
Environment=EXAMOS_ALLOW_UNPROVISIONED_DEV=1
ProtectSystem=full
ProtectHome=yes
StateDirectory=examos
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
PrivateDevices=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/log/examos /etc/examos/exam.conf

[Install]
WantedBy=multi-user.target
UNIT
    install -m 0644 /dev/null "$STAGE/etc/examos/vmware-development-mode"
fi

# Keep the image unprovisioned. The copied overlay templates contain explicit
# NOT_PROVISIONED/NOT_CONFIGURED values and production services fail closed
# until the institution's deployment authority supplies device-specific
# configuration and TPM-sealed secrets after installation.

# Permissions
find "$STAGE" -type d -exec chmod 0755 {} + 2>/dev/null || true
find "$STAGE" -type f -exec chmod 0644 {} + 2>/dev/null || true
find "$STAGE/usr/local/bin" -type f -exec chmod 0755 {} + 2>/dev/null || true
find "$STAGE/usr/local/sbin" -type f -exec chmod 0755 {} + 2>/dev/null || true
chmod 0600 "$STAGE/etc/examos/admin.conf"
echo "  Overlay staged."

# ── Step 3: Build image with mkosi ──────────────────────────────────
echo "=== Step 3/5: Building image with mkosi (5-15 min) ==="
mkosi \
    --directory="$ROOT/image" \
    --output-directory="$MKOSI_WS/output" \
    --build-directory="$MKOSI_WS/build" \
    --cache-directory="$MKOSI_WS/cache" \
    --package-cache-directory="$PKG_CACHE" \
    --workspace-directory="$MKOSI_WS" \
    --extra-tree="$STAGE:/" \
    --force \
    build 2>&1 | tee "$MKOSI_WS/mkosi-build.log"

# Find output image
RAW=""
for f in "$MKOSI_WS/output/examos.raw" "$MKOSI_WS/output/examos" "$MKOSI_WS/output/examos.raw.raw"; do
    [ -f "$f" ] && [ -s "$f" ] && RAW="$f" && break
done
if [ -z "$RAW" ]; then
    RAW=$(find "$MKOSI_WS/output" -name '*.raw' -type f 2>/dev/null | head -1)
fi
if [ -z "$RAW" ] || [ ! -s "$RAW" ]; then
    echo "FATAL: No image found. Log snippet:"
    tail -n 50 "$MKOSI_WS/mkosi-build.log" || true
    exit 1
fi
echo "  Image: $RAW ($(du -sh "$RAW" | cut -f1))"

# ── Step 4: Patch image for VMware ──────────────────────────────────
echo "=== Step 4/5: Patching image for VMware boot ==="
MNT="$TMPDIR/rootfs"
mkdir -p "$MNT"
losetup -fP "$RAW"
LOOP=$(losetup -j "$RAW" | head -1 | cut -d: -f1)
echo "  Loop: $LOOP"

# Find root partition (ext4/btrfs/xfs)
ROOT_PART=""
for p in "${LOOP}p2" "${LOOP}p1" "${LOOP}p3"; do
    [ -b "$p" ] || continue
    FSTYPE=$(blkid -o value -s TYPE "$p" 2>/dev/null || true)
    if [ "$FSTYPE" = "ext4" ] || [ "$FSTYPE" = "btrfs" ] || [ "$FSTYPE" = "xfs" ]; then
        ROOT_PART="$p"
        break
    fi
done
if [ -z "$ROOT_PART" ]; then
    echo "FATAL: no root partition found"
    lsblk "$LOOP"
    losetup -d "$LOOP"
    exit 1
fi
mount "$ROOT_PART" "$MNT"

# Create a locked exam account if the base image does not contain one. Never
# assign a build-time password; operator access is provisioned separately.
if ! grep -q '^exam:' "$MNT/etc/passwd" 2>/dev/null; then
    chroot "$MNT" useradd -m -s /bin/bash -G video,render,input,audio,tty exam 2>/dev/null || true
    echo "  Exam account created without a password."
fi

# Set graphical.target as default
ln -sf /usr/lib/systemd/system/graphical.target \
    "$MNT/etc/systemd/system/default.target" 2>/dev/null || true

# Disable tty1 getty (kiosk owns the display)
rm -f "$MNT/etc/systemd/system/getty.target.wants/getty@tty1.service" 2>/dev/null || true

# Unmask serial console on ttyS0 for debug access
rm -f "$MNT/etc/systemd/system/serial-getty@.service" 2>/dev/null || true
rm -f "$MNT/etc/systemd/system/serial-getty@ttyS0.service" 2>/dev/null || true
mkdir -p "$MNT/etc/systemd/system/getty.target.wants"
ln -sf /usr/lib/systemd/system/serial-getty@.service \
    "$MNT/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service" 2>/dev/null || true

echo "  Image patched."
umount "$MNT"
losetup -d "$LOOP"
LOOP=""
rmdir "$MNT" 2>/dev/null || true

# ── Step 5: Convert to VMDK ────────────────────────────────────────
echo "=== Step 5/5: Converting RAW → VMDK ==="
# Preserve the raw image beside the VMDK in this unique run directory.
RAW_OUTPUT="$VMWARE_OUTPUT_DIR/examos.raw"
VMDK="$VMWARE_OUTPUT_DIR/examos.vmdk"
FLAT="$VMWARE_OUTPUT_DIR/examos-flat.vmdk"
cp --no-preserve=ownership "$RAW" "$RAW_OUTPUT"

qemu-img convert -f raw -O vmdk \
    -o subformat=monolithicFlat,adapter_type=lsilogic,compat6 \
    "$RAW" "$VMDK"

# Keep the isolated workspace and build logs for traceability. Cleanup trap
# only unmounts/detaches resources created by this invocation.

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ExamOS VMware Image Built Successfully!"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "  Run artifacts: $VMWARE_OUTPUT_DIR"
echo "  VMDK:  $VMDK"
ls -lh "$VMDK" "$FLAT" 2>/dev/null || true
echo ""
echo "  Attach this VMDK to a newly created VMware virtual machine."
echo "  No credentials are embedded; provision through the approved deployment process."
echo "══════════════════════════════════════════════════════════════"
