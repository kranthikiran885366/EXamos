#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — dm-verity Hash Tree Generation
#
# Called as a POST-BUILD step (outside the mkosi chroot) to:
#   1. Take the assembled raw disk image produced by mkosi.
#   2. Extract the root filesystem partition.
#   3. Convert it to SquashFS (read-only, compressed).
#   4. Compute the dm-verity hash tree and root hash.
#   5. Write a verity descriptor that the initramfs early-userspace can read.
#   6. Record all values in the build manifest.
#
# This script runs on the CI build host (not inside the guest image).
# It requires: veritysetup, mksquashfs, losetup, partx, dd, sha256sum, jq
#
# Usage:
#   IMAGE_PATH=image/examos.raw \
#   MANIFEST_OUT=artifacts/phase2/phase2-manifest.json \
#   bash image/scripts/dm-verity-setup.sh
#
# Environment variables:
#   IMAGE_PATH      Path to the raw disk image (required)
#   MANIFEST_OUT    Where to write/update the build manifest (required)
#   SQUASHFS_COMP   SquashFS compression algorithm (default: zstd)
#   VERITY_HASH_ALG Hash algorithm for dm-verity (default: sha256)
#   WORK_DIR        Scratch directory (default: /tmp/examos-verity-$$)
#   KEEP_WORK       Set to 1 to retain WORK_DIR after exit (default: 0)
#
# Exit codes:
#   0   Success — root hash written, manifest updated
#   1   Failure — see stderr
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------
IMAGE_PATH="${IMAGE_PATH:-}"
MANIFEST_OUT="${MANIFEST_OUT:-artifacts/phase2/phase2-manifest.json}"
SQUASHFS_COMP="${SQUASHFS_COMP:-zstd}"
VERITY_HASH_ALG="${VERITY_HASH_ALG:-sha256}"
WORK_DIR="${WORK_DIR:-/tmp/examos-verity-$$}"
KEEP_WORK="${KEEP_WORK:-0}"

log()  { echo "[dm-verity] $*"; }
fail() { echo "[dm-verity] FAIL: $*" >&2; exit 1; }

# -----------------------------------------------------------------------
# Validate prerequisites
# -----------------------------------------------------------------------
for tool in veritysetup mksquashfs losetup partx sha256sum jq; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required tool not found: $tool (install cryptsetup-bin squashfs-tools)"
done

[ -n "$IMAGE_PATH" ]        || fail "IMAGE_PATH is not set"
[ -f "$IMAGE_PATH" ]        || fail "Image not found: $IMAGE_PATH"
[ -n "$MANIFEST_OUT" ]      || fail "MANIFEST_OUT is not set"

# -----------------------------------------------------------------------
# Cleanup trap
# -----------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    # Unmount and detach loop device
    if [ -n "${LOOP_DEV:-}" ]; then
        log "Detaching loop device $LOOP_DEV"
        losetup -d "$LOOP_DEV" 2>/dev/null || true
    fi
    if mountpoint -q "${WORK_DIR}/rootfs" 2>/dev/null; then
        umount "${WORK_DIR}/rootfs" 2>/dev/null || true
    fi
    if [ "$KEEP_WORK" != "1" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
    if [ "$exit_code" -ne 0 ]; then
        echo "[dm-verity] FAIL: dm-verity setup did not complete successfully" >&2
    fi
}
trap cleanup EXIT

# -----------------------------------------------------------------------
# Prepare work directory
# -----------------------------------------------------------------------
mkdir -p "$WORK_DIR"/{rootfs,squashfs,verity}
log "Work directory: $WORK_DIR"
log "Source image:   $IMAGE_PATH"

# -----------------------------------------------------------------------
# Step 1: Attach raw image as loop device and identify partitions
# -----------------------------------------------------------------------
log "Attaching image as loop device..."
LOOP_DEV=$(losetup --find --show --partscan "$IMAGE_PATH")
log "Loop device: $LOOP_DEV"

# Wait for partition devices to appear
sleep 1
partx -u "$LOOP_DEV" 2>/dev/null || true

# Identify the root partition (partition 2 for GPT disk images from mkosi;
# partition 1 is typically the EFI System Partition)
# Try to find the largest Linux filesystem partition
ROOT_PART=""
for part_num in 2 3 1; do
    candidate="${LOOP_DEV}p${part_num}"
    if [ -b "$candidate" ]; then
        # Check if it looks like a Linux root (ext4/btrfs — not FAT32/EFI)
        FS_TYPE=$(blkid -o value -s TYPE "$candidate" 2>/dev/null || echo "unknown")
        log "Partition ${part_num}: $candidate  fstype=$FS_TYPE"
        if echo "$FS_TYPE" | grep -qE "^(ext4|ext3|btrfs|xfs|erofs)$"; then
            ROOT_PART="$candidate"
            ROOT_PART_NUM=$part_num
            ROOT_FS_TYPE="$FS_TYPE"
            break
        fi
    fi
done

if [ -z "$ROOT_PART" ]; then
    # Last resort: try to find any non-EFI partition
    for p in "${LOOP_DEV}"p*; do
        [ -b "$p" ] || continue
        FS_TYPE=$(blkid -o value -s TYPE "$p" 2>/dev/null || echo "unknown")
        if [ "$FS_TYPE" != "vfat" ] && [ "$FS_TYPE" != "msdos" ]; then
            ROOT_PART="$p"
            ROOT_FS_TYPE="$FS_TYPE"
            break
        fi
    done
fi

[ -n "$ROOT_PART" ] || fail "Could not identify root partition in $IMAGE_PATH"
log "Root partition: $ROOT_PART (type: ${ROOT_FS_TYPE:-unknown})"

# -----------------------------------------------------------------------
# Step 2: Mount root partition and create SquashFS
# -----------------------------------------------------------------------
log "Mounting root partition read-only..."
mount -o ro "$ROOT_PART" "${WORK_DIR}/rootfs"

SQUASHFS_IMAGE="${WORK_DIR}/squashfs/examos-root.squashfs"
log "Creating SquashFS image (compression: $SQUASHFS_COMP)..."
mksquashfs \
    "${WORK_DIR}/rootfs" \
    "$SQUASHFS_IMAGE" \
    -comp "$SQUASHFS_COMP" \
    -noappend \
    -no-progress \
    -xattrs \
    -wildcards \
    -e "proc/*" \
    -e "sys/*" \
    -e "dev/*" \
    -e "run/*" \
    -e "tmp/*"

umount "${WORK_DIR}/rootfs"

SQUASHFS_SIZE=$(stat -c %s "$SQUASHFS_IMAGE")
SQUASHFS_SHA256=$(sha256sum "$SQUASHFS_IMAGE" | awk '{print $1}')
log "SquashFS created: ${SQUASHFS_SIZE} bytes, SHA-256: ${SQUASHFS_SHA256}"

# -----------------------------------------------------------------------
# Step 3: Generate dm-verity hash tree
# -----------------------------------------------------------------------
VERITY_HASH_IMAGE="${WORK_DIR}/verity/examos-root.verity"
VERITY_OUTPUT_FILE="${WORK_DIR}/verity/veritysetup-output.txt"

log "Generating dm-verity hash tree..."
veritysetup format \
    --hash "$VERITY_HASH_ALG" \
    --data-block-size=4096 \
    --hash-block-size=4096 \
    "$SQUASHFS_IMAGE" \
    "$VERITY_HASH_IMAGE" \
    2>&1 | tee "$VERITY_OUTPUT_FILE"

# Extract root hash from veritysetup output
ROOT_HASH=$(grep "Root hash:" "$VERITY_OUTPUT_FILE" | awk '{print $3}' | tr -d '[:space:]')
UUID=$(grep "UUID:" "$VERITY_OUTPUT_FILE" | awk '{print $2}' | tr -d '[:space:]' || echo "")
DATA_BLOCKS=$(grep "Data blocks:" "$VERITY_OUTPUT_FILE" | awk '{print $3}' || echo "")
HASH_TYPE=$(grep "Hash type:" "$VERITY_OUTPUT_FILE" | awk '{print $3}' || echo "$VERITY_HASH_ALG")
SALT=$(grep "Salt:" "$VERITY_OUTPUT_FILE" | awk '{print $2}' || echo "")

[ -n "$ROOT_HASH" ] || fail "Failed to extract root hash from veritysetup output"
log "dm-verity root hash: $ROOT_HASH"

VERITY_HASH_SHA256=$(sha256sum "$VERITY_HASH_IMAGE" | awk '{print $1}')
VERITY_HASH_SIZE=$(stat -c %s "$VERITY_HASH_IMAGE")

# -----------------------------------------------------------------------
# Step 4: Write verity descriptor for initramfs / kernel cmdline
# -----------------------------------------------------------------------
VERITY_DESC_FILE="${WORK_DIR}/verity/verity-descriptor.conf"
cat > "$VERITY_DESC_FILE" <<EOF
# ExamOS dm-verity descriptor
# Generated by dm-verity-setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Include these values in the kernel command line for dm-verity enforcement.
# WARNING: This descriptor was generated from a TEST-SIGNED build artifact.
# P3 Secure Boot integration will protect these values in the production chain.
VERITY_ROOT_HASH=${ROOT_HASH}
VERITY_UUID=${UUID}
VERITY_SALT=${SALT}
VERITY_HASH_ALG=${VERITY_HASH_ALG}
VERITY_DATA_DEVICE=ROOT_PARTITION   # replaced by initramfs with actual device
VERITY_HASH_DEVICE=HASH_PARTITION   # replaced by initramfs with actual device
# Kernel cmdline fragment (substitute ROOT_PART and HASH_PART with actual paths):
# root=/dev/mapper/root \
#   dm-verity.device=ROOT_PART \
#   dm-verity.verity_roothash=${ROOT_HASH} \
#   rd.dm-verity=1
EOF

log "Verity descriptor written: $VERITY_DESC_FILE"

# -----------------------------------------------------------------------
# Step 5: Copy artifacts to output locations
# -----------------------------------------------------------------------
ARTIFACT_DIR=$(dirname "$MANIFEST_OUT")
mkdir -p "$ARTIFACT_DIR"

SQUASHFS_OUT="${ARTIFACT_DIR}/examos-root.squashfs"
VERITY_HASH_OUT="${ARTIFACT_DIR}/examos-root.verity"
VERITY_DESC_OUT="${ARTIFACT_DIR}/verity-descriptor.conf"
VERITY_LOG_OUT="${ARTIFACT_DIR}/veritysetup-output.txt"

cp "$SQUASHFS_IMAGE"    "$SQUASHFS_OUT"
cp "$VERITY_HASH_IMAGE" "$VERITY_HASH_OUT"
cp "$VERITY_DESC_FILE"  "$VERITY_DESC_OUT"
cp "$VERITY_OUTPUT_FILE" "$VERITY_LOG_OUT"

log "Artifacts written:"
log "  SquashFS:          $SQUASHFS_OUT"
log "  dm-verity hashes:  $VERITY_HASH_OUT"
log "  Descriptor:        $VERITY_DESC_OUT"
log "  veritysetup log:   $VERITY_LOG_OUT"

# -----------------------------------------------------------------------
# Step 6: Update build manifest
# -----------------------------------------------------------------------
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
IMAGE_DIGEST=$(sha256sum "$IMAGE_PATH" | awk '{print $1}')
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

# Write manifest (create or update)
cat > "$MANIFEST_OUT" <<EOF
{
  "phase": "P2",
  "status": "BUILD_COMPLETE",
  "gitCommit": "${GIT_COMMIT}",
  "buildProfile": "release-test",
  "buildTool": "mkosi 26 + dm-verity-setup.sh",
  "imageArtifact": "${IMAGE_PATH}",
  "imageDigest": "sha256:${IMAGE_DIGEST}",
  "squashfsArtifact": "${SQUASHFS_OUT}",
  "squashfsDigest": "sha256:${SQUASHFS_SHA256}",
  "squashfsSizeBytes": ${SQUASHFS_SIZE},
  "verityRootHash": "${ROOT_HASH}",
  "verityHashAlgorithm": "${HASH_TYPE}",
  "verityUUID": "${UUID}",
  "veritySalt": "${SALT}",
  "verityDataBlocks": "${DATA_BLOCKS}",
  "verityHashArtifact": "${VERITY_HASH_OUT}",
  "verityHashDigest": "sha256:${VERITY_HASH_SHA256}",
  "kernelVersion": "POPULATED_AT_RUNTIME",
  "chromiumVersion": "POPULATED_AT_RUNTIME",
  "firewallBackend": "nftables",
  "configVersion": "p2.0",
  "testExecutionTimestamp": "${TIMESTAMP}",
  "buildNote": "TEST_SIGNED — P3 Secure Boot chain not yet applied",
  "mandatoryTests": {
    "passed": 0,
    "failed": 0,
    "blocked": 0,
    "notRun": 20
  },
  "artifacts": [
    "${SQUASHFS_OUT}",
    "${VERITY_HASH_OUT}",
    "${VERITY_DESC_OUT}",
    "${VERITY_LOG_OUT}"
  ]
}
EOF

log "Manifest written: $MANIFEST_OUT"

# -----------------------------------------------------------------------
# Step 7: Summary
# -----------------------------------------------------------------------
echo ""
echo "=== dm-verity Setup Complete ==="
echo "Root hash:     $ROOT_HASH"
echo "SquashFS SHA:  $SQUASHFS_SHA256"
echo "Hash image:    $VERITY_HASH_SHA256"
echo ""
echo "Kernel cmdline fragment to add:"
echo "  root=/dev/mapper/root rd.dm-verity=1 \\"
echo "  dm-verity.device=<ROOT_DEV> dm-verity.verity_roothash=${ROOT_HASH}"
echo ""
echo "NOTE: These are TEST_SIGNED build values."
echo "      P3 Secure Boot integration is required for production root hash protection."
echo "=============================="
