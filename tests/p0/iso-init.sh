#!/usr/bin/bash
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

log() {
    # /dev/console may be VGA even when the kernel serial console is enabled.
    # Emit the boot-proof records to ttyS0 as well, so the headless QEMU gate
    # can distinguish the optical root loader from an accidental disk-root
    # boot path.
    printf '%s\n' "ExamOS ISO init: $*" >/dev/console 2>/dev/null || true
    if [ -c /dev/ttyS0 ]; then
        printf '%s\n' "ExamOS ISO init: $*" >/dev/ttyS0 2>/dev/null || true
    fi
}

fail() {
    log "$1"
    sync || true
    if command -v poweroff >/dev/null 2>&1; then
        poweroff -f || true
    fi
    exit 1
}

mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev ||
    fail "cannot mount devtmpfs"
mountpoint -q /proc || mount -t proc proc /proc ||
    fail "cannot mount proc"
mountpoint -q /sys || mount -t sysfs sysfs /sys ||
    fail "cannot mount sysfs"
mkdir -p /run /sysroot
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run ||
    fail "cannot mount initramfs runtime storage"
mkdir -p /run/iso /run/lower /run/volatile ||
    fail "cannot create optical root staging directories"

modprobe ahci || fail "cannot load AHCI SATA controller support"
modprobe sr_mod || fail "cannot load optical block-device support"

ISO_DEVICE=""
for attempt in $(seq 1 60); do
    for device in /dev/sr*; do
        [ -b "$device" ] || continue
        if blkid -p -s TYPE -o value "$device" 2>/dev/null | grep -qx iso9660; then
            ISO_DEVICE="$device"
            break 2
        fi
    done
    sleep 1
done

[ -n "$ISO_DEVICE" ] || fail "no readable ISO9660 optical device found"

mount -t iso9660 -o ro "$ISO_DEVICE" /run/iso ||
    fail "cannot mount optical media read-only"
ROOT_IMAGE=/run/iso/examos-root.ext4
[ -s "$ROOT_IMAGE" ] || fail "embedded root filesystem is missing"

METADATA=/run/iso/EXAMOS-P0.conf
[ -s "$METADATA" ] || fail "optical media root metadata is missing"
EXPECTED_ROOT_LABEL="$(sed -n 's/^ROOT_FILESYSTEM_LABEL=//p' "$METADATA")"
EXPECTED_ROOT_UUID="$(sed -n 's/^ROOT_FILESYSTEM_UUID=//p' "$METADATA")"
case "$EXPECTED_ROOT_LABEL" in
    ''|*[!A-Za-z0-9._-]*) fail "optical media root label is invalid" ;;
esac
case "$EXPECTED_ROOT_UUID" in
    ????????-????-????-????-????????????) ;;
    *) fail "optical media root UUID is invalid" ;;
esac
case "$EXPECTED_ROOT_UUID" in
    *[!0-9a-fA-F-]*) fail "optical media root UUID contains invalid characters" ;;
esac

modprobe isofs || fail "cannot load ISO9660 filesystem support"
modprobe loop || fail "cannot load loop-device support"
modprobe ext4 || fail "cannot load ext4 filesystem support"
modprobe overlay || fail "cannot load overlay filesystem support"
ROOT_LOOP="$(losetup --find --show --read-only "$ROOT_IMAGE")" ||
    fail "cannot attach the embedded root filesystem read-only"
# The loop is read-only, so the kernel cannot replay a journal. ISO build
# must already have run e2fsck on this image (same H-12 reconciliation).
# noload is still required here: this matches dm-verity-setup.sh and is the
# only legal mount on write-unavailable optical media.
mount -t ext4 -o ro,noload "$ROOT_LOOP" /run/lower ||
    fail "cannot mount the embedded ext4 root filesystem"

ROOT_LABEL="$(blkid -p -s LABEL -o value "$ROOT_LOOP")" ||
    fail "cannot read embedded root filesystem label"
[ "$ROOT_LABEL" = "$EXPECTED_ROOT_LABEL" ] ||
    fail "embedded root filesystem label does not match its ISO metadata"
ROOT_UUID="$(blkid -p -s UUID -o value "$ROOT_LOOP")" ||
    fail "cannot read embedded root filesystem UUID"
[ "$ROOT_UUID" = "$EXPECTED_ROOT_UUID" ] ||
    fail "embedded root filesystem UUID does not match its ISO metadata"

mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run/volatile ||
    fail "cannot create the memory-only writable layer"
mkdir -p /run/volatile/upper /run/volatile/work
mount -t overlay overlay \
    -o lowerdir=/run/lower,upperdir=/run/volatile/upper,workdir=/run/volatile/work \
    /sysroot ||
    fail "cannot create the volatile writable root overlay"

log "UEFI optical media selected"
log "mounted canonical root filesystem $ROOT_UUID read-only"
log "activated volatile overlay root"

mkdir -p /sysroot/run
mount --move /run /sysroot/run ||
    fail "cannot preserve volatile runtime mounts across switch_root"
exec /usr/sbin/switch_root /sysroot /usr/lib/systemd/systemd
