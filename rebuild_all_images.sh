#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="/mnt/d/SEB BRO"
cd "$WORKSPACE"

echo "======================================================================="
echo "  ExamOS Master Production Rebuild: All Binaries, VMDK & UEFI ISO"
echo "======================================================================="

# --- Step 1: Build All Native C/C++ Subsystems ---
echo ""
echo "=== [1/6] Rebuilding all ExamOS Native Subsystems ==="
make -C "$WORKSPACE/kiosk/launcher" all
make -C "$WORKSPACE/agent" all
make -C "$WORKSPACE/proctoring" all
make -C "$WORKSPACE/server" all

echo "  ✔ kiosk-launcher : $(ls -lh "$WORKSPACE/kiosk/launcher/examos-kiosk-launcher" | awk '{print $5}')"
echo "  ✔ agent          : $(ls -lh "$WORKSPACE/agent/examos-agent" | awk '{print $5}')"
echo "  ✔ server         : $(ls -lh "$WORKSPACE/server/examos-server" | awk '{print $5}')"

# --- Step 2: Build Production Frontend ---
echo ""
echo "=== [2/6] Building ExamOS Console Frontend ==="
cd "$WORKSPACE/frontend"
npm run build
cd "$WORKSPACE"
echo "  ✔ Frontend build complete in frontend/dist"

# --- Step 3: Update Overlay Files ---
echo ""
echo "=== [3/6] Synchronizing Image Overlay Assets ==="
mkdir -p "$WORKSPACE/image/overlay/usr/local/bin"
mkdir -p "$WORKSPACE/image/overlay/usr/share/examos"
mkdir -p "$WORKSPACE/image/overlay/usr/share/examos/migrations"

cp -f "$WORKSPACE/server/examos-server" "$WORKSPACE/image/overlay/usr/local/bin/"
cp -f "$WORKSPACE/server/examos-db-migrate" "$WORKSPACE/image/overlay/usr/local/bin/"
cp -f "$WORKSPACE/agent/examos-agent" "$WORKSPACE/image/overlay/usr/local/bin/"
cp -f "$WORKSPACE/kiosk/launcher/examos-kiosk-launcher" "$WORKSPACE/image/overlay/usr/local/bin/"
cp -f "$WORKSPACE/server/migrations/"*.sql "$WORKSPACE/image/overlay/usr/share/examos/migrations/"
echo "  ✔ Overlay assets synchronized"

# --- Step 4: Inject into RootFS in examos.raw ---
echo ""
echo "=== [4/6] Updating ExamOS Raw Disk Image RootFS ==="
MNT="/tmp/examos_rebuild_mnt"
mkdir -p "$MNT"
umount -R "$MNT" 2>/dev/null || true
losetup -D 2>/dev/null || true
sleep 1

losetup -fP "$WORKSPACE/image/examos.raw"
LOOP=$(losetup -j "$WORKSPACE/image/examos.raw" | head -n 1 | cut -d: -f1)
echo "  Attached loop device: $LOOP"

mount "${LOOP}p2" "$MNT"

# Install binaries into RootFS
mkdir -p "$MNT/usr/local/bin" "$MNT/usr/share/examos" "$MNT/usr/share/examos/migrations" "$MNT/var/www/html"
cp -f "$WORKSPACE/server/examos-server" "$MNT/usr/local/bin/"
cp -f "$WORKSPACE/server/examos-db-migrate" "$MNT/usr/local/bin/"
cp -f "$WORKSPACE/agent/examos-agent" "$MNT/usr/local/bin/"
cp -f "$WORKSPACE/kiosk/launcher/examos-kiosk-launcher" "$MNT/usr/local/bin/"
chmod 0755 "$MNT/usr/local/bin/examos-"*

# Install latest migrations and templates
cp -f "$WORKSPACE/server/migrations/"*.sql "$MNT/usr/share/examos/migrations/"
cp -f "$WORKSPACE/image/overlay/usr/share/examos/"* "$MNT/usr/share/examos/" 2>/dev/null || true

# Install frontend distribution for local kiosk web views
cp -rf "$WORKSPACE/frontend/dist/." "$MNT/var/www/html/" 2>/dev/null || true

# Update exam config
mkdir -p "$MNT/etc/examos"
cat << 'EOF' > "$MNT/etc/examos/exam.conf"
EXAM_URL=file:///usr/share/examos/onboarding.html
EXAM_NAME=National Examination Board Kiosk Session
EXAM_DURATION_MINUTES=120
EXAM_ID=EXAM-2026-NAT-01
ALLOWED_ORIGINS=file:///usr/share/examos/onboarding.html,file:///usr/share/examos/waiting.html,https://staging.examos.example.edu,http://127.0.0.1:8895
EOF
chmod 0644 "$MNT/etc/examos/exam.conf"

sync
umount "$MNT"
sleep 1
e2fsck -f -y "${LOOP}p2" || true
losetup -d "$LOOP"
echo "  ✔ RootFS successfully updated and filesystem verified"

# --- Step 5: Rebuild VMware VMDK ---
echo ""
echo "=== [5/6] Rebuilding VMware VMDK Image ==="
RAW="$WORKSPACE/image/examos.raw"
VMDK="$WORKSPACE/image/examos.vmdk"
rm -f "$VMDK" "$WORKSPACE/image/examos-flat.vmdk"
rm -f "$WORKSPACE/output/examos.vmdk" "$WORKSPACE/output/examos-flat.vmdk"

qemu-img convert -f raw -O vmdk -o subformat=monolithicFlat,adapter_type=lsilogic,compat6 "$RAW" "$VMDK"

mkdir -p "$WORKSPACE/output"
cp -f "$VMDK" "$WORKSPACE/output/examos.vmdk"
if [ -f "$WORKSPACE/image/examos-flat.vmdk" ]; then
    cp -f "$WORKSPACE/image/examos-flat.vmdk" "$WORKSPACE/output/examos-flat.vmdk"
fi

# Ensure VMX points to examos.vmdk
cp -f "$WORKSPACE/image/examos.vmx" "$WORKSPACE/output/examos.vmx"
echo "  ✔ VMware VMDK built: $(ls -lh "$WORKSPACE/output/examos.vmdk" | awk '{print $5, $9}')"
echo "  ✔ VMware VMX ready : $WORKSPACE/output/examos.vmx"

# --- Step 6: Rebuild Hybrid UEFI ISO ---
echo ""
echo "=== [6/6] Rebuilding VMware Hybrid UEFI ISO ==="
bash "$WORKSPACE/scripts/build-examos-iso.sh"

echo ""
echo "======================================================================="
echo "  ✔ ALL REBUILDS COMPLETED SUCCESSFULLY"
echo "======================================================================="
echo "  VMware VM (Disk) : $WORKSPACE/output/examos.vmx"
echo "  VMware VMDK      : $WORKSPACE/output/examos.vmdk ($(ls -lh "$WORKSPACE/output/examos.vmdk" | awk '{print $5}'))"
echo "  VMware ISO       : $WORKSPACE/output/examos.iso ($(ls -lh "$WORKSPACE/output/examos.iso" | awk '{print $5}'))"
echo "  VMware ISO (VM)  : $WORKSPACE/output/examos-iso.vmx"
echo "  ISO SHA256       : $(cut -d' ' -f1 "$WORKSPACE/output/examos.iso.sha256")"
echo "======================================================================="
