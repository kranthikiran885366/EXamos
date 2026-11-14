#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_DIR="$ROOT/image"
ARTIFACT_DIR="${EXAMOS_BUILD_ARTIFACT_DIR:-$ROOT/artifacts/p0}"
source "$ROOT/scripts/p0-image-path.sh"
OUTPUT_DIR="$(examos_image_output_dir "$ROOT" "$IMAGE_DIR")"
IMAGE_FILE="$OUTPUT_DIR/examos.raw"
BUILD_STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-build.XXXXXX")"
OVERLAY_DIR="$BUILD_STAGE_DIR/overlay"
VERIFY_DIR="$BUILD_STAGE_DIR/verify"
trap 'rm -rf -- "$BUILD_STAGE_DIR"' EXIT
mkdir -p "$ARTIFACT_DIR"
mkdir -p "$OUTPUT_DIR"

echo "=================================================="
echo "       ExamOS Development Image Builder           "
echo "=================================================="

# 1. Compile all Native C/C++ Subsystems
echo "[1/4] Compiling native C/C++ subsystems..."
make -C "$ROOT" all

# 2. Stage the overlay on a Linux filesystem so DrvFS mode bits cannot leak
#    into the image as executable, world-writable systemd configuration.
echo "[2/4] Staging a permission-normalized rootfs overlay..."
mkdir -p "$OVERLAY_DIR"
cp -a "$IMAGE_DIR/overlay/." "$OVERLAY_DIR/"
mkdir -p "$OVERLAY_DIR/usr/local/bin"
# The overlay carries a deliberately fail-closed validator placeholder so a
# direct mkosi invocation cannot ship the obsolete partial script. Install the
# complete runtime validator here, exactly as the production build does, or the
# P2 lockdown post-install script will refuse to build.
install -D -m 0755 "$IMAGE_DIR/scripts/p2-startup-validator.sh" \
    "$OVERLAY_DIR/usr/local/bin/p2-startup-validator.sh"
install -D -m 0755 "$ROOT/kiosk/launcher/examos-kiosk-launcher" "$OVERLAY_DIR/usr/local/bin/examos-kiosk-launcher"
install -D -m 0755 "$ROOT/agent/examos-agent" "$OVERLAY_DIR/usr/local/bin/examos-agent"
install -D -m 0755 "$ROOT/proctoring/examos-proctor" "$OVERLAY_DIR/usr/local/bin/examos-proctor"
install -D -m 0755 "$ROOT/server/examos-server" "$OVERLAY_DIR/usr/local/bin/examos-server"
install -D -m 0755 "$ROOT/server/examos-db-migrate" "$OVERLAY_DIR/usr/local/bin/examos-db-migrate"
install -D -m 0755 "$IMAGE_DIR/scripts/tpm-seal-secrets.sh" "$OVERLAY_DIR/usr/local/sbin/tpm-seal-secrets.sh"
install -D -m 0755 "$ROOT/scripts/setup-postgres-tls.sh" "$OVERLAY_DIR/usr/local/sbin/examos-setup-postgres-tls"
install -D -m 0755 "$ROOT/scripts/provision-remote-postgres.sh" "$OVERLAY_DIR/usr/local/sbin/examos-provision-remote-postgres"
install -d "$OVERLAY_DIR/usr/share/examos/migrations"
install -m 0644 "$ROOT"/server/migrations/*.sql "$OVERLAY_DIR/usr/share/examos/migrations/"
find "$OVERLAY_DIR" -type d -exec chmod 0755 {} +
find "$OVERLAY_DIR" -type f -exec chmod 0644 {} +
find "$OVERLAY_DIR/usr/local/bin" -type f -exec chmod 0755 {} +
find "$OVERLAY_DIR/usr/local/sbin" -type f -exec chmod 0755 {} +

# 3. Execute mkosi build
echo "[3/4] Running mkosi image synthesis..."
mkosi_args=(
  --directory "$IMAGE_DIR" \
  --output-directory "$OUTPUT_DIR" \
  --extra-tree "$OVERLAY_DIR:/" \
)
if [[ -n "${EXAMOS_MKOSI_BUILD_DIR:-}" ]]; then
  mkosi_args+=(--build-directory "$EXAMOS_MKOSI_BUILD_DIR")
fi
if [[ -n "${EXAMOS_MKOSI_CACHE_DIR:-}" ]]; then
  mkosi_args+=(--cache-directory "$EXAMOS_MKOSI_CACHE_DIR")
fi
mkosi "${mkosi_args[@]}" --force build 2>&1 | tee "$ARTIFACT_DIR/build.log"

# 4. Validate the exact output and compute its checksum
echo "[4/4] Validating generated image artifact..."
if [[ ! -s "$IMAGE_FILE" ]]; then
    echo "ERROR: Expected image artifact was not produced: $IMAGE_FILE" >&2
    exit 1
fi

systemd-dissect --validate "$IMAGE_FILE"
mkdir -p "$VERIFY_DIR"
required_image_paths=(
  /usr/local/bin/examos-kiosk-launcher
  /usr/local/bin/examos-agent
  /usr/local/bin/examos-proctor
  /usr/local/bin/examos-kiosk-readiness
  /usr/local/bin/examos-server
  /usr/local/sbin/tpm-seal-secrets.sh
  /usr/local/sbin/examos-setup-postgres-tls
  /usr/local/sbin/examos-provision-remote-postgres
  /etc/systemd/system/examos-agent.service
  /etc/systemd/system/examos-kiosk.service
  /etc/systemd/system/examos-kiosk-readiness.service
  /etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf
  /etc/chromium.d/README
  /etc/systemd/system/examos-proctor.service
  /etc/systemd/system/examos-server.service
  /etc/systemd/system/graphical.target.wants/examos-kiosk.service
  /etc/systemd/system/multi-user.target.wants/examos-agent.service
  /etc/apparmor.d/examos-kiosk
  /usr/lib/sysusers.d/examos.conf
)
for image_path in "${required_image_paths[@]}"; do
  extracted_path="$VERIFY_DIR$image_path"
  mkdir -p "$(dirname "$extracted_path")"
  systemd-dissect --copy-from "$IMAGE_FILE" "$image_path" "$extracted_path"
  if [[ ! -s "$extracted_path" ]]; then
    echo "ERROR: Required ExamOS image content is missing: $image_path" >&2
    exit 1
  fi
done
if ! cmp -s "$OVERLAY_DIR/etc/apparmor.d/examos-kiosk" "$VERIFY_DIR/etc/apparmor.d/examos-kiosk"; then
  echo "ERROR: Built image does not contain the canonical Chromium AppArmor profile." >&2
  exit 1
fi
if ! cmp -s "$OVERLAY_DIR/etc/chromium.d/README" "$VERIFY_DIR/etc/chromium.d/README"; then
  echo "ERROR: Built image is missing the Chromium wrapper's empty-config sentinel." >&2
  exit 1
fi
if systemd-dissect --copy-from "$IMAGE_FILE" /etc/apparmor.d/usr.bin.chromium \
    "$VERIFY_DIR/etc/apparmor.d/usr.bin.chromium" >/dev/null 2>&1; then
  echo "ERROR: Built image contains a competing legacy Chromium AppArmor profile." >&2
  exit 1
fi
kiosk_unit="$VERIFY_DIR/etc/systemd/system/examos-kiosk.service"
if ! grep -Fxq 'User=exam' "$kiosk_unit" ||
   ! grep -Fxq 'Group=exam' "$kiosk_unit" ||
   ! grep -Fxq 'PAMName=login' "$kiosk_unit" ||
   ! grep -Fxq 'TTYPath=/dev/tty1' "$kiosk_unit" ||
   ! grep -Fxq 'Requires=examos-preflight.service' "$kiosk_unit" ||
   ! grep -Fxq 'After=examos-preflight.service' "$kiosk_unit" ||
   ! grep -Fxq 'StandardInput=tty' "$kiosk_unit" ||
   ! grep -Fxq 'RuntimeDirectory=examos-kiosk' "$kiosk_unit" ||
   ! grep -Fxq 'RuntimeDirectoryMode=0700' "$kiosk_unit" ||
   ! grep -Fxq 'Environment=LIBSEAT_BACKEND=logind' "$kiosk_unit" ||
   ! grep -Fxq 'Environment=EXAMOS_ALLOWED_EXAM_HOSTS=staging.examos.example.edu,exam.university.edu,exam.alpha.edu,portal.beta.edu,sppio-os.vercel.app' "$kiosk_unit" ||
   ! grep -Fxq 'ReadWritePaths=/run/examos-kiosk /tmp' "$kiosk_unit" ||
   ! grep -Fxq 'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_SYS_CHROOT CAP_SYS_TTY_CONFIG' "$kiosk_unit" ||
   ! grep -Fxq 'StandardOutput=journal' "$kiosk_unit" ||
   ! grep -Fxq 'StandardError=journal' "$kiosk_unit" ||
   ! grep -Fxq 'ExecStart=/usr/bin/env XDG_RUNTIME_DIR=/run/examos-kiosk /usr/bin/cage -s -- /usr/local/bin/examos-kiosk-launcher' "$kiosk_unit" ||
   grep -Eq '^(User|Group)=root$|/run/user/|--no-sandbox|ExecStartPre=.*(mkdir|chown|chmod)|^Environment=WAYLAND_DISPLAY=' "$kiosk_unit"; then
  echo "ERROR: Kiosk service must use the dedicated unprivileged exam account and canonical launcher." >&2
  exit 1
fi
apparmor_profile="$VERIFY_DIR/etc/apparmor.d/examos-kiosk"
if ! grep -Fxq '/usr/bin/uname             ix,' "$apparmor_profile" ||
   ! grep -Fxq '/usr/bin/expr              ix,' "$apparmor_profile" ||
! grep -Fxq '/usr/bin/findmnt            ix,' "$apparmor_profile" ||
! grep -Fxq '/usr/lib/chromium/chromium Px -> examos-kiosk,' "$apparmor_profile" ||
! grep -Fxq '/usr/lib/chromium/chrome_crashpad_handler ix,' "$apparmor_profile" ||
! grep -Fq 'userns,' "$apparmor_profile" ||
! grep -Fq 'capability sys_admin,' "$apparmor_profile" ||
! grep -Fxq 'owner /proc/[0-9]*/mountinfo r,' "$apparmor_profile" ||
! grep -Fxq 'owner /proc/[0-9]*/fd/      r,' "$apparmor_profile" ||
! grep -Fxq '/etc/chromium.d/           r,' "$apparmor_profile" ||
   ! grep -Fxq '/etc/chromium.d/*          r,' "$apparmor_profile" ||
   ! grep -Fxq '/run/examos-kiosk/wayland-[0-9]* rw,' "$apparmor_profile" ||
   ! grep -Fxq '/run/examos-kiosk/examos_kiosk_*/** rwkl,' "$apparmor_profile" ||
   grep -Fq 'deny capability ptrace,' "$apparmor_profile"; then
  echo "ERROR: Chromium AppArmor policy must allow its confined launcher/runtime paths without invalid ptrace capability rules." >&2
  exit 1
fi
proctor_unit="$VERIFY_DIR/etc/systemd/system/examos-proctor.service"
if ! grep -Fxq 'Environment=XDG_RUNTIME_DIR=/run/examos-kiosk' "$proctor_unit" ||
   ! grep -Fxq 'ReadWritePaths=/run/examos-kiosk /tmp' "$proctor_unit" ||
   ! grep -Fxq 'Requires=examos-kiosk.service' "$proctor_unit" ||
   grep -Fq '/run/user/1000' "$proctor_unit"; then
  echo "ERROR: Proctor service must use the kiosk-owned Wayland runtime directory." >&2
  exit 1
fi
readiness_unit="$VERIFY_DIR/etc/systemd/system/examos-kiosk-readiness.service"
readiness_script="$VERIFY_DIR/usr/local/bin/examos-kiosk-readiness"
readiness_target_dropin="$VERIFY_DIR/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf"
if ! grep -Fxq 'Environment=XDG_RUNTIME_DIR=/run/examos-kiosk' "$readiness_unit" ||
   ! grep -Fxq 'Wants=examos-kiosk.service' "$readiness_unit" ||
   ! grep -Fxq 'After=examos-kiosk.service' "$readiness_unit" ||
   grep -Fxq 'Requires=examos-kiosk.service' "$readiness_unit" ||
   ! grep -Fxq 'Wants=examos-kiosk-readiness.service' "$readiness_target_dropin" ||
   ! grep -Fxq 'TimeoutStartSec=90' "$readiness_unit" ||
   ! grep -Fxq 'ExecStart=/usr/local/bin/examos-kiosk-readiness' "$readiness_unit" ||
   ! grep -Fq 'XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is required}/wayland-0' "$readiness_script" ||
   ! grep -Fq 'EXAMOS_KIOSK_READY cage=1 chromium=1 wayland_socket=1' "$readiness_script" ||
   ! grep -Fq 'stable_seconds=10' "$readiness_script" ||
   ! grep -Fq 'EXAMOS_KIOSK_DIAGNOSTICS_COMPLETE' "$readiness_script" ||
   grep -Fq '/run/user/1000' "$readiness_script"; then
  echo "ERROR: Kiosk readiness must verify the live compositor socket and Chromium in the managed runtime directory." >&2
  exit 1
fi
for binary in examos-kiosk-launcher examos-agent examos-proctor examos-server; do
  if [[ ! -x "$VERIFY_DIR/usr/local/bin/$binary" ]]; then
    echo "ERROR: ExamOS image binary is not executable: $binary" >&2
    exit 1
  fi
done
if [[ ! -x "$VERIFY_DIR/usr/local/sbin/tpm-seal-secrets.sh" ]]; then
  echo "ERROR: TPM provisioning script is not executable in the image." >&2
  exit 1
fi
if [[ ! -x "$VERIFY_DIR/usr/local/sbin/examos-setup-postgres-tls" ]]; then
  echo "ERROR: PostgreSQL provisioning script is not executable in the image." >&2
  exit 1
fi
if [[ ! -x "$VERIFY_DIR/usr/local/sbin/examos-provision-remote-postgres" ]]; then
  echo "ERROR: Remote PostgreSQL provisioning script is not executable in the image." >&2
  exit 1
fi
sha256sum "$IMAGE_FILE" > "$ARTIFACT_DIR/image.sha256"
stat --printf='size_bytes=%s\n' "$IMAGE_FILE" > "$ARTIFACT_DIR/image-size.txt"
echo "SUCCESS: ExamOS Image built: $IMAGE_FILE"
cat "$ARTIFACT_DIR/image.sha256"
cat "$ARTIFACT_DIR/image-size.txt"
