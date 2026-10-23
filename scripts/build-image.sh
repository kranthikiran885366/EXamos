#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_DIR="$ROOT/image"
ARTIFACT_DIR="$ROOT/artifacts/p0"
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
mkosi \
  --directory "$IMAGE_DIR" \
  --output-directory "$OUTPUT_DIR" \
  --extra-tree "$OVERLAY_DIR:/" \
  --force \
  build 2>&1 | tee "$ARTIFACT_DIR/build.log"

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
  /usr/local/bin/examos-server
  /usr/local/sbin/tpm-seal-secrets.sh
  /usr/local/sbin/examos-setup-postgres-tls
  /usr/local/sbin/examos-provision-remote-postgres
  /etc/systemd/system/examos-agent.service
  /etc/systemd/system/examos-kiosk.service
  /etc/systemd/system/examos-proctor.service
  /etc/systemd/system/examos-server.service
  /etc/systemd/system/graphical.target.wants/examos-kiosk.service
  /etc/systemd/system/multi-user.target.wants/examos-agent.service
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
