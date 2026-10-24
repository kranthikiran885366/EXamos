#!/usr/bin/env bash
# ExamOS Full Production Image Builder
# Runs on: Ubuntu 22.04+ / Debian Trixie / WSL2
# Usage:   bash scripts/build-full-image.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -ne 0 ]]; then
    echo "ERROR: credentials must not be supplied to an image build." >&2
    echo "Provision operator and candidate accounts after installation through the deployment authority." >&2
    exit 2
fi

# ── Step 0: Check host dependencies ──────────────────────────────────────────
echo "[0/6] Checking host dependencies..."
MISSING=()
for cmd in mkosi qemu-system-x86_64 openssl make gcc g++ pkg-config; do
    command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "ERROR: Missing required tools: ${MISSING[*]}" >&2
    echo ""
    echo "Install on Ubuntu/Debian WSL2:"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install -y mkosi qemu-system-x86 qemu-utils ovmf \\"
    echo "    build-essential pkg-config libssl-dev libpq-dev libcap-dev"
    echo ""
    echo "Install mkosi (latest):"
    echo "  pip3 install --user mkosi"
    echo "  # or: sudo apt-get install mkosi"
    exit 1
fi
echo "  All dependencies present."

# A release build must have the real vision dependency and approved external
# model/data governance inputs.  This does not copy candidate media or model
# binaries into the source tree; deployment supplies approved artifacts.
if ! pkg-config --exists opencv4; then
    echo "ERROR: production P4 build requires OpenCV development metadata (opencv4)." >&2
    exit 2
fi
if ! python3 "$ROOT/tests/phase4/model-governance.py"; then
    echo "ERROR: production P4 model/data governance is not approved; refusing release image build." >&2
    exit 2
fi

# ── Step 1: Keep all runtime credentials out of the release image ─────────────
echo "[1/6] Credentials are not part of the image build."
echo "  Admin and candidate credentials must be provisioned after installation."

# ── Step 3: Compile all native C/C++ binaries ────────────────────────────────
echo "[3/6] Compiling native C/C++ subsystems..."
make -C "$ROOT" EXAMOS_USE_OPENCV=1 all
echo "  Binaries compiled."

# ── Step 4: Stage overlay with correct permissions ───────────────────────────
echo "[4/6] Staging rootfs overlay..."
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-stage.XXXXXX")"
trap 'rm -rf -- "$STAGE_DIR"' EXIT
cp -a "$ROOT/image/overlay/." "$STAGE_DIR/"
mkdir -p "$STAGE_DIR/etc/examos"
# The overlay contains a deliberately fail-closed placeholder so a direct
# mkosi invocation cannot accidentally ship the obsolete, partial validator.
# The production build always installs the complete runtime validator here
# before mkosi applies the P2 lockdown post-install script.
install -D -m 0755 "$ROOT/image/scripts/p2-startup-validator.sh" \
    "$STAGE_DIR/usr/local/bin/p2-startup-validator.sh"
cat > "$STAGE_DIR/etc/examos/admin.conf" <<'EOF'
# Provision a unique ADMIN_PASSWORD_PBKDF2 verifier after installation.
ADMIN_USERNAME=NOT_PROVISIONED
ADMIN_PASSWORD_PBKDF2=NOT_PROVISIONED
EOF
: > "$STAGE_DIR/etc/examos/candidates.conf"
cat > "$STAGE_DIR/etc/examos/proctor.env" <<'EOF'
# Runtime secrets are unsealed from this device's TPM at boot.
EOF
rm -f "$STAGE_DIR/etc/examos/agent.env"
mkdir -p "$STAGE_DIR/usr/local/bin"
install -m 0755 "$ROOT/kiosk/launcher/examos-kiosk-launcher" "$STAGE_DIR/usr/local/bin/"
install -m 0755 "$ROOT/agent/examos-agent"                   "$STAGE_DIR/usr/local/bin/"
install -m 0755 "$ROOT/proctoring/examos-proctor"            "$STAGE_DIR/usr/local/bin/"
install -m 0755 "$ROOT/server/examos-server"                 "$STAGE_DIR/usr/local/bin/"
install -m 0755 "$ROOT/server/examos-db-migrate"              "$STAGE_DIR/usr/local/bin/"
install -D -m 0755 "$ROOT/image/scripts/tpm-seal-secrets.sh" "$STAGE_DIR/usr/local/sbin/tpm-seal-secrets.sh"
install -D -m 0755 "$ROOT/scripts/setup-postgres-tls.sh" "$STAGE_DIR/usr/local/sbin/examos-setup-postgres-tls"
install -D -m 0755 "$ROOT/scripts/provision-remote-postgres.sh" "$STAGE_DIR/usr/local/sbin/examos-provision-remote-postgres"
install -d "$STAGE_DIR/usr/share/examos/migrations"
install -m 0644 "$ROOT"/server/migrations/*.sql "$STAGE_DIR/usr/share/examos/migrations/"

# ── Detector inventory ───────────────────────────────────────────────────────
# The proctoring worker needs a digest-verified detector inventory. It is
# provisioned on the build host, never committed, and the build fails if it
# cannot be obtained, because a shipped proctor without a detector cannot
# produce examination evidence.
echo "  Provisioning the detector inventory..."
MODEL_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/examos-models.XXXXXX")"
if ! bash "$ROOT/scripts/download-vision-models.sh" --dest "$MODEL_STAGE" >/dev/null 2>&1; then
    echo "ERROR: the detector inventory could not be provisioned." >&2
    echo "       Run scripts/download-vision-models.sh manually to see the reason." >&2
    rm -rf "$MODEL_STAGE"
    exit 1
fi

# ── Deployment content ───────────────────────────────────────────────────────
# The browser policy catalogue, the appliance identity marker and the
# detector inventory are staged with their required permissions.
REPO_ROOT="$ROOT" bash "$ROOT/image/scripts/stage-deployment-content.sh" "$STAGE_DIR" "$MODEL_STAGE"
rm -rf "$MODEL_STAGE"

# ── Shared library check ─────────────────────────────────────────────────────
# The proctoring worker is built on the build host and shipped in the image.
# Its shared libraries must be present in the image, or the appliance would
# ship a component that cannot start. The check fails the build rather than
# shipping a broken worker.
echo "  Checking the shipped binaries against the image..."
if command -v ldd >/dev/null 2>&1; then
    for binary in examos-proctor examos-server examos-agent; do
        missing=""
        while IFS= read -r line; do
            library=$(echo "$line" | awk '{print $1}')
            case "$library" in
                linux-vdso*|libc.so*|libm.so*|libpthread.so*|libdl.so*|librt.so*|ld-linux*|libresolv*) continue ;;
            esac
            if ! find "$STAGE_DIR" -name "$(basename "$library")" -print -quit 2>/dev/null | grep -q .; then
                missing="$missing $library"
            fi
        done < <(ldd "$STAGE_DIR/usr/local/bin/$binary" 2>/dev/null || true)
        if [ -n "$missing" ]; then
            echo "ERROR: $binary needs shared libraries that the image does not provide:" >&2
            echo "       $missing" >&2
            echo "       Add the matching packages to image/mkosi.conf." >&2
            exit 1
        fi
    done
    echo "  Shared library check passed"
fi

# Normalize permissions
find "$STAGE_DIR" -type d -exec chmod 0755 {} +
find "$STAGE_DIR" -type f -exec chmod 0644 {} +
find "$STAGE_DIR/usr/local/bin" -type f -exec chmod 0755 {} +
find "$STAGE_DIR/usr/local/sbin" -type f -exec chmod 0755 {} +
# Sensitive config files
[[ -f "$STAGE_DIR/etc/examos/admin.conf" ]]      && chmod 0600 "$STAGE_DIR/etc/examos/admin.conf"
[[ -f "$STAGE_DIR/etc/examos/candidates.conf" ]] && chmod 0640 "$STAGE_DIR/etc/examos/candidates.conf"
[[ -d "$STAGE_DIR/etc/examos" ]]                 && chmod 0750 "$STAGE_DIR/etc/examos"
[[ -d "$STAGE_DIR/etc/examos/models" ]]          && chmod 0755 "$STAGE_DIR/etc/examos/models"
[[ -f "$STAGE_DIR/etc/examos/browser_policies.json" ]] && chmod 0644 "$STAGE_DIR/etc/examos/browser_policies.json"
[[ -f "$STAGE_DIR/etc/examos/appliance-identity" ]]    && chmod 0644 "$STAGE_DIR/etc/examos/appliance-identity"
[[ -d "$STAGE_DIR/etc/examos/sealed" ]]          && chmod 0700 "$STAGE_DIR/etc/examos/sealed"
echo "  Overlay staged at $STAGE_DIR"

# ── Step 5: Build disk image with mkosi ──────────────────────────────────────
echo "[5/6] Building disk image with mkosi (this takes 5-15 minutes)..."
OUTPUT_DIR="$ROOT/output"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$ROOT/artifacts/p1"

mkosi \
    --directory "$ROOT/image" \
    --output-directory "$OUTPUT_DIR" \
    --extra-tree "$STAGE_DIR:/" \
    --force \
    build 2>&1 | tee "$ROOT/artifacts/p1/build.log"

# ── Step 6: Validate and record artifact ─────────────────────────────────────
echo "[6/6] Validating image artifact..."
IMAGE_FILE=""
for candidate in \
    "$OUTPUT_DIR/examos.raw" \
    "$OUTPUT_DIR/examos" \
    "$OUTPUT_DIR/image.raw"; do
    if [[ -s "$candidate" ]]; then
        IMAGE_FILE="$candidate"
        break
    fi
done

if [[ -z "$IMAGE_FILE" ]]; then
    echo "ERROR: No image artifact found in $OUTPUT_DIR" >&2
    echo "Contents of $OUTPUT_DIR:" >&2
    ls -lh "$OUTPUT_DIR" >&2
    exit 1
fi

IMAGE_RELATIVE=$(realpath --relative-to="$ROOT" "$IMAGE_FILE")
case "$IMAGE_RELATIVE" in
    ""|/*|../*|*/../*|*/..)
        echo "ERROR: Image resolves outside the workspace: $IMAGE_FILE" >&2
        exit 1
        ;;
esac
(cd "$ROOT" && sha256sum "$IMAGE_RELATIVE") | tee "$ROOT/artifacts/p1/image.sha256"
du -sh "$IMAGE_FILE" | tee "$ROOT/artifacts/p1/image-size.txt"

echo ""
echo "=================================================="
echo "  ExamOS image built successfully!"
echo "  Image: $IMAGE_FILE"
echo ""
echo "  To boot in QEMU:"
echo "    bash scripts/run-qemu.sh"
echo ""
echo "  To provision more candidates:"
echo "    bash scripts/provision-candidate.sh <CANDIDATE_ID>"
echo "=================================================="
