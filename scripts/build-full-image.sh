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

# ── Step 3: Compile all native C/C++, Rust, and eBPF subsystems ──────────────
echo "[3/6] Compiling native C/C++, Rust, and eBPF subsystems..."
make -C "$ROOT" EXAMOS_USE_OPENCV=1 all
if command -v cargo >/dev/null 2>&1; then
    cargo build --release --manifest-path "$ROOT/rust-services/Cargo.toml"
else
    echo "ERROR: cargo (Rust toolchain) is required to build sppio-securityd." >&2
    exit 1
fi
if [ -f "$ROOT/kernel/bpf_lsm/Makefile" ]; then
    make -C "$ROOT/kernel/bpf_lsm" all
fi
if [ -f "$ROOT/kernel/bpf_xdp/Makefile" ]; then
    make -C "$ROOT/kernel/bpf_xdp" all
fi
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"
echo "  Binaries compiled (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)."

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
install -m 0755 "$ROOT/rust-services/target/release/sppio-securityd" "$STAGE_DIR/usr/local/bin/sppio-securityd"
install -D -m 0644 "$ROOT/kernel/bpf_lsm/examos_lsm.bpf.o" "$STAGE_DIR/usr/lib/examos/bpf/examos_lsm.bpf.o"
install -D -m 0644 "$ROOT/kernel/bpf_xdp/examos_xdp_filter.bpf.o" "$STAGE_DIR/usr/lib/examos/bpf/examos_xdp_filter.bpf.o"
install -D -m 0755 "$ROOT/image/scripts/pfr-800-193-verify.sh" "$STAGE_DIR/usr/local/bin/pfr-800-193-verify.sh"
install -D -m 0755 "$ROOT/image/scripts/ab-partition-setup.sh" "$STAGE_DIR/usr/local/sbin/ab-partition-setup.sh"
install -d "$STAGE_DIR/etc/systemd/system/multi-user.target.wants"
for unit in sppio-securityd.service examos-bpf-lsm.service examos-xdp-filter.service examos-pfr-verify.service examos-ab-commit.service; do
    if [ -f "$STAGE_DIR/etc/systemd/system/$unit" ]; then
        ln -sf "../$unit" "$STAGE_DIR/etc/systemd/system/multi-user.target.wants/$unit"
    fi
done
bash "$ROOT/scripts/generate-slsa-sbom.sh" "$ROOT" "$STAGE_DIR/usr/share/examos/supply-chain"
install -D -m 0755 "$ROOT/image/scripts/tpm-seal-secrets.sh" "$STAGE_DIR/usr/local/sbin/tpm-seal-secrets.sh"
install -D -m 0755 "$ROOT/image/scripts/tpm-luks2-enroll.sh" "$STAGE_DIR/usr/local/sbin/tpm-luks2-enroll.sh"
install -D -m 0755 "$ROOT/image/scripts/examos-rotate-keys.sh" "$STAGE_DIR/usr/local/sbin/examos-rotate-keys.sh"
install -D -m 0755 "$ROOT/image/scripts/examos-db-backup.sh" "$STAGE_DIR/usr/local/sbin/examos-db-backup.sh"
install -D -m 0755 "$ROOT/image/scripts/examos-nts-sync.sh" "$STAGE_DIR/usr/local/sbin/examos-nts-sync.sh"
install -D -m 0755 "$ROOT/image/scripts/examos-diag-bundle.sh" "$STAGE_DIR/usr/local/sbin/examos-diag-bundle.sh"
install -D -m 0755 "$ROOT/image/scripts/examos-preflight-check.sh" "$STAGE_DIR/usr/local/bin/examos-preflight-check.sh"
install -d "$STAGE_DIR/etc/systemd/system/timers.target.wants"
for timer in examos-key-rotate.timer examos-db-backup.timer; do
    if [ -f "$STAGE_DIR/etc/systemd/system/$timer" ]; then
        ln -sf "../$timer" "$STAGE_DIR/etc/systemd/system/timers.target.wants/$timer"
    fi
done
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
KIOSK_UNIT="$STAGE_DIR/etc/systemd/system/examos-kiosk.service"
PROCTOR_UNIT="$STAGE_DIR/etc/systemd/system/examos-proctor.service"
if ! grep -Fxq 'User=exam' "$KIOSK_UNIT" ||
   ! grep -Fxq 'Requires=examos-preflight.service' "$KIOSK_UNIT" ||
   ! grep -Fxq 'After=examos-preflight.service' "$KIOSK_UNIT" ||
   ! grep -Fxq 'PAMName=login' "$KIOSK_UNIT" ||
   ! grep -Fxq 'TTYPath=/dev/tty1' "$KIOSK_UNIT" ||
   ! grep -Fxq 'StandardInput=tty' "$KIOSK_UNIT" ||
   ! grep -Fxq 'RuntimeDirectory=examos-kiosk' "$KIOSK_UNIT" ||
   ! grep -Fxq 'RuntimeDirectoryMode=0700' "$KIOSK_UNIT" ||
   ! grep -Fxq 'Environment=LIBSEAT_BACKEND=logind' "$KIOSK_UNIT" ||
   ! grep -Fxq 'Environment=EXAMOS_ALLOWED_EXAM_HOSTS=staging.examos.example.edu,exam.university.edu,exam.alpha.edu,portal.beta.edu,sppio-os.vercel.app' "$KIOSK_UNIT" ||
   ! grep -Fxq 'ReadWritePaths=/run/examos-kiosk /tmp' "$KIOSK_UNIT" ||
   ! grep -Fxq 'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_SYS_CHROOT CAP_SYS_TTY_CONFIG' "$KIOSK_UNIT" ||
   ! grep -Fxq 'StandardOutput=journal' "$KIOSK_UNIT" ||
   ! grep -Fxq 'StandardError=journal' "$KIOSK_UNIT" ||
   ! grep -Fxq 'ExecStart=/usr/bin/env XDG_RUNTIME_DIR=/run/examos-kiosk /usr/bin/cage -s -- /usr/local/bin/examos-kiosk-launcher' "$KIOSK_UNIT" ||
   grep -Eq '^(User|Group)=root$|/run/user/|--no-sandbox|ExecStartPre=.*(mkdir|chown|chmod)|^Environment=WAYLAND_DISPLAY=' "$KIOSK_UNIT"; then
    echo "ERROR: kiosk service must use the unprivileged account and systemd-managed runtime directory." >&2
    exit 1
fi
APPARMOR_PROFILE="$STAGE_DIR/etc/apparmor.d/examos-kiosk"
if [[ ! -s "$STAGE_DIR/etc/chromium.d/README" ]] ||
   [[ -e "$STAGE_DIR/etc/apparmor.d/usr.bin.chromium" ]] ||
   ! grep -Fxq 'profile examos-kiosk /{usr/bin,usr/lib/chromium}/chromium flags=(enforce) {' "$APPARMOR_PROFILE" ||
   ! grep -Fxq '/usr/bin/uname             ix,' "$APPARMOR_PROFILE" ||
   ! grep -Fxq '/usr/bin/expr              ix,' "$APPARMOR_PROFILE" ||
   ! grep -Fxq '/usr/bin/findmnt            ix,' "$APPARMOR_PROFILE" ||
   ! grep -Fxq '/usr/lib/chromium/chromium Px -> examos-kiosk,' "$APPARMOR_PROFILE" ||
   ! grep -Fq 'userns,' "$APPARMOR_PROFILE" ||
   ! grep -Fq 'capability sys_admin,' "$APPARMOR_PROFILE" ||
   ! grep -Fxq '/usr/lib/chromium/chrome_crashpad_handler ix,' "$APPARMOR_PROFILE" ||
   ! grep -Fxq 'owner /proc/[0-9]*/mountinfo r,' "$APPARMOR_PROFILE" ||
   ! grep -Fxq 'owner /proc/[0-9]*/fd/      r,' "$APPARMOR_PROFILE" ||
   ! grep -Fxq '/etc/chromium.d/           r,' "$APPARMOR_PROFILE" ||
   ! grep -Fxq '/etc/chromium.d/*          r,' "$APPARMOR_PROFILE" ||
   ! grep -Fxq '/run/examos-kiosk/wayland-[0-9]* rw,' "$APPARMOR_PROFILE" ||
   ! grep -Fxq '/run/examos-kiosk/examos_kiosk_*/** rwkl,' "$APPARMOR_PROFILE" ||
   grep -Fq 'deny capability ptrace,' "$APPARMOR_PROFILE"; then
    echo "ERROR: Chromium AppArmor policy must allow its confined launcher/runtime paths without invalid ptrace capability rules." >&2
    exit 1
fi
if ! grep -Fxq 'Environment=XDG_RUNTIME_DIR=/run/examos-kiosk' "$PROCTOR_UNIT" ||
   ! grep -Fxq 'ReadWritePaths=/run/examos-kiosk /tmp' "$PROCTOR_UNIT" ||
   ! grep -Fxq 'Requires=examos-kiosk.service' "$PROCTOR_UNIT" ||
   grep -Fq '/run/user/1000' "$PROCTOR_UNIT"; then
    echo "ERROR: proctor service must use the kiosk-owned Wayland runtime directory." >&2
    exit 1
fi
READINESS_UNIT="$STAGE_DIR/etc/systemd/system/examos-kiosk-readiness.service"
READINESS_SCRIPT="$STAGE_DIR/usr/local/bin/examos-kiosk-readiness"
READINESS_TARGET_DROPIN="$STAGE_DIR/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf"
if ! grep -Fxq 'Environment=XDG_RUNTIME_DIR=/run/examos-kiosk' "$READINESS_UNIT" ||
   ! grep -Fxq 'Wants=examos-kiosk.service' "$READINESS_UNIT" ||
   ! grep -Fxq 'After=examos-kiosk.service' "$READINESS_UNIT" ||
   grep -Fxq 'Requires=examos-kiosk.service' "$READINESS_UNIT" ||
   ! grep -Fxq 'Wants=examos-kiosk-readiness.service' "$READINESS_TARGET_DROPIN" ||
   ! grep -Fxq 'TimeoutStartSec=90' "$READINESS_UNIT" ||
   ! grep -Fxq 'ExecStart=/usr/local/bin/examos-kiosk-readiness' "$READINESS_UNIT" ||
   ! grep -Fq 'XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is required}/wayland-0' "$READINESS_SCRIPT" ||
   ! grep -Fq 'EXAMOS_KIOSK_READY cage=1 chromium=1 wayland_socket=1' "$READINESS_SCRIPT" ||
   ! grep -Fq 'stable_seconds=10' "$READINESS_SCRIPT" ||
   ! grep -Fq 'EXAMOS_KIOSK_DIAGNOSTICS_COMPLETE' "$READINESS_SCRIPT" ||
   grep -Fq '/run/user/1000' "$READINESS_SCRIPT"; then
    echo "ERROR: kiosk readiness must verify the live compositor socket and Chromium in the managed runtime directory." >&2
    exit 1
fi
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

systemd-dissect --validate "$IMAGE_FILE"
VERIFY_DIR="$STAGE_DIR/image-verify"
mkdir -p "$VERIFY_DIR/etc/apparmor.d"
mkdir -p "$VERIFY_DIR/etc/chromium.d"
systemd-dissect --copy-from "$IMAGE_FILE" /etc/apparmor.d/examos-kiosk \
    "$VERIFY_DIR/etc/apparmor.d/examos-kiosk"
if ! cmp -s "$APPARMOR_PROFILE" "$VERIFY_DIR/etc/apparmor.d/examos-kiosk"; then
    echo "ERROR: Built image does not contain the canonical Chromium AppArmor profile." >&2
    exit 1
fi
systemd-dissect --copy-from "$IMAGE_FILE" /etc/chromium.d/README \
    "$VERIFY_DIR/etc/chromium.d/README"
if ! cmp -s "$STAGE_DIR/etc/chromium.d/README" "$VERIFY_DIR/etc/chromium.d/README"; then
    echo "ERROR: Built image is missing the Chromium wrapper's empty-config sentinel." >&2
    exit 1
fi
if systemd-dissect --copy-from "$IMAGE_FILE" /etc/apparmor.d/usr.bin.chromium \
    "$VERIFY_DIR/etc/apparmor.d/usr.bin.chromium" >/dev/null 2>&1; then
    echo "ERROR: Built image contains a competing legacy Chromium AppArmor profile." >&2
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
