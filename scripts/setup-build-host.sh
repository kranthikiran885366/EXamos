#!/usr/bin/env bash
# ExamOS WSL2 / Ubuntu Build Host Setup
# Run once on a fresh WSL2 Ubuntu 22.04+ instance.
# Usage: bash scripts/setup-build-host.sh
set -euo pipefail

echo "=================================================="
echo "  ExamOS Build Host Setup"
echo "=================================================="

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/5] Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libcap-dev \
    libseccomp-dev \
    qemu-system-x86 \
    qemu-utils \
    ovmf \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    xorriso \
    mtools \
    dosfstools \
    squashfs-tools \
    systemd-container \
    debootstrap \
    arch-install-scripts \
    openssl \
    jq \
    shellcheck

# ── 2. mkosi ─────────────────────────────────────────────────────────────────
echo "[2/5] Installing mkosi..."
# Try apt first (may be older version)
if apt-cache show mkosi &>/dev/null; then
    MKOSI_APT_VER=$(apt-cache show mkosi | grep '^Version:' | head -1 | awk '{print $2}')
    echo "  apt mkosi version: $MKOSI_APT_VER"
fi
# Install latest from pip for best Debian Trixie support
pip3 install --user --upgrade mkosi
MKOSI_BIN="$HOME/.local/bin/mkosi"
if [[ ! -x "$MKOSI_BIN" ]]; then
    sudo apt-get install -y mkosi
fi
echo "  mkosi: $(mkosi --version 2>/dev/null || echo 'installed')"

# ── 3. OVMF firmware paths ────────────────────────────────────────────────────
echo "[3/5] Locating OVMF firmware..."
OVMF_PATHS=(
    /usr/share/OVMF/OVMF_CODE.fd
    /usr/share/OVMF/OVMF_CODE_4M.fd
    /usr/share/ovmf/OVMF.fd
    /usr/share/qemu/OVMF.fd
)
OVMF_FOUND=""
for p in "${OVMF_PATHS[@]}"; do
    if [[ -f "$p" ]]; then
        OVMF_FOUND="$p"
        break
    fi
done
if [[ -z "$OVMF_FOUND" ]]; then
    echo "  WARNING: OVMF firmware not found. Installing ovmf package..."
    sudo apt-get install -y ovmf
fi
echo "  OVMF: ${OVMF_FOUND:-installed}"

# ── 4. Verify QEMU ────────────────────────────────────────────────────────────
echo "[4/5] Verifying QEMU..."
qemu-system-x86_64 --version | head -1

# ── 5. PATH setup ─────────────────────────────────────────────────────────────
echo "[5/5] Ensuring ~/.local/bin is on PATH..."
PROFILE_FILE="$HOME/.bashrc"
if ! grep -q 'HOME/.local/bin' "$PROFILE_FILE" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$PROFILE_FILE"
    echo "  Added ~/.local/bin to PATH in $PROFILE_FILE"
fi
export PATH="$HOME/.local/bin:$PATH"

echo ""
echo "=================================================="
echo "  Build host setup complete!"
echo ""
echo "  Next steps:"
echo "  1. Open a new terminal (or: source ~/.bashrc)"
echo "  2. cd to your ExamOS project directory"
echo "  3. Run: bash scripts/build-full-image.sh \\"
echo "  Credentials are provisioned after installation by the deployment authority."
echo "  4. Boot: bash scripts/run-qemu.sh"
echo "=================================================="
