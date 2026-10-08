# ExamOS Phase 1 (P1) — Build Instructions & Appliance Generation

## 1. Prerequisites

- **Host OS**: Ubuntu 24.04 / 26.04 LTS (Native or WSL2)
- **Toolchain**: GCC/G++ 13+, GNU Make, Linux Kernel Headers
- **Image Builders**: `mkosi` v26, `systemd-container`, `xorriso`
- **Virtualization**: `qemu-system-x86`, `ovmf`, `swtpm`
- **Libraries**: `libssl-dev`, `libcurl4-openssl-dev`, `libudev-dev`

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    build-essential gcc g++ make \
    libssl-dev libcurl4-openssl-dev libudev-dev \
    mkosi systemd-container xorriso \
    qemu-system-x86 ovmf swtpm \
    nftables apparmor apparmor-utils
```

---

## 2. Compiling Native C/C++ Subsystems

```bash
# Clean previous objects and build all subsystems
make clean
make all

# Verify built binaries:
# - kiosk/launcher/examos-kiosk-launcher
# - agent/examos-agent
# - proctoring/examos-proctor
# - server/examos-server
```

---

## 3. Building the Raw Appliance Image

```bash
cd image
sudo mkosi build
```

This generates:
- `image/examos.raw` (Bootable UEFI GPT disk image)
- `image/examos.raw.efi` (Unified Kernel Image)

---

## 4. Generating the Bootable ISO Image

```bash
bash scripts/build-iso.sh
```

Output:
- `artifacts/iso/examos-appliance-v0.2.0.iso`
- `artifacts/iso/examos-appliance-v0.2.0.iso.sha256`

---

## 5. Running P1 Automated Tests

```bash
# Run full static and dynamic gate test suite
bash tests/p1/collect-artifacts.sh
bash tests/p1/kiosk.sh
bash tests/p1/network.sh
bash tests/p1/performance.sh
bash tests/p1/gate.sh
```
