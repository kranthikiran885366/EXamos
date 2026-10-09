# ExamOS Phase 0 (P0) — Tool Installation Guide

## 1. Package Installation
On Ubuntu 26.04 or Debian Linux build hosts, execute:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    git \
    qemu-system-x86 \
    ovmf \
    swtpm \
    swtpm-tools \
    tpm2-tools \
    sbsigntool \
    efitools \
    cryptsetup-bin \
    squashfs-tools \
    mkosi \
    systemd-container \
    debian-archive-keyring
```

## 2. KVM Permission Setup
Ensure the current developer user has read/write permissions to `/dev/kvm`:

```bash
sudo usermod -aG kvm "$USER"
```

*Note: Group membership updates require logging out and logging back in.*

## 3. Environment Verification
Run the ExamOS doctor diagnostic to verify all tools and firmware paths:

```bash
bash tests/p0/examos-doctor.sh
```
