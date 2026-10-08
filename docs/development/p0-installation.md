# P0 installation

## Supported host

Use a real Ubuntu/Debian Linux build host with KVM and UEFI support.

## Install dependencies

```bash
sudo apt update
sudo apt install -y \
  git \
  qemu-system-x86 \
  qemu-utils \
  ovmf \
  swtpm \
  swtpm-tools \
  tpm2-tools \
  sbsigntool \
  efitools \
  cryptsetup-bin \
  squashfs-tools \
  mkosi \
  debootstrap \
  uidmap \
  systemd-container \
  python3 \
  ca-certificates \
  openssl
```

## Verify after install

```bash
uname -s
uname -m
ls -l /dev/kvm
mkosi --version
qemu-system-x86_64 --version
swtpm --version
tpm2_pcrread --version
```

This document reflects the intended environment; it is not claiming the current Windows workspace satisfies it.
