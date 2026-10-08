# Installation

## Install the build host packages

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

## Verify tools

```bash
git --version
mkosi --version
qemu-system-x86_64 --version
swtpm --version
tpm2_pcrread --version
```

## Host checks

```bash
uname -m
ls -l /dev/kvm
```

The build host should be Ubuntu 26.04 or a matching Ubuntu-derived Linux VM with KVM and UEFI support.
