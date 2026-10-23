# ExamOS P0 requirements

## Host requirements

- Ubuntu 26.04 LTS recommended as the build host
- x86_64 architecture required
- KVM enabled
- UEFI firmware available
- At least 50 GB free disk space
- 16 GB RAM recommended

## Tooling requirements

- git
- qemu-system-x86
- qemu-utils
- ovmf
- swtpm
- swtpm-tools
- tpm2-tools
- sbsigntool
- efitools
- cryptsetup-bin
- squashfs-tools
- mkosi
- debootstrap
- uidmap
- systemd-container

## Acceptance criteria

- Host validation passes
- mkosi installs and runs
- Image builds from a clean checkout
- The build can be booted under QEMU with OVMF
- Artifacts and logs are captured
- CI gate runs and reports PASS
