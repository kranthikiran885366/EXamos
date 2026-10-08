# P0 troubleshooting

## Observed current issue

This workspace is running under MSYS/Windows, not a Linux build host. The host lacks `/dev/kvm`, UEFI, and the P0 build toolchain.

## Common issues

- KVM unavailable: verify BIOS/UEFI virtualization settings and use a Linux host
- OVMF missing: install `ovmf`
- mkosi missing or syntax mismatch: inspect `mkosi --help` and the installed version
- QEMU missing: install `qemu-system-x86`
- insufficient disk space: verify free space with `df -h "$HOME"`
- repository secret material: remove any private keys and validate with `tests/p0/repository-check.sh`

## Required result

When the prerequisites are missing, do not invent a pass; use FAIL/BLOCKED instead.
