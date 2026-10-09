# ExamOS Phase 0 (P0) — Troubleshooting Guide

## 1. Observed and Potential Issues

### KVM Device Permission
- **Symptom:** `/dev/kvm` exists but QEMU emits `Could not access KVM kernel module: Permission denied`.
- **Resolution:** Add developer user to the `kvm` group: `sudo usermod -aG kvm $USER`.

### OVMF Firmware Discovery
- **Symptom:** `OVMF_CODE.fd` not found.
- **Resolution:** Debian/Ubuntu packages place 4MB OVMF firmware in `/usr/share/OVMF/OVMF_CODE_4M.fd`. `tests/p0/boot.sh` dynamically locates both standard and 4M paths.

### mkosi Option Syntax
- **Symptom:** Unrecognized configuration keys between mkosi v14, v24, and v26.
- **Resolution:** Verify options directly against `mkosi --help` on the build host. The repository targets mkosi v26 standard format.
