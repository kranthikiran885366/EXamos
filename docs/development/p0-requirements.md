# ExamOS Phase 0 (P0) — Host & Tooling Requirements

## 1. Objective
Phase 0 establishes a reproducible, testable, production-grade Linux development and build foundation for ExamOS.

## 2. Host System Requirements
- **Host Operating System:** Ubuntu 26.04 LTS (or compatible modern Debian/Ubuntu Linux).
- **CPU Architecture:** x86-64 with hardware virtualization extensions (Intel VT-x `vmx` or AMD-V `svm`).
- **Hardware Acceleration:** `/dev/kvm` accessible for virtualized guest acceleration.
- **Storage Capacity:** Minimum 20 GB available disk space (100 GB recommended for full multi-release builds).
- **Memory:** Minimum 4 GB RAM (16 GB recommended).

## 3. Required Toolchain
| Tool | Package | Required Version | Verified on Host |
|---|---|---|---|
| **mkosi** | `mkosi` | &ge; 20 | 26 |
| **QEMU** | `qemu-system-x86` | &ge; 8.0 | 10.2.1 |
| **OVMF** | `ovmf` | UEFI Firmware | `/usr/share/OVMF/OVMF_CODE_4M.fd` |
| **swtpm** | `swtpm`, `swtpm-tools` | &ge; 0.7 | 0.10.1 |
| **TPM 2.0 Tools** | `tpm2-tools` | &ge; 5.0 | 5.7 |
| **Secure Boot** | `sbsigntool`, `efitools` | Standard | 0.9.4 |
| **dm-verity** | `cryptsetup-bin` | Standard | 2.8.4 |
| **SquashFS** | `squashfs-tools` | Standard | 4.7.5 |
