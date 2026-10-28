# SPPIO™ Security Gap & Implementation Status Matrix (Phase 1)

Date: 2026-10-28  
Evaluator: Phase 1 OS Build & Validation Pipeline  
Scope: Operating System Image, Boot Chain, Cryptographic Controls, and Hardware Enforcement  

---

| Security Control Area | Current Status | Supporting Evidence & Exact Findings |
|---|---|---|
| **Secure Boot** | **PARTIALLY IMPLEMENTED** | RSA-2048 development keys (`PK`, `KEK`, `db`) exist in `image/trust/`, but running `sbverify --list` on extracted `BOOTX64.EFI` confirms `No signature table present`. The image does not enforce Secure Boot signature validation at boot time. |
| **Signed UKI** | **PARTIALLY IMPLEMENTED** | A full systemd-stub Unified Kernel Image exists at `EFI/Linux/examos-6.12.113+deb13-amd64.efi` (139.5 MB) containing `.linux`, `.initrd`, `.cmdline`, `.osrel`, and `.sbat` sections. However, `sbverify --list` confirms no Authenticode signature table is attached. |
| **TPM 2.0 Measured Boot** | **IMPLEMENTED BUT NOT VERIFIED** | `systemd-stub` and `systemd-pcrlock` are installed; serial boot logs show `systemd-pcrlock` attempting PCR measurements. However, cryptographically verified PCR quote validation against expected hash reference values is not yet automated. |
| **TPM Quote Verification** | **PARTIALLY IMPLEMENTED** | `tpm2-tools` and TPM unsealing scripts (`tpm-seal-secrets.sh`, `enroll-physical-tpm.sh`) are present in the image overlay. However, remote attestation quote validation in a live server-agent exchange is not verified at runtime. |
| **Root Filesystem Integrity** | **PARTIALLY IMPLEMENTED** | Build tooling for dm-verity hash trees and SquashFS exists (`image/scripts/dm-verity-setup.sh`). However, the active disk image `image/examos.raw` mounts a direct ext4 partition on Partition 2 rather than an authenticated dm-verity block device. |
| **Kernel & Boot-Chain Integrity** | **PARTIALLY IMPLEMENTED** | Debian Linux kernel 6.12.113 is configured with `lockdown=confidentiality` on the embedded `.cmdline`. However, without a cryptographically enforced Secure Boot chain, the kernel command line could theoretically be bypassed if an unauthenticated bootloader is swapped. |
| **OS Hardening** | **IMPLEMENTED BUT NOT VERIFIED** | Static sysctl configuration (`etc/sysctl.d/99-examos-security.conf`), swap disabling, core dump restriction, and module lock service exist in the overlay. Full runtime sysctl verification is deferred to Phase 2 VM testing. |
| **AppArmor / MAC** | **IMPLEMENTED BUT NOT VERIFIED** | AppArmor package is installed, and policy definitions exist for `examos-kiosk` and `chromium`. Enforcing status has not been verified in a running system via `aa-status`. |
| **Default-Deny Network Policy** | **IMPLEMENTED BUT NOT VERIFIED** | `nftables` is enabled with `etc/nftables.conf` dropping all unsolicited input and forwarded traffic. Active ruleset filtering has not been tested with synthetic network probes in this phase. |
| **Exam-Browser Configuration** | **PARTIALLY IMPLEMENTED** | Chromium enterprise policies (`examos_policies.json`) restrict devtools, popups, and unauthorized extensions. However, in previous VM serial runs, the Wayland display manager (`cage`) failed with `Unable to create the wlroots backend` when running without proper DRM/KMS device access. |
| **Authentication & Authorization** | **PARTIALLY IMPLEMENTED** | First-boot credentials scripts exist, PBKDF2 hashing is used in `admin.conf`. However, placeholder seeds and developer credentials must be securely rotated and provisioned via deployment authority prior to production. |
| **Audit-Log Persistence** | **PARTIALLY IMPLEMENTED** | Serial logging captures boot output; systemd journal is configured. However, tamper-evident cryptographic ledger forwarding (`SPPIO-Ledger™`) requires active connection to `examos-server`. |
| **Recovery & Rollback Behavior** | **PARTIALLY IMPLEMENTED** | Emergency fallback target `examos-lockdown-failed.target` and operator recovery scripts exist. Dual-partition A/B rollback is not yet implemented. |

---

### Known Blockers for Production Release:
1. **Unsigned EFI Bootloader & UKI**: Before production deployment or hardware Secure Boot enrollment, `sbsign` must sign `BOOTX64.EFI` and the UKI using the `db` key.
2. **Wayland wlroots Backend in Headless VM**: The `cage` compositor crashes if no virtual GPU (e.g. `virtio-gpu-pci` or `qxl`) or DRM node (`/dev/dri/card0`) is allocated. Phase 2 QEMU scripts must explicitly supply virtual display hardware or fallback to headless dummy DRM.
3. **dm-verity Active Mount**: Partition 2 must be switched to read-only SquashFS with an authenticated dm-verity hash tree and verified root hash parameter passed via kernel commandline.
