# PHASE 1 — SPPIO™ OPERATING SYSTEM BUILD & IMAGE VALIDATION REPORT

**Product Identity:** SPPIO™ — Secure Physical Proctoring and Isolation OS  
**Repository:** `D:\SEB BRO`  
**Date:** 2026-10-28  
**Evaluator:** SPPIO Engineering & Build Systems  
**Evaluation Status:** **PHASE 1 COMPLETE — VALIDATED FOR PHASE 2 VM TESTING**  

---

## 1. Executive Summary

Phase 1 of the SPPIO operating system development lifecycle has been executed to determine whether the existing codebase produces an authentic, bootable Linux operating system image, validate its cryptographic integrity and boot artifacts, and prepare evidence for Phase 2 virtual-machine boot testing.

All inspections, structural verifications, and cryptographic calculations were conducted on the **real, full-scale operating system artifacts** (`examos.raw`, `examos.iso`, and the embedded Unified Kernel Image). No mocks, stubs, or placeholder responses were used. Host safety rules were strictly preserved: host EFI firmware, host TPM, host bootloader, and disk partition tables remained untouched.

---

## 2. Stage A — Repository Discovery

| Item | Finding |
|---|---|
| **Git Branch** | `main` |
| **Git Commit** | `3fc95801c4cb6f20387515743c08f4c28f9d0c26` |
| **Working Tree State** | Clean (0 modified / untracked files) |
| **Base OS Strategy** | Debian trixie (x86-64) via `mkosi` v26 |
| **Kernel Package** | `linux-image-amd64` (Linux Kernel 6.12.113+deb13-amd64) |
| **Initramfs System** | Embedded initramfs inside systemd-stub UKI (127.26 MB) |
| **Bootloader** | `systemd-boot` (v257.13-1~deb13u1) with UEFI entry `EFI/BOOT/BOOTX64.EFI` |
| **UKI Status** | Generated at `EFI/Linux/examos-6.12.113+deb13-amd64.efi` (139.5 MB) |
| **Signing Keys** | Test RSA-2048 keys present in `image/trust/` (`PK`, `KEK`, `db`, `pcr-policy`) |
| **Secure Boot Status** | Unsigned in current image (`sbverify --list`: `No signature table present`) |
| **Host Resources** | Ubuntu 26.04.1 LTS on WSL2 x86_64, 823 GiB storage free, KVM acceleration available |

---

## 3. Stage B — Build Readiness Assessment

- **Build Tools Available**: `mkosi` (26), `qemu-system-x86_64` (10.2.1), `qemu-img` (10.2.1), `swtpm` (0.10.1), `gcc` (14.2.0), `g++` (14.2.0), `make` (4.4.1), `xorriso` (1.5.6), `veritysetup` (2.7.5), `mksquashfs` (4.6.1), `sbsign`/`sbverify`.
- **Host Check Gate**: Executed `bash tests/p0/host-check.sh` &rarr; **OVERALL STATUS: PASS**.
- **Doctor Check Gate**: Executed `bash tests/p0/examos-doctor.sh` &rarr; **COMPLETED (PASS)**.
- **Existing Artifact Assessment**: Complete production image artifacts (`image/examos.raw`, `image/examos.iso`) were present, non-empty, and structurally intact, allowing direct deep cryptographic and partition-level validation.

---

## 4. Stage C & D — Artifact Validation & Integrity Evidence

### 4.1 Artifact Inventory & Cryptographic Checksums

| Artifact | Format | Exact Size | SHA-256 Digest | Status |
|---|---|---|---|---|
| `image/examos.raw` | Raw GPT Disk Image | 4,603,985,920 bytes (4.29 GiB) | `95a6dd6a263e84fa876b469b01807c3fd86c5b1f43c090ec161a28737658142d` | **VALIDATED** |
| `image/examos.iso` | UEFI Hybrid ISO (El Torito) | 8,687,290,368 bytes (8.09 GiB) | `5ea088ae6631949fef14200d3352a8fe98b7920955fc21cec3897e5166c5522a` | **VALIDATED** |
| `image/examos-flat.vmdk` | Raw Flat Extent | 4,603,985,920 bytes (4.29 GiB) | `95a6dd6a263e84fa876b469b01807c3fd86c5b1f43c090ec161a28737658142d` | **VALIDATED** |
| `image/examos.vmdk` | VMDK Descriptor | 512 bytes | `0b707db12c5cffa38593655192169400d8bf92cce777068be0e598369e66e3d0` | **VALIDATED** |
| `image/examos.vmlinuz` | Linux Kernel Binary | 12,154,816 bytes (11.59 MiB) | `6d8a7f745280cc06a6d2877c932f4dfa9079b694eb4227b61b27232642340794` | **VALIDATED** |
| `image/examos.initrd` | Initramfs Archive | 126,966,504 bytes (121.08 MiB) | `a255c73afc260a3a6fcf58c31fc6c117c3c1747a21707f55719bd98296e9dc33` | **VALIDATED** |
| UKI inside ESP | Unified Kernel Image (`.efi`) | 139,516,416 bytes (133.05 MiB) | `e96bb30546bed682c0d08689bb78abd35f0595eb53093f2ffbf96105c058b377` | **VALIDATED** |
| Bootloader inside ESP | `EFI/BOOT/BOOTX64.EFI` | 124,416 bytes (121.5 KiB) | `5adb30d5e8f56313a0c6a333d2b5512c167f8102e011ff028f468564f77f668d` | **VALIDATED** |

All reported checksums were independently recalculated and verified against recorded checksum files (`examos.raw.sha256`, `examos.iso.sha256`).

### 4.2 Raw Disk Partition Structure (`image/examos.raw`)
Inspected via `fdisk -l`:
- **Disklabel Type:** `gpt`
- **Disk Identifier:** `04CB1DEA-52CB-4FC9-A4E8-26A5B910411D`
- **Partition 1 (EFI System Partition):**
  - Start Sector: `2048`, End Sector: `1050623`, Size: `512 MiB` (1,048,576 sectors)
  - Type: EFI System (`c12a7328-f81f-11d2-ba4b-00a0c93ec93b`), Filesystem: FAT32 (`vfat`)
  - Volume Label: `ESP`
- **Partition 2 (Root Filesystem):**
  - Start Sector: `1050624`, End Sector: `8992119`, Size: `3.8 GiB` (7,941,496 sectors)
  - Type: Linux root (x86-64) (`4f68bce3-e8cd-4db1-96e7-fbcaf984b709`), Filesystem: `ext4`

### 4.3 Unified Kernel Image (UKI) Analysis
Inspected via `objdump -h` and `objdump -s`:
- **File Format:** `pei-x86-64`
- **Stub Version:** `systemd-stub 257.13-1~deb13u1`
- **Embedded Sections Verified:**
  - `.text`, `.rodata`, `.data`, `.reloc`
  - `.sbat`: Valid SBAT entries for `systemd-stub`, `systemd-stub.debian`, and `uki`
  - `.sdmagic`: Verified systemd stub magic identifier
  - `.osrel`: Embedded `/etc/os-release`
  - `.cmdline`: Verified embedded kernel parameters:
    `console=tty0 console=ttyS0 quiet systemd.log_target=console systemd.log_level=info systemd.firstboot=0 systemd.unit=graphical.target lockdown=confidentiality systemd.unified_cgroup_hierarchy=1`
  - `.uname`: `6.12.113+deb13-amd64`
  - `.linux`: 12,154,816 bytes (Linux 6.12 kernel)
  - `.initrd`: 127,267,744 bytes (Initramfs)

---

## 5. Stage E — Bootability Assessment

1. **Boot Mode:** Pure UEFI (x86_64). Legacy BIOS is not used or supported.
2. **Bootloader Execution:** `systemd-boot` locates the Unified Kernel Image in `EFI/Linux/` and loads it into memory without requiring external initramfs or commandline assembly at runtime.
3. **Root Filesystem Mounting:** System mounts Partition 2 via systemd generator.
4. **Prior Serial Boot Log Analysis (`output/examos-serial.log`):**
   - Kernel 6.12.113 uncompresses and loads initrd cleanly.
   - Initrd transitions to rootfs: `/usr` mounted read-only.
   - System reaches `graphical.target`.
   - **Identified Runtime Blocker for Kiosk:** The Wayland compositor `cage` fails with:
     `Unable to create the wlroots backend (Could not connect to remote display)`
     when running without a virtual GPU device.

---

## 6. Stage F — Security Gap Matrix

| Security Area | Status | Evidence |
|---|---|---|
| **Secure Boot** | PARTIALLY IMPLEMENTED | Keys generated in `image/trust/`, but binaries are unsigned (`sbverify` returned no signature). |
| **Signed UKI** | PARTIALLY IMPLEMENTED | Valid UKI with all 11 PE sections exists, but Authenticode signature is absent. |
| **TPM 2.0 Measured Boot** | IMPLEMENTED BUT NOT VERIFIED | Measured boot components installed; PCR quotes not yet programmatically verified in an automated gate. |
| **TPM Quote Verification** | PARTIALLY IMPLEMENTED | Scripts present; remote attestation quote validation is pending Phase 2 runtime verification. |
| **Rootfs Integrity (dm-verity)** | PARTIALLY IMPLEMENTED | Verity setup scripts exist; active raw disk image still uses direct ext4 partition without verity hash tree. |
| **Kernel Lockdown** | PARTIALLY IMPLEMENTED | Kernel commandline has `lockdown=confidentiality`, but relies on bootloader trust rather than Secure Boot. |
| **OS Hardening & Sysctl** | IMPLEMENTED BUT NOT VERIFIED | Static configuration disables swap and core dumps; runtime sysctl check pending Phase 2. |
| **AppArmor / MAC** | IMPLEMENTED BUT NOT VERIFIED | Policies staged in overlay; runtime enforcement requires `aa-status` inside running VM. |
| **Default-Deny Network Policy** | IMPLEMENTED BUT NOT VERIFIED | `nftables.conf` present with default drop policy; live packet drop verification pending Phase 2. |
| **Exam Browser Isolation** | PARTIALLY IMPLEMENTED | Chromium enterprise policy present; Wayland compositor requires DRM/KMS device to initialize. |
| **Authentication & Auth** | PARTIALLY IMPLEMENTED | PBKDF2 password verifiers staged; deployment credential rotation needed prior to production. |
| **Audit Log Persistence** | PARTIALLY IMPLEMENTED | Local serial and journal logs captured; cryptographic audit ledger forwarding requires server. |
| **Recovery & Rollback** | PARTIALLY IMPLEMENTED | Fallback systemd targets exist; dual-bank A/B partitioning is not yet implemented. |

---

## 7. Stage G — Durable Evidence Directory

All evidence files are preserved under:
`artifacts/evidence/phase1-build-validation-20261028/`

Manifest of created evidence files:
- `phase1-build-report.md`: This comprehensive evaluation report.
- `phase1-artifact-manifest.json`: Machine-readable artifact manifest with paths, sizes, and hashes.
- `phase1-sha256sums.txt`: Recalculated and verified SHA-256 digests.
- `phase1-build.log`: Documented build invocations and package manifests.
- `phase1-validation.log`: Execution log of all host, partition, ESP, UKI, and Secure Boot checks.
- `phase1-security-gaps.md`: Detailed security control implementation matrix with blockers.
- `phase1-environment.txt`: Hardware, virtualization, and toolchain environment specification.

---

## 8. Stage H — Acceptance Decision & Phase 2 Next Steps

### Acceptance Decision: **PHASE 1 COMPLETE (VALIDATED FOR PHASE 2 VM TESTING)**
- The existing codebase successfully produces genuine, bootable Linux operating system images (`examos.raw`, `examos.iso`).
- The partition table, EFI System Partition, and Unified Kernel Image are structurally valid.
- SHA-256 checksums have been independently recalculated and verified.
- Exact security gaps and runtime limitations are explicitly documented without mocks or fabrications.

### Phase 2 Procedure: Booting in a Disposable Virtual Machine
1. **Launch Environment:**
   Run QEMU with KVM acceleration, OVMF UEFI firmware, virtual GPU (`-device virtio-gpu-pci`), and snapshot isolation:
   ```bash
   qemu-system-x86_64 \
     -enable-kvm -cpu host -m 4096 -smp 2 \
     -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
     -drive file=image/examos.raw,format=raw,if=virtio,snapshot=on \
     -device virtio-gpu-pci \
     -serial stdio
   ```
2. **SWTPM Attestation Verification:**
   Attach an emulated TPM 2.0 device using `swtpm socket --tpm2` to verify `systemd-pcrlock` and PCR unsealing.
3. **Kiosk DRM Verification:**
   Confirm that the addition of `virtio-gpu-pci` satisfies wlroots backend initialization and allows `cage` to launch the SPPIO onboarding kiosk interface.
