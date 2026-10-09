# ExamOS Phase 0 (P0) — Release Record

## 1. Release Objective
Phase 0 establishes the verified development foundation, tooling discovery, and automated build-to-boot pipeline for ExamOS.

## 2. Environment & Tooling Baseline
- **Host OS:** Ubuntu 26.04.1 LTS (Resolute Raccoon) x86_64
- **Kernel:** Linux 6.6.87.2-microsoft-standard-WSL2
- **Image Builder:** mkosi 26
- **Emulator:** QEMU 10.2.1
- **Firmware:** OVMF 4M (`/usr/share/OVMF/OVMF_CODE_4M.fd`)
- **Virtual TPM:** swtpm 0.10.1 & tpm2-tools 5.7
- **Secure Boot Tools:** sbsign 0.9.4 & efitools
- **Integrity Tools:** veritysetup 2.8.4 & mksquashfs 4.7.5

## 3. Verified Artifacts
- **Disk Image:** `image/examos.raw`
- **Checksum:** Measured in `artifacts/p0/image.sha256`
- **Size Baseline:** Measured in `artifacts/p0/image-size.txt`
- **Boot Verification:** Verified in `artifacts/p0/boot.log`

## 4. Test Results
- **Host Check:** PASS
- **Doctor Check:** PASS
- **Repository Integrity:** PASS
- **mkosi Build:** PASS
- **QEMU + OVMF Boot:** PASS
- **CI Workflow:** PASS

## 5. Gate Decision
**PHASE 0 STATUS: PASS**
Release Tag: `v0.1.0`
