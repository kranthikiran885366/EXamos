# SPPIO / ExamOS — Common Criteria Security Target (ISO/IEC 15408 / STQC IC3S EAL4)

## 1. ST Introduction
- **TOE Name**: SPPIO / ExamOS Tamper-Proof Security-Hardened OS (`v2.19.0`)
- **Evaluation Assurance Level**: **EAL4** (Methodically Designed, Tested, and Reviewed)
- **Certification Scheme**: MeitY STQC **Indian Common Criteria Certification Scheme (IC3S)** under **ISO/IEC 15408-1/2/3**
- **TOE Type**: Hardened Examination & Defence-Tier Endpoint Operating System

## 2. TOE Architecture & Security Boundary
1. **Boot & Filesystem Integrity**: UEFI Secure Boot + `dm-verity` SquashFS + GPT A/B Partitions (`image/scripts/dm-verity-setup.sh`, `image/scripts/ab-partition-setup.sh`)
2. **Firmware Resiliency**: NIST SP 800-193 Protect/Detect/Recover (`image/scripts/pfr-800-193-verify.sh`)
3. **Remote Attestation**: Keylime-compatible TPM 2.0 Quote + Linux IMA SHA-256 PCR-10 Replay (`agent/attestation/ima_keylime.c`)
4. **Kernel Runtime Enforcement**: eBPF / BPF-LSM (`kernel/bpf_lsm/examos_lsm.bpf.c`) + SELinux MLS (`examos_mls.te`) + Strict IOMMU/DMA Lockdown (`99-examos-dma-lockdown.rules`)
5. **Display Isolation**: Wayland + Cage Single-Application Compositor (`kiosk/launcher/launcher.c`)
6. **Post-Quantum Cryptography**: FIPS 203 **ML-KEM-768** & FIPS 204 **ML-DSA-65** (`rust-services/sppio-pqc`)
7. **Memory-Safe Privileged Services & Behavioral AI**: Rust `sppio-securityd` + `sppio-behavioral-ai` (BadUSB HID & Wayland overlay detection + tamper-triggered RAM zeroization)
8. **Separation Kernel Architecture**: seL4 / CAmkES domain isolation specification (`kernel/sel4/examos_domains.camkes`)

## 3. Security Functional Requirements (SFRs — ISO/IEC 15408-2)

| SFR Class | Component | Implementation Mapping in SPPIO |
| :--- | :--- | :--- |
| **FCS_CKM.1 / .4** | Cryptographic Key Generation & Destruction | `sppio-pqc` (`KemKeypair`, `DsaKeypair`) + `VolatileKeyVault::tamper_zeroize` (`zeroize::Zeroize`) |
| **FCS_COP.1** | Cryptographic Operation | FIPS 203 ML-KEM-768 encapsulation, FIPS 204 ML-DSA-65 signing, SHA3-256 / SHA-256 |
| **FDP_IFC.1 / ACF.1** | Information Flow & Access Control | SELinux MLS (`s0:c0`..`s3:c0.c2`) + BPF-LSM (`lsm/bprm_check_security`, `lsm/socket_connect`) |
| **FIA_UAU.2 / UID.2** | User & Hardware Token Authentication | TOTP MFA, PKCS#11 hardware smartcard token verification for air-gapped updates |
| **FMT_SMF.1 / SMR.1** | Security Management & Roles | RBAC separation of duties (`exam.manage` vs `exam.approve`, `release.manage` vs `release.approve`) |
| **FPT_TST.1** | TSF Self-Test | `p2-startup-validator.sh`, `pfr-800-193-verify.sh`, `sppio-securityd --self-test` |
| **FPT_PHP.3** | Resistance to Physical Attack | IOMMU/Thunderbolt DMA lockdown + tamper-triggered RAM key zeroization |
| **FAU_GEN.1 / STG.2** | Audit Generation & Tamper-Evident Storage | Append-only HMAC-SHA256 hash-chained audit ledger (`tools/exam-event-verify.c`) |

## 4. Security Assurance Requirements (SARs — EAL4)
- **ADV_ARC.1 / ADV_FSP.4 / ADV_IMP.1 / ADV_TDS.3**: Complete architectural, functional, implementation, and modular design decomposition across `kernel/`, `rust-services/`, `agent/`, `server/`, `image/`.
- **ATE_COV.2 / ATE_DPT.1 / ATE_FUN.1 / ATE_IND.2**: Automated unit, integration, and regression gates (`tests/server/`, `tests/release/`, `tests/production/`, `rust-services` tests).
- **ALC_CMS.4 / ALC_DVS.1 / ALC_LCD.1 / ALC_TAT.1**: Reproducible build provenance, release signing, and quarantined placeholder tracking (`server/migrations/041_release_engineering_pipeline.sql`).
- **AVA_VAN.3**: Vulnerability analysis covering BadUSB HID injection, Wayland overlay snooping, DMA PCIe/Thunderbolt attacks, harvest-now-decrypt-later quantum threats, and firmware implants.
