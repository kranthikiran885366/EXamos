# SPPIO / ExamOS — Security Architecture Whitepaper (2-Page Executive Summary)

## 1. Purpose & Threat Model
SPPIO / ExamOS is a hardened, bare-metal examination and high-assurance technical recruitment OS engineered for universities, national testing agencies, and BFSI/enterprise assessment centers. Unlike browser-only lockdown extensions that run inside an untrusted host OS, SPPIO boots a dedicated, measured, read-only Linux environment anchored in hardware.

### Core Threats Mitigated
- **Host OS & VM Tampering**: Defeated via UEFI Secure Boot, TPM 2.0 measured boot (PCRs `0, 2, 4, 7, 11`), Anti-VM detection (CPUID, ACPI/DMI, `RDTSC`), and Kernel Lockdown in `confidentiality` mode.
- **Root & Kernel Escalation**: `CONFIG_MODULE_SIG_FORCE=y`, `kernel.modules_disabled=1`, `kernel.kexec_load_disabled=1`, eBPF LSM (`bprm_check_security`, `socket_connect`, inode-based `file_open`), and Intel CET / Clang CFI.
- **Network Exfiltration & DNS Tunneling**: eBPF XDP driver-layer packet filtering with strict allowlists and enforced DNS-over-TLS / DNS-over-HTTPS.
- **Peripheral & DMA Attacks**: USBGuard composite-device blocking (`HID+Storage`, `HID+CDC`, `HID+Wireless`), Thunderbolt suppression, and strict IOMMU DMA isolation.
- **Offline Disk Extraction**: LUKS2 full-disk encryption sealed to TPM 2.0 PCRs (`image/scripts/tpm-luks2-enroll.sh`).

## 2. Cryptographic Attestation & Key Release
1. **Authenticated Clock Sync**: `examos-nts-sync.sh` synchronizes boot time over NTS / TLS-verified server time before quote generation.
2. **TPM 2.0 + IMA Quote**: `examos-agent` presents a hardware-signed TPM quote, PCR 10 IMA measurement log, and mTLS device certificate to `sppio-core`.
3. **Device-Bound Key Release**: `sppio-core` verifies the quote against the enrolled EK/AK trust feed and wraps the exam decryption key using the device's TPM-bound public key.
4. **Tamper-Evident Audit Chain**: Security, proctoring, and hardware-guard events are hash-chained (`HMAC-SHA256` with scheduled key rotation via `examos-rotate-keys.sh`) and queued in an AES-256-GCM + HMAC-SHA256 offline WAL (`offline_buffer.c`) during transient lab Wi-Fi drops.

## 3. Supply Chain & Governance
- **SLSA & SBOM**: Reproducible image builds with signed SPDX SBOMs (`NOTICE` + `image/scripts/slsa-sbom.sh`).
- **Web Console Security**: `HttpOnly; SameSite=Strict; Secure` session cookies, strict Content-Security-Policy (`frontend/vercel.json`), mandatory TOTP 2FA for all console administrators, and brute-force/enumeration rate limiting across `/login`, `/recovery`, and `/register-institution?tab=track`.
