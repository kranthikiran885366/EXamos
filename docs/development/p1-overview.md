# ExamOS Phase 1 (P1) — Minimal Boot to Kiosk Architecture & Overview

## 1. Executive Summary

ExamOS Phase 1 (P1) establishes the first functional examination appliance runtime for secure, isolated testing. It boots an unprivileged candidate environment directly through UEFI/OVMF into Cage (Wayland) and Chromium kiosk mode without presenting a standard desktop environment, window manager, system tray, or interactive login prompt.

---

## 2. Boot & Runtime Execution Chain

```text
POWER ON
   │
   ▼
UEFI / OVMF Firmware
   │
   ▼
Unified Kernel Image / systemd-boot
   │
   ▼
Linux Kernel (Kernel Lockdown: Integrity, Yama ptrace: 3, BPF: restricted)
   │
   ▼
systemd (Default target: graphical.target)
   │
   ├─► examos-server.service (Admin Dashboard & Candidate Login API on port 8000)
   ├─► examos-agent.service (Attestation & Hardware Guard Agent)
   ├─► nftables.service (Default-Deny Firewall)
   │
   ▼
examos-kiosk.service
   │
   ▼
Unprivileged Candidate Account (User=exam, UID=1000, nologin shell)
   │
   ▼
Cage (Wayland Kiosk Compositor)
   │
   ▼
examos-kiosk-launcher (Native C Supervisor)
   │
   ▼
Chromium (App Mode, Ephemeral tmpfs RAM Profile, Lockdown Flags)
   │
   ▼
Configured Examination URL (HTTPS) / Candidate Authentication Portal
```

---

## 3. Subsystem Architecture

### 3.1 Security Server & Admin Dashboard (`server/`)
- **Native C POSIX HTTP/1.1 Engine**: Multi-threaded socket server (`main.c`).
- **Admin Control Portal (`/admin`)**: Protected by HTTP Basic Authentication with SHA-256 password verification (`admin/config_manager.c`, `admin/admin_dashboard.c`). Allows real-time exam URL updates, kiosk restarts, and telemetry inspection.
- **Candidate Verification Portal (`/`)**: Embedded candidate login interface for credentials verification before entering the active exam session (`login/candidate_login.c`).
- **Tamper-Evident Ledger (`/api/v1/ledger`)**: SHA-256 hash-chained immutable audit ledger (`events/ledger.c`).

### 3.2 Kiosk Runtime Supervisor (`kiosk/launcher/`)
- **Native C Supervisor (`launcher.c`)**: Manages Chromium child process under Cage.
- **Ephemeral RAM Profiles**: Uses `mkdtemp("/tmp/examos_kiosk_XXXXXX")` to ensure zero state persistence across sessions.
- **Configuration Resolution**: Dynamically reads `/etc/examos/exam.conf` or `EXAMOS_EXAM_URL`.
- **Crash Throttling & Self-Healing**: Automatically cleans up memory and restarts Chromium if terminated.

### 3.3 Endpoint Security & Kernel Hardening (`image/overlay/`)
- **Default-Deny Firewall (`etc/nftables.conf`)**: Inbound connections dropped; outbound restricted to DNS (53), HTTPS (443), and HTTP (80 for CRL/OCSP).
- **Kernel Sysctl Hardening (`etc/sysctl.d/99-examos-security.conf`)**: Ptrace scope 3 (YAMA), unprivileged BPF disabled, ASLR fully randomized, kptr restrict level 2.
- **Hardware & USB Guard (`etc/udev/rules.d/99-examos-usb-lockdown.rules`)**: Blocks USB Mass Storage (Class 08h) and unauthorized network adapters; authorizes only HID devices and system webcams.
- **AppArmor Mandatory Access Control (`etc/apparmor.d/examos-kiosk`)**: Restricts Chromium filesystem, process, and capability boundaries through one canonical attachment.
- **Chromium wrapper configuration**: `etc/chromium.d/README` is an intentional empty-config sentinel for Debian's wrapper loop; the build verifies it is present so an empty fragment glob cannot become a failing shell source.
- **Chromium procfs access**: The kiosk profile limits `mountinfo` and file-descriptor directory reads to owner-matched processes, needed by Chromium's shared-memory helper and Crashpad without granting general procfs access.

---

## 4. Phase Boundary Definition

| Feature | Phase 1 (P1) | Phase 2 (P2) | Phase 3 (P3) |
|---|---|---|---|
| Direct Kiosk Boot | ✅ Implemented | ✅ Implemented | ✅ Implemented |
| Unprivileged `exam` User | ✅ Implemented | ✅ Implemented | ✅ Implemented |
| Ephemeral Browser Profile | ✅ Implemented | ✅ Implemented | ✅ Implemented |
| Admin Dashboard URL Config | ✅ Implemented | ✅ Implemented | ✅ Implemented |
| Candidate Login Portal | ✅ Implemented | ✅ Implemented | ✅ Implemented |
| Default-Deny Firewall | ✅ Implemented | ✅ Enforced strict | ✅ Enforced strict |
| USB Port Lockdown | ✅ Implemented | ✅ Enforced strict | ✅ Enforced strict |
| Read-Only dm-verity Rootfs | ⏳ P2 Scope | ✅ Implemented | ✅ Implemented |
| Chromium Managed Policies | ⏳ P2 Scope | ✅ Enforced strict | ✅ Enforced strict |
| Production Secure Boot Keys | ⏳ P3 Scope | ⏳ P3 Scope | ✅ Implemented |
| TPM 2.0 Remote Attestation | ⏳ P3 Scope | ⏳ P3 Scope | ✅ Implemented |
