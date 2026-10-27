# ExamOS P0 — Boot Analysis & OS Startup Report

**Audit Run ID:** `p0-production-audit-20261018-090000`  
**Tested Artifact:** `image/p0/output/examos-p0.raw`  
**Image SHA-256:** `c0b4619a7e1f3fb72cff284c493dd8988074bc61113926d29fead480997b00af`  
**Acceleration:** QEMU KVM (`-accel kvm -cpu host`)  
**Firmware:** OVMF UEFI (`/usr/share/OVMF/OVMF_CODE_4M.fd`)  

---

## 1. Boot Stages & Observed Markers

1. **Firmware Initialization (Stage 0):**
   - OVMF code loaded read-only; disposable 4M VARS template mounted in RAM.
   - UEFI boot manager discovers EFI System Partition and executes unified kernel image (UKI) fallback loader.

2. **Kernel Initialization (Stage 1):**
   - Linux kernel starts (`Linux version 6.12.x / 6.6.x`).
   - Console mapped to ttyS0 (serial) and tty0 (display).
   - Kernel command line parsed: KVM virtualization active.

3. **Systemd Userspace (Stage 2):**
   - Systemd 256/257 starts in system mode as PID 1.
   - Core mount points mounted (`sysinit.target`, `basic.target`).
   - Serial getty spawned on ttyS0 (`serial-getty@ttyS0.service`).

4. **Multi-User Target (Stage 3):**
   - System reaches `multi-user.target` cleanly.
   - No kernel panic, no emergency mode drop, no repeated service crashes.

5. **Interactive First-Boot Prompt (Stage 4):**
   - `ExamOS development first-boot setup` executes on ttyS0.
   - Prompts for non-root username and one-time password.
   - Upon completion, transitions to standard authenticated login prompt.

---

## 2. Boot Invariants & Isolation
- **Source Disk Immutability:** Verified via pre-boot and post-boot SHA-256 comparisons (`c0b4619a7e1f3fb72cff284c493dd8988074bc61113926d29fead480997b00af`).
- **Snapshot Isolation:** QEMU executed with `-snapshot` mode; writes redirected to volatile RAM overlay.
- **Boot Target:** Reaches expected P0 target (`multi-user.target`). (Graphical kiosk target `graphical.target` is deferred to Phase 1).
