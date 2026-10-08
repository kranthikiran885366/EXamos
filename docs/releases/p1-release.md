# ExamOS Release Record — Phase 1 (v0.2.0)

## 1. Release Identification

- **Release Name**: ExamOS Phase 1 (Minimal Boot to Kiosk)
- **Version**: `0.2.0`
- **Architecture**: `x86_64` (UEFI / OVMF)
- **Target Distribution**: Debian 13 (`trixie`)
- **Kernel Version**: Linux `6.12.111+deb13-amd64`
- **Compositor / Display**: Cage (Wayland)
- **Browser Runtime**: Chromium (Enterprise Kiosk Managed Policies)

---

## 2. Gate Verification Summary

- **Primary Gate**: CI builds and boots an ExamOS image in QEMU with OVMF, reaching the unprivileged kiosk environment with no standard desktop, panel, or login prompt.
- **Gate Status**: **PASS**
- **Results File**: `artifacts/p1/results.json`
- **Performance Baseline**: Boot-to-page < 60s reference target; raw image 2.2 GB; bootable ISO 134 MB.

---

## 3. Verified Native Subsystems

| Subsystem | Binary | Description |
|---|---|---|
| Kiosk Launcher | `examos-kiosk-launcher` | Native C Cage supervisor with ephemeral RAM profiles |
| Security Agent | `examos-agent` | Attestation, hardware guard, process killer daemon |
| Control Server | `examos-server` | Candidate portal, admin dashboard, cryptographic ledger |
| Proctoring Engine | `examos-proctor` | Native C++ anomaly detection foundation |

---

## 4. Known Phase Boundaries & Limitations

- **Phase 1 Boundary**: Establishes functional kiosk runtime, unprivileged user, dynamic exam URL configuration, and default-deny firewall.
- **Not in Phase 1**: Immutable `dm-verity` rootfs (P2), production Secure Boot PK/KEK/db certificate enrollment (P3), remote TPM quotes (P3), live video proctoring streaming (P4).
