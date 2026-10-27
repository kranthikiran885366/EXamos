# ExamOS P0 — Physical Hardware Readiness & Host Assessment

**Date (UTC):** `2026-10-18T03:37:57.106998+00:00`  
**Physical Host Machine:** Dell Inc. Vostro 15 3510  
**Target Hardware Qualification Status:** `NOT_QUALIFIED` / `PHYSICAL_TEST_BLOCKED`

---

## 1. Verified Host Hardware Observations (Read-Only)

All observations were collected using non-destructive CIM and hardware tools from Windows:

| Subsystem | Observed Value | Verification Tool / Command |
|---|---|---|
| **Manufacturer & Model** | Dell Inc. Vostro 15 3510 | `Get-CimInstance Win32_ComputerSystem` |
| **Processor** | 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (8 logical CPUs) | `Get-CimInstance Win32_Processor` |
| **Physical Memory** | 8,311,836,672 bytes (~7.74 GiB RAM) | `Get-CimInstance Win32_ComputerSystem` |
| **Boot SSD (Internal)** | NVMe KIOXIA 256GB (`\\.\PHYSICALDRIVE1`) | `Get-CimInstance Win32_DiskDrive` |
| **Data HDD (Internal)** | Seagate 1TB ST1000LM035 (`\\.\PHYSICALDRIVE0`) | `Get-CimInstance Win32_DiskDrive` |
| **TPM 2.0 Presence** | Present: `True`, Version `2.0`, Manufacturer `Nuvoton (NTC / NPCT75x)` | `tpmtool.exe getdeviceinformation` |
| **TPM Attestation Readiness**| `Ready For Attestation: True`, `Spec Version: 1.38` | `tpmtool.exe getdeviceinformation` |
| **BitLocker PCR Binding** | **`Bitlocker PCR7 Binding State: Bound`** | `tpmtool.exe getdeviceinformation` |
| **UEFI Secure Boot State** | `UEFISecureBootEnabled: 1` (Active/Enforced) | `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State` |

---

## 2. Safety Evaluation & Critical Risk Factors

> [!CAUTION]
> **CRITICAL SAFETY WARNING: Active BitLocker PCR7 Binding**
> The physical host's internal NVMe SSD is encrypted with BitLocker and actively bound to TPM PCR7 (`UEFISecureBootEnabled: 1`). Any modification to firmware boot order, Secure Boot keys, EFI variables, or internal partition tables will trip BitLocker, locking Windows out and demanding recovery keys.

In strict adherence to Safety Rule 5 & 6:
- **No writes to internal physical disks (`\\.\PHYSICALDRIVE0`, `\\.\PHYSICALDRIVE1`).**
- **No changes to UEFI boot variables, Secure Boot keys, or firmware settings.**
- **No flashing of USB media without explicit operator identification and confirmation.**

---

## 3. Physical Test Readiness Verdict: `PHYSICAL_TEST_BLOCKED`

Physical testing on the Dell Vostro 15 3510 is currently **BLOCKED** because:
1. P0 image does not yet carry production Secure Boot signatures accepted by Microsoft 3rd Party UEFI CA (enrolled in factory Dell firmware).
2. Physical external USB media has not been provided, authorized, or identified by device serial.
3. Live execution must remain in isolated QEMU/KVM virtual hardware until production key ceremonies (Phase 3) and independent physical validation plans (Phase 6) are established.
