# ExamOS hardware qualification — in-scope models

**Status: no device is currently qualified.**

P0 QEMU/OVMF boots do not qualify a laptop, firmware revision, USB controller,
or physical TPM. Qualification is per exact model, firmware, and device
identity. Missing hardware remains BLOCKED.

## Models in scope for future qualification

Only the following platform is authorized as a *candidate* for qualification.
It is not approved for production or live examinations.

| Model | Architecture | Firmware | TPM | Role | Qualification |
|---|---|---|---|---|---|
| Dell Vostro 15 3510 | x86-64 | UEFI with Secure Boot left enabled | TPM 2.0 (must be confirmed on the unit) | Lab candidate only | **NOT QUALIFIED** |

No other OEM model, SKU, or firmware revision is in scope until a completed
qualification record exists for that exact identity.

## What “qualified” requires

A model becomes qualified only when all of the following exist for a named
physical unit:

1. Read-only inventory (manufacturer, model, service tag, CPU, firmware
   version, TPM manufacturer/version, Secure Boot enabled, BitLocker
   protection status without recovery secrets).
2. External-media boot from firmware boot menu with **no** persistent boot-order
   change and **no** writes to internal disks.
3. Organization-signed UKI accepted by firmware without disabling Secure Boot.
4. Server-issued nonce, persistent enrolled EK/AK, hardware `TPM2_Quote`, and
   event-log replay bound to the quote.
5. Documented return to Windows and post-test integrity checks.

## Recovery plan (mandatory before any physical boot)

- Internal HDD/NVMe, EFI variables, BCD, BitLocker, and TPM state are
  **out of bounds**.
- The only allowed write target is an operator-identified **external** USB/SSD
  after the full identity is displayed and the owner approves that exact
  command in chat.
- Windows recovery: firmware boot menu → existing Windows Boot Manager. Do not
  create ExamOS boot entries on internal ESP.
- BitLocker recovery material stays with the device owner; this repository
  must never store recovery keys.
- If Secure Boot rejects the image, diagnose the image and signing identity.
  Do not disable Secure Boot to obtain a green result.
- Abort immediately if disk identity is ambiguous (RAID abstraction, duplicate
  sizes, or missing serial).

## Evidence location

Per-device records belong under an isolated evidence directory supplied by
`EXAMOS_PRODUCTION_ARTIFACT_DIR`, never as a PASS overwritten onto older
files. `tests/production/hardware-qualification-gate.sh` is BLOCKED until a
completed qualification file is provided.
