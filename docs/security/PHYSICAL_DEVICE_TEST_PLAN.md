# Physical device test plan — Dell Vostro 15 3510

**In-scope candidate model:** Dell Vostro 15 3510 (x86-64 UEFI).  
**Qualification: NOT QUALIFIED.** No other model is in scope.

**Status: READ-ONLY PREFLIGHT PARTIAL (2026-10-12).** No firmware, TPM,
EFI, boot configuration, BitLocker, or disk writes have been performed.

## Current read-only preflight

- Windows identifies the host as a Dell Vostro 15 3510.
- Windows disk inventory (serial numbers intentionally omitted) returned a
  1 TB ST1000LM035 disk as GPT/online and a 256 GB KIOXIA NVMe disk as
  GPT/online and the boot/system disk. Windows reports both through its RAID
  bus abstraction; do not infer a removable target from disk numbering.
- `Confirm-SecureBootUEFI` could not confirm Secure Boot because the current
  process lacks the required privilege.
- `Get-Tpm` returned no usable TPM state; TPM presence, readiness, manufacturer,
  and PCR banks remain **unknown**.
- BitLocker status queries were denied; volume protection status remains
  **unknown**. No recovery material was queried or displayed.
- WSL exposes x86-64 and `vmx`. The user was added to the existing `kvm`
  group; on 2026-10-12 the actual QEMU KVM initialization probe passed, and
  the current P0 disk guest reached its serial login under KVM. This updates
  the earlier permission-denied record. It remains WSL/QEMU virtual evidence,
  not physical-device evidence.

Re-run all read-only checks with appropriate Windows privileges immediately
before any later physical test. Previously recorded Secure Boot/TPM/BitLocker
claims are not current evidence.

## Absolute prohibitions

- No writes to internal HDD or NVMe.
- No EFI/BCD/BitLocker/recovery partition modification.
- No TPM clear/reinit.
- No Secure Boot key replacement or disable.
- No target selection by assuming `/dev/sdb`.

## Phase A — read-only (no firmware changes)

Collect UEFI/Secure Boot/TPM manufacturer and PCR banks, boot entries, hardware inventory, BitLocker **protection status** (never print recovery keys), Windows boot integrity. Stop if identity is ambiguous.

## Phase B — disposable VM

Complete QEMU/OVMF boot and negative Secure Boot / verity tests first. The
candidate must include an organization-signed UKI, its approved DB certificate,
and a dm-verity root hash bound in the signed command line. Capture the P2
secure-boot gate and raw TCG event log; replay it with
`tools/examos-eventlog-replay.py` before Phase C. No host disk access.

## Phase C — external media only

Identify target by model, serial, size, bus. Display full identity. Confirm it is not either internal disk. Obtain explicit approval for that device and operation. Boot from firmware boot menu without persistent boot-order change. Keep Secure Boot enabled; if the image cannot boot, diagnose the image—do not disable Secure Boot.

## Phase D — hardware attestation (only after C + approval)

Fresh server-issued nonce, hardware `TPM2_Quote`, AK signature verify, PCR and
raw event-log replay. Bind the replayed PCR values to the quote and preserve
the raw log hash. Distinguish firmware measurements from swtpm. No production
enrollment and no real exam keys without a reviewed procedure.

## Phase E — return to Windows

Firmware boot menu → Windows. Recheck Secure Boot, TPM, BitLocker, partitions, boot entries. Remove only files this test created after path verification.

## Required approval before Phase C

Exact command, target identity, consequence, and rollback limits must be shown in chat and approved by the user.
