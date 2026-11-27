# Bulk BIOS Prep, Proctor Troubleshooting & 5-Minute Live-USB Trial

---

## Part A: Bulk BIOS Prep Guide (50+ Lab PCs — Dell / HP / Lenovo)

Before booting ExamOS (Live-USB or PXE), enable these 4 firmware settings across the lab:
1. **Boot Mode**: `UEFI Only` (Disable Legacy / CSM).
2. **TPM 2.0**: `Enabled` & `Activated` (Intel PTT or Discrete TPM 2.0).
3. **Secure Boot**: `Enabled`.
4. **Virtualization / IOMMU**: `VT-d` / `AMD-Vi` `Enabled` (for strict DMA isolation); **PXE Boot** `Enabled` if using network provisioning (`image/pxe/examos.ipxe`).

### Vendor Bulk CLI References
- **Dell (`cctk` / Dell Command | Configure)**:
  - `cctk --TpmSecurity=Enabled --TpmActivation=Enabled --SecureBoot=Enabled --UefiNwStack=Enabled`
- **HP (`BIOSConfigUtility64.exe` / BCU)**:
  - Export template with `BCU /GetConfig:lab.txt`, set `TPM Device = Available`, `TPM State = Enable`, `Secure Boot = Enable`, apply via `BCU /SetConfig:lab.txt`.
- **Lenovo (`ThinkBIOS` / WMI PowerShell)**:
  - Set `SecurityChip = Active`, `SecureBoot = Enable`, `NetworkBoot = PXE` via `Lenovo_SetBiosSetting` + `Lenovo_SaveBiosSettings`.

---

## Part B: Proctor 1-Page Troubleshooting Sheet (Top 5 Lab Issues)

| # | Symptom / Pre-Flight Red Flag | Root Cause | 30-Second Fix |
|---|-------------------------------|------------|---------------|
| 1 | `TPM 2.0 (/dev/tpmrm0) missing` | TPM disabled or hidden in BIOS | Reboot -> BIOS -> Security -> Enable **TPM 2.0 / Intel PTT**, Save & Exit. |
| 2 | `Secure Boot OFF` / PFR fail | CSM/Legacy boot or Secure Boot off | Reboot -> BIOS -> Boot -> Disable Legacy/CSM, Enable **Secure Boot**. |
| 3 | `No V4L2 camera` | Privacy shutter closed or webcam unplugged | Open physical camera shutter, reconnect USB webcam, re-run `examos-preflight-check.sh`. |
| 4 | `TLS / Attestation time error` | Dead CMOS battery (wrong BIOS clock) | Connect Ethernet/Wi-Fi; `examos-nts-sync.sh` syncs clock automatically over NTS/HTTPS. |
| 5 | `USB mouse/keyboard blocked` | Composite gaming/hub keyboard with storage | Swap to standard wired HID mouse/keyboard (USBGuard blocks HID+Storage combos). |

---

## Part C: 5-Minute Live-USB Trial Checklist (Zero Changes to Windows)

1. Flash the signed `examos-live.iso` to a USB 3.0 drive (`dd` / Rufus in DD mode).
2. Boot one test PC via `F12` / `F9` Boot Menu -> select the USB drive (**do not touch internal NVMe/Windows partitions**).
3. Run the 10-second check: `examos-preflight-check.sh` (verifies Webcam, Mic, Network, TPM 2.0, Power).
4. Confirm clock sync (`examos-nts-sync.sh`) and sanitized diagnostic export (`examos-diag-bundle.sh`).
5. Power off and remove the USB drive — the existing Windows installation remains completely untouched.
