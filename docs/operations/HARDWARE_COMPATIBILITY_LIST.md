# SPPIO / ExamOS — Hardware Compatibility List (HCL)

## 1. Baseline Station Requirements
- **CPU**: x86_64 (Intel Core 8th Gen+ / AMD Ryzen 3000+) with hardware virtualization/IOMMU (`VT-d` / `AMD-Vi`)
- **Security**: Discrete or firmware **TPM 2.0** (`/dev/tpmrm0`) + **UEFI Secure Boot**
- **RAM / Storage**: >= 4 GB RAM (8 GB recommended for local vision), >= 16 GB storage or USB 3.0 boot / PXE netboot
- **Peripherals**: Standard UVC USB/integrated webcam, USB/3.5mm headset or built-in mic, wired keyboard/mouse

## 2. Qualified Lab Desktop & Workstation Families
| Vendor | Model Series | TPM 2.0 | Secure Boot | IOMMU / VT-d | Status |
|--------|-------------|---------|-------------|--------------|--------|
| **Dell** | OptiPlex 3080 / 5090 / 7090 / 7010 | Yes (dTPM/PTT) | Yes | Yes | Qualified |
| **HP** | ProDesk 400 / 600 G6–G9, EliteDesk 800 | Yes | Yes | Yes | Qualified |
| **Lenovo** | ThinkCentre M70q / M75q / M90t | Yes | Yes | Yes | Qualified |

## 3. Network & Wi-Fi Chipsets
- **Wired Ethernet (Recommended for 50+ seat labs & PXE)**: Intel `e1000e` / `igc` / `igb`, Realtek `r8169` (`RTL8111`/`RTL8168`).
- **Wi-Fi**: Intel AX200 / AX201 / AX210 (`iwlwifi`), Realtek `rtw88` / `rtw89` (requires WPA2/WPA3 without captive-portal redirect).

## 4. Unsupported / Blocked Configurations
- Virtual machines (VMware, VirtualBox, QEMU/KVM, Hyper-V) — blocked by `anti_vm.c`.
- Composite USB peripherals exposing Mass Storage or CDC-Ethernet alongside HID — blocked by `usbguard/rules.conf`.
