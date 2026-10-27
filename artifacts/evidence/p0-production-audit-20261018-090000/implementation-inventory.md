# ExamOS P0 — Implementation Inventory

**Audit Run ID:** `p0-production-audit-20261018-090000`

---

## 1. Component Locations

| Component | Path | Language / Tech | Role |
|---|---|---|---|
| P0 Build Config | `image/p0/mkosi.conf` | INI / mkosi | Declares Debian Trixie base packages, UKI, and GPT disk format |
| P0 Build Script | `tests/p0/build.sh` | Bash | Orchestrates `mkosi` compilation into `image/p0/output/` |
| First-Boot Helper | `image/p0/dev-console-setup.cpp` | C++17 | Interactive serial account setup daemon |
| Serial Test Driver | `tests/p0/first-boot-test.cpp` | C++17 | Automated serial TCP driver for testing first boot |
| ISO Builder | `tests/p0/build-iso.sh` | Bash / xorriso | Synthesizes hybrid UEFI optical media from raw disk |
| ISO Boot Driver | `tests/p0/boot-iso.sh` | Bash / QEMU | Validates optical boot under OVMF |
| Disk Forensics | `tests/p0/image-forensics.sh` | Bash / fdisk | Analyzes GPT, partition UUIDs, and filesystem labels |
| Server Binary | `server/examos-server` | C / POSIX | Examination backend & ledger runtime |
| Agent Binary | `agent/examos-agent` | C / libcurl | Appliance health & attestation client |
| Kiosk Launcher | `kiosk/launcher/examos-kiosk-launcher`| C / Wayland | Kiosk session supervisor |
