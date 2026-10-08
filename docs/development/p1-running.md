# ExamOS Phase 1 (P1) — Running and Verification Guide

## 1. Running ExamOS in Virtualized Environment (QEMU + OVMF)

ExamOS is designed for UEFI x86-64 execution. In development and CI environments, it is run under QEMU with OVMF firmware and virtual TPM 2.0 emulator (`swtpm`).

### Prerequisites
- QEMU (`qemu-system-x86_64` >= 8.0)
- OVMF UEFI firmware (`/usr/share/OVMF/OVMF_CODE_4M.fd` or `/usr/share/OVMF/OVMF_CODE.fd`)
- `swtpm` (optional, for TPM 2.0 development emulation)

### Quick Run Script
```bash
# Automated headless boot test with serial capture
bash tests/p1/boot.sh

# Interactive QEMU run with graphics display
qemu-system-x86_64 \
    -M q35 -accel kvm \
    -m 2048 -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive file=image/examos.raw,format=raw,if=virtio \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -vga virtio -display gtk
```

---

## 2. Boot Flow & Runtime Behavior

1. **UEFI Boot**: Firmware loads the unified kernel image or systemd-boot from ESP.
2. **Kernel Initialization**: Linux kernel boots with kernel lockdown (`integrity`), `apparmor=1`, and `console=tty0 console=ttyS0`.
3. **systemd Target**: System reaches `graphical.target`.
4. **Service Startup**:
   - `examos-server.service` starts and binds port 8000.
   - `examos-agent.service` starts security monitoring and heartbeat.
   - `examos-kiosk.service` starts Cage compositor as user `exam`.
5. **Kiosk Execution**:
   - Cage launches `examos-kiosk-launcher`.
   - Launcher initializes an ephemeral profile directory in RAM (`/tmp/examos_kiosk_XXXXXX`).
   - Launcher executes Chromium in `--kiosk --app=<URL>` mode.
   - If no external URL is configured, it displays the embedded Candidate Verification Portal (`http://127.0.0.1:8000/`).

---

## 3. Administrator Operations

### Accessing the Admin Dashboard
- Open `http://127.0.0.1:8000/admin` (or configure via API).
- Default credentials:
  - **Username**: `admin`
  - **Password**: `ExamOS@Admin2025!`
- Actions available:
  - Set target examination URL.
  - Set exam title and duration.
  - Restart kiosk browser session.
  - View tamper-evident event ledger.
