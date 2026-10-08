# ExamOS — Prevention-First Secure Operating System

ExamOS is a Linux examination-appliance development prototype, primarily implemented in **native C and C++**.

> **Status: development prototype, not enterprise-ready.** The image has been
> built and booted to a serial login under QEMU/OVMF. The current server does
> not authenticate devices or verify TPM quotes, the exam/session backend is
> not implemented, and the proctoring code does not perform face/gaze/audio
> recognition. Do not use this build for live examinations or treat its
> telemetry as trusted.

---

## Architecture Overview

```text
                  +------------------------------------------------+
                  |          ExamOS Linux Base Image               |
                  |   (lockdown=confidentiality, sysctl, udev)    |
                  +------------------------------------------------+
                                          |
          +-------------------------------+-------------------------------+
          |                               |                               |
+-------------------+           +-------------------+           +-------------------+
|  Cage / Wayland   |           |  Security Agent   |           | Proctoring Engine |
|  Kiosk Supervisor |           |   (Native C)      |           |   (Native C++)    |
|   (Native C)      |           |                   |           |                   |
| - Ephemeral RAM   |           | - PCR snapshot    |           | - Capture stub    |
|   browser profile |           | - Hardware Guard  |           | - Anomaly Engine  |
| - Chromium kiosk  |           | - Local Telemetry |           | - No CV pipeline  |
| - Draft policies  |           | - Wi-Fi/BLE scans |           | - No recognition  |
+-------------------+           +-------------------+           +-------------------+
          |                               |                               |
          +-------------------------------+-------------------------------+
                                          |
                                          v
                  +------------------------------------------------+
                  |            ExamOS Server Platform              |
                  |                  (Native C)                    |
                  | - Local Hash-Chain Prototype                  |
                  | - No trusted risk decisions                    |
                  | - No authenticated exam sessions               |
                  +------------------------------------------------+
```

---

## Subsystems (Native C / C++)

1. **Kiosk Launcher (`kiosk/launcher/`)**: Native C prototype for launching Chromium under Cage Wayland with an ephemeral profile and kiosk flags. Boot-to-kiosk operation has not been validated.
2. **Kiosk Policies (`kiosk/policies/`)**: Draft Chromium policy configuration; effective policy enforcement in the built image has not been validated.
3. **Security Agent (`agent/`)**: Native C prototype for reading TPM PCRs and collecting device telemetry. It does not create a TPM-signed quote or authenticated heartbeat, and hardware observations are not enforcement.
4. **Proctoring Engine (`proctoring/`)**: Native C++ prototype only. It does not currently acquire/process real camera frames or perform face, gaze, or speech recognition.
5. **Server Platform (`server/`)**: Local development HTTP service with an in-process session manager and hash-chain ledger prototype. Authenticated exam workflows, remote TLS/API security, durable ledger guarantees, and TPM quote verification are not implemented.

---

## Building Native Subsystems

Compile all C and C++ modules directly using `make`:

```bash
# Build all native binaries
make all

# Clean build artifacts
make clean
```

---

## P0 Foundation & OS Image Generation

The P0 foundation synthesizes a minimal Debian Trixie disk image using `mkosi`:

```bash
# Verify host readiness
./scripts/examos-doctor.sh

# Run end-to-end P0 test suite
./scripts/p0.sh

# Build disk image
./scripts/build-image.sh

# Launch image in QEMU with UEFI (OVMF)
./scripts/run-qemu.sh
```
