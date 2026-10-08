# ExamOS P0 Release & Architecture Record

## 1. Objective

Establish the reproducible, native C/C++ development foundation for ExamOS, including host validation, repository structure, native subsystem compilation, mkosi disk configuration, build workflow, artifact collection, and a UEFI boot pipeline under QEMU with OVMF.

## 2. Observed Validation Environment

- **Build host**: Ubuntu 26.04 under WSL, x86_64, with `/dev/kvm` available
- **Toolchain observed**: mkosi 26, QEMU 10.2.1, OVMF, swtpm 0.10.1
- **Image target**: Debian Trixie, UEFI/systemd-boot
- **Most recent verified image**: `artifacts/p0/image-current.sha256`

The P0 host, native build, API smoke test, image structure, and serial boot to
the login target with the local server started have been observed. Boot-to-
kiosk operation has not been demonstrated; do not infer it from the serial
login test.

## 3. Tool Versions

- **git**: 2.52.0.windows.1
- **gcc / g++ / make**: Linux target build tools specified in Makefile and CI
- **mkosi**: Configured for Debian Trixie target disk synthesis
- **qemu-system-x86_64**: Configured with OVMF UEFI firmware
- **swtpm / tpm2-tools**: Virtual TPM 2.0 measurement pipeline

## 4. Prototype Status and Known Gaps

The current code is not a production or enterprise examination platform:

- The kiosk launcher and Chromium policy files have not been validated as a complete boot-to-kiosk flow.
- The agent can read local PCR values and collect telemetry, but does not produce a TPM-signed quote or authenticated heartbeat. Hardware checks observe selected paths; they do not enforce USB or display restrictions.
- The proctoring code does not capture and analyze real video/audio frames and does not implement face, gaze, or speech recognition.
- The local HTTP server is not a remote enterprise service. It has no authenticated exam-session lifecycle, device identity verification, TLS, or durable/externally anchored ledger.
- No enterprise deployment, secure update/signing, recovery, fleet management, privacy review, threat model, or hardware acceptance testing has been completed.

The server returns `UNAVAILABLE` for attestation and exam sessions until those trust and workflow paths are implemented. Telemetry is recorded as unverified and must not be used for security decisions.

## 5. Release Gate

**P0 status: bootable development prototype.** Image build validation and a QEMU/OVMF serial-login test are engineering checks only. They do not establish boot-to-kiosk behavior, enterprise readiness, or suitability for live examinations. Do not deploy this build for live examinations.
