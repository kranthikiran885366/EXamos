# ExamOS

Prevention-first secure operating system and enterprise examination platform.

## Current status

P0 is not complete in this environment. The host currently being used here is a Windows/MSYS environment, not a Linux build host, and it does not provide /dev/kvm, UEFI firmware, or the required QEMU/mkosi toolchain. The repository therefore documents the intended P0 workflow and uses fail-closed validation rather than fabricating a pass.

## Development stages

- P0 Foundation
- P1 Minimal kiosk
- P2 Endpoint lockdown
- P3 Trusted boot and TPM attestation
- P4 Proctoring and evidence
- P5 Behaviour, variants and viva
- P6 Hardware validation and red team
- E1 Environment intelligence
- E2 Enterprise control plane
- E3 Device fleet
- E4 Release management
- E5 High availability
- E6 Buildroot production optimization

## Current phase

P0

## Repository layout

The project is intentionally organized so that the P0 build/test foundation is independent from later feature work.

```text
examos/
├── image/
│   ├── mkosi.conf
│   ├── examos-build.conf
│   ├── dev.conf
│   ├── release.conf
│   ├── overlay/
│   ├── config/
│   └── scripts/
├── kiosk/
├── agent/
├── proctoring/
├── server/
├── tests/
├── docs/
├── scripts/
├── artifacts/
├── cache/
├── .github/
├── .gitignore
├── README.md
└── docs/releases/version.yaml
```

## P0 objective

P0 proves that the build environment, repository layout, mkosi image pipeline, host validation, QEMU/OVMF boot testing, artifact collection, and CI foundation are all reproducible and working before feature work begins.
