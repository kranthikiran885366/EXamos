# Architecture

The P0 architecture is intentionally minimal. It establishes a reproducible build host and a clean Debian-based image without pushing any exam runtime or lockdown logic into the build.

## Component flow

```text
Developer
  -> Ubuntu 26.04 build host
  -> Git repository
  -> mkosi
  -> Debian image
  -> QEMU + OVMF
  -> systemd boot
```

## Scope

- Build host configuration
- Repository layout and metadata
- mkosi image build
- QEMU/OVMF boot validation
- Artifact collection and CI gate

## Explicitly out of scope for P0

- Chromium kiosk runtime
- endpoint lockdown
- attestation
- proctoring
- behaviour analysis
- red-team testing
