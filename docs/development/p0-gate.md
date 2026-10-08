# P0 gate

The P0 gate is intentionally narrow:

```text
Clean checkout
  -> Host validation
  -> Dependency validation
  -> mkosi build
  -> Artifact collection
  -> QEMU/OVMF bootstrap validation
  -> CI pass
  -> tag P0
```

## Success criteria

- Build host is suitable for Linux image work
- KVM and QEMU are available
- mkosi can produce a Debian-based image
- The image is bootable under OVMF
- Logs and checksums are recorded
- The CI workflow reports PASS

## Not required in P0

- kiosk lockdown
- Chromium runtime
- attestation
- proctoring
- secure exam operation
