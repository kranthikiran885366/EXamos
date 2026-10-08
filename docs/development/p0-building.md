# P0 build process

The build process is intentionally minimal and must not include kiosk, attestation, or lockdown features.

## Build directory

```bash
cd ~/examos/image
```

## Build the minimal ExamOS image

```bash
mkosi -f
```

## Artifact discovery

```bash
find . -maxdepth 2 -type f | sort
```

## Required evidence

P0 requires real build logs, artifact discovery, SHA-256 calculation, and a QEMU/OVMF boot result.

This environment does not satisfy those prerequisites, so the build is intentionally blocked and reported as such.
