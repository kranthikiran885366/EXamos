# Building ExamOS

## Repository setup

```bash
mkdir -p ~/examos
cd ~/examos
```

## Build and verify the image

```bash
bash ./scripts/build-image.sh
```

The builder compiles the native components, stages a permission-normalized
copy of the root filesystem overlay, and builds `examos-production.raw`. It
validates the disk image and checks that the native binaries and systemd units
are present before recording the build log, SHA-256, and exact size under
`artifacts/p0`. On Linux it writes the image under `image/`. On WSL, when the
checkout is on a Windows-mounted filesystem, it defaults to
`$HOME/.local/share/examos/images` because mkosi cannot reliably preserve image
metadata when exporting a disk to DrvFS. Set `EXAMOS_OUTPUT_DIR` to choose
another output directory. The P0 boot test uses a copied OVMF variable store
and QEMU snapshot mode so it does not modify the built image; it passes only
after observing the serial login target and ExamOS local server startup.

Run the UEFI boot test with:

```bash
bash ./tests/p0/boot.sh
```

Run the API behavior check (untrusted telemetry is marked as such, and
unimplemented attestation/session endpoints fail closed) with:

```bash
bash ./tests/p0/server-smoke.sh
```

## Trigger the P0 gate

```bash
cd ~/examos
bash ./scripts/p0.sh
```

The P0 gate checks native compilation, API smoke behavior, image structure and
payload, and a QEMU serial-login/local-server startup. A P0 PASS is not evidence of a
production kiosk workflow, TPM quote verification, real proctoring, or
enterprise readiness.

## Reproducibility notes

- Keep the source tree clean
- Store artifacts under `artifacts/p0`
- Do not check in signing keys or production data
- Validate a clean build before tagging the P0 milestone
