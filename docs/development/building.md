# Building ExamOS

## Repository setup

```bash
mkdir -p ~/examos
cd ~/examos
```

## Build the image

```bash
cd image
mkosi -f
```

## Trigger the P0 gate

```bash
cd ~/examos
bash ./scripts/p0.sh
```

## Reproducibility notes

- Keep the source tree clean
- Store artifacts under `artifacts/p0`
- Do not check in signing keys or production data
- Validate a clean build before tagging the P0 milestone
