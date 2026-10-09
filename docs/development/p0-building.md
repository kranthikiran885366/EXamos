# ExamOS Phase 0 (P0) — Image Build Guide

## 1. Minimal Target Build
The P0 build compiles a minimal, reproducible Debian Linux disk image using `mkosi`.

### Manual Build:
```bash
cd image
mkosi build
```

### Automated Build with Metadata Collection:
```bash
bash tests/p0/build.sh
```

## 2. Artifact Output
The build produces:
- `image/examos.raw` (or `examos.raw.raw` depending on mkosi version)
- `artifacts/p0/build.log`
- `artifacts/p0/image.sha256`
- `artifacts/p0/image-size.txt`

## 3. Strict Non-Fabrication Rule
Build artifacts and hashes must always be derived directly from actual tool execution. Never invent or manually write hash values.
