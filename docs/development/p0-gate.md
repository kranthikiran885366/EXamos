# ExamOS Phase 0 (P0) — Acceptance Gate Specification

## 1. Acceptance Criteria
The official ExamOS Phase 0 gate requires:
- **Build:** Automated reproducible compilation of the minimal Debian image via `mkosi`.
- **Boot:** Successful UEFI boot under QEMU with OVMF firmware.
- **Evidence:** Recorded artifacts (`image.sha256`, `image-size.txt`, `boot.log`, `results.json`).
- **CI Pipeline:** Green `.github/workflows/p0.yml` execution.

## 2. Gate Decision Command
```bash
bash scripts/p0.sh
```
Exit code 0 confirms all P0 requirements are satisfied.
