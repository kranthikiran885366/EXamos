# ExamOS Phase 0 (P0) — Testing Guide

## 1. Test Suite Overview
Phase 0 validation comprises:
1. **Host Verification (`tests/p0/host-check.sh`):** Checks CPU flags, KVM, disk capacity, and core packages.
2. **Doctor Diagnostics (`tests/p0/examos-doctor.sh`):** Formats comprehensive system readiness reports.
3. **Repository Structure (`tests/p0/repository-check.sh`):** Enforces clean tree layout and zero private keys.
4. **QEMU / OVMF Boot (`tests/p0/boot.sh`):** Boot test under UEFI firmware with console logging.

## 2. Running the Complete P0 Pipeline
```bash
bash scripts/p0.sh
```

## 3. Results Schema
Test outcomes are persisted in `artifacts/p0/results.json` using explicit `PASS` / `FAIL` states.
