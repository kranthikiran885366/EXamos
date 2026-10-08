# ExamOS Phase 1 (P1) — Testing Strategy & Execution

## 1. Overview

The P1 test suite automates the verification of the complete appliance stack from source code to bootable image and runtime behavior.

---

## 2. Test Scripts Reference

| Script | Purpose | Success Condition |
|---|---|---|
| `tests/p1/build.sh` | Compiles native C/C++ subsystems and builds disk image via mkosi | Exit code 0, image artifact produced |
| `tests/p1/boot.sh` | Boots the image in QEMU under UEFI/OVMF and inspects serial output | Kernel & systemd boot markers found in `boot.log` |
| `tests/p1/kiosk.sh` | Statically checks kiosk service, unprivileged user, and desktop absence | User `exam`, graphical target, no desktop environments |
| `tests/p1/network.sh` | Verifies default-deny firewall and network package configuration | `policy drop` present, HTTPS/DNS rules present |
| `tests/p1/performance.sh` | Measures image size, sha256 checksum, and boot baseline | Metric file `performance.txt` generated |
| `tests/p1/gate.sh` | Authoritative P1 Gate evaluation orchestrator | Generates `artifacts/p1/results.json` with status `PASS` |

---

## 3. Running the Complete Suite

```bash
# Execute full validation pipeline
bash tests/p1/collect-artifacts.sh
bash tests/p1/kiosk.sh
bash tests/p1/network.sh
bash tests/p1/performance.sh
bash tests/p1/gate.sh
```

All test outcomes are strictly non-fabricated and recorded directly to `artifacts/p1/`.
