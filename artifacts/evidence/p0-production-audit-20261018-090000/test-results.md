# ExamOS P0 Production Audit — Detailed Test Results

**Run ID:** `p0-production-audit-20261018-090000`  
**Date (UTC):** `2026-10-18T03:37:57.071449+00:00`  
**Host:** Dell Vostro 15 3510 / WSL2 Ubuntu 26.04 (Linux kernel 6.6.x x86_64)

---

## 1. Static Contract & Prerequisite Checks

| Test ID | Script | Command | Exit Code | Result | Start Time | End Time |
|---|---|---|---|---|---|---|
| P0-HOST | `tests/p0/host-check.sh` | `bash tests/p0/host-check.sh` | 1 | **FAIL** | 2026-10-18T03:29:07.252027+00:00 | 2026-10-18T03:36:28.199151+00:00 |
| P0-REPO | `tests/p0/repository-check.sh` | `bash tests/p0/repository-check.sh` | 0 | **PASS** | 2026-10-18T03:36:28.207677+00:00 | 2026-10-18T03:37:04.065942+00:00 |
| P0-KEYS | `tests/p0/private-key-check.sh` | `bash tests/p0/private-key-check.sh` | 0 | **PASS** | 2026-10-18T03:37:04.066930+00:00 | 2026-10-18T03:37:06.343173+00:00 |
| P0-PROV | `tests/p0/provenance-check-test.sh` | `bash tests/p0/provenance-check-test.sh` | 0 | **PASS** | 2026-10-18T03:37:06.343173+00:00 | 2026-10-18T03:37:07.890388+00:00 |
| P0-TPM-MAP | `tests/p0/tpm-secret-mapping-test.sh` | `bash tests/p0/tpm-secret-mapping-test.sh` | 0 | **PASS** | 2026-10-18T03:37:07.890388+00:00 | 2026-10-18T03:37:09.259809+00:00 |
| P0-AGENT-CFG | `tests/p0/agent-config-contract-test.sh` | `bash tests/p0/agent-config-contract-test.sh` | 0 | **PASS** | 2026-10-18T03:37:09.259809+00:00 | 2026-10-18T03:37:09.933331+00:00 |

---

## 2. Dynamic Hardening & Runtime Verification

| Test | Target / Command | Exit Code | Status | Notes |
|---|---|---|---|---|
| Disk Forensics | `tests/p0/image-forensics.sh` | 1 | **FAIL** | GPT, ESP partition, Root partition |
| QEMU/OVMF Disk Boot | `tests/p0/boot.sh` | 1 | **FAIL** | KVM accelerated, snapshot overlay |
| First-Boot Setup | `tests/p0/first-boot-test.sh` | 1 | **FAIL** | Native C++ serial driver over loopback TCP |
| Hybrid UEFI ISO Boot | `tests/p0/boot-iso.sh` | 1 | **FAIL** | Optical boot in QEMU |
| Server Smoke | `tests/p0/server-smoke.sh` | 0 | **PASS** | Loopback binding & ledger integrity |

---

## 3. Raw Execution Logs

### A. Host Check Log
```

```

### B. QEMU / OVMF Disk Boot Log
```
============================================================
ExamOS P0 â€” QEMU / OVMF Boot Validation
============================================================
[P0-BOOT] OVMF Code: /usr/share/OVMF/OVMF_CODE_4M.fd
[P0-BOOT] FATAL: P0 build artifact is missing; run tests/p0/build.sh first.
```

### C. First Boot Account Setup Log
```
[P0-FIRST-BOOT] FATAL: source image does not match the recorded build digest.
```

### D. Hybrid ISO Boot Log
```
[P0-ISO-BOOT] FATAL: P0 ISO is missing or empty
```
