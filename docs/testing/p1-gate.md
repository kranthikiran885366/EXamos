# ExamOS Phase 1 (P1) — Gate Criteria & Verification Record

## 1. Official P1 Gate Definition

The official Phase 1 gate requires:
1. **Bootable Appliance**: System boots through UEFI/OVMF into Linux without errors.
2. **Kiosk Exclusivity**: Reaches Cage (Wayland) + Chromium kiosk with no desktop environments, system panels, or interactive console login.
3. **Unprivileged Runtime**: Kiosk runs under user `exam` (UID 1000) with nologin shell.
4. **Configurable Target**: Exam URL dynamically loaded via Admin Dashboard or `/etc/examos/exam.conf`.
5. **Baseline Security**: Default-deny firewall (nftables), USB lockdown udev rules, AppArmor MAC, kernel hardening sysctls.
6. **Artifact Deliverables**: Raw disk image, bootable ISO image, SHA-256 checksums, and recorded test logs.

---

## 2. Gate Verification Summary

| Gate Check | Script | Expected Output | Actual Result | Status |
|---|---|---|---|---|
| Kiosk Session Check | `tests/p1/kiosk.sh` | User=exam, graphical.target, pure Cage | All checks passed | ✅ PASS |
| Network Security | `tests/p1/network.sh` | Default-deny policy, 443/53 outbound | Verified nftables ruleset | ✅ PASS |
| Performance Baseline | `tests/p1/performance.sh` | Disk size & boot baseline recorded | 2.2G disk / 134M ISO recorded | ✅ PASS |
| Clean Build Pipeline | `tests/p1/build.sh` | Successful compilation & mkosi run | Built without errors | ✅ PASS |
| Bootable ISO Generation | `scripts/build-iso.sh` | Bootable hybrid ISO created | `examos-appliance-v0.2.0.iso` | ✅ PASS |
| Overall P1 Gate | `tests/p1/gate.sh` | PASS in results.json | `status: "PASS"` | ✅ PASS |

---

## 3. Results Record (`artifacts/p1/results.json`)

```json
{
  "phase": "P1",
  "version": "0.2.0",
  "status": "PASS",
  "checks": {
    "kiosk": "PASS",
    "network": "PASS",
    "admin_dashboard": "PASS",
    "candidate_login": "PASS",
    "sysusers_exam": "PASS"
  },
  "gate": "PASS",
  "gate_reason": "All mandatory P1 checks passed."
}
```
