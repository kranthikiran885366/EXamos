# Production readiness (separate from P0 and P3)

This directory describes evidence that **source edits cannot create**.

| ID | Blocker | Gate | Pass condition |
|---|---|---|---|
| EXT-01 | Clean identifiable commit | `tests/production/clean-source-gate.sh` | Clean worktree at a recorded HEAD |
| EXT-02 | Reproducible builds | `tests/p0/reproducible-build.sh` | Two isolated mkosi builds match (`EXAMOS_P0_REPRO_MODE=image`) |
| EXT-03 | VMware UEFI ISO boot | `tests/p0/vmware-optical-boot.sh` | Workstation version, VMX, ISO digest, guest log |
| EXT-04 | Hardware models | `tests/production/hardware-qualification-gate.sh` | Completed qualification for a named unit |
| EXT-05 | Org Secure Boot / registries | `tests/production/trust-provisioning-gate.sh` | HSM-backed signatures, not `image/trust` |
| EXT-06 | Physical TPM | `tests/production/server-verified-tpm-challenge.sh` | Enrolled device + server nonce + hardware quote |
| EXT-07 | Independent assessment | `tests/production/external-acceptance-gate.sh` | Signed independent approval |

Run all seven:

```bash
bash scripts/production-readiness.sh
```

Overall PASS is required for production certification. A P0 or P3 PASS does
not substitute. Missing VMware, hardware, keys, or reviewers remain BLOCKED.
