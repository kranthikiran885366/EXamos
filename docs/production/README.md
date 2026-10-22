# Production readiness (separate from P0 and P3)

This directory describes evidence that **source edits cannot create**.

| ID | Blocker | Gate | Pass condition |
|---|---|---|---|
| EXT-01 | Clean identifiable commit | `tests/production/clean-source-gate.sh` | Clean worktree at a recorded HEAD |
| EXT-02 | Reproducible builds | `tests/p0/reproducible-build.sh` | Two isolated mkosi builds match (`EXAMOS_P0_REPRO_MODE=image`) |
| EXT-03 | VMware UEFI ISO boot | `tests/p0/vmware-optical-boot.sh` | Workstation version, VMX, ISO digest, guest log |
| EXT-04 | Hardware models | `tests/production/hardware-qualification-gate.sh` | Completed qualification for a named unit |
| EXT-05 | Org Secure Boot / registries | `tests/production/trust-provisioning-gate.sh` | Externally pinned organization keys, signed manifests, verified UKI and DB certificate, manufacturer-certified enrolled TPM EK |
| EXT-06 | Physical TPM | `tests/production/server-verified-tpm-challenge.sh` | Enrolled device + server nonce + hardware quote |
| EXT-07 | Independent assessment | `tests/production/external-acceptance-gate.sh` | Signed independent approval |

Run all seven:

```bash
bash scripts/production-readiness.sh
```

Overall PASS is required for production certification. A P0 or P3 PASS does
not substitute. Missing VMware, hardware, keys, or reviewers remain BLOCKED.

EXT-05 reads its approved SHA-256 pins from protected organization environment
configuration: `EXAMOS_RELEASES_PUBLIC_KEY_SHA256`,
`EXAMOS_DEVICES_PUBLIC_KEY_SHA256`, `EXAMOS_TPM_CA_STORE_SHA256`,
`EXAMOS_PROD_SECUREBOOT_CERT_SHA256`, and
`EXAMOS_PROD_DB_CA_STORE_SHA256`. It also requires `EXAMOS_PROD_TPM_EK_CERT`
and checks that its public-key fingerprint appears in the signed device
manifest. The gate verifies signatures and certificate chains; the pin source
must be controlled outside this checkout. This check does not prove that a
private key was operated inside an HSM; retain the organization's HSM audit
record and signing approval separately.
