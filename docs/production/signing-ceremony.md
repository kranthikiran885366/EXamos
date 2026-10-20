# Organization-owned Secure Boot and release-trust ceremony

**Status: not provisioned.** Development keys under `image/trust/` are
test-only and must never be used as production trust anchors.

## Required organization inputs

| Asset | Owner | Custody | Repository policy |
|---|---|---|---|
| UEFI Platform Key (PK) | Security owner | Offline HSM / air-gapped | Private key never in git or CI |
| Key Exchange Key (KEK) | Security owner | Offline HSM | Same |
| Signature database (db) certificate | Security owner | HSM; public cert may be distributed | Public cert supplied at verify time |
| UKI signing identity | Release owner | HSM | Sign outside the build host |
| Release/device registry signing key | Trust enrollment owner | HSM | Signed manifests only |
| TPM manufacturer CA bundle | Trust enrollment owner | Controlled distribution | Path via `EXAMOS_TPM_CA_STORE` |

## Ceremony steps (outside this repository)

1. Generate production keys on an air-gapped HSM. Record key identifiers,
   algorithms (RSA-3072+ or NIST P-256+), and dual-control operators.
2. Export public certificates only. Store private material in approved custody.
3. Enroll PK/KEK/db on lab firmware using the organization process — **not** by
   this repository rewriting a developer laptop’s keys.
4. Sign the release UKI and measured-boot policy. Record signer identity,
   timestamp, and payload SHA-256.
5. Sign `devices.json` and `releases.json` (or their production equivalents)
   and distribute signatures next to the manifests.
6. File the ceremony record as independently stored evidence. The production
   gate reads those files; it does not create them.

## What this repository will accept

`tests/production/trust-provisioning-gate.sh` PASSes only when all of the
following environment paths exist, are readable, and verify:

- `EXAMOS_PROD_DB_CERT` — organization db certificate (PEM)
- `EXAMOS_PROD_UKI` — release UKI
- `EXAMOS_PROD_UKI_SIGNATURE` or a sbverify-compatible signed UKI
- `EXAMOS_PROD_RELEASE_MANIFEST` + `EXAMOS_PROD_RELEASE_SIGNATURE` +
  `EXAMOS_PROD_RELEASE_PUBKEY`
- `EXAMOS_PROD_DEVICE_MANIFEST` + `EXAMOS_PROD_DEVICE_SIGNATURE` +
  `EXAMOS_PROD_DEVICE_PUBKEY`
- `EXAMOS_TPM_CA_STORE` — manufacturer EK CA bundle

Absence is **BLOCKED**, not PASS. Development snapshot keys are rejected.
