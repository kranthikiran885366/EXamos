# ExamOS P3 Release: examos-0.4.0

## Release Summary

| Field | Value |
|-------|-------|
| Release ID | `examos-0.4.0` |
| Version | 0.4.0 |
| Phase | P3 — Trusted Boot + TPM Attestation + Secure Exam-Key Release |
| Status | DEVELOPMENT |
| UKI Hash | Placeholder (update after real signed build) |
| PCR Bank | SHA-256 |

## Golden PCR Values (Development)

These values are **test constants**, not from a real measured boot. See `artifacts/p3/golden-pcr.json` for the authoritative record.

| PCR | Name | Value |
|-----|------|-------|
| 0 | CRTM / UEFI Firmware | `f4a3c2e1b09876543210abcdef0123456789abcdef0123456789abcdef012345` |
| 4 | Boot Manager / UKI | `a1b2c3d4e5f6071829304a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f` |
| 7 | Secure Boot Policy | `778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566` |
| 11 | ExamOS Rootfs | `112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00` |

## Generating Production Golden PCR Values

1. Build and sign the ExamOS UKI with the production db signing key
2. Boot the signed image on an enrolled machine with Secure Boot enabled
3. After boot, read PCRs:
   ```bash
   tpm2_pcrread sha256:0,4,7,11
   ```
4. Record the output
5. Get security-team review and cryptographic verification
6. Update `server/config/releases.json` with the verified values
7. Update `artifacts/p3/golden-pcr.json` with provenance metadata
8. Set `approval_status` to `APPROVED_STAGING` or `APPROVED_PRODUCTION`
9. Tag the release commit

## Components

| Binary | Version | Build |
|--------|---------|-------|
| examos-server | 0.4.0 | gcc -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong |
| examos-agent | 0.4.0 | gcc -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong |
| examos-proctor | 0.4.0 | g++ -std=c++17 -O2 |
| examos-kiosk-launcher | 0.4.0 | gcc -O2 |
| examos-verifier | 1.0.0 | go build |

## Known Limitations

- The Admin Releases UI can persist a release draft and server-computed manifest digest, but no trusted signing service currently verifies or signs that manifest. Drafts cannot be approved or offered to devices.
- The entered package list is not a complete SBOM, and the backend has no configured vulnerability feed or scan worker; CVE status is therefore unknown, not clean.
- Validation evidence submitted through the UI is stored with a digest, but user-submitted records are not automated test results and do not satisfy release validation gates.
- Deployment groups are persisted as plans only. Device assignments, rollout dispatch, pause/resume, and authenticated device-agent telemetry are not implemented; no rollout progress is reported.
- The release has not been validated on an enrolled physical TPM or trusted EK manufacturer chain
- The checked-in device and release registries are development-only and cannot authorize production devices
- A physical TPM enrollment request is not trusted until EK-chain validation, MakeCredential/ActivateCredential, and signed registry approval complete
- The agent reports the TCG event-log hash, but the server does not replay the event log into PCR values; this is not measured-boot proof
- No TLS on the server (plaintext HTTP in development)
- PCR values are test constants until a real measured boot is performed
- The exam key derivation uses SHA-256, not HKDF with a sealed server master key

## Upgrade Path to Production

1. Provision real physical-TPM enrollment and signed production device/release registries; the legacy shared-suffix verifier is not production authorization
2. Create persistent TPM EK/AK handles with `scripts/enroll-physical-tpm.sh` on each approved physical device
3. Validate the EK chain, complete MakeCredential/ActivateCredential, and sign a device registry binding EK, TPM AK Name, and AK public-key digest
4. Generate real golden PCR values from a controlled, Secure-Boot-enabled measured boot
5. Run `tests/p3/hardware-tpm-preflight.sh` on the physical device, then verify full server-side attestation and signed release evidence
6. Deploy TLS termination (nginx/caddy) in front of the HTTP server
7. Migrate exam key derivation to HKDF-SHA256 with a TPM-sealed master key
8. Implement persistent device registry (PostgreSQL) replacing in-memory registry
