# ExamOS P3 Trust Model

## Purpose

The current P3 implementation exercises TPM quote verification, but this
repository does not yet certify production hardware enrollment, event-log
replay, Secure Boot, measured boot, or dm-verity. Production release remains
blocked until those controls are independently provisioned and verified.

## Trust Chain

```
Power On
   │
   ▼ UEFI Firmware (PCR 0)
   │   Measures itself into TPM PCR 0
   │
   ▼ Secure Boot (PCR 7)
   │   Verifies UKI signature against enrolled db certificate
   │   Measures Secure Boot policy state into PCR 7
   │
   ▼ Signed Unified Kernel Image (PCR 4)
   │   Kernel + initrd + cmdline measured into PCR 4
   │
   ▼ ExamOS Runtime (PCR 11)
   │   dm-verity root hash measured into PCR 11
   │
   ▼ Security Agent starts
   │   Reads PCR 0, 4, 7, 11 via tpm2_pcrread
   │   Derives EK fingerprint from TPM EK public area
   │   Requests nonce from attestation server
   │
   ▼ Attestation Server
   │   Issues cryptographically random nonce (256-bit)
   │   Stores nonce in session record (single-use)
   │
   ▼ Agent produces TPM Quote
   │   TPM creates a nonce-bound TPMS_ATTEST quote and AK signature
   │
   ▼ Server verifies (16 checks)
   │   Device enrolled, not revoked
   │   TPM AK Name and AK public-key DER digest match signed enrollment
   │   Release known, not revoked
   │   Nonce fresh, session-bound, single-use
   │   EK fingerprint matches enrolled device
   │   AK present
   │   All 4 PCRs present
   │   PCRs match golden measurements
   │   Event log hash present
   │   Quote signature mathematically valid
   │
   ▼ Session state → TRUSTED
   │
   ▼ Exam key released (session-bound, 64-char hex)
   │
   ▼ Exam content delivered
```

## What Each PCR Covers

| PCR | Measures | Detects Tampering With |
|-----|----------|----------------------|
| 0 | UEFI firmware code and data | BIOS reflash, firmware implants |
| 4 | Boot manager + UKI payload | Modified kernel, initrd, or cmdline |
| 7 | Secure Boot policy + db certificates | Disabled Secure Boot, enrolled rogue certs |
| 11 | ExamOS rootfs dm-verity roothash | Modified root filesystem |

## What This Model Provides

- Firmware integrity verification (PCR 0)
- Secure Boot enforcement (PCR 7)
- Boot chain integrity (PCR 4)
- Runtime OS integrity (PCR 11)
- Device identity binding (EK fingerprint)
- Freshness guarantee (single-use server nonce)
- Session binding (device ↔ session ↔ attestation ID)
- Replay prevention (nonce consumed on first use)
- Re-attestation during exam (continuous trust)
- Revocation (device and release, effective within one heartbeat)

## What This Model Does NOT Guarantee

- Protection against hardware-level attackers with physical TPM access
- Absolute prevention of all memory attacks post-boot
- Security of the exam content server itself
- Protection if the candidate controls the server infrastructure

ExamOS P3 raises the cost of cheating to hardware-level exploitation. It does not make cheating impossible for well-resourced adversaries.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `EXAMOS_TPM_MODE` | `production` or `development` |
| `EXAMOS_DEVICES_CONFIG` | Path to enrolled device registry JSON |
| `EXAMOS_RELEASES_CONFIG` | Path to golden release registry JSON |
| `EXAMOS_GOLDEN_PCR_PATH` | Path to golden-pcr.json for agent fallback and verifier |
| `EXAMOS_RELEASE_ID` | Release ID being attested |
| `EXAMOS_DEVICE_ID` | Device identifier |
| `EXAMOS_AGENT_API_TOKEN` | Bearer token for agent endpoints (min 32 chars) |

Production device records must bind both the TPM-generated `ak_name` and
`ak_pub_sha256` (SHA-256 of the AK SubjectPublicKeyInfo DER) in the signed
registry. A TPM Name hashes the marshaled TPM public area, not OpenSSL DER;
the verifier therefore checks both enrolled values independently rather than
claiming one can be derived from the other. Test suites generate temporary
software-TPM evidence and random credentials per run. Neither is a production
trust anchor or release credential.

## Key Separation

```
Platform Key (PK)
    └── KEK
          └── db signing certificate
                └── UKI signing key
PCR policy signing key (separate)
```

Production keys are offline, hardware-protected, and never committed to Git or CI.
