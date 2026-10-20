# ExamOS P3 Attestation Service

## Overview

The attestation service implements the 16-step deterministic trust chain that every exam machine must pass before receiving a session-bound exam key. It is implemented in `server/attestation/attestation_service.c` and loaded dynamically from JSON config files at startup.

## Configuration Loading

At startup `attestation_service_init()` follows this resolution order:

1. `EXAMOS_DEVICES_CONFIG` env var → path to `devices.json`
2. `/etc/examos/devices.json` (production)
3. `<binary_dir>/../config/devices.json` (development)
4. No fallback: missing, empty, malformed, or invalid trust registries fail startup.

Same pattern for releases via `EXAMOS_RELEASES_CONFIG`.

## The 16-Step Verification Chain

`attestation_verify_evidence()` executes these checks in strict order. Any failure stops the chain and returns a structured error code.

| Step | Check | Error Code |
|------|-------|-----------|
| 1 | Request format valid (device_id, release_id, nonce present) | `P3_MALFORMED_REQUEST` |
| 2 | Session exists — nonce matches a pending session | `P3_INVALID_NONCE` |
| 3 | Device ID is in the enrolled device registry | `P3_UNKNOWN_DEVICE` |
| 4 | Device is not revoked | `P3_REVOKED_DEVICE` |
| 5 | Release ID is in the golden release registry | `P3_UNKNOWN_RELEASE` |
| 6 | Release is not revoked | `P3_REVOKED_RELEASE` |
| 7 | Nonce session device_id matches submitted device_id | `P3_SESSION_BINDING_FAIL` |
| 8 | Nonce has not been used before (replay protection, atomic) | `P3_NONCE_REPLAY` |
| 9 | EK fingerprint matches the enrolled device's registered EK | `P3_UNKNOWN_DEVICE` |
| 10 | AK Name and public-key digest match the enrolled identity | `P3_INVALID_AK` |
| 11 | All 4 PCR values (0, 4, 7, 11) are present | `P3_PCR_MISMATCH` |
| 12–13 | PCR 0, 4, 7, 11 match the golden release measurements exactly | `P3_PCR_MISMATCH` |
| 14 | Event log hash is present | `P3_EVENTLOG_INVALID` |
| 15 | Quote signature is mathematically valid | `P3_INVALID_SIGNATURE` |
| 16 | All checks passed — session state → TRUSTED | — |

## Nonce Lifecycle

```
attestation_create_challenge()
    → generates 256-bit random nonce from /dev/urandom
    → stores in session with nonce_used=0

attestation_verify_evidence()
    → matches nonce to session
    → sets nonce_used=1 atomically before further checks
    → replay attempt returns P3_NONCE_REPLAY

attestation_re_attest_challenge()
    → generates new 256-bit nonce
    → resets nonce_used=0 in the existing TRUSTED session
    → client must produce a fresh quote covering the new nonce
```

## Exam Key Generation

On successful attestation (step 16):

```
key_seed = "EXAMOS-KEY-" || attestation_id || device_id || unix_timestamp
exam_key = SHA256(key_seed)  [64-char hex]
```

The key is stored in the session record and only released through the key-release gateway after re-verifying session state.

## Session State Machine

```
PENDING
   │
   ▼ (verify passes all 16 checks)
TRUSTED ←────────────────────────────┐
   │                                 │
   ▼ (re-attest challenge issued)    │ (re-attest verify passes)
   │ nonce_used=0, state=TRUSTED     │
   │                                 │
   └─────────────────────────────────┘
   │
   ▼ (verify fails / device revoked / release revoked)
FAILED / REVOKED
```

## Runtime Device and Release Registration

The admin API supports dynamic enrollment without server restart:

```
POST /api/v1/admin/device/register
    Body: { "device_id": "...", "ek_fingerprint": "...", "allowed_release": "..." }

POST /api/v1/admin/release/register
    Body: { "release_id": "...", "pcr0": "...", "pcr4": "...", "pcr7": "...", "pcr11": "..." }
```

Both require HTTP Basic admin authentication.

## Revocation

```
POST /api/v1/admin/revoke/device   { "device_id": "..." }
POST /api/v1/admin/revoke/release  { "release_id": "..." }
```

Revocation is immediate and in-memory. Active sessions with revoked devices or releases will fail their next re-attestation challenge.

## Quote Signature

The native authorization path verifies the TPM-generated `TPMS_ATTEST`
signature using the enrolled AK public key, with nonce, PCR selection, and
quoted PCR digest validation. It does not use a shared quote suffix. The
separate Go verifier is a deprecated development-only prototype and must not
authorize devices. Production enrollment and measured-boot certification
remain external prerequisites.
