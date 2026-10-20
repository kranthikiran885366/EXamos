# ExamOS P3 Exam Key Release

## Design Principle

The exam decryption key is **never sent before trust is established**. The key release gateway enforces a strict sequence: attestation must reach TRUSTED state before any key is made available, and the key is only released to a candidate bearer token that is bound to the attested session.

## Key Release Flow

```
Candidate login → candidate bearer token
    │
    ▼
POST /api/v1/exam/key-release
    Headers: Authorization: Bearer <candidate_token>
    Body:    { "session_id": "<attestation_id>", "device_id": "<device>" }
    │
    ▼
key_release_get_session_key()
    ├── Check 1: session exists
    ├── Check 2: session.state == TRUSTED
    ├── Check 3: device_id binding (session.device_id == request.device_id)
    ├── Check 4: exam_key_released flag set
    └── Check 5: audit log written to ledger
    │
    ▼ (all checks pass)
Response: { "status": "KEY_RELEASED", "session_key": "<64-char-hex>" }
```

## Key Properties

- **Session-bound**: each attestation session produces a unique key
- **Device-bound**: key is tied to the attesting device's session
- **Time-stamped**: key seed includes a Unix timestamp
- **Non-reusable**: key is stored in the session; the session cannot re-attest with the same nonce
- **Audited**: every key release writes to the tamper-evident ledger

## Key Derivation

```
key_seed = "EXAMOS-KEY-" || attestation_id || device_id || unix_timestamp
exam_key = SHA256(key_seed)  [64 hex chars = 256-bit key material]
```

This is a development construction. Production should use a proper KDF (HKDF-SHA256) with a server-side master key that is itself TPM-sealed.

## Error Codes

| Code | Meaning |
|------|---------|
| `P3_SESSION_INVALID` | Session ID not found |
| `P3_ATTESTATION_FAILED` | Session in FAILED state |
| `P3_REVOKED_DEVICE` | Session in REVOKED state (device revoked) |
| `P3_KEY_RELEASE_DENIED` | Session found but key not ready or device binding failed |

## Key Expiry

Keys do not expire in P3 by time — their validity is governed by the session state. If:

- The device is revoked → session state → REVOKED → next key-release attempt fails
- The release is revoked → next re-attestation fails → trust lost → key effectively invalidated

Production should add an explicit `expiresAt` timestamp to the key record.

## What Is Never Logged

- The plaintext exam key value is not written to logs or the ledger
- Only the key release event metadata (session_id, device_id, timestamp) is logged

## Candidate-Facing Error Message

When key release fails the candidate sees:

```
Exam environment verification failed.
Your examination cannot start at this time.
Please contact examination support.
Reference: EX-XXXX
```

Internal error codes remain in the server audit log and are not exposed to the candidate.
