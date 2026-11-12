# SPPIO TPM Trust Feed

## Status

The strict feed parser and detached-signature verification interface are
implemented in `server/attestation/tpm_trust_feed.c`. They are exercised with
ephemeral unit-test keys only. No test key or trust anchor is a production
credential.

The production server deliberately refuses EK trust-anchor startup until an
approved trust-feed provisioning adapter is configured and integrated. The
standalone verifier does not provision an authority, load a feed from an
operator-selected path, persist replay state, apply revocations, or prove
physical TPM operation. No production trust decision is implied by its unit
tests.

## Feed format

The verifier accepts a bounded, ASCII-encoded JSON document and a detached
signature over `SPPIO-TPM-TRUST-FEED-V1\n` followed by the exact feed bytes.
Duplicate keys, malformed escapes,
non-ASCII strings, unknown fields, incorrect types, invalid CA certificates,
and mismatched certificate fingerprints are rejected. The detached signature
is mandatory; the signature algorithm is selected by the separately supplied
policy, never by the feed.

The v1 top-level object has exactly these required fields:

| Field | Type and validation |
| --- | --- |
| `schema` | Exact string `sppio-tpm-trust-feed-v1` |
| `authority_id` | ASCII identifier; must equal the independently provisioned authority |
| `sequence` | Positive integer, strictly greater than persisted high-water sequence |
| `issued_at`, `expires_at` | Positive Unix-second integers; valid and within configured age |
| `ek_roots` | Non-empty array of `{id, pem, sha256}` CA certificates |
| `revoked_device_ids` | Array of unique ASCII device identifiers |
| `revoked_ek_fingerprints` | Array of unique, nonzero 64-character SHA-256 fingerprints |

No trust-anchor or trust-authority value is included as a repository default or
sample credential.

Timestamps are positive Unix seconds. Each EK root must be a currently valid
CA certificate whose DER SHA-256 matches the feed entry. The authority ID must
match a provisioned expected ID. The signing key's SHA-256 is calculated over
DER SubjectPublicKeyInfo and compared with an independently provisioned pin;
neither identity nor pin is taken from the feed. Changing even whitespace in
the JSON invalidates its signature.

Supported detached-signature policies are Ed25519, RSA-PSS-SHA256 with a
3072-bit-or-larger RSA key and 32-byte salt, ECDSA P-256/SHA-256, and ECDSA
P-384/SHA-384.

## Fail-closed policy

The verifier returns `BLOCKED_CONFIGURATION` if the expected authority,
signing public key, independently supplied public-key fingerprint, maximum
evidence age, or durable replay-state input is missing. It rejects evidence
whose issue or expiry time is invalid, whose age or total lifetime exceeds the
configured maximum, or whose sequence is not greater than the caller-supplied
persisted sequence.

The replay check is only effective across restarts if the caller obtains the
high-water sequence from durable, trusted state and commits a newly accepted
sequence atomically with feed application. That persistence and application
transaction are not yet integrated.

## Pending administrator decisions

- Confirm the SPPIO Trust Authority identity and its enrollment/provisioning
  ceremony.
- Provision the authority public key and its SHA-256 pin independently of the
  feed; no value is embedded in this repository.
- Approve the out-of-band trust-anchor configuration location and access
  controls. Ordinary application environment/configuration is not a trust
  anchor source.
- Set the maximum evidence age and approve clock-synchronization requirements.
- Approve durable replay-state storage and atomic feed/revocation application.
- Approve the operational distribution, rotation, rollback, and recovery
  procedures for signed feeds.

Until these decisions are approved and the adapter is integrated, production
TPM trust remains blocked. Software TPM tests are not physical TPM evidence.
