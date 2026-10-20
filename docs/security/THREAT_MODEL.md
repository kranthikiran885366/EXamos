# ExamOS threat model (P3 / boot / key release)

## Assets

- Exam decryption keys after attestation.
- Device identity (EK, AK, enrolled registry).
- PCR / UKI / dm-verity measurements.
- Candidate answers, ledger, session journal.
- Signing keys (PK/KEK/db, registry signing keys, HMAC keys).

## Actors

- Candidate on kiosk.
- Local attacker with USB / network on exam LAN.
- Compromised or cloned TPM software stack.
- Operator with filesystem access on the appliance.
- Remote attacker if server is reachable beyond loopback (current prototype: plaintext HTTP).

## Trust boundaries

| Boundary | Trusted side | Untrusted side |
|----------|--------------|----------------|
| Firmware + Secure Boot db | Org keys | Unsigned UKI |
| TPM 2.0 | Hardware quote | swtpm / synthetic digest |
| Device/release JSON | Signed production manifests | Unsigned development files |
| Server process | Independent verify | Agent-supplied evidence JSON |
| Key-release API | TRUSTED session + device bind | Candidate token alone |

## Abuse cases (must deny)

1. Replay of an old nonce/quote.
2. AK substitution after enrollment.
3. Unknown EK / unknown device.
4. Revoked device or release still obtains a key.
5. Forged ledger/journal without HMAC key.
6. Go suffix-hash verifier used as production authorization.
7. Missing PCR baseline treated as match.
8. Tampered rootfs with unsigned boot fallback.
9. Writing ExamOS onto internal Windows/BitLocker disks.

## Development vs production

Development may use swtpm, unsigned registries, and explicit `EXAMOS_TPM_MODE=development`. Production must set `EXAMOS_TPM_MODE=production`, require HMAC, signed registries, EK chain, enrolled AK, and hardware TPM. TOFU is forbidden in production (`ak_credential_activation_check`).
