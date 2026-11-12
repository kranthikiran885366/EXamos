# ExamOS Production Release Trust Model

**Status:** repository-level verification contract foundation.  This document
does not authorize a production release, signing operation, firmware change,
TPM operation, or hardware test.

## Scope and outcomes

`VERIFIED` means only that all defined repository-level cryptographic,
provenance, artifact, and policy checks passed against authenticated external
trust and revocation evidence.  It is not production release authorization and
does not prove Secure Boot firmware enforcement, hardware TPM validation, or
runtime dm-verity enforcement.

| Decision | Meaning |
| --- | --- |
| `DEVELOPMENT` | Known legacy manifest or independently enforced test-only material. Never production-verifiable. |
| `BLOCKED` | Required external trust, approval, revocation, provenance, or evidence input is absent. |
| `REJECTED` | Supplied material is malformed, expired, cryptographically invalid, unapproved, or mismatched. |
| `VERIFIED` | Reserved for the later approved verifier with complete authenticated external inputs. |

## Trust boundaries

1. Source trust binds repository identity, full commit, clean tree, and inputs.
2. Build trust binds recipe, dependencies, toolchain, and reproducibility evidence.
3. Artifact trust binds the exact bytes of policy-required artifacts.
4. Signing trust binds metadata signer DER-SPKI SHA-256 separately from Secure
   Boot DB certificate DER SHA-256.
5. Verification trust requires an externally authenticated trust configuration
   and independently authenticated revocation evidence.

Repository development keys and test fixtures are prohibited from producing
production `VERIFIED`.

## Signature contract

Detached signatures cover only UTF-8 RFC 8785 JSON Canonicalization Scheme
bytes generated after strict JSON parsing and duplicate-key rejection.  Raw
JSON file bytes, whitespace, and a BOM are never signature input.  Allowed
algorithms are RSA-PSS-SHA256 (MGF1 SHA-256, salt length 32),
ECDSA-P256-SHA256, and ECDSA-P384-SHA384, selected solely by authenticated
external policy.

The verifier must not generate keys, contact a signer, enroll firmware trust,
or fall back to repository development credentials.

The local Python provenance tooling uses the pinned `rfc8785==0.1.4`
implementation. Install it with
`python -m pip install -r tools/requirements-release.txt`; the release
provenance unit tests include canonical property-order, UTF-16 key-order,
Unicode, number-formatting, and digest-binding cases. This local canonicalizer
does not supply production trust configuration or revocation evidence.

The current C server does not yet consume those canonical bytes. Release draft
creation therefore leaves the manifest digest empty, release verification
returns an explicit service-unavailable result, and all activation, rollout,
and recovery trust checks remain blocked. Persisted PostgreSQL JSONB text is
not accepted as a signing representation or verification result.

The current C server does not yet consume those canonical bytes. Release draft
creation therefore leaves the manifest digest empty, release verification
returns an explicit service-unavailable result, and all activation, rollout,
and recovery trust checks remain blocked. Persisted PostgreSQL JSONB text is
not accepted as a signing representation or verification result.

## External prerequisites

The organization must supply and authenticate:

- metadata signing authority and approved signer fingerprints;
- Secure Boot DB trust-anchor owner and approved DER certificate fingerprint;
- trust-configuration approval authority fingerprint, provisioned outside the
  evidence artifact;
- revocation source, trust anchor, freshness limit, rotation procedure, and
  failure behavior.

Until revocation evidence is approved and supplied, production verification is
`BLOCKED`.

## Artifact safety

Artifacts must reside in a trusted read-only release snapshot.  The verifier
rejects traversal, absolute paths, symlinks, non-regular files, duplicate roles
or paths, changed file metadata during hashing, and policy size/count limits.
If immutable stable reads cannot be established, verification is `BLOCKED`.

The verifier must use descriptor-relative `O_NOFOLLOW` access for every path
component.  If the host cannot provide those operations, it must return
`BLOCKED`; it must not weaken access to ordinary path-based reads. The local
`verify_artifact_inventory` helper checks exact inventory, size, and SHA-256
under a caller-provided immutable snapshot; it does not establish that the
snapshot is read-only or provide SBOM schema validation.
