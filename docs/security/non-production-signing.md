# SPPIO non-production signing workflow

## Scope and guardrails

`tools/nonprod_signing.py` provides an offline, non-production signing and
verification workflow for release manifests and TPM trust feeds. It uses the
AWS CLI's existing profile; it does not accept or persist AWS credentials,
create keys, or call production APIs. Both the KMS aliases and required tags
are fixed to non-production purposes. A separately provisioned SHA-256 public
key fingerprint is mandatory.

The release manifest is signed over RFC 8785 canonical bytes. A TPM trust feed
is signed over `SPPIO-TPM-TRUST-FEED-V1\n` followed by its exact UTF-8 bytes.
Both use AWS KMS ECDSA P-256/SHA-256 and are independently verified locally
with Python `cryptography` before a bundle is written.

This tool does not integrate with the production release API, persist accepted
trust-feed sequence numbers, or apply trust-feed roots and revocations to
enrolled devices. Production release verification and device trust therefore
remain fail-closed. It is not evidence of physical TPM verification.

## KMS prerequisites

The tool expects two separate customer-managed KMS keys in the selected
non-production account and region:

| Purpose | Alias | Required tags |
| --- | --- | --- |
| Release manifests | `alias/examos-nonprod-release-signing` | `Environment=nonproduction`, `Purpose=release-signing` |
| TPM trust feeds | `alias/examos-nonprod-tpm-trust-feed` | `Environment=nonproduction`, `Purpose=tpm-trust-feed` |

Each key must be enabled, AWS-KMS-origin, `ECC_NIST_P256`, and `SIGN_VERIFY`.
The tool also checks that the key is in the caller's account and selected
region. The independently supplied fingerprint must be obtained and approved
out of band; it must not be copied from the feed or generated bundle.

The AWS account inspected during this work had no customer-managed signing
key in `ap-south-1`; its only listed key was the AWS-managed Secrets Manager
encryption key, which cannot sign. No key was created. AWS KMS pricing lists
customer-managed key storage at about `$1/month` and asymmetric signing at
`$0.15` per 10,000 requests; asymmetric requests are excluded from the free
tier. See the [AWS KMS pricing page](https://aws.amazon.com/kms/pricing/).

## Commands

Install the pinned Python dependencies from `tools/requirements-release.txt`.
Authenticate using the approved local AWS profile; do not put a console
password, access key, or session token in command arguments, environment
files, or this repository.

```powershell
python tools\nonprod_signing.py sign-release `
  --input path\to\manifest.json `
  --output path\to\release-signature.json `
  --expected-fingerprint sha256:<independently-provisioned-pin> `
  --region ap-south-1 `
  --profile default

python tools\nonprod_signing.py sign-trust-feed `
  --input path\to\trust-feed.json `
  --output path\to\trust-feed-signature.json `
  --expected-fingerprint sha256:<independently-provisioned-pin> `
  --region ap-south-1 `
  --profile default

python tools\nonprod_signing.py verify `
  --bundle path\to\trust-feed-signature.json `
  --expected-fingerprint sha256:<independently-provisioned-pin>
```

The tool refuses to overwrite an existing output file, rejects noncanonical
release JSON, malformed or duplicate-key JSON, invalid trust-feed schema,
wrong key purpose/tags/specification, mismatched independent pins, and invalid
signatures. The trust-feed bundle preserves its exact signed payload bytes.

## Test evidence and remaining work

`tests/release/test_nonprod_signing.py` uses only in-memory ephemeral software
keys and a mocked KMS client. It validates canonicalization, domain separation,
fingerprint binding, purpose isolation, and signature rejection. These tests
do not call AWS or demonstrate a real KMS key.

Before using the workflow against AWS, an administrator must approve and
provision the two non-production keys and independently verify their public
key fingerprints. Production authority identity, trust-anchor provisioning
location, maximum evidence age, durable replay-state integration, atomic
revocation application, release-server canonical-byte persistence, and
independent production verification remain pending.
