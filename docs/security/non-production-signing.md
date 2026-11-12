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
KMS metadata must identify the same key as the ARN returned by the alias
lookup, and the `GetPublicKey` response must advertise `ECDSA_SHA_256`.

## Least-privilege access

The signing runtime should use a dedicated non-production role, not an
administrator identity. Replace the account and key-ID placeholders with the
two approved key ARNs; do not broaden the KMS resources to `*`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IdentifyCaller",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    },
    {
      "Sid": "InspectAndSignOnlyApprovedNonproductionKeys",
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:ListResourceTags",
        "kms:Sign"
      ],
      "Resource": [
        "arn:aws:kms:<region>:<account-id>:key/<release-key-id>",
        "arn:aws:kms:<region>:<account-id>:key/<trust-feed-key-id>"
      ]
    }
  ]
}
```

Attach key policies that permit this role only the listed operations on the
matching key. Prefer separate runtime roles for release signing and trust-feed
signing, each scoped to its single key. The CLI implementation selects
`ECDSA_SHA_256`, validates the key's purpose tags and alias, and independently
verifies every returned signature. Do not grant the runtime role key creation,
alias/tag mutation, key-policy administration, disabling/deletion, or
production-key access. Confirm the actions and any desired KMS condition keys
against the current AWS KMS authorization reference before provisioning.

Key provisioning and policy administration belong to a separate, audited
administrator role. Use a time-limited, approval-gated session; restrict
changes to the two named non-production keys and their aliases; require
independent review of key policies and tags; and do not use that role for
ordinary signing. Key creation may require a separate tightly controlled
provisioning permission because KMS creation is not scoped to an existing key.
No administrator or IAM change is made by this repository workflow.

## Key lifecycle, recovery, and audit

AWS KMS asymmetric keys require manual rotation. Create a replacement key
under a new key ID, verify its public-key fingerprint out of band through an
independent administrator channel, update the separately managed pin, and
test verification before switching the signing alias. Keep the old public key
available for the approved verification-retention period; stop signing with
the old key, then disable it only after consumers have accepted the replacement.
Revoke a compromised key/pin promptly through the independently controlled
trust configuration, preserve incident evidence, and do not rely on feed
contents to revoke the key that authenticates that feed. Define rollback
ownership and an offline recovery approver before production use. See AWS
[KMS key rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)
and [key-spec compatibility](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html).

Enable and retain CloudTrail KMS management and cryptographic-operation
events, including `Sign`, key-policy/alias/tag changes, and key state changes.
Alert on unexpected principals, regions, keys, or signing volume; periodically
reconcile key IDs, aliases, tags, and fingerprints against the approved
inventory. Do not log credentials or private key material. KMS does not export
the private key; recovery from loss or compromise is by controlled rotation,
not key restoration.

AWS currently lists `$1/month` per customer-managed key and `$0.15` per 10,000
asymmetric requests (including signing); asymmetric `Sign` and `GetPublicKey`
requests are excluded from the free tier. The estimated base cost for two
keys is therefore approximately `$2/month`, plus those request charges and
any extra period when old and replacement keys overlap. Prices can vary or
change; confirm the live [AWS KMS pricing](https://aws.amazon.com/kms/pricing/)
before provisioning. The supported signing algorithm and key spec are
documented in the [KMS Sign API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
and [KMS key-spec compatibility table](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html).
No resources or billable operations are created by this workflow.

## Test evidence and remaining work

`tests/release/test_nonprod_signing.py` uses only in-memory ephemeral software
keys and a mocked KMS client. It validates canonicalization, domain separation,
fingerprint binding, purpose isolation, digest and signature tampering, key-ID
consistency, unsupported algorithms, pin changes/rotation, and
cross-environment rejection. These tests do not call AWS or demonstrate a
real KMS key.

Before using the workflow against AWS, an administrator must approve and
provision the two non-production keys and independently verify their public
key fingerprints. Production authority identity, trust-anchor provisioning
location, maximum evidence age, durable replay-state integration, atomic
revocation application, release-server canonical-byte persistence, and
independent production verification remain pending.
