# Authentication Architecture Decision

**Decision date:** 2026-10-18  
**Decision state:** target selected for implementation; deployment approval and
production provisioning remain blocked  
**Repository revision:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1`

## Decision

Proceed toward **ExamOS-managed administrator identities backed by PostgreSQL,
with TOTP MFA for privileged roles**, as the target architecture in the
supplied implementation plan.

This is an implementation direction, not evidence that a database, account,
MFA secret store, or remote TLS boundary is available. The local checkout
contains no OIDC integration/provider configuration and no PostgreSQL
integration. The current host has no local PostgreSQL service/process or
listener; WSL lacks `libpq` pkg-config metadata. A remote approved service was
not tested because no endpoint or TLS configuration was available.

## Rationale

- The supplied plan sets PostgreSQL-backed managed accounts with TOTP as its
  default when no already-provisioned OIDC provider is evidenced.
- PostgreSQL was selected by the user as the persistent datastore earlier in
  this conversation.
- Reusing the current process-local identity arrays would not provide durable
  account lifecycle, tenant isolation, or server-side session revocation.
- Keeping both the current PBKDF2 Basic-auth fallback and a future managed
  login would leave a weaker bypass path; authentication must converge on one
  authority before privileged remote use.

## Consequences and constraints

- Implement PostgreSQL access using a maintained client library, versioned
  migrations, parameterized SQL, bounded connection lifecycle, TLS
  certificate verification, least-privilege database roles, and explicit
  query/connect timeouts.
- Credential, MFA encryption, database connection, and migration secrets must
  come from an approved managed secret path. No secret or endpoint is created
  by this decision.
- TOTP secrets require encryption at rest with a key supplied by approved
  secret management; recovery must be controlled and auditable.
- Do not expose remote authentication or bind off loopback until TLS,
  authorization, rate limiting, and database trust are verified.
- Existing administrator access must not be represented as functional until
  an actual identity is securely provisioned and the Basic-auth bypass is
  removed or proven equivalent to the approved MFA and authorization policy.

## Alternatives considered

1. **Existing OIDC provider with provider-enforced MFA:** not selected at this
   stage because no provider or configuration exists in repository/environment
   evidence. Reconsider only if an approved provider is provisioned and
   architecture owners authorize it.
2. **Retain file-configured Basic authentication:** rejected as the target:
   it has no account identity/role/tenant model, has no MFA, and conflicts
   with the required single authoritative authentication path.

## Status

**PARTIAL / BLOCKED.** Target architecture is selected. A real PostgreSQL TLS
test instance, managed secret path, schema, implementation, TOTP, authorization
enforcement, runtime tests, and operational approval remain outstanding.
