# Authentication Remediation — Focused Threat Model

**Scope:** administrator authentication, authorization, persistence, sessions,
MFA, audit, dashboard and service boundary  
**Source revision:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1`  
**Evidence class:** source/configuration review; runtime behavior unverified

## Assets

- Administrator credentials, MFA seeds and recovery credentials.
- Session credentials and session revocation state.
- Institution, exam, room, candidate, device, report and release records.
- Audit records and evidence exports.
- PostgreSQL credentials, TLS trust material and migration authority.
- Exam configuration and privileged operation controls.

## Trust boundaries and actors

- Unauthenticated network client → plain HTTP ExamOS listener, currently
  restricted to loopback.
- Browser dashboard JavaScript → admin API; current UI stores reusable
  credentials/tokens in browser `sessionStorage`.
- Request handler → process-local enterprise arrays and file/config stores.
- ExamOS service (currently configured as root) → host files, logs and runtime
  secret environment.
- Future application DB role → PostgreSQL service across an unverified
  deployment boundary.
- Platform/institution administrators, exam operators, auditors, candidates,
  automated agents and support personnel; current admin routes do not enforce
  the proposed distinctions.

## Threats and current controls

| Threat | Existing control/evidence | Residual risk |
|---|---|---|
| Password guessing or credential stuffing | Basic-auth process-local attempt counter; five failures trigger 15-minute lockout, ten attempts/window cap. | JSON login bypasses this limiter; limiter is not distributed and uses one fixed record key. |
| Authentication bypass or inconsistent verifier | PBKDF2 config verifier exists. | In-memory login compares supplied password directly to stored field; Basic fallback ignores username and has no MFA. |
| Privilege escalation | Role enum and session role field exist. | Admin authorization validates a bearer token but does not check role/permission. |
| Cross-tenant disclosure or mutation | Records include institution/exam identifiers. | Routes frequently request data with null tenant/resource filters; no server-derived scope enforcement. |
| Session theft, prediction or persistence loss | Eight-hour expiration and in-memory revoke function. | Token generation uses `rand()` and predictable inputs; no logout API; session state vanishes on restart; browser retains bearer and Basic credentials. |
| MFA bypass | None identified. | TOTP/OIDC absent; no privileged MFA enforcement. |
| SQL injection / DB credential exposure | No database code found. | PostgreSQL, parameterized queries, DB TLS and managed DB secrets are absent, so no integration controls can be evaluated. |
| Credential exposure over transport | Server refuses non-loopback bind without verified TLS/mTLS. | HTTP is plaintext on loopback; remote TLS/proxy boundary is not implemented or verified. |
| Browser script execution/CSP failure | CSP defaults to self-only script execution. | Inline dashboard/login scripts and handlers conflict with CSP, likely breaking UI and motivating unsafe weakening. |
| Audit repudiation or secret leakage | Hash-chained ledger exists. | Admin auth attempts are not evidenced in the ledger; static actor labels used for some actions; end-to-end audit durability/access not tested. |
| Host/service compromise | systemd sandbox settings exist. | Full server runs as root; service capability/filesystem needs have not been minimized or runtime-tested. |

## Assumptions and blockers

- No remote database, OIDC provider, production account, or privileged secret
  channel is assumed.
- The target is PostgreSQL-backed managed identities with TOTP, subject to
  approved key custody and TLS configuration.
- Local source/tests cannot prove actual tenant isolation, database behavior,
  TLS validation, MFA enrollment, or production service confinement.
- Existing synthetic fixtures must remain labelled test-only and cannot
  satisfy integration or production acceptance.

## Priority

Before enabling remote administrator use: remove the weaker auth path, enforce
deny-by-default role/resource scopes, replace predictable sessions, persist
revocation, enforce privileged MFA, add complete audit events, fix CSP without
weakening it, establish verified TLS and least-privilege database/service
roles, then pass negative as well as positive integration tests.
