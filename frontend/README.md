# ExamOS Console (frontend only, JavaScript)

React 18 + Vite + React Router, plain JavaScript. No backend: persistence is IndexedDB, and all logic runs in the browser through per-module services.

    npm install
    npm run dev                       # http://localhost:5173
    npm run build && npm run preview  # production build with security headers

First load seeds a workspace through the real services (keys, releases, policies, centers, 152 devices, 120 candidates, a live exam, sessions). Dev login page lists bootstrap accounts and the live TOTP code.
"Reset workspace" (Admin, super admin) wipes IndexedDB and re-seeds.

## Structure
    src/core/db        IndexedDB layer, tenant context, live collection hook
    src/core/security  crypto (ECDSA, PBKDF2, hashing), TOTP, RBAC, audit chain, sanitisers
    src/core/services  shared service helpers, key store, question generator
    src/core/ui        Crud, forms, step-up modal, shell
    src/modules/<key>  service.js (rules + persistence) and <Key>Page.jsx (UI), one folder per module A-P

## How the modules integrate
- Release (signed, SBOM-scanned, 2-person approval, staged rollout, revoke) -> Fleet devices run a release -> TPM attestation checks PCRs against that release's golden values.
- Firewall rules -> Policy origins must be allowed to publish; rule changes that would break a published policy are refused.
- Policy (ECDSA-signed, versioned, 2-person rollback) -> Exams must reference a published, signature-valid policy -> Devices converge to it via heartbeats.
- Exam lifecycle (separation of duties, capacity, schedule-conflict and tenant checks) -> Candidates (CSV import, seat allocation, identity) -> Sessions start only if identity, live window, heartbeat, release, policy and fresh attestation all pass -> signed submission receipt.
- Engine (simulated device agent) -> heartbeats, periodic attestation, isolation and incidents -> Ops dashboard KPIs, seat heatmap, Incidents, Reports.
- Every write is audited in a persisted SHA-256 hash chain that can be verified.

## Real vs simulated
Real: validation, state machines, RBAC checks in services, ECDSA signing/verification with non-extractable keys, PBKDF2, TOTP, nonce/replay protection, receipts, audit chain, computed metrics (including measured IndexedDB p95).
Simulated: the device agent (heartbeats, TPM quotes), there is no real TPM or network.

## Security notes
CSP, frame-ancestors none, nosniff, no-referrer, Permissions-Policy, COOP/CORP, HSTS (preview server headers; copy to your host). Session in memory only, idle lock 5 min, 8 h expiry, step-up re-auth for sensitive actions.
Limits: browser-side enforcement can be bypassed by anyone with devtools, and IndexedDB is not encrypted at rest. A production system needs server-side authn/authz, signing keys in an HSM/KMS, and a server audit store.
