# ExamOS — Full-Stack Integration: React Console + C/C++ Backend

This document describes the completed integration between:

| Project | Path | Role |
|---------|------|------|
| **ExamOS Main (C/C++)** | `D:\SEB BRO` | Backend server, agent, kiosk, proctoring (PostgreSQL + raw HTTP) |
| **ExamOS Console (React)** | `C:\Users\krant\Downloads\examos-frontend\examos-frontend` | Admin/operator/candidate frontend (React 18 + Vite) |

## 1. What was integrated

### Backend (C server) — `D:\SEB BRO/server/main.c`
- **CORS support added** so the React console (localhost:5173) can call the C server (localhost:8000):
  - `EXAMOS_CORS_ALLOWED_ORIGINS` env var (comma-separated origins).
  - Defaults to `http://localhost:5173` and `http://127.0.0.1:5173`.
  - `OPTIONS` preflight handler returning `Access-Control-Allow-Methods/Headers/Credentials`.
  - All responses now emit `Access-Control-Allow-Origin`, `Vary: Origin`, `Access-Control-Allow-Credentials: true`.
  - Relaxed `Cross-Origin-Resource-Policy: cross-origin` (was `same-origin` which blocked cross-origin fetch).
- Build verified clean: `make clean && make` → exit 0, zero warnings.

### Frontend API layer — `examos-frontend/src/core/api/`
- **`config/api.js`** — API base URL (`VITE_API_BASE`, default `http://localhost:8000`), full endpoint registry mapped to every C-server route, role-name map.
- **`client.js`** — Advanced HTTP client with:
  - ECDSA P-256 request signing (Web Crypto `SubtleCrypto`) on all mutating requests — each request is signed with `X-ExamOS-Signature`, `X-ExamOS-Signature-Alg`, `X-ExamOS-Signature-Key-Id`, `X-ExamOS-Request-Id`, `X-ExamOS-Timestamp`.
  - Bearer admin + candidate token management.
  - Automatic retry with backoff (configurable `MAX_RETRIES`, `REQUEST_TIMEOUT`).
  - Request/response audit trail (every call recorded).
  - `ApiError` typed errors with status + body.
- **`services.js`** — Wrapper functions for every backend route:
  - Auth: `adminLogin`, `adminLogout`, `adminProfile`, `candidateLogin`, `candidateLogout`
  - Platform: institutions, users, roles, campuses, rooms, exams (create/validate/approve/schedule/state/url/roster/checkin/submission/readiness/purge)
  - Exam sessions, fleet/devices, incidents, telemetry
  - Attestation: nonce/verify/re-attest/status, revoke release/device
  - Candidate workbench: paper, save answer, submit, announcements, terminals, command, key-release/eligibility
  - Consent, proctoring events/checkpoint/verify, second camera pairing
  - Ledger/audit, admin reload/lock, heartbeat, config save

### Auth — `examos-frontend/src/core/auth/`
- **`authService.js`** — Talks to `/api/v1/admin/login`, `/api/v1/admin/logout`, `/api/v1/admin/session`, `/api/v1/candidate/login`. Stores tokens in `sessionStorage`.
- **`AuthContext.jsx`** — Hybrid local (IndexedDB) + backend authentication. Detects backend readiness on mount. On successful backend login, seeds IndexedDB cache via `syncAll()`.
- **`ProtectedRoute.jsx`** — Maps backend roles (`PLATFORM_OWNER` → `superadmin`, etc.) to frontend RBAC keys so existing permission checks work unchanged.

### UI
- **`Shell.jsx`, `Sidebar.jsx`, `Topbar.jsx`** — Backend status indicator (online/offline, mode) in sidebar brand + topbar connection chip.
- **`LoginPage.jsx`** — Toggle between Local (IndexedDB demo) and Backend (C server) auth; Admin vs Candidate realm. Successful candidate login redirects to `/exam` (the C-server workbench).
- **`app.css`** — `.backend-status` / `.backend-conn` online/offline indicators.

### Sync layer — `examos-frontend/src/core/api/sync.js`
- Pulls collections from the backend (institutions, users, exams, campuses, rooms, roles, policies, fleet, incidents) into IndexedDB for offline reads.
- `syncAll()` runs after backend login (best-effort).
- `getViaBackend` / `createViaBackend` helpers for hybrid read-through cache.

## 2. Backend routes exposed to the console

| Domain | Route | Method | Auth |
|--------|-------|--------|------|
| Health | `/api/v1/health` | GET | none |
| Status | `/api/v1/status` | GET | admin |
| Admin login | `/api/v1/admin/login` | POST | none |
| Admin logout | `/api/v1/admin/logout` | POST | admin |
| Admin session | `/api/v1/admin/session` | GET | admin |
| Candidate login | `/api/v1/candidate/login` | POST | none |
| Institutions | `/api/v1/admin/institutions` | GET/POST | admin |
| Users | `/api/v1/admin/users` | GET/POST | admin |
| Roles | `/api/v1/admin/roles` | GET | admin |
| Campuses | `/api/v1/admin/campuses` | GET/POST | admin |
| Rooms | `/api/v1/admin/rooms` | GET/POST | admin |
| Exams | `/api/v1/admin/exams` | GET | admin |
| Create exam | `/api/v1/platform/exams/create` | POST | admin |
| Validate exam | `/api/v1/platform/exams/:id/validate` | POST | admin |
| Approve exam | `/api/v1/platform/exams/:id/approve` | POST | admin |
| Exam state | `/api/v1/platform/exams/:id/state` | POST | admin |
| Exam URL | `/api/v1/platform/exams/:id/url` | POST | admin |
| Schedule exam | `/api/v1/platform/exams/:id/schedule` | POST | admin |
| Policy rollback | `/api/v1/platform/exams/:id/policy/rollback` | POST | security admin |
| Roster | `/api/v1/admin/roster` | GET | admin |
| Add roster | `/api/v1/platform/exams/:id/roster` | POST | admin |
| Checkin | `/api/v1/platform/exams/:id/checkin` | POST | admin |
| Submission | `/api/v1/platform/exams/:id/submissions` | POST | admin |
| Readiness | `/api/v1/platform/exams/:id/readiness` | GET | admin |
| Purge | `/api/v1/platform/exams/purge` | POST | security admin |
| Sessions | `/api/v1/platform/exams/sessions` | POST | admin |
| Fleet | `/api/v1/admin/fleet` | GET | admin |
| Fleet compliance | `/api/v1/admin/fleet/compliance` | GET | admin |
| Fleet bulk | `/api/v1/admin/fleet/bulk` | POST | security admin |
| Incidents | `/api/v1/admin/incidents` | GET/POST | admin |
| Policies | `/api/v1/admin/policies` | GET | admin |
| Policy catalog | `/api/v1/admin/policies/catalog` | GET | admin |
| Telemetry | `/api/v1/admin/telemetry` | GET | admin |
| Attestation nonce | `/api/v1/attestation/nonce` | POST | agent token |
| Attestation verify | `/api/v1/attestation/verify` | POST | agent token |
| Attestation re-attest | `/api/v1/attestation/re-attest` | POST | agent token |
| Attestation status | `/api/v1/attestation/status` | GET | admin |
| Revoke release | `/api/v1/admin/revoke/release` | POST | security admin |
| Revoke device | `/api/v1/admin/revoke/device` | POST | security admin |
| Exam paper | `/api/v1/exam/paper` | GET | candidate token |
| Save answer | `/api/v1/exam/save_answer` | POST | candidate token |
| Submit exam | `/api/v1/exam/submit` | POST | candidate token |
| Announcements | `/api/v1/exam/announcements` | GET | none |
| Terminals | `/api/v1/exam/terminals` | GET | admin |
| Exam command | `/api/v1/exam/command` | POST | admin |
| Key release | `/api/v1/exam/key-release` | POST | candidate token |
| Key eligibility | `/api/v1/exam/key-release/eligibility` | GET | candidate token |
| Consent | `/api/v1/consent` | POST | candidate token |
| Proctoring events | `/api/v1/proctoring/events` | GET/POST | proctor/admin |
| Proctoring checkpoint | `/api/v1/proctoring/checkpoint` | POST | proctor/admin |
| Proctoring verify | `/api/v1/proctoring/verify` | POST | admin |
| Second camera request | `/api/v1/second-camera/request` | POST | candidate token |
| Second camera pair | `/api/v1/second-camera/pair` | POST | candidate token |
| Ledger | `/api/v1/ledger` | GET | admin |
| Config | `/api/v1/admin/config` | POST | admin |
| Admin reload | `/api/v1/admin/reload` | POST | security admin |
| Admin lock | `/api/v1/admin/lock` | POST | security admin |
| Heartbeat | `/api/v1/heartbeat` | POST | agent token |

## 3. How to run

### 3.1 Backend (C server)

```bash
# In WSL Ubuntu:
cd "/mnt/d/SEB BRO/server"

# 1. Build (already built, but rebuild after any change):
make clean && make

# 2. Run migrations against PostgreSQL (001–017):
# ./examos-db-migrate   # or apply migrations/*.sql with psql

# 3. Provision initial platform owner:
# ./examos-admin-provision

# 4. Copy env and edit secrets:
cp ../deploy/examos.env.example ../deploy/examos.env
# edit EXAMOS_LEDGER_HMAC_KEY, EXAMOS_AGENT_API_TOKEN, DB password, etc.

# 5. Start server:
EXAMOS_CORS_ALLOWED_ORIGINS="http://localhost:5173" ./examos-server
# or use the helper:
bash ../scripts/run-server.sh
```

The server listens on `http://127.0.0.1:8000` by default (loopback, per security design).

### 3.2 Frontend (React console)

```bash
cd "C:\Users\krant\Downloads\examos-frontend\examos-frontend"

# 1. Copy env:
copy .env.example .env   # (or set VITE_API_BASE=http://localhost:8000)

# 2. Install (already installed):
npm install

# 3. Dev server:
npm run dev          # http://localhost:5173

# 4. Production build:
npm run build && npm run preview
```

### 3.3 End-to-end flow
1. Start PostgreSQL + run migrations + provision admin.
2. Start `examos-server` (port 8000).
3. Start the console (`npm run dev`, port 5173).
4. Open `http://localhost:5173/login`.
5. Toggle "Backend (C server)" + "Admin console", sign in with provisioned admin credentials.
6. Backend status shows "online" in the sidebar/topbar.
7. Create an institution → campus → exam → approve → schedule → add roster → checkin candidates.
8. For candidate exam: switch realm to "Candidate exam", sign in with candidate ID + PIN → redirects to `/exam` workbench served by the C server.

## 4. Security properties

- **CORS**: only listed origins may call the API; credentials allowed.
- **Request signing**: ECDSA P-256 signatures on mutating requests (tamper evidence).
- **Bearer tokens**: admin session (`admin_session` cookie + `Authorization: Bearer`) and candidate session tokens.
- **RBAC**: every route checks granular permissions (`AUTH_PERM_READ`, `EXAM_MUTATION`, `SECURITY_ADMIN`, etc.).
- **Session hygiene**: 8-hour expiry, idle lock (5 min), step-up re-auth, PIN cleansed from memory on the C side.
- **Audit chain**: every console API call recorded; backend maintains a SHA-256 HMAC ledger.
- **CSP / security headers**: `nosniff`, `frame-ancestors none`, `same-origin` COOP/CORP, `Referrer-Policy: no-referrer`, `Permissions-Policy` restricting camera/mic/usb.
- **IndexedDB cache**: local offline cache; not encrypted at rest (matches existing design).

## 5. Files changed

**Backend (`D:\SEB BRO`):**
- `server/main.c` — CORS origin check, OPTIONS preflight, CORS headers on all responses.
- `deploy/examos.env.example` — server environment template (new).
- `scripts/run-server.sh` — server startup helper (new).
- `deploy/examos-server.service` — systemd unit example (new).

**Frontend (`examos-frontend`):**
- `src/config/api.js` — endpoint registry + config (new).
- `src/core/api/client.js` — signed HTTP client (new).
- `src/core/api/services.js` — all backend service wrappers (new).
- `src/core/api/sync.js` — backend ↔ IndexedDB sync (new).
- `src/core/security/requestSigner.js` — ECDSA P-256 signing (new).
- `src/core/security/auditClient.js` — audit-chain client (new).
- `src/core/auth/authService.js` — backend auth (new).
- `src/core/auth/AuthContext.jsx` — hybrid local/backend auth (edited).
- `src/core/auth/ProtectedRoute.jsx` — backend→frontend role mapping (edited).
- `src/core/ui/Shell.jsx`, `Sidebar.jsx`, `Topbar.jsx` — backend status UI (edited).
- `src/modules/auth/LoginPage.jsx` — local/backend login realms (edited).
- `src/styles/app.css` — backend status indicators (edited).
- `.env.example` — frontend env template (new).

## 6. Next steps (production hardening)

1. **TLS termination**: Set `EXAMOS_TLS_TERMINATED=1` and place a TLS proxy (nginx/Envoy) in front; enable `EXAMOS_ADMIN_COOKIE_SECURE=1`.
2. **mTLS**: Set `EXAMOS_MTLS_CA_CERT` and provision TPM-sealed agent certs (TRK-31/P3).
3. **PostgreSQL**: Apply migrations 001–017 and run `examos-admin-provision` for the initial platform owner.
4. **Encrypted IndexedDB**: For production, encrypt the local cache (currently matches existing design — not encrypted at rest).
5. **Server audit store**: Forward console audit events to a server-side immutable store (currently local IndexedDB + best-effort POST).
