# ExamOS Console

React 18 + Vite + React Router. The authenticated C server and PostgreSQL are the source of truth for application records. The browser has no application database or offline record cache; reads and writes go through the server API and fail visibly when unavailable.

    npm install
    npm run dev                       # http://localhost:5173
    npm run build && npm run preview

## Structure
    src/core/db        server API adapter, tenant context, live refresh hooks
    src/core/api       authenticated API client and endpoint services
    src/core/auth      server-backed login, roles, and session handling
    src/core/security  client presentation helpers; authorization remains server-side
    src/core/ui        CRUD, forms, shell, and shared display components
    src/modules/<key>  module workflows and pages

## Data and trust boundaries
- Application records are fetched from and persisted by authenticated server endpoints. The UI does not create local fallback records.
- Admin session continuity uses the server-managed HttpOnly cookie; access tokens remain in memory. Tenant selection and display preferences are browser UI state, not record storage.
- The browser does not sign API requests with a stored private key. Server authentication and authorization are the access-control boundary.
- Policy signing/verification, trusted release execution, TPM quote verification, candidate answer submission, and independent receipt verification remain unavailable unless the backend confirms them. The UI must not infer trust from client-side simulations or stored fields.
- Event lists and the cryptographic ledger are distinct server-side sources and must be displayed with their actual scope.

## Validation
Run the frontend regression tests with `node --test tests/*.test.js`, then `npm run build`.
