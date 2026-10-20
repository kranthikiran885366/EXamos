# E1 operational runbook

## Current safe state

E1 sensor collection is disabled. The heartbeat's E1 status values indicate `DISABLED_BY_POLICY` and `NOT_COLLECTED`; they do not mean the device was scanned or that no nearby devices exist.

## Before any authorized staging session

Do not enable collection until the E1 gate report is no longer blocked and the deployment has source-specific consent, validated policy, supported hardware, canonical event-chain integration, access controls, and retention/deletion evidence.

## Interpreting sensor states

- `DISABLED_BY_POLICY`: collection was not authorized/enabled.
- `UNAVAILABLE`: a capability is not available; this is not an empty scan.
- `UNSUPPORTED_PLATFORM`: the platform lacks a validated method.
- `PERMISSION_DENIED`: the operating system denied access.
- `INITIALIZING`, `DEGRADED`, or `FAILED`: system health states, not candidate behavior.
- `NOT_COLLECTED`: no observation was acquired.

Never convert a missing, denied, stale, or failed sensor result to “no nearby devices,” and never treat sensor failure as misconduct.

## Incident response and rollback

If a future authorized E1 deployment affects exam connectivity, privacy, or reliability, disable E1 collection through the reviewed policy and preserve P0–P6 controls. Record the actual source state and operational error without logging secrets, raw radio data, or bystander identifiers. Escalate false-positive concerns to an authorized human reviewer and preserve the candidate appeal path.

Current artifact [rf-scanner-unit-test.json](../../artifacts/e1/rf-scanner-unit-test.json) covers only disabled collector behavior; it is not a hardware or production-health report.
