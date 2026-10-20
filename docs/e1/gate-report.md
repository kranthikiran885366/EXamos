# ExamOS E1 gate report

**Decision:** `BLOCKED_PREREQUISITE`  
**Audit date:** 2026-10-12  
**Source commit observed:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1`  
**Working tree:** Dirty; evidence is not release-eligible.

| Gate | Status | Evidence / reason |
|---|---|---|
| E1-A Architecture and prerequisites | `BLOCKED_PREREQUISITE` | P0 ISO boot FAIL; P1 FAIL; P2 runtime tests NOT_RUN; P3 aggregate INVALIDATED; P4 INVALIDATED; P5-I BLOCKED; P6 BLOCKED. The frozen requested service stack is absent from this native C/C++ repository. |
| E1-B Consent and policy | `PARTIAL` | Candidate-authenticated per-source scope preference is durably recorded on the existing session chain and explicitly returns `DISABLED_BY_POLICY`; approved disclosure UX/version, signed collection policy, revocation lifecycle, and sensor-start enforcement remain unimplemented. |
| E1-C Hardware capability | `PARTIAL` | A Windows developer-host smoke confirmed the Wi-Fi link, Bluetooth-controller presence, and one camera frame. The ExamOS image was not booted; BLE scanning and RF receiver testing were not run; no target hardware is qualified. |
| E1-D Observation quality | `NOT_AVAILABLE` | The client collector now emits disabled/not-collected states, not observations. |
| E1-E Correlation | `NOT_IMPLEMENTED` | Existing unlinked module correlates in-memory BLE/room entries but lacks validated source events, freshness/quality rules, and canonical event-chain integration. |
| E1-F Security and privacy | `BLOCKED_PREREQUISITE` | Candidate login/bearer/session and malformed-scope rejection are exercised in a development HTTP integration test; production RBAC/tenant isolation, privacy-retention controls, and release-valid P3/P4 prerequisites remain unverified. |
| E1-G Evidence integrity | `BLOCKED_PREREQUISITE` | Existing P4 evidence is invalidated; E1 module uses the separate legacy ledger interface. |
| E1-H Performance | `NOT_RUN` | No supported-hardware E1 resource measurements. |
| E1-I Evaluation and limitations | `BLOCKED_ENVIRONMENT` | No approved labelled sensor dataset or real hardware results. |
| E1-J Rollback and regression | `NOT_RUN` | No E1 deployment/rollback test; P0–P6 regression gate is not clear. |

## Work performed in this increment

- Removed active Wi-Fi scanning and invented AP/RSSI fallback data from the client heartbeat collector.
- Removed the misleading Bluetooth-adapter-as-nearby-device count.
- The collector now reports `DISABLED_BY_POLICY` and `NOT_COLLECTED` for Wi-Fi, BLE, and RF; this is not a claim that hardware is absent.
- Added an isolated C unit test and a source guard against active scan invocation.
- Added a candidate-session-bound E1 consent-preference endpoint with strict per-source booleans and durable append to the existing per-session event chain. It never starts sensor collection.
- Added a test using the repository's real event-chain implementation for scope validation, session binding, durable verification, and persistence failure.
- Re-ran the radio-policy and consent/event-chain test scripts successfully, and linked the complete native server with the E1 route into a temporary binary. Existing OpenSSL 3 deprecation warnings remain non-fatal.
- Added an out-of-tree full-server HTTP integration test using ephemeral candidate credentials and development trust fixtures. It exercises login, bearer/session checks, malformed consent rejection, valid response, and persisted event contents. The test does not start collection or establish production/hardware acceptance.
- Ran a privacy-bounded physical host smoke: verified the connected Wi-Fi link, Bluetooth controller/service presence without BLE scanning, and read/discarded one in-memory camera frame. No E1 observations were collected; the ExamOS image and RF receiver were not tested. See [hardware-smoke-2026-10-12.json](../../artifacts/e1/hardware-smoke-2026-10-12.json).
- Replaced unsupported PASS assertions in the pre-change audit with observed evidence and explicit blockers.

## Not run / not claimed

- No ExamOS-target Wi-Fi/BLE/RF/camera acceptance, BLE scan, RF receiver test, second-camera pipeline test, or approved sensor-dataset evaluation. The host-only Wi-Fi link and one-frame camera smoke do not satisfy hardware acceptance.
- No E1 collection, correlation, database, retention, load, or deployment test. Consent HTTP/authentication and event persistence have a development integration test, not a production security certification.
- No end-to-end E1 PASS and no production readiness claim.
- The isolated collector test verifies only that unconfigured collection remains disabled and serializes honestly. The HTTP integration test uses ephemeral test credentials and development trust fixtures and does not validate physical sensors or production trust.

See [pre-change-audit.md](./pre-change-audit.md) for the component-by-component evidence and missing prerequisites.
