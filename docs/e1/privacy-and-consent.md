# E1 privacy and consent

## Current behavior

E1 collection is disabled. The client emits only status metadata stating that Wi-Fi, BLE, and RF observations are `NOT_COLLECTED` because their state is `DISABLED_BY_POLICY`. It does not scan for access points, enumerate nearby Bluetooth devices, or report fabricated signal measurements.

The existing candidate consent route records camera and microphone consent only. A separate `POST /api/v1/e1/consent` route now accepts the authenticated candidate session and four explicit source-scope booleans, verifies the body session matches the bearer session, rejects duplicate/unknown/missing fields, and appends the preference to the existing per-session event chain. The response explicitly says `collection_status: DISABLED_BY_POLICY`; this records preference only and must not be interpreted as authorization or activation of environmental sensing. Second-camera pairing is also not proof of E1 consent or a functioning media analysis pipeline.

`tests/e1/e1-consent-http-test.sh` exercises the live HTTP listener with a freshly provisioned candidate credential, a real login-created bearer session, and temporary development trust configuration. It verifies rejection and acceptance responses and the persisted event. Its fixtures are test-only and do not constitute production trust, sensor data, or hardware acceptance.

## Conditions before enabling any source

Do not enable an E1 source until all of the following are implemented and verified:

- authenticated, active exam session and source-specific candidate disclosure/consent, including an approved disclosure text/version and lifecycle;
- policy authorization for the actual collection source and supported observation mode;
- collection start/stop bound to the session and revocation lifecycle;
- source capability and health are reported distinctly from an empty observation;
- data minimization, reviewer access roles, retention/deletion, and accessibility fallback are approved;
- event delivery uses the validated canonical event integrity mechanism;
- source-specific privacy/security tests and real supported-hardware evidence pass.

Consent must identify each enabled source, collected data categories, transient versus retained data, purpose, reviewer access, retention, and an approved fallback. Declining an optional sensor is not misconduct evidence.

## Prohibited collection

No packet payloads, message or browsing content, active probing, deauthentication, injection, device pairing, or attempts to connect to nearby devices. Do not persist raw SSIDs, BSSIDs, BLE addresses, or cross-session bystander identifiers. Optional RF acquisition remains disabled pending real equipment, lawful authorization, and an approved policy.

Sensor failure, denial, staleness, or lack of hardware is a system-health/data-quality condition, not a candidate risk signal. Consequential decisions require human review and an appeal path.
