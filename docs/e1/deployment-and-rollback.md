# E1 deployment and rollback

## Current deployment decision

E1 sensor collection is disabled and must remain so. No production/staging enablement procedure is available because source-specific consent, authenticated policy, sensor health, durable event integration, and retention controls are not implemented.

## Safe disable/rollback

The current client collector reports `DISABLED_BY_POLICY` and performs no Wi-Fi scan, Bluetooth enumeration, or RF acquisition. Keep this behavior unless a reviewed change adds consent-bound and policy-validated controls. Do not enable collection by changing only a runtime flag.

## Preconditions for future staging

1. Validate the exact P0–P6 release-candidate evidence on a clean, commit-bound tree.
2. Resolve the architecture discrepancy without replacing or duplicating existing services.
3. Implement source-specific consent and authenticated, signed/versioned policy.
4. Validate real sensor and event-persistence health before collection.
5. Prove event-chain compatibility, bounded resource behavior, retention/deletion, access controls, and rollback.
6. Use declared staging hardware and a documented, authorized procedure; label fixtures so they cannot be mistaken for sensor evidence.

If collection affects connectivity, privacy, or core exam reliability, disable E1 collection and preserve the core exam controls. A sensor failure is not a misconduct signal.
