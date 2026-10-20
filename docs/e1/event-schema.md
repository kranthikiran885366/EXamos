# E1 event schema status

**Status:** Consent preference is integrated as an additive event on the existing per-session event chain. E1 sensor observations remain unimplemented.

The repository has an existing per-session event-chain API in `server/events/event_chain.c` and a separate legacy ledger API in `server/events/ledger.c`. The existing unlinked `server/environment/environment_engine.c` calls the legacy ledger and therefore is not an approved E1 event producer. Do not add a competing chain or silently change historical event canonicalization.

The current consent event type is `E1_CONSENT_RECORDED`; its payload contains schema/disclosure identifiers, the four explicit source-scope booleans, and `collection_status: DISABLED_BY_POLICY`. Candidate input is parsed as a strict flat JSON object; missing, duplicate, unknown, mistyped, or mismatched-session fields are rejected. Storage errors return unavailable rather than success.

The current heartbeat representation is operational status:

```json
{
  "wifi": {"state": "DISABLED_BY_POLICY", "observation": "NOT_COLLECTED"},
  "ble": {"state": "DISABLED_BY_POLICY", "observation": "NOT_COLLECTED"},
  "rf": {"state": "DISABLED_BY_POLICY", "observation": "NOT_COLLECTED"}
}
```

This status is not an observation event, does not imply that hardware is absent, and must not be sent as evidence of zero nearby devices.

Before approving a versioned observation schema, define authenticated session binding, consent/policy version, actual source and receive times, monotonic sequence/idempotency, source quality/freshness, sensor/configuration provenance, privacy-safe identifiers, and canonical event-chain persistence. Add compatibility and tamper-verification tests before enabling ingestion.
