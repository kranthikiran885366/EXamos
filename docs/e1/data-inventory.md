# E1 data inventory

**Collection status:** Disabled / not collected.

| Source | Current emitted data | Raw observation data | Persistence / retention | Authorization status |
|---|---|---|---|---|
| Wi-Fi | Capability state `DISABLED_BY_POLICY`; observation `NOT_COLLECTED` | None from the E1 collector | No E1 observation is persisted by this collector | No E1 consent or signed collection policy exists |
| BLE | Capability state `DISABLED_BY_POLICY`; observation `NOT_COLLECTED` | None from the E1 collector | No E1 observation is persisted by this collector | No E1 consent or signed collection policy exists |
| Optional RF | Capability state `DISABLED_BY_POLICY`; observation `NOT_COLLECTED` | No RF receiver integration exists | None | No device, lawful deployment authorization, or collection policy is evidenced |
| Second camera / room analysis | No E1 room-analysis event is produced | Existing proctoring camera/session implementation is outside this E1 collector; do not infer media analysis from pairing events | Governed by existing P4 implementation/policy; E1 retention behavior is not established | Existing camera consent does not constitute E1 room-analysis consent |

The heartbeat still carries the E1 status JSON as operational telemetry. It contains no environmental measurement or device identifier. This inventory does not establish the server's durable storage or deletion behavior; that must be verified before E1 is enabled.

Any future data category requires an amended inventory, approved consent/policy, retention/deletion tests, and a versioned schema before implementation.
