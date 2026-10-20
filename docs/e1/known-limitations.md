# E1 known limitations and blockers

- E1 production integration is blocked by the P0–P6 evidence status and by the frozen-architecture/repository mismatch; see [pre-change-audit.md](./pre-change-audit.md).
- No ExamOS target Wi-Fi/BLE, optional RF, or E1 room-analysis hardware has been qualified. A limited Windows host smoke checked Wi-Fi link state, Bluetooth-controller presence, and one camera frame; it did not exercise E1 radio collection or qualify ExamOS hardware.
- E1 source-scope preference recording is implemented and tested through the live HTTP listener with ephemeral development credentials. No approved disclosure lifecycle, signed production policy, sensor-start/revocation enforcement, production authorization/tenant-isolation, retention, or deletion test is implemented.
- The current candidate consent record covers camera/microphone only; E1 preferences are a separate event and do not activate collection.
- The second-camera pairing implementation does not establish a validated WebRTC/SFU media path or room-analysis result.
- The legacy in-memory environment correlation engine is not linked into the server and is not a production API. The separate consent-preference module is linked, but is not an observation or correlation pipeline.
- No approved sensor dataset exists; no detection, precision, recall, false-positive, or overhead metrics are available.
- Wi-Fi/BLE observations, when eventually authorized, cannot establish device ownership, exact distance, intent, or absence of an unobservable device. RSSI is not a distance measurement; identifiers may randomize; shared-room interference is expected.
- Sensor failure or missing data must remain a health/quality state and must never increase misconduct risk by itself.
- This increment disables the unsafe collector; it does not implement a replacement hardware sensor pipeline.
