# ExamOS E1 — Threat model

**Status:** Design scope; production implementation is blocked.  
**Current collection state:** Disabled / not collected.  
**Decision boundary:** E1 observations, if later authorized and validated, are evidence for human review, not a misconduct decision.

## Intended scope

E1 may eventually consume explicitly authorized, supported, privacy-reviewed observations from Wi-Fi/BLE radios, an optional passive RF energy sensor, and normalized room-context events from a validated second-camera analysis path. The current repository does not establish these capabilities as production-ready. The client collector is disabled until policy and consent integration exist.

## Risks E1 may provide limited evidence about

- A signal observation changed during an authorized collection window.
- An approved sensor or data feed became unavailable, stale, or degraded.
- Independently sourced, quality-qualified observations overlapped in time under a versioned and reproducible rule.
- The second-camera media or analysis pipeline reported a measured quality or availability change, if that pipeline is separately validated.

Such a result does not identify the candidate as the device owner, establish intent, prove device type, or establish that an observation is related to an exam rule.

## Risks E1 cannot prove by itself

- A nearby transmitter belongs to the candidate or is being used for assistance.
- A device is absent because a scan returned no observations.
- A signal's RSSI gives reliable distance or location.
- A randomized Wi-Fi/BLE identifier refers to the same physical device over time.
- Every protocol, powered-off/passive/shielded device, or receiver is observable.
- A camera model has correctly identified a prohibited object in every lighting, occlusion, or camera-placement condition.
- A temporal overlap is causal or suspicious.

Shared rooms, adjacent apartments, accessibility peripherals, dense RF environments, identifier randomization, driver limits, and sensor failure can all produce incomplete or benign observations.

## Threats to the E1 pipeline

| Threat | Required control | Current status |
|---|---|---|
| Collection begins without valid session consent | Session-bound, per-source consent and policy gate before sensor start | Not implemented; current E1 collector is disabled |
| Active or invasive radio operation | Prohibit probing, pairing, deauthentication, injection, payload capture, and connection attempts | Previous `iw scan` path removed from the collector; no sensor acceptance claim |
| Fabricated or stale data is treated as real | Preserve source/receive time, state, freshness, provenance, and fixture labeling | Not implemented for observations |
| Cross-session disclosure or unauthorized reviewer access | Existing auth/RBAC/session and tenant checks with executable tests | No E1 API is integrated |
| Event alteration, loss, or duplicate delivery | One approved P4 chain, idempotency, verification and persistence-failure reporting | E1 worktree module uses a separate legacy ledger path; P4 is not release-valid |
| Sensor failure is interpreted as misconduct | Emit health/data-quality state; do not raise risk from missing data | No production E1 risk integration |
| Correlation overstates evidence | Versioned deterministic rule, source-event links, missing-input explanation, human review | Existing unlinked correlation code is not accepted |
| Excessive or retained bystander data | Minimize identifiers and payloads; access control and verified deletion | No E1 retention test or approved collection policy |

## Mandatory operating constraints

- Collection is off unless an authorized session, explicit source-specific consent, and validated policy all permit it.
- No packet or communication payload collection; no active interference or interaction with observed devices.
- Do not persist stable bystander identifiers or use them for cross-exam tracking.
- Do not claim universal radio or camera coverage.
- Sensor, policy, network, or persistence failures are system-health conditions, never misconduct evidence by themselves.
- Consequential decisions remain with an authorized human reviewer and must have an appeal path.
