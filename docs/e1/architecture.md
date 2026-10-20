# E1 architecture status

**Status:** Production integration blocked.

The E1 target flow is: authenticated exam session and source-specific consent → validated policy → supported sensor supervisor → normalized, quality-bearing event → the existing authoritative P4 event chain → existing review flow.

The repository does not currently implement that integrated flow:

- `agent/main.c` sends heartbeat telemetry; the RF collector now reports only `DISABLED_BY_POLICY` / `NOT_COLLECTED`.
- `server/main.c` has candidate consent for camera/microphone and now accepts a separate authenticated E1 source-scope preference route. It records that preference on the existing per-session chain; collection remains disabled.
- `server/environment/environment_engine.c` exists in the dirty worktree but is not linked by `server/Makefile` or routed through `server/main.c`.
- The separate, unlinked observation/correlation E1 module uses process-local fixed arrays and a legacy ledger call; it is not a durable, authenticated observation API. The consent route does not depend on it.
- The repository has two event-related APIs. E1 must use the P4-approved canonical interface, not create or assume a second chain.
- The inspected second-camera pairing state is not proof of a live validated WebRTC/SFU stream or a room-analysis result.
- The supplied frozen architecture requires Node.js, MongoDB, Redis streams, Python analysis workers, WebRTC/SFU and Docker. The repository/P6 prerequisite audit identifies that stack as absent. This work does not replace the native C/C++ platform or create a parallel stack.

Before integration, reconcile the architecture contract with the actual repository and validate P0–P6 prerequisites. Until then, E1 remains disabled; isolated tests do not imply sensor capability.
