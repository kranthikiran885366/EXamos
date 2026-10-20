# E1 correlation rules status

**Status:** No production correlation rule is approved.

The existing unlinked `server/environment/environment_engine.c` pairs any BLE and second-camera entries in the same session whose integer timestamp difference is within the caller-supplied `window_ms`. The code does not verify event semantics, source quality, freshness, consent at correlation time, or source event-chain IDs. The stored integer timestamps are seconds in the current struct while the argument is named milliseconds, making the window comparison unit-inconsistent. Its rule output must not be used as evidence.

Future rules must be deterministic and versioned, link exact verified source events/hashes, record measured time tolerance, quality and missing inputs, explain the observation without inferring intent, and be reproducible from source events. Sensor failure or missing data must not increase candidate risk.

The current implementation is not called an E1 production integration and produces no accepted E1 correlation.
