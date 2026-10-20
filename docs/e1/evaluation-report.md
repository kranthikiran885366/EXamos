# E1 evaluation report

**Decision:** `BLOCKED_ENVIRONMENT`  
**Dataset:** Not available.  
**Host hardware smoke:** Limited Windows developer-host checks are recorded in [hardware-smoke-2026-10-12.json](../../artifacts/e1/hardware-smoke-2026-10-12.json). The Wi-Fi link was connected and a single camera frame was read then discarded; Bluetooth controller presence was checked without scanning. The ExamOS image, BLE observations, RF receiver, and second-camera analysis path were not tested.  
**Detection metrics:** Not available; no metrics are claimed.

The host smoke is not supported-target acceptance and supplies no E1 observation, correlation, or detection evidence. The isolated C test for the disabled collector is a software safety/unit test only. Neither evaluates Wi-Fi/BLE/RF observations, room-camera performance, false positives, detection rates, or supported hardware.

No `evaluation.json` or `evaluation.csv` containing invented metrics is published. An evaluation run may be reported only after an approved dataset, real declared hardware, reproducible procedure, source/configuration provenance, and actual measurements are available.
