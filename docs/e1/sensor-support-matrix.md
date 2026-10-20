# E1 sensor support matrix

No E1 sensor is currently qualified on real hardware. The CI/WSL environment is not a substitute for the supported ExamOS target-device matrix.

| Manufacturer/model | OS image version | Wi-Fi chipset/driver | Bluetooth chipset/driver | Optional RF receiver | Second-camera capability | Known restrictions | Tests run | Result |
|---|---|---|---|---|---|---|---|---|
| No declared hardware record | Not established for E1 | Not measured | Not measured | None declared | Media/analysis not validated for E1 | P0 ISO boot fails; E1 collection disabled | Isolated disabled-state C test only | `BLOCKED_ENVIRONMENT` |
| Developer workstation (host-only smoke; not approved release hardware) | Windows 11 10.0.26200; ExamOS image not booted | Intel Wireless-AC 9462, driver 24.40.0.4; link connected at 433.3 Mbps | Intel Bluetooth controller present, driver 24.40.0.3; service running; BLE scan not run | Not declared or tested | One integrated-camera frame read at 640x480; second-camera path not tested | WSL exposes no camera, rfkill, or USB device path; E1 radio collection remains disabled | Wi-Fi link smoke PASS; Bluetooth controller presence only; one-frame camera smoke PASS; RF NOT_RUN | `NOT_QUALIFIED` |

The host-only measurements are recorded in [hardware-smoke-2026-10-12.json](../../artifacts/e1/hardware-smoke-2026-10-12.json). They prove limited host device/link capability only; they do not qualify any ExamOS sensor or device. Do not add a supported-device row until the exact ExamOS image, target hardware/driver versions, approved test procedure, and relevant sensor tests are validated. Never infer support from a visible adapter or a synthetic fixture.
