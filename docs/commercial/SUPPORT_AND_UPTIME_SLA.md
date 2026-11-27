# SPPIO / ExamOS — Support & Uptime Service Level Agreement (SLA)

## 1. Service Availability Target
- **Control Plane (`sppio-core` API & Console)**: **99.9%** monthly uptime during scheduled examination windows.
- **Offline Resilience**: Workstations buffer signed telemetry in encrypted local WAL storage (`offline-events.wal`) during lab Wi-Fi interruptions so active exams continue uninterrupted and auto-sync on reconnect.

## 2. Incident Response & Support Tiers
| Severity | Definition | Initial Response | Target Mitigation |
|----------|-----------|------------------|-------------------|
| **P1 — Critical** | Active exam window blocked across >=10% of stations or control-plane outage | **15 minutes** | **2 hours** |
| **P2 — High** | Single-station attestation/hardware block or degraded proctoring feed | **1 hour** | **4 hours** |
| **P3 — Normal** | Non-blocking console UI issue, report export, or onboarding question | **1 business day** | **3 business days** |

## 3. Staged Updates & Rollback
- OS/kernel updates follow staged canary rings (**5% -> 25% -> 100%**).
- Automatic A/B partition rollback restores the prior signed slot if post-boot P2 health checks fail.

## 4. Remote Diagnostics
- Stations generate PII-free signed diagnostic bundles via `examos-diag-bundle.sh` for rapid hardware/driver triage without requiring on-site lab visits.
