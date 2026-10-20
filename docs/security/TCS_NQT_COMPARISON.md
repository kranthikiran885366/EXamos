# ExamOS and TCS iON NQT: evidence-based comparison

**Reviewed:** 2026-10-11
**Scope:** Publicly available TCS iON NQT product information versus the
current ExamOS repository and its recorded evidence.

## Important scope distinction

TCS iON NQT is publicly presented as an assessment and job-readiness product,
not as a standalone operating system. The public TCS iON NQT page describes
assessment-related skills and job-listing opportunities, but does not publish
an operating-system image, kernel policy, secure-boot design, TPM protocol,
browser lockdown implementation, API architecture, or full security
certification package.

Accordingly, this is **not** a technical equivalence or vendor security
certification comparison. TCS's internal delivery controls, deployment
architecture and any exam-client software are unknown from the public sources
reviewed here. Absence of public technical detail is not evidence that TCS has
no such controls.

## Comparison

| Dimension | TCS iON NQT — public evidence only | ExamOS — repository evidence | Gap / interpretation |
|---|---|---|---|
| Product category | Public TCS iON NQT page presents an assessment/career platform and discusses assessment experience and job opportunities. | ExamOS is a Linux examination-appliance prototype with a native C/C++ server, kiosk, security agent and proctoring components. | These are different layers: assessment service versus candidate device OS/appliance. A like-for-like OS comparison is not possible. |
| Candidate device and OS | No authoritative OS, supported-device matrix or endpoint build specification was found in the cited public NQT page. | Debian Trixie/mkosi image, systemd-boot, Cage/Wayland and Chromium are configured in-tree. | ExamOS must publish a supported hardware/firmware matrix and complete real-device acceptance tests. Do not assume TCS uses or does not use a particular OS. |
| Kiosk and escape resistance | No implementation-level lockdown or bypass test evidence was present in the cited public material. | Chromium managed policies, kiosk services, firewall and hardening configuration exist. P1 is FAIL; P2's 20 mandatory tests are NOT_RUN. | ExamOS has configuration, not demonstrated enforcement. Need successful guest/hardware escape, reboot, alternate-console, URL, USB and network negative tests. |
| Secure/measured boot and device trust | No public technical description of a TCS NQT TPM/Secure Boot attestation protocol was found in the source reviewed. | C code includes TPM quote parsing and signature verification. The aggregate P3 result is INVALIDATED; a separate 18/18 swtpm suite artifact is from a DIRTY tree. Physical TPM, production registry and release-gate evidence remain absent. | ExamOS must prove genuine hardware trust and signed production provisioning; no claim of parity is justified. |
| Network and API security | Public product page does not document NQT network transport or service authentication. | ExamOS server uses plaintext HTTP and now refuses all non-loopback binds; the former `EXAMOS_TLS_TERMINATED=1` bypass is removed. | A complete, tested TLS/mTLS deployment and service identity design is still required before remote use. TCS's actual design cannot be inferred. |
| Proctoring and monitoring | The cited public NQT material is not a technical model/proctoring specification and provides no model accuracy, false-positive, retention or appeal data. | OpenCV model code is optional and not enabled/linked or packaged in the current proctor image. Prior P4 detection metrics are invalidated; P4 is not release eligible. | Build a reproducible, licensed model pipeline; independently evaluate on representative labelled data; validate privacy, bias, false positives, human review and appeals. |
| Assessment workflow and evidence | Public material describes the NQT assessment/career opportunity at product level; backend implementation and evidence format are not disclosed there. | ExamOS has native C exam/session services, candidate behavior checks, file-backed evidence chains and P5 features. P5-A–E have recorded passes, while P5-F–H and P5-I are blocked. | P5 requires provider completion and broader evidence; synthetic feature tests do not establish production assessment validity or fraud-detection accuracy. |
| Scale, resilience and service operations | No measured service SLO, capacity result, disaster-recovery or operational architecture is established by the cited NQT page. | A P4 50-session concurrency artifact exists, but P4 is invalidated and P0–P3 regression failed. The C server creates detached threads per accepted connection and has no visible bounded worker pool at that accept path. | Need load/soak/failure testing, bounded resource controls, tested backups/restore, incident response and support procedures. |
| Privacy, accessibility and governance | The cited public page is insufficient to compare technical data handling, retention, accessibility, appeals or certifications. | ExamOS has consent and reviewer-related code, but production privacy, retention, model fairness, legal review and pilot evidence are not established by current phase artifacts. | Provide explicit candidate disclosures, minimum-data collection, retention/deletion, accessibility, fairness evaluation, independent human review and an appeal process. |
| Release evidence | Public product information is not an independent certification report for TCS's internal controls. | P0 is partial; P1 fails; P2 is not run; P3 aggregate is invalidated; P4 is invalidated; P5/P6 are blocked. | There is no substantiated basis to claim ExamOS is production-ready or equivalent to TCS iON NQT. Compare against a dated, authorized technical specification and evidence set, not marketing claims. |

## Practical gap assessment

### Where ExamOS has tangible implementation

- A bootable Debian-based image and a QEMU serial-boot record.
- Static kiosk, managed Chromium, network lockdown and systemd hardening
  configuration.
- Native C attestation and key-release paths, including TPMS_ATTEST parsing
  and AK signature verification in source.
- File-backed ledger/session mechanisms and hash-chain verification code.
- Candidate workflow, behavior baseline, variant, viva and reviewer code.

These are implementation facts, not proof of enforced security, service
availability, detection quality or production suitability.

### Highest-priority gaps before any honest product comparison

1. Fix the agent-authenticated shell-injection path documented in
   [the end-to-end audit](END_TO_END_AUDIT.md).
2. Complete P0–P2 on clean, commit-bound artifacts and supported physical
   devices.
3. Complete physical-TPM P3 release evidence, production registry/key
   ceremony, and actual event-log validation.
4. Enable and package the P4 model stack; replace invalid metrics with
   independently labelled, representative evaluation results.
5. Complete P5 provider/review/privacy gates and P0–P4 regression.
6. Establish production TLS, durable storage, operational recovery, privacy,
   fairness/accessibility, support and independent review.
7. Publish ExamOS's intended candidate deployment and security claims with
   evidence, limitations, device compatibility, data lifecycle and incident
   procedures.

## Evidence needed for a fair vendor-level comparison

Obtain an authorized, current TCS iON NQT technical pack or candidate
requirements that identifies:

- Supported operating systems/devices and any required secure examination
  client.
- Candidate data, camera/microphone capture, proctoring and retention.
- Transport and authentication properties, secure boot/device-trust claims,
  and relevant independent assessment or certification.
- Accessibility, exception handling, human review and appeal processes.
- Availability/support commitments and test-day recovery procedures.

Then compare the exact TCS service and ExamOS release version against the same
threat model and test cases. Until those materials are available, mark each
TCS implementation detail **UNKNOWN**, not PASS or FAIL.

## Sources and limitations

1. [Official TCS iON NQT page](https://www.tcsion.com/hub/national-qualifier-test/) — accessed 2026-10-11. Public product/candidate-facing page; it does not provide the low-level operating-system or control details listed above.
2. ExamOS source and recorded evidence linked in [the end-to-end production-readiness audit](END_TO_END_AUDIT.md), including P0–P6 gate artifacts. Repository evidence is dirty, mixed-validity and not independent certification.
