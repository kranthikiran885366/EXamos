# ExamOS production roadmap and deployment plan

**Decision: NOT PRODUCTION READY.** This plan reflects the evidence recorded in
`docs/security/END_TO_END_AUDIT.md`, `docs/security/RELEASE_READINESS.md`, and
the phase artifacts. A source file, CI workflow, synthetic fixture, or passing
software-TPM test is not a production acceptance result.

## User goal and delivery window

The requested outcome is an examination OS and its applications that are
production-grade, free of mocks/duplicate implementations/baked-in deployment
values, and usable in WSL as well as on supported devices installed directly.
Treat five hours as an initial engineering window for planning, gap closure, and
reproducible validation. It is not enough to certify the whole system: physical
device access, production keys and trust roots, consented evaluation data,
independent review, and a pilot require external owners and elapsed time.

â€œNo fixed valuesâ€ means no embedded secrets, credentials, production URLs,
deployment identity, trust roots, PCR baselines, model paths, or policy choices.
It cannot mean no configuration: those values must be supplied as validated,
versioned deployment inputs. Missing or invalid required inputs must block
release and fail closed. Protocol constants and documented safe resource limits
remain explicit code/schema contracts.

â€œNo mocksâ€ applies to production execution and production claims. Unit and
integration tests may use isolated fakes/fixtures when labeled as such; they
must never be reported as device, model-quality, or release evidence. Remove
duplicate implementations only after tracing call sites, compatibility
contracts, and the canonical owner for each capability.

## Current verified state

| Area | Recorded state | Release consequence |
|---|---|---|
| P0 image and boot | Current disk/ISO evidence is stale or failed; worktree is dirty | Rebuild and bind all evidence to an immutable clean source revision |
| P1 kiosk/network | `artifacts/p1/results.json` is FAIL | No live exam use |
| P2 lockdown | Mandatory runtime tests are NOT_RUN | Static configuration is not enforcement evidence |
| P3 trust/key release | Aggregate is INVALIDATED; software TPM evidence is development-only | No physical device trust or production key release |
| P4 proctoring | Prior quality result is INVALIDATED; model/data governance is BLOCKED | No detection-quality or fairness claims |
| P5 workflows | Overall BLOCKED; provider/review prerequisites remain | No production viva or automated risk decisions |
| P6 operations | Physical matrix, red team, pilot, key ceremony, architecture decision missing | No enterprise release |
| Open hardware snapshot | `artifacts/production/hardware-trust.json` is BLOCKED | Do not enroll or authorize this host based on this snapshot |

This table is a starting snapshot, not a substitute for rerunning gates against
the exact source and image being considered.

## Supported execution targets

### WSL development target

WSL is a developer/build/test environment. Build and static checks should work
from a clean WSL Linux filesystem checkout; QEMU/OVMF and software TPM are
development integration environments. Host hardware passthrough is
capability-dependent. A WSL run must label absent or virtualized Secure Boot,
TPM, firmware event log, camera, USB enforcement, and dm-verity evidence as
unavailable or virtual. It must never silently promote those results to
physical hardware acceptance.

### Directly installed device target

The appliance target is a declared, qualified Linux x86-64 UEFI device model
and firmware configuration. Installation is from verified, signed external
media after the disposable VM gates pass. The installer must enumerate the
selected target by stable identity (model, serial, capacity, bus), reject the
system disk and ambiguous devices, show the exact planned operation, and
preserve rollback/recovery procedures. Do not modify internal disks, EFI,
BitLocker, TPM state, Secure Boot keys, or persistent boot order without the
specific approved test procedure and explicit device-scoped approval.

WSL compatibility is not evidence that direct installation works. Device
support is a matrix of tested model, firmware, TPM/EK chain, network, camera,
audio, storage, and peripherals, each tied to an image digest and gate report.

## Five-hour engineering plan

Use the first five engineering hours as a time-boxed remediation sprint. Stop
at the time boundary and report remaining blockers plainly.

| Elapsed | Work | Required output |
|---|---|---|
| 0:00â€“0:30 | Freeze baseline without cleaning the dirty tree; inventory phase artifacts, tool availability, and duplicate entry points | Scoped issue list and preserved baseline hashes/status |
| 0:30â€“1:15 | Reconcile architecture and target contracts; identify WSL-only versus physical checks; audit hardcoded deployment inputs | Canonical component map, config ownership/schema, target matrix |
| 1:15â€“3:15 | Fix one complete, high-priority vertical slice selected from reproducible build/boot, configuration validation, or trust-gate correctness | Reviewed source change with no fake success path |
| 3:15â€“4:15 | Run only relevant, safe checks; build/test output bound to current source state; inspect failures | Logs/results retained without overwriting historical evidence |
| 4:15â€“5:00 | Update deployment/runbook and issue register; state gate and external prerequisites | Reviewable diff and prioritized next sprint |

If dependencies or the host environment prevent a task, use the remaining
window on an independent source audit or documentation/gate correction; never
manufacture a PASS or overwrite evidence to imply completion.

## Release workstreams and exit gates

| Order | Workstream | Concrete exit criteria | Evidence owner |
|---|---|---|---|
| 0 | Scope and architecture | Product owner confirms native-C architecture and supported protocols; one canonical implementation per service; component/API/data ownership map | Product and architecture owners |
| 1 | Build and supply chain | Clean immutable checkout; pinned reviewed dependencies; reproducible build; SBOM; signed provenance; image/UKI/root hashes; rollback-tested release | Build/release engineering |
| 2 | Boot and kiosk (P0/P1) | Current image boots in QEMU/OVMF and disposable VMware; positive/negative boot tests; kiosk reaches configured exam origin with no shell escape; evidence bound to source/image digests | OS engineering |
| 3 | OS enforcement (P2) | Live guest tests prove firewall allow/deny, USB authorization, AppArmor, module lockdown, read-only integrity and corruption rejection, fail-closed recovery | OS/security engineering |
| 4 | Device trust (P3) | Organization-controlled signed registries and key ceremony; manufacturer EK validation; physical TPM credential activation and quote; TCG event-log replay bound to quote/PCRs; replay/revocation/PCR-negative tests | Hardware security/key custodians |
| 5 | Transport and services | Authenticated TLS/mTLS for every remote hop; managed certificate rotation; authorization/rate limits; transactional persistence; backup/restore and crash/power-loss recovery | Service/platform engineering |
| 6 | Proctoring governance (P4) | Pinned/licensed models with hashes; consented representative independently labeled data; documented retention/deletion, subgroup error bounds and human escalation; real-device load/adversarial tests | ML/privacy/assessment owners |
| 7 | Assessment workflow (P5) | Production provider contract and outage behavior; answer integrity/idempotence; human review and appeal; access control, audit and privacy review; validated fairness/false-flag behavior | Assessment/product owners |
| 8 | Enterprise operations (P6) | Three or more distinct qualified device models; authorized red team and remediated retest; volunteer pilot and rollback; support, monitoring, incident response, patch/rollback, SLO and DR drills | Operations and independent approver |

Every gate accepts only PASS bound to the same clean source revision, build
inputs, image digest, target profile, and evidence package. BLOCKED, NOT_RUN,
FAIL, INVALIDATED, stale, dirty-tree, synthetic, and software-TPM results are
not PASS. Gate schemas must keep these states distinct.

## Deployment inputs and configuration contract

Each deployment release must provide a signed, schema-validated configuration
bundle for its environment. At minimum it owns the exam origin and allowed
origins, server endpoints, trust roots and signing identities, device/release
registries, PCR policy, firewall destinations, identity/credential provider,
certificate lifecycle, storage/retention policy, model inventory and policy,
and supported hardware profile. Secret material is delivered through the
approved secret/key-custody channel and is never stored in source, image
defaults, test artifacts, or ordinary configuration files.

Configuration validation must reject unknown/duplicate keys, unsafe wildcard
origins, insecure transport, expired or unsigned trust material, weak secrets,
unapproved model hashes/licences, and missing mandatory values. Report the
source and version of each non-secret value without printing secrets. Development
profiles must be visibly non-production and technically unable to release real
exam keys.

## Safe release sequence

1. Resolve architecture scope and supported-device profiles.
2. Build from a clean, immutable, reviewed revision and generate provenance,
   SBOM, hashes, and signed artifacts in controlled CI.
3. Run P0/P1 and P2 positive and negative gates in disposable virtual targets;
   keep software TPM results clearly labeled development-only.
4. Complete production key/trust ceremony and the physical TPM/firmware gates
   on specifically authorized, non-destructive devices.
5. Pass TLS, persistence, privacy/model governance, P4/P5, red-team, and pilot
   exit criteria.
6. Independently review the release evidence package; sign, publish, monitor,
   and retain a tested rollback path.

Do not flash or install on this workstation as part of the WSL sprint. The
current physical-device plan explicitly prohibits internal-disk and firmware
writes and requires separately approved external media operations.

## Open decisions and external dependencies

- Confirm native-C architecture as the product direction; the P6 report names
  a different Node/Mongo/Redis/Python/SFU/Docker architecture that is not
  present in this repository. Do not silently replace either architecture.
- Identify production owners for signing keys, device enrollment, TLS identity,
  personal data, retention, and model/data approval.
- Provide consented labeled data and a production inference-provider contract.
- Qualify the physical device matrix and obtain authorized security review,
  pilot participants, and rollback approval.

These require organizational decisions, external resources, and elapsed time;
source edits alone cannot complete them within a five-hour coding window.

## Sprint execution record — 2026-10-16

The current Windows host exposes an Ubuntu 26.04 WSL distribution with GNU
make, GCC/G++, and QEMU available. A full native application build completed
from the mounted worktree with outputs directed to `/tmp`; the security agent
also built independently with its strict warning flags. This verifies native
compilation in WSL only. No guest boot, direct installation, firmware write,
or physical-device acceptance was performed.

One configuration defect was corrected in the agent heartbeat path: it no
longer has a loopback server URL or placeholder device identity fallback.
Initialization now requires explicit `EXAMOS_TPM_MODE`, server URL, and device
identity; production mode accepts HTTPS only, while HTTP remains available to
explicit development mode. The URL parser rejects unsupported schemes,
embedded user information, query strings, and fragments. The endpoint length
limit is 2048 bytes and the device identity limit is 64 bytes. URL construction
now detects truncation, and libcurl global lifecycle remains with the process
owner rather than being initialized again by the heartbeat subsystem.

Focused heartbeat configuration regression tests passed in WSL, covering
missing/invalid mode and inputs, URL and identity limits, disallowed URL
components, development HTTP, and production HTTPS enforcement. These tests
run with `make -C agent test-heartbeat-config`; they and compilation do not
change any phase gate to PASS and are not device or release evidence. The
repository was already dirty before this sprint; no pre-existing changes or
recorded artifacts were cleaned or overwritten.

**Delivery status remains BLOCKED — NOT APPROVED FOR LIVE EXAMINATIONS.** The
reported build does not address failed/stale P0/P1 evidence, unrun P2 runtime
enforcement tests, invalidated P3/P4 evidence, blocked P5/P6 work, production
key custody, real model/data governance, independent review, or the qualified
physical-device matrix. Direct installation and certification remain outside
the verified work completed here.
