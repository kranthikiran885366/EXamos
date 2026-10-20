# External acceptance — independent assessment

P0 scripts cannot close organizational risk acceptance. Production use
requires a signed assessment from named owners, stored outside the image.

## Required sign-offs

| Role | Decision | Artifact |
|---|---|---|
| Security owner | Threat model residual risk accepted or rejected | Signed assessment |
| Operations owner | Incident, update, and support process exists | Operational readiness record |
| Independent assessor | Review of evidence pack (not the build engineer) | Assessment with scope and limitations |

## Minimum assessment contents

- Scope: P0 virtual boot vs production hardware vs live examinations
- Evidence reviewed (commit, ISO digest, VMware/QEMU reports, TPM quotes)
- Explicit statement that software-TPM and QEMU results are not hardware proof
- Open BLOCKED items (VMware, physical TPM, Secure Boot custody, models)
- Approval or rejection for a named environment only

## How to supply evidence

Set `EXAMOS_INDEPENDENT_ASSESSMENT_PATH` to a UTF-8 document that contains:

```
ASSESSMENT_STATUS=APPROVED|REJECTED
ASSESSOR_NAME=...
ASSESSOR_ROLE=independent
SCOPE=...
SOURCE_COMMIT=<40-hex>
ISO_SHA256=<64-hex or NOT_APPLICABLE>
```

`tests/production/external-acceptance-gate.sh` treats missing, unsigned, or
self-approved files as BLOCKED. This repository does not generate a fake
approval.
