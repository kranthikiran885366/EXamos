# Runbook: P3 Attestation Failure

## Purpose

This runbook covers investigation and resolution of attestation failures during exam operations.

---

## Failure Codes and Responses

### `P3_UNKNOWN_DEVICE`

**Meaning**: The device ID or EK fingerprint is not in the enrolled device registry.

**Causes**:
- Machine was not enrolled before the exam session
- Machine was re-imaged and EK fingerprint changed
- Rogue machine attempting admission (unregistered software TPM)
- Agent sending wrong `EXAMOS_DEVICE_ID`

**Response**:
1. Check `EXAMOS_DEVICE_ID` env var on the failing machine
2. Verify device is in `server/config/devices.json` or the production registry
3. Check the EK fingerprint matches: `tpm2_createek --ek-context ek.ctx --key-algorithm rsa --public ek.pub && sha256sum ek.pub`
4. If legitimate machine: enroll via `POST /api/v1/admin/device/register`
5. If unknown machine: block and investigate

---

### `P3_PCR_MISMATCH`

**Meaning**: One or more PCR values do not match the golden measurements for the enrolled release.

**Causes**:
- PCR 0: BIOS firmware was updated or replaced
- PCR 4: Kernel, initrd, or boot command line was modified; UKI was re-signed
- PCR 7: Secure Boot was disabled; new certificate was enrolled; db was modified
- PCR 11: Root filesystem was modified (dm-verity roothash changed)

**Response**:
1. Retrieve actual PCR values from the failing machine: `tpm2_pcrread sha256:0,4,7,11`
2. Compare against golden values in `artifacts/p3/golden-pcr.json`
3. Identify which PCR(s) differ
4. Determine cause:
   - PCR 0 diff: BIOS update? Investigate firmware integrity
   - PCR 4 diff: Was UKI re-built? Is this the correct image version?
   - PCR 7 diff: Was Secure Boot disabled or keys changed?
   - PCR 11 diff: Was the rootfs modified after build?
5. If legitimate new image: generate new golden PCRs, register new release
6. If tampering: quarantine machine, file security incident

---

### `P3_NONCE_REPLAY`

**Meaning**: The submitted nonce was already consumed by a previous attestation.

**Causes**:
- Replay attack: attacker captured a valid attestation transcript and is resubmitting it
- Agent bug: agent resubmitted evidence instead of requesting a fresh nonce
- Race condition: two agent instances running for the same device

**Response**:
1. Check if there are multiple agent instances: `pgrep -f examos-agent`
2. Check the server ledger for `P3_ATTESTATION_VERIFIED` events for this device
3. If replay attack: block the source IP, investigate network capture
4. If agent bug: restart agent, check `EXAMOS_REATTEST_INTERVAL` config

---

### `P3_REVOKED_DEVICE`

**Meaning**: The device was revoked by an administrator.

**Causes**:
- Device was revoked due to security incident
- Device was revoked by accident
- Machine was decommissioned

**Response**:
1. Check the ledger for `P3_DEVICE_REVOKED` event to find when/why
2. If revocation was correct: do not re-enroll; machine cannot participate
3. If revocation was accidental: re-enroll via `POST /api/v1/admin/device/register`

---

### `P3_REVOKED_RELEASE`

**Meaning**: The ExamOS release the machine is running was revoked.

**Causes**:
- Security vulnerability found in the release
- Release was retired after a new version was deployed
- Accidental revocation

**Response**:
1. Determine the release ID from the agent logs or ledger
2. Check the ledger for `P3_RELEASE_REVOKED` event
3. If legitimate revocation: all machines must be re-imaged with the approved release
4. If accidental: there is no un-revoke API; restart the server to reload config from `releases.json` (which still has `revoked: false`)

---

### `P3_INVALID_SIGNATURE`

**Meaning**: The quote signature does not match the expected value.

**Causes**:
- The deprecated Go development verifier is misconfigured (it is not part of production authorization)
- PCR values were tampered with in transit
- Agent is running a different quote formula version

**Response**:
1. Confirm the native server validated the TPM quote signature, nonce, PCR selection, and enrolled AK identity
2. Check agent version matches server version
3. Check for network-level tampering (MITM)
4. Review recent deployments — was the suffix rotated?

---

### `P3_SESSION_BINDING_FAIL`

**Meaning**: The device ID in the evidence does not match the device ID the session nonce was issued to.

**Causes**:
- Session hijacking: evidence from machine A is being used for machine B's session
- Agent using wrong `EXAMOS_DEVICE_ID`

**Response**:
1. Check `EXAMOS_DEVICE_ID` on both machines
2. Check which device requested the nonce (from server ledger)
3. If hijacking attempt: block both devices, investigate

---

## General Diagnostic Steps

```bash
# Check server logs for P3 events
grep "P3_" /tmp/examos_event_ledger.log

# Check agent connectivity
curl -sf http://<server>:8000/api/v1/health

# Verify server config loaded correctly
grep "AttestConfig" /var/log/examos/server.log

# Check PCRs on suspect machine
tpm2_pcrread sha256:0,4,7,11

# Run Go verifier against captured evidence
EXAMOS_GOLDEN_PCR_PATH=artifacts/p3/golden-pcr.json \
    server/attestation/examos-verifier --file evidence.json
```

## Escalation

If attestation failures affect more than 5% of exam machines at a venue, escalate to the ExamOS security team immediately with:

- Machine IDs
- Failure codes
- Server ledger excerpt
- PCR values from affected machines
- Network topology diagram
