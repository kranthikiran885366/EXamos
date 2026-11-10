# ExamOS P3 TPM Architecture

## TPM 2.0 Requirements

ExamOS P3 requires TPM 2.0. TPM 1.2 is not supported.

### Hardware (production)

- Physical TPM 2.0 chip (fTPM acceptable if manufacturer-certified)
- Accessible via `/dev/tpmrm0` (resource manager) or `/dev/tpm0`
- EK certificate from TPM manufacturer in EK certificate hierarchy
- `tpm2-tools` ≥ 4.0 installed

### Development / CI

- `swtpm` software TPM emulator
- Accessible via UNIX socket passed to QEMU as TPM TIS device
- EK derived from `EXAMOS_DEV_EK_SEED` env var
- PCR values from `EXAMOS_GOLDEN_PCR_PATH` JSON file

## PCR Bank

ExamOS uses SHA-256 PCR bank exclusively:

```bash
tpm2_pcrread sha256:0,4,7,11
```

## EK Fingerprint Derivation

### Production

The agent never creates a new Attestation Key while attesting. A production
device must have an enrolled EK and AK persisted in its TPM and the EK
fingerprint, TPM Name, and AK public-key digest bound by the signed device
registry. The default handles are `0x81010001` (EK) and `0x81010002` (AK);
provisioning refuses to replace occupied handles.

On the physical ExamOS device, as root, choose the handle and capture an
enrollment request:

```bash
sudo env EXAMOS_TPM_EK_HANDLE=0x81010001 \
  EXAMOS_TPM_AK_HANDLE=0x81010002 \
  EXAMOS_INSTITUTION_ID=institution-001 \
  EXAMOS_DEVICE_ID=device-001 \
  EXAMOS_RELEASE_ID=exam-os-release-id \
  EXAMOS_ENROLLMENT_OUTPUT=/etc/examos/enrollment-request.json \
  bash scripts/enroll-physical-tpm.sh --confirm-persist
```

This command requires an accessible physical TPM device node, reads the
manufacturer EK certificate, creates TPM-resident EK and AK objects and
persists them at the chosen handles. It never clears the TPM and never
replaces an occupied handle. The `institution_id` is carried in the pending
request and must be preserved in the resulting approved device-registry entry.
The output remains `PENDING_EXTERNAL_APPROVAL`; do not add the request directly
to the trusted registry.

### Offline operator MakeCredential / ActivateCredential ceremony

Use `scripts/physical-tpm-ceremony.py` on a controlled operator workstation.
The TPM manufacturer CA bundle and its SHA-256 pin, along with both production
registry public-key pins, must come from protected organization configuration
and be checked out-of-band. Never place production signing keys in git, on a
device, in CI, or in ordinary files.

On the operator workstation, verify the request's EK certificate and prepare a
challenge with a fresh quote nonce plus a separate verifier-state file:

```bash
python3 scripts/physical-tpm-ceremony.py make-credential \
  --request /secure/enrollment-request.json \
  --ca-bundle /secure/tpm-manufacturer-ca.pem \
  --ca-sha256 <externally-pinned-ca-sha256> \
  --challenge-out /secure/device-001.challenge.json \
  --state-out /secure/device-001.verifier-state.json
```

Transport only the challenge JSON to the intended ExamOS device. Keep verifier
state in protected operator custody; it contains the random secret and is
created with mode `0600`. On the physical Linux target, activate the challenge
as root. The command refuses software/network TPMs, and prints only the
structured response JSON (never the secret). The response contains the
activation-secret SHA-256, TPMT_PUBLIC encodings read from both persistent
handles, and a TPM quote over the fresh challenge nonce:

```bash
sudo python3 scripts/physical-tpm-ceremony.py activate-credential \
  --request /etc/examos/enrollment-request.json \
  --challenge /secure/device-001.challenge.json
```

Capture the JSON emitted on stdout as `/secure/device-001.response.json` and
return it to the operator workstation. `approve` checks the
request, pinned EK CA, challenge/state/response binding, detached signatures
of the current production device and release registries, and the externally
pinned registry public keys. It also recomputes each TPM Name from its
serialized TPMT_PUBLIC and checks the RSA modulus/exponent against the
certificate/request PEM. It derives the EK qualified Name from the endorsement
hierarchy and verifies the request AK qualified Name derives from that EK and
AK Name. The quote verifier checks TPMS_ATTEST magic/type, the challenge nonce,
qualifiedSigner, exact SHA-256 PCR selection 0/4/7/11, and the RSASSA/SHA-256
signature under the requested AK PEM. This binds successful MakeCredential
activation to the key that signed the quote; quote PCR values themselves are
not approved here and remain subject to normal P3 attestation policy. It
requires the requested release to be approved,
unrevoked, and populated with nonzero SHA-256 UKI/PCR0/PCR4/PCR7/PCR11 hashes.
It rejects duplicate device IDs and EK fingerprints. For example:

```bash
python3 scripts/physical-tpm-ceremony.py approve \
  --request /secure/enrollment-request.json \
  --ca-bundle /secure/tpm-manufacturer-ca.pem \
  --ca-sha256 <externally-pinned-ca-sha256> \
  --challenge /secure/device-001.challenge.json \
  --state /secure/device-001.verifier-state.json \
  --response /secure/device-001.response.json \
  --devices /secure/devices.json \
  --devices-signature /secure/devices.json.sig \
  --devices-public-key /secure/devices.pub \
  --devices-key-sha256 <externally-pinned-devices-key-sha256> \
  --releases /secure/releases.json \
  --releases-signature /secure/releases.json.sig \
  --releases-public-key /secure/releases.pub \
  --releases-key-sha256 <externally-pinned-releases-key-sha256> \
  --candidate-out /secure/devices.enrollment-candidate.json \
  --registration-out /secure/device-001.registration.json
```

The candidate contains an `ENROLLED` entry bound to the request's
`institution_id`, device ID, EK fingerprint, exact AK public PEM/Name and
approved release. The separate registration payload contains only
`device_id`, `institution_id`, and the exact `ak_public_key_pem` from the
request, plus `tpm_present: true` and `tpm_version: "2.0"` supported by the
TPM 2.0 enrollment operation; it asserts no secure-boot or readiness state.
Both files are written
only to new paths. Review and sign the candidate out of band using the
organization's dual-control HSM ceremony, then distribute the signed registry
and signature through the established trust-provisioning process. This CLI
never signs, overwrites, installs a production manifest, sends an HTTP
request, or accepts/stores an admin bearer token.

After signing, deploy the signed device manifest and signature through the
production trust configuration and reload/restart the P3 server using its
normal manifest-loading procedure. The signed registry entry alone does not
complete application registration. Call the existing authorized
`POST /api/v1/devices/register` path with the same `device_id`,
`institution_id`, and the exact `ak_public_key_pem` value from the approved
registry entry (`ak_public_pem` in the registry). Production rejects any
mismatch. Use the generated registration JSON as the request body through the
normal authenticated admin session; never add a bearer token to ceremony
files or command arguments. Complete the endpoint's approval step if active
policy requires it. Then allow the device to complete its normal server
nonce/quote flow. Fresh institution readiness evidence is persisted only
after registration, approved status, and a match to exactly one active policy;
do not treat enrollment or manifest deployment alone as readiness evidence.

For a read-only check that the physical TPM can sign and verify a fresh quote
with the persistent AK, run `sudo bash tests/p3/hardware-tpm-preflight.sh`.
This is hardware quote evidence, not a server attestation or release
certification.

### Development

```
EXAMOS_DEV_EK_SEED=<ephemeral-test-seed>
ek_fingerprint = SHA256("EXAMOS-DEV-EK-" + seed)
```

An explicit seed is mandatory for software-only development mode; it never
defaults to a device ID.

## AK (Attestation Key) Derivation

### Production

The enrollment request records the actual TPM-generated Name and the SHA-256
digest of the public key exported from the persistent AK. The TPM Name hashes
the TPM public area, not OpenSSL SubjectPublicKeyInfo DER; both values are
bound independently by the signed registry.

### Development

```
ak_pub_hex = SHA256("EXAMOS-DEV-AK-" + ek_seed + ek_fingerprint)
```

## Quote Signature Verification

The native P3 path verifies the TPM-generated `TPMS_ATTEST` signature using
the enrolled AK public key and checks nonce, PCR selection, and quoted PCR
digest. `EXAMOS_AK_QUOTE_SUFFIX` is not used for native authorization and
must not be provisioned as a production credential. The Go verifier is a
deprecated development-only prototype; its legacy shared-suffix digest is
not cryptographic TPM quote verification and cannot authorize a device.

The repository device registry is empty. Software-TPM test credentials and
registries are generated in temporary storage per run, and do not establish
production device enrollment.

## TCG Event Log

The agent reads the binary TCG event log from:

```
/sys/kernel/security/tpm0/binary_bios_measurements
/sys/kernel/security/tpm/binary_bios_measurements
```

SHA-256 of the entire log file is sent as `event_log_hash`. In production, a
missing or empty log fails attestation. Hashing only authenticates the bytes
that were reported; it does not replay events into PCRs or prove that the
event log explains the quoted PCR values. Server-side replay remains a
production blocker.

In development, if the event log is unavailable, a deterministic synthetic hash keyed to the release ID is used (clearly logged as WARNING).

## swtpm Setup (Development)

```bash
# Create a disposable swtpm state directory
mkdir -p /tmp/examos-p3-tpm

# Initialise
swtpm_setup --tpm2 --tpmstate /tmp/examos-p3-tpm --create-ek-cert --create-platform-cert

# Start
swtpm socket \
    --tpm2 \
    --tpmstate dir=/tmp/examos-p3-tpm \
    --ctrl type=unixio,path=/tmp/examos-p3-tpm/swtpm-sock \
    --log level=20 \
    --daemon

# Attach to QEMU
# -chardev socket,id=chrtpm,path=/tmp/examos-p3-tpm/swtpm-sock
# -tpmdev emulator,id=tpm0,chardev=chrtpm
# -device tpm-tis,tpmdev=tpm0
```
