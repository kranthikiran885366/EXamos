#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${1:-}" != "--confirm-persist" || $# -ne 1 ]]; then
    echo "Usage: EXAMOS_TPM_EK_HANDLE=0x81010001 EXAMOS_TPM_AK_HANDLE=0x81010002 EXAMOS_DEVICE_ID=... EXAMOS_INSTITUTION_ID=... EXAMOS_RELEASE_ID=... EXAMOS_ENROLLMENT_OUTPUT=/path/request.json $0 --confirm-persist" >&2
    echo "This creates and persists TPM EK/AK objects; it never clears the TPM." >&2
    exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "BLOCKED: run enrollment as root on the target ExamOS device. A TPM device node does not prove physical provenance." >&2
    exit 2
fi

for name in EXAMOS_TPM_EK_HANDLE EXAMOS_TPM_AK_HANDLE EXAMOS_DEVICE_ID EXAMOS_INSTITUTION_ID EXAMOS_RELEASE_ID EXAMOS_ENROLLMENT_OUTPUT EXAMOS_TPM_CA_STORE EXAMOS_TPM_CA_STORE_SHA256; do
    if [[ -z "${!name:-}" ]]; then
        echo "FAIL: $name must be configured explicitly." >&2
        exit 1
    fi
done
if [[ ! -f "$EXAMOS_TPM_CA_STORE" || -L "$EXAMOS_TPM_CA_STORE" ||
      ! "$EXAMOS_TPM_CA_STORE_SHA256" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "BLOCKED: provide the organization-approved TPM manufacturer CA bundle and its externally pinned SHA-256." >&2
    exit 2
fi
CA_STORE_DIGEST=$(sha256sum -- "$EXAMOS_TPM_CA_STORE" | cut -d' ' -f1)
if [[ "${CA_STORE_DIGEST,,}" != "${EXAMOS_TPM_CA_STORE_SHA256,,}" ]]; then
    echo "FAIL: TPM manufacturer CA bundle does not match the externally pinned fingerprint." >&2
    exit 1
fi

if [[ ! "$EXAMOS_TPM_EK_HANDLE" =~ ^0[xX][[:xdigit:]]{8}$ ||
      ! "$EXAMOS_TPM_AK_HANDLE" =~ ^0[xX][[:xdigit:]]{8}$ ]]; then
    echo "FAIL: EK and AK handles must be 8-digit hexadecimal values, such as 0x81010001." >&2
    exit 1
fi
EK_HANDLE_VALUE=$((EXAMOS_TPM_EK_HANDLE))
AK_HANDLE_VALUE=$((EXAMOS_TPM_AK_HANDLE))
if (( EK_HANDLE_VALUE < 0x81000000 || EK_HANDLE_VALUE > 0x81ffffff ||
      AK_HANDLE_VALUE < 0x81000000 || AK_HANDLE_VALUE > 0x81ffffff ||
      EK_HANDLE_VALUE == AK_HANDLE_VALUE )); then
    echo "FAIL: EK and AK must use distinct handles in 0x81000000-0x81ffffff." >&2
    exit 1
fi
EK_HANDLE=$(printf '0x%08x' "$EK_HANDLE_VALUE")
AK_HANDLE=$(printf '0x%08x' "$AK_HANDLE_VALUE")
if [[ ! "$EXAMOS_DEVICE_ID" =~ ^[A-Za-z0-9._:-]{1,63}$ ||
      ! "$EXAMOS_INSTITUTION_ID" =~ ^[A-Za-z0-9._:-]{1,63}$ ||
      ! "$EXAMOS_RELEASE_ID" =~ ^[A-Za-z0-9._:-]{1,63}$ ]]; then
    echo "FAIL: device, institution, and release IDs must use 1-63 ASCII letters, digits, dot, underscore, colon, or hyphen." >&2
    exit 1
fi

TPM_DEVICE=""
if [[ -c /dev/tpmrm0 ]]; then
    TPM_DEVICE=/dev/tpmrm0
elif [[ -c /dev/tpm0 ]]; then
    TPM_DEVICE=/dev/tpm0
else
    echo "BLOCKED: no TPM character device found; refusing software TPM and network TCTI. A character device alone does not establish physical provenance." >&2
    exit 2
fi
for tool in tpm2_getcap tpm2_createek tpm2_createak tpm2_evictcontrol \
            tpm2_readpublic tpm2_nvread openssl python3 xxd systemctl; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "BLOCKED: required physical enrollment tool missing: $tool" >&2
        exit 2
    }
done
systemctl start tpm2-abrmd.service || {
    echo "BLOCKED: TPM access broker could not be started." >&2
    exit 2
}
systemctl is-active --quiet tpm2-abrmd.service || {
    echo "BLOCKED: TPM access broker is not active." >&2
    exit 2
}
export TPM2TOOLS_TCTI=tabrmd

OUTPUT=$EXAMOS_ENROLLMENT_OUTPUT
OUTPUT_DIR=$(dirname "$OUTPUT")
mkdir -p "$OUTPUT_DIR"
if [[ -e "$OUTPUT" ]]; then
    echo "FAIL: enrollment output already exists; preserve it and choose a new path: $OUTPUT" >&2
    exit 1
fi

WORK_DIR=$(mktemp -d "${TMPDIR:-/run}/examos-tpm-enroll.XXXXXX")
chmod 0700 "$WORK_DIR"
cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

if ! tpm2_getcap handles-persistent >"$WORK_DIR/handles.txt"; then
    echo "FAIL: could not query persistent TPM handles." >&2
    exit 1
fi
if python3 - "$WORK_DIR/handles.txt" "$EK_HANDLE" "$AK_HANDLE" <<'PY'
import sys

wanted = {int(value, 0) for value in sys.argv[2:]}
for line in open(sys.argv[1], encoding="utf-8"):
    for value in line.replace(":", " ").split():
        try:
            if int(value, 0) in wanted:
                raise SystemExit(0)
        except ValueError:
            continue
raise SystemExit(1)
PY
then
    echo "FAIL: one requested TPM persistent handle is already occupied; no TPM object was changed." >&2
    exit 1
fi

EK_CERT_INDEX=0x01c00002
tpm2_createek --ek-context "$WORK_DIR/ek.ctx" --key-algorithm rsa >/dev/null
tpm2_readpublic --object-context "$WORK_DIR/ek.ctx" --format pem \
    --output "$WORK_DIR/ek.pem" >/dev/null
if ! tpm2_nvread --hierarchy owner --output "$WORK_DIR/ek-cert.der" \
    "$EK_CERT_INDEX" >/dev/null 2>&1; then
    echo "BLOCKED: RSA EK manufacturer certificate is unavailable at NV $EK_CERT_INDEX; no AK was persisted." >&2
    exit 2
fi
if ! openssl x509 -inform DER -in "$WORK_DIR/ek-cert.der" \
    -out "$WORK_DIR/ek-cert.pem" 2>/dev/null; then
    echo "FAIL: TPM EK certificate is not valid DER X.509; no AK was persisted." >&2
    exit 1
fi
if ! openssl verify -CAfile "$EXAMOS_TPM_CA_STORE" "$WORK_DIR/ek-cert.pem" >/dev/null; then
    echo "FAIL: TPM EK manufacturer certificate is not trusted by the pinned organization CA bundle; no AK was persisted." >&2
    exit 1
fi
openssl pkey -pubin -in "$WORK_DIR/ek.pem" -outform DER \
    -out "$WORK_DIR/ek-public.der"
openssl x509 -in "$WORK_DIR/ek-cert.pem" -pubkey -noout \
    -out "$WORK_DIR/ek-cert-public.pem"
openssl pkey -pubin -in "$WORK_DIR/ek-cert-public.pem" -outform DER \
    -out "$WORK_DIR/ek-cert-public.der"
if ! cmp -s "$WORK_DIR/ek-public.der" "$WORK_DIR/ek-cert-public.der"; then
    echo "FAIL: EK certificate public key does not match the TPM EK public key." >&2
    exit 1
fi
EK_FINGERPRINT=$(sha256sum "$WORK_DIR/ek-public.der" | cut -d' ' -f1)

tpm2_createak --ek-context "$WORK_DIR/ek.ctx" \
    --ak-context "$WORK_DIR/ak.ctx" \
    --key-algorithm rsa --hash-algorithm sha256 \
    --signing-algorithm rsassa \
    --public "$WORK_DIR/ak-public.tss" --name "$WORK_DIR/ak.name" >/dev/null
CREATED_NAME=$(xxd -p -c 10000 "$WORK_DIR/ak.name" | tr -d '\n')
if [[ ${#CREATED_NAME} -ne 68 || "${CREATED_NAME:0:4}" != "000b" ]]; then
    echo "FAIL: TPM created an AK with an unexpected Name; no AK was persisted." >&2
    exit 1
fi
tpm2_readpublic --object-context "$WORK_DIR/ak.ctx" --format pem \
    --output "$WORK_DIR/ak-transient.pem" \
    --qualified-name "$WORK_DIR/ak-transient.qualified-name" >/dev/null
openssl pkey -pubin -in "$WORK_DIR/ak-transient.pem" -outform DER \
    -out "$WORK_DIR/ak-transient.der"

if ! tpm2_evictcontrol --hierarchy owner --object-context "$WORK_DIR/ek.ctx" \
    "$EK_HANDLE" >/dev/null; then
    echo "FAIL: TPM did not persist the EK at $EK_HANDLE." >&2
    exit 1
fi
tpm2_readpublic --object-context "$EK_HANDLE" --format pem \
    --output "$WORK_DIR/ek-persistent.pem" >/dev/null
openssl pkey -pubin -in "$WORK_DIR/ek-persistent.pem" -outform DER \
    -out "$WORK_DIR/ek-persistent.der"
if ! cmp -s "$WORK_DIR/ek-public.der" "$WORK_DIR/ek-persistent.der"; then
    echo "FAIL: persisted EK differs from its manufacturer-certified key." >&2
    echo "The EK remains persisted at $EK_HANDLE; preserve the device and investigate before retrying." >&2
    exit 1
fi
if ! tpm2_evictcontrol --hierarchy owner --object-context "$WORK_DIR/ak.ctx" \
    "$AK_HANDLE" >/dev/null; then
    echo "FAIL: TPM did not persist the newly created AK at $AK_HANDLE." >&2
    echo "The EK remains persisted at $EK_HANDLE; preserve the device and investigate before retrying." >&2
    exit 1
fi
tpm2_readpublic --object-context "$AK_HANDLE" --format pem \
    --output "$WORK_DIR/ak.pem" --name "$WORK_DIR/ak-persisted.name" \
    --qualified-name "$WORK_DIR/ak-persisted.qualified-name" >/dev/null
PERSISTED_NAME=$(xxd -p -c 10000 "$WORK_DIR/ak-persisted.name" | tr -d '\n')
AK_QUALIFIED_NAME=$(xxd -p -c 10000 "$WORK_DIR/ak-persisted.qualified-name" | tr -d '\n')
openssl pkey -pubin -in "$WORK_DIR/ak.pem" -outform DER \
    -out "$WORK_DIR/ak-public.der"
if [[ "$PERSISTED_NAME" != "$CREATED_NAME" ]] ||
   ! cmp -s "$WORK_DIR/ak-transient.der" "$WORK_DIR/ak-public.der" ||
   ! cmp -s "$WORK_DIR/ak-transient.qualified-name" "$WORK_DIR/ak-persisted.qualified-name"; then
    echo "FAIL: persistent AK identity differs from the TPM-created enrollment identity." >&2
    echo "The persistent objects at $EK_HANDLE and $AK_HANDLE were not removed; preserve the device and investigate before retrying." >&2
    exit 1
fi
AK_PUBLIC_SHA256=$(sha256sum "$WORK_DIR/ak-public.der" | cut -d' ' -f1)
AK_PUBLIC_AREA_HEX=$(xxd -p -c 10000 "$WORK_DIR/ak-public.tss" | tr -d '\n')
if [[ -z "$AK_PUBLIC_AREA_HEX" || $((${#AK_PUBLIC_AREA_HEX} % 2)) -ne 0 ]]; then
    echo "FAIL: TPM did not return a valid AK public area." >&2
    echo "The persistent objects at $EK_HANDLE and $AK_HANDLE were not removed; preserve the device and investigate before retrying." >&2
    exit 1
fi
EK_CERT_PEM=$(cat "$WORK_DIR/ek-cert.pem")
AK_PEM=$(cat "$WORK_DIR/ak.pem")
TPM_PROPERTIES=$(tpm2_getcap properties-fixed)

python3 - "$OUTPUT" "$EXAMOS_DEVICE_ID" "$EXAMOS_INSTITUTION_ID" "$EXAMOS_RELEASE_ID" "$EK_HANDLE" \
    "$AK_HANDLE" "$EK_FINGERPRINT" "$CREATED_NAME" "$AK_QUALIFIED_NAME" "$AK_PUBLIC_SHA256" \
    "$AK_PUBLIC_AREA_HEX" "$EK_CERT_PEM" "$AK_PEM" "$TPM_PROPERTIES" "$CA_STORE_DIGEST" <<'PY'
import json
import pathlib
import sys

(
    output, device_id, institution_id, release_id, ek_handle, ak_handle, ek_fingerprint, ak_name,
    ak_qualified_name, ak_public_sha256, ak_public_area_hex, ek_certificate, ak_public,
    properties, ca_store_sha256,
) = sys.argv[1:]
record = {
    "_schema": "examos-physical-tpm-enrollment-request-v1",
    "enrollment_status": "PENDING_EXTERNAL_APPROVAL",
    "device_id": device_id,
    "institution_id": institution_id,
    "allowed_release": release_id,
    "tpm_ek_handle": ek_handle,
    "tpm_ak_handle": ak_handle,
    "ek_fingerprint": ek_fingerprint,
    "ek_certificate_pem": ek_certificate,
    "ek_certificate_chain": "",
    "ak_name": ak_name,
    "ak_name_hex": ak_name,
    "ak_qualified_name": ak_qualified_name,
    "ak_pub_sha256": ak_public_sha256,
    "ak_public_pem": ak_public,
    "ak_public_key_pem": ak_public,
    "ak_public_area_hex": ak_public_area_hex,
    "tpm_present": True,
    "tpm_version": "2.0",
    "os_release_id": release_id,
    "tpm_fixed_properties": properties,
    "tpm_manufacturer_ca_store_sha256": ca_store_sha256,
    "approval_requirements": [
        "validate EK certificate chain against approved manufacturer roots",
        "complete MakeCredential/ActivateCredential for this AK Name",
        "approve and sign the production device registry out of band",
    ],
}
path = pathlib.Path(output)
with path.open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
path.chmod(0o600)
PY

echo "PASS: persistent TPM EK/AK created at $EK_HANDLE and $AK_HANDLE after the EK certificate passed the pinned CA check; a device node alone is not proof of physical hardware."
echo "PENDING: enrollment request is not trusted until manufacturer-chain validation, credential activation, and signed-registry approval are complete."
echo "Enrollment request: $OUTPUT"
