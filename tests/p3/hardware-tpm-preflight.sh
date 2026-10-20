#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$(id -u)" -ne 0 ]]; then
    echo "BLOCKED: run this check as root on the physical ExamOS device." >&2
    exit 2
fi
if [[ -z "${EXAMOS_TPM_EK_HANDLE:-}" || -z "${EXAMOS_TPM_AK_HANDLE:-}" ]]; then
    echo "BLOCKED: set EXAMOS_TPM_EK_HANDLE and EXAMOS_TPM_AK_HANDLE to their enrolled persistent handles." >&2
    exit 2
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
    echo "FAIL: EK and AK handles must be distinct and in the TPM persistent-handle range." >&2
    exit 1
fi
EK_HANDLE=$(printf '0x%08x' "$EK_HANDLE_VALUE")
AK_HANDLE=$(printf '0x%08x' "$AK_HANDLE_VALUE")
if [[ -c /dev/tpmrm0 ]]; then
    export TPM2TOOLS_TCTI=device:/dev/tpmrm0
elif [[ -c /dev/tpm0 ]]; then
    export TPM2TOOLS_TCTI=device:/dev/tpm0
else
    echo "BLOCKED: no physical TPM device node is available; refusing swtpm or network TCTI." >&2
    exit 2
fi

for tool in tpm2_getcap tpm2_createek tpm2_readpublic tpm2_nvread \
            tpm2_quote tpm2_pcrread tpm2_checkquote openssl python3 xxd; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "BLOCKED: required physical TPM validation tool missing: $tool" >&2
        exit 2
    }
done

EVIDENCE_DIR=${EXAMOS_P3_ARTIFACT_DIR:-/var/lib/examos/evidence/p3-physical}
mkdir -p "$EVIDENCE_DIR"
chmod 0700 "$EVIDENCE_DIR"
WORK_DIR=$(mktemp -d "${TMPDIR:-/run}/examos-tpm-preflight.XXXXXX")
chmod 0700 "$WORK_DIR"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

if ! tpm2_readpublic --object-context "$AK_HANDLE" --format pem \
    --output "$WORK_DIR/ak.pem" --name "$WORK_DIR/ak.name" >/dev/null; then
    echo "FAIL: persistent AK $AK_HANDLE cannot be read from the physical TPM." >&2
    exit 1
fi
AK_NAME=$(xxd -p -c 10000 "$WORK_DIR/ak.name" | tr -d '\n')
if [[ ${#AK_NAME} -ne 68 || "${AK_NAME:0:4}" != "000b" ]]; then
    echo "FAIL: persistent TPM AK Name is not a SHA-256 TPM Name." >&2
    exit 1
fi
openssl pkey -pubin -in "$WORK_DIR/ak.pem" -outform DER \
    -out "$WORK_DIR/ak-public.der"
AK_PUBLIC_SHA256=$(sha256sum "$WORK_DIR/ak-public.der" | cut -d' ' -f1)

tpm2_readpublic --object-context "$EK_HANDLE" --format pem \
    --output "$WORK_DIR/ek.pem" >/dev/null
openssl pkey -pubin -in "$WORK_DIR/ek.pem" -outform DER \
    -out "$WORK_DIR/ek-public.der"
EK_FINGERPRINT=$(sha256sum "$WORK_DIR/ek-public.der" | cut -d' ' -f1)
if ! tpm2_nvread --hierarchy owner --output "$WORK_DIR/ek-cert.der" \
    0x01c00002 >/dev/null 2>&1; then
    echo "FAIL: physical TPM RSA EK manufacturer certificate is unavailable." >&2
    exit 1
fi
openssl x509 -inform DER -in "$WORK_DIR/ek-cert.der" \
    -out "$WORK_DIR/ek-cert.pem"
openssl x509 -in "$WORK_DIR/ek-cert.pem" -pubkey -noout \
    -out "$WORK_DIR/ek-cert-public.pem"
openssl pkey -pubin -in "$WORK_DIR/ek-cert-public.pem" -outform DER \
    -out "$WORK_DIR/ek-cert-public.der"
if ! cmp -s "$WORK_DIR/ek-public.der" "$WORK_DIR/ek-cert-public.der"; then
    echo "FAIL: persistent EK does not match its manufacturer certificate." >&2
    exit 1
fi

NONCE=$(openssl rand -hex 32)
tpm2_pcrread --output "$WORK_DIR/pcrs.bin" sha256:0,4,7,11 >/dev/null
tpm2_pcrread sha256:0,4,7,11 >"$WORK_DIR/pcrs.yaml"
tpm2_quote --key-context "$AK_HANDLE" --pcr-list sha256:0,4,7,11 \
    --qualification "$NONCE" --message "$WORK_DIR/quote.msg" \
    --signature "$WORK_DIR/quote.sig" --hash-algorithm sha256 >/dev/null
tpm2_checkquote --public "$WORK_DIR/ak.pem" \
    --message "$WORK_DIR/quote.msg" --signature "$WORK_DIR/quote.sig" \
    --pcr "$WORK_DIR/pcrs.bin" --pcr-list sha256:0,4,7,11 \
    --qualification "$NONCE" >/dev/null

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
cp "$WORK_DIR/ak.name" "$EVIDENCE_DIR/ak-name-$STAMP.bin"
cp "$WORK_DIR/ak.pem" "$EVIDENCE_DIR/ak-public-$STAMP.pem"
cp "$WORK_DIR/pcrs.yaml" "$EVIDENCE_DIR/pcrs-$STAMP.yaml"
cp "$WORK_DIR/quote.msg" "$EVIDENCE_DIR/quote-$STAMP.attest"
cp "$WORK_DIR/quote.sig" "$EVIDENCE_DIR/quote-$STAMP.signature"
cp "$WORK_DIR/ek-cert.der" "$EVIDENCE_DIR/ek-certificate-$STAMP.der"
python3 - "$EVIDENCE_DIR/hardware-preflight-$STAMP.json" "$STAMP" \
    "$EK_HANDLE" "$AK_HANDLE" "$AK_NAME" "$AK_PUBLIC_SHA256" "$EK_FINGERPRINT" "$NONCE" \
    "$WORK_DIR/quote.msg" "$WORK_DIR/quote.sig" "$WORK_DIR/ek-cert.der" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    output, timestamp, ek_handle, ak_handle, ak_name, ak_hash, ek_hash, nonce,
    quote_path, signature_path, certificate_path,
) = sys.argv[1:]
digest = lambda path: hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
record = {
    "_schema": "examos-physical-tpm-preflight-v1",
    "result": "PASS",
    "evidence_type": "physical-hardware-quote-preflight",
    "not_production_attestation": True,
    "timestamp_utc": timestamp,
    "tpm_ek_handle": ek_handle,
    "tpm_ak_handle": ak_handle,
    "ak_name": ak_name,
    "ak_pub_sha256": ak_hash,
    "ek_fingerprint": ek_hash,
    "nonce_origin": "local-random-not-server-issued",
    "nonce": nonce,
    "quote_sha256": digest(pathlib.Path(quote_path)),
    "signature_sha256": digest(pathlib.Path(signature_path)),
    "ek_certificate_sha256": digest(pathlib.Path(certificate_path)),
    "local_quote_verification": "tpm2_checkquote PASS",
}
with pathlib.Path(output).open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
pathlib.Path(output).chmod(0o600)
PY

echo "PASS: physical TPM generated and locally verified a fresh quote using AK $AK_HANDLE."
echo "NOT PRODUCTION CERTIFICATION: challenge was locally generated, not server-issued; server verification, EK-chain approval, measured release, and secure boot policy remain separate gates."
echo "Evidence: $EVIDENCE_DIR/hardware-preflight-$STAMP.json"
