#!/usr/bin/env python3
"""Offline operator ceremony for physical TPM enrollment.

The tool prepares a TPM MakeCredential challenge, obtains a response on the
physical device, then emits an unsigned registry candidate for external HSM
approval. It never signs or updates a trusted manifest.
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys


REQUEST_SCHEMA = "examos-physical-tpm-enrollment-request-v1"
CHALLENGE_SCHEMA = "examos-physical-tpm-credential-challenge-v1"
STATE_SCHEMA = "examos-physical-tpm-verifier-state-v1"
RESPONSE_SCHEMA = "examos-physical-tpm-credential-response-v1"
DEVICE_SCHEMA = "examos-device-registry-v1"
RELEASE_SCHEMA = "examos-release-registry-v1"
ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,63}\Z")
HASH_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")
TPM_NAME_PATTERN = re.compile(r"000b[0-9a-fA-F]{64}\Z")
HANDLE_PATTERN = re.compile(r"0[xX]81[0-9a-fA-F]{6}\Z")
MAX_INPUT_SIZE = 8 * 1024 * 1024


class CeremonyError(Exception):
    pass


class Blocked(CeremonyError):
    pass


def fail(message):
    raise CeremonyError(message)


def require(condition, message):
    if not condition:
        fail(message)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("JSON input contains a duplicate key.")
        result[key] = value
    return result


def read_regular(path, limit=MAX_INPUT_SIZE, protected=False):
    path = pathlib.Path(path)
    try:
        info = path.lstat()
    except OSError:
        fail("Input file is missing or inaccessible.")
    require(stat.S_ISREG(info.st_mode), "Input must be a regular, non-symlink file.")
    require(info.st_size <= limit, "Input file exceeds the configured size limit.")
    if protected:
        require(os.name == "posix", "Protected verifier state requires POSIX file permissions.")
        require(info.st_uid == os.geteuid(), "Protected verifier state must be owned by this operator.")
        require(stat.S_IMODE(info.st_mode) == 0o600, "Protected verifier state permissions must be exactly 0600.")
        try:
            parent_info = path.parent.resolve(strict=True).stat()
        except OSError:
            fail("Protected verifier state directory is unavailable.")
        require(parent_info.st_uid == os.geteuid() and stat.S_IMODE(parent_info.st_mode) & 0o022 == 0,
                "Protected verifier state directory must be operator-owned and not group- or world-writable.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            require(stat.S_ISREG(opened.st_mode), "Input must be a regular file.")
            require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
                    "Input changed while it was being opened.")
            data = stream.read(limit + 1)
    except OSError:
        fail("Input file could not be read safely.")
    require(len(data) <= limit, "Input file exceeds the configured size limit.")
    return data


def read_json(path, protected=False):
    raw = read_regular(path, protected=protected)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object)
    except CeremonyError:
        raise
    except (UnicodeError, ValueError):
        fail("Input is not valid UTF-8 JSON.")
    require(isinstance(value, dict), "JSON document must be an object.")
    return raw, value


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_hash(value, label, nonzero=False):
    require(isinstance(value, str) and HASH_PATTERN.fullmatch(value) is not None,
            "{} must be a 64-digit SHA-256 value.".format(label))
    require(not nonzero or re.search(r"[1-9a-fA-F]", value) is not None,
            "{} must not be all zeroes.".format(label))


def run_checked(argv, *, input_data=None, env=None, missing_is_blocked=True):
    try:
        result = subprocess.run(
            argv, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, env=env, timeout=60,
        )
    except FileNotFoundError:
        if missing_is_blocked:
            raise Blocked("Required command is unavailable: {}.".format(argv[0]))
        fail("Required verification command failed.")
    except (OSError, subprocess.TimeoutExpired):
        fail("Required verification command could not complete.")
    if result.returncode != 0:
        fail("Required verification command failed: {}.".format(pathlib.Path(argv[0]).name))
    return result.stdout


def resolve_parent(path):
    path = pathlib.Path(path)
    try:
        parent = path.parent.resolve(strict=True)
        info = parent.stat()
    except OSError:
        fail("Output directory must already exist and be accessible.")
    require(stat.S_ISDIR(info.st_mode), "Output parent must be a directory.")
    if os.name == "posix":
        require(info.st_uid == os.geteuid(), "Output directory must be owned by this operator.")
        require(stat.S_IMODE(info.st_mode) & 0o022 == 0,
                "Output directory must not be group- or world-writable.")
    return parent / path.name, parent


def create_exclusive(path, data, mode=0o600):
    path, _ = resolve_parent(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            os.chmod(str(path), mode)
    except FileExistsError:
        fail("Refusing to overwrite an existing output file.")
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass
        fail("Output file could not be created safely.")
    return path


def scratch_file(directory, suffix):
    directory = pathlib.Path(directory)
    for _ in range(10):
        candidate = directory / (".physical-tpm-" + secrets.token_hex(16) + suffix)
        try:
            fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            return candidate
        except FileExistsError:
            continue
        except OSError:
            fail("Secure scratch file could not be created.")
    fail("Could not allocate a unique secure scratch file.")


def scratch_output_path(directory, suffix):
    directory = pathlib.Path(directory)
    for _ in range(10):
        candidate = directory / (".physical-tpm-" + secrets.token_hex(16) + suffix)
        try:
            candidate.lstat()
        except FileNotFoundError:
            return candidate
        except OSError:
            fail("Secure scratch path could not be checked.")
    fail("Could not allocate a unique secure scratch path.")


def remove_files(paths):
    for path in paths:
        try:
            pathlib.Path(path).unlink()
        except OSError:
            pass


def wipe_file(path):
    path = pathlib.Path(path)
    try:
        size = path.stat().st_size
        with path.open("r+b", buffering=0) as stream:
            remaining = size
            zeros = b"\0" * 4096
            while remaining:
                count = min(remaining, len(zeros))
                stream.write(zeros[:count])
                remaining -= count
            os.fsync(stream.fileno())
    except OSError:
        pass


def read_u16(data, offset):
    require(offset + 2 <= len(data), "TPM structure is truncated.")
    return int.from_bytes(data[offset:offset + 2], "big"), offset + 2


def read_u32(data, offset):
    require(offset + 4 <= len(data), "TPM structure is truncated.")
    return int.from_bytes(data[offset:offset + 4], "big"), offset + 4


def parse_tpm2b_public(encoded):
    require(isinstance(encoded, bytes) and 2 <= len(encoded) <= 8192,
            "Serialized TPM public area has an invalid size.")
    size = int.from_bytes(encoded[:2], "big")
    # tss format may include the TPM2B_PUBLIC size prefix; tpmt format is
    # the serialized TPMT_PUBLIC body itself.
    public = encoded[2:] if size == len(encoded) - 2 else encoded
    offset = 0
    object_type, offset = read_u16(public, offset)
    name_alg, offset = read_u16(public, offset)
    require(name_alg == 0x000B, "TPM public area must use SHA-256 NameAlg.")
    _, offset = read_u32(public, offset)  # objectAttributes
    policy_size, offset = read_u16(public, offset)
    require(offset + policy_size <= len(public), "TPM public authPolicy is truncated.")
    offset += policy_size
    require(object_type == 0x0001, "Only RSA TPM public areas are supported.")

    symmetric, offset = read_u16(public, offset)
    if symmetric == 0x0006:  # TPM_ALG_AES
        _, offset = read_u16(public, offset)  # keyBits
        _, offset = read_u16(public, offset)  # mode
    else:
        require(symmetric == 0x0010, "Unsupported TPM RSA symmetric definition.")

    scheme, offset = read_u16(public, offset)
    if scheme in (0x0014, 0x0016, 0x0017):  # RSASSA, RSAPSS, OAEP
        _, offset = read_u16(public, offset)  # scheme hash
    else:
        require(scheme in (0x0010, 0x0015), "Unsupported TPM RSA scheme.")

    key_bits, offset = read_u16(public, offset)
    exponent, offset = read_u32(public, offset)
    modulus_size, offset = read_u16(public, offset)
    require(modulus_size > 0 and offset + modulus_size == len(public),
            "TPM RSA public modulus is malformed.")
    modulus = int.from_bytes(public[offset:offset + modulus_size], "big")
    require(modulus.bit_length() == key_bits, "TPM RSA keyBits does not match the modulus.")
    exponent = exponent or 65537
    name = b"\x00\x0b" + hashlib.sha256(public).digest()
    return {
        "public": public,
        "name_alg": name_alg,
        "name": name,
        "modulus": modulus,
        "exponent": exponent,
    }


def derive_qualified_name(public_area, parent_qualified_name):
    return b"\x00\x0b" + hashlib.sha256(parent_qualified_name + public_area["name"]).digest()


def parse_rsa_public_der(der):
    def item(data, offset):
        require(offset < len(data), "Public-key DER is truncated.")
        tag = data[offset]
        offset += 1
        require(offset < len(data), "Public-key DER length is truncated.")
        length = data[offset]
        offset += 1
        if length & 0x80:
            count = length & 0x7F
            require(0 < count <= 4 and offset + count <= len(data),
                    "Public-key DER length is invalid.")
            require(data[offset] != 0, "Public-key DER length is non-canonical.")
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count
            require(length >= 0x80, "Public-key DER length is non-canonical.")
        require(offset + length <= len(data), "Public-key DER value is truncated.")
        return tag, data[offset:offset + length], offset + length

    tag, outer, end = item(der, 0)
    require(tag == 0x30 and end == len(der), "Public key is not a DER SubjectPublicKeyInfo.")
    _, _, offset = item(outer, 0)  # AlgorithmIdentifier
    tag, bit_string, end = item(outer, offset)
    require(tag == 0x03 and end == len(outer) and bit_string[:1] == b"\0",
            "Public key DER has an invalid subjectPublicKey bit string.")
    tag, rsa_sequence, end = item(bit_string, 1)
    require(tag == 0x30 and end == len(bit_string),
            "Public key does not contain a DER RSA public key.")
    tag, modulus_bytes, offset = item(rsa_sequence, 0)
    require(tag == 0x02, "RSA public key modulus is missing.")
    tag, exponent_bytes, end = item(rsa_sequence, offset)
    require(tag == 0x02 and end == len(rsa_sequence), "RSA public key exponent is missing.")
    require(modulus_bytes and exponent_bytes and not (modulus_bytes[0] & 0x80) and
            not (exponent_bytes[0] & 0x80), "RSA public key DER integers are invalid.")
    return int.from_bytes(modulus_bytes, "big"), int.from_bytes(exponent_bytes, "big")


def parse_quote_attest(encoded):
    require(isinstance(encoded, bytes) and 2 <= len(encoded) <= 4096,
            "Quote attestation has an invalid size.")
    if int.from_bytes(encoded[:2], "big") == len(encoded) - 2:
        attest = encoded[2:]
    else:
        attest = encoded
    require(len(attest) >= 6, "TPMS_ATTEST is truncated.")
    magic, offset = read_u32(attest, 0)
    quote_type, offset = read_u16(attest, offset)
    require(magic == 0xFF544347, "TPMS_ATTEST magic is invalid.")
    require(quote_type == 0x8018, "TPMS_ATTEST is not a quote.")

    signer_size, offset = read_u16(attest, offset)
    require(signer_size > 0 and offset + signer_size <= len(attest),
            "TPMS_ATTEST qualifiedSigner is malformed.")
    signer = attest[offset:offset + signer_size]
    offset += signer_size
    nonce_size, offset = read_u16(attest, offset)
    require(offset + nonce_size <= len(attest), "TPMS_ATTEST extraData is malformed.")
    nonce = attest[offset:offset + nonce_size]
    offset += nonce_size
    require(offset + 25 <= len(attest), "TPMS_ATTEST clockInfo or firmwareVersion is truncated.")
    offset += 25  # TPMS_CLOCK_INFO (17 bytes) and firmwareVersion (8 bytes)
    selection_count, offset = read_u32(attest, offset)
    require(selection_count == 1, "Quote must select exactly one PCR bank.")
    hash_alg, offset = read_u16(attest, offset)
    select_size, offset = read_u8(attest, offset)
    require(select_size == 3 and offset + select_size <= len(attest),
            "Quote PCR selection has an invalid size.")
    pcr_select = attest[offset:offset + select_size]
    offset += select_size
    digest_size, offset = read_u16(attest, offset)
    require(digest_size == 32 and offset + digest_size == len(attest),
            "Quote PCR digest is malformed.")
    return attest, signer, nonce, hash_alg, pcr_select


def read_u8(data, offset):
    require(offset < len(data), "TPM structure is truncated.")
    return data[offset], offset + 1


def parse_rsassa_sha256_signature(encoded):
    require(isinstance(encoded, bytes) and 8 <= len(encoded) <= 4096,
            "TPMT_SIGNATURE has an invalid size.")
    offset = 0
    sig_alg, offset = read_u16(encoded, offset)
    hash_alg, offset = read_u16(encoded, offset)
    require(sig_alg == 0x0014 and hash_alg == 0x000B,
            "Quote signature must use RSASSA with SHA-256.")
    signature_size, offset = read_u16(encoded, offset)
    require(signature_size > 0 and offset + signature_size == len(encoded),
            "TPMT_SIGNATURE RSA signature is malformed.")
    return encoded[offset:]


def validate_quote_fields(attest_data, request, quote_nonce):
    attest, signer, nonce, hash_alg, pcr_select = parse_quote_attest(attest_data)
    require(hmac.compare_digest(signer.hex(), request["ak_qualified_name"].lower()),
            "Quote qualifiedSigner does not match the request AK qualified Name.")
    require(hmac.compare_digest(nonce, quote_nonce),
            "Quote extraData does not match the fresh challenge nonce.")
    require(hash_alg == 0x000B and pcr_select == b"\x91\x08\x00",
            "Quote PCR selection must be SHA-256 PCRs 0, 4, 7, and 11.")
    return attest


def decode_response_field(response, key, limit=8192):
    value = response.get(key)
    require(isinstance(value, str), "Credential response {} must be base64 text.".format(key))
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        fail("Credential response {} is not valid base64.".format(key))
    require(0 < len(decoded) <= limit, "Credential response {} has an invalid size.".format(key))
    return decoded


def rsa_components_from_pem(pem, work_dir, scratch):
    try:
        pem_bytes = pem.encode("ascii") if isinstance(pem, str) else pem
    except UnicodeError:
        fail("Public key PEM is not valid ASCII.")
    pem_path = scratch_file(work_dir, ".verify-public.pem")
    scratch.append(pem_path)
    pem_path.write_bytes(pem_bytes)
    der = run_checked(["openssl", "pkey", "-pubin", "-in", str(pem_path), "-outform", "DER"])
    return parse_rsa_public_der(der)


def verify_credential_response(request, challenge, response, ek_public_pem, work_dir):
    fields = {
        "_schema", "challenge_id", "activation_sha256",
        "ek_public_tpm2b_b64", "ak_public_tpm2b_b64",
        "quote_attest_b64", "quote_signature_b64",
    }
    require(set(response) == fields, "Credential response contains fields outside its schema.")
    require(response.get("_schema") == RESPONSE_SCHEMA and
            response.get("challenge_id") == challenge["challenge_id"],
            "Credential response is not bound to this challenge.")
    activation_sha256 = response.get("activation_sha256")
    validate_hash(activation_sha256, "activation secret response")

    ek_area = parse_tpm2b_public(decode_response_field(response, "ek_public_tpm2b_b64"))
    ak_area = parse_tpm2b_public(decode_response_field(response, "ak_public_tpm2b_b64"))
    scratch = []
    try:
        ek_cert_components = rsa_components_from_pem(ek_public_pem, work_dir, scratch)
        ak_key_path = scratch_file(work_dir, ".ak-request-key.pem")
        attest_path = scratch_file(work_dir, ".quote-attest.bin")
        signature_path = scratch_file(work_dir, ".quote-signature.bin")
        raw_signature_path = scratch_file(work_dir, ".quote-rsa-signature.bin")
        scratch.extend((ak_key_path, attest_path, signature_path, raw_signature_path))
        ak_key_path.write_text(request["ak_public_pem"], encoding="ascii")

        # Compare the public parameters, then bind each TPM Name to the exact
        # serialized TPMT_PUBLIC bytes carried in the response.
        require((ek_area["modulus"], ek_area["exponent"]) == ek_cert_components,
                "Response EK TPMT_PUBLIC does not match the pinned EK certificate public key.")
        ak_components = parse_rsa_public_der(run_checked([
            "openssl", "pkey", "-pubin", "-in", str(ak_key_path), "-outform", "DER",
        ]))
        require((ak_area["modulus"], ak_area["exponent"]) == ak_components,
                "Response AK TPMT_PUBLIC does not match the request AK PEM.")
        require(hmac.compare_digest(ak_area["name"].hex(), request["ak_name"].lower()),
                "Response AK TPMT_PUBLIC does not hash to the request AK Name.")
        ek_qname = derive_qualified_name(ek_area, bytes.fromhex("4000000b"))
        ak_qname = derive_qualified_name(ak_area, ek_qname)
        require(hmac.compare_digest(ak_qname.hex(), request["ak_qualified_name"].lower()),
                "Request AK qualified Name does not derive from its TPM parent EK and AK Name.")

        attest_encoded = decode_response_field(response, "quote_attest_b64", limit=4096)
        signature_encoded = decode_response_field(response, "quote_signature_b64", limit=4096)
        attest = validate_quote_fields(
            attest_encoded, request, bytes.fromhex(challenge["quote_nonce"])
        )
        raw_signature = parse_rsassa_sha256_signature(signature_encoded)
        attest_path.write_bytes(attest)
        signature_path.write_bytes(signature_encoded)
        raw_signature_path.write_bytes(raw_signature)
        run_checked([
            "openssl", "dgst", "-sha256", "-verify", str(ak_key_path),
            "-signature", str(raw_signature_path), str(attest_path),
        ])
    finally:
        remove_files(scratch)
    return activation_sha256


def validate_request(request):
    require(request.get("_schema") == REQUEST_SCHEMA, "Unexpected enrollment request schema.")
    require(request.get("enrollment_status") == "PENDING_EXTERNAL_APPROVAL",
            "Enrollment request is not pending external approval.")
    for key in ("institution_id", "device_id", "allowed_release"):
        require(isinstance(request.get(key), str) and ID_PATTERN.fullmatch(request[key]) is not None,
                "Enrollment request has an invalid {}.".format(key))
    for key in ("tpm_ek_handle", "tpm_ak_handle"):
        require(isinstance(request.get(key), str) and HANDLE_PATTERN.fullmatch(request[key]) is not None,
                "Enrollment request has an invalid {}.".format(key))
    require(int(request["tpm_ek_handle"], 16) != int(request["tpm_ak_handle"], 16),
            "EK and AK handles must be distinct.")
    for key in ("ek_fingerprint", "ak_pub_sha256", "tpm_manufacturer_ca_store_sha256"):
        validate_hash(request.get(key), key, nonzero=True)
    for key in ("ak_name", "ak_qualified_name"):
        require(isinstance(request.get(key), str) and TPM_NAME_PATTERN.fullmatch(request[key]) is not None,
                "Enrollment request has an invalid {}.".format(key))
    require(isinstance(request.get("ek_certificate_pem"), str) and
            "-----BEGIN CERTIFICATE-----" in request["ek_certificate_pem"],
            "Enrollment request does not contain a PEM EK certificate.")
    require(isinstance(request.get("ak_public_pem"), str) and
            len(request["ak_public_pem"]) <= 2047 and
            "-----BEGIN PUBLIC KEY-----" in request["ak_public_pem"],
            "Enrollment request does not contain a PEM AK public key.")
    require(len(request["ek_certificate_pem"]) <= 1024 * 1024,
            "Enrollment request EK certificate exceeds the size limit.")
    try:
        request["ek_certificate_pem"].encode("ascii")
        request["ak_public_pem"].encode("ascii")
    except UnicodeError:
        fail("Enrollment request PEM data is not valid ASCII.")


def validate_ca_and_request(request, ca_path, ca_pin, scratch_dir):
    validate_hash(ca_pin, "external TPM CA pin", nonzero=True)
    ca_bytes = read_regular(ca_path)
    require(hmac.compare_digest(digest(ca_bytes).lower(), ca_pin.lower()),
            "TPM manufacturer CA bundle does not match the external SHA-256 pin.")
    require(hmac.compare_digest(request["tpm_manufacturer_ca_store_sha256"].lower(), ca_pin.lower()),
            "Request CA bundle fingerprint differs from the externally pinned bundle.")

    scratch = []
    try:
        ca_snapshot = scratch_file(scratch_dir, ".manufacturer-ca.pem")
        scratch.append(ca_snapshot)
        ca_snapshot.write_bytes(ca_bytes)
        cert_path = scratch_file(scratch_dir, ".ek-cert.pem")
        scratch.append(cert_path)
        cert_path.write_text(request["ek_certificate_pem"], encoding="ascii")
        run_checked(["openssl", "verify", "-CAfile", str(ca_snapshot), str(cert_path)])
        ek_public = run_checked(
            ["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"]
        )
        ek_der = run_checked(
            ["openssl", "pkey", "-pubin", "-outform", "DER"], input_data=ek_public
        )
        require(hmac.compare_digest(digest(ek_der).lower(), request["ek_fingerprint"].lower()),
                "EK certificate public key does not match the request fingerprint.")
        key_details = run_checked(
            ["openssl", "pkey", "-pubin", "-text", "-noout"], input_data=ek_public
        )
        require(b"Modulus:" in key_details,
                "Only RSA EK certificates created by the physical enrollment workflow are supported.")
        ak_public = request["ak_public_pem"].encode("ascii")
        ak_der = run_checked(["openssl", "pkey", "-pubin", "-outform", "DER"], input_data=ak_public)
        require(hmac.compare_digest(digest(ak_der).lower(), request["ak_pub_sha256"].lower()),
                "AK public key does not match the request fingerprint.")
    except UnicodeError:
        fail("Enrollment request PEM data is not valid ASCII.")
    finally:
        remove_files(scratch)
    return ek_public


def request_identity(request):
    return {
        "institution_id": request["institution_id"],
        "device_id": request["device_id"],
        "allowed_release": request["allowed_release"],
        "ek_fingerprint": request["ek_fingerprint"].lower(),
        "ak_name": request["ak_name"].lower(),
    }


def challenge_binding(request, challenge):
    allowed_fields = {
        "_schema", "challenge_id", "institution_id", "device_id", "allowed_release",
        "ek_fingerprint", "ak_name", "quote_nonce", "request_sha256", "credential_blob",
    }
    require(set(challenge) == allowed_fields,
            "Credential challenge contains fields outside the transportable challenge schema.")
    identity = request_identity(request)
    for key, value in identity.items():
        require(challenge.get(key) == value, "Credential challenge does not match enrollment request.")
    require(challenge.get("_schema") == CHALLENGE_SCHEMA, "Unexpected credential challenge schema.")
    require(isinstance(challenge.get("challenge_id"), str) and
            re.fullmatch(r"[0-9a-f]{32}", challenge["challenge_id"]) is not None,
            "Credential challenge has an invalid identifier.")
    require(isinstance(challenge.get("quote_nonce"), str) and
            re.fullmatch(r"[0-9a-f]{64}", challenge["quote_nonce"]) is not None,
            "Credential challenge has an invalid quote nonce.")
    require(challenge.get("request_sha256") == digest(canonical_json(request)),
            "Credential challenge is bound to a different enrollment request.")
    try:
        credential_blob = challenge.get("credential_blob")
        require(isinstance(credential_blob, str), "Credential challenge blob must be base64 text.")
        blob = base64.b64decode(credential_blob, validate=True)
    except (binascii.Error, ValueError):
        fail("Credential challenge has an invalid credential blob.")
    require(0 < len(blob) <= 1024 * 1024, "Credential challenge blob has an invalid size.")
    return blob


def verify_physical_tpm_identity(request, env, work_dir, scratch):
    ek_pem = scratch_output_path(work_dir, ".physical-ek.pem")
    ak_pem = scratch_output_path(work_dir, ".physical-ak.pem")
    ak_name_path = scratch_output_path(work_dir, ".physical-ak-name")
    ak_qname_path = scratch_output_path(work_dir, ".physical-ak-qualified-name")
    ek_public_path = scratch_output_path(work_dir, ".physical-ek-public.tss")
    ak_public_path = scratch_output_path(work_dir, ".physical-ak-public.tss")
    ek_qname_path = scratch_output_path(work_dir, ".physical-ek-qualified-name")
    scratch.extend((ek_pem, ak_pem, ak_name_path, ak_qname_path,
                    ek_public_path, ak_public_path, ek_qname_path))
    run_checked([
        "tpm2_readpublic", "--object-context", request["tpm_ek_handle"],
        "--format", "pem", "--output", str(ek_pem),
    ], env=env)
    run_checked([
        "tpm2_readpublic", "--object-context", request["tpm_ek_handle"],
        "--format", "tss", "--output", str(ek_public_path),
        "--qualified-name", str(ek_qname_path),
    ], env=env)
    run_checked([
        "tpm2_readpublic", "--object-context", request["tpm_ak_handle"],
        "--format", "pem", "--output", str(ak_pem),
        "--name", str(ak_name_path), "--qualified-name", str(ak_qname_path),
    ], env=env)
    run_checked([
        "tpm2_readpublic", "--object-context", request["tpm_ak_handle"],
        "--format", "tss", "--output", str(ak_public_path),
    ], env=env)
    ek_public = parse_tpm2b_public(read_regular(ek_public_path, limit=8192))
    ak_public = parse_tpm2b_public(read_regular(ak_public_path, limit=8192))
    actual_ek_der = run_checked([
        "openssl", "pkey", "-pubin", "-in", str(ek_pem), "-outform", "DER",
    ])
    actual_ak_der = run_checked([
        "openssl", "pkey", "-pubin", "-in", str(ak_pem), "-outform", "DER",
    ])
    try:
        requested_ak_pem = request["ak_public_pem"].encode("ascii")
    except UnicodeError:
        fail("Enrollment request AK public key is not valid ASCII.")
    requested_ak_der = run_checked(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], input_data=requested_ak_pem,
    )
    require(hmac.compare_digest(digest(actual_ek_der).lower(), request["ek_fingerprint"].lower()),
            "Physical TPM EK does not match the enrollment request.")
    require(hmac.compare_digest(actual_ak_der, requested_ak_der) and
            hmac.compare_digest(digest(actual_ak_der).lower(), request["ak_pub_sha256"].lower()),
            "Physical TPM AK public key does not match the enrollment request.")
    require(rsa_components_pem(ek_pem, env, scratch) ==
            (ek_public["modulus"], ek_public["exponent"]),
            "Physical TPM EK serialized public area does not match its PEM key.")
    require(rsa_components_pem(ak_pem, env, scratch) ==
            (ak_public["modulus"], ak_public["exponent"]),
            "Physical TPM AK serialized public area does not match its PEM key.")
    require(read_regular(ak_name_path, limit=128).hex().lower() == request["ak_name"].lower(),
            "Physical TPM AK Name does not match the enrollment request.")
    require(read_regular(ak_qname_path, limit=128).hex().lower() == request["ak_qualified_name"].lower(),
            "Physical TPM AK qualified Name does not match the enrollment request.")
    endorsement_hierarchy_qname = bytes.fromhex("4000000b")
    derived_ek_qname = derive_qualified_name(ek_public, endorsement_hierarchy_qname)
    derived_ak_qname = derive_qualified_name(ak_public, derived_ek_qname)
    require(read_regular(ek_qname_path, limit=128) == derived_ek_qname,
            "Physical TPM EK qualified Name does not derive from the endorsement hierarchy and EK Name.")
    require(hmac.compare_digest(ak_public["name"].hex(), request["ak_name"].lower()),
            "Serialized TPM AK public area does not hash to the request AK Name.")
    require(hmac.compare_digest(derived_ak_qname.hex(), request["ak_qualified_name"].lower()),
            "Request AK qualified Name does not derive from its TPM parent EK and AK Name.")
    return read_regular(ek_public_path, limit=8192), read_regular(ak_public_path, limit=8192)


def rsa_components_pem(path, env, scratch):
    der_path = scratch_file(pathlib.Path(path).parent, ".public-key.der")
    scratch.append(der_path)
    der_path.write_bytes(run_checked(
        ["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"], env=env,
    ))
    return parse_rsa_public_der(read_regular(der_path, limit=8192))


def make_credential(args):
    _, request = read_json(args.request)
    validate_request(request)
    challenge_path, challenge_dir = resolve_parent(args.challenge_out)
    state_path, state_dir = resolve_parent(args.state_out)
    require(challenge_dir == state_dir, "Challenge and verifier state must be in the same protected directory.")
    require(challenge_path != state_path, "Challenge and verifier state must use different paths.")
    if os.name != "posix":
        raise Blocked("Creating protected verifier state requires POSIX mode-0600 support.")
    ek_public = validate_ca_and_request(request, args.ca_bundle, args.ca_sha256, challenge_dir)

    secret = secrets.token_bytes(32)
    challenge_id = secrets.token_hex(16)
    scratch = []
    state_created = False
    try:
        secret_path = scratch_file(state_dir, ".secret")
        scratch.append(secret_path)
        secret_path.write_bytes(secret)
        os.chmod(str(secret_path), 0o600)
        ek_path = scratch_file(state_dir, ".ek-public.pem")
        scratch.append(ek_path)
        ek_path.write_bytes(ek_public)
        blob_path = scratch_output_path(state_dir, ".credential")
        scratch.append(blob_path)
        run_checked([
            "tpm2_makecredential", "-G", "rsa", "-u", str(ek_path),
            "-s", str(secret_path), "-n", request["ak_name"], "-o", str(blob_path),
        ], env={**os.environ, "TPM2TOOLS_TCTI": "none"})
        blob = read_regular(blob_path, limit=1024 * 1024)
        require(len(blob) > 0, "TPM MakeCredential returned an empty credential blob.")
        challenge = {
            "_schema": CHALLENGE_SCHEMA,
            "challenge_id": challenge_id,
            **request_identity(request),
            "quote_nonce": secrets.token_hex(32),
            "request_sha256": digest(canonical_json(request)),
            "credential_blob": base64.b64encode(blob).decode("ascii"),
        }
        challenge_bytes = canonical_json(challenge)
        state = {
            "_schema": STATE_SCHEMA,
            "challenge_id": challenge_id,
            "identity": request_identity(request),
            "request_sha256": digest(canonical_json(request)),
            "challenge_sha256": digest(challenge_bytes),
            "secret": base64.b64encode(secret).decode("ascii"),
        }
        create_exclusive(state_path, canonical_json(state), 0o600)
        state_created = True
        create_exclusive(challenge_path, challenge_bytes, 0o600)
    except Exception:
        if state_created:
            remove_files([state_path])
        raise
    finally:
        # Best effort overwrite before unlink; the verifier state is the sole
        # durable copy of the challenge secret.
        for path in scratch:
            if pathlib.Path(path).suffix == ".secret":
                wipe_file(path)
        remove_files(scratch)
    print("MakeCredential challenge created. Transport the challenge JSON; keep verifier state protected.")


def activate_credential(args):
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise Blocked("Activation is permitted only as root on the physical Linux target.")
    device = None
    for candidate in ("/dev/tpmrm0", "/dev/tpm0"):
        try:
            if stat.S_ISCHR(os.lstat(candidate).st_mode):
                device = candidate
                break
        except OSError:
            continue
    if device is None:
        raise Blocked("No physical TPM character device is available; software and network TPMs are refused.")
    _, request = read_json(args.request)
    validate_request(request)
    _, challenge = read_json(args.challenge)
    blob = challenge_binding(request, challenge)

    _, work_dir = resolve_parent(args.challenge)
    scratch = []
    session_started = False
    session_path = None
    try:
        env = {**os.environ, "TPM2TOOLS_TCTI": "device:" + device}
        ek_public_area, ak_public_area = verify_physical_tpm_identity(request, env, work_dir, scratch)
        blob_path = scratch_file(work_dir, ".credential")
        scratch.append(blob_path)
        blob_path.write_bytes(blob)
        session_path = scratch_output_path(work_dir, ".policy-session")
        scratch.append(session_path)
        recovered_path = scratch_output_path(work_dir, ".activated-secret")
        scratch.append(recovered_path)
        run_checked(["tpm2_startauthsession", "--policy-session", "-S", str(session_path)], env=env)
        session_started = True
        run_checked(["tpm2_policysecret", "-S", str(session_path), "-c", "0x4000000B"], env=env)
        run_checked([
            "tpm2_activatecredential", "-c", request["tpm_ak_handle"],
            "-C", request["tpm_ek_handle"], "-i", str(blob_path),
            "-o", str(recovered_path), "-P", "session:" + str(session_path),
        ], env=env)
        recovered = read_regular(recovered_path, limit=64)
        require(len(recovered) == 32, "Activated credential has an invalid size.")
        attest_path = scratch_output_path(work_dir, ".quote-attest")
        signature_path = scratch_output_path(work_dir, ".quote-signature")
        scratch.extend((attest_path, signature_path))
        run_checked([
            "tpm2_quote", "-c", request["tpm_ak_handle"],
            "-l", "sha256:0,4,7,11", "-q", challenge["quote_nonce"],
            "-m", str(attest_path), "-s", str(signature_path), "-g", "sha256",
        ], env=env)
        attest = read_regular(attest_path, limit=4096)
        signature = read_regular(signature_path, limit=4096)
        validate_quote_fields(attest, request, bytes.fromhex(challenge["quote_nonce"]))
        parse_rsassa_sha256_signature(signature)
        response = {
            "_schema": RESPONSE_SCHEMA,
            "challenge_id": challenge["challenge_id"],
            "activation_sha256": hashlib.sha256(recovered).hexdigest(),
            "ek_public_tpm2b_b64": base64.b64encode(ek_public_area).decode("ascii"),
            "ak_public_tpm2b_b64": base64.b64encode(ak_public_area).decode("ascii"),
            "quote_attest_b64": base64.b64encode(attest).decode("ascii"),
            "quote_signature_b64": base64.b64encode(signature).decode("ascii"),
        }
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
    finally:
        if session_started and session_path is not None:
            try:
                run_checked(["tpm2_flushcontext", str(session_path)],
                            env={**os.environ, "TPM2TOOLS_TCTI": "device:" + device})
            except CeremonyError:
                pass
        for path in scratch:
            if pathlib.Path(path).suffix == ".activated-secret":
                wipe_file(path)
        remove_files(scratch)


def verify_pinned_manifest(path, signature_path, public_key_path, key_pin, schema, label, scratch_dir):
    validate_hash(key_pin, label + " public-key pin", nonzero=True)
    manifest_raw = read_regular(path)
    signature = read_regular(signature_path, limit=1024 * 1024)
    public_key = read_regular(public_key_path)
    scratch = []
    try:
        manifest_snapshot = scratch_file(scratch_dir, ".manifest.json")
        signature_snapshot = scratch_file(scratch_dir, ".manifest.sig")
        key_snapshot = scratch_file(scratch_dir, ".registry-public.pem")
        scratch.extend((manifest_snapshot, signature_snapshot, key_snapshot))
        manifest_snapshot.write_bytes(manifest_raw)
        signature_snapshot.write_bytes(signature)
        key_snapshot.write_bytes(public_key)
        key_der = run_checked(["openssl", "pkey", "-pubin", "-in", str(key_snapshot), "-outform", "DER"])
        require(hmac.compare_digest(digest(key_der).lower(), key_pin.lower()),
                "{} public key does not match the external SHA-256 pin.".format(label))
        # Verify the exact bytes that were parsed and checked above.
        run_checked([
            "openssl", "dgst", "-sha256", "-verify", str(key_snapshot),
            "-signature", str(signature_snapshot), str(manifest_snapshot),
        ])
    finally:
        remove_files(scratch)
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"), object_pairs_hook=strict_object)
    except CeremonyError:
        raise
    except (UnicodeError, ValueError):
        fail("{} manifest is not valid UTF-8 JSON.".format(label))
    require(isinstance(manifest, dict) and manifest.get("_schema") == schema and
            manifest.get("environment") == "production" and manifest.get("version") == "1",
            "{} manifest does not use the supported production schema.".format(label))
    return manifest


def approved_release(releases, release_id):
    entries = releases.get("releases")
    require(isinstance(entries, list), "Release manifest has no releases array.")
    matches = [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("release_id") == release_id
    ]
    require(len(matches) == 1, "Release manifest must contain exactly one entry for the requested release.")
    entry = matches[0]
    require(entry.get("approval_status") == "APPROVED_PRODUCTION" and entry.get("revoked") is False,
            "Requested release is not approved for production or is revoked.")
    require(isinstance(entry.get("pcr_bank"), str) and entry["pcr_bank"].lower() == "sha256",
            "Requested release does not use the SHA-256 PCR bank.")
    for field in ("uki_hash", "pcr0", "pcr4", "pcr7", "pcr11"):
        validate_hash(entry.get(field), "release " + field, nonzero=True)


def validate_current_devices(devices):
    entries = devices.get("devices")
    require(isinstance(entries, list), "Device manifest has no devices array.")
    seen_ids = set()
    seen_fingerprints = set()
    allowed_statuses = {"ENROLLED", "TRUSTED", "SUSPENDED", "REVOKED", "RETIRED"}
    for entry in entries:
        require(isinstance(entry, dict), "Device manifest contains a malformed device entry.")
        device_id = entry.get("device_id")
        institution_id = entry.get("institution_id")
        release_id = entry.get("allowed_release")
        require(isinstance(device_id, str) and ID_PATTERN.fullmatch(device_id) is not None,
                "Device manifest contains an invalid device ID.")
        if institution_id is not None:
            require(isinstance(institution_id, str) and ID_PATTERN.fullmatch(institution_id) is not None,
                    "Device manifest contains an invalid institution ID.")
        require(isinstance(release_id, str) and ID_PATTERN.fullmatch(release_id) is not None,
                "Device manifest contains an invalid allowed release.")
        require(isinstance(entry.get("status"), str) and entry["status"] in allowed_statuses,
                "Device manifest contains an unsupported device status.")
        fingerprint = entry.get("ek_fingerprint")
        validate_hash(fingerprint, "device EK fingerprint", nonzero=True)
        validate_hash(entry.get("ak_pub_sha256"), "device AK public-key digest", nonzero=True)
        qualified_name = entry.get("ak_qualified_name")
        require(isinstance(qualified_name, str) and TPM_NAME_PATTERN.fullmatch(qualified_name) is not None,
                "Device manifest contains an invalid AK qualified Name.")
        public_pem = entry.get("ak_public_pem")
        require(isinstance(public_pem, str) and len(public_pem) <= 2047 and
                "-----BEGIN PUBLIC KEY-----" in public_pem,
                "Device manifest contains an invalid AK public key.")
        try:
            public_der = run_checked(
                ["openssl", "pkey", "-pubin", "-outform", "DER"],
                input_data=public_pem.encode("ascii"),
            )
        except UnicodeError:
            fail("Device manifest contains a non-ASCII AK public key.")
        require(hmac.compare_digest(digest(public_der).lower(), entry["ak_pub_sha256"].lower()),
                "Device manifest AK public key does not match its SHA-256 digest.")
        require(device_id not in seen_ids, "Device manifest contains a duplicate device ID.")
        require(fingerprint.lower() not in seen_fingerprints,
                "Device manifest contains a duplicate EK fingerprint.")
        seen_ids.add(device_id)
        seen_fingerprints.add(fingerprint.lower())
    return entries


def approve(args):
    _, request = read_json(args.request)
    validate_request(request)
    _, candidate_dir = resolve_parent(args.candidate_out)
    ek_public_pem = validate_ca_and_request(
        request, args.ca_bundle, args.ca_sha256, candidate_dir
    )
    _, challenge = read_json(args.challenge)
    blob = challenge_binding(request, challenge)
    del blob
    _, state = read_json(args.state, protected=True)
    require(set(state) == {
        "_schema", "challenge_id", "identity", "request_sha256", "challenge_sha256", "secret",
    }, "Protected verifier state contains fields outside its schema.")
    require(state.get("_schema") == STATE_SCHEMA and
            state.get("challenge_id") == challenge["challenge_id"] and
            state.get("identity") == request_identity(request) and
            state.get("request_sha256") == digest(canonical_json(request)) and
            state.get("challenge_sha256") == digest(canonical_json(challenge)),
            "Protected verifier state does not match this request and challenge.")
    try:
        encoded_secret = state.get("secret")
        require(isinstance(encoded_secret, str), "Protected verifier state secret must be base64 text.")
        secret = base64.b64decode(encoded_secret, validate=True)
    except (binascii.Error, ValueError):
        fail("Protected verifier state contains an invalid secret.")
    require(len(secret) == 32, "Protected verifier state has an invalid secret size.")
    _, response = read_json(args.response)
    activation_sha256 = verify_credential_response(
        request, challenge, response, ek_public_pem, candidate_dir
    )
    expected_response = hashlib.sha256(secret).hexdigest()
    require(hmac.compare_digest(expected_response.lower(), activation_sha256.lower()),
            "Activation response does not match the protected verifier state.")

    devices = verify_pinned_manifest(
        args.devices, args.devices_signature, args.devices_public_key,
        args.devices_key_sha256, DEVICE_SCHEMA, "Device registry", candidate_dir,
    )
    releases = verify_pinned_manifest(
        args.releases, args.releases_signature, args.releases_public_key,
        args.releases_key_sha256, RELEASE_SCHEMA, "Release registry", candidate_dir,
    )
    approved_release(releases, request["allowed_release"])
    entries = validate_current_devices(devices)
    for entry in entries:
        existing_id = entry.get("device_id")
        existing_ek = entry.get("ek_fingerprint")
        require(existing_id != request["device_id"], "Device ID already exists in the current registry.")
        require(not (isinstance(existing_ek, str) and
                     existing_ek.lower() == request["ek_fingerprint"].lower()),
                "EK fingerprint already exists in the current registry.")

    candidate = json.loads(json.dumps(devices))
    candidate["devices"].append({
        "institution_id": request["institution_id"],
        "device_id": request["device_id"],
        "ek_fingerprint": request["ek_fingerprint"].lower(),
        "ak_name": request["ak_name"].lower(),
        "ak_qualified_name": request["ak_qualified_name"].lower(),
        "ak_pub_sha256": request["ak_pub_sha256"].lower(),
        "ak_public_pem": request["ak_public_pem"],
        "status": "ENROLLED",
        "allowed_release": request["allowed_release"],
    })
    output_path, _ = resolve_parent(args.candidate_out)
    registration_path, registration_dir = resolve_parent(args.registration_out)
    _, output_dir = resolve_parent(output_path)
    require(output_path != registration_path,
            "Candidate manifest and registration payload must use different paths.")
    require(output_dir == registration_dir,
            "Candidate manifest and registration payload must be in the same protected directory.")
    candidate_created = False
    try:
        create_exclusive(output_path, json.dumps(candidate, indent=2, ensure_ascii=True).encode("ascii") + b"\n")
        candidate_created = True
        registration_payload = {
            "device_id": request["device_id"],
            "institution_id": request["institution_id"],
            "ak_public_key_pem": request["ak_public_pem"],
            "tpm_present": True,
            "tpm_version": "2.0",
        }
        create_exclusive(
            registration_path,
            json.dumps(registration_payload, indent=2, ensure_ascii=True).encode("ascii") + b"\n",
        )
    except Exception:
        if candidate_created:
            remove_files([output_path])
        raise
    print("Unsigned candidate registry created: {}".format(output_path))
    print("Separate admin-session registration payload created: {}".format(registration_path))
    print("Do not trust or deploy this candidate until it is reviewed and signed externally using the organization HSM ceremony.")
    print("No endpoint call or admin bearer token is used; submit the payload through the normal authenticated admin session after signed registry rollout.")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Operator-side offline physical TPM enrollment ceremony. No command signs or overwrites a trusted manifest.",
        epilog="Production registry signing remains an external, dual-control organization HSM operation. Never place production signing keys in this repository, on a device, in CI, or in ordinary files.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    make = commands.add_parser(
        "make-credential",
        help="Verify an enrollment request and pinned EK CA, then write a transportable challenge and separate protected verifier state.",
        description="Creates an RSA TPM MakeCredential challenge. The JSON challenge contains no secret; verifier state is protected mode 0600.",
    )
    make.add_argument("--request", required=True, help="Physical enrollment request JSON.")
    make.add_argument("--ca-bundle", required=True, help="Organization-pinned TPM manufacturer CA bundle.")
    make.add_argument("--ca-sha256", required=True, help="Externally supplied SHA-256 pin for the CA bundle.")
    make.add_argument("--challenge-out", required=True, help="New transportable challenge JSON path; must not exist.")
    make.add_argument("--state-out", required=True, help="New protected verifier-state path; must not exist.")
    make.set_defaults(handler=make_credential)

    activate = commands.add_parser(
        "activate-credential",
        help="On the physical Linux target only, activate a challenge and emit a secret-free activation hash plus AK quote evidence.",
        description="Requires root and /dev/tpmrm0 or /dev/tpm0. Software/network TPMs are refused. Output is structured JSON containing the activation hash, TPM public areas, and quote attest/signature bytes; the secret is never emitted.",
    )
    activate.add_argument("--request", required=True, help="Enrollment request matching the challenge.")
    activate.add_argument("--challenge", required=True, help="Transported challenge JSON.")
    activate.set_defaults(handler=activate_credential)

    approve_parser = commands.add_parser(
        "approve",
        help="Verify evidence and signed production registries, then write an unsigned ENROLLED device-registry candidate.",
        description="Checks verifier state, activation response, EK certificate, manifest signatures and external public-key pins. Writes an unsigned registry candidate and separate minimal API payload; it never signs, sends, or replaces a manifest.",
    )
    approve_parser.add_argument("--request", required=True, help="Physical enrollment request JSON.")
    approve_parser.add_argument("--ca-bundle", required=True, help="Organization-pinned TPM manufacturer CA bundle.")
    approve_parser.add_argument("--ca-sha256", required=True, help="Externally supplied SHA-256 pin for the CA bundle.")
    approve_parser.add_argument("--challenge", required=True, help="Transportable challenge JSON.")
    approve_parser.add_argument("--state", required=True, help="Protected verifier state from make-credential (mode 0600).")
    approve_parser.add_argument("--response", required=True, help="Structured JSON response emitted by activate-credential.")
    approve_parser.add_argument("--devices", required=True, help="Current signed production device registry JSON.")
    approve_parser.add_argument("--devices-signature", required=True, help="Detached SHA-256 signature for current device registry.")
    approve_parser.add_argument("--devices-public-key", required=True, help="Public key used to verify the current device registry.")
    approve_parser.add_argument("--devices-key-sha256", required=True, help="External SHA-256 pin of the device-registry public-key DER.")
    approve_parser.add_argument("--releases", required=True, help="Current signed production release registry JSON.")
    approve_parser.add_argument("--releases-signature", required=True, help="Detached SHA-256 signature for current release registry.")
    approve_parser.add_argument("--releases-public-key", required=True, help="Public key used to verify the current release registry.")
    approve_parser.add_argument("--releases-key-sha256", required=True, help="External SHA-256 pin of the release-registry public-key DER.")
    approve_parser.add_argument("--candidate-out", required=True, help="New unsigned candidate path; existing files are never overwritten.")
    approve_parser.add_argument("--registration-out", required=True, help="New minimal /api/v1/devices/register JSON payload path; existing files are never overwritten.")
    approve_parser.set_defaults(handler=approve)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if os.name == "posix":
            os.umask(0o077)
        args.handler(args)
    except Blocked as error:
        print("BLOCKED: {}".format(error), file=sys.stderr)
        return 2
    except CeremonyError as error:
        print("FAIL: {}".format(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("BLOCKED: interrupted; no manifest was signed or replaced.", file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("FAIL: input or output could not be handled safely.", file=sys.stderr)
        return 1
    except Exception:
        print("FAIL: unexpected ceremony error; no manifest was signed or replaced.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
