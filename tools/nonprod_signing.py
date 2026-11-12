#!/usr/bin/env python3
"""Non-production AWS KMS signing for release manifests and TPM trust feeds."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import BasicConstraints, ExtensionNotFound, load_pem_x509_certificate

import release_provenance

MAX_INPUT_BYTES = 1 << 20
FEED_DOMAIN = b"SPPIO-TPM-TRUST-FEED-V1\n"
SIGNATURE_ALGORITHM = "ecdsa-p256-sha256"
KMS_SIGNING_ALGORITHM = "ECDSA_SHA_256"
FINGERPRINT_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,63}\Z")

PURPOSES = {
    "release": {
        "alias": "alias/examos-nonprod-release-signing",
        "tag": "release-signing",
        "bundle_purpose": "release-manifest",
    },
    "trust-feed": {
        "alias": "alias/examos-nonprod-tpm-trust-feed",
        "tag": "tpm-trust-feed",
        "bundle_purpose": "tpm-trust-feed",
    },
}

BUNDLE_FIELDS = {
    "schema",
    "environment",
    "purpose",
    "key_alias",
    "key_arn",
    "signature_algorithm",
    "canonicalization",
    "payload_base64",
    "payload_digest",
    "signature_base64",
    "public_key_pem",
    "public_key_fingerprint",
}


class SigningError(ValueError):
    """A non-production signing or verification step failed closed."""


def _reject_constant(value: str) -> None:
    raise SigningError(f"unsupported JSON constant {value!r}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SigningError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_surrogates(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise SigningError("JSON contains an unpaired surrogate")
    elif isinstance(value, list):
        for item in value:
            _reject_surrogates(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_surrogates(key)
            _reject_surrogates(item)


def _parse_object(data: bytes, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise SigningError(f"{description} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise SigningError(f"{description} must be a JSON object")
    _reject_surrogates(value)
    return value


def _read_stable_json(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        before = path.lstat()
    except OSError as error:
        raise SigningError(f"cannot inspect input {path}: {error}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SigningError("input must be a regular, non-symlink file")
    if before.st_size <= 0 or before.st_size > MAX_INPUT_BYTES:
        raise SigningError(f"input size must be between 1 and {MAX_INPUT_BYTES} bytes")
    try:
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise SigningError(f"cannot read input {path}: {error}") from error
    if (
        len(raw) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise SigningError("input changed while it was being read")
    return raw, _parse_object(raw, str(path))


def _validate_feed(feed: dict[str, Any]) -> None:
    required = {
        "schema",
        "authority_id",
        "sequence",
        "issued_at",
        "expires_at",
        "ek_roots",
        "revoked_device_ids",
        "revoked_ek_fingerprints",
    }
    if set(feed) != required or feed.get("schema") != "sppio-tpm-trust-feed-v1":
        raise SigningError("TPM trust feed has an unsupported schema or fields")
    authority = feed.get("authority_id")
    if not isinstance(authority, str) or not IDENTIFIER_PATTERN.fullmatch(authority):
        raise SigningError("TPM trust feed authority_id is invalid")
    for field in ("sequence", "issued_at", "expires_at"):
        if (
            type(feed.get(field)) is not int
            or feed[field] <= 0
            or feed[field] > 0xFFFFFFFFFFFFFFFF
        ):
            raise SigningError(f"TPM trust feed {field} must be a positive integer")
    if feed["expires_at"] <= feed["issued_at"]:
        raise SigningError("TPM trust feed expires_at must follow issued_at")
    now = int(time.time())
    if feed["issued_at"] > now + 60 or feed["expires_at"] <= now:
        raise SigningError("TPM trust feed is not currently valid")

    roots = feed.get("ek_roots")
    if not isinstance(roots, list) or not roots or len(roots) > 32:
        raise SigningError("TPM trust feed must contain 1 to 32 EK roots")
    seen_root_ids: set[str] = set()
    seen_root_fingerprints: set[str] = set()
    for root in roots:
        if not isinstance(root, dict) or set(root) != {"id", "pem", "sha256"}:
            raise SigningError("each TPM trust feed EK root must contain id, pem, and sha256")
        root_id, pem, fingerprint = root["id"], root["pem"], root["sha256"]
        if not isinstance(root_id, str) or not IDENTIFIER_PATTERN.fullmatch(root_id):
            raise SigningError("TPM trust feed EK root id is invalid")
        if root_id in seen_root_ids:
            raise SigningError("TPM trust feed EK root IDs must be unique")
        if not isinstance(pem, str) or not pem.isascii():
            raise SigningError("TPM trust feed EK root PEM must be ASCII")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise SigningError("TPM trust feed EK root fingerprint is invalid")
        if fingerprint in seen_root_fingerprints:
            raise SigningError("TPM trust feed EK root fingerprints must be unique")
        try:
            certificate = load_pem_x509_certificate(pem.encode("ascii"))
            constraints = certificate.extensions.get_extension_for_class(BasicConstraints).value
        except (ValueError, UnicodeEncodeError, UnsupportedAlgorithm) as error:
            raise SigningError("TPM trust feed EK root is not a valid certificate") from error
        except ExtensionNotFound as error:
            raise SigningError("TPM trust feed EK root lacks basic constraints") from error
        if not constraints.ca:
            raise SigningError("TPM trust feed EK root certificate is not a CA")
        certificate_now = datetime.now(timezone.utc)
        if (
            certificate.not_valid_before_utc > certificate_now
            or certificate.not_valid_after_utc <= certificate_now
        ):
            raise SigningError("TPM trust feed EK root certificate is not currently valid")
        actual_fingerprint = hashlib.sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        if actual_fingerprint != fingerprint:
            raise SigningError("TPM trust feed EK root fingerprint does not match its certificate")
        seen_root_ids.add(root_id)
        seen_root_fingerprints.add(fingerprint)

    revoked_devices = feed.get("revoked_device_ids")
    if not isinstance(revoked_devices, list) or len(revoked_devices) > 128:
        raise SigningError("TPM trust feed revoked_device_ids is invalid")
    if any(not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value)
           for value in revoked_devices):
        raise SigningError("TPM trust feed contains an invalid revoked device ID")
    if len(set(revoked_devices)) != len(revoked_devices):
        raise SigningError("TPM trust feed revoked device IDs must be unique")

    revoked_eks = feed.get("revoked_ek_fingerprints")
    if not isinstance(revoked_eks, list) or len(revoked_eks) > 128:
        raise SigningError("TPM trust feed revoked_ek_fingerprints is invalid")
    if any(
        not isinstance(value, str)
        or not re.fullmatch(r"[0-9a-f]{64}", value)
        or value == "0" * 64
        for value in revoked_eks
    ):
        raise SigningError("TPM trust feed contains an invalid revoked EK fingerprint")
    if len(set(revoked_eks)) != len(revoked_eks):
        raise SigningError("TPM trust feed revoked EK fingerprints must be unique")


class AwsKms:
    def __init__(self, region: str, profile: str | None = None):
        self.region = region
        self.profile = profile

    def _run_json(self, arguments: list[str]) -> dict[str, Any]:
        command = ["aws", *arguments, "--region", self.region, "--output", "json"]
        if self.profile:
            command.extend(["--profile", self.profile])
        environment = os.environ.copy()
        environment.update({
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_MAX_ATTEMPTS": "1",
            "AWS_PAGER": "",
        })
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                env=environment,
            )
        except FileNotFoundError as error:
            raise SigningError("AWS CLI is not installed or is not on PATH") from error
        except subprocess.TimeoutExpired as error:
            raise SigningError("AWS CLI request timed out") from error
        except OSError as error:
            raise SigningError(f"AWS CLI could not run: {error}") from error
        if result.returncode != 0:
            operation = " ".join(arguments[:2])
            raise SigningError(f"AWS CLI {operation} failed with exit code {result.returncode}")
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SigningError("AWS CLI returned invalid JSON") from error
        if not isinstance(response, dict):
            raise SigningError("AWS CLI returned an unexpected response")
        return response

    def identity(self) -> dict[str, Any]:
        return self._run_json(["sts", "get-caller-identity"])

    def describe_key(self, alias: str) -> dict[str, Any]:
        response = self._run_json(["kms", "describe-key", "--key-id", alias])
        metadata = response.get("KeyMetadata")
        if not isinstance(metadata, dict):
            raise SigningError("KMS did not return key metadata")
        return metadata

    def tags_for_key(self, key_id: str) -> dict[str, str]:
        response = self._run_json(["kms", "list-resource-tags", "--key-id", key_id])
        tags = response.get("Tags")
        if not isinstance(tags, list):
            raise SigningError("KMS did not return key tags")
        return {
            entry["TagKey"]: entry["TagValue"]
            for entry in tags
            if isinstance(entry, dict)
            and isinstance(entry.get("TagKey"), str)
            and isinstance(entry.get("TagValue"), str)
        }

    def public_key(self, key_id: str) -> dict[str, Any]:
        return self._run_json(["kms", "get-public-key", "--key-id", key_id])

    def sign(self, key_id: str, message: bytes) -> bytes:
        with tempfile.TemporaryDirectory(prefix="sppio-kms-sign-") as directory:
            message_path = Path(directory) / "message.bin"
            try:
                message_path.write_bytes(message)
            except OSError as error:
                raise SigningError(f"could not stage message for AWS KMS: {error}") from error
            response = self._run_json([
                "kms",
                "sign",
                "--key-id",
                key_id,
                "--message",
                f"fileb://{message_path.as_posix()}",
                "--message-type",
                "RAW",
                "--signing-algorithm",
                KMS_SIGNING_ALGORITHM,
            ])
        signature = response.get("Signature")
        if not isinstance(signature, str):
            raise SigningError("AWS KMS did not return a signature")
        try:
            return base64.b64decode(signature, validate=True)
        except ValueError as error:
            raise SigningError("AWS KMS returned an invalid signature encoding") from error


def _public_key_der(response: dict[str, Any], key_id: str) -> bytes:
    algorithms = response.get("SigningAlgorithms")
    if (
        response.get("KeyId") != key_id
        or response.get("KeySpec") != "ECC_NIST_P256"
        or response.get("KeyUsage") != "SIGN_VERIFY"
        or not isinstance(algorithms, list)
        or KMS_SIGNING_ALGORITHM not in algorithms
    ):
        raise SigningError("KMS public key metadata does not match the non-production signing policy")
    encoded = response.get("PublicKey")
    if not isinstance(encoded, str):
        raise SigningError("KMS did not return public key material")
    try:
        return base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise SigningError("KMS returned invalid public key encoding") from error


def _fingerprint(public_der: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_der).hexdigest()


def _load_p256_public_key(public_der: bytes) -> ec.EllipticCurvePublicKey:
    try:
        public_key = serialization.load_der_public_key(public_der)
    except (ValueError, UnsupportedAlgorithm) as error:
        raise SigningError("KMS returned an invalid DER public key") from error
    if (
        not isinstance(public_key, ec.EllipticCurvePublicKey)
        or not isinstance(public_key.curve, ec.SECP256R1)
    ):
        raise SigningError("KMS public key is not ECDSA P-256")
    return public_key


def _message_for_payload(purpose: str, payload: bytes, data: dict[str, Any]) -> tuple[bytes, str]:
    if purpose == "release":
        if data.get("schema_version") != "1.0":
            raise SigningError("release manifest must use schema_version 1.0")
        try:
            canonical = release_provenance.canonicalize_jcs(data)
        except release_provenance.ProvenanceError as error:
            raise SigningError(f"release manifest cannot be canonicalized: {error}") from error
        return canonical, "RFC8785"
    _validate_feed(data)
    return payload, "exact-bytes-domain-separated"


def _signing_message(purpose: str, payload: bytes) -> bytes:
    return FEED_DOMAIN + payload if purpose == "trust-feed" else payload


def _validate_key(
    kms: AwsKms,
    purpose: str,
    expected_fingerprint: str,
) -> tuple[dict[str, Any], bytes]:
    if (
        not isinstance(expected_fingerprint, str)
        or not FINGERPRINT_PATTERN.fullmatch(expected_fingerprint)
    ):
        raise SigningError("an independently provisioned sha256 public-key fingerprint is required")
    purpose_config = PURPOSES[purpose]
    alias = purpose_config["alias"]
    identity = kms.identity()
    account = identity.get("Account")
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
        raise SigningError("AWS STS did not return a valid account ID")

    metadata = kms.describe_key(alias)
    key_id, key_arn = metadata.get("KeyId"), metadata.get("Arn")
    arn_parts = key_arn.split(":") if isinstance(key_arn, str) else []
    if (
        metadata.get("KeyState") != "Enabled"
        or metadata.get("Enabled") is not True
        or metadata.get("KeyManager") != "CUSTOMER"
        or metadata.get("Origin") != "AWS_KMS"
        or metadata.get("KeyUsage") != "SIGN_VERIFY"
        or metadata.get("KeySpec") != "ECC_NIST_P256"
        or not isinstance(key_id, str)
        or len(arn_parts) != 6
        or arn_parts[2] != "kms"
        or arn_parts[3] != kms.region
        or arn_parts[4] != account
        or arn_parts[5] != f"key/{key_id}"
    ):
        raise SigningError("KMS key is not an enabled same-account non-production P-256 signing key")
    tags = kms.tags_for_key(key_id)
    if (
        tags.get("Environment") != "nonproduction"
        or tags.get("Purpose") != purpose_config["tag"]
    ):
        raise SigningError("KMS key is missing the required non-production purpose tags")

    public_response = kms.public_key(key_id)
    public_der = _public_key_der(public_response, key_id)
    public_key = _load_p256_public_key(public_der)
    actual_fingerprint = _fingerprint(public_der)
    if actual_fingerprint != expected_fingerprint:
        raise SigningError("KMS public key does not match the independently provisioned fingerprint")
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return {
        "key_id": key_id,
        "key_arn": key_arn,
        "key_alias": alias,
        "public_key_pem": public_pem,
        "public_key_fingerprint": actual_fingerprint,
    }, public_der


def create_bundle(
    purpose: str,
    payload: bytes,
    parsed_payload: dict[str, Any],
    expected_fingerprint: str,
    kms: AwsKms,
) -> dict[str, Any]:
    if not isinstance(purpose, str) or purpose not in PURPOSES:
        raise SigningError("only non-production release or TPM trust-feed signing is supported")
    if _parse_object(payload, "signing payload") != parsed_payload:
        raise SigningError("signing payload bytes do not match their parsed JSON object")
    signed_payload, canonicalization = _message_for_payload(purpose, payload, parsed_payload)
    context, public_der = _validate_key(kms, purpose, expected_fingerprint)
    message = _signing_message(purpose, signed_payload)
    signature = kms.sign(context["key_id"], message)
    try:
        _load_p256_public_key(public_der).verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError) as error:
        raise SigningError("independent local verification rejected the AWS KMS signature") from error
    return {
        "schema": "sppio-nonproduction-signature-v1",
        "environment": "nonproduction",
        "purpose": PURPOSES[purpose]["bundle_purpose"],
        "key_alias": context["key_alias"],
        "key_arn": context["key_arn"],
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "canonicalization": canonicalization,
        "payload_base64": base64.b64encode(signed_payload).decode("ascii"),
        "payload_digest": "sha256:" + hashlib.sha256(signed_payload).hexdigest(),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "public_key_pem": context["public_key_pem"],
        "public_key_fingerprint": context["public_key_fingerprint"],
    }


def verify_bundle(bundle: dict[str, Any], expected_fingerprint: str) -> dict[str, str]:
    if set(bundle) != BUNDLE_FIELDS:
        raise SigningError("signature bundle has unknown or missing fields")
    if bundle.get("schema") != "sppio-nonproduction-signature-v1":
        raise SigningError("signature bundle schema is unsupported")
    if bundle.get("environment") != "nonproduction":
        raise SigningError("production or unspecified signing bundles are not accepted")
    purpose = bundle.get("purpose")
    purpose_config = next(
        (config for config in PURPOSES.values() if config["bundle_purpose"] == purpose),
        None,
    )
    if purpose_config is None or bundle.get("key_alias") != purpose_config["alias"]:
        raise SigningError("signature bundle purpose or non-production alias is invalid")
    if bundle.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        raise SigningError("signature bundle algorithm is unsupported")
    canonicalization = bundle.get("canonicalization")
    if not isinstance(canonicalization, str) or canonicalization not in {
        "RFC8785",
        "exact-bytes-domain-separated",
    }:
        raise SigningError("signature bundle canonicalization is unsupported")
    if canonicalization == "RFC8785" and purpose != "release-manifest":
        raise SigningError("RFC 8785 bytes are only valid for release manifests")
    if canonicalization == "exact-bytes-domain-separated" and purpose != "tpm-trust-feed":
        raise SigningError("domain-separated bytes are only valid for TPM trust feeds")

    if not isinstance(expected_fingerprint, str) or not FINGERPRINT_PATTERN.fullmatch(expected_fingerprint):
        raise SigningError("an independently provisioned sha256 public-key fingerprint is required")
    if bundle.get("public_key_fingerprint") != expected_fingerprint:
        raise SigningError("bundle public key does not match the independent fingerprint")
    key_arn = bundle.get("key_arn")
    if not isinstance(key_arn, str) or ":key/" not in key_arn:
        raise SigningError("signature bundle KMS key ARN is invalid")
    arn_parts = key_arn.split(":")
    if (
        len(arn_parts) != 6
        or arn_parts[0] != "arn"
        or arn_parts[1] != "aws"
        or arn_parts[2] != "kms"
        or not re.fullmatch(r"[a-z0-9-]+", arn_parts[3])
        or not re.fullmatch(r"[0-9]{12}", arn_parts[4])
        or not arn_parts[5].startswith("key/")
    ):
        raise SigningError("signature bundle KMS key ARN is invalid")

    if not isinstance(bundle["public_key_pem"], str):
        raise SigningError("signature bundle public key is invalid")
    try:
        payload = base64.b64decode(bundle["payload_base64"], validate=True)
        signature = base64.b64decode(bundle["signature_base64"], validate=True)
        public_pem = bundle["public_key_pem"].encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise SigningError("signature bundle contains invalid base64 or public-key data") from error
    if not 8 <= len(signature) <= 72:
        raise SigningError("signature bundle contains an invalid ECDSA signature length")
    expected_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if expected_digest != bundle.get("payload_digest"):
        raise SigningError("signature bundle payload digest does not match")
    data = _parse_object(payload, "signature bundle payload")
    if purpose == "release-manifest":
        if data.get("schema_version") != "1.0":
            raise SigningError("release manifest must use schema_version 1.0")
        try:
            if release_provenance.canonicalize_jcs(data) != payload:
                raise SigningError("release payload is not RFC 8785 canonical JSON")
        except release_provenance.ProvenanceError as error:
            raise SigningError(f"release payload cannot be canonicalized: {error}") from error
        message = payload
    else:
        _validate_feed(data)
        message = FEED_DOMAIN + payload

    try:
        public_key = serialization.load_pem_public_key(public_pem)
    except ValueError as error:
        raise SigningError("signature bundle public key is invalid") from error
    if (
        not isinstance(public_key, ec.EllipticCurvePublicKey)
        or not isinstance(public_key.curve, ec.SECP256R1)
    ):
        raise SigningError("signature bundle public key is not ECDSA P-256")
    actual_fingerprint = _fingerprint(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    if actual_fingerprint != expected_fingerprint:
        raise SigningError("signature bundle public key does not match the independent fingerprint")
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as error:
        raise SigningError("signature bundle signature is invalid") from error
    return {
        "purpose": purpose,
        "key_arn": key_arn,
        "payload_digest": bundle["payload_digest"],
        "signature": "VALID",
    }


def _write_bundle(path: Path, bundle: dict[str, Any]) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(bundle, output, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            output.write("\n")
    except FileExistsError as error:
        raise SigningError(f"output already exists: {path}") from error
    except OSError as error:
        raise SigningError(f"cannot write signature bundle {path}: {error}") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("sign-release", "sign-trust-feed"):
        command = subparsers.add_parser(name)
        command.add_argument("--input", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--expected-fingerprint", required=True)
        command.add_argument("--region", required=True)
        command.add_argument("--profile")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--expected-fingerprint", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "verify":
            _, bundle = _read_stable_json(arguments.bundle)
            result = verify_bundle(bundle, arguments.expected_fingerprint)
            print(json.dumps(result, sort_keys=True))
            return 0

        payload, parsed_payload = _read_stable_json(arguments.input)
        purpose = "release" if arguments.command == "sign-release" else "trust-feed"
        kms = AwsKms(arguments.region, arguments.profile)
        bundle = create_bundle(
            purpose,
            payload,
            parsed_payload,
            arguments.expected_fingerprint,
            kms,
        )
        _write_bundle(arguments.output, bundle)
        print(json.dumps({
            "status": "signed-and-independently-verified",
            "purpose": bundle["purpose"],
            "key_arn": bundle["key_arn"],
            "public_key_fingerprint": bundle["public_key_fingerprint"],
            "output": str(arguments.output),
        }, sort_keys=True))
        return 0
    except (SigningError, release_provenance.ProvenanceError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
