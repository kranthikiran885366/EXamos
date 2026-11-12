#!/usr/bin/env python3
"""Tests for the non-production KMS signing workflow using ephemeral keys."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import nonprod_signing as signing


class FakeKms:
    def __init__(self):
        self.region = "ap-south-1"
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.key_id = "12345678-1234-1234-1234-123456789abc"
        self.key_arn = (
            "arn:aws:kms:ap-south-1:123456789012:key/" + self.key_id
        )
        self.key_spec = "ECC_NIST_P256"
        self.public_der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.expected_fingerprint = signing._fingerprint(self.public_der)
        self.tags = {
            "Environment": "nonproduction",
            "Purpose": "release-signing",
        }
        self.sign_count = 0
        self.corrupt_signature = False

    def identity(self):
        return {"Account": "123456789012"}

    def describe_key(self, alias):
        self.alias = alias
        return {
            "KeyId": self.key_id,
            "Arn": self.key_arn,
            "KeyState": "Enabled",
            "Enabled": True,
            "KeyManager": "CUSTOMER",
            "Origin": "AWS_KMS",
            "KeyUsage": "SIGN_VERIFY",
            "KeySpec": self.key_spec,
        }

    def aliases_for_key(self, key_id):
        return [{"AliasName": self.alias, "TargetKeyId": key_id}]

    def tags_for_key(self, key_id):
        return dict(self.tags)

    def public_key(self, key_id):
        return {
            "KeyId": key_id,
            "KeySpec": "ECC_NIST_P256",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["ECDSA_SHA_256"],
            "PublicKey": base64.b64encode(self.public_der).decode("ascii"),
        }

    def sign(self, key_id, message):
        self.sign_count += 1
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return b"invalid-signature" if self.corrupt_signature else signature


def make_ca_pem_and_fingerprint():
    private_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SPPIO test root")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return pem, hashlib.sha256(der).hexdigest()


def make_feed():
    pem, root_fingerprint = make_ca_pem_and_fingerprint()
    now = int(datetime.now(timezone.utc).timestamp())
    return {
        "schema": "sppio-tpm-trust-feed-v1",
        "authority_id": "sppio-nonprod-test",
        "sequence": 1,
        "issued_at": now - 1,
        "expires_at": now + 300,
        "ek_roots": [{
            "id": "test-root",
            "pem": pem,
            "sha256": root_fingerprint,
        }],
        "revoked_device_ids": ["test-device"],
        "revoked_ek_fingerprints": ["1" * 64],
    }


class NonprodSigningTests(unittest.TestCase):
    def test_release_manifest_is_jcs_canonical_and_independently_verified(self):
        kms = FakeKms()
        raw = b'{"schema_version":"1.0","z":2,"a":1}'
        parsed = signing._parse_object(raw, "test manifest")
        bundle = signing.create_bundle(
            "release", raw, parsed, kms.expected_fingerprint, kms
        )
        canonical = b'{"a":1,"schema_version":"1.0","z":2}'
        self.assertEqual(base64.b64decode(bundle["payload_base64"]), canonical)
        self.assertEqual(
            bundle["payload_digest"],
            "sha256:" + hashlib.sha256(canonical).hexdigest(),
        )
        self.assertEqual(bundle["canonicalization"], "RFC8785")
        self.assertEqual(signing.verify_bundle(bundle, kms.expected_fingerprint)["signature"], "VALID")
        self.assertEqual(kms.sign_count, 1)

    def test_trust_feed_is_signed_as_exact_domain_separated_bytes(self):
        kms = FakeKms()
        kms.tags["Purpose"] = "tpm-trust-feed"
        feed = make_feed()
        raw = json.dumps(feed, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        bundle = signing.create_bundle(
            "trust-feed", raw, feed, kms.expected_fingerprint, kms
        )
        self.assertEqual(bundle["canonicalization"], "exact-bytes-domain-separated")
        self.assertEqual(base64.b64decode(bundle["payload_base64"]), raw)
        self.assertEqual(signing.verify_bundle(bundle, kms.expected_fingerprint)["signature"], "VALID")

    def test_wrong_independent_pin_fails_before_signing(self):
        kms = FakeKms()
        raw = b'{"schema_version":"1.0"}'
        with self.assertRaisesRegex(signing.SigningError, "independently provisioned fingerprint"):
            signing.create_bundle(
                "release", raw, signing._parse_object(raw, "manifest"),
                "sha256:" + "0" * 64, kms,
            )
        self.assertEqual(kms.sign_count, 0)

    def test_production_or_unscoped_key_is_rejected(self):
        kms = FakeKms()
        kms.tags["Environment"] = "production"
        raw = b'{"schema_version":"1.0"}'
        with self.assertRaisesRegex(signing.SigningError, "purpose tags"):
            signing.create_bundle(
                "release", raw, signing._parse_object(raw, "manifest"),
                kms.expected_fingerprint, kms,
            )
        self.assertEqual(kms.sign_count, 0)

    def test_bad_kms_signature_is_rejected(self):
        kms = FakeKms()
        kms.corrupt_signature = True
        raw = b'{"schema_version":"1.0"}'
        with self.assertRaisesRegex(signing.SigningError, "independent local verification"):
            signing.create_bundle(
                "release", raw, signing._parse_object(raw, "manifest"),
                kms.expected_fingerprint, kms,
            )

    def test_modified_bundle_payload_is_rejected(self):
        kms = FakeKms()
        raw = b'{"schema_version":"1.0","value":1}'
        bundle = signing.create_bundle(
            "release", raw, signing._parse_object(raw, "manifest"),
            kms.expected_fingerprint, kms,
        )
        bundle["payload_base64"] = base64.b64encode(b'{"schema_version":"1.0","value":2}').decode()
        with self.assertRaisesRegex(signing.SigningError, "payload digest"):
            signing.verify_bundle(bundle, kms.expected_fingerprint)

    def test_duplicate_json_keys_and_invalid_feed_schema_are_rejected(self):
        with self.assertRaisesRegex(signing.SigningError, "duplicate JSON key"):
            signing._parse_object(b'{"schema_version":"1.0","schema_version":"1.0"}', "manifest")

        feed = make_feed()
        feed["unexpected"] = True
        with self.assertRaisesRegex(signing.SigningError, "unsupported schema or fields"):
            signing._validate_feed(feed)

    def test_wrong_purpose_tag_is_rejected(self):
        kms = FakeKms()
        kms.tags["Purpose"] = "tpm-trust-feed"
        raw = b'{"schema_version":"1.0"}'
        with self.assertRaisesRegex(signing.SigningError, "purpose tags"):
            signing.create_bundle(
                "release", raw, signing._parse_object(raw, "manifest"),
                kms.expected_fingerprint, kms,
            )

    def test_symmetric_key_is_rejected_before_signing(self):
        kms = FakeKms()
        kms.key_spec = "SYMMETRIC_DEFAULT"
        raw = b'{"schema_version":"1.0"}'
        with self.assertRaisesRegex(signing.SigningError, "P-256 signing key"):
            signing.create_bundle(
                "release", raw, signing._parse_object(raw, "manifest"),
                kms.expected_fingerprint, kms,
            )
        self.assertEqual(kms.sign_count, 0)

    def test_expired_feed_is_rejected_before_signing(self):
        feed = make_feed()
        feed["issued_at"] -= 600
        feed["expires_at"] -= 300
        with self.assertRaisesRegex(signing.SigningError, "not currently valid"):
            signing._validate_feed(feed)

    def test_cli_sign_and_verify_round_trip(self):
        kms = FakeKms()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "manifest.json"
            bundle_path = root / "signature.json"
            source.write_bytes(b'{"schema_version":"1.0","value":1}')
            with patch.object(signing, "AwsKms", return_value=kms):
                with contextlib.redirect_stdout(io.StringIO()):
                    sign_result = signing.main([
                        "sign-release",
                        "--input", str(source),
                        "--output", str(bundle_path),
                        "--expected-fingerprint", kms.expected_fingerprint,
                        "--region", "ap-south-1",
                    ])
                    verify_result = signing.main([
                        "verify",
                        "--bundle", str(bundle_path),
                        "--expected-fingerprint", kms.expected_fingerprint,
                    ])
            self.assertEqual(sign_result, 0)
            self.assertEqual(verify_result, 0)
            self.assertEqual(kms.sign_count, 1)


if __name__ == "__main__":
    unittest.main()
