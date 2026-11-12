#!/usr/bin/env python3
"""Isolated tests for the release-provenance foundation; no gate is invoked."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import release_provenance as provenance


class ReleaseProvenanceTests(unittest.TestCase):
    def write(self, directory: Path, name: str, content: bytes) -> Path:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def require_descriptor_access(self):
        if provenance.artifact_access_capability() is not None:
            self.skipTest("descriptor-relative no-follow artifact access is unavailable")

    def test_duplicate_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.write(Path(temp), "manifest.json", b'{"schema_version":"1.0","schema_version":"1.0"}')
            with self.assertRaises(provenance.ProvenanceError) as raised:
                provenance.load_strict_json(path, provenance.MAX_MANIFEST_BYTES)
            self.assertEqual(raised.exception.code, "MANIFEST_INVALID")

    def test_nested_duplicate_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.write(Path(temp), "manifest.json", b'{"nested":{"key":1,"key":2}}')
            with self.assertRaises(provenance.ProvenanceError) as raised:
                provenance.load_strict_json(path, provenance.MAX_MANIFEST_BYTES)
            self.assertEqual(raised.exception.code, "MANIFEST_INVALID")

    def test_invalid_utf8_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.write(Path(temp), "manifest.json", b'\xff')
            with self.assertRaises(provenance.ProvenanceError) as raised:
                provenance.load_strict_json(path, provenance.MAX_MANIFEST_BYTES)
            self.assertEqual(raised.exception.code, "MANIFEST_INVALID")

    def test_surrogate_and_nonfinite_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name, content in (("surrogate.json", b'{"nested":["\\ud800"]}'), ("nonfinite.json", b'{"value":NaN}')):
                with self.subTest(name=name):
                    with self.assertRaises(provenance.ProvenanceError) as raised:
                        provenance.load_strict_json(self.write(directory, name, content), provenance.MAX_MANIFEST_BYTES)
                    self.assertEqual(raised.exception.code, "MANIFEST_INVALID")

    def test_jcs_property_order_and_nested_values(self):
        first = {"z": [None, True, False], "a": {"d": 4.5, "c": "value"}}
        second = {"a": {"c": "value", "d": 4.5}, "z": [None, True, False]}
        expected = b'{"a":{"c":"value","d":4.5},"z":[null,true,false]}'
        self.assertEqual(provenance.canonicalize_jcs(first), expected)
        self.assertEqual(provenance.canonicalize_jcs(second), expected)

    def test_jcs_rfc8785_number_and_string_vector(self):
        source = r'''{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"€$\u000f\nA'B\"\\\"/"}'''
        expected = r'''{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\"/"}'''.encode("utf-8")
        self.assertEqual(provenance.canonicalize_jcs(json.loads(source)), expected)

    def test_jcs_sorts_property_names_by_utf16_code_units(self):
        value = {"\ue000": 2, "\U0001f600": 1}
        self.assertEqual(
            provenance.canonicalize_jcs(value),
            '{"😀":1,"":2}'.encode("utf-8"),
        )

    def test_jcs_rejects_unrepresentable_numbers(self):
        with self.assertRaises(provenance.ProvenanceError) as raised:
            provenance.canonicalize_jcs({"number": 1e400})
        self.assertEqual(raised.exception.code, "MANIFEST_INVALID")

    def test_canonical_digest_hashes_exact_jcs_bytes(self):
        manifest = {"b": 2, "a": 1}
        canonical, digest = provenance.canonical_manifest_digest(manifest)
        self.assertEqual(canonical, b'{"a":1,"b":2}')
        self.assertEqual(digest, "sha256:" + hashlib.sha256(canonical).hexdigest())
        self.assertEqual(
            provenance.canonical_manifest_digest(manifest, "sha384")[1],
            "sha384:" + hashlib.sha384(canonical).hexdigest(),
        )
        with self.assertRaises(provenance.ProvenanceError) as raised:
            provenance.canonical_manifest_digest(manifest, "sha512")
        self.assertEqual(raised.exception.code, "DIGEST_ALGORITHM_UNSUPPORTED")

    def test_legacy_manifest_is_development_only(self):
        decision = provenance.classify_manifest({"_schema": "examos-release-evidence-v1"})
        self.assertEqual(decision.decision, provenance.DecisionKind.DEVELOPMENT)

    def test_unknown_schema_is_rejected_not_legacy(self):
        decision = provenance.classify_manifest({"schema_version": "not-v1"})
        self.assertEqual(decision.decision, provenance.DecisionKind.REJECTED)

    def test_traversal_and_backslash_paths_are_rejected(self):
        for value in ("../outside", "/absolute", "dir\\file", "./relative", "dir//file"):
            with self.assertRaises(provenance.ProvenanceError):
                provenance.normalized_artifact_path(value)

    def test_test_marker_is_not_self_authorizing(self):
        manifest = {"schema_version": "1.0", "test_only": True}
        self.assertIsNone(provenance.classify_manifest(manifest))
        decision = provenance.classify_manifest(manifest, authenticated_test_policy=True)
        self.assertEqual(decision.decision, provenance.DecisionKind.DEVELOPMENT)

    def test_unavailable_safe_descriptor_access_blocks(self):
        with patch.object(provenance.os, "supports_dir_fd", set()):
            decision = provenance.artifact_access_capability()
        self.assertIsNotNone(decision)
        self.assertEqual(decision.decision, provenance.DecisionKind.BLOCKED)

    def test_symlink_artifact_root_is_rejected(self):
        root_metadata = SimpleNamespace(st_mode=provenance.stat.S_IFLNK)
        with patch.object(provenance, "artifact_access_capability", return_value=None), patch.object(Path, "lstat", return_value=root_metadata):
            with self.assertRaises(provenance.ProvenanceError) as raised:
                provenance.open_stable_artifact(Path("release-root"), "image.iso")
        self.assertEqual(raised.exception.code, "ARTIFACT_ROOT_UNTRUSTED")

    def test_file_replacement_during_hashing_is_rejected(self):
        before = SimpleNamespace(st_size=1, st_dev=1, st_ino=1, st_mtime_ns=1, st_ctime_ns=1)
        after = SimpleNamespace(st_size=1, st_dev=1, st_ino=2, st_mtime_ns=1, st_ctime_ns=1)
        with patch.object(provenance.os, "fstat", side_effect=(before, after)), patch.object(provenance.os, "read", side_effect=(b"x", b"")):
            with self.assertRaises(provenance.ProvenanceError) as raised:
                provenance.sha256_file_descriptor(42, 8)
        self.assertEqual(raised.exception.code, "ARTIFACT_ROOT_UNSTABLE")

    def test_artifact_inventory_verifies_exact_stable_files(self):
        self.require_descriptor_access()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            content = b"release artifact"
            self.write(root, "image/release.iso", content)
            inventory = [{
                "role": "installer",
                "path": "image/release.iso",
                "size_bytes": len(content),
                "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
            }]
            verified = provenance.verify_artifact_inventory(root, inventory)
            self.assertEqual(verified[0]["path"], "image/release.iso")
            self.assertEqual(verified[0]["size_bytes"], len(content))

    def test_artifact_inventory_rejects_modified_and_unexpected_files(self):
        self.require_descriptor_access()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write(root, "release.iso", b"modified")
            inventory = [{
                "role": "installer",
                "path": "release.iso",
                "size_bytes": len(b"original"),
                "sha256": "sha256:" + hashlib.sha256(b"original").hexdigest(),
            }]
            with self.assertRaises(provenance.ProvenanceError) as raised:
                provenance.verify_artifact_inventory(root, inventory)
            self.assertEqual(raised.exception.code, "ARTIFACT_DIGEST_MISMATCH")

            inventory[0]["size_bytes"] = len(b"modified")
            inventory[0]["sha256"] = "sha256:" + hashlib.sha256(b"modified").hexdigest()
            self.write(root, "unexpected.txt", b"extra")
            with self.assertRaises(provenance.ProvenanceError) as raised:
                provenance.verify_artifact_inventory(root, inventory)
            self.assertEqual(raised.exception.code, "ARTIFACT_INVENTORY_MISMATCH")

    def test_foundation_cannot_verify_production(self):
        decision = provenance.verify_release()
        self.assertEqual(decision.decision, provenance.DecisionKind.BLOCKED)
        self.assertNotEqual(decision.decision, provenance.DecisionKind.VERIFIED)


if __name__ == "__main__":
    unittest.main()
