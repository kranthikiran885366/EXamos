#!/usr/bin/env python3
"""Isolated tests for the release-provenance foundation; no gate is invoked."""
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
        path.write_bytes(content)
        return path

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

    def test_foundation_cannot_verify_production(self):
        decision = provenance.verify_release()
        self.assertEqual(decision.decision, provenance.DecisionKind.BLOCKED)
        self.assertNotEqual(decision.decision, provenance.DecisionKind.VERIFIED)


if __name__ == "__main__":
    unittest.main()
