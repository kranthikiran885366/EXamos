#!/usr/bin/env python3
"""Strict, verification-only primitives for ExamOS release provenance.

This foundation intentionally cannot return VERIFIED.  Production verification
requires an independently approved JCS dependency, authenticated trust
configuration, and authenticated revocation evidence, none of which are
repository-controlled inputs.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

MAX_MANIFEST_BYTES = 1 << 20
MAX_TRUST_CONFIG_BYTES = 1 << 20
MAX_ARTIFACTS = 32
MAX_EVIDENCE = 16
MAX_TOTAL_HASH_BYTES = 64 << 30


class DecisionKind(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class VerificationState(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass(frozen=True)
class Decision:
    decision: DecisionKind
    verification: VerificationState
    reason_code: str
    diagnostics: tuple[str, ...] = ()


class ProvenanceError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def _reject_constant(value: str) -> None:
    raise ProvenanceError("MANIFEST_INVALID", f"unsupported JSON constant {value!r}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceError("MANIFEST_INVALID", f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_unpaired_surrogates(value: Any) -> None:
    """Reject surrogate code points in every decoded string and object key."""
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ProvenanceError("MANIFEST_INVALID", "JSON contains an unpaired surrogate")
    elif isinstance(value, list):
        for item in value:
            _reject_unpaired_surrogates(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_unpaired_surrogates(key)
            _reject_unpaired_surrogates(item)


def load_strict_json(path: Path, maximum_bytes: int) -> Any:
    """Read bounded UTF-8 JSON while rejecting duplicate keys and non-finite values."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProvenanceError("TRUST_CONFIG_MISSING", f"cannot read {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProvenanceError("MANIFEST_INVALID", f"{path} is not a regular non-symlink file")
    if metadata.st_size > maximum_bytes:
        raise ProvenanceError("MANIFEST_TOO_LARGE", f"{path} exceeds {maximum_bytes} bytes")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvenanceError("MANIFEST_INVALID", f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise ProvenanceError("MANIFEST_INVALID", "top-level JSON value must be an object")
    _reject_unpaired_surrogates(value)
    return value


def canonicalize_jcs(value: Any) -> bytes:
    """Use only the independently approved, pinned RFC 8785 implementation."""
    try:
        import rfc8785  # type: ignore[import-not-found]
    except ImportError as error:
        raise ProvenanceError("JCS_DEPENDENCY_UNAVAILABLE", "approved RFC 8785 dependency is unavailable") from error
    try:
        return rfc8785.dumps(value)
    except Exception as error:  # library-specific canonicalization errors
        raise ProvenanceError("MANIFEST_INVALID", f"JCS canonicalization failed: {error}") from error


def normalized_relative_path(value: str) -> PurePosixPath:
    """Validate one canonical, POSIX-relative path representation."""
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ProvenanceError("ARTIFACT_PATH_INVALID", "artifact path is empty or ambiguously encoded")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ProvenanceError("ARTIFACT_PATH_INVALID", f"unsafe artifact path {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute():
        raise ProvenanceError("ARTIFACT_PATH_INVALID", f"unsafe artifact path {value!r}")
    return path


def normalized_artifact_path(value: str) -> PurePosixPath:
    return normalized_relative_path(value)


def artifact_access_capability() -> Decision | None:
    """Return BLOCKED rather than weakening descriptor-relative no-follow access."""
    required = ("O_NOFOLLOW", "O_DIRECTORY")
    if any(not hasattr(os, name) for name in required) or os.open not in os.supports_dir_fd:
        return Decision(
            DecisionKind.BLOCKED,
            VerificationState.NOT_ATTEMPTED,
            "ARTIFACT_ACCESS_UNAVAILABLE",
            ("descriptor-relative O_NOFOLLOW access is unavailable on this platform",),
        )
    return None


def open_stable_artifact(root: Path, relative_path: str) -> int:
    """Open a regular artifact below a non-symlink root without following links.

    The caller must additionally establish a trusted read-only snapshot. This
    helper deliberately does not infer immutability from ordinary file metadata.
    """
    capability = artifact_access_capability()
    if capability is not None:
        raise ProvenanceError(capability.reason_code, capability.diagnostics[0])
    relative = normalized_relative_path(relative_path)
    root_stat = root.lstat()
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ProvenanceError("ARTIFACT_ROOT_UNTRUSTED", "artifact root is not a non-symlink directory")
    nofollow = os.O_NOFOLLOW
    directory_flag = os.O_DIRECTORY
    current_fd = os.open(root, os.O_RDONLY | directory_flag | nofollow)
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(component, os.O_RDONLY | directory_flag | nofollow, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        artifact_fd = os.open(relative.parts[-1], os.O_RDONLY | nofollow, dir_fd=current_fd)
    finally:
        os.close(current_fd)
    opened = os.fstat(artifact_fd)
    if not stat.S_ISREG(opened.st_mode):
        os.close(artifact_fd)
        raise ProvenanceError("ARTIFACT_PATH_INVALID", "artifact is not a regular file")
    return artifact_fd


def sha256_file_descriptor(fd: int, maximum_bytes: int) -> tuple[int, str]:
    before = os.fstat(fd)
    if before.st_size > maximum_bytes:
        raise ProvenanceError("ARTIFACT_SIZE_MISMATCH", "artifact exceeds configured size limit")
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum_bytes:
            raise ProvenanceError("ARTIFACT_SIZE_MISMATCH", "artifact exceeds configured size limit")
        digest.update(chunk)
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ):
        raise ProvenanceError("ARTIFACT_ROOT_UNSTABLE", "artifact changed while being read")
    return total, digest.hexdigest()


def classify_manifest(manifest: dict[str, Any], *, authenticated_test_policy: bool = False) -> Decision | None:
    """Only the known legacy schema is development material; malformed v1 is rejected."""
    if manifest.get("_schema") == "examos-release-evidence-v1":
        return Decision(DecisionKind.DEVELOPMENT, VerificationState.NOT_ATTEMPTED, "LEGACY_MANIFEST")
    if authenticated_test_policy:
        return Decision(DecisionKind.DEVELOPMENT, VerificationState.NOT_ATTEMPTED, "TEST_MATERIAL_PROHIBITED")
    if manifest.get("schema_version") == "1.0":
        return None
    return Decision(DecisionKind.REJECTED, VerificationState.FAIL, "MANIFEST_INVALID", ("unknown manifest schema",))


def verify_release(**_: Any) -> Decision:
    """Fail closed until external trust and revocation implementations are approved.

    This public entry point exists to prevent later callers from treating the
    foundation as a production verifier before the external prerequisites are
    implemented and independently reviewed.
    """
    return Decision(
        DecisionKind.BLOCKED,
        VerificationState.NOT_ATTEMPTED,
        "REVOCATION_EVIDENCE_MISSING",
        ("production verification is unavailable pending external revocation policy and evidence",),
    )
