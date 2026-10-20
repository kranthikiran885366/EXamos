#!/usr/bin/env python3
"""Replay SHA-256 TCG PCR events from a raw binary firmware event log.

This deliberately implements a narrow, auditable subset: TPM 2 event logs
with a Spec ID Event03 header and SHA-256 digests.  It does not guess PCRs or
accept a hash of the log as proof.  Unsupported formats fail closed so a
release workflow can route them to a reviewed full TCG parser.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

EV_NO_ACTION = 0x00000003
TPM_ALG_SHA256 = 0x000B
PCRS = (0, 4, 7, 11)


class ReplayError(ValueError):
    pass


def take(data, offset, count):
    if count < 0 or offset + count > len(data):
        raise ReplayError("truncated TCG event log")
    return data[offset:offset + count], offset + count


def u32(data, offset):
    raw, offset = take(data, offset, 4)
    return struct.unpack("<I", raw)[0], offset


def replay(data):
    """Return PCR state after replaying supported TCG2 SHA-256 events."""
    offset = 0
    pcr, offset = u32(data, offset)
    event_type, offset = u32(data, offset)
    digest, offset = take(data, offset, 20)  # legacy SHA-1 field
    event_size, offset = u32(data, offset)
    spec_event, offset = take(data, offset, event_size)
    if pcr != 0 or event_type != EV_NO_ACTION or len(digest) != 20:
        raise ReplayError("missing initial Spec ID Event03 record")
    if len(spec_event) < 29 or not spec_event.startswith(b"Spec ID Event03"):
        raise ReplayError("unsupported TPM event-log header")
    digest_count = struct.unpack_from("<I", spec_event, 24)[0]
    cursor = 28
    algorithms = {}
    for _ in range(digest_count):
        if cursor + 4 > len(spec_event):
            raise ReplayError("truncated Spec ID algorithm table")
        alg, size = struct.unpack_from("<HH", spec_event, cursor)
        algorithms[alg] = size
        cursor += 4
    if algorithms.get(TPM_ALG_SHA256) != 32:
        raise ReplayError("TPM event log does not declare SHA-256 bank")

    state = {index: bytes(32) for index in PCRS}
    events = 0
    while offset < len(data):
        event_pcr, offset = u32(data, offset)
        _event_type, offset = u32(data, offset)
        count, offset = u32(data, offset)
        if count > 32:
            raise ReplayError("unreasonable digest count")
        sha256_digest = None
        for _ in range(count):
            alg_raw, offset = take(data, offset, 2)
            alg = struct.unpack("<H", alg_raw)[0]
            if alg not in algorithms:
                raise ReplayError(f"digest algorithm {alg:#x} missing from Spec ID")
            value, offset = take(data, offset, algorithms[alg])
            if alg == TPM_ALG_SHA256:
                sha256_digest = value
        size, offset = u32(data, offset)
        _payload, offset = take(data, offset, size)
        if event_pcr in state:
            if sha256_digest is None:
                raise ReplayError(f"PCR {event_pcr} event has no SHA-256 digest")
            state[event_pcr] = hashlib.sha256(state[event_pcr] + sha256_digest).digest()
        events += 1
    if not events:
        raise ReplayError("event log contains no replayable events")
    return {str(index): value.hex() for index, value in state.items()}, events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-log", required=True, type=Path)
    parser.add_argument("--expect-pcr", action="append", default=[],
                        metavar="INDEX=HEX", help="require a replayed PCR value")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        raw = args.event_log.read_bytes()
        state, event_count = replay(raw)
        expected = {}
        for value in args.expect_pcr:
            index, separator, digest = value.partition("=")
            if not separator or index not in state or len(digest) != 64:
                raise ReplayError("invalid --expect-pcr; use 0|4|7|11=<64 hex>")
            int(digest, 16)
            expected[index] = digest.lower()
        mismatches = {key: {"expected": value, "actual": state[key]}
                      for key, value in expected.items() if state[key] != value}
        result = {"status": "PASS" if not mismatches else "FAIL",
                  "event_count": event_count,
                  "event_log_sha256": hashlib.sha256(raw).hexdigest(),
                  "pcr_sha256": state,
                  "mismatches": mismatches}
    except (OSError, ReplayError, ValueError) as exc:
        result = {"status": "FAIL", "error": str(exc)}
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
