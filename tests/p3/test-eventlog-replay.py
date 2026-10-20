#!/usr/bin/env python3
"""Positive and tamper-negative coverage for the narrow TCG2 replayer."""
import hashlib
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[2] / "tools" / "examos-eventlog-replay.py"
SPEC = importlib.util.spec_from_file_location("eventlog", TOOL)
EVENTLOG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVENTLOG)


def spec_header():
    body = b"Spec ID Event03\x00" + b"\x00" * 8
    body += struct.pack("<I", 1) + struct.pack("<HH", 0x000B, 32) + b"\x00"
    return struct.pack("<II", 0, 3) + b"\x00" * 20 + struct.pack("<I", len(body)) + body


def event(pcr, digest, payload=b"x"):
    return (struct.pack("<III", pcr, 0x0000000C, 1) + struct.pack("<H", 0x000B) +
            digest + struct.pack("<I", len(payload)) + payload)


class EventLogReplayTests(unittest.TestCase):
    def test_replays_sha256_extend(self):
        digest = bytes.fromhex("11" * 32)
        state, count = EVENTLOG.replay(spec_header() + event(7, digest))
        self.assertEqual(count, 1)
        self.assertEqual(state["7"], hashlib.sha256(bytes(32) + digest).hexdigest())
        self.assertEqual(state["0"], "00" * 32)

    def test_truncation_fails_closed(self):
        with self.assertRaises(EVENTLOG.ReplayError):
            EVENTLOG.replay(spec_header() + b"\x00")

    def test_missing_sha256_digest_fails_closed(self):
        malformed = spec_header() + struct.pack("<IIIH", 7, 12, 1, 0x0004) + b"\x00" * 20 + struct.pack("<I", 0)
        with self.assertRaises(EVENTLOG.ReplayError):
            EVENTLOG.replay(malformed)


if __name__ == "__main__":
    unittest.main()
