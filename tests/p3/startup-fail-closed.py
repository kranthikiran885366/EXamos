#!/usr/bin/env python3
"""Exercise required server secrets, explicit TPM mode, and trust registries."""

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SERVER = Path(__file__).resolve().parents[2] / "server" / "examos-server"
SECRET_NAMES = (
    "EXAMOS_AGENT_API_TOKEN",
    "EXAMOS_PROCTOR_API_TOKEN",
    "EXAMOS_EVENT_SIGNING_KEY",
    "EXAMOS_VARIANT_SECRET",
)
PRODUCTION_LEDGER_KEY = "EXAMOS_LEDGER_HMAC_KEY"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    if not SERVER.is_file():
        raise SystemExit(f"FAIL: server binary is missing: {SERVER}")

    with tempfile.TemporaryDirectory(prefix="examos-startup-guard-") as temp:
        root = Path(temp)
        devices = root / "devices.json"
        releases = root / "releases.json"
        devices.write_text(json.dumps({"devices": [{
            "device_id": "startup-guard-test",
            "ek_fingerprint": secrets.token_hex(32),
            "allowed_release": "startup-guard-release",
        }]}), encoding="utf-8")
        releases.write_text(json.dumps({"releases": [{
            "release_id": "startup-guard-release",
            "uki_hash": secrets.token_hex(32),
            "pcr0": secrets.token_hex(32),
            "pcr4": secrets.token_hex(32),
            "pcr7": secrets.token_hex(32),
            "pcr11": secrets.token_hex(32),
            "revoked": False,
        }]}), encoding="utf-8")

        base = os.environ.copy()
        base.update({
            "EXAMOS_TPM_MODE": "development",
            "EXAMOS_DEVICES_CONFIG": str(devices),
            "EXAMOS_RELEASES_CONFIG": str(releases),
            "EXAMOS_LEDGER_PATH": str(root / "ledger.log"),
            "EXAMOS_SESSION_JOURNAL": str(root / "session_journal.log"),
        })
        for name in SECRET_NAMES:
            base[name] = secrets.token_hex(32)
        base[PRODUCTION_LEDGER_KEY] = secrets.token_hex(32)

        def expect_rejected(label, env, message):
            env["EXAMOS_SERVER_PORT"] = str(free_port())
            try:
                result = subprocess.run(
                    [str(SERVER)], env=env, capture_output=True, text=True,
                    timeout=5, check=False,
                )
            except subprocess.TimeoutExpired:
                raise SystemExit(f"FAIL: {label} did not terminate promptly")
            output = result.stdout + result.stderr
            if result.returncode == 0 or message not in output:
                raise SystemExit(f"FAIL: {label} was not rejected as expected")
            print(f"PASS: {label}")

        for name in SECRET_NAMES:
            missing = base.copy()
            missing.pop(name)
            expect_rejected(f"missing {name}", missing, name)
            short = base.copy()
            short[name] = "short"
            expect_rejected(f"short {name}", short, name)

        for mode in (None, "invalid"):
            env = base.copy()
            if mode is None:
                env.pop("EXAMOS_TPM_MODE")
                label = "unset EXAMOS_TPM_MODE"
            else:
                env["EXAMOS_TPM_MODE"] = mode
                label = "invalid EXAMOS_TPM_MODE"
            expect_rejected(label, env, "EXAMOS_TPM_MODE")

        prod_missing_hmac = base.copy()
        prod_missing_hmac["EXAMOS_TPM_MODE"] = "production"
        prod_missing_hmac.pop(PRODUCTION_LEDGER_KEY)
        expect_rejected(
            "production missing EXAMOS_LEDGER_HMAC_KEY",
            prod_missing_hmac,
            "EXAMOS_LEDGER_HMAC_KEY",
        )

        empty_devices = root / "empty-devices.json"
        empty_devices.write_text('{"devices":[]}\n', encoding="utf-8")
        env = base.copy()
        env["EXAMOS_DEVICES_CONFIG"] = str(empty_devices)
        expect_rejected(
            "empty device registry", env,
            "no valid device and release registries",
        )

        # Runtime resource-control regression: one incomplete request must not
        # create unbounded workers.  The next connection receives an explicit
        # overload response, and capacity is restored after the first closes.
        runtime = base.copy()
        runtime["EXAMOS_SERVER_PORT"] = str(free_port())
        runtime["EXAMOS_MAX_ACTIVE_CONNECTIONS"] = "1"
        process = subprocess.Popen(
            [str(SERVER)], env=runtime, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        slow = None
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    slow = socket.create_connection(("127.0.0.1", int(runtime["EXAMOS_SERVER_PORT"])), timeout=1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise SystemExit("FAIL: bounded-worker server did not start")
                    time.sleep(0.05)

            with socket.create_connection(("127.0.0.1", int(runtime["EXAMOS_SERVER_PORT"])), timeout=2) as busy:
                busy.settimeout(2)
                response = busy.recv(4096)
            if b"503 Service Unavailable" not in response:
                raise SystemExit("FAIL: active-connection limit did not reject overload")

            slow.close()
            slow = None
            deadline = time.monotonic() + 3
            response = b""
            while time.monotonic() < deadline:
                with socket.create_connection(("127.0.0.1", int(runtime["EXAMOS_SERVER_PORT"])), timeout=2) as healthy:
                    healthy.settimeout(2)
                    healthy.sendall(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    response = healthy.recv(4096)
                if b"200 OK" in response:
                    break
                time.sleep(0.05)
            if b"200 OK" not in response:
                raise SystemExit("FAIL: worker capacity was not restored after client close")
            print("PASS: bounded active connections reject overload and recover")
        finally:
            if slow is not None:
                slow.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    print("PASS: all fail-closed startup checks")


if __name__ == "__main__":
    main()
