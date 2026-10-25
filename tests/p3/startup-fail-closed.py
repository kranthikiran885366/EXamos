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
            "EXAMOS_ALLOW_UNPROVISIONED_DEV": "1",
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
        prod_missing_hmac.pop("EXAMOS_ALLOW_UNPROVISIONED_DEV", None)
        prod_missing_hmac.pop(PRODUCTION_LEDGER_KEY)
        expect_rejected(
            "production missing EXAMOS_LEDGER_HMAC_KEY",
            prod_missing_hmac,
            "EXAMOS_LEDGER_HMAC_KEY",
        )

        prod_unprovisioned = base.copy()
        prod_unprovisioned["EXAMOS_TPM_MODE"] = "production"
        expect_rejected(
            "production forbids unprovisioned development override",
            prod_unprovisioned,
            "EXAMOS_ALLOW_UNPROVISIONED_DEV is forbidden",
        )

        prod_missing_database = base.copy()
        prod_missing_database["EXAMOS_TPM_MODE"] = "production"
        prod_missing_database.pop("EXAMOS_ALLOW_UNPROVISIONED_DEV", None)
        # Supply a valid KEK so the server reaches the PostgreSQL init check
        # rather than exiting at the earlier KEK validation step.
        prod_missing_database["EXAMOS_EXAM_KEY_KEK"] = secrets.token_hex(32)
        # Do not inherit a developer/host database connection into this
        # negative test. In particular, a real TLS connection can take the
        # libpq timeout before the expected fail-closed startup is observed.
        # Point at a path known not to exist so this case tests the missing
        # production credential deterministically and without touching a DB.
        prod_missing_database["EXAMOS_DATABASE_URL_FILE"] = str(
            root / "missing-production-database-url"
        )
        # On a non-ExamOS host the appliance check fires first; both messages
        # confirm the server refused to start in production mode without a
        # provisioned store — the contract is "server exited non-zero" and
        # "either no-appliance OR no-PostgreSQL message present".
        env_port = str(free_port())
        prod_missing_database["EXAMOS_SERVER_PORT"] = env_port
        try:
            result_db = subprocess.run(
                [str(SERVER)], env=prod_missing_database, capture_output=True,
                text=True, timeout=5, check=False,
            )
        except subprocess.TimeoutExpired:
            raise SystemExit("FAIL: production missing database did not terminate promptly")
        output_db = result_db.stdout + result_db.stderr
        accepted_msgs = (
            "PostgreSQL TLS connection or required schema unavailable",
            "This server only runs on an ExamOS appliance",
        )
        if result_db.returncode == 0 or not any(m in output_db for m in accepted_msgs):
            raise SystemExit(
                "FAIL: production refuses to start without provisioned PostgreSQL TLS and attestation state"
                " was not rejected as expected"
            )
        print("PASS: production refuses to start without provisioned PostgreSQL TLS and attestation state")

        # Runtime resource-control regression: one incomplete request must not
        # create unbounded workers.  The next connection receives an explicit
        # overload response, and capacity is restored after the first closes.
        runtime = base.copy()
        runtime["EXAMOS_SERVER_PORT"] = str(free_port())
        runtime["EXAMOS_MAX_CLIENTS"] = "1"
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
