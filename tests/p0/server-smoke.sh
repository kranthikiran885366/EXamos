#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
make -C "$ROOT/server" all

python3 - "$ROOT/server/examos-server" <<'PY'
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

server_binary = sys.argv[1]
with socket.socket() as reservation:
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]

with tempfile.TemporaryDirectory(prefix="examos-server-test-") as temp_dir:
    env = os.environ.copy()
    env["EXAMOS_SERVER_PORT"] = str(port)
    env["EXAMOS_LEDGER_PATH"] = os.path.join(temp_dir, "ledger.log")
    server = subprocess.Popen(
        [server_binary],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def request(method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        payload = json.dumps(body) if body is not None else None
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        result = (response.status, json.loads(response.read()))
        connection.close()
        return result

    try:
        for _ in range(50):
            if server.poll() is not None:
                raise RuntimeError("ExamOS server exited before becoming ready")
            try:
                request("GET", "/api/v1/ledger")
                break
            except (ConnectionError, OSError, TimeoutError):
                time.sleep(0.1)
        else:
            raise RuntimeError("ExamOS server did not become ready")

        with open("/proc/net/tcp", encoding="ascii") as listeners:
            listening_addresses = {
                line.split()[1]
                for line in listeners.readlines()[1:]
                if int(line.split()[1].split(":")[1], 16) == port
                and line.split()[3] == "0A"
            }
        assert listening_addresses == {f"0100007F:{port:04X}"}, listening_addresses

        status, response = request("POST", "/api/v1/attestation", {})
        assert status == 503 and response.get("verified") is False, (status, response)

        status, response = request("GET", "/exam/session")
        assert status == 503 and response.get("status") == "UNAVAILABLE", (status, response)

        status, response = request("POST", "/api/v1/heartbeat", {"device_id": "test"})
        assert status == 202 and response.get("trusted") is False, (status, response)

        status, response = request("GET", "/api/v1/ledger")
        assert status == 200 and response.get("ledger_integrity") == "INTACT", (status, response)
        assert response.get("total_blocks") == 1, (status, response)

        ledger_path = env["EXAMOS_LEDGER_PATH"]
        with open(ledger_path, "r+b") as ledger:
            contents = ledger.read()
            assert b"UNTRUSTED_DEVICE" in contents
            ledger.seek(0)
            ledger.write(contents.replace(b"UNTRUSTED_DEVICE", b"UNTRUSTED_ATTACK"))
            ledger.flush()
            os.fsync(ledger.fileno())
        status, response = request("GET", "/api/v1/ledger")
        assert status == 200 and response.get("ledger_integrity") == "TAMPERED", (status, response)

        print("[PASS] Loopback-only API, fail-closed trust/session responses, untrusted telemetry, and ledger tamper detection")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
PY
