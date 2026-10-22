#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
make -C "$ROOT/server" all

python3 - "$ROOT/server/examos-server" <<'PY'
import http.client
import base64
import hashlib
import json
import os
import secrets
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
    env["EXAMOS_TPM_MODE"] = "development"
    env["EXAMOS_ALLOW_UNPROVISIONED_DEV"] = "1"
    env["EXAMOS_LEDGER_PATH"] = os.path.join(temp_dir, "ledger.log")
    agent_token = secrets.token_hex(32)
    env["EXAMOS_AGENT_API_TOKEN"] = agent_token
    env["EXAMOS_PROCTOR_API_TOKEN"] = secrets.token_hex(32)
    env["EXAMOS_EVENT_SIGNING_KEY"] = secrets.token_hex(32)
    env["EXAMOS_VARIANT_SECRET"] = secrets.token_hex(32)
    env["EXAMOS_LEDGER_HMAC_KEY"] = secrets.token_hex(32)
    candidate_id = "smoke-" + secrets.token_hex(8)
    candidate_pin = secrets.token_urlsafe(16)
    candidate_salt = secrets.token_bytes(16)
    candidate_iterations = 600000
    candidate_digest = hashlib.pbkdf2_hmac(
        "sha256", candidate_pin.encode(), candidate_salt, candidate_iterations
    )
    candidate_store = os.path.join(temp_dir, "candidates.conf")
    with open(candidate_store, "w", encoding="ascii") as store:
        store.write(
            f"{candidate_id}:{candidate_iterations}:{candidate_salt.hex()}:{candidate_digest.hex()}\n"
        )
    env["EXAMOS_CANDIDATE_STORE"] = candidate_store
    admin_username = "smoke-" + secrets.token_hex(8)
    admin_password = secrets.token_urlsafe(32)
    admin_salt = secrets.token_bytes(16)
    admin_iterations = 600000
    admin_digest = hashlib.pbkdf2_hmac(
        "sha256", admin_password.encode(), admin_salt, admin_iterations
    )
    admin_config = os.path.join(temp_dir, "admin.conf")
    with open(admin_config, "w", encoding="ascii") as config:
        config.write(f"ADMIN_USERNAME={admin_username}\n")
        config.write(
            f"ADMIN_PASSWORD_PBKDF2={admin_iterations}:{admin_salt.hex()}:{admin_digest.hex()}\n"
        )
    os.chmod(admin_config, 0o600)
    env["EXAMOS_ADMIN_CONFIG"] = admin_config
    admin_auth = "Basic " + base64.b64encode(
        f"{admin_username}:{admin_password}".encode()
    ).decode("ascii")
    server = subprocess.Popen(
        [server_binary],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def request(method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        payload = json.dumps(body) if body is not None else None
        request_headers = {"Content-Type": "application/json"} if payload is not None else {}
        if headers:
            request_headers.update(headers)
        connection.request(method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        result = (response.status, json.loads(response.read()))
        connection.close()
        return result

    try:
        for _ in range(50):
            if server.poll() is not None:
                raise RuntimeError("ExamOS server exited before becoming ready")
            try:
                health_status, health = request("GET", "/api/v1/health")
                if health_status == 200:
                    break
            except (ConnectionError, OSError, TimeoutError):
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("ExamOS server did not become ready")

        assert health.get("liveness") == "LIVE", health
        assert health.get("readiness") == "NOT_PRODUCTION_READY", health

        status, response = request("GET", "/api/v1/status", headers={"Authorization": admin_auth})
        assert status == 200 and response.get("attestation_status") == "NOT_PRODUCTION_READY", (status, response)

        for _ in range(50):
            if server.poll() is not None:
                raise RuntimeError("ExamOS server exited before authenticated API became ready")
            try:
                request("GET", "/api/v1/ledger", headers={"Authorization": admin_auth})
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

        status, response = request(
            "POST",
            "/api/v1/attestation/nonce",
            {"device_id": "unprovisioned", "session_id": "smoke-session", "release_id": "smoke-release"},
            {"Authorization": f"Bearer {agent_token}"},
        )
        assert status == 403 and response.get("error_code") == "P3_UNKNOWN_DEVICE", (status, response)

        status, response = request(
            "POST", "/api/v1/candidate/login",
            {"candidate_id": candidate_id, "pin": candidate_pin},
        )
        assert status == 200 and response.get("status") == "SUCCESS", (status, response)
        candidate_token = response["token"]

        status, response = request(
            "POST", "/api/v1/exam/key-release",
            {"session_id": "smoke-session", "device_id": "unprovisioned"},
            {"Authorization": f"Bearer {candidate_token}"},
        )
        assert status == 403 and response.get("error_code") == "P3_SESSION_INVALID", (status, response)

        status, response = request(
            "POST", "/api/v1/heartbeat", {"device_id": "test"},
            {"Authorization": f"Bearer {agent_token}"},
        )
        assert status == 202 and response.get("status") == "RECEIVED_UNTRUSTED", (status, response)

        status, response = request("GET", "/api/v1/ledger", headers={"Authorization": admin_auth})
        assert status == 200 and response.get("ledger_integrity") == "INTACT", (status, response)
        assert response.get("total_blocks") == 2, (status, response)

        ledger_path = env["EXAMOS_LEDGER_PATH"]
        with open(ledger_path, "r+b") as ledger:
            contents = ledger.read()
            assert b"HEARTBEAT_TELEMETRY" in contents
            assert b"CANDIDATE_AUTH_SUCCESS" in contents
            ledger.seek(0)
            ledger.write(contents.replace(b"HEARTBEAT_TELEMETRY", b"HEARTBEAT_TAMPERED"))
            ledger.flush()
            os.fsync(ledger.fileno())
        status, response = request("GET", "/api/v1/ledger", headers={"Authorization": admin_auth})
        assert status == 200 and response.get("ledger_integrity") == "TAMPERED", (status, response)

        print("[PASS] Loopback-only API, unprovisioned-device rejection, fail-closed session, untrusted telemetry, and ledger tamper detection")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
PY
