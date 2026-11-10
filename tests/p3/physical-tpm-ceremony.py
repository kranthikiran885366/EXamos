#!/usr/bin/env python3
"""Disposable swtpm integration test for the offline enrollment ceremony."""

import base64
import hashlib
import json
import os
import pathlib
import shutil
import socket
import stat
import subprocess
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "physical-tpm-ceremony.py"
WORK = pathlib.Path(os.environ.get(
    "EXAMOS_TPM_TEST_WORKDIR",
    str(ROOT / "tests" / "p3" / ".physical-tpm-ceremony-test"),
))
EK_HANDLE = "0x81010009"
AK_HANDLE = "0x8101000a"


def run(command, env=None, expected=0, input_data=None):
    result = subprocess.run(
        command, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, check=False,
    )
    if result.returncode != expected:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        details = stderr or stdout or "no command output"
        raise RuntimeError(
            "{} exited {}; expected {}: {}".format(
                pathlib.Path(command[0]).name, result.returncode, expected, details
            )
        )
    return result.stdout


def available_port_pair():
    for port in range(20000, 60000):
        sockets = []
        try:
            for candidate in (port, port + 1):
                sock = socket.socket()
                sock.bind(("127.0.0.1", candidate))
                sockets.append(sock)
            return port, port + 1
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError("no adjacent free swtpm ports")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(str(path), 0o600)


def key_pin(path):
    der = run(["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"])
    return hashlib.sha256(der).hexdigest()


def sign_manifest(manifest, private_key, signature):
    run(["openssl", "dgst", "-sha256", "-sign", str(private_key),
         "-out", str(signature), str(manifest)])


def approve_arguments(challenge_path, state_path, request_path, ca_bundle, ca_pin,
                      response_path, devices_path, releases_path):
    return [
        sys.executable, str(CLI), "approve", "--request", str(request_path),
        "--ca-bundle", str(ca_bundle), "--ca-sha256", ca_pin,
        "--challenge", str(challenge_path), "--state", str(state_path),
        "--response", str(response_path),
        "--devices", str(devices_path),
        "--devices-signature", str(WORK / "devices.sig"),
        "--devices-public-key", str(WORK / "devices.pub"),
        "--devices-key-sha256", key_pin(WORK / "devices.pub"),
        "--releases", str(releases_path),
        "--releases-signature", str(WORK / "releases.sig"),
        "--releases-public-key", str(WORK / "releases.pub"),
        "--releases-key-sha256", key_pin(WORK / "releases.pub"),
    ]


def write_response(path, response):
    write_json(path, response)


def mutate_quote_attest(attest_encoded, mutation):
    raw = bytearray(attest_encoded)
    if len(raw) >= 2 and int.from_bytes(raw[:2], "big") == len(raw) - 2:
        prefix = raw[:2]
        body = raw[2:]
    else:
        prefix = b""
        body = raw
    require = lambda condition: condition or (_ for _ in ()).throw(
        RuntimeError("TPMS_ATTEST structure was not parseable in test helper.")
    )
    offset = 6
    signer_size = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    require(signer_size > 0 and offset + signer_size <= len(body))
    signer_offset = offset
    offset += signer_size
    nonce_size = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    require(nonce_size > 0 and offset + nonce_size <= len(body))
    nonce_offset = offset
    if mutation == "signer":
        body[signer_offset:signer_offset + signer_size] = b"\x00\x0b" + b"\xA5" * (signer_size - 2)
    elif mutation == "nonce":
        body[nonce_offset] ^= 0x01
    else:
        raise RuntimeError("unknown quote mutation")
    if prefix:
        return (len(body).to_bytes(2, "big") + body)
    return bytes(body)


def activate(challenge, out_dir, env, suffix):
    blob = base64.b64decode(challenge["credential_blob"], validate=True)
    blob_path = out_dir / (suffix + ".blob")
    secret_path = out_dir / (suffix + ".secret")
    session_path = out_dir / (suffix + ".session")
    recovered_path = out_dir / (suffix + ".recovered")
    blob_path.write_bytes(blob)
    os.chmod(str(blob_path), 0o600)
    run(["tpm2_flushcontext", "-t"], env=env)
    run(["tpm2_flushcontext", "-s"], env=env)
    run(["tpm2_startauthsession", "--policy-session", "-S", str(session_path)], env=env)
    try:
        run(["tpm2_policysecret", "-S", str(session_path), "-c", "0x4000000B"], env=env)
        run([
            "tpm2_activatecredential", "-c", AK_HANDLE, "-C", EK_HANDLE,
            "-i", str(blob_path), "-o", str(recovered_path),
            "-P", "session:" + str(session_path),
        ], env=env)
        return recovered_path.read_bytes()
    finally:
        run(["tpm2_flushcontext", str(session_path)], env=env, expected=0)


def main():
    required = (
        "openssl", "swtpm", "tpm2_startup", "tpm2_createek", "tpm2_createak",
        "tpm2_readpublic", "tpm2_evictcontrol", "tpm2_makecredential", "tpm2_startauthsession",
        "tpm2_quote",
        "tpm2_policysecret", "tpm2_activatecredential", "tpm2_flushcontext",
    )
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        reason = "missing " + ", ".join(missing)
        print("[PHYSICAL-TPM-CEREMONY] BLOCKED: {}".format(reason), file=sys.stderr)
        return 2
    if os.name != "posix":
        reason = "requires POSIX"
        print("[PHYSICAL-TPM-CEREMONY] BLOCKED: {}".format(reason), file=sys.stderr)
        return 2
    if WORK.exists():
        print("[PHYSICAL-TPM-CEREMONY] BLOCKED: test workspace already exists; preserve it and retry.", file=sys.stderr)
        return 2

    WORK.mkdir(mode=0o700)
    os.chmod(str(WORK), 0o700)
    if stat.S_IMODE(WORK.stat().st_mode) != 0o700:
        shutil.rmtree(WORK, ignore_errors=True)
        print(
            "[PHYSICAL-TPM-CEREMONY] BLOCKED: test filesystem does not honor "
            "private POSIX directory permissions; set EXAMOS_TPM_TEST_WORKDIR "
            "to an operator-owned Linux filesystem directory.",
            file=sys.stderr,
        )
        return 2
    os.umask(0o077)
    tpm_process = None
    try:
        state_dir = WORK / "swtpm-state"
        state_dir.mkdir(mode=0o700)
        tpm_port, ctrl_port = available_port_pair()
        log_path = WORK / "swtpm.log"
        with log_path.open("wb") as log:
            tpm_process = subprocess.Popen([
                "swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + str(state_dir),
                "--server", "type=tcp,port={},bindaddr=127.0.0.1".format(tpm_port),
                "--ctrl", "type=tcp,port={},bindaddr=127.0.0.1".format(ctrl_port),
                "--flags", "not-need-init,startup-clear",
            ], stdout=log, stderr=log)
        env = {**os.environ, "TPM2TOOLS_TCTI": "swtpm:host=127.0.0.1,port={}".format(tpm_port)}
        time.sleep(0.3)
        if tpm_process.poll() is not None:
            raise RuntimeError("swtpm exited during startup with status {}.".format(tpm_process.returncode))
        try:
            run(["tpm2_startup", "-c"], env=env, expected=0)
        except RuntimeError as error:
            if "tcti" in str(error).lower() or "connect" in str(error).lower():
                raise
            pass
        run(["tpm2_createek", "-G", "rsa", "-c", EK_HANDLE,
             "-u", str(WORK / "ek.pub"), "-R"], env=env)
        run([
            "tpm2_readpublic", "-c", EK_HANDLE, "-f", "pem",
            "-o", str(WORK / "ek.pem"), "-q", str(WORK / "ek.qname"),
        ], env=env)
        run([
            "tpm2_createak", "-C", EK_HANDLE, "-G", "rsa", "-g", "sha256", "-s", "rsassa",
            "-c", str(WORK / "ak.ctx"), "-u", str(WORK / "ak.pub"),
            "-n", str(WORK / "ak.name"), "-R",
        ], env=env)
        run(["tpm2_evictcontrol", "-c", str(WORK / "ak.ctx"), AK_HANDLE], env=env)
        run([
            "tpm2_readpublic", "-c", AK_HANDLE, "-f", "pem", "-o", str(WORK / "ak.pem"),
            "-n", str(WORK / "ak.name"), "-q", str(WORK / "ak.qname"),
        ], env=env)
        run([
            "tpm2_readpublic", "-c", EK_HANDLE, "-f", "tss",
            "-o", str(WORK / "ek.public.tss"),
        ], env=env)
        run([
            "tpm2_readpublic", "-c", AK_HANDLE, "-f", "tss",
            "-o", str(WORK / "ak.public.tss"),
        ], env=env)

        run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(WORK / "test-ca.key"), "-out", str(WORK / "test-ca.pem"),
            "-subj", "/CN=Disposable TPM Test CA", "-days", "1",
        ])
        run([
            "openssl", "x509", "-new", "-force_pubkey", str(WORK / "ek.pem"),
            "-subj", "/CN=Disposable swtpm EK", "-CA", str(WORK / "test-ca.pem"),
            "-CAkey", str(WORK / "test-ca.key"), "-CAcreateserial", "-days", "1",
            "-out", str(WORK / "ek-cert.pem"),
        ])

        ak_name = (WORK / "ak.name").read_bytes().hex()
        ak_qname = (WORK / "ak.qname").read_bytes().hex()
        ak_der = run(["openssl", "pkey", "-pubin", "-in", str(WORK / "ak.pem"), "-outform", "DER"])
        ek_der = run(["openssl", "pkey", "-pubin", "-in", str(WORK / "ek.pem"), "-outform", "DER"])
        ca_bundle = WORK / "test-ca.pem"
        ca_pin = hashlib.sha256(ca_bundle.read_bytes()).hexdigest()
        request = {
            "_schema": "examos-physical-tpm-enrollment-request-v1",
            "enrollment_status": "PENDING_EXTERNAL_APPROVAL",
            "institution_id": "test-institution",
            "device_id": "test-device-001",
            "allowed_release": "test-release-001",
            "tpm_ek_handle": EK_HANDLE,
            "tpm_ak_handle": AK_HANDLE,
            "ek_fingerprint": hashlib.sha256(ek_der).hexdigest(),
            "ek_certificate_pem": (WORK / "ek-cert.pem").read_text(encoding="ascii"),
            "ak_name": ak_name,
            "ak_qualified_name": ak_qname,
            "ak_pub_sha256": hashlib.sha256(ak_der).hexdigest(),
            "ak_public_pem": (WORK / "ak.pem").read_text(encoding="ascii"),
            "tpm_manufacturer_ca_store_sha256": ca_pin,
        }
        request_path = WORK / "request.json"
        write_json(request_path, request)
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", str(WORK / "devices.key")])
        run(["openssl", "pkey", "-in", str(WORK / "devices.key"), "-pubout",
             "-out", str(WORK / "devices.pub")])
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", str(WORK / "releases.key")])
        run(["openssl", "pkey", "-in", str(WORK / "releases.key"), "-pubout",
             "-out", str(WORK / "releases.pub")])
        devices = {
            "_schema": "examos-device-registry-v1",
            "environment": "production",
            "version": "1",
            "devices": [{
                "device_id": "existing-test-device",
                "institution_id": "existing-test-institution",
                "ek_fingerprint": "a" * 64,
                "ak_qualified_name": ak_qname,
                "ak_pub_sha256": hashlib.sha256(ak_der).hexdigest(),
                "ak_public_pem": request["ak_public_pem"],
                "status": "ENROLLED",
                "allowed_release": "test-release-001",
            }],
        }
        releases = {
            "_schema": "examos-release-registry-v1",
            "environment": "production",
            "version": "1",
            "releases": [{
                "release_id": "test-release-001",
                "uki_hash": "1" * 64,
                "pcr0": "2" * 64,
                "pcr4": "3" * 64,
                "pcr7": "4" * 64,
                "pcr11": "5" * 64,
                "approval_status": "APPROVED_PRODUCTION",
                "pcr_bank": "SHA256",
                "revoked": False,
            }],
        }
        write_json(WORK / "devices.json", devices)
        write_json(WORK / "releases.json", releases)
        sign_manifest(WORK / "devices.json", WORK / "devices.key", WORK / "devices.sig")
        sign_manifest(WORK / "releases.json", WORK / "releases.key", WORK / "releases.sig")

        challenge_path = WORK / "challenge.json"
        state_path = WORK / "verifier-state.json"
        run([
            sys.executable, str(CLI), "make-credential", "--request", str(request_path),
            "--ca-bundle", str(ca_bundle), "--ca-sha256", ca_pin,
            "--challenge-out", str(challenge_path), "--state-out", str(state_path),
        ])
        challenge = json.loads(challenge_path.read_text(encoding="utf-8"))
        state_stat = state_path.stat()
        if stat.S_IMODE(state_stat.st_mode) != 0o600:
            raise RuntimeError("verifier state permissions were not 0600.")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if base64.b64encode(base64.b64decode(state["secret"])).decode("ascii") in challenge_path.read_text(encoding="utf-8"):
            raise RuntimeError("transport challenge contains the verifier secret.")

        # Exercise the TPM protocol itself against swtpm. The CLI's
        # activate-credential command remains physical-device-only.
        recovered = activate(challenge, WORK, env, "valid-activation")
        local_secret = base64.b64decode(state["secret"], validate=True)
        if recovered != local_secret:
            raise RuntimeError("swtpm activation did not recover the protected secret.")
        response = hashlib.sha256(recovered).hexdigest()
        quote_attest_path = WORK / "quote.attest"
        quote_signature_path = WORK / "quote.signature"
        run([
            "tpm2_quote", "-c", AK_HANDLE, "-l", "sha256:0,4,7,11",
            "-q", challenge["quote_nonce"], "-m", str(quote_attest_path),
            "-s", str(quote_signature_path), "-g", "sha256",
        ], env=env)
        response = {
            "_schema": "examos-physical-tpm-credential-response-v1",
            "challenge_id": challenge["challenge_id"],
            "activation_sha256": response,
            "ek_public_tpm2b_b64": base64.b64encode((WORK / "ek.public.tss").read_bytes()).decode("ascii"),
            "ak_public_tpm2b_b64": base64.b64encode((WORK / "ak.public.tss").read_bytes()).decode("ascii"),
            "quote_attest_b64": base64.b64encode(quote_attest_path.read_bytes()).decode("ascii"),
            "quote_signature_b64": base64.b64encode(quote_signature_path.read_bytes()).decode("ascii"),
        }
        if "secret" in response or base64.b64encode(local_secret).decode("ascii") in json.dumps(response):
            raise RuntimeError("credential response exposed the activation secret.")
        response_path = WORK / "response.json"
        write_response(response_path, response)

        wrong_secret_path = WORK / "wrong-ak.secret"
        wrong_secret_path.write_bytes(os.urandom(32))
        wrong_credential = WORK / "wrong-ak.blob"
        wrong_name = "000b" + "f" * 64
        run([
            "tpm2_makecredential", "-G", "rsa", "-u", str(WORK / "ek.pem"),
            "-s", str(wrong_secret_path), "-n", wrong_name, "-o", str(wrong_credential),
        ], env={**env, "TPM2TOOLS_TCTI": "none"})
        wrong_challenge = dict(challenge)
        wrong_challenge["credential_blob"] = base64.b64encode(wrong_credential.read_bytes()).decode("ascii")
        wrong_challenge["ak_name"] = wrong_name
        try:
            activate(wrong_challenge, WORK, env, "wrong-ak")
        except RuntimeError as error:
            if "tpm2_activatecredential exited" not in str(error):
                raise
        else:
            raise RuntimeError("swtpm accepted a credential bound to the wrong AK Name.")

        def approval(challenge_file=challenge_path, response_file=response_path):
            return approve_arguments(
                challenge_file, state_path, request_path, ca_bundle, ca_pin,
                response_file, WORK / "devices.json", WORK / "releases.json",
            )

        wrong_response = dict(response)
        wrong_response["activation_sha256"] = "0" * 64
        wrong_response_path = WORK / "wrong-response.json"
        write_response(wrong_response_path, wrong_response)
        run(approval(response_file=wrong_response_path) + [
            "--candidate-out", str(WORK / "wrong-response-candidate.json"),
            "--registration-out", str(WORK / "wrong-response-registration.json"),
        ], expected=1)
        wrong_ak_path = WORK / "wrong-ak-challenge.json"
        wrong_challenge["credential_blob"] = challenge["credential_blob"]
        write_json(wrong_ak_path, wrong_challenge)
        run(approval(challenge_file=wrong_ak_path) + [
            "--candidate-out", str(WORK / "wrong-ak-candidate.json"),
            "--registration-out", str(WORK / "wrong-ak-registration.json"),
        ], expected=1)

        for case, mutation in (("bad-signature", "signature"),
                               ("wrong-nonce", "nonce"),
                               ("wrong-qualified-name", "signer"),
                               ("wrong-ak-public-name", "ak-public")):
            altered = dict(response)
            if mutation == "signature":
                signature = bytearray(base64.b64decode(altered["quote_signature_b64"]))
                signature[-1] ^= 0x01
                altered["quote_signature_b64"] = base64.b64encode(signature).decode("ascii")
            elif mutation == "ak-public":
                public_area = bytearray(base64.b64decode(altered["ak_public_tpm2b_b64"]))
                public_area[-1] ^= 0x01
                altered["ak_public_tpm2b_b64"] = base64.b64encode(public_area).decode("ascii")
            else:
                attest = base64.b64decode(altered["quote_attest_b64"])
                altered["quote_attest_b64"] = base64.b64encode(
                    mutate_quote_attest(attest, mutation)
                ).decode("ascii")
            altered_path = WORK / (case + ".json")
            write_response(altered_path, altered)
            run(approval(response_file=altered_path) + [
                "--candidate-out", str(WORK / (case + "-candidate.json")),
                "--registration-out", str(WORK / (case + "-registration.json")),
            ], expected=1)

        for field in ("device_id", "ek_fingerprint"):
            duplicate = json.loads(json.dumps(devices))
            entry = dict(duplicate["devices"][0])
            if field == "device_id":
                entry[field] = request[field]
            else:
                entry["device_id"] = "other-device"
                entry[field] = request[field]
            duplicate["devices"].append(entry)
            write_json(WORK / "devices.json", duplicate)
            sign_manifest(WORK / "devices.json", WORK / "devices.key", WORK / "devices.sig")
            run(approval() + ["--candidate-out", str(WORK / ("duplicate-" + field + ".json")),
                              "--registration-out", str(WORK / ("duplicate-" + field + "-registration.json"))],
                expected=1)
        write_json(WORK / "devices.json", devices)
        sign_manifest(WORK / "devices.json", WORK / "devices.key", WORK / "devices.sig")

        candidate_path = WORK / "candidate.json"
        registration_path = WORK / "registration.json"
        run(approval() + [
            "--candidate-out", str(candidate_path),
            "--registration-out", str(registration_path),
        ])
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        registration = json.loads(registration_path.read_text(encoding="utf-8"))
        entry = candidate["devices"][-1]
        if len(candidate["devices"]) != len(devices["devices"]) + 1 or candidate["devices"][0] != devices["devices"][0]:
            raise RuntimeError("candidate did not preserve the current registry entries.")
        if entry.get("institution_id") != request["institution_id"]:
            raise RuntimeError("candidate omitted the request institution binding.")
        if (entry.get("ak_public_pem") != request["ak_public_pem"] or
                entry.get("status") != "ENROLLED" or
                entry.get("allowed_release") != request["allowed_release"] or
                entry.get("ak_name") != request["ak_name"].lower()):
            raise RuntimeError("candidate did not preserve the exact AK public identity.")
        if "signature" in candidate:
            raise RuntimeError("CLI unexpectedly signed the candidate.")
        if registration != {
            "device_id": request["device_id"],
            "institution_id": request["institution_id"],
            "ak_public_key_pem": request["ak_public_pem"],
            "tpm_present": True,
            "tpm_version": "2.0",
        }:
            raise RuntimeError("registration payload contains mismatched or invented device claims.")
        print("[PHYSICAL-TPM-CEREMONY] PASS: swtpm activation, TPMT_PUBLIC/Name/QN and quote binding, rejection cases, and unsigned candidate checks")
        return 0
    except Exception as error:
        detail = str(error)
        log_path = WORK / "swtpm.log"
        if log_path.is_file():
            try:
                log = log_path.read_text(encoding="utf-8", errors="replace").strip()
                if log:
                    detail += "\nswtpm log:\n" + log[-4000:]
            except OSError:
                pass
        print("[PHYSICAL-TPM-CEREMONY] FAIL: {}".format(detail), file=sys.stderr)
        return 1
    finally:
        if tpm_process is not None:
            tpm_process.terminate()
            try:
                tpm_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tpm_process.kill()
                tpm_process.wait()
        shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
