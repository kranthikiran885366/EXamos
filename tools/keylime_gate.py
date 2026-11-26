#!/usr/bin/env python3
"""Check an enrolled appliance against the Keylime v2.5 verifier over mTLS.

This consumes verifier decisions; it does not replace Keylime's TPM/IMA
verification. The measured profile refuses boot without fresh successful
measured-boot AND runtime-policy evidence. No cached success is accepted.
"""
from __future__ import annotations
import argparse
import json
import math
from pathlib import Path
import ssl
import signal
import stat
import sys
import time
import urllib.request
import uuid

from release_provenance import load_strict_json, ProvenanceError

MAX_RESPONSE = 1 << 20


class GateError(ValueError):
    pass


def deadline_expired(_signum, _frame):
    raise GateError("verifier deadline exceeded")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GateError("duplicate verifier JSON field")
        result[key] = value
    return result


def reject_constant(value):
    raise GateError("non-finite verifier value")


def evaluate(response: dict, max_age: int, now: float) -> None:
    if type(response) is not dict or type(response.get("code")) is not int or response["code"] != 200:
        raise GateError("verifier did not return a successful decision")
    result = response.get("results")
    if type(result) is not dict:
        raise GateError("missing verifier result")
    # GET_QUOTE=3 is Keylime's periodic integrity-check state. Reject retry,
    # registration, initialization, failure and unknown states conservatively.
    for field, value in [("operational_state", 3), ("has_mb_refstate", 1), ("has_runtime_policy", 1)]:
        if type(result.get(field)) is not int or result[field] != value:
            raise GateError(f"verifier prerequisite rejected: {field}")
    if result.get("attestation_status") != "PASS":
        raise GateError("attestation did not pass")
    successful = result.get("last_successful_attestation")
    received = result.get("last_received_quote")
    for value in [successful, received]:
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise GateError("missing attestation timestamp")
        if not 0 <= now - value <= max_age:
            raise GateError("stale or future attestation timestamp")
    if received > successful:
        raise GateError("latest received quote has not passed attestation")


def protected_file(path: Path, private=False) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise GateError(f"root-owned non-writable regular file required: {path}")
    if private and metadata.st_mode & 0o077:
        raise GateError("mTLS private key permissions must be 0600 or stricter")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GateError("verifier redirects are forbidden")


def fetch_status(config: dict) -> dict:
    endpoint = urllib.parse.urlsplit(config["verifier_url"])
    if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password:
        raise GateError("an HTTPS verifier without embedded credentials is required")
    if endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment:
        raise GateError("verifier URL must be an origin")
    agent_id = str(uuid.UUID(config["agent_uuid"]))
    context = ssl.create_default_context(cafile=config["ca_certificate"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.verify_flags &= ~ssl.VERIFY_X509_PARTIAL_CHAIN
    context.load_cert_chain(config["client_certificate"], config["client_key"])
    # Do not forward this client's certificate through environment proxies.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context), NoRedirect())
    url = config["verifier_url"].rstrip("/") + "/v2.5/agents/" + agent_id
    with opener.open(url, timeout=5) as response:
        if response.status != 200:
            raise GateError("verifier HTTP status rejected")
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise GateError("oversized verifier response")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        protected_file(args.config)
        config = load_strict_json(args.config, 16384)
        required = {"verifier_url", "agent_uuid", "ca_certificate", "client_certificate", "client_key", "max_age_seconds"}
        if set(config) != required:
            raise GateError("Keylime configuration fields are missing or unknown")
        age = config["max_age_seconds"]
        if type(age) is not int or not 1 <= age <= 60:
            raise GateError("max_age_seconds must be 1..60")
        for field in ("ca_certificate", "client_certificate", "client_key"):
            if not isinstance(config[field], str) or not Path(config[field]).is_absolute():
                raise GateError("absolute certificate paths are required")
            protected_file(Path(config[field]), private=field == "client_key")
        signal.signal(signal.SIGALRM, deadline_expired)
        signal.alarm(8)
        try:
            evaluate(fetch_status(config), age, time.time())
        finally:
            signal.alarm(0)
    except (GateError, ProvenanceError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"KEYLIME_REJECTED: {error}", file=sys.stderr)
        return 1
    print("KEYLIME_VERIFIED: fresh measured-boot and IMA verifier decision")
    return 0


if __name__ == "__main__":
    sys.exit(main())
