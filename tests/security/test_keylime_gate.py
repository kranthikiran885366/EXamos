"""Decision fixtures and a real local TLS server; no live TPM qualification."""
import copy
import http.server
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import keylime_gate as gate


def decision():
    now = int(time.time())
    return {"code": 200, "results": {"operational_state": 3,
        "has_mb_refstate": 1, "has_runtime_policy": 1,
        "attestation_status": "PASS", "last_successful_attestation": now,
        "last_received_quote": now}}


class DecisionTests(unittest.TestCase):
    def test_fresh_evidence(self):
        gate.evaluate(decision(), 30, time.time())

    def test_rejects_unsafe_decisions(self):
        cases = [("operational_state", 7), ("operational_state", 4),
            ("operational_state", True), ("has_mb_refstate", 0),
            ("has_runtime_policy", 0), ("attestation_status", "FAIL"),
            ("last_successful_attestation", 1),
            ("last_successful_attestation", float("nan")),
            ("last_received_quote", int(time.time())+10)]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                data=decision(); data["results"][field]=value
                with self.assertRaises(gate.GateError): gate.evaluate(data,30,time.time())
        data=decision(); data["results"]["last_successful_attestation"]-=1
        with self.assertRaises(gate.GateError): gate.evaluate(data,30,time.time())

    def test_duplicate_json(self):
        with self.assertRaises(gate.GateError):
            json.loads('{"code":200,"code":500}', object_pairs_hook=gate.unique_object)


class MutualTLSTests(unittest.TestCase):
    def test_authenticated_transport_and_wrong_ca(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def openssl(*args):
                subprocess.run(["openssl",*map(str,args)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            openssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout",root/"ca.key",
                "-out",root/"ca.pem","-days","1","-subj","/CN=ExamOS Test CA")
            for name,cn in [("server","localhost"),("client","test-client")]:
                openssl("req","-newkey","rsa:2048","-nodes","-keyout",root/f"{name}.key",
                    "-out",root/f"{name}.csr","-subj",f"/CN={cn}")
                (root/"extension").write_text("subjectAltName=DNS:localhost\n")
                openssl("x509","-req","-in",root/f"{name}.csr","-CA",root/"ca.pem","-CAkey",root/"ca.key",
                    "-CAcreateserial","-out",root/f"{name}.pem","-days","1","-extfile",root/"extension")
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    assert self.path == "/v2.5/agents/12345678-1234-1234-1234-123456789abc"
                    assert self.connection.getpeercert()
                    data=json.dumps(decision()).encode()
                    self.send_response(200); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
                def log_message(self,*args): pass
            server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(root/"server.pem",root/"server.key")
            ctx.verify_mode=ssl.CERT_REQUIRED; ctx.load_verify_locations(root/"ca.pem")
            server.socket=ctx.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            config={"verifier_url":f"https://localhost:{server.server_port}",
                "agent_uuid":"12345678-1234-1234-1234-123456789abc",
                "ca_certificate":str(root/"ca.pem"),"client_certificate":str(root/"client.pem"),
                "client_key":str(root/"client.key")}
            try:
                gate.evaluate(gate.fetch_status(config),30,time.time())
                bad=copy.copy(config); bad["ca_certificate"]=str(root/"server.pem")
                with self.assertRaises(OSError): gate.fetch_status(bad)
                bad=copy.copy(config); bad["verifier_url"]=bad["verifier_url"].replace("https:","http:")
                with self.assertRaises(gate.GateError): gate.fetch_status(bad)
            finally:
                server.shutdown(); server.server_close(); thread.join()


if __name__ == "__main__": unittest.main()
