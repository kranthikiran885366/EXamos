# ExamOS TLS provisioning

**Status:** implementation complete; certificate and key provisioning is an
operator/deployment input. No certificate or private key is committed to this
repository.

The server supports two mutually exclusive transport modes:

1. **Same-host TLS ingress (default appliance layout).** The server binds
   loopback only and an ingress proxy terminates TLS. The proxy must be the
   only process reachable from the network and must forward to
   `127.0.0.1:${EXAMOS_SERVER_PORT}`.
2. **In-process TLS.** The server binds a provisioned non-loopback address and
   terminates TLS itself with OpenSSL. A cleartext non-loopback listener is
   refused before `bind()`.

A loopback cleartext listener is accepted because it is not reachable from the
network. A non-loopback listener without TLS is always refused.

## In-process TLS

Set the listener address and both TLS variables in the server environment
(for example `/etc/examos/proctor.env`):

```ini
EXAMOS_BIND_ADDR=10.20.0.10
EXAMOS_TLS_CERT=/etc/examos/tls/server.crt
EXAMOS_TLS_KEY=/etc/examos/tls/server.key
```

Both variables must be present; setting only one is a fatal startup error.
Startup also fails if either file is missing, the key is not a regular file, or
(in production mode) the key is readable by group or other.

Provision the material:

```bash
install -d -o root -g root -m 0755 /etc/examos/tls
install -o root -g root -m 0644 server.crt /etc/examos/tls/server.crt
install -o root -g root -m 0600 server.key /etc/examos/tls/server.key
openssl x509 -in /etc/examos/tls/server.crt -noout -subject -issuer -dates
openssl pkey -in /etc/examos/tls/server.key -check -noout
```

The certificate must contain the DNS name or IP address used by clients. The
private key must never be world-readable, must not be stored in the image, and
must be rotated by replacing both files and restarting the service.

### Enforced TLS policy

- TLS 1.2 is the minimum; SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are disabled.
- Only ECDHE AEAD cipher suites and TLS 1.3 AEAD suites are accepted.
- HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and a
  strict referrer policy are emitted.
- The server refuses to start with a cleartext listener on any non-loopback
  address.

## Ingress-proxy TLS

Keep the server on loopback (the default) and terminate TLS in the proxy. The
proxy must:

- present a certificate whose name matches the candidate-facing URL;
- use TLS 1.2 or later and disable obsolete protocols and ciphers;
- set or preserve HSTS, CSP, frame denial, MIME-sniffing denial and referrer
  policy headers;
- forward only to `127.0.0.1:${EXAMOS_SERVER_PORT}` and not expose that port;
- preserve the client address only through an explicitly trusted header, and
  never trust a client-supplied forwarding header.

The in-process TLS test (`tests/p0/server-tls-test.sh`) exercises the server
directly and does not validate the proxy configuration.

## Verification

The regression test creates its own short-lived self-signed certificate and
exercises the server directly:

```bash
tests/p0/server-tls-test.sh
```

Expected result: `[TLS] RESULT: PASS`. The test covers the handshake, HSTS and
security headers, cleartext rejection and the TLS 1.2 minimum. It does **not**
validate an operator-provisioned certificate chain.

After provisioning production material, verify the real listener:

```bash
openssl s_client -connect 10.20.0.10:8000 -servername exam.example.edu \
  -tls1_2 </dev/null
curl --cacert /etc/ssl/certs/ca-certificates.crt \
  https://exam.example.edu/api/v1/health
```

Confirm the presented chain, subject/SAN, expiry, negotiated protocol and
cipher suite. Record the observed values with the deployment evidence.

Do not treat a local self-signed certificate as production evidence. Production
certificate issuance, chain validation, renewal and client trust are external
controls and must be recorded with the release evidence.
