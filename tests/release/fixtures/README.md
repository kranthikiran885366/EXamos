# Test-only release-verification fixtures

This directory must never contain production keys, certificates, manifests,
or release artifacts.  Fixtures used by the isolated verifier tests are
deliberately malformed or synthetic and must never authorize `VERIFIED`.
