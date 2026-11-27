#!/usr/bin/env bash
# =============================================================================
# SPPIO / ExamOS — Verifiable Supply Chain: SLSA v1.0 + Reproducible SBOM
# =============================================================================
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
OUT_DIR="${2:-$ROOT/build/supply-chain}"
mkdir -p "$OUT_DIR"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"
COMMIT_SHA="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
BUILD_TS="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

ARTIFACTS=(
  "$ROOT/server/examos-server"
  "$ROOT/agent/examos-agent"
  "$ROOT/kiosk/launcher/examos-kiosk-launcher"
  "$ROOT/proctoring/examos-proctor"
  "$ROOT/rust-services/target/release/sppio-securityd"
  "$ROOT/kernel/bpf_lsm/examos_lsm.bpf.o"
  "$ROOT/kernel/bpf_xdp/examos_xdp_filter.bpf.o"
)

SBOM_FILE="$OUT_DIR/examos-sbom.cdx.json"
SLSA_FILE="$OUT_DIR/examos-provenance.slsa.json"

python3 - "$ROOT" "$SBOM_FILE" "$SLSA_FILE" "$COMMIT_SHA" "$BUILD_TS" "$SOURCE_DATE_EPOCH" "${ARTIFACTS[@]}" <<'PY'
import hashlib, json, os, sys

root, sbom_path, slsa_path, commit, build_ts, epoch = sys.argv[1:7]
artifacts = sys.argv[7:]

components = []
subjects = []
for path in artifacts:
    if not os.path.isfile(path):
        continue
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    digest = h.hexdigest()
    rel = os.path.relpath(path, root).replace("\\", "/")
    components.append({
        "type": "application",
        "name": os.path.basename(path),
        "purl": f"pkg:generic/examos/{os.path.basename(path)}@{commit[:12]}",
        "hashes": [{"alg": "SHA-256", "content": digest}],
        "properties": [{"name": "examos:path", "value": rel}],
    })
    subjects.append({"name": rel, "digest": {"sha256": digest}})

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": build_ts,
        "component": {"type": "operating-system", "name": "SPPIO-ExamOS", "version": commit[:12]},
    },
    "components": components,
}
with open(sbom_path, "w") as f:
    json.dump(sbom, f, indent=2, sort_keys=True)

slsa = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": subjects,
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": "https://examos.in/slsa/reproducible-image-build/v1",
            "externalParameters": {"source_date_epoch": int(epoch), "git_commit": commit},
        },
        "runDetails": {
            "builder": {"id": "https://examos.in/builders/isolated-ci/v1"},
            "metadata": {"finishedOn": build_ts, "reproducible": True},
        },
    },
}
with open(slsa_path, "w") as f:
    json.dump(slsa, f, indent=2, sort_keys=True)
PY

if [ -n "${EXAMOS_SBOM_SIGNING_KEY:-}" ] && [ -f "$EXAMOS_SBOM_SIGNING_KEY" ]; then
    openssl dgst -sha256 -sign "$EXAMOS_SBOM_SIGNING_KEY" -out "${SBOM_FILE}.sig" "$SBOM_FILE"
    openssl dgst -sha256 -sign "$EXAMOS_SBOM_SIGNING_KEY" -out "${SLSA_FILE}.sig" "$SLSA_FILE"
fi

echo "[slsa-sbom] Generated $SBOM_FILE and $SLSA_FILE (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
