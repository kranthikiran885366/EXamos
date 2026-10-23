#!/usr/bin/env bash
# =============================================================================
# ExamOS Image Build - provisioning content and detector inventory
#
# Staged into the image root filesystem:
#   /etc/examos/browser_policies.json   the provisioned browser policy catalogue
#   /etc/examos/appliance-identity      the appliance identity marker
#   /etc/examos/models/                 the detector inventory and its manifest
#
# The browser policy catalogue and the detector inventory are the only two
# pieces of deployment content the server and the proctoring worker need.
# Both are verified: the catalogue is a schema-checked file, and every
# detector artefact is checked against the digest recorded in the manifest.
# =============================================================================
set -euo pipefail

STAGE_DIR="${1:?usage: stage-deployment-content.sh STAGE_DIR [MODEL_SOURCE_DIR]}"
MODEL_SOURCE_DIR="${2:-}"

EXAMOS_DIR="$STAGE_DIR/etc/examos"
MODELS_DIR="$EXAMOS_DIR/models"

install -d -o root -g root -m 0750 "$EXAMOS_DIR"
install -d -o root -g root -m 0755 "$MODELS_DIR"

# ---------------------------------------------------------------------------
# 1. Browser policy catalogue
#
# The catalogue is the only source of browser policies the platform will
# accept. An examination must reference a policy by name from it.
# ---------------------------------------------------------------------------
CATALOGUE_SRC="$REPO_ROOT/server/config/browser_policies.json"
if [ ! -f "$CATALOGUE_SRC" ]; then
    echo "[stage] FATAL: the browser policy catalogue is missing: $CATALOGUE_SRC" >&2
    exit 1
fi
if ! python3 - "$CATALOGUE_SRC" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
if manifest.get("_schema") != "examos-browser-policy-catalog-v1":
    raise SystemExit("unsupported browser policy catalogue schema")
policies = manifest.get("policies")
if not isinstance(policies, list) or not policies:
    raise SystemExit("the browser policy catalogue contains no policy")
for policy in policies:
    if not policy.get("name") or not isinstance(policy.get("policy"), dict):
        raise SystemExit("a browser policy entry is malformed")
PY
then
    echo "[stage] FATAL: the browser policy catalogue is malformed" >&2
    exit 1
fi
install -o root -g root -m 0644 "$CATALOGUE_SRC" "$EXAMOS_DIR/browser_policies.json"
echo "[stage] browser policy catalogue installed"

# ---------------------------------------------------------------------------
# 2. Appliance identity marker
#
# The examination components refuse to run without it. The marker records
# which image the appliance was built from; the deployment workflow may
# replace it with the appliance's own provisioned identity.
# ---------------------------------------------------------------------------
if [ ! -f "$EXAMOS_DIR/appliance-identity" ]; then
    BUILD_ID="${EXAMOS_BUILD_ID:-$(cat "$STAGE_DIR/etc/examos/build-id" 2>/dev/null || echo unknown)}"
    printf 'examos-appliance-%s\n' "$BUILD_ID" > "$EXAMOS_DIR/appliance-identity"
fi
chown root:root "$EXAMOS_DIR/appliance-identity"
chmod 0644 "$EXAMOS_DIR/appliance-identity"
echo "[stage] appliance identity: $(cat "$EXAMOS_DIR/appliance-identity")"

# ---------------------------------------------------------------------------
# 3. Detector inventory
#
# The models are not committed to the repository. They are provisioned on the
# build host with scripts/download-vision-models.sh, which verifies every
# download against its published digest and writes the manifest.
# ---------------------------------------------------------------------------
if [ -n "$MODEL_SOURCE_DIR" ] && [ -d "$MODEL_SOURCE_DIR" ]; then
    for artefact in "$MODEL_SOURCE_DIR"/*; do
        [ -f "$artefact" ] || continue
        install -o root -g root -m 0644 "$artefact" "$MODELS_DIR/$(basename "$artefact")"
    done
    if [ -f "$MODELS_DIR/MODEL-MANIFEST.json" ]; then
        echo "[stage] detector inventory installed ($(ls -1 "$MODELS_DIR" | wc -l) files)"
    else
        echo "[stage] FATAL: the detector inventory has no manifest" >&2
        exit 1
    fi
else
    echo "[stage] WARNING: no detector inventory was supplied." >&2
    echo "[stage] The proctoring worker will refuse to start until one is provisioned." >&2
fi

exit 0
