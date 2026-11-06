#!/usr/bin/env bash
# =============================================================================
# ExamOS F2 — Chromium Managed Policy Generator
#
# Reads /etc/examos/exam.conf, validates EXAM_URL, and generates a Chromium
# managed-policy JSON file allowing only the configured origin.
#
# The policy file is written atomically to both Chromium and Chrome policy
# paths so the kiosk cannot launch with a stale or hardcoded domain.
#
# This script is called by examos-chromium-policy.service (root oneshot,
# Before=examos-kiosk.service) so the policy is always consistent with the
# currently configured exam URL before Chromium starts.
#
# Usage (run as root on the target appliance):
#   bash /usr/local/sbin/generate-chromium-policy.sh [--dry-run] [--check-only]
#
# Options:
#   --dry-run     Print generated policy JSON to stdout without installing.
#   --check-only  Only validate exam.conf; do not write any file.
#
# Exit codes:
#   0  Success — policy written (or dry-run printed / check-only passed)
#   1  Configuration error — EXAM_URL missing, invalid, or fail-closed
#   2  Tool error — Python not available, JSON validation failed, write failed
# =============================================================================
set -euo pipefail

EXAM_CONF="${EXAM_CONF:-/etc/examos/exam.conf}"

# Both Chromium (Debian package) and Google Chrome policy paths
POLICY_PATHS=(
    "/etc/chromium/policies/managed/examos_policies.json"
    "/etc/opt/chrome/policies/managed/examos_policies.json"
)
POLICY_PATHS=()
for candidate in \
    /etc/chromium/policies/managed/examos_policies.json \
    /etc/opt/chrome/policies/managed/examos_policies.json; do
    if [ -d "$(dirname "$candidate")" ] || [ "$candidate" = "/etc/chromium/policies/managed/examos_policies.json" ]; then
        POLICY_PATHS+=("$candidate")
    fi
done

DRY_RUN=0
CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --dry-run)    DRY_RUN=1 ;;
        --check-only) CHECK_ONLY=1 ;;
    esac
done

log()  { echo "[gen-chrome-policy] $*" >&2; }
fail() { echo "[gen-chrome-policy] FATAL: $*" >&2; exit 1; }
warn() { echo "[gen-chrome-policy] WARNING: $*" >&2; }

# -----------------------------------------------------------------------
# Read EXAM_URL from exam.conf
# -----------------------------------------------------------------------
[ -f "$EXAM_CONF" ] || fail "exam.conf not found at ${EXAM_CONF}"

EXAM_URL=""
ALLOWED_ORIGINS=""
while IFS='=' read -r key val; do
    # Strip inline comments and leading/trailing whitespace
    val="${val%%#*}"
    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"
    if [ "$key" = "EXAM_URL" ] && [ -n "$val" ]; then
        EXAM_URL="$val"
    elif [ "$key" = "ALLOWED_ORIGINS" ] && [ -n "$val" ]; then
        ALLOWED_ORIGINS="$val"
    fi
done < <(grep -v '^[[:space:]]*#' "$EXAM_CONF" | grep '=')

# -----------------------------------------------------------------------
# Validate and canonicalize EXAM_URL. Additional origins must be approved
# separately; a configured hostname never grants access to its subdomains.
# -----------------------------------------------------------------------
if [ -z "$EXAM_URL" ] || [ "$EXAM_URL" = "NOT_CONFIGURED" ]; then
    fail "EXAM_URL is ${EXAM_URL:-empty} in ${EXAM_CONF}. " \
         "Provision it via the ExamOS Admin Dashboard before starting the kiosk."
fi

PYTHON_BIN=$(command -v python3 || command -v python || true)
if [ -z "$PYTHON_BIN" ]; then
    fail "Python not available — cannot validate EXAM_URL safely. Install python3."
fi

URL_VALIDATION_OUTPUT=$("$PYTHON_BIN" - "$EXAM_URL" 2>&1 <<'PYEOF'
import ipaddress
import re
import sys
from urllib.parse import urlsplit

def reject(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)

raw = sys.argv[1]
if len(raw) > 2048 or any(ord(char) <= 0x20 or ord(char) == 0x7f for char in raw):
    reject("URL is too long or contains whitespace/control characters")
if "\\" in raw:
    reject("URL must not contain backslashes")

try:
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    port = parsed.port
except ValueError as error:
    reject("Malformed URL authority: " + str(error))

if scheme != "https" or not parsed.netloc or not host:
    reject("Production exam endpoints MUST use HTTPS exclusively (no plain HTTP)")
if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
    reject("URL credentials are not permitted")
if port is not None and not 1 <= port <= 65535:
    reject("URL port must be between 1 and 65535")

try:
    address = ipaddress.ip_address(host)
    canonical_host = address.compressed.lower()
    if address.version == 6:
        canonical_host = "[" + canonical_host + "]"
except ValueError:
    try:
        canonical_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        reject("URL hostname is invalid")
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if not re.fullmatch(label + r"(?:\." + label + r")*", canonical_host):
        reject("URL hostname is invalid")

if canonical_host in ("example.com", "example.org", "example.net", "test.invalid"):
    reject("Documentation/example hostnames are not valid exam endpoints")
if "DEPLOYMENT_REQUIRED" in raw or "NOT_CONFIGURED" in raw:
    reject("Placeholder values are not valid exam endpoints")

authority = canonical_host + ((":" + str(port)) if port is not None else "")
print(scheme + "://" + authority)
PYEOF
) || fail "Invalid EXAM_URL '${EXAM_URL}': ${URL_VALIDATION_OUTPUT}"
EXAM_ORIGIN="$URL_VALIDATION_OUTPUT"
log "Validated exact exam origin: ${EXAM_ORIGIN}"

if [ "$CHECK_ONLY" -eq 1 ]; then
    log "Check-only mode: exam.conf is valid."
    exit 0
fi

# -----------------------------------------------------------------------
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")

# -----------------------------------------------------------------------
# Build JSON — inject exam origin(s) into URLAllowlist, VideoCaptureAllowedUrls,
# AudioCaptureAllowedUrls.  All other policy values are static and remain
# in the trusted image overlay.
# -----------------------------------------------------------------------

ADDITIONAL_ORIGINS=()
if [ -n "$ALLOWED_ORIGINS" ]; then
    IFS=',' read -ra ORIGIN_LIST <<< "$ALLOWED_ORIGINS"
    for o in "${ORIGIN_LIST[@]}"; do
        o="${o#"${o%%[![:space:]]*}"}"
        o="${o%"${o##*[![:space:]]}"}"
        if [ -n "$o" ] && [ "$o" != "$EXAM_ORIGIN" ]; then
            ADDITIONAL_ORIGINS+=("$o")
        fi
    done
fi

for candidate_origin in "${ADDITIONAL_ORIGINS[@]}"; do
    if [ "$candidate_origin" = "http://127.0.0.1:8000" ||
         "$candidate_origin" = "http://localhost:8000" ]; then
        fail "loopback admin origins are not valid exam media origins"
    fi
done

# Validate every explicitly approved extra origin and serialize with a JSON
# encoder. Never place administrator-controlled text directly into JSON.
ORIGIN_ARRAY=$("$PYTHON_BIN" - "$EXAM_ORIGIN" "${ADDITIONAL_ORIGINS[@]}" <<'PYEOF'
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit

def reject(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)

def canonical_origin(raw):
    if not raw or len(raw) > 512 or any(ord(c) <= 0x20 or ord(c) == 0x7f for c in raw):
        reject("additional origin is empty, too long, or contains whitespace/control characters")
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        reject("malformed additional origin: " + str(error))
    if scheme not in ("https", "http") or not parsed.netloc or not host:
        reject("additional values must be absolute HTTPS origins (or loopback HTTP:8000)")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        reject("credentials are forbidden in additional origins")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        reject("additional values must be origins without paths, queries, or fragments")
    if port is not None and not 1 <= port <= 65535:
        reject("additional origin port is outside the valid range")
    try:
        address = ipaddress.ip_address(host)
        if getattr(address, "scope_id", None):
            reject("scoped IPv6 addresses are not valid policy origins")
        canonical_host = address.compressed.lower()
        if address.version == 6:
            canonical_host = "[" + canonical_host + "]"
        is_loopback = address.is_loopback
    except ValueError:
        try:
            canonical_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            reject("additional origin hostname is invalid")
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if not re.fullmatch(label + r"(?:\." + label + r")*", canonical_host):
            reject("additional origin hostname is invalid")
    if scheme != "https":
        reject("All additional origins must use HTTPS exclusively in production")
    authority = canonical_host + ((":" + str(port)) if port is not None else "")
    return scheme + "://" + authority

exam_origin = sys.argv[1]
approved = [exam_origin]
for raw in sys.argv[2:]:
    origin = canonical_origin(raw)
    if origin not in approved:
        approved.append(origin)
print(json.dumps([origin + "/*" for origin in approved], separators=(",", ":")))
PYEOF
) || fail "ALLOWED_ORIGINS contains an invalid origin; policy was not written."

POLICY_JSON=$(cat <<ENDPOLICY
{
  "_generated_by": "generate-chromium-policy.sh",
  "_generated_at": "${TIMESTAMP}",
  "_source_commit": "${GIT_COMMIT}",
  "_source_config": "${EXAM_CONF}",
  "_exam_origin": "${EXAM_ORIGIN}",
  "_do_not_edit": "This file is regenerated at boot. Changes will be overwritten.",

  "URLBlocklist": [
    "*"
  ],

  "URLAllowlist": ${ORIGIN_ARRAY},

  "VideoCaptureAllowedUrls": ${ORIGIN_ARRAY},

  "AudioCaptureAllowedUrls": ${ORIGIN_ARRAY},

  "ScreenCaptureAllowed": false,
  "ScreenCaptureAllowedByOrigins": [],

  "ExtensionInstallBlocklist": [
    "*"
  ],

  "DeveloperToolsAvailability": 2,
  "DownloadRestrictions": 3,
  "PrintingEnabled": false,
  "DefaultPopupsSetting": 2,
  "IncognitoModeAvailability": 1,
  "AllowFileSelectionDialogs": false,

  "PasswordManagerEnabled": false,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,

  "SavingBrowserHistoryDisabled": true,
  "BrowserSignin": 0,
  "SyncDisabled": true,
  "MetricsReportingEnabled": false,

  "BookmarkBarEnabled": false,
  "SpellCheckServiceEnabled": false,
  "TranslateEnabled": false,
  "DefaultSearchProviderEnabled": false,

  "BrowserAddPersonEnabled": false,
  "BrowserGuestModeEnabled": false,

  "DefaultClipboardSetting": 1,
  "PromptForDownloadLocation": false,
  "AllowDinosaurEasterEgg": false,
  "ExternalProtocolDialogShowAlwaysOpenCheckbox": false,
  "SafeBrowsingProtectionLevel": 1,
  "NetworkPredictionOptions": 2,
  "AlternateErrorPagesEnabled": false,
  "SearchSuggestEnabled": false,

  "ImportBookmarks": false,
  "ImportHistory": false,
  "ImportHomepage": false,
  "ImportSavedPasswords": false,
  "ImportSearchEngine": false,

  "RestoreOnStartup": 4,
  "RestoreOnStartupURLs": [],
  "HomepageIsNewTabPage": false,
  "NewTabPageLocation": "about:blank"
}
ENDPOLICY
)

# -----------------------------------------------------------------------
# Validate the generated JSON before writing anything
# -----------------------------------------------------------------------
echo "$POLICY_JSON" | "$PYTHON_BIN" -c "
import sys, json
try:
    data = json.load(sys.stdin)
    # Sanity-check required keys are present and non-empty
    required = ['URLBlocklist', 'URLAllowlist', 'VideoCaptureAllowedUrls', 'AudioCaptureAllowedUrls']
    for k in required:
        if k not in data or not isinstance(data[k], list) or len(data[k]) == 0:
            print('INVALID: key missing or empty: ' + k, file=sys.stderr)
            sys.exit(1)
    # Require the exact configured origin, including supported loopback development URLs.
    allowlist = data['URLAllowlist']
    expected_exam_origin = '${EXAM_ORIGIN}/*'
    if expected_exam_origin not in allowlist:
        print('INVALID: URLAllowlist does not contain the exact configured exam origin', file=sys.stderr)
        sys.exit(1)
    print('JSON validation PASSED: ' + str(len(data)) + ' policy keys, ' +
          str(len(allowlist)) + ' URLAllowlist entries', file=sys.stderr)
except json.JSONDecodeError as e:
    print('INVALID JSON: ' + str(e), file=sys.stderr)
    sys.exit(1)
" || fail "Generated JSON failed validation — policy NOT written."

if [ "$DRY_RUN" -eq 1 ]; then
    echo "$POLICY_JSON"
    log "Dry-run complete — policy printed to stdout, not installed."
    exit 0
fi

# -----------------------------------------------------------------------
# Write atomically to both policy paths
# -----------------------------------------------------------------------
WRITE_ERRORS=0
for POLICY_PATH in "${POLICY_PATHS[@]}"; do
    POLICY_DIR=$(dirname "$POLICY_PATH")

    if [ ! -d "$POLICY_DIR" ]; then
        mkdir -p "$POLICY_DIR" || { warn "Cannot create dir ${POLICY_DIR}"; WRITE_ERRORS=$((WRITE_ERRORS+1)); continue; }
    fi

    POLICY_TMP=$(mktemp "${POLICY_PATH}.tmp.XXXXXX") || { warn "Cannot create exclusive temporary policy for ${POLICY_PATH}"; WRITE_ERRORS=$((WRITE_ERRORS+1)); continue; }
    printf '%s\n' "$POLICY_JSON" > "$POLICY_TMP" || { warn "Cannot write tmp policy to ${POLICY_TMP}"; rm -f -- "$POLICY_TMP"; WRITE_ERRORS=$((WRITE_ERRORS+1)); continue; }

    # Validate the written tmp file before replacing the live policy
    "$PYTHON_BIN" - "$POLICY_TMP" <<'PYEOF' \
        || { warn "Tmp file JSON re-validation failed for ${POLICY_TMP}"; rm -f "$POLICY_TMP"; WRITE_ERRORS=$((WRITE_ERRORS+1)); continue; }
import json, sys
with open(sys.argv[1], encoding="utf-8") as policy_file:
    json.load(policy_file)
PYEOF

    chmod 0644 "$POLICY_TMP" || { warn "Cannot set readable policy mode on ${POLICY_TMP}"; rm -f -- "$POLICY_TMP"; WRITE_ERRORS=$((WRITE_ERRORS+1)); continue; }
    mv -fT -- "$POLICY_TMP" "$POLICY_PATH" || { warn "Atomic rename failed for ${POLICY_PATH}"; rm -f -- "$POLICY_TMP"; WRITE_ERRORS=$((WRITE_ERRORS+1)); continue; }

    log "Policy written to ${POLICY_PATH}"
done

if [ "$WRITE_ERRORS" -gt 0 ]; then
    fail "${WRITE_ERRORS} policy path(s) failed to update. Check warnings above."
fi

log "Chromium managed policy active:"
log "  Exam origin  : ${EXAM_ORIGIN}"
log "  Source config: ${EXAM_CONF}"
