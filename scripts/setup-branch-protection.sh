#!/usr/bin/env bash
# Configure GitHub branch protection rules on `main` requiring all P0-P5 CI gates.
# Requires: gh CLI authenticated with repo admin permissions.
set -euo pipefail

REPO="${1:-kranthikiran885366/EXamos}"
BRANCH="main"

if ! command -v gh >/dev/null 2>&1; then
    echo "ERROR: GitHub CLI (gh) is required." >&2
    exit 1
fi

echo "Applying branch protection to ${REPO}:${BRANCH}..."
gh api --method PUT "repos/${REPO}/branches/${BRANCH}/protection" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "P0 Gate",
      "P1 Gate",
      "P2 Gate",
      "P3 Gate",
      "P4 Gate",
      "P5 Gate"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": true
}
JSON
echo "Branch protection configured on ${REPO}:${BRANCH}."
