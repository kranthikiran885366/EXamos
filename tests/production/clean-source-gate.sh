#!/usr/bin/env bash
# P0 release runs require a clean, identifiable commit.
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${EXAMOS_PRODUCTION_ARTIFACT_DIR:-$WORKSPACE/artifacts/production}"
mkdir -p "$OUT"
commit="$(git -C "$WORKSPACE" rev-parse HEAD)"
status_txt="$(git -C "$WORKSPACE" status --porcelain --untracked-files=all -- . \
    ':(exclude)artifacts/**' \
    ':(exclude)image/p0/output/**' \
    ':(exclude)build/**' \
    ':(exclude)cache/**' || true)"
count=0
if [ -n "$status_txt" ]; then
    count="$(printf '%s\n' "$status_txt" | wc -l | tr -d ' ')"
fi
tree=CLEAN
result=PASS
reason="HEAD $commit is identifiable and the source worktree is clean"
if [ "$count" -gt 0 ]; then
    tree=DIRTY
    result=BLOCKED
    reason="source worktree has $count modified or untracked paths; commit or preserve unrelated work before a P0 release run"
fi
python3 - "$OUT/clean-source.json" "$commit" "$tree" "$count" "$result" "$reason" <<'PY'
import json, sys, datetime
out, commit, tree, count, result, reason = sys.argv[1:7]
report = {
    "schema": "examos.production.clean-source.v1",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "source_tree_state": tree,
    "dirty_path_count": int(count),
    "result": result,
    "reason": reason,
    "release_eligible": result == "PASS",
}
open(out, "w", encoding="utf-8").write(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
sys.exit(0 if result == "PASS" else 2)
PY
