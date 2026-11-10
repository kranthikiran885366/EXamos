#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${1:-}"
[[ -n "$WORKSPACE" && -d "$WORKSPACE" ]] || {
    echo "Usage: $0 WORKSPACE" >&2
    exit 2
}

while IFS= read -r -d '' file; do
    bash -n "$file"
done < <(find "$WORKSPACE/tests/virtual-hardware" -type f -name '*.sh' -print0)

python3 - "$WORKSPACE/tests/virtual-hardware" <<'PY'
import ast
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
files = [
    path for path in root.rglob("*")
    if path.is_file() and path.suffix in {".sh", ".py", ".md"}
]
files.append(root.parent / "server" / "postgres-schema-bootstrap-test.c")
for path in files:
    if not path.is_file():
        continue
    content = path.read_bytes()
    if b"\r" in content:
        raise SystemExit(f"CR character found in {path}")
    if not content.endswith(b"\n"):
        raise SystemExit(f"Missing final newline in {path}")
    for line_number, line in enumerate(content.splitlines(), start=1):
        if line.endswith((b" ", b"\t")):
            raise SystemExit(f"Trailing whitespace in {path}:{line_number}")
    if path.suffix == ".py":
        ast.parse(content.decode("utf-8"), filename=str(path))
print("Python syntax checks passed.")
PY

git -C "$WORKSPACE" diff --check -- .gitignore tests/server/postgres-auth-e2e-test.c
