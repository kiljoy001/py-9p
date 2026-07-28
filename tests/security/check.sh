#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="$ROOT/.venv/bin"

bandit_bin="$PY/bandit"
[ -x "$bandit_bin" ] || bandit_bin="$(command -v bandit)"
audit_bin="$PY/pip-audit"
[ -x "$audit_bin" ] || audit_bin="$(command -v pip-audit)"

echo "=== bandit ==="
"$bandit_bin" -r "$ROOT/py9p" -q
echo "bandit: clean"

echo "=== pip-audit ==="
"$audit_bin" --skip-editable
echo "pip-audit: clean"
