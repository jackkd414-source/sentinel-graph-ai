#!/usr/bin/env bash
# Canonical verification: backend tests -> typecheck -> release PII gate.
# Exit 0 only if every stage passes.
set -uo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

py="$root/.venv/bin/python"; [ -x "$py" ] || py="$root/.venv/Scripts/python.exe"
[ -x "$py" ] || { echo "FAIL: no venv interpreter; run scripts/setup.sh" >&2; exit 1; }

fail=0
echo "== pytest =="
"$py" -m pytest || fail=1
echo "== tsc =="
node "$root/frontend/node_modules/typescript/bin/tsc" -b "$root/frontend" || fail=1
echo "== release gate =="
"$py" tools/make_release.py || fail=1

echo
[ "$fail" -eq 0 ] && echo "VERIFY: PASS" || echo "VERIFY: FAIL"
exit "$fail"
