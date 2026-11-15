#!/usr/bin/env bash
# SentinelGraph AI - Linux / macOS setup.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "[1/3] virtualenv"
py="$root/.venv/bin/python"
[ -x "$py" ] || python3 -m venv .venv

echo "[2/3] backend dependencies"
"$py" -m pip install --upgrade pip >/dev/null
"$py" -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt

echo "[3/3] frontend bundle"
(cd frontend && [ -d node_modules ] || npm install)
(cd frontend && npm run build)

echo
echo "Setup complete. Next: scripts/start.sh"
