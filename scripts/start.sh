#!/usr/bin/env bash
# SentinelGraph AI - Linux / macOS startup (localhost-only by default).
#   SG_PORT=9000 scripts/start.sh
#   SG_AUTH_TOKEN=<secret> scripts/start.sh 0.0.0.0   # LAN, requires the token
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

host="${1:-127.0.0.1}"
py="$root/.venv/bin/python"
[ -x "$py" ] || { echo "Virtualenv missing. Run scripts/setup.sh first." >&2; exit 1; }

export PYTHONPATH="$root/backend"

# Master key: .env -> data/.master_key -> generate once and persist.
# A random key per start would make stored provider credentials undecryptable.
if [ -z "${SG_MASTER_KEY:-}" ] && [ -f "$root/.env" ]; then
  SG_MASTER_KEY="$(sed -nE 's/^[[:space:]]*SG_MASTER_KEY[[:space:]]*=[[:space:]]*//p' "$root/.env" | head -1 | tr -d '"'"'"' ')"
  export SG_MASTER_KEY
fi
key_file="$root/data/.master_key"
if [ -z "${SG_MASTER_KEY:-}" ] && [ -f "$key_file" ]; then
  SG_MASTER_KEY="$(tr -d '\r\n' < "$key_file")"
  export SG_MASTER_KEY
fi
if [ -z "${SG_MASTER_KEY:-}" ]; then
  mkdir -p "$root/data"
  SG_MASTER_KEY="$("$py" -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
  export SG_MASTER_KEY
  printf '%s' "$SG_MASTER_KEY" > "$key_file"
  echo "Generated SG_MASTER_KEY -> data/.master_key (reused on next start)"
fi
port="${SG_PORT:-8088}"

if [ ! -f "$root/data/sentinelgraph.db" ]; then
  echo "Bootstrapping empty database + synthetic demo..."
  "$py" -m sentinelgraph init
  "$py" -m sentinelgraph load-demo
fi

# The app itself refuses a non-loopback bind without SG_AUTH_TOKEN.
exec "$py" -m sentinelgraph serve --host "$host" --port "$port"
