"""CLI entry point: `python -m sentinelgraph` runs the server.

Subcommands kept deliberately tiny:
  serve    - run the API + built frontend (default)
  init     - create the database and default project, then exit
  keys     - generate an SG_MASTER_KEY value
  load-demo- Run the demo dataset through the pipeline headlessly (no server)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import demo_data
from .config import get_settings
from .db import connect, init_db, seed_iocs, cursor
from .ingest import parse_json_text
from .pipeline import analyze_project, store_import
from .timeutil import now_iso


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from . import auth
    from .config import enforce_secure_binding, is_loopback_host

    s = get_settings()
    host = args.host or s.host
    # Create the analyst account before the bind decision. An account is a valid
    # authentication path, so the guard has to see whether one exists, and the
    # operator should learn about the default password before the port opens
    # rather than after.
    init_db()
    account = auth.ensure_default_user()
    # Fail before uvicorn binds: never expose an unauthenticated API off-host.
    enforce_secure_binding(
        host, s.auth_token,
        user_auth_available=bool(account),
        default_password_in_use=auth.uses_default_password(),
        allow_default_password=s.allow_default_password,
    )
    # The weak-exposure warning is emitted by the app's own startup hook, which
    # runs on both this path and a direct `uvicorn sentinelgraph.api:app`, so it
    # is deliberately not repeated here.
    if not is_loopback_host(host):
        os.environ["SG_HOST"] = host  # let the app's own startup guard agree
    print(f"SentinelGraph AI  ->  http://{host}:{args.port or s.port}")
    if not is_loopback_host(host):
        print("  auth    : login required on every /api request"
              + (", or the shared SG_AUTH_TOKEN" if s.auth_token else ""))
    print(f"  database : {s.db_path}")
    print("  AI mode  : " + ("provider configured" if s.master_key else
                              "core-only until a provider is configured"))
    uvicorn.run("sentinelgraph.api:app", host=host,
                port=args.port or s.port, reload=args.reload, log_level="info")
    return 0


def cmd_init(_: argparse.Namespace) -> int:
    init_db()
    from .api import _ensure_default_project
    pid = _ensure_default_project()
    print(f"Database ready. Default project id={pid}")
    return 0


def cmd_keys(_: argparse.Namespace) -> int:
    from .security import generate_master_key
    key = generate_master_key()
    print("Add this line to your .env file:\n")
    print(f"SG_MASTER_KEY={key}\n")
    print("Store it securely. Losing it makes stored provider keys unrecoverable.")
    return 0


def cmd_load_demo(args: argparse.Namespace) -> int:
    import hashlib

    init_db()
    from .api import _ensure_default_project
    pid = _ensure_default_project()
    body = json.dumps(demo_data.all_events(), indent=1)
    parsed = parse_json_text(body, "demo")
    res = store_import(pid, "sentinelgraph-synthetic-v1.json", "demo_synthetic", parsed,
                       hashlib.sha256(body.encode()).hexdigest(), len(body.encode()),
                       None, is_synthetic=True, artifact_kind="demo_seed")
    result = analyze_project(pid)
    print(json.dumps({"import": res, "analysis": result}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinelgraph")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("serve", help="run the web server")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--reload", action="store_true")
    s.set_defaults(func=cmd_serve)

    i = sub.add_parser("init", help="initialise the database")
    i.set_defaults(func=cmd_init)

    k = sub.add_parser("keys", help="generate an SG_MASTER_KEY")
    k.set_defaults(func=cmd_keys)

    d = sub.add_parser("load-demo", help="load and analyse the demo dataset")
    d.set_defaults(func=cmd_load_demo)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        args = p.parse_args(["serve"])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
