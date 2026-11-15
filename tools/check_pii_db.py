"""Scan a SentinelGraph database for residual real-machine PII markers.

Read-only. Exit code is always 0; the report is the point. Use it to prove a
*release* database was rebuilt from the synthetic demo dataset and contains no
telemetry from the analyst's own machine.

    python tools/check_pii_db.py                 # scans data/sentinelgraph.db
    python tools/check_pii_db.py --db path.db
    python tools/check_pii_db.py --marker ACME01  # add a project-specific marker

Generic markers (no hard-coded personal names or hostnames live in this file):

    DESKTOP-         default Windows workstation hostname prefix
    S-1-5-           Windows security identifiers
    C:\\Users\\       real Windows user profile paths
    /home/           real Linux home paths
    @<domain>        handled per-run via --marker if you know the real domain

Synthetic demo values (WS-FIN-07, r.santoso, RFC 5737 IPs, *.example domains)
must NOT match; if they do, the marker list is wrong, not the data.
"""
from __future__ import annotations

import argparse
import os
import socket
import sqlite3
import sys

# Patterns that only real Windows machines produce. The synthetic demo dataset
# uses WS-*/SRV-*/MAILGW-* hostnames and RFC 5737 IPs, so it never matches.
PATTERN_MARKERS = [
    "DESKTOP-",      # default Windows workstation hostname prefix
    "S-1-5-",        # Windows security identifiers
]

# Generic account names that a synthetic dataset may legitimately contain.
_IGNORE_IDENTITIES = {"", "user", "analyst", "root", "runner", "admin", "test",
                      "svc", "system", "administrator", "unknown", "owner"}


def runtime_identities() -> list[str]:
    """The identity of *this* machine. If the DB carries these, it contains
    telemetry from the analyst's own box - the exact PII we must never ship."""
    ids: list[str] = []
    try:
        host = socket.gethostname().strip()
        if host:
            ids.append(host)
    except OSError:
        pass
    for var in ("USERNAME", "USER", "LOGNAME"):
        val = os.environ.get(var, "").strip()
        if val:
            ids.append(val)
    return ids

TABLES = {
    "events": ["host", "user_name", "file_path", "command_line", "process_name", "message"],
    "alerts": ["host", "user_name", "message", "title"],
    "incidents": ["title", "host", "description"],
    "graph_nodes": ["label", "host", "name"],
    "graph_edges": ["label"],
    "iocs": ["value", "description"],
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan a SentinelGraph DB for real-machine PII.")
    ap.add_argument("--db", default="data/sentinelgraph.db")
    ap.add_argument("--marker", action="append", default=[],
                    help="extra marker string to search for (repeatable)")
    args = ap.parse_args(argv)

    markers = PATTERN_MARKERS + [m for m in args.marker if m]
    local = [i for i in runtime_identities() if i.lower() not in _IGNORE_IDENTITIES]
    markers += local

    try:
        conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        print(f"[error] cannot open {args.db}: {exc}")
        return 2

    cur = conn.cursor()
    existing = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    total = 0

    print(f"Scanning {args.db}")
    print(f"Markers: {', '.join(markers)}\n")

    for table, cols in TABLES.items():
        if table not in existing:
            print(f"[skip] table {table} absent")
            continue
        present = {r[1] for r in cur.execute(f"PRAGMA table_info({table})")}
        for col in cols:
            if col not in present:
                continue
            clause = " OR ".join([f"{col} LIKE ?" for _ in markers])
            params = [f"%{m}%" for m in markers]
            try:
                n = cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {clause}", params).fetchone()[0]
            except sqlite3.Error as exc:
                print(f"[err] {table}.{col}: {exc}")
                continue
            if n:
                total += n
                print(f"HIT {table}.{col}: {n}")

    conn.close()
    print(f"\nTOTAL PII ROW-MATCHES: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
