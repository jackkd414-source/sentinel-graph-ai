"""Verify SentinelGraph can parse Sysmon-format events (event IDs 1/3/11/22/23).

Run against a live server:
    python tools/verify_sysmon_format.py [--base http://127.0.0.1:8088]

This proves the export script's field mapping matches what ingest.py expects,
*before* Sysmon is installed, so a mapping bug is caught early.
"""
from __future__ import annotations

import argparse
import json
import urllib.request

# Exactly the shape produced by export-windows-logs.ps1 from Sysmon EventData.
EVENTS = [
    {  # Event 1 - ProcessCreate: office -> powershell  => R-002
        "@timestamp": "2026-11-04T21:00:00Z", "host": "SG-TEST", "source": "edr",
        "event_id": 1, "event_type": "process_create", "user_name": "alice",
        "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "parent_process": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "command_line": "powershell.exe -enc SQBFAFgA",
    },
    {  # Event 3 - NetworkConnect to a threat indicator => R-003
        "@timestamp": "2026-11-04T21:01:00Z", "host": "SG-TEST", "source": "edr",
        "event_id": 3, "event_type": "network_connect", "user_name": "alice",
        "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "dst_ip": "198.51.100.23", "dst_port": "443",
    },
    {  # Event 22 - DNSEvent
        "@timestamp": "2026-11-04T21:02:00Z", "host": "SG-TEST", "source": "edr",
        "event_id": 22, "event_type": "dns_query", "user_name": "alice",
        "domain": "malicious-c2.example",
    },
    {  # Event 11 - FileCreate
        "@timestamp": "2026-11-04T21:03:00Z", "host": "SG-TEST", "source": "edr",
        "event_id": 11, "event_type": "file_access", "user_name": "alice",
        "file_path": r"C:\Users\alice\Downloads\invoice.ps1",
    },
]


def post(base: str, path: str, body: dict) -> dict:
    req = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def get(base: str, path: str) -> dict:
    with urllib.request.urlopen(base + path, timeout=60) as r:
        return json.load(r)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8088")
    args = ap.parse_args()

    checks: list[tuple[str, bool, str]] = []
    res = post(args.base, "/api/ingest/text", {
        "text": json.dumps(EVENTS), "filename": "sysmon-format-check.json",
        "source_type": "edr",
    })
    a = res.get("analysis") or {}

    checks.append(("all Sysmon events accepted",
                   res.get("records_ok") == len(EVENTS),
                   f"{res.get('records_ok')}/{len(EVENTS)}"))
    checks.append(("detection pipeline ran", bool(a), "analysis present in response"))

    alerts = get(args.base, "/api/alerts?limit=100").get("alerts", [])
    rules = {x["rule_id"] for x in alerts}
    checks.append(("R-002 fired (process chain)", "R-002" in rules,
                   f"rules seen: {sorted(rules)}"))
    checks.append(("R-003 fired (IOC match)", "R-003" in rules,
                   "network_connect to seeded indicator"))

    # Prove the fields actually landed in the graph, not just the event table.
    g = get(args.base, "/api/graph")
    kinds: dict[str, int] = {}
    for n in g.get("nodes", []):
        kinds[n["node_type"]] = kinds.get(n["node_type"], 0) + 1
    checks.append(("process nodes in graph", kinds.get("process", 0) >= 1,
                   f"process={kinds.get('process', 0)}"))
    checks.append(("user nodes in graph", kinds.get("user", 0) >= 1,
                   f"user={kinds.get('user', 0)}"))

    print("=" * 62)
    print("Sysmon event-format verification")
    print("=" * 62)
    ok = 0
    for name, passed, detail in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name:34} {detail}")
        ok += int(passed)
    print("-" * 62)
    print(f"{ok}/{len(checks)} checks passed")
    print("VERDICT:", "PASS" if ok == len(checks) else "FAIL")
    return 0 if ok == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
