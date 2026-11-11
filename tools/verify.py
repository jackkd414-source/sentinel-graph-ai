"""End-to-end verification of SentinelGraph AI.

Exercises the real HTTP API of a running server and prints a PASS/FAIL verdict.
Exit code is the verdict: 0 = all checks passed, 1 = at least one failed.

It does NOT assert on anything it cannot observe. Every check either reads a
database-backed endpoint or a file the server produced.

Usage:
    ./.venv/Scripts/python.exe tools/verify.py --base http://127.0.0.1:8088
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

CHECKS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str) -> None:
    CHECKS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def http(base: str, path: str, method: str = "GET", body: dict | None = None,
         timeout: int = 120) -> tuple[int, bytes]:
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def jget(base: str, path: str):
    code, raw = http(base, path)
    if code != 200:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8088")
    ap.add_argument("--skip-ai", action="store_true",
                    help="skip AI checks (no provider configured)")
    ap.add_argument("--reset", action="store_true",
                    help="DESTRUCTIVE: wipe the project and load the synthetic demo "
                         "dataset before verifying. Without this flag the verifier "
                         "runs against whatever data is currently loaded.")
    args = ap.parse_args(argv)
    b = args.base

    # ---------- core pipeline ----------
    code, _ = http(b, "/api/health")
    record("server responds to /api/health", code == 200, f"HTTP {code}")

    health = jget(b, "/api/health") or {}
    record("database initialised", "db" in json.dumps(health).lower(),
           health.get("db", {}).get("path", "") if isinstance(health.get("db"), dict) else "")

    # Guard: do not silently destroy real imported data. The demo loader with
    # reset=true deletes every event/alert/incident in the project, so it only
    # runs when the operator explicitly asks for it.
    ev = (jget(b, "/api/events?limit=1") or {})
    events = ev.get("total") or ev.get("count") or len(ev.get("events") or [])
    if args.reset:
        http(b, "/api/demo/load?reset=true", "POST")
        ev = (jget(b, "/api/events?limit=1") or {})
        events = ev.get("total") or ev.get("count") or 0
        record("demo dataset loaded", events >= 20, f"{events} events")
    else:
        record("server has data to verify", events > 0,
               f"{events} events (existing project data preserved; "
               f"pass --reset to load the synthetic demo set)")
        if events == 0:
            print("\nNo events present. Load the demo dataset in the UI, or re-run "
                  "with --reset to wipe and load it explicitly.\n")
            return 1


    incs = (jget(b, "/api/incidents") or {}).get("incidents") or []
    # The synthetic demo dataset yields 4 incidents; real telemetry usually
    # yields fewer (often just volume-spike alerts). Only demand 3+ when the
    # demo set was explicitly loaded, so a clean real-data run is not a false FAIL.
    need = 3 if args.reset else 1
    record(f"incidents created (>= {need})", len(incs) >= need,
           f"{len(incs)} incidents"
           + ("" if args.reset else " - real data may legitimately produce few"))

    if not incs:
        print("\nNo incidents: cannot continue.")
        return 1
    iid = incs[0]["id"]

    det = jget(b, f"/api/incidents/{iid}") or {}
    record("incident detail has alerts", bool(det.get("alerts")), f"{len(det.get('alerts') or [])} alerts")
    record("incident detail has timeline", bool(det.get("timeline")), f"{len(det.get('timeline') or [])} events")
    # The per-incident attack graph is rendered client-side: the UI takes the
    # global graph and keeps nodes reachable from this incident's alerts. So the
    # contract to verify is that the alert-derived entities match graph nodes.
    det_node_keys = set()
    for a in (det.get("alerts") or []):
        for ent in (a.get("entities") or []):
            det_node_keys.add(ent if isinstance(ent, str) else str(ent))
    g_all = jget(b, "/api/graph") or {}
    node_keys = {n.get("node_key") for n in (g_all.get("nodes") or [])}
    record("incident entities are present in the attack graph",
           not det_node_keys or bool(det_node_keys & node_keys),
           f"{len(det_node_keys & node_keys) if det_node_keys else 'n/a'} matched")

    # every alert must cite at least one real event
    alerts = det.get("alerts") or []
    ev_ids = {e["id"] for e in (det.get("timeline") or [])}
    all_cited = all(a.get("evidence") or a.get("evidence_event_ids") for a in alerts)
    record("all alerts carry evidence references", all_cited, f"{len(alerts)} alerts checked")

    cited_ids = {e["id"] for a in alerts for e in (a.get("evidence") or [])}
    record("citations resolve to stored events", cited_ids <= ev_ids if cited_ids else False,
           f"cited={sorted(cited_ids)} stored={sorted(ev_ids)}")

    # ---------- shape consistency ----------
    al = (jget(b, "/api/alerts?limit=1") or {}).get("alerts") or []
    if al:
        has_obj = "evidence" in al[0]
        has_ids = "evidence_event_ids" in al[0]
        record("/api/alerts exposes evidence objects AND ids", has_obj and has_ids,
               f"evidence={has_obj} evidence_event_ids={has_ids}")

    # ---------- graph ----------
    g = jget(b, "/api/graph") or {}
    record("attack graph built", len(g.get("nodes") or []) > 5,
           f"{len(g.get('nodes') or [])} nodes / {len(g.get('edges') or [])} edges")
    edges = g.get("edges") or []
    # Structural edges (host->ip, user->host derived from identifier co-occurrence)
    # legitimately carry no single event: they are DERIVED relations. What must
    # hold is that every edge is either evidence-backed or explicitly derived.
    backed = [e for e in edges if e.get("evidence_event_ids")]
    derived = [e for e in edges if e.get("status") in ("inferred", "derived")]
    unaccounted = [e for e in edges
                   if not e.get("evidence_event_ids") and e.get("status") not in ("inferred", "derived")]
    record("every graph edge is evidence-backed or explicitly derived",
           not unaccounted,
           f"{len(backed)} evidenced / {len(derived)} derived / {len(unaccounted)} unaccounted")

    # ---------- report ----------
    code, raw = http(b, f"/api/incidents/{iid}/report?fmt=md")
    md = raw.decode("utf-8", "replace")
    record("markdown report generated", code == 200 and len(md) > 2000, f"{len(md)} chars")
    for section in ("Executive summary", "Chronology", "Findings", "Limitations",
                    "Known impact vs. unestablished impact"):
        record(f"report section: {section}", section in md, "")
    record("report refuses to claim confirmed compromise",
           "NOT established" in md, "explicit non-claim present")

    code, raw = http(b, f"/api/incidents/{iid}/report?fmt=html")
    record("html report generated", code == 200 and b"<html" in raw.lower(), f"HTTP {code}")

    code, raw = http(b, f"/api/incidents/{iid}/report?fmt=json")
    record("json report generated", code == 200 and raw.strip().startswith(b"{"), f"HTTP {code}")

    # ---------- frontend ----------
    code, raw = http(b, "/")
    record("frontend served", code == 200 and b"<div id=\"root\"" in raw, f"HTTP {code}")

    # ---------- AI (optional) ----------
    if not args.skip_ai:
        st = (jget(b, "/api/ai/status") or {})
        # The endpoint nests the payload under "status".
        st = st.get("status") or st
        mode = st.get("mode")
        record("ai status endpoint reachable", mode is not None, f"mode={mode}")

        res = None
        code, raw = http(b, f"/api/incidents/{iid}/analyze?task=summarize", "POST", timeout=180)
        try:
            res = json.loads(raw)
        except ValueError:
            res = None

        if mode in ("core_only", "missing_credential"):
            record("AI analysis degrades honestly without provider",
                   code == 200 and (res or {}).get("status") == "no_provider",
                   f"status={(res or {}).get('status')}")
        else:
            record("AI analysis returned a status", res is not None and "status" in (res or {}),
                   f"status={(res or {}).get('status')}")
            if res and res.get("status") in ("ok", "ok_with_warnings"):
                a = res["analysis"]
                rec = a.get("stripped_reference_count", 0)
                print(f"       evidence guard stripped {rec} fabricated citation(s)")
                bad = [h for h in a.get("hypotheses", [])
                       if h.get("supporting_event_ids")
                       and not set(h["supporting_event_ids"]) <= ev_ids]
                record("no fabricated event ID survived validation", not bad,
                       f"{len(bad)} bad hypotheses")
                statuses = {h.get("evidence_status") for h in a.get("hypotheses", [])}
                record("hypotheses carry evidence_status tags",
                       statuses <= {"supported", "contested", "unsupported"} and bool(statuses) or not a.get("hypotheses"),
                       str(sorted(s for s in statuses if s)))
            elif res and res.get("status") in ("validation_failed", "error"):
                # A failing model must not corrupt the report.
                _, raw2 = http(b, f"/api/incidents/{iid}/report?fmt=md")
                record("report survives failed AI run",
                       b"did not produce usable output" in raw2 or b"deterministic core" in raw2,
                       "honest failure recorded")

    # ---------- verdict ----------
    failed = [c for c in CHECKS if not c[1]]
    print()
    print("=" * 62)
    print(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("FAILED:")
        for n, _, d in failed:
            print(f"  - {n} :: {d}")
        print("VERDICT: FAIL")
        return 1
    print("VERDICT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
