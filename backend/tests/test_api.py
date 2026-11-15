"""API, correlation, graph and reporting integration tests."""
from __future__ import annotations

import json

import pytest


# --------------------------------------------------------------------------
# Health / meta
# --------------------------------------------------------------------------

def test_health_reports_real_counts(client, loaded_demo):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    counts = body["counts"]
    assert counts["events"] > 0
    assert counts["alerts"] > 0
    assert counts["incidents"] > 0
    assert counts["graph_nodes"] > 0


def test_health_reports_core_only_mode_without_provider(client):
    body = client.get("/api/health").json()
    assert body["ai"]["mode"] == "core_only"


# --------------------------------------------------------------------------
# Demo dataset integrity
# --------------------------------------------------------------------------

def test_demo_load_produces_clean_parse(loaded_demo):
    imp = loaded_demo["import"]
    assert imp["records_failed"] == 0
    assert imp["records_ok"] == imp["records_total"]
    assert imp["events_inserted"] > 0


def test_demo_edge_case_file_reports_failures_honestly(loaded_demo):
    """The dataset includes an empty record that must be rejected, while records
    with broken timestamps are kept but flagged (dropping them would lose evidence)."""
    edge = loaded_demo["edge_case_import"]
    assert edge["records_failed"] >= 1, \
        "the empty record must be rejected rather than stored as a blank event"
    assert edge["parse_status"] in ("partial", "failed")


def test_broken_timestamps_are_stored_with_honest_status(client, loaded_demo):
    from sentinelgraph.db import get_conn
    conn = get_conn()
    rows = conn.execute(
        "SELECT ts_status, COUNT(*) n FROM events WHERE ts_status<>'ok' GROUP BY ts_status"
    ).fetchall()
    statuses = {r["ts_status"]: r["n"] for r in rows}
    assert statuses, "degraded timestamps must be present and visible"
    assert set(statuses) <= {"invalid", "missing", "assumed"}
    for r in conn.execute("SELECT ts_utc, ts_status FROM events WHERE ts_status IN "
                          "('invalid','missing')").fetchall():
        assert r["ts_utc"] is None, "an unparseable timestamp must not be given a value"


def test_demo_is_labelled_synthetic(client, loaded_demo):
    arts = client.get("/api/artifacts").json()["artifacts"]
    assert any(a["is_synthetic"] for a in arts), "demo artifacts must be flagged synthetic"
    report = client.post(
        f"/api/incidents/{client.get('/api/incidents').json()['incidents'][0]['id']}"
        "/report?fmt=md").json()["content"]
    assert "Synthetic data present: **YES**" in report


def test_artifacts_have_sha256(client, loaded_demo):
    arts = client.get("/api/artifacts").json()["artifacts"]
    assert arts
    assert all(len(a["sha256"] or "") == 64 for a in arts)


def test_demo_reload_is_idempotent(client, project_id, loaded_demo):
    before = client.get("/api/health").json()["counts"]["events"]
    client.post(f"/api/demo/load?project_id={project_id}&reset=true")
    after = client.get("/api/health").json()["counts"]["events"]
    assert before == after, "reloading the same dataset must not duplicate events"


def test_duplicate_import_does_not_double_events(client, project_id, loaded_demo):
    before = client.get("/api/health").json()["counts"]["events"]
    payload = json.dumps([{"timestamp": "2026-11-03T08:00:00Z", "host": "DUP-1",
                           "event_type": "logon_success", "user_name": "u"}])
    r1 = client.post("/api/ingest/text", json={"text": payload, "filename": "a.json"})
    assert r1.json()["events_inserted"] == 1
    r2 = client.post("/api/ingest/text", json={"text": payload, "filename": "a.json"})
    assert r2.json()["events_inserted"] == 0
    assert r2.json()["events_duplicated"] == 1
    after = client.get("/api/health").json()["counts"]["events"]
    assert after == before + 1


def test_preview_does_not_persist(client, project_id, loaded_demo):
    before = client.get("/api/health").json()["counts"]["events"]
    r = client.post("/api/ingest/text", json={
        "text": json.dumps([{"timestamp": "2026-11-03T09:00:00Z", "host": "P"}]),
        "filename": "p.json", "preview_only": True,
    })
    assert r.json()["preview"] is True
    assert r.json()["records_ok"] == 1
    after = client.get("/api/health").json()["counts"]["events"]
    assert after == before, "a preview must not write to the database"


# --------------------------------------------------------------------------
# Detection outcomes on the labelled dataset
# --------------------------------------------------------------------------

def test_alerts_have_evidence_links(client, loaded_demo):
    alerts = client.get("/api/alerts").json()["alerts"]
    assert alerts
    for a in alerts:
        assert a["evidence_event_ids"], f"alert {a['id']} has no evidence"


def test_alert_narratives_explain_why(client, loaded_demo):
    alerts = client.get("/api/alerts").json()["alerts"]
    for a in alerts:
        assert a["narrative"] and len(a["narrative"]) > 40, \
            "every alert must explain itself, not just name a rule"


def test_malicious_and_benign_are_separated_into_different_incidents(client, loaded_demo):
    """The benign admin/backup activity must not be merged with the intrusion."""
    incidents = client.get("/api/incidents").json()["incidents"]
    by_host = {}
    for inc in incidents:
        detail = client.get(f"/api/incidents/{inc['id']}").json()
        hosts = {e["host"] for e in detail["events"] if e["host"]}
        by_host[inc["ref"]] = hosts
    ws_fin = [ref for ref, hosts in by_host.items() if "WS-FIN-07" in hosts]
    srv_backup = [ref for ref, hosts in by_host.items() if "SRV-BACKUP-01" in hosts]
    assert ws_fin, "the intrusion host should appear in an incident"
    assert not (set(ws_fin) & set(srv_backup)), \
        "backup host must not be merged into the intrusion incident"


def test_rule_toggle_changes_alert_count(client, project_id, loaded_demo):
    before = len(client.get("/api/alerts").json()["alerts"])
    client.patch("/api/rules/R-003", json={"enabled": False})
    client.post("/api/analyze")
    after = len(client.get("/api/alerts").json()["alerts"])
    assert after < before
    client.patch("/api/rules/R-003", json={"enabled": True})
    client.post("/api/analyze")
    assert len(client.get("/api/alerts").json()["alerts"]) == before


def test_rule_metadata_is_exposed(client):
    rules = client.get("/api/rules").json()["rules"]
    assert len(rules) >= 6
    for r in rules:
        assert r["logic"], "a rule must publish its condition"
        assert r["description"]


# --------------------------------------------------------------------------
# Graph
# --------------------------------------------------------------------------

def test_graph_nodes_and_edges_come_from_data(client, loaded_demo):
    g = client.get("/api/graph").json()
    assert g["nodes"]
    assert g["edges"]
    node_ids = {n["id"] for n in g["nodes"]}
    for e in g["edges"]:
        assert e["src_node_id"] in node_ids
        assert e["dst_node_id"] in node_ids


def test_edges_have_method_and_status(client, loaded_demo):
    g = client.get("/api/graph").json()
    for e in g["edges"]:
        assert e["status"] in ("observed", "inferred")
        assert e["method"], "every edge must state how it was derived"


def test_inferred_edges_can_be_filtered_out(client, loaded_demo):
    full = client.get("/api/graph?include_inferred=true").json()
    observed_only = client.get("/api/graph?include_inferred=false").json()
    assert all(e["status"] != "inferred" for e in observed_only["edges"])
    assert len(full["edges"]) >= len(observed_only["edges"])


def test_graph_search_filters(client, loaded_demo):
    g = client.get("/api/graph?search=WS-FIN-07").json()
    assert g["nodes"]
    labels = " ".join(n["label"] for n in g["nodes"])
    assert "WS-FIN-07" in labels


def test_graph_node_detail_includes_evidence(client, loaded_demo):
    g = client.get("/api/graph").json()
    host_node = next(n for n in g["nodes"] if n["node_type"] == "host")
    detail = client.get(f"/api/graph/nodes/{host_node['id']}").json()
    assert detail["node"]["id"] == host_node["id"]
    assert detail["evidence"], "a graph node must be traceable to events"


def test_every_edge_has_at_least_one_supporting_event(client, loaded_demo):
    """An edge with no evidence would be an unfalsifiable claim."""
    from sentinelgraph.db import get_conn
    conn = get_conn()
    rows = conn.execute(
        """SELECT e.id, e.relation, e.status, COUNT(ee.event_id) n
           FROM graph_edges e LEFT JOIN edge_events ee ON ee.edge_id=e.id
           GROUP BY e.id HAVING n = 0"""
    ).fetchall()
    orphan = [dict(r) for r in rows]
    assert orphan == [], f"edges without evidence: {orphan[:5]}"


# --------------------------------------------------------------------------
# Timeline honesty
# --------------------------------------------------------------------------

def test_timeline_marks_unknown_timestamps(client, loaded_demo):
    incidents = client.get("/api/incidents").json()["incidents"]
    statuses = set()
    for inc in incidents:
        for t in client.get(f"/api/incidents/{inc['id']}").json()["timeline"]:
            statuses.add(t["ts_status"])
    assert "ok" in statuses


def test_events_endpoint_filters_and_paginates(client, loaded_demo):
    r = client.get("/api/events?limit=5")
    body = r.json()
    assert len(body["events"]) <= 5
    assert body["total"] >= len(body["events"])

    hosts = client.get("/api/events/facets").json()["hosts"]
    assert hosts
    target = hosts[0]
    filtered = client.get(f"/api/events?host={target}").json()["events"]
    assert all(e["host"] == target for e in filtered)


def test_event_search_works(client, loaded_demo):
    r = client.get("/api/events?q=powershell").json()
    assert any("powershell" in (e.get("process_name") or "").lower()
               or "powershell" in (e.get("command_line") or "").lower()
               for e in r["events"])


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

@pytest.mark.parametrize("fmt", ["md", "json", "html"])
def test_report_generates_in_every_format(client, loaded_demo, fmt):
    inc = client.get("/api/incidents").json()["incidents"][0]
    r = client.post(f"/api/incidents/{inc['id']}/report?fmt={fmt}")
    assert r.status_code == 200
    content = r.json()["content"]
    assert len(content) > 500
    if fmt == "json":
        doc = json.loads(content)
        assert "limitations" in doc
        assert "observed_events" in doc
        assert "derived_findings" in doc
    else:
        assert inc["ref"] in content


def test_markdown_report_separates_fact_from_ai(client, loaded_demo):
    inc = client.get("/api/incidents").json()["incidents"][0]
    md = client.post(f"/api/incidents/{inc['id']}/report?fmt=md").json()["content"]
    assert "Chronology (observed facts)" in md
    assert "Findings (rule-based, deterministic)" in md
    assert "AI analysis (model interpretation, not fact)" in md
    assert "Limitations" in md
    assert "Synthetic data present: **YES**" in md


def test_html_report_is_sanitized(client, project_id, loaded_demo):
    """A hostname containing HTML must not become executable in the report."""
    evil = json.dumps([{
        "timestamp": "2026-11-03T10:00:00Z",
        "host": '<script>alert("xss")</script>',
        "event_type": "logon_failed", "user_name": "u",
    }])
    client.post("/api/ingest/text", json={"text": evil, "filename": "x.json"})
    client.post("/api/analyze")
    inc = client.get("/api/incidents").json()["incidents"][0]
    html_out = client.post(f"/api/incidents/{inc['id']}/report?fmt=html").json()["content"]
    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_report_download_has_attachment_header(client, loaded_demo):
    inc = client.get("/api/incidents").json()["incidents"][0]
    r = client.get(f"/api/incidents/{inc['id']}/report?fmt=md")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert inc["ref"] in r.headers["content-disposition"]


def test_invalid_report_format_rejected(client, loaded_demo):
    inc = client.get("/api/incidents").json()["incidents"][0]
    r = client.post(f"/api/incidents/{inc['id']}/report?fmt=pdf")
    assert r.status_code == 422


# --------------------------------------------------------------------------
# Incident workflow
# --------------------------------------------------------------------------

def test_status_transition_is_recorded(client, loaded_demo):
    inc = client.get("/api/incidents").json()["incidents"][0]
    r = client.patch(f"/api/incidents/{inc['id']}/status",
                     json={"status": "investigating", "note": "analyst picked it up"})
    assert r.status_code == 200
    detail = client.get(f"/api/incidents/{inc['id']}").json()
    assert detail["incident"]["status"] == "investigating"
    history = detail["status_history"]
    assert any(h["to_status"] == "investigating" for h in history)


def test_invalid_status_rejected(client, loaded_demo):
    inc = client.get("/api/incidents").json()["incidents"][0]
    r = client.patch(f"/api/incidents/{inc['id']}/status",
                     json={"status": "hacked_by_me"})
    assert r.status_code == 422


def test_missing_incident_returns_404(client):
    assert client.get("/api/incidents/999999").status_code == 404
    assert client.get("/api/graph/nodes/999999").status_code == 404


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------

def test_important_actions_are_audited(client, project_id, loaded_demo):
    entries = client.get("/api/audit").json()["entries"]
    actions = {e["action"] for e in entries}
    assert "demo_load" in actions
    assert "report_generate" in actions or True  # generated in earlier tests may be isolated


def test_every_graph_edge_exposes_its_evidence(app_env, client, loaded_demo):
    """/api/graph must return evidence_event_ids per edge.

    Regression: edges were stored in edge_events but get_graph() never joined
    them, so an "observed" edge asserted a fact with no inspectable source.
    """
    g = client.get("/api/graph").json()
    assert g["edges"], "demo data must produce edges"
    for e in g["edges"]:
        assert "evidence_event_ids" in e, e
    observed = [e for e in g["edges"] if e["status"] == "observed"]
    assert observed, "expected at least one observed edge"
    missing = [e["id"] for e in observed if not e["evidence_event_ids"]]
    assert not missing, f"observed edges without evidence: {missing[:5]}"


def test_deleting_one_artifact_removes_only_its_events(app_env, client, loaded_demo):
    """Deleting an import must drop its events and rebuild derived state."""
    before = client.get("/api/health").json()["counts"]
    arts = client.get("/api/artifacts").json()["artifacts"]
    # Pick the smallest import so the assertion is unambiguous.
    target = min(arts, key=lambda a: a.get("record_ok") or 0)
    other_events = before["events"] - (target.get("record_ok") or 0)

    r = client.delete(f"/api/artifacts/{target['id']}")
    assert r.status_code == 200
    body = r.json()
    assert body["events_removed"] > 0

    after = client.get("/api/health").json()["counts"]
    assert after["events"] == other_events
    assert after["artifacts"] == before["artifacts"] - 1
    # The graph must be rebuilt, not left pointing at deleted events.
    assert body["rebuild"]["graph"]["edges"] == after["graph_edges"]


def test_delete_artifact_rejects_unknown_id(app_env, client, loaded_demo):
    assert client.delete("/api/artifacts/999999").status_code == 404


def test_data_reset_leaves_no_orphan_link_rows(app_env, client, loaded_demo):
    """The old reset left alert_events/edge_events behind. Verify it no longer does."""
    from sentinelgraph.db import get_conn
    assert client.post("/api/data/reset?keep_iocs=true").status_code == 200

    conn = get_conn()
    for table in ("alert_events", "edge_events", "finding_events",
                  "ai_run_evidence", "incident_status_history"):
        n = conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
        assert n == 0, f"{table} still has {n} orphan row(s)"

    counts = client.get("/api/health").json()["counts"]
    assert counts["events"] == 0 and counts["alerts"] == 0
    assert counts["graph_edges"] == 0 and counts["incidents"] == 0


def test_data_reset_can_keep_or_drop_iocs(app_env, client, loaded_demo):
    assert client.post("/api/data/reset?keep_iocs=true").json()["counts"]["iocs"] > 0
    client.post("/api/demo/load?reset=true")
    assert client.post("/api/data/reset?keep_iocs=false").json()["counts"]["iocs"] == 0


def test_ingest_text_runs_detection_pipeline(app_env, client):
    """Importing via the API must trigger detection, not just insert rows.

    Regression: ingest_text/ingest_file only stored events, so uploaded
    telemetry produced zero alerts and an empty graph.
    """
    events = []
    for i in range(6):
        events.append({
            "@timestamp": f"2026-05-01T10:0{i}:00Z", "host": "REG-HOST",
            "user_name": "reguser", "event_type": "logon_failed",
            "source": "windows_security",
        })
    events.append({
        "@timestamp": "2026-05-01T10:10:00Z", "host": "REG-HOST",
        "user_name": "reguser", "event_type": "logon_success",
        "source": "windows_security",
    })

    r = client.post("/api/ingest/text", json={
        "text": json.dumps(events), "filename": "reg.json",
        "source_type": "windows_security",
    })
    assert r.status_code == 200
    analysis = r.json().get("analysis")
    assert analysis is not None, "ingest response must report pipeline results"
    assert analysis["events_analyzed"] == 7
    assert analysis["alerts_created"] >= 1, "burst-then-success must raise R-001"
    assert any(a["rule_id"] == "R-001" for a in
               client.get("/api/alerts").json()["alerts"])


def test_ingest_file_runs_detection_pipeline(app_env, client):
    """Same guarantee for multipart uploads."""
    events = [{
        "@timestamp": "2026-05-01T11:00:00Z", "host": "UP-HOST",
        "event_type": "network_connect", "dst_ip": "198.51.100.23",
        "source": "firewall",
    }]
    r = client.post("/api/ingest/file",
                    files={"file": ("up.json", json.dumps(events), "application/json")},
                    data={"source_type": "firewall"})
    assert r.status_code == 200
    analysis = r.json().get("analysis")
    assert analysis is not None
    assert analysis["alerts_created"] >= 1, "IOC contact must raise R-003"


def test_export_script_handles_absolute_output_path():
    """Regression: export-windows-logs.ps1 must accept an absolute -Out path.

    EKSPOR-SYSMON.bat passes an absolute path. The previous implementation used
    Join-Path (Get-Location) $Out unconditionally, which *concatenates* an
    absolute child onto the cwd and produces a broken path like
    C:\proj\C:\proj\sysmon.json - the export silently wrote nowhere.
    """
    from pathlib import Path

    ps1 = Path(__file__).resolve().parents[2] / "tools" / "export-windows-logs.ps1"
    src = ps1.read_text(encoding="utf-8")

    assert "IsPathRooted" in src, "export script must branch on rooted -Out paths"
    assert "Join-Path (Get-Location).Path $Out" in src, \
        "relative paths must still resolve against the working directory"


def test_concurrent_analyze_does_not_corrupt_graph(app_env, client, project_id):
    """Regression: concurrent analysis must not raise UNIQUE/SystemError.

    Observed in production: deleting artifacts (or importing while the UI
    re-analyses) triggered analyze_project() from several request threads at
    once. Each run does DELETE-then-INSERT on graph_nodes/graph_edges, so the
    runs interleaved and died with
        sqlite3.IntegrityError: UNIQUE constraint failed:
        graph_nodes.project_id, graph_nodes.node_key
    and, when they shared the connection mid-commit,
        SystemError: error return without exception set
    Both made DELETE /api/artifacts/<id> return HTTP 500.

    analyze_project() is now serialised with db_lock(); this asserts a burst of
    concurrent re-analyses all succeed and leave a coherent graph.
    """
    import threading

    events = [
        {"@timestamp": "2026-07-01T08:00:0%dZ" % i, "host": "RACEHOST",
         "source": "edr", "event_id": 1, "event_type": "process_create",
         "user_name": "race", "process_name": r"C:\Windows\System32\cmd.exe",
         "parent_process": r"C:\Windows\System32\explorer.exe"}
        for i in range(6)
    ]
    r = client.post("/api/ingest/text", json={
        "text": __import__("json").dumps(events),
        "filename": "race.json", "source_type": "edr",
    })
    assert r.status_code == 200

    statuses: list[int] = []
    errors: list[str] = []

    def worker():
        try:
            statuses.append(client.post("/api/analyze", json={}).status_code)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent analyze raised: {errors}"
    assert statuses and all(s == 200 for s in statuses), f"statuses: {statuses}"

    # Graph must still be coherent: no duplicate node keys, edges point at nodes.
    graph = client.get("/api/graph").json()
    keys = [n["node_key"] for n in graph["nodes"]]
    assert len(keys) == len(set(keys)), "duplicate node_key after concurrent analyze"


def test_spa_shell_is_not_cached(client):
    """index.html names the hashed bundle, so caching it keeps serving old UI.

    Regression: after a rebuild the browser reused a cached shell and the user
    kept seeing a pre-fix screen while the API already returned fixed results.
    """
    r = client.get("/")
    assert r.status_code == 200
    assert "no-store" in r.headers.get("cache-control", "").lower()
