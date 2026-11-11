"""End-to-end analysis pipeline: import -> normalize -> detect -> correlate -> graph.

This module is the single place that writes derived data, so the ordering is
auditable: rules run on stored events, incidents are computed from stored
alerts, and the graph is rebuilt from stored alerts + events.
"""
from __future__ import annotations

from typing import Any

from . import correlation, detection
from .db import cursor, db_lock, get_conn, rows_to_dicts, seed_iocs
from .timeutil import now_iso


def store_import(
    project_id: int,
    artifact_name: str,
    source_type: str,
    parsed: Any,
    sha256: str | None,
    size_bytes: int | None,
    stored_path: str | None,
    is_synthetic: bool = False,
    artifact_kind: str = "file",
) -> dict[str, Any]:
    """Persist one import batch: artifact row + deduplicated events."""
    inserted = 0
    duplicated = 0
    now = now_iso()

    if parsed.failed and parsed.events:
        parse_status = "partial"
    elif parsed.failed and not parsed.events:
        parse_status = "failed"
    else:
        parse_status = "ok"

    notes = ""
    if parsed.failed:
        sample = parsed.failed[:5]
        notes = f"{len(parsed.failed)} record(s) rejected. Samples: {sample}"

    with cursor() as cur:
        cur.execute(
            """INSERT INTO artifacts
               (project_id,name,source_type,artifact_kind,stored_path,sha256,size_bytes,
                record_total,record_ok,record_failed,parse_status,parse_notes,is_synthetic,imported_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (project_id, artifact_name[:300], source_type, artifact_kind, stored_path,
             sha256, size_bytes, parsed.total, len(parsed.events), len(parsed.failed),
             parse_status, notes[:2000], 1 if is_synthetic else 0, now),
        )
        artifact_id = cur.lastrowid

        for ev in parsed.events:
            dedup = _dedup_key(ev)
            exists = cur.execute(
                "SELECT id FROM events WHERE project_id=? AND dedup_key=?",
                (project_id, dedup),
            ).fetchone()
            if exists:
                duplicated += 1
                continue
            cur.execute(
                """INSERT INTO events
                   (project_id,artifact_id,external_id,ts_raw,ts_utc,ts_status,source,event_type,
                    action,severity,host,user_name,src_ip,dst_ip,dst_port,domain,url,file_path,
                    file_hash,process_name,process_id,parent_process,parent_pid,command_line,
                    bytes_out,raw,dedup_key,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (project_id, artifact_id, ev.get("external_id"), ev.get("ts_raw"),
                 ev.get("ts_utc"), ev.get("ts_status") or "missing", ev["source"],
                 ev["event_type"], ev.get("action"), ev.get("severity"), ev.get("host"),
                 ev.get("user_name"), ev.get("src_ip"), ev.get("dst_ip"), ev.get("dst_port"),
                 ev.get("domain"), ev.get("url"), ev.get("file_path"), ev.get("file_hash"),
                 ev.get("process_name"), ev.get("process_id"), ev.get("parent_process"),
                 ev.get("parent_pid"), ev.get("command_line"), ev.get("bytes_out"),
                 ev.get("raw"), dedup, now),
            )
            inserted += 1

    return {
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "parse_status": parse_status,
        "records_total": parsed.total,
        "records_ok": len(parsed.events),
        "records_failed": len(parsed.failed),
        "events_inserted": inserted,
        "events_duplicated": duplicated,
        "warnings": parsed.warnings,
        "failures": parsed.failed[:20],
    }


def _dedup_key(ev: dict[str, Any]) -> str:
    """Content hash of the semantically meaningful fields.

    Re-importing the same file must not double the event count, but two
    genuinely distinct events at the same second must not collapse either.
    """
    import hashlib

    parts = [
        ev.get("ts_raw") or "", ev.get("ts_utc") or "", ev.get("source") or "",
        ev.get("event_type") or "", ev.get("host") or "", ev.get("user_name") or "",
        ev.get("src_ip") or "", ev.get("dst_ip") or "", ev.get("domain") or "",
        ev.get("file_path") or "", ev.get("process_name") or "",
        str(ev.get("process_id") or ""), ev.get("command_line") or "",
        str(ev.get("bytes_out") or ""), (ev.get("raw") or "")[:400],
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def analyze_project(project_id: int, fresh: bool = True) -> dict[str, Any]:
    """Run detection + correlation + graph over the project's stored events.

    Serialised via db_lock(): this function rewrites alerts, incidents and the
    graph table, and every request shares one SQLite connection.
    """
    with db_lock():
        return _analyze_project_locked(project_id, fresh)


def _analyze_project_locked(project_id: int, fresh: bool = True) -> dict[str, Any]:
    conn = get_conn()

    seed_iocs(conn, project_id)
    events = rows_to_dicts(
        conn.execute("SELECT * FROM events WHERE project_id=? ORDER BY ts_utc", (project_id,)).fetchall()
    )
    iocs = rows_to_dicts(
        conn.execute("SELECT * FROM iocs WHERE project_id=?", (project_id,)).fetchall()
    )
    enabled = {
        r["id"] for r in conn.execute("SELECT id FROM rules WHERE enabled=1").fetchall()
    }

    drafts, engine_errors = detection.run_all(events, iocs, enabled)

    with cursor() as cur:
        if fresh:
            cur.execute("DELETE FROM alert_events WHERE alert_id IN "
                        "(SELECT id FROM alerts WHERE project_id=?)", (project_id,))
            cur.execute("UPDATE alerts SET incident_id=NULL WHERE project_id=?", (project_id,))
            cur.execute("DELETE FROM incidents WHERE project_id=?", (project_id,))
            cur.execute("DELETE FROM alerts WHERE project_id=?", (project_id,))

        created_alerts: list[dict[str, Any]] = []
        now = now_iso()
        for d in drafts:
            if not d.event_ids:
                continue  # an alert with no evidence is not an alert
            cur.execute(
                """INSERT INTO alerts
                   (project_id,rule_id,title,severity,narrative,host,user_name,first_ts,
                    last_ts,dedup_key,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (project_id, d.rule_id, d.title[:400], d.severity, d.narrative, d.host,
                 d.user_name, d.first_ts, d.last_ts, d.dedup_key, now),
            )
            aid = cur.lastrowid
            for eid in dict.fromkeys(d.event_ids):
                role = "trigger" if eid == d.trigger_event_id else "supporting"
                cur.execute(
                    "INSERT OR IGNORE INTO alert_events (alert_id,event_id,role) VALUES (?,?,?)",
                    (aid, eid, role),
                )
            created_alerts.append({
                "id": aid, "rule_id": d.rule_id, "title": d.title,
                "severity": d.severity, "host": d.host, "user_name": d.user_name,
                "first_ts": d.first_ts, "last_ts": d.last_ts,
                "event_ids": list(dict.fromkeys(d.event_ids)),
                "narrative": d.narrative,
            })

        # incidents
        groups = correlation.group_incidents(project_id, created_alerts)
        incidents_out = []
        for idx, g in enumerate(groups, start=1):
            existing = cur.execute(
                "SELECT ref FROM incidents WHERE project_id=? AND ref=?",
                (project_id, f"INC-{idx:04d}"),
            ).fetchone()
            ref = f"INC-{idx:04d}"
            n = idx
            while existing:
                n += 1
                ref = f"INC-{n:04d}"
                existing = cur.execute(
                    "SELECT ref FROM incidents WHERE project_id=? AND ref=?",
                    (project_id, ref),
                ).fetchone()
            cur.execute(
                """INSERT INTO incidents
                   (project_id,ref,title,severity,status,summary,first_ts,last_ts,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (project_id, ref, g["title"][:400], g["severity"], "open", g["summary"],
                 g["first_ts"], g["last_ts"], now, now),
            )
            inc_id = cur.lastrowid
            for aid in g["alert_ids"]:
                cur.execute("UPDATE alerts SET incident_id=? WHERE id=?", (inc_id, aid))
            cur.execute(
                """INSERT INTO incident_status_history (incident_id,from_status,to_status,note,changed_at)
                   VALUES (?,?,?,?,?)""",
                (inc_id, None, "open", "Created by correlation engine", now),
            )
            incidents_out.append({
                "id": inc_id, "ref": ref, "severity": g["severity"],
                "title": g["title"], "hosts": g["hosts"], "users": g["users"],
                "first_ts": g["first_ts"], "last_ts": g["last_ts"],
                "alert_ids": g["alert_ids"], "rule_ids": g["rule_ids"],
                "summary": g["summary"],
            })

    graph_stats = correlation.build_graph(project_id, events, created_alerts, iocs)

    by_sev: dict[str, int] = {}
    for a in created_alerts:
        by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1

    return {
        "events_analyzed": len(events),
        "alerts_created": len(created_alerts),
        "alerts_by_severity": by_sev,
        "incidents_created": len(incidents_out),
        "graph": graph_stats,
        "rules_enabled": sorted(enabled),
        "engine_errors": engine_errors,
        "ioc_count": len(iocs),
    }
