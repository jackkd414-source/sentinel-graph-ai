"""Report generation: Markdown, JSON, printable HTML.

Reports are generated ONLY from stored database rows. AI text is clearly
fenced and labelled as model output, with its own evidence citations, so a
reader can never mistake an inference for an observed fact.
"""
from __future__ import annotations

import json
from typing import Any

from .db import cursor, get_conn, rows_to_dicts
from . import ai_providers, attack_map
from .security import escape_text, redact_secrets, strip_unsafe_html
from .timeutil import now_iso


def gather(incident_id: int) -> dict[str, Any]:
    conn = get_conn()
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not inc:
        raise ValueError("Incident not found")
    incident = dict(inc)
    project_id = incident["project_id"]

    alerts = rows_to_dicts(conn.execute(
        """SELECT a.*, r.name AS rule_name, r.description AS rule_description,
                  r.logic AS rule_logic
           FROM alerts a JOIN rules r ON r.id=a.rule_id
           WHERE a.incident_id=? ORDER BY a.severity, a.first_ts""",
        (incident_id,),
    ).fetchall())

    events: dict[int, dict[str, Any]] = {}
    alert_evidence: dict[int, list[dict[str, Any]]] = {}
    for a in alerts:
        rows = conn.execute(
            """SELECT e.*, ae.role FROM alert_events ae JOIN events e ON e.id=ae.event_id
               WHERE ae.alert_id=? ORDER BY e.ts_utc IS NULL, e.ts_utc""",
            (a["id"],),
        ).fetchall()
        alert_evidence[a["id"]] = rows_to_dicts(list(rows))
        for r in rows:
            events[r["id"]] = dict(r)

    artifacts = rows_to_dicts(conn.execute(
        "SELECT * FROM artifacts WHERE project_id=? ORDER BY imported_at", (project_id,)
    ).fetchall())

    status_history = rows_to_dicts(conn.execute(
        "SELECT * FROM incident_status_history WHERE incident_id=? ORDER BY changed_at",
        (incident_id,),
    ).fetchall())

    ai_runs = rows_to_dicts(conn.execute(
        "SELECT * FROM ai_runs WHERE incident_id=? ORDER BY id DESC LIMIT 1", (incident_id,)
    ).fetchall())
    ai = ai_runs[0] if ai_runs else None
    if ai and ai.get("result_json"):
        try:
            ai["result_json"] = json.loads(ai["result_json"])
        except (TypeError, ValueError):
            pass

    edges = rows_to_dicts(conn.execute(
        """SELECT e.*, s.node_key AS src_key, s.label AS src_label, s.node_type AS src_type,
                  d.node_key AS dst_key, d.label AS dst_label, d.node_type AS dst_type
           FROM graph_edges e
           JOIN graph_nodes s ON s.id=e.src_node_id
           JOIN graph_nodes d ON d.id=e.dst_node_id
           WHERE e.project_id=?
             AND (e.src_node_id IN (SELECT id FROM graph_nodes WHERE project_id=?)
                  OR e.dst_node_id IN (SELECT id FROM graph_nodes WHERE project_id=?))
           ORDER BY e.status, e.relation""",
        (project_id, project_id, project_id),
    ).fetchall())

    findings = rows_to_dicts(conn.execute(
        "SELECT * FROM findings WHERE incident_id=? ORDER BY id", (incident_id,)
    ).fetchall())

    return {
        "incident": incident,
        "alerts": alerts,
        "alert_evidence": alert_evidence,
        "events": sorted(events.values(), key=lambda e: e.get("ts_utc") or "9999"),
        "artifacts": artifacts,
        "status_history": status_history,
        "ai": ai,
        "edges": edges,
        "findings": findings,
        "generated_at": now_iso(),
    }


def _ts_display(ev: dict[str, Any]) -> str:
    if ev.get("ts_utc"):
        return ev["ts_utc"]
    return f"UNKNOWN ({ev.get('ts_status')})"


def build_markdown(data: dict[str, Any]) -> str:
    inc = data["incident"]
    L: list[str] = []
    a = L.append

    a(f"# Incident Report - {inc['ref']}")
    a("")
    a(f"**Title:** {inc['title']}  ")
    a(f"**Severity:** {inc['severity'].upper()}  ")
    a(f"**Status:** {inc['status']}  ")
    a(f"**Observed window (UTC):** {inc.get('first_ts') or 'unknown'} -> "
      f"{inc.get('last_ts') or 'unknown'}  ")
    a(f"**Report generated:** {data['generated_at']}")
    a("")
    a("> **Data provenance:** this report is generated from dataset(s) marked below. "
      "Synthetic demo data is not evidence of a real intrusion.")
    synthetic = any(x.get("is_synthetic") for x in data["artifacts"])
    a(f"> Synthetic data present: **{'YES' if synthetic else 'no'}**")
    a("")

    a("## 1. Executive summary")
    a("")
    a(inc.get("summary") or "_No machine summary available._")
    a("")

    a("## 2. Scope and data sources")
    a("")
    if data["artifacts"]:
        a("| Artifact | Type | Records | Parse status | SHA-256 | Synthetic |")
        a("|---|---|---|---|---|---|")
        for art in data["artifacts"]:
            a(f"| {art['name']} | {art['source_type']} | {art['record_ok']}/{art['record_total']} "
              f"| {art['parse_status']} | {(art['sha256'] or '-')[:16]} | "
              f"{'yes' if art['is_synthetic'] else 'no'} |")
    else:
        a("_No artifacts recorded._")
    a("")
    a(f"Total evidence events linked to this incident: **{len(data['events'])}**")
    a("")

    a("## 3. Chronology (observed facts)")
    a("")
    if data["events"]:
        a("| Time (UTC) | Host | User | Event | Detail | Event ID |")
        a("|---|---|---|---|---|---|")
        for ev in data["events"]:
            detail = (ev.get("command_line") or ev.get("file_path")
                      or ev.get("dst_ip") or ev.get("domain") or ev.get("process_name") or "")
            a(f"| {_ts_display(ev)} | {ev.get('host') or '-'} | {ev.get('user_name') or '-'} "
              f"| {ev.get('event_type')} | {str(detail)[:70]} | #{ev['id']} |")
    else:
        a("_No events linked._")
    a("")

    a("## 4. Findings (rule-based, deterministic)")
    a("")
    a("These are produced by the rule engine, not by an LLM. Each finding lists the "
      "exact event IDs that support it.")
    a("")
    for al in data["alerts"]:
        a(f"### {al['rule_id']} - {al['title']}")
        a("")
        a(f"- **Severity:** {al['severity']}")
        a(f"- **Rule:** {al.get('rule_name')} v(alerts reference rule catalogue)")
        a(f"- **Reconstructed logic:** `{al.get('rule_logic')}`")
        tech = attack_map.summary_line(al["rule_id"])
        if tech:
            a(f"- **ATT&CK:** {tech}")
        a(f"- **Why it fired:** {al['narrative']}")
        evid = data["alert_evidence"].get(al["id"], [])
        if evid:
            a(f"- **Supporting events:** "
              + ", ".join(f"#{e['id']} ({e.get('event_type')} @ {_ts_display(e)})" for e in evid))
        a("")

    a("## 5. Attack graph relations")
    a("")
    a("`observed` = the relationship is written in the source data. "
      "`inferred` = produced by correlation logic and must be re-verified.")
    a("")
    if data["edges"]:
        a("| Source | Relation | Target | Status | Method |")
        a("|---|---|---|---|---|")
        for e in data["edges"][:60]:
            a(f"| {e['src_label']} ({e['src_type']}) | {e['relation']} | "
              f"{e['dst_label']} ({e['dst_type']}) | {e['status']} | {e['method'][:80]} |")
        if len(data["edges"]) > 60:
            a(f"| _…{len(data['edges']) - 60} more edges omitted_ | | | | |")
    else:
        a("_No graph relations._")
    a("")

    a("## 6. AI analysis (model interpretation, not fact)")
    a("")
    ai = data.get("ai")
    if not ai:
        a("_No AI analysis was run for this incident. All findings above were produced "
          "by the deterministic core engine._")
    elif ai["status"] == "no_provider":
        a("_No AI provider was configured when this analysis was requested. All findings "
          "above were produced by the deterministic core engine, which does not depend on "
          "any external model._")
    elif ai["status"] in ("error", "validation_failed"):
        a(f"AI analysis did not produce usable output: **{ai['status']}** "
          f"({ai.get('error_category') or '-'}). No AI content is included.")
    else:
        a(f"Provider **{ai.get('provider')}**, model **{ai.get('model')}** "
          f"(latency {ai.get('latency_ms')} ms).")
        a("")
        a("> The block below is generated text. It is an interpretation of the evidence "
          "and must be verified by an analyst before any action.")
        a("")
        res = ai.get("result_json") or {}
        if isinstance(res, str):
            try:
                res = json.loads(res)
            except ValueError:
                res = {}
        a("**Summary:** " + (res.get("summary") or "-"))
        a("")
        a("_This summary is free-form model text. It is NOT verified against the event "
          "store; only claims carrying event citations below could be checked._")
        a("")
        if res.get("timeline_interpretation"):
            a("**Timeline interpretation:** " + res["timeline_interpretation"])
            a("")
        hyps = res.get("hypotheses") or []
        if hyps:
            a("**Hypotheses:**")
            a("")
            for h in hyps:
                sup = ", ".join(f"#{i}" for i in (h.get("supporting_event_ids") or [])) or "none"
                con = ", ".join(f"#{i}" for i in (h.get("contradicting_event_ids") or [])) or "none"
                status_tag = {
                    "supported": "[evidence-linked]",
                    "contested": "[evidence CONTESTED]",
                    "unsupported": "[NO SURVIVING EVIDENCE - treat as unverified claim]",
                }.get(h.get("evidence_status", ""), "")
                a(f"- *{h.get('confidence')}* {status_tag} - {h.get('statement')} "
                  f"(supports: {sup}; contradicts: {con})")
                if h.get("reasoning"):
                    a(f"  - Reasoning: {h['reasoning']}")
            a("")
        stripped = res.get("stripped_reference_count") or 0
        if stripped:
            a(f"> Evidence guard: {stripped} citation(s) produced by the model referenced "
              f"events that do not exist in this incident and were removed.")
            a("")
        rc = res.get("root_cause_hypothesis") or {}
        if rc.get("statement"):
            a(f"**Root-cause hypothesis ({rc.get('confidence')}):** {rc['statement']}")
            a("")
        if res.get("missing_information"):
            a("**Information still missing:**")
            for m in res["missing_information"]:
                a(f"- {m}")
            a("")
        if res.get("next_investigation_steps"):
            a("**Recommended next steps (advisory, require human approval):**")
            for s in res["next_investigation_steps"]:
                a(f"- {s}")
            a("")
        if res.get("uncertainty_notes"):
            a("**Uncertainty:** " + res["uncertainty_notes"])
            a("")

    a("## 7. Known impact vs. unestablished impact")
    a("")
    hosts = sorted({e["host"] for e in data["events"] if e.get("host")})
    a(f"- **Hosts with observed activity:** {', '.join(hosts) if hosts else 'none identified'}")
    a("- **Confirmed compromise:** NOT established by this evidence set. The rule engine "
      "shows correlated suspicious behaviour, which requires analyst validation.")
    a("- **Confirmed data exfiltration:** NOT established. Outbound transfer volume is "
      "observed; whether sensitive data left is unknown unless DLP or payload evidence exists.")
    a("")

    a("## 8. Recommendations")
    a("")
    a("Advisory only. SentinelGraph does not execute response actions.")
    a("")
    a("- Isolate the affected host pending forensic imaging, if the alert set is confirmed.")
    a("- Rotate credentials for every account that appears in an authentication anomaly.")
    a("- Block the indicated C2 destinations at the perimeter and hunt for the same "
      "indicators on other hosts.")
    a("- Preserve the imported artifacts (SHA-256 listed above) before any remediation.")
    a("")

    a("## 9. Limitations")
    a("")
    a("- Detection is rule-based correlation over normalized events. It is not zero-day "
      "detection and makes no claim of full coverage.")
    a("- Timestamps marked `assumed` were parsed without explicit timezone and interpreted "
      "using a declared default; `UNKNOWN` timestamps were absent or unparseable.")
    a("- The synthetic demo dataset is small; the volume-anomaly rule (R-006) is therefore "
      "illustrative rather than calibrated.")
    a("- Grouping of alerts into incidents uses shared host/account and rule family within "
      "a 6-hour window; this is a heuristic.")
    a("- AI output is interpretation. Confidence labels are qualitative, not calibrated "
      "probabilities.")
    a("")

    a("## 10. Status history")
    a("")
    for h in data["status_history"]:
        a(f"- {h['changed_at']}: {h['from_status'] or '(new)'} -> {h['to_status']} "
          f"{('- ' + h['note']) if h.get('note') else ''}")
    a("")
    return "\n".join(L)


def build_json_report(data: dict[str, Any]) -> dict[str, Any]:
    inc = data["incident"]
    ai = data.get("ai") or {}
    return {
        "report_meta": {
            "generated_at": data["generated_at"],
            "generator": "SentinelGraph AI",
            "incident_ref": inc["ref"],
            "synthetic_data_present": any(x.get("is_synthetic") for x in data["artifacts"]),
            "ai_used": bool(ai and ai.get("status") in ("ok", "ok_with_warnings")),
            "ai_provider": ai.get("provider") if ai else None,
            "ai_model": ai.get("model") if ai else None,
        },
        "incident": {
            "ref": inc["ref"],
            "title": inc["title"],
            "severity": inc["severity"],
            "status": inc["status"],
            "first_ts": inc.get("first_ts"),
            "last_ts": inc.get("last_ts"),
            "summary": inc.get("summary"),
        },
        "data_sources": [
            {
                "name": a["name"], "type": a["source_type"], "sha256": a["sha256"],
                "records_ok": a["record_ok"], "records_failed": a["record_failed"],
                "parse_status": a["parse_status"], "synthetic": bool(a["is_synthetic"]),
            }
            for a in data["artifacts"]
        ],
        "observed_events": [
            {
                "id": e["id"], "ts_utc": e.get("ts_utc"), "ts_status": e.get("ts_status"),
                "ts_raw": e.get("ts_raw"), "source": e.get("source"),
                "event_type": e.get("event_type"), "host": e.get("host"),
                "user": e.get("user_name"), "process": e.get("process_name"),
                "parent_process": e.get("parent_process"),
                "command_line": e.get("command_line"), "dst_ip": e.get("dst_ip"),
                "domain": e.get("domain"), "file_path": e.get("file_path"),
                "bytes_out": e.get("bytes_out"),
            }
            for e in data["events"]
        ],
        "derived_findings": [
            {
                "alert_id": a["id"], "rule_id": a["rule_id"], "title": a["title"],
                "severity": a["severity"], "narrative": a["narrative"],
                "evidence_event_ids": [e["id"] for e in data["alert_evidence"].get(a["id"], [])],
                "formation": "deterministic rule engine",
            }
            for a in data["alerts"]
        ],
        "graph_relations": [
            {
                "source": e["src_key"], "relation": e["relation"], "target": e["dst_key"],
                "status": e["status"], "method": e["method"],
                "confidence": e["confidence"],
            }
            for e in data["edges"]
        ],
        "ai_hypotheses": (
            (ai.get("result_json") or {}).get("hypotheses", [])
            if isinstance(ai.get("result_json"), dict) else []
        ),
        "limitations": [
            "Rule-based correlation only; not zero-day detection.",
            "Confirmed compromise and confirmed exfiltration are not established by correlation alone.",
            "AI confidence labels are qualitative, not calibrated probabilities.",
        ],
        "status_history": data["status_history"],
    }


def build_html(data: dict[str, Any]) -> str:
    inc = data["incident"]
    synthetic = any(x.get("is_synthetic") for x in data["artifacts"])
    rows_html = []
    for ev in data["events"]:
        detail = (ev.get("command_line") or ev.get("file_path") or ev.get("dst_ip")
                  or ev.get("domain") or ev.get("process_name") or "")
        rows_html.append(
            "<tr>"
            f"<td>{escape_text(_ts_display(ev))}</td>"
            f"<td>{escape_text(ev.get('host'))}</td>"
            f"<td>{escape_text(ev.get('user_name'))}</td>"
            f"<td>{escape_text(ev.get('event_type'))}</td>"
            f"<td class='mono'>{escape_text(str(detail))[:140]}</td>"
            f"<td>#{ev['id']}</td>"
            "</tr>"
        )

    findings_html = []
    for al in data["alerts"]:
        evid = data["alert_evidence"].get(al["id"], [])
        tech = attack_map.summary_line(al["rule_id"])
        tech_html = f"<p class='sev'>ATT&amp;CK: {escape_text(tech)}</p>" if tech else ""
        findings_html.append(
            f"<div class='finding sev-{escape_text(al['severity'])}'>"
            f"<h3>{escape_text(al['rule_id'])} &mdash; {escape_text(al['title'])}</h3>"
            f"<p class='sev'>Severity: {escape_text(al['severity'])}</p>"
            f"{tech_html}"
            f"<p>{strip_unsafe_html(escape_text(al['narrative']))}</p>"
            f"<p class='evidence'>Supporting events: "
            + ", ".join(f"#{e['id']}" for e in evid) +
            "</p></div>"
        )

    edges_html = "".join(
        f"<tr><td>{escape_text(e['src_label'])}<br><span class='t'>{escape_text(e['src_type'])}</span></td>"
        f"<td>{escape_text(e['relation'])}</td>"
        f"<td>{escape_text(e['dst_label'])}<br><span class='t'>{escape_text(e['dst_type'])}</span></td>"
        f"<td class='{escape_text(e['status'])}'>{escape_text(e['status'])}</td>"
        f"<td class='t'>{escape_text(e['method'][:120])}</td></tr>"
        for e in data["edges"][:80]
    )

    ai = data.get("ai")
    if not ai:
        ai_html = ("<p class='muted'>No AI analysis was run. All findings were produced by "
                   "the deterministic core engine.</p>")
    elif ai["status"] in ("error", "validation_failed", "no_provider"):
        ai_html = (f"<p class='muted'>AI analysis did not produce usable output: "
                   f"<b>{escape_text(ai['status'])}</b> "
                   f"({escape_text(ai.get('error_category') or '-')}). No AI content included.</p>")
    else:
        res = ai.get("result_json") or {}
        if isinstance(res, str):
            try:
                res = json.loads(res)
            except ValueError:
                res = {}
        hyps = res.get("hypotheses") or []
        ai_html = (
            f"<p class='muted'>Provider <b>{escape_text(ai.get('provider'))}</b>, "
            f"model <b>{escape_text(ai.get('model'))}</b>, latency {ai.get('latency_ms')} ms. "
            "Generated text &mdash; verify before acting.</p>"
            f"<p>{escape_text(res.get('summary'))}</p>"
            "<p class='muted'><i>Summary is free-form model text, not verified against "
            "the event store. Only cited hypotheses below were checked.</i></p>"
            + ("<ul>" + "".join(
                f"<li><i>{escape_text(h.get('confidence'))}</i> "
                + {
                    "supported": "<span class='ok'>[evidence-linked]</span> ",
                    "contested": "<span class='warn'>[evidence CONTESTED]</span> ",
                    "unsupported": "<span class='warn'>[NO SURVIVING EVIDENCE]</span> ",
                }.get(h.get("evidence_status", ""), "")
                + f"{escape_text(h.get('statement'))} "
                f"<span class='t'>(supports: "
                f"{', '.join('#' + str(i) for i in (h.get('supporting_event_ids') or [])) or 'none'}; "
                f"contradicts: "
                f"{', '.join('#' + str(i) for i in (h.get('contradicting_event_ids') or [])) or 'none'})"
                f"</span></li>"
                for h in hyps) + "</ul>" if hyps else "")
            + (f"<p class='warn'>Evidence guard: {res.get('stripped_reference_count')} "
               f"model citation(s) referenced non-existent events and were removed.</p>"
               if res.get("stripped_reference_count") else "")
            + ("<p><b>Missing information:</b></p><ul>" + "".join(
                f"<li>{escape_text(m)}</li>" for m in (res.get('missing_information') or []))
               + "</ul>" if res.get("missing_information") else "")
            + ("<p><b>Recommended next steps (advisory):</b></p><ul>" + "".join(
                f"<li>{escape_text(s)}</li>" for s in (res.get('next_investigation_steps') or []))
               + "</ul>" if res.get("next_investigation_steps") else "")
        )

    banner = (
        "<div class='banner'>SYNTHETIC DEMO DATA &mdash; this report was generated from "
        "labelled synthetic events and does not describe a real intrusion.</div>"
        if synthetic else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Incident Report {escape_text(inc['ref'])} - SentinelGraph AI</title>
<style>
:root {{ --bg:#0a1220; --panel:#101b2d; --line:#1e3350; --fg:#d8e6f5; --muted:#7f9bbd;
        --cyan:#35e0e0; --red:#ff5d5d; --amber:#ffb020; --purple:#a97bff; --green:#39d98a; }}
* {{ box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--fg); font-family:system-ui,-apple-system,'Segoe UI',sans-serif;
        margin:0; padding:32px; line-height:1.55; }}
.wrap {{ max-width:1100px; margin:0 auto; }}
h1 {{ color:var(--cyan); font-size:24px; margin:0 0 4px; letter-spacing:.3px; }}
h2 {{ color:var(--cyan); font-size:16px; margin:28px 0 10px; padding-bottom:6px;
      border-bottom:1px solid var(--line); text-transform:uppercase; letter-spacing:1px; }}
h3 {{ font-size:14px; margin:0 0 6px; }}
.meta {{ color:var(--muted); font-size:13px; margin-bottom:16px; }}
.meta b {{ color:var(--fg); }}
.banner {{ background:#3a1d1d; border:1px solid #6b2a2a; color:#ffb0b0; padding:10px 14px;
           border-radius:6px; font-size:13px; margin:14px 0; }}
table {{ width:100%; border-collapse:collapse; font-size:12.5px; margin-bottom:8px; }}
th {{ text-align:left; color:var(--muted); font-weight:600; border-bottom:1px solid var(--line);
      padding:7px 8px; font-size:11px; text-transform:uppercase; letter-spacing:.6px; }}
td {{ border-bottom:1px solid #16243a; padding:7px 8px; vertical-align:top; }}
tr:hover td {{ background:#0e1a2b; }}
.mono {{ font-family:ui-monospace,'Cascadia Code',Consolas,monospace; font-size:11.5px; color:#a8c4e0; }}
.t {{ color:var(--muted); font-size:11px; }}
.finding {{ background:var(--panel); border:1px solid var(--line); border-left:3px solid var(--amber);
            padding:12px 14px; margin-bottom:10px; border-radius:4px; }}
.finding.sev-critical {{ border-left-color:var(--red); }}
.finding.sev-high {{ border-left-color:#ff8b3d; }}
.finding.sev-medium {{ border-left-color:var(--amber); }}
.finding.sev-low {{ border-left-color:var(--cyan); }}
.sev {{ color:var(--muted); font-size:11.5px; margin:0 0 6px; text-transform:uppercase; letter-spacing:.5px; }}
.evidence {{ color:var(--cyan); font-size:12px; font-family:ui-monospace,monospace; }}
.observed {{ color:var(--green); }} .inferred {{ color:var(--purple); }}
.muted {{ color:var(--muted); font-size:13px; }}
.ok {{ color:#1f7a4d; font-size:11px; font-weight:600; }}
.warn {{ color:#b4341f; font-size:11px; font-weight:600; }}
ul {{ margin:6px 0 6px 18px; padding:0; }} li {{ margin-bottom:4px; font-size:13px; }}
.footer {{ color:var(--muted); font-size:11.5px; margin-top:32px; border-top:1px solid var(--line);
           padding-top:12px; }}
@media print {{ body {{ background:#fff; color:#111; }} .banner {{ background:#fff3cd; color:#7a5b00;
   border-color:#e0c98a; }} table th {{ color:#444; border-color:#ccc; }}
   td {{ border-color:#e5e5e5; }} .finding {{ background:#fafafa; border-color:#ddd; }}
   h1,h2 {{ color:#0b4a6f; }} .mono,.t,.muted {{ color:#555; }} }}
</style></head>
<body><div class="wrap">
<h1>Incident Report &mdash; {escape_text(inc['ref'])}</h1>
<div class="meta">
  <b>{escape_text(inc['title'])}</b><br>
  Severity: <b>{escape_text(inc['severity'].upper())}</b> &nbsp;|&nbsp;
  Status: <b>{escape_text(inc['status'])}</b> &nbsp;|&nbsp;
  Window (UTC): <b>{escape_text(inc.get('first_ts') or 'unknown')}</b> &rarr;
  <b>{escape_text(inc.get('last_ts') or 'unknown')}</b><br>
  Generated: {escape_text(data['generated_at'])} by SentinelGraph AI
</div>
{banner}

<h2>1. Executive summary</h2>
<p>{escape_text(inc.get('summary') or 'No summary available.')}</p>

<h2>2. Scope and data sources</h2>
<table><tr><th>Artifact</th><th>Type</th><th>Records</th><th>Parse</th><th>SHA-256</th><th>Synthetic</th></tr>
{''.join(f"<tr><td>{escape_text(a['name'])}</td><td>{escape_text(a['source_type'])}</td>"
         f"<td>{a['record_ok']}/{a['record_total']}</td><td>{escape_text(a['parse_status'])}</td>"
         f"<td class='mono'>{(a['sha256'] or '-')[:16]}</td>"
         f"<td>{'yes' if a['is_synthetic'] else 'no'}</td></tr>" for a in data['artifacts'])}
</table>

<h2>3. Chronology (observed facts)</h2>
<table><tr><th>Time (UTC)</th><th>Host</th><th>User</th><th>Event</th><th>Detail</th><th>ID</th></tr>
{''.join(rows_html) or "<tr><td colspan='6' class='muted'>No events.</td></tr>"}
</table>

<h2>4. Findings (deterministic rule engine)</h2>
{''.join(findings_html) or "<p class='muted'>No findings.</p>"}

<h2>5. Attack graph relations</h2>
<table><tr><th>Source</th><th>Relation</th><th>Target</th><th>Status</th><th>Method</th></tr>
{edges_html or "<tr><td colspan='5' class='muted'>No relations.</td></tr>"}
</table>

<h2>6. AI analysis (interpretation, not fact)</h2>
{ai_html}

<h2>7. Known vs. unestablished impact</h2>
<ul>
<li><b>Confirmed compromise:</b> NOT established by correlation alone.</li>
<li><b>Confirmed data exfiltration:</b> NOT established; outbound volume is observed only.</li>
<li><b>Hosts with observed activity:</b> {
  escape_text(', '.join(sorted({e['host'] for e in data['events'] if e.get('host')})) or 'none')}</li>
</ul>

<h2>8. Recommendations (advisory, human approval required)</h2>
<ul>
<li>Isolate affected host(s) pending forensic imaging if the alert set is confirmed.</li>
<li>Rotate credentials for accounts appearing in authentication anomalies.</li>
<li>Block indicated C2 destinations and hunt the same indicators on other hosts.</li>
<li>Preserve imported artifacts by the SHA-256 values above before remediation.</li>
</ul>

<h2>9. Limitations</h2>
<ul>
<li>Rule-based correlation; not zero-day detection, no coverage claim.</li>
<li>Timestamps marked <span class="mono">assumed</span> were parsed without an explicit
    timezone; <span class="mono">UNKNOWN</span> timestamps were absent or unparseable.</li>
<li>Incident grouping uses shared host/account plus rule family within 6 hours (heuristic).</li>
<li>AI confidence labels are qualitative, not calibrated probabilities.</li>
</ul>

<div class="footer">
SentinelGraph AI &mdash; From Signals to Story.<br>
Observed facts and derived findings are separated throughout this document.
AI-generated text is confined to section 6 and labelled accordingly.
</div>
</div></body></html>"""


# --------------------------------------------------------------------------
# AI-assisted narrative (optional)
# --------------------------------------------------------------------------
# The deterministic sections above are the report of record. When an operator
# asks for an AI narrative, the model receives ONLY facts gathered from the
# database; its output is fenced, labelled and caveated so a reader can never
# mistake an inference for an observed fact. With no provider configured the
# deterministic report is returned unchanged.

AI_SYSTEM_PROMPT = (
    "You are a senior SOC analyst writing the narrative section of a formal "
    "incident report. You are given deterministic facts extracted from an "
    "evidence store.\n"
    "Hard rules:\n"
    "  * Use ONLY the supplied facts. Never invent hosts, users, IP addresses, "
    "hashes, timestamps, rule ids or CVE ids.\n"
    "  * Keep observed facts separate from inference, and label inference.\n"
    "  * State uncertainty and missing evidence explicitly.\n"
    "  * Do not speculate about attacker identity or attribution.\n"
    "  * Plain professional English, markdown only, no code fences.\n"
    "Headings, in this order: '### Executive summary', '### What the evidence "
    "shows', '### Most likely attack path', '### Recommended next steps', "
    "'### Confidence and gaps'."
)


def build_ai_prompt(data: dict[str, Any]) -> str:
    """Render the gathered facts into a compact prompt. No secrets included."""
    inc = data["incident"]
    synthetic = any(a.get("is_synthetic") for a in data["artifacts"])
    out: list[str] = [
        f"Incident {inc['ref']}: {inc['title']}",
        f"Severity {inc['severity']}, status {inc['status']}",
        f"Observed window (UTC): {inc.get('first_ts') or 'unknown'} -> "
        f"{inc.get('last_ts') or 'unknown'}",
        f"Machine summary: {inc.get('summary') or '(none)'}",
        f"Dataset is synthetic/demo: {'yes' if synthetic else 'no'}",
        "",
        f"Findings ({len(data['alerts'])}):",
    ]
    for a in data["alerts"]:
        text = a.get("narrative") or a.get("rule_description") or ""
        out.append(f"- [{a['severity']}] {a.get('rule_name') or a.get('rule_id')}: {text}".strip())
    out += ["", f"Evidence events ({len(data['events'])}):"]
    for ev in data["events"][:60]:
        bits = [
            ev.get("ts_utc") or ev.get("ts_raw") or "-",
            ev.get("host") or "-",
            ev.get("event_type") or "-",
            ev.get("command_line") or ev.get("file_path") or ev.get("domain")
            or ev.get("process_name") or ev.get("action") or "",
        ]
        out.append("- " + " | ".join(str(b) for b in bits if b))
    out += ["", f"Graph relationships ({len(data['edges'])}):"]
    for e in data["edges"][:60]:
        out.append(f"- {e.get('src_label')} -[{e.get('relation')}/{e.get('status')}]-> "
                   f"{e.get('dst_label')}")
    return "\n".join(out)


def _ai_narrative(
    data: dict[str, Any], spec: ai_providers.ProviderSpec | None,
) -> tuple[str, dict[str, Any]]:
    """Ask the active provider for the narrative. Never raises."""
    if spec is None:
        return "", {"status": "no_provider",
                    "message": "No AI provider is configured; the deterministic "
                               "report was generated without an AI section."}
    try:
        result = ai_providers.complete(spec, AI_SYSTEM_PROMPT, build_ai_prompt(data))
    except Exception as exc:  # adapters normally catch; belt and braces
        return "", {"status": "error", "error_category": "exception",
                    "error_message": redact_secrets(str(exc))[:300],
                    "provider": spec.provider_type, "model": spec.model_id}
    if not result.ok:
        return "", {"status": "error", "error_category": result.error_category,
                    "error_message": redact_secrets(result.error_message)[:300],
                    "provider": spec.provider_type, "model": spec.model_id}
    text = (result.text or "").strip()
    if not text:
        return "", {"status": "empty",
                    "message": "The provider returned an empty response."}
    return text, {"status": "ok", "provider": spec.provider_type,
                  "model": spec.model_id, "latency_ms": result.latency_ms}


def _record_ai_run(project_id: int, incident_id: int, note: dict[str, Any],
                   chars: int) -> None:
    """Persist the run for traceability, same shape as analysis runs."""
    with cursor() as cur:
        cur.execute(
            """INSERT INTO ai_runs
               (project_id,incident_id,task,provider,model,status,latency_ms,
                result_json,error_category,error_message,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (project_id, incident_id, "report", note.get("provider"),
             note.get("model"), note.get("status") or "error", note.get("latency_ms"),
             json.dumps({"narrative_chars": chars}), note.get("error_category"),
             note.get("error_message"), now_iso()),
        )


_AI_MD_BANNER = (
    "## AI-assisted narrative\n\n"
    "> **Model output - a hypothesis, not evidence.** Generated by {who}. "
    "Every claim below must be checked against the deterministic sections that "
    "follow; the evidence store, not the model, is the report of record.\n\n"
    "{text}\n\n---\n\n"
)


def _inject_ai_md(md: str, text: str, note: dict[str, Any]) -> str:
    block = _AI_MD_BANNER.format(
        who=f"`{note.get('provider')} / {note.get('model')}`", text=text)
    marker = "## 1. Executive summary"
    return md.replace(marker, block + marker, 1) if marker in md else block + md


def _inject_ai_html(doc: str, text: str, note: dict[str, Any]) -> str:
    who = escape_text(f"{note.get('provider')} / {note.get('model')}")
    body = escape_text(text).replace("\n", "<br>")
    section = (
        '<section class="ai-narrative"><h2>AI-assisted narrative</h2>'
        "<p><strong>Model output - a hypothesis, not evidence.</strong> "
        f"Generated by {who}. Check every claim against the deterministic "
        "sections of this report.</p>"
        f"<div>{body}</div></section>"
    )
    return doc.replace("</body>", section + "</body>", 1)


def generate(incident_id: int, fmt: str = "md", persist: bool = True,
             use_ai: bool = False,
             spec: ai_providers.ProviderSpec | None = None) -> dict[str, Any]:
    """Build a report. ``use_ai`` adds a clearly fenced model narrative."""
    data = gather(incident_id)
    note: dict[str, Any] | None = None
    ai_text = ""
    if use_ai:
        ai_text, note = _ai_narrative(data, spec)

    if fmt == "md":
        content = build_markdown(data)
        if ai_text:
            content = _inject_ai_md(content, ai_text, note or {})
    elif fmt == "html":
        content = build_html(data)
        if ai_text:
            content = _inject_ai_html(content, ai_text, note or {})
    elif fmt == "json":
        payload = build_json_report(data)
        if note is not None:
            payload["ai_narrative"] = {"text": ai_text, **note}
        content = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        raise ValueError(f"Unsupported format: {fmt}")

    if use_ai and note is not None:
        _record_ai_run(data["incident"]["project_id"], incident_id, note, len(ai_text))

    if persist:
        with cursor() as cur:
            cur.execute(
                "INSERT INTO reports (project_id,incident_id,fmt,content,created_at) VALUES (?,?,?,?,?)",
                (data["incident"]["project_id"], incident_id, fmt, content, now_iso()),
            )
            report_id = cur.lastrowid
    else:
        report_id = None

    return {"id": report_id, "fmt": fmt, "content": content,
            "incident_ref": data["incident"]["ref"], "ai": note}
