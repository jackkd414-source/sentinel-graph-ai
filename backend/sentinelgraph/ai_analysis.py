"""AI analysis: context building, schema validation, evidence verification.

The model is an interpreter, not a source of truth. Concretely:

1. We build a *minimal, selected* context - only the events linked to the
   incident, capped. Never the whole database.
2. The response must be JSON matching ANALYSIS_SCHEMA.
3. Every evidence reference the model returns is checked against the DB.
   References to event IDs that do not exist, or that are not part of the
   supplied context, are stripped and counted. If the model invents facts,
   the run is marked and the raw output is not presented as findings.
4. Nothing the model returns is ever written into the events table.
"""
from __future__ import annotations

import json
from typing import Any

from . import ai_providers
from .db import cursor, get_conn, rows_to_dicts
from .security import redact_secrets
from .timeutil import now_iso

MAX_EVENTS_IN_CONTEXT = 60
MAX_CHARS_PER_EVENT = 400

ANALYSIS_SCHEMA_HINT = """Return ONLY a JSON object, no markdown fences, with this shape:
{
  "summary": "string, 2-5 sentences, plain language",
  "timeline_interpretation": "string",
  "hypotheses": [
    {"statement": "string", "confidence": "low|medium|high",
     "supporting_event_ids": [int], "contradicting_event_ids": [int],
     "reasoning": "string"}
  ],
  "root_cause_hypothesis": {"statement": "string", "confidence": "low|medium|high"},
  "missing_information": ["string"],
  "next_investigation_steps": ["string"],
  "uncertainty_notes": "string"
}

Rules you MUST obey:
- You may only reference event IDs that appear in the supplied EVENTS list.
- Do not invent hosts, IPs, hashes, usernames, timestamps, or test results.
- If the data does not establish something, say so explicitly in
  missing_information or uncertainty_notes instead of guessing.
- confidence is a qualitative label, not a calibrated probability."""

ALLOWED_CONFIDENCE = {"low", "medium", "high"}


class SchemaValidationError(ValueError):
    pass


def _extract_json(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        # strip a fenced block if the model ignored instructions
        parts = raw.split("```")
        for part in parts:
            candidate = part.strip()
            if candidate.startswith("{"):
                raw = candidate
                break
            if candidate.lower().startswith("json"):
                raw = candidate[4:].strip()
                break
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        start, end = raw.find("{"), raw.rfind("}")
        if start == -1 or end <= start:
            raise SchemaValidationError("Response contained no JSON object.")
        try:
            doc = json.loads(raw[start:end + 1])
        except json.JSONDecodeError as exc:
            raise SchemaValidationError(f"Unparseable JSON: {exc.msg}") from exc
    if not isinstance(doc, dict):
        raise SchemaValidationError("Response JSON root is not an object.")
    return doc


def validate_analysis(
    doc: dict[str, Any],
    allowed_event_ids: set[int],
) -> tuple[dict[str, Any], list[str]]:
    """Coerce + verify model output. Returns (clean_doc, issues)."""
    issues: list[str] = []
    out: dict[str, Any] = {}

    def text_field(key: str, required: bool = False) -> str:
        val = doc.get(key)
        if val is None:
            if required:
                issues.append(f"missing '{key}'")
            return ""
        if not isinstance(val, str):
            issues.append(f"'{key}' was not a string; coerced")
            val = json.dumps(val)[:2000]
        return redact_secrets(val)[:6000]

    out["summary"] = text_field("summary", required=True)
    out["timeline_interpretation"] = text_field("timeline_interpretation")
    out["uncertainty_notes"] = text_field("uncertainty_notes")

    def str_list(key: str) -> list[str]:
        val = doc.get(key)
        if val is None:
            return []
        if isinstance(val, str):
            return [redact_secrets(val)[:500]]
        if not isinstance(val, list):
            issues.append(f"'{key}' was not a list; dropped")
            return []
        return [redact_secrets(str(v))[:500] for v in val[:20]]

    out["missing_information"] = str_list("missing_information")
    out["next_investigation_steps"] = str_list("next_investigation_steps")

    rc = doc.get("root_cause_hypothesis")
    if isinstance(rc, dict):
        conf = str(rc.get("confidence", "low")).lower()
        if conf not in ALLOWED_CONFIDENCE:
            issues.append("root_cause_hypothesis.confidence not in scale; set to low")
            conf = "low"
        out["root_cause_hypothesis"] = {
            "statement": redact_secrets(str(rc.get("statement", "")))[:1000],
            "confidence": conf,
        }
    else:
        out["root_cause_hypothesis"] = {"statement": "", "confidence": "low"}

    hyps_clean = []
    raw_hyps = doc.get("hypotheses")
    if not isinstance(raw_hyps, list):
        if raw_hyps is not None:
            issues.append("'hypotheses' was not a list; dropped")
        raw_hyps = []

    for h in raw_hyps[:8]:
        if not isinstance(h, dict):
            issues.append("hypothesis entry not an object; dropped")
            continue
        conf = str(h.get("confidence", "low")).lower()
        if conf not in ALLOWED_CONFIDENCE:
            conf = "low"
            issues.append("hypothesis confidence not in scale; set to low")

        def ids(key: str) -> tuple[list[int], int]:
            vals = h.get(key) or []
            if not isinstance(vals, list):
                return [], 0
            keep, dropped = [], 0
            for v in vals:
                # Accept only genuine integers. int(1.5) == 1 would silently
                # reinterpret a malformed value as a different event ID.
                if isinstance(v, bool):
                    dropped += 1
                    continue
                if isinstance(v, int):
                    iv = v
                elif isinstance(v, str) and v.strip().isdigit():
                    iv = int(v.strip())
                else:
                    dropped += 1
                    continue
                if iv in allowed_event_ids:
                    keep.append(iv)
                else:
                    dropped += 1
            return keep, dropped

        sup, sup_dropped = ids("supporting_event_ids")
        con, con_dropped = ids("contradicting_event_ids")
        if sup_dropped or con_dropped:
            issues.append(
                f"stripped {sup_dropped + con_dropped} evidence reference(s) "
                "not present in the supplied context"
            )
        hyps_clean.append({
            "statement": redact_secrets(str(h.get("statement", "")))[:1200],
            "confidence": conf,
            "supporting_event_ids": sup,
            "contradicting_event_ids": con,
            "reasoning": redact_secrets(str(h.get("reasoning", "")))[:2000],
        })

    out["hypotheses"] = hyps_clean
    return out, issues


# --------------------------------------------------------------------------
# Context building
# --------------------------------------------------------------------------

def build_incident_context(incident_id: int, max_events: int = MAX_EVENTS_IN_CONTEXT) -> dict[str, Any]:
    conn = get_conn()
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not inc:
        raise ValueError("Incident not found")

    alert_rows = conn.execute(
        "SELECT * FROM alerts WHERE incident_id=? ORDER BY severity DESC", (incident_id,)
    ).fetchall()

    event_ids: list[int] = []
    for a in alert_rows:
        for r in conn.execute(
            "SELECT event_id FROM alert_events WHERE alert_id=?", (a["id"],)
        ).fetchall():
            if r["event_id"] not in event_ids:
                event_ids.append(r["event_id"])

    events = []
    if event_ids:
        placeholders = ",".join("?" for _ in event_ids)
        rows = conn.execute(
            f"SELECT * FROM events WHERE id IN ({placeholders}) "
            "ORDER BY ts_utc IS NULL, ts_utc LIMIT ?",
            (*event_ids, max_events),
        ).fetchall()
        events = rows_to_dicts(rows)

    return {
        "incident": dict(inc),
        "alerts": rows_to_dicts(list(alert_rows)),
        "events": events,
        "total_events_available": len(event_ids),
        "truncated": len(event_ids) > len(events),
    }


def _render_event(ev: dict[str, Any]) -> dict[str, Any]:
    keep = {
        "id": ev["id"],
        "ts": ev.get("ts_utc") or f"UNKNOWN ({ev.get('ts_status')})",
        "ts_raw": ev.get("ts_raw"),
        "source": ev.get("source"),
        "event_type": ev.get("event_type"),
        "host": ev.get("host"),
        "user": ev.get("user_name"),
        "process": ev.get("process_name"),
        "parent": ev.get("parent_process"),
        "command_line": (ev.get("command_line") or "")[:200] or None,
        "dst_ip": ev.get("dst_ip"),
        "domain": ev.get("domain"),
        "file": ev.get("file_path"),
        "bytes_out": ev.get("bytes_out"),
    }
    return {k: v for k, v in keep.items() if v is not None}


def build_prompt(ctx: dict[str, Any]) -> tuple[str, str, set[int], dict[str, Any]]:
    inc = ctx["incident"]
    alerts = [
        {
            "rule_id": a["rule_id"],
            "title": a["title"],
            "severity": a["severity"],
            "narrative": a["narrative"][:600],
        }
        for a in ctx["alerts"]
    ]
    events = [_render_event(e) for e in ctx["events"]]
    allowed = {e["id"] for e in ctx["events"]}

    system = (
        "You are a defensive SOC analyst assistant inside SentinelGraph AI. "
        "You explain forensic evidence. You NEVER invent data. "
        "You distinguish observed facts from your own inferences. "
        "If evidence is insufficient, you say so plainly. "
        "Never suggest destructive or offensive actions; recommendations are "
        "advisory and require human approval.\n\n" + ANALYSIS_SCHEMA_HINT
    )

    user = json.dumps({
        "incident": {
            "ref": inc.get("ref"),
            "title": inc.get("title"),
            "severity": inc.get("severity"),
            "first_ts": inc.get("first_ts"),
            "last_ts": inc.get("last_ts"),
        },
        "alerts": alerts,
        "EVENTS": events,
        "context_note": (
            f"{len(events)} of {ctx['total_events_available']} evidence events supplied"
            + ("; truncated to fit context limit" if ctx["truncated"] else "")
        ),
    }, ensure_ascii=False, indent=1)

    manifest = {
        "event_ids": sorted(allowed),
        "event_count": len(events),
        "truncated": ctx["truncated"],
        "chars": len(user),
    }
    return system, user, allowed, manifest


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

def run_analysis(incident_id: int, spec: ai_providers.ProviderSpec | None,
                 task: str = "summarize") -> dict[str, Any]:
    """Execute one AI analysis run and persist it with its evidence links."""
    ctx = build_incident_context(incident_id)
    system, user, allowed_ids, manifest = build_prompt(ctx)
    project_id = ctx["incident"]["project_id"]
    now = now_iso()

    if spec is None:
        with cursor() as cur:
            cur.execute(
                """INSERT INTO ai_runs
                   (project_id,incident_id,task,provider,model,status,error_category,
                    error_message,request_context,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (project_id, incident_id, task, None, None, "no_provider",
                 "no_provider",
                 "No AI provider is configured. Core detection, timeline, graph and "
                 "reports remain fully available.",
                 json.dumps(manifest), now),
            )
            run_id = cur.lastrowid
        return {
            "status": "no_provider",
            "run_id": run_id,
            "message": "No AI provider configured. Analysis ran in core (non-AI) mode.",
            "manifest": manifest,
        }

    result = ai_providers.complete(spec, system, user)

    if not result.ok:
        with cursor() as cur:
            cur.execute(
                """INSERT INTO ai_runs
                   (project_id,incident_id,task,provider,model,status,latency_ms,
                    request_context,error_category,error_message,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (project_id, incident_id, task, spec.provider_type, spec.model_id, "error",
                 result.latency_ms, json.dumps(manifest), result.error_category,
                 redact_secrets(result.error_message), now),
            )
            run_id = cur.lastrowid
        return {
            "status": "error",
            "run_id": run_id,
            "error_category": result.error_category,
            "error_message": result.error_message,
            "manifest": manifest,
        }

    issues: list[str] = []
    try:
        doc = _extract_json(result.text)
        clean, issues = validate_analysis(doc, allowed_ids)
        # Classify every hypothesis by whether it survived evidence checking.
        # A hypothesis whose citations were all stripped is an unsupported
        # claim: it may still be worth reading, but it must never look
        # evidenced. This mirrors the observed/derived/hypothesis split that
        # the deterministic core uses.
        unsupported: list[str] = []
        for h in clean["hypotheses"]:
            if not h["supporting_event_ids"]:
                h["evidence_status"] = "unsupported"
                unsupported.append(h["statement"])
            elif h["contradicting_event_ids"]:
                h["evidence_status"] = "contested"
            else:
                h["evidence_status"] = "supported"

        clean["summary_is_unverified"] = True
        clean["unsupported_hypotheses"] = unsupported
        clean["stripped_reference_count"] = sum(
            int(i.split()[1]) for i in issues
            if i.startswith("stripped ") and i.split()[1].isdigit()
        )
        status = "ok" if not issues else "ok_with_warnings"
    except SchemaValidationError as exc:
        with cursor() as cur:
            cur.execute(
                """INSERT INTO ai_runs
                   (project_id,incident_id,task,provider,model,status,latency_ms,request_context,
                    error_category,error_message,result_json,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (project_id, incident_id, task, spec.provider_type, spec.model_id,
                 "validation_failed", result.latency_ms, json.dumps(manifest),
                 "schema_invalid", str(exc)[:300],
                 json.dumps({"raw_output": redact_secrets(result.text)[:4000]}), now),
            )
            run_id = cur.lastrowid
        return {
            "status": "validation_failed",
            "run_id": run_id,
            "message": "Model output did not match the required schema and was not "
                       "applied as findings.",
            "issues": [str(exc)],
            "manifest": manifest,
        }

    usage = result.usage or {}
    with cursor() as cur:
        cur.execute(
            """INSERT INTO ai_runs
               (project_id,incident_id,task,provider,model,status,latency_ms,prompt_tokens,
                output_tokens,request_context,result_json,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (project_id, incident_id, task, spec.provider_type, spec.model_id, status,
             result.latency_ms, usage.get("prompt_tokens") or usage.get("input_tokens"),
             usage.get("completion_tokens") or usage.get("output_tokens"),
             json.dumps(manifest), json.dumps(clean, ensure_ascii=False), now),
        )
        run_id = cur.lastrowid
        for eid in {i for h in clean["hypotheses"]
                    for i in h["supporting_event_ids"] + h["contradicting_event_ids"]}:
            cur.execute(
                "INSERT INTO ai_run_evidence (ai_run_id,event_id) VALUES (?,?)",
                (run_id, eid),
            )

    return {
        "status": status,
        "run_id": run_id,
        "provider": spec.provider_type,
        "model": spec.model_id,
        "latency_ms": result.latency_ms,
        "analysis": clean,
        "issues": issues,
        "manifest": manifest,
    }


def latest_runs(incident_id: int) -> list[dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM ai_runs WHERE incident_id=? ORDER BY id DESC LIMIT 10",
        (incident_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for key in ("request_context", "result_json"):
            if d.get(key):
                try:
                    d[key] = json.loads(d[key])
                except (TypeError, ValueError):
                    pass
        out.append(d)
    return out
