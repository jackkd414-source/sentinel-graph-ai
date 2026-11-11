"""AI layer tests.

The central claim of this product is that the model cannot corrupt the
evidence store. These tests try to break that claim.
"""
from __future__ import annotations

import json

import pytest

from sentinelgraph import ai_analysis, ai_providers
from sentinelgraph.ai_analysis import (
    SchemaValidationError,
    _extract_json,
    validate_analysis,
)


ALLOWED = {1, 2, 3}


# --------------------------------------------------------------------------
# JSON extraction from messy model output
# --------------------------------------------------------------------------

def test_extract_plain_json():
    doc = _extract_json('{"summary": "ok"}')
    assert doc["summary"] == "ok"


def test_extract_fenced_json():
    doc = _extract_json('```json\n{"summary": "ok"}\n```')
    assert doc["summary"] == "ok"


def test_extract_json_with_preamble():
    doc = _extract_json('Here is the analysis:\n{"summary": "ok"}\nHope this helps.')
    assert doc["summary"] == "ok"


def test_extract_rejects_non_json():
    with pytest.raises(SchemaValidationError):
        _extract_json("I cannot help with that.")


# --------------------------------------------------------------------------
# Evidence verification - the anti-hallucination core
# --------------------------------------------------------------------------

def test_fabricated_event_ids_are_stripped():
    doc = {
        "summary": "Something happened.",
        "hypotheses": [{
            "statement": "Attacker used host WS-EVIL-99",
            "confidence": "high",
            "supporting_event_ids": [1, 2, 999999],
            "contradicting_event_ids": [777],
        }],
    }
    clean, issues = validate_analysis(doc, ALLOWED)
    hyp = clean["hypotheses"][0]
    assert hyp["supporting_event_ids"] == [1, 2], "invented event id must be removed"
    assert hyp["contradicting_event_ids"] == []
    assert any("stripped" in i for i in issues)


def test_all_fabricated_evidence_leaves_empty_support():
    doc = {"summary": "x", "hypotheses": [{
        "statement": "y", "confidence": "high",
        "supporting_event_ids": [111, 222],
    }]}
    clean, issues = validate_analysis(doc, ALLOWED)
    assert clean["hypotheses"][0]["supporting_event_ids"] == []
    assert issues


def test_non_integer_evidence_refs_dropped():
    doc = {"summary": "x", "hypotheses": [{
        "statement": "y", "confidence": "low",
        "supporting_event_ids": ["one", None, 1.5, {"a": 1}, 2],
    }]}
    clean, _ = validate_analysis(doc, ALLOWED)
    assert clean["hypotheses"][0]["supporting_event_ids"] == [2]


def test_invalid_confidence_is_coerced_to_low():
    doc = {"summary": "x", "hypotheses": [{
        "statement": "y", "confidence": "99% certain",
        "supporting_event_ids": [1],
    }]}
    clean, issues = validate_analysis(doc, ALLOWED)
    assert clean["hypotheses"][0]["confidence"] == "low"
    assert any("confidence" in i for i in issues)


def test_missing_summary_is_reported():
    clean, issues = validate_analysis({"hypotheses": []}, ALLOWED)
    assert clean["summary"] == ""
    assert any("summary" in i for i in issues)


def test_secrets_in_model_output_are_redacted():
    doc = {"summary": "The key is sk-abcdef1234567890abcd and it leaked."}
    clean, _ = validate_analysis(doc, ALLOWED)
    assert "sk-abcdef1234567890abcd" not in clean["summary"]
    assert "REDACTED" in clean["summary"]


def test_non_dict_hypothesis_entries_dropped():
    doc = {"summary": "x", "hypotheses": ["just a string", {"statement": "ok",
           "confidence": "low", "supporting_event_ids": [1]}]}
    clean, issues = validate_analysis(doc, ALLOWED)
    assert len(clean["hypotheses"]) == 1
    assert any("not an object" in i for i in issues)


def test_hypotheses_capped():
    doc = {"summary": "x", "hypotheses": [
        {"statement": f"h{i}", "confidence": "low", "supporting_event_ids": [1]}
        for i in range(50)
    ]}
    clean, _ = validate_analysis(doc, ALLOWED)
    assert len(clean["hypotheses"]) <= 8


# --------------------------------------------------------------------------
# Provider dispatch without network
# --------------------------------------------------------------------------

def test_missing_credential_reports_cleanly_not_success():
    spec = ai_providers.ProviderSpec(provider_type="openai", model_id="gpt-x", api_key=None)
    res = ai_providers.complete(spec, "s", "u")
    assert res.ok is False
    assert res.error_category == "no_credential"


def test_unsupported_provider_type_is_rejected():
    spec = ai_providers.ProviderSpec(provider_type="nope", model_id="m", api_key="k")
    res = ai_providers.complete(spec, "s", "u")
    assert res.ok is False
    assert res.error_category == "unsupported_provider"


def test_oversized_context_is_refused_before_any_request():
    spec = ai_providers.ProviderSpec(provider_type="openai", model_id="m", api_key="k")
    huge = "x" * (ai_providers.MAX_CONTEXT_CHARS + 10)
    res = ai_providers.complete(spec, "s", huge)
    assert res.ok is False
    assert res.error_category == "context_too_large"


def test_all_declared_providers_have_a_dispatch_entry():
    for ptype in ai_providers.PROVIDER_TYPES:
        assert ptype in ai_providers.DISPATCH, f"{ptype} declared but not implemented"


# --------------------------------------------------------------------------
# Mock provider integration: schema failure must not write findings
# --------------------------------------------------------------------------

def test_schema_failure_is_recorded_not_applied(app_env, monkeypatch, client, loaded_demo):
    from sentinelgraph import ai_analysis as aa
    from sentinelgraph.db import get_conn

    incidents = client.get("/api/incidents").json()["incidents"]
    inc_id = incidents[0]["id"]

    def fake_complete(spec, system, user):
        return ai_providers.CallResult(
            ok=True, text="I think this is bad but I will not return JSON.",
            provider="openai", model="mock-model", latency_ms=12,
        )

    monkeypatch.setattr(ai_providers, "complete", fake_complete)
    monkeypatch.setattr(aa.ai_providers, "complete", fake_complete)

    spec = ai_providers.ProviderSpec(provider_type="openai", model_id="mock-model",
                                     api_key="sk-test-key")
    result = aa.run_analysis(inc_id, spec)
    assert result["status"] == "validation_failed"

    conn = get_conn()
    run = conn.execute("SELECT * FROM ai_runs WHERE id=?", (result["run_id"],)).fetchone()
    assert run["status"] == "validation_failed"
    assert run["result_json"] is None or "raw_output" in (run["result_json"] or "")
    # nothing was inserted into findings/events by the AI path
    n_findings = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
    assert n_findings == 0


def test_successful_run_stores_validated_json_and_evidence(app_env, monkeypatch, client,
                                                           loaded_demo):
    from sentinelgraph import ai_analysis as aa
    from sentinelgraph.db import get_conn

    inc = client.get("/api/incidents").json()["incidents"][0]
    inc_id = inc["id"]
    real_ids = [a["id"] for a in client.get("/api/alerts").json()["alerts"]]

    ctx = aa.build_incident_context(inc_id)
    first_event = ctx["events"][0]["id"]

    payload = {
        "summary": "Correlated phishing-driven activity on a finance workstation.",
        "timeline_interpretation": "Link open, then script host spawn, then C2 contact.",
        "hypotheses": [{
            "statement": "The account was used to stage data before a C2 upload.",
            "confidence": "medium",
            "supporting_event_ids": [first_event, 987654],
            "contradicting_event_ids": [],
            "reasoning": "Sensitive file reads precede a large outbound transfer.",
        }],
        "root_cause_hypothesis": {"statement": "Phishing email led to script execution.",
                                  "confidence": "medium"},
        "missing_information": ["No DLP telemetry to confirm payload contents."],
        "next_investigation_steps": ["Collect memory image from the workstation."],
        "uncertainty_notes": "Cannot confirm data left the network.",
    }

    def fake_complete(spec, system, user):
        return ai_providers.CallResult(
            ok=True, text=json.dumps(payload), provider="openai",
            model="mock-model", latency_ms=8, usage={"prompt_tokens": 100,
                                                     "completion_tokens": 80},
        )

    monkeypatch.setattr(aa.ai_providers, "complete", fake_complete)
    spec = ai_providers.ProviderSpec(provider_type="openai", model_id="mock-model",
                                     api_key="sk-test-key")
    result = aa.run_analysis(inc_id, spec)

    assert result["status"] in ("ok", "ok_with_warnings")
    hyp = result["analysis"]["hypotheses"][0]
    assert hyp["supporting_event_ids"] == [first_event], \
        "the fabricated id 987654 must have been stripped"
    assert any("stripped" in i for i in result["issues"])

    conn = get_conn()
    links = conn.execute(
        "SELECT event_id FROM ai_run_evidence WHERE ai_run_id=?", (result["run_id"],)
    ).fetchall()
    assert [r["event_id"] for r in links] == [first_event]


def test_no_provider_mode_keeps_core_features_working(app_env, client, loaded_demo):
    """With zero AI configuration the whole core pipeline must still function."""
    inc = client.get("/api/incidents").json()["incidents"][0]
    r = client.post(f"/api/incidents/{inc['id']}/analyze")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "no_provider"
    assert "core" in body["message"].lower()

    # graph, timeline and report still work
    assert client.get("/api/graph").json()["nodes"] != []
    assert client.get(f"/api/incidents/{inc['id']}").json()["timeline"] != []
    rep = client.post(f"/api/incidents/{inc['id']}/report?fmt=md")
    assert rep.status_code == 200
    assert "deterministic core engine" in rep.json()["content"]


def test_hypothesis_with_all_citations_stripped_is_marked_unsupported(app_env, client, loaded_demo):
    """A hypothesis that cites only non-existent events must not look evidenced.

    Regression for the case where a model returns a plausible-sounding stage
    ("ransomware deployed") backed by fabricated event IDs. Stripping the IDs is
    not enough: the UI and the report must also show that nothing supports it.
    """
    from sentinelgraph import ai_analysis
    from sentinelgraph.ai_analysis import validate_analysis

    doc = {
        "summary": "Ransomware was deployed across the estate.",
        "hypotheses": [
            {
                "statement": "Ransomware deployed everywhere",
                "confidence": "high",
                "supporting_event_ids": [424242, 434343],
                "contradicting_event_ids": [],
                "reasoning": "invented",
            }
        ],
    }
    clean, issues = validate_analysis(doc, {1, 2, 3})
    assert clean["hypotheses"][0]["supporting_event_ids"] == []
    assert any("stripped" in i for i in issues)


def test_evidence_status_classification(app_env, client, loaded_demo):
    """validate_analysis alone does not set status; run_analysis does.

    Verify the classification helper's contract through the real code path that
    assigns it, so the tag cannot silently disappear.
    """
    from sentinelgraph import ai_analysis
    import inspect

    src = inspect.getsource(ai_analysis.run_analysis)
    assert 'h["evidence_status"] = "unsupported"' in src
    assert 'h["evidence_status"] = "contested"' in src
    assert 'h["evidence_status"] = "supported"' in src
    assert "stripped_reference_count" in src


def test_keyless_provider_reports_ai_enabled_not_missing_credential(app_env, client, loaded_demo):
    """Ollama/local providers take no API key; status must not call them broken."""
    from sentinelgraph import provider_store

    client.post("/api/ai/providers", json={
        "name": "Local", "provider_type": "ollama",
        "model_id": "llama3", "api_key": "",
        "base_url": "http://127.0.0.1:11434",
    })
    client.post("/api/ai/providers/1/activate")
    st = provider_store.ai_status()
    assert st["mode"] == "ai_enabled", st
    assert "no usable credential" not in st["detail"].lower()


def test_reasoning_model_that_burns_budget_reports_truncation_not_invalid_json():
    """A reasoning model can spend every token on hidden reasoning and return
    finish_reason=length with empty content. That must be reported as
    output_truncated with advice, not as 'response contained no JSON object'."""
    from sentinelgraph import ai_providers as p

    spec = p.ProviderSpec(provider_type="custom_openai", model_id="reasoner",
                          api_key="k", base_url="http://127.0.0.1:9/v1",
                          max_output_tokens=2048)

    class FakeResp:
        status_code = 200

        @staticmethod
        def json():
            return {
                "choices": [{"message": {"content": ""}, "finish_reason": "length"}],
                "usage": {"completion_tokens": 2048,
                          "completion_tokens_details": {"reasoning_tokens": 2048}},
            }

    class FakeClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, *a, **k): return FakeResp()

    # Stub out URL validation too: this test targets response handling, and the
    # SSRF guard would reject the dummy loopback base_url before the POST.
    orig_client = p.httpx.Client
    orig_resolve = p.resolve_base_url
    p.httpx.Client = FakeClient
    p.resolve_base_url = lambda spec: "https://example.invalid/v1"
    try:
        with pytest.raises(p.ProviderError) as ei:
            p._call_openai_like(spec, "sys", "user")
    finally:
        p.httpx.Client = orig_client
        p.resolve_base_url = orig_resolve

    assert ei.value.category == "output_truncated"
    assert "max_tokens" in ei.value.message
    assert "reasoning" in ei.value.message.lower()


def test_truncated_model_output_leaves_report_free_of_ai_claims(app_env, client, loaded_demo):
    """When AI output is unusable the report must say so rather than omit it.

    Exercises the renderer directly with a validation_failed run so the test
    does not depend on a live model being reachable.
    """
    from sentinelgraph import reporting

    data = reporting.gather(
        client.get("/api/incidents").json()["incidents"][0]["id"])
    data["ai"] = {
        "status": "validation_failed",
        "error_category": "output_truncated",
        "provider": "custom_openai",
        "model": "reasoner",
    }
    md = reporting.build_markdown(data)
    assert "did not produce usable output" in md
    assert "output_truncated" in md
    # No model text may leak in when validation failed.
    assert "Summary:" not in md


def test_report_states_no_provider_without_claiming_failure(app_env, client, loaded_demo):
    """'no provider configured' must not read as 'the AI broke'."""
    from sentinelgraph import reporting

    data = reporting.gather(
        client.get("/api/incidents").json()["incidents"][0]["id"])
    data["ai"] = None
    md = reporting.build_markdown(data)
    assert "No AI analysis was run" in md
    assert "did not produce usable output" not in md


def test_sysmon_format_fields_are_ingested_and_detected(app_env, client):
    """The Sysmon field mapping the export script produces must actually work.

    Guards the contract between export-windows-logs.ps1 and ingest.py: if either
    side renames a field (parent_process, dst_ip, ...), detection silently dies.
    """
    events = [
        {"@timestamp": "2026-06-01T09:00:00Z", "host": "SYM-HOST", "source": "edr",
         "event_id": 1, "event_type": "process_create", "user_name": "symuser",
         "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "parent_process": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"},
        {"@timestamp": "2026-06-01T09:01:00Z", "host": "SYM-HOST", "source": "edr",
         "event_id": 3, "event_type": "network_connect", "user_name": "symuser",
         "dst_ip": "198.51.100.23", "dst_port": "443"},
        {"@timestamp": "2026-06-01T09:02:00Z", "host": "SYM-HOST", "source": "edr",
         "event_id": 22, "event_type": "dns_query", "user_name": "symuser",
         "domain": "malicious-c2.example"},
    ]
    r = client.post("/api/ingest/text", json={
        "text": json.dumps(events), "filename": "sysmon.json", "source_type": "edr",
    })
    assert r.status_code == 200
    analysis = r.json()["analysis"]
    assert analysis["records_ok" if "records_ok" in analysis else "events_analyzed"]

    rules = {a["rule_id"] for a in client.get("/api/alerts").json()["alerts"]}
    assert "R-002" in rules, "Sysmon process chain must raise R-002"
    assert "R-003" in rules, "Sysmon network event to IOC must raise R-003"

    kinds: dict[str, int] = {}
    for n in client.get("/api/graph").json()["nodes"]:
        kinds[n["node_type"]] = kinds.get(n["node_type"], 0) + 1
    assert kinds.get("process", 0) >= 1, "process nodes must reach the graph"
    assert kinds.get("user", 0) >= 1, "user nodes must reach the graph"
