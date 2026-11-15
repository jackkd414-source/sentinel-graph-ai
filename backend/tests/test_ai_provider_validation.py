"""Provider / model validation regression tests.

These use a *fake* dispatch entry (a local Python function), so nothing is sent
to a real provider and no telemetry leaves the machine. They pin the behaviour
the product promises: provider and model selection are explicit, credentials
are masked, failures are classified instead of silently succeeding, structured
analysis output is validated, evidence references are checked, and no-provider
mode degrades cleanly.

The live path is deliberately *not* exercised here. A real call requires a
credential the operator supplies and explicitly authorises; these tests prove
the classification and guard logic that surrounds it.
"""
from __future__ import annotations

import httpx
import pytest

from sentinelgraph import ai_analysis, ai_providers
from sentinelgraph.ai_analysis import validate_analysis
from sentinelgraph.ai_providers import (
    DISPATCH,
    PROVIDER_TYPES,
    CallResult,
    ProviderError,
    ProviderSpec,
    complete,
    resolve_base_url,
)
from sentinelgraph.ai_providers import test_connection as check_connection
from sentinelgraph.security import SSRFError, redact_secrets


# ---------------------------------------------------------------------------
# Provider and model selection
# ---------------------------------------------------------------------------

def test_provider_selection_covers_all_declared_types():
    assert set(PROVIDER_TYPES) == {
        "openai", "anthropic", "gemini", "openrouter", "ollama", "custom_openai",
    }
    # Every declared provider must have a dispatch entry.
    assert set(DISPATCH) == set(PROVIDER_TYPES)


def test_ollama_is_local_and_keyless():
    meta = PROVIDER_TYPES["ollama"]
    assert meta["needs_key"] is False
    assert meta["base_url"].startswith("http://127.0.0.1")


def test_cloud_providers_require_a_key():
    for name in ("openai", "anthropic", "gemini", "openrouter"):
        assert PROVIDER_TYPES[name]["needs_key"] is True


def test_model_selection_is_carried_into_the_spec():
    spec = ProviderSpec(provider_type="openai", model_id="gpt-4o-mini",
                        fast_model_id="gpt-4o-mini-fast")
    assert spec.provider_type == "openai"
    assert spec.model_id == "gpt-4o-mini"
    assert spec.fast_model_id == "gpt-4o-mini-fast"


def test_ollama_loopback_base_url_is_allowed():
    """The only sanctioned private-endpoint exception is local Ollama."""
    spec = ProviderSpec(provider_type="ollama", model_id="llama3",
                        base_url="http://127.0.0.1:11434", allow_private=True)
    assert resolve_base_url(spec) == "http://127.0.0.1:11434"


def test_custom_base_url_is_rejected_even_with_allow_private():
    """allow_private only unlocks the *local Ollama* exception, by design.

    A custom OpenAI-compatible endpoint pointing at loopback is still refused so
    the SSRF guard cannot be talked into reaching internal services.
    """
    spec = ProviderSpec(provider_type="custom_openai", model_id="local-model",
                        base_url="http://127.0.0.1:8080/v1", allow_private=True)
    with pytest.raises(SSRFError):
        resolve_base_url(spec)


def test_internal_custom_base_url_is_rejected_without_allow_private():
    spec = ProviderSpec(provider_type="custom_openai", model_id="m",
                        base_url="http://169.254.169.254/latest/meta-data")
    with pytest.raises(SSRFError):
        resolve_base_url(spec)


# ---------------------------------------------------------------------------
# Credential masking
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,secret",
    [
        ("Authorization: Bearer sk-live-abcdefghijkl", "sk-live-abcdefghijkl"),
        ("api_key=sk-proj-0123456789abcdef", "sk-proj-0123456789abcdef"),
        ("key AIzaSyA1234567890abcdefghijklmnopqrstu", "AIzaSyA1234567890abcdefghijklmnopqrstu"),
        ("sk-ant-api03-abcdefghijklmn", "sk-ant-api03-abcdefghijklmn"),
    ],
)
def test_credentials_are_masked_in_free_text(raw, secret):
    masked = redact_secrets(raw)
    assert "REDACTED" in masked
    assert secret not in masked


def test_redaction_leaves_ordinary_text_alone():
    text = "Provider returned HTTP 500 while generating a summary."
    assert redact_secrets(text) == text


# ---------------------------------------------------------------------------
# Error classification (auth / rate limit / timeout)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "status,expected",
    [
        (401, "auth"), (403, "auth"), (429, "rate_limit"), (402, "quota"),
        (404, "model_not_found"), (400, "bad_request"), (500, "provider_error"),
        (418, "bad_request"),
    ],
)
def test_http_error_classification(status, expected):
    err = ai_providers._classify_http(status, "body")
    assert isinstance(err, ProviderError)
    assert err.category == expected


def test_model_not_found_is_detected_from_the_body():
    err = ai_providers._classify_http(400, '{"error":"model gpt-x not found"}')
    assert err.category == "model_not_found"


def _fake_dispatch(monkeypatch, fn):
    monkeypatch.setitem(DISPATCH, "openai", fn)


def test_auth_error_is_reported_not_success(monkeypatch):
    _fake_dispatch(monkeypatch, lambda spec, system, user: (_ for _ in ()).throw(
        ProviderError("auth", "HTTP 401: invalid key")))
    spec = ProviderSpec(provider_type="openai", model_id="m", api_key="sk-test")
    res = complete(spec, "sys", "user")
    assert res.ok is False
    assert res.error_category == "auth"


def test_rate_limit_is_reported_not_success(monkeypatch):
    _fake_dispatch(monkeypatch, lambda spec, system, user: (_ for _ in ()).throw(
        ProviderError("rate_limit", "HTTP 429")))
    spec = ProviderSpec(provider_type="openai", model_id="m", api_key="sk-test")
    res = complete(spec, "sys", "user")
    assert res.ok is False
    assert res.error_category == "rate_limit"


def test_timeout_is_reported_not_success(monkeypatch):
    _fake_dispatch(monkeypatch, lambda spec, system, user: (_ for _ in ()).throw(
        httpx.TimeoutException("slow")))
    spec = ProviderSpec(provider_type="openai", model_id="m", api_key="sk-test",
                        timeout_s=5)
    res = complete(spec, "sys", "user")
    assert res.ok is False
    assert res.error_category == "timeout"
    assert "timeout" in res.error_message.lower()


def test_missing_credential_is_not_reported_as_success():
    spec = ProviderSpec(provider_type="openai", model_id="m", api_key=None)
    res = complete(spec, "sys", "user")
    assert res.ok is False
    assert res.error_category == "no_credential"


def test_unknown_provider_is_rejected():
    spec = ProviderSpec(provider_type="does-not-exist", model_id="m")
    res = complete(spec, "sys", "user")
    assert res.ok is False
    assert res.error_category == "unsupported_provider"


def test_no_provider_mode_returns_structured_error():
    """A deployment with no provider must degrade cleanly, not raise."""
    spec = ProviderSpec(provider_type="none", model_id="")
    res = complete(spec, "sys", "user")
    assert isinstance(res, CallResult)
    assert res.ok is False
    assert res.error_category == "unsupported_provider"


# ---------------------------------------------------------------------------
# Test Connection (fake provider - no live request)
# ---------------------------------------------------------------------------

def test_test_connection_reports_structured_result(monkeypatch):
    _fake_dispatch(monkeypatch, lambda spec, system, user: CallResult(
        ok=True, text="OK", latency_ms=7, model=spec.model_id,
        provider=spec.provider_type))
    spec = ProviderSpec(provider_type="openai", model_id="gpt-4o-mini",
                        api_key="sk-test")
    result = check_connection(spec)
    assert result["ok"] is True
    assert result["provider"] == "openai"
    assert result["model"] == "gpt-4o-mini"
    assert result["sample_reply"] == "OK"
    assert isinstance(result["latency_ms"], int)
    assert result["error_category"] is None
    assert "checked_at" in result


def test_test_connection_reports_failure_category(monkeypatch):
    _fake_dispatch(monkeypatch, lambda spec, system, user: CallResult(
        ok=False, error_category="auth", error_message="HTTP 401"))
    spec = ProviderSpec(provider_type="openai", model_id="m", api_key="sk-test")
    result = check_connection(spec)
    assert result["ok"] is False
    assert result["error_category"] == "auth"


# ---------------------------------------------------------------------------
# Structured analysis output + evidence references
# ---------------------------------------------------------------------------

def test_structured_analysis_output_is_validated():
    doc = {
        "summary": "Suspicious logon followed by lateral movement.",
        "timeline_interpretation": "Logon at 09:14, lateral move at 09:16.",
        "root_cause_hypothesis": {
            "statement": "Credential reuse from MAILGW-01",
            "confidence": "high",
        },
        "hypotheses": [{
            "statement": "Credential reuse from MAILGW-01",
            "confidence": "high",
            "supporting_event_ids": [1, 2],
            "contradicting_event_ids": [],
        }],
        "missing_information": ["Which account was used on MAILGW-01"],
    }
    clean, issues = validate_analysis(doc, {1, 2, 3})
    assert clean["summary"] == doc["summary"]
    assert clean["root_cause_hypothesis"]["confidence"] == "high"
    assert clean["hypotheses"][0]["supporting_event_ids"] == [1, 2]
    assert not [i for i in issues if "stripped" in i]


def test_evidence_references_are_enforced():
    doc = {
        "summary": "Claim without real evidence.",
        "hypotheses": [{
            "statement": "Attacker used WS-EVIL-99",
            "confidence": "high",
            "supporting_event_ids": [1, 999999],
        }],
    }
    clean, issues = validate_analysis(doc, {1, 2, 3})
    assert clean["hypotheses"][0]["supporting_event_ids"] == [1]
    assert any("stripped" in i for i in issues)


def test_invalid_confidence_is_downgraded_not_trusted():
    doc = {
        "summary": "s",
        "hypotheses": [{"statement": "x", "confidence": "certain"}],
    }
    clean, issues = validate_analysis(doc, {1})
    assert clean["hypotheses"][0]["confidence"] == "low"
    assert any("confidence" in i for i in issues)


def test_secrets_in_model_output_are_redacted():
    doc = {
        "summary": "Leaked key sk-live-abcdefghijkl in the transcript.",
        "hypotheses": [],
    }
    clean, _ = validate_analysis(doc, {1})
    assert "sk-live-abcdefghijkl" not in clean["summary"]
    assert "REDACTED" in clean["summary"]
