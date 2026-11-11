"""AI provider adapters.

Design constraints that shaped this module:
  * Each provider has a genuinely different request/response shape. We model
    that explicitly instead of pretending one OpenAI-shaped call fits all.
  * Every call goes through the same credential resolution path so no key can
    leak into logs, errors, or responses.
  * Outputs are schema-validated and evidence-references are checked against
    the database before anything is stored. The model cannot invent events.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import env_provider_keys, get_settings
from .security import redact_secrets, validate_provider_url

PROVIDER_TYPES = {
    "openai": {
        "label": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "needs_key": True,
        "supports_model_list": True,
        "docs": "https://platform.openai.com/docs/api-reference",
    },
    "anthropic": {
        "label": "Anthropic",
        "base_url": "https://api.anthropic.com/v1",
        "needs_key": True,
        "supports_model_list": True,
        "docs": "https://docs.anthropic.com/en/api",
    },
    "gemini": {
        "label": "Google Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "needs_key": True,
        "supports_model_list": True,
        "docs": "https://ai.google.dev/api",
    },
    "openrouter": {
        "label": "OpenRouter",
        "base_url": "https://openrouter.ai/api/v1",
        "needs_key": True,
        "supports_model_list": True,
        "docs": "https://openrouter.ai/docs",
    },
    "ollama": {
        "label": "Ollama (local)",
        "base_url": "http://127.0.0.1:11434",
        "needs_key": False,
        "supports_model_list": True,
        "docs": "https://github.com/ollama/ollama/blob/main/docs/api.md",
    },
    "custom_openai": {
        "label": "Custom OpenAI-compatible",
        "base_url": "",
        "needs_key": True,
        "supports_model_list": False,
        "docs": "Any endpoint implementing POST {base}/chat/completions",
    },
}

# Reasoning models spend part of this budget on hidden reasoning before they
# emit any visible text, so the ceiling needs headroom above the JSON we want.
MAX_OUTPUT_TOKENS_DEFAULT = 8192
MAX_CONTEXT_CHARS = 24000      # hard ceiling on what we will ever send
REQUEST_TIMEOUT_DEFAULT = 60


@dataclass
class ProviderSpec:
    provider_type: str
    model_id: str
    api_key: str | None = None
    base_url: str | None = None
    timeout_s: int = REQUEST_TIMEOUT_DEFAULT
    max_output_tokens: int | None = MAX_OUTPUT_TOKENS_DEFAULT
    fast_model_id: str | None = None
    allow_private: bool = False
    name: str = "default"


@dataclass
class CallResult:
    ok: bool
    text: str = ""
    error_category: str | None = None
    error_message: str = ""
    latency_ms: int = 0
    model: str = ""
    provider: str = ""
    usage: dict[str, Any] = field(default_factory=dict)


class ProviderError(Exception):
    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category
        self.message = message


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _classify_http(status: int, body: str) -> ProviderError:
    text = (body or "")[:800]
    low = text.lower()
    if status in (401, 403):
        return ProviderError("auth", f"Authentication/authorization failed (HTTP {status}).")
    if status == 404 or "model" in low and "not found" in low:
        return ProviderError("model_not_found", f"Model or endpoint not found (HTTP {status}).")
    if status == 429:
        return ProviderError("rate_limit", "Rate limited or quota exhausted (HTTP 429).")
    if status == 402:
        return ProviderError("quota", "Payment required / quota exhausted (HTTP 402).")
    if 400 <= status < 500:
        return ProviderError("bad_request", f"Provider rejected the request (HTTP {status}).")
    if 500 <= status < 600:
        return ProviderError("provider_error", f"Provider-side failure (HTTP {status}).")
    return ProviderError("unexpected", f"Unexpected HTTP {status}.")


def _net_error(exc: Exception) -> ProviderError:
    if isinstance(exc, httpx.TimeoutException):
        return ProviderError("timeout", "Request timed out.")
    if isinstance(exc, httpx.ConnectError):
        return ProviderError("network", "Could not connect to the provider endpoint.")
    return ProviderError("network", f"Network error: {type(exc).__name__}.")


def _sanitize(msg: str) -> str:
    return redact_secrets(msg)[:500]


def resolve_base_url(spec: ProviderSpec) -> str:
    default = PROVIDER_TYPES[spec.provider_type]["base_url"]
    url = (spec.base_url or default).rstrip("/")
    validate_provider_url(url, spec.provider_type, allow_private=spec.allow_private)
    return url


# --------------------------------------------------------------------------
# Providers
# --------------------------------------------------------------------------

def _call_openai_like(spec: ProviderSpec, system: str, user: str) -> CallResult:
    base = resolve_base_url(spec)
    headers = {"Content-Type": "application/json"}
    if spec.api_key:
        headers["Authorization"] = f"Bearer {spec.api_key}"
    if spec.provider_type == "openrouter":
        headers["HTTP-Referer"] = "https://sentinelgraph.local"
        headers["X-Title"] = "SentinelGraph AI"

    payload: dict[str, Any] = {
        "model": spec.model_id,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.1,
    }
    if spec.max_output_tokens:
        payload["max_tokens"] = spec.max_output_tokens

    t0 = time.perf_counter()
    with httpx.Client(timeout=spec.timeout_s, follow_redirects=False) as client:
        resp = client.post(f"{base}/chat/completions", headers=headers, json=payload)
    latency = int((time.perf_counter() - t0) * 1000)

    if resp.status_code >= 400:
        raise _classify_http(resp.status_code, resp.text)

    try:
        data = resp.json()
        choice = data["choices"][0]
        text = choice["message"]["content"] or ""
        finish = choice.get("finish_reason")
        usage = data.get("usage") or {}
    except (KeyError, IndexError, ValueError) as exc:
        raise ProviderError("invalid_response",
                            f"Provider returned an unexpected body shape ({type(exc).__name__}).")

    # A reasoning model can burn the entire max_tokens budget on hidden
    # reasoning and return an empty content string with finish_reason=length.
    # Reporting that as "no JSON object" is misleading - say what happened.
    reasoning_tokens = (usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
    if finish == "length" and not text.strip():
        budget = spec.max_output_tokens or 0
        detail = (f" all {reasoning_tokens} completion tokens went to hidden reasoning"
                  if reasoning_tokens else "")
        raise ProviderError(
            "output_truncated",
            f"Model hit the {budget}-token max_tokens limit before producing any "
            f"content;{detail}. Raise max_tokens for this provider or use a "
            f"non-reasoning model.")

    return CallResult(
        ok=True, text=text, latency_ms=latency, model=spec.model_id,
        provider=spec.provider_type,
        usage=usage,
    )


def _call_anthropic(spec: ProviderSpec, system: str, user: str) -> CallResult:
    base = resolve_base_url(spec)
    headers = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }
    if spec.api_key:
        headers["x-api-key"] = spec.api_key

    payload: dict[str, Any] = {
        "model": spec.model_id,
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "temperature": 0.1,
    }
    if spec.max_output_tokens:
        payload["max_tokens"] = spec.max_output_tokens

    t0 = time.perf_counter()
    with httpx.Client(timeout=spec.timeout_s, follow_redirects=False) as client:
        resp = client.post(f"{base}/messages", headers=headers, json=payload)
    latency = int((time.perf_counter() - t0) * 1000)

    if resp.status_code >= 400:
        raise _classify_http(resp.status_code, resp.text)

    try:
        data = resp.json()
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    except (ValueError, AttributeError) as exc:
        raise ProviderError("invalid_response",
                            f"Provider returned an unexpected body shape ({type(exc).__name__}).")

    return CallResult(ok=True, text=text, latency_ms=latency, model=spec.model_id,
                      provider="anthropic", usage=data.get("usage") or {})


def _call_gemini(spec: ProviderSpec, system: str, user: str) -> CallResult:
    base = resolve_base_url(spec)
    url = f"{base}/models/{spec.model_id}:generateContent"
    headers = {"Content-Type": "application/json"}
    if spec.api_key:
        headers["x-goog-api-key"] = spec.api_key

    payload: dict[str, Any] = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"temperature": 0.1},
    }
    if spec.max_output_tokens:
        payload["generationConfig"]["maxOutputTokens"] = spec.max_output_tokens

    t0 = time.perf_counter()
    with httpx.Client(timeout=spec.timeout_s, follow_redirects=False) as client:
        resp = client.post(url, headers=headers, json=payload)
    latency = int((time.perf_counter() - t0) * 1000)

    if resp.status_code >= 400:
        raise _classify_http(resp.status_code, resp.text)

    try:
        data = resp.json()
        cands = data.get("candidates") or []
        parts = (cands[0].get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts)
    except (ValueError, IndexError, KeyError, AttributeError) as exc:
        raise ProviderError("invalid_response",
                            f"Provider returned an unexpected body shape ({type(exc).__name__}).")

    return CallResult(ok=True, text=text, latency_ms=latency, model=spec.model_id,
                      provider="gemini", usage=data.get("usageMetadata") or {})


def _call_ollama(spec: ProviderSpec, system: str, user: str) -> CallResult:
    base = resolve_base_url(spec)
    payload: dict[str, Any] = {
        "model": spec.model_id,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "options": {"temperature": 0.1},
    }
    if spec.max_output_tokens:
        payload["options"]["num_predict"] = spec.max_output_tokens

    t0 = time.perf_counter()
    with httpx.Client(timeout=spec.timeout_s, follow_redirects=False) as client:
        resp = client.post(f"{base}/api/chat", json=payload)
    latency = int((time.perf_counter() - t0) * 1000)

    if resp.status_code >= 400:
        raise _classify_http(resp.status_code, resp.text)
    try:
        data = resp.json()
        text = (data.get("message") or {}).get("content") or ""
    except (ValueError, AttributeError) as exc:
        raise ProviderError("invalid_response",
                            f"Provider returned an unexpected body shape ({type(exc).__name__}).")

    return CallResult(ok=True, text=text, latency_ms=latency, model=spec.model_id,
                      provider="ollama", usage={"eval_count": data.get("eval_count")})


DISPATCH = {
    "openai": _call_openai_like,
    "openrouter": _call_openai_like,
    "custom_openai": _call_openai_like,
    "anthropic": _call_anthropic,
    "gemini": _call_gemini,
    "ollama": _call_ollama,
}


def complete(spec: ProviderSpec, system: str, user: str) -> CallResult:
    """Single entry point. Never raises - returns a classified CallResult."""
    if len(user) + len(system) > MAX_CONTEXT_CHARS:
        return CallResult(ok=False, error_category="context_too_large",
                          error_message=f"Prompt exceeds {MAX_CONTEXT_CHARS} characters; "
                                        "reduce the selected evidence.",
                          provider=spec.provider_type, model=spec.model_id)
    if spec.provider_type not in PROVIDER_TYPES:
        return CallResult(ok=False, error_category="unsupported_provider",
                          error_message=f"Provider type '{spec.provider_type}' is not supported.",
                          provider=spec.provider_type, model=spec.model_id)
    needs_key = PROVIDER_TYPES[spec.provider_type]["needs_key"]
    if needs_key and not spec.api_key:
        return CallResult(ok=False, error_category="no_credential",
                          error_message="No API key configured for this provider.",
                          provider=spec.provider_type, model=spec.model_id)
    fn = DISPATCH.get(spec.provider_type)
    if fn is None:
        return CallResult(ok=False, error_category="unsupported_provider",
                          error_message=f"Provider type '{spec.provider_type}' is not implemented.",
                          provider=spec.provider_type, model=spec.model_id)
    try:
        return fn(spec, system, user)
    except ProviderError as exc:
        return CallResult(ok=False, error_category=exc.category,
                          error_message=_sanitize(exc.message),
                          provider=spec.provider_type, model=spec.model_id)
    except Exception as exc:  # noqa: BLE001
        net = _net_error(exc)
        return CallResult(ok=False, error_category=net.category,
                          error_message=_sanitize(net.message),
                          provider=spec.provider_type, model=spec.model_id)


# --------------------------------------------------------------------------
# Health check (real request - not an API-key presence check)
# --------------------------------------------------------------------------

def test_connection(spec: ProviderSpec) -> dict[str, Any]:
    """Send a minimal real request and report what actually happened."""
    t0 = time.perf_counter()
    result = complete(
        spec,
        system="You are a health check. Reply with exactly: OK",
        user="Reply with exactly: OK",
    )
    total_ms = int((time.perf_counter() - t0) * 1000)
    return {
        "ok": result.ok,
        "provider": spec.provider_type,
        "model": spec.model_id,
        "base_url": (spec.base_url or PROVIDER_TYPES[spec.provider_type]["base_url"]),
        "latency_ms": result.latency_ms or total_ms,
        "error_category": result.error_category,
        "error_message": result.error_message,
        "sample_reply": (result.text or "")[:120],
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def list_models(spec: ProviderSpec) -> dict[str, Any]:
    """Best-effort model discovery. Manual model IDs remain the primary path."""
    meta = PROVIDER_TYPES[spec.provider_type]
    if not meta["supports_model_list"]:
        return {"ok": False, "models": [],
                "error": "This provider type does not expose a model list. "
                         "Enter the model ID manually."}
    try:
        base = resolve_base_url(spec)
        headers: dict[str, str] = {}
        if spec.provider_type == "ollama":
            with httpx.Client(timeout=min(spec.timeout_s, 15)) as c:
                r = c.get(f"{base}/api/tags")
            if r.status_code >= 400:
                return {"ok": False, "models": [], "error": f"HTTP {r.status_code}"}
            return {"ok": True,
                    "models": [m.get("name") for m in (r.json().get("models") or [])]}

        if spec.provider_type == "gemini":
            if spec.api_key:
                headers["x-goog-api-key"] = spec.api_key
            with httpx.Client(timeout=min(spec.timeout_s, 15)) as c:
                r = c.get(f"{base}/models", headers=headers)
            if r.status_code >= 400:
                return {"ok": False, "models": [], "error": f"HTTP {r.status_code}"}
            models = [m.get("name", "").split("/")[-1] for m in (r.json().get("models") or [])]
            return {"ok": True, "models": sorted(m for m in models if m)}

        if spec.api_key:
            headers["Authorization"] = f"Bearer {spec.api_key}"
        if spec.provider_type == "anthropic" and spec.api_key:
            headers["x-api-key"] = spec.api_key
            headers["anthropic-version"] = "2023-06-01"
            headers.pop("Authorization", None)
        with httpx.Client(timeout=min(spec.timeout_s, 15)) as c:
            r = c.get(f"{base}/models", headers=headers)
        if r.status_code >= 400:
            return {"ok": False, "models": [], "error": f"HTTP {r.status_code}"}
        data = r.json()
        items = data.get("data") if isinstance(data, dict) else None
        models = [m.get("id") for m in (items or []) if isinstance(m, dict)]
        return {"ok": True, "models": sorted(m for m in models if m)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "models": [], "error": _sanitize(type(exc).__name__)}


def env_key_for(provider_type: str) -> str | None:
    keys = env_provider_keys()
    if provider_type == "custom_openai":
        return keys.get("openai")
    return keys.get(provider_type)


def default_base_url(provider_type: str) -> str:
    return PROVIDER_TYPES[provider_type]["base_url"]
