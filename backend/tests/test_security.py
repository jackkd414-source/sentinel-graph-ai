"""Security tests: credential handling, SSRF, upload validation, sanitization."""
from __future__ import annotations

import pytest

from sentinelgraph.security import (
    SSRFError,
    mask_secret,
    redact_secrets,
    strip_unsafe_html,
    validate_provider_url,
)

# NOTE: the `app_env` fixture reloads sentinelgraph modules for isolation, which
# would make the module-level import above a *different class object* than the
# one raised at runtime. The tests that use `app_env` therefore re-import the
# exception lazily via `security_module()` instead of relying on identity.


def security_module():
    import importlib
    import sys
    mod = sys.modules.get("sentinelgraph.security")
    return mod if mod is not None else importlib.import_module("sentinelgraph.security")


# --------------------------------------------------------------------------
# Credential masking / redaction
# --------------------------------------------------------------------------

def test_mask_secret_never_reveals_full_value():
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    masked = mask_secret(secret)
    assert masked != secret
    assert secret not in masked
    assert masked.startswith("sk-p")
    assert masked.endswith("3456")


def test_mask_short_secret_fully_hidden():
    assert set(mask_secret("abc123")) == {"*"}


def test_mask_empty():
    assert mask_secret(None) == ""
    assert mask_secret("") == ""


@pytest.mark.parametrize("text", [
    "Error with key sk-proj-abcdef1234567890abcdef",
    "Authorization: Bearer sk-ant-api03-AAAAAAAAAAAAAAAA",
    "google key AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
    "api_key=supersecretvalue123",
])
def test_redact_secrets_removes_credentials(text):
    out = redact_secrets(text)
    assert "REDACTED" in out
    for token in ("sk-proj-abcdef1234567890abcdef", "sk-ant-api03-AAAAAAAAAAAAAAAA",
                  "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ123456", "supersecretvalue123"):
        assert token not in out


def test_redact_preserves_ordinary_text():
    text = "Host WS-FIN-07 connected to 203.0.113.66 at 08:21 UTC."
    assert redact_secrets(text) == text


# --------------------------------------------------------------------------
# SSRF protection
# --------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://127.0.0.1:8080/v1",                    # IPv4 localhost
    "http://10.0.0.5/v1",                          # private
    "http://192.168.1.10/v1",                      # private
    "http://172.16.0.1/v1",                        # private
    "http://0.0.0.0/v1",                           # unspecified
    "http://[::1]/v1",                             # IPv6 localhost
    "http://[fe80::1]/v1",                         # IPv6 link-local
    "http://[fc00::1]/v1",                         # IPv6 unique-local
    # --- the reported bypass: IPv4-mapped IPv6 ------------------------------
    "http://[::ffff:127.0.0.1]:8088/v1",           # mapped localhost
    "http://[::ffff:10.0.0.5]/v1",                 # mapped private
    "http://[::ffff:169.254.169.254]/v1",          # mapped metadata
    # --- other IPv6 transition formats that embed an IPv4 address -----------
    "http://[2002:7f00:1::]/v1",                   # 6to4 -> 127.0.0.1
    "http://[2002:a9fe:a9fe::]/v1",                # 6to4 -> 169.254.169.254
])
def test_ssrf_blocks_internal_addresses(url):
    with pytest.raises(SSRFError):
        validate_provider_url(url, "custom_openai")
    with pytest.raises(SSRFError):
        validate_provider_url(url, "custom_openai", allow_private=True)


def test_ssrf_blocks_address_normalisation_is_not_string_matching():
    """A mapped address must be recognised by value, not by how it is spelled."""
    from sentinelgraph import security
    import ipaddress
    assert security._is_blocked_address(ipaddress.ip_address("::ffff:127.0.0.1")) is True
    assert security._is_blocked_address(ipaddress.ip_address("::ffff:8.8.8.8")) is False
    assert security._is_blocked_address(ipaddress.ip_address("::ffff:10.0.0.1")) is True


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/",
    "gopher://example.com/",
    "javascript:alert(1)",
])
def test_ssrf_blocks_non_http_schemes(url):
    with pytest.raises(SSRFError):
        validate_provider_url(url, "custom_openai")


def test_ssrf_blocks_embedded_credentials():
    with pytest.raises(SSRFError):
        validate_provider_url("https://user:pass@api.example.com/v1", "custom_openai")


def test_ssrf_allows_public_https(monkeypatch):
    """The guard must not be blanket-deny, checked without live DNS.

    The original test resolved api.openai.com at run time, so it failed offline
    and could not be reproduced deterministically. Mocking the resolver keeps
    the same assertion with no network dependency.
    """
    from sentinelgraph import security
    monkeypatch.setattr(security, "_resolve_host", lambda host: ["104.18.6.192"])
    url = validate_provider_url("https://api.openai.com/v1", "openai")
    assert url == "https://api.openai.com/v1"


def test_ssrf_fails_closed_when_host_does_not_resolve(monkeypatch):
    from sentinelgraph import security
    monkeypatch.setattr(security, "_resolve_host", lambda host: [])
    with pytest.raises(SSRFError):
        validate_provider_url("https://no-such-host.invalid/v1", "custom_openai")


def test_ssrf_blocks_when_dns_returns_private_address(monkeypatch):
    """A public-looking name resolving to an internal address must be rejected."""
    from sentinelgraph import security
    monkeypatch.setattr(security, "_resolve_host", lambda host: ["10.0.0.7"])
    with pytest.raises(SSRFError):
        validate_provider_url("https://rebind.example/v1", "custom_openai")


def test_ssrf_blocks_when_dns_returns_mapped_private_address(monkeypatch):
    from sentinelgraph import security
    monkeypatch.setattr(security, "_resolve_host", lambda host: ["::ffff:169.254.169.254"])
    with pytest.raises(SSRFError):
        validate_provider_url("https://rebind.example/v1", "custom_openai")


def test_ssrf_dns_rebinding_pins_the_verified_address(monkeypatch):
    """After a host is validated to a public IP, a later re-resolution to an
    internal IP must not be used: the transport connects to the pinned one."""
    import httpx
    from sentinelgraph import security

    monkeypatch.setattr(security, "_resolve_host", lambda host: ["93.184.216.34"])
    url, pinned = security.validate_and_resolve("http://rebind.example/v1", "custom_openai")
    assert pinned == "93.184.216.34"

    # Attacker flips DNS to loopback between validation and connect.
    monkeypatch.setattr(security, "_resolve_host", lambda host: ["127.0.0.1"])

    captured: dict[str, str] = {}
    original = httpx.HTTPTransport.handle_request

    def fake(self, request):  # noqa: ANN001
        captured["url"] = str(request.url)
        captured["host"] = request.headers.get("host", "")
        raise httpx.ConnectError("stop here")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", fake)
    transport = security.PinnedHTTPTransport("rebind.example", pinned)
    with pytest.raises(httpx.ConnectError):
        transport.handle_request(httpx.Request("GET", "http://rebind.example/v1/models"))
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", original)

    assert captured["url"].startswith("http://93.184.216.34"), captured
    assert "127.0.0.1" not in captured["url"]
    assert captured["host"] == "rebind.example"


def test_ssrf_transport_refuses_host_change(monkeypatch):
    """If the request host is not the one we validated, refuse to connect."""
    import httpx
    from sentinelgraph import security
    req = httpx.Request("GET", "http://evil.example/v1")
    with pytest.raises(httpx.TransportError):
        security._rewrite_to_pinned(req, "rebind.example", "93.184.216.34")


def test_ssrf_pinned_client_does_not_follow_redirects(monkeypatch):
    import httpx
    from sentinelgraph import security
    monkeypatch.setattr(security, "_resolve_host", lambda host: ["93.184.216.34"])
    client = security.open_pinned_client("https://redirect.example/v1", "custom_openai")
    assert client.follow_redirects is False
    assert isinstance(client._transport, security.PinnedHTTPTransport)
    client.close()


def test_ssrf_allows_local_ollama_loopback():
    url = validate_provider_url("http://127.0.0.1:11434", "ollama", allow_private=True)
    assert url.endswith("11434")
    assert validate_provider_url("http://localhost:11434", "ollama", allow_private=True)


def test_ssrf_ollama_exception_is_loopback_only():
    # The intentional Ollama exception must not open a door to any private host.
    with pytest.raises(SSRFError):
        validate_provider_url("http://10.0.0.9:11434", "ollama", allow_private=True)
    with pytest.raises(SSRFError):
        validate_provider_url("http://192.168.1.50:11434", "ollama", allow_private=True)


def test_ssrf_still_blocks_loopback_for_non_local_provider():
    with pytest.raises(SSRFError):
        validate_provider_url("http://127.0.0.1:11434", "custom_openai")
    # allow_private only relaxes the guard for the local runtime, not others.
    with pytest.raises(SSRFError):
        validate_provider_url("http://127.0.0.1:11434", "custom_openai", allow_private=True)


# --------------------------------------------------------------------------
# HTML sanitization for reports
# --------------------------------------------------------------------------

def test_sanitizer_escapes_script_tag():
    out = strip_unsafe_html('<script>alert("x")</script>')
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_sanitizer_removes_event_handlers():
    out = strip_unsafe_html('<img src=x onerror=alert(1)>')
    assert "<img" not in out
    assert "onerror" in out  # content preserved as inert text
    assert out.startswith("&lt;")


def test_sanitizer_keeps_safe_structural_tags():
    out = strip_unsafe_html("<p>hello <strong>world</strong></p>")
    assert "<p>" in out and "<strong>" in out


def test_sanitizer_escapes_iframe():
    out = strip_unsafe_html('<iframe src="http://evil"></iframe>')
    assert "<iframe" not in out


# --------------------------------------------------------------------------
# Provider config API: secrets must never leave the server
# --------------------------------------------------------------------------

def test_provider_key_persisted_encrypted_without_env_master_key(client, app_env):
    """With no SG_MASTER_KEY a key is provisioned next to the DB, so saving works.

    The secret must still be encrypted at rest and must never be echoed back.
    """
    secret = "sk-should-never-be-stored-in-plaintext-3456"
    r = client.post("/api/ai/providers", json={
        "name": "test", "provider_type": "openai", "model_id": "gpt-4o-mini",
        "api_key": secret,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert secret not in r.text
    assert body["secret_source"] == "db"
    assert body["credential_configured"] is True
    assert secret not in (body.get("credential_hint") or "")

    import sqlite3

    conn = sqlite3.connect(app_env["db_path"])
    secret_enc, source = conn.execute(
        "SELECT secret_enc, secret_source FROM provider_configs").fetchone()
    conn.close()
    assert source == "db"
    assert secret_enc and secret_enc.startswith("gAAAAA")  # Fernet token
    assert secret not in secret_enc
    assert secret.encode() not in app_env["db_path"].read_bytes()


def test_provider_creation_refused_when_master_key_unavailable(client, monkeypatch):
    """Fail closed: with no usable key the secret is refused, never stored plaintext."""
    from sentinelgraph import provider_store

    monkeypatch.setattr(provider_store._cipher, "_fernet", None)
    r = client.post("/api/ai/providers", json={
        "name": "test", "provider_type": "openai", "model_id": "gpt-4o-mini",
        "api_key": "sk-should-not-be-stored-1234",
    })
    assert r.status_code == 400
    assert "master key" in r.json()["detail"].lower()


def test_provider_created_with_master_key_never_returns_secret(app_env, monkeypatch):
    from sentinelgraph import config, security

    monkeypatch.setenv("SG_MASTER_KEY", security.generate_master_key())
    config.get_settings.cache_clear()
    for mod in ("sentinelgraph.security", "sentinelgraph.provider_store"):
        import importlib
        importlib.reload(__import__(mod, fromlist=["x"]))

    from fastapi.testclient import TestClient
    from sentinelgraph.api import app
    with TestClient(app) as c:
        importlib.reload(__import__("sentinelgraph.provider_store", fromlist=["x"]))
        r = c.post("/api/ai/providers", json={
            "name": "openai-test", "provider_type": "openai",
            "model_id": "gpt-4o-mini", "api_key": "sk-verysecretvalue123456",
        })
        assert r.status_code == 200, r.text
        body = r.text
        assert "sk-verysecretvalue123456" not in body, "plaintext key leaked in response"
        cfg = r.json()
        assert cfg["credential_configured"] is True
        assert cfg["credential_hint"].startswith("sk-v")
        assert cfg["secret_source"] == "db"

        listed = c.get("/api/ai/providers").text
        assert "sk-verysecretvalue123456" not in listed


def test_unsupported_provider_type_rejected(client):
    r = client.post("/api/ai/providers", json={
        "name": "x", "provider_type": "definitely_not_real",
        "model_id": "m", "api_key": "k",
    })
    assert r.status_code == 422


def test_ssrf_blocked_at_provider_creation(client):
    r = client.post("/api/ai/providers", json={
        "name": "ssrf", "provider_type": "custom_openai",
        "model_id": "m", "base_url": "http://169.254.169.254/v1", "api_key": "k",
    })
    assert r.status_code == 400


# --------------------------------------------------------------------------
# Upload validation
# --------------------------------------------------------------------------

def test_upload_rejects_unsupported_extension(client, project_id):
    r = client.post("/api/ingest/file",
                    files={"file": ("payload.exe", b"MZ\x90\x00", "application/octet-stream")})
    assert r.status_code == 400
    assert "Unsupported file type" in r.json()["detail"]


def test_upload_rejects_empty_file(client, project_id):
    r = client.post("/api/ingest/file", files={"file": ("empty.json", b"", "application/json")})
    assert r.status_code == 400


def test_upload_rejects_binary_garbage(client, project_id):
    r = client.post("/api/ingest/file",
                    files={"file": ("data.csv", bytes(range(256)) * 4, "text/csv")})
    assert r.status_code == 400


def test_upload_path_traversal_name_is_neutralised(client, project_id, app_env):
    payload = b'[{"timestamp":"2026-11-03T08:00:00Z","host":"H1"}]'
    r = client.post("/api/ingest/file",
                    files={"file": ("../../evil.json", payload, "application/json")})
    assert r.status_code == 200
    artifacts = client.get("/api/artifacts").json()["artifacts"]
    assert artifacts
    assert all(".." not in (a["name"] or "") for a in artifacts)
    # nothing was written outside the artifact dir
    assert not (app_env["artifact_dir"].parent / "evil.json").exists()


def test_upload_oversized_rejected(client, monkeypatch):
    from sentinelgraph import api as api_mod
    monkeypatch.setattr(api_mod.settings, "max_upload_bytes", 100)
    r = client.post("/api/ingest/file",
                    files={"file": ("big.json", b"[" + b"{}," * 200 + b"{}]",
                                    "application/json")})
    assert r.status_code == 413
