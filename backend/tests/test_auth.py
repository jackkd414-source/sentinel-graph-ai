"""Authentication + CORS tests for SG_AUTH_TOKEN deployments.

These exercise the middleware directly through TestClient. The token is
considered sensitive: no assertion here ever prints or compares it inside an
error message body.
"""
from __future__ import annotations

import pytest

TOKEN = "test-token-0123456789abcdef"


@pytest.fixture()
def auth_client(client, monkeypatch):
    """Client with SG_AUTH_TOKEN active."""
    from sentinelgraph import api as api_mod

    monkeypatch.setattr(api_mod.settings, "auth_token", TOKEN)
    return client


# --------------------------------------------------------------------------
# Token enforcement
# --------------------------------------------------------------------------

def test_health_is_unauthenticated(auth_client):
    r = auth_client.get("/api/health")
    assert r.status_code == 200


def test_sensitive_endpoint_without_token_is_401(auth_client):
    r = auth_client.get("/api/projects")
    assert r.status_code == 401
    assert r.json()["detail"] == "Unauthorized"


def test_wrong_token_is_401(auth_client):
    r = auth_client.get("/api/projects", headers={"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401


def test_correct_token_is_accepted(auth_client):
    r = auth_client.get("/api/projects", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text


def test_auth_disabled_by_default_allows_localhost(client):
    # No token configured => localhost single-analyst mode, no 401.
    assert client.get("/api/projects").status_code == 200


@pytest.mark.parametrize("method,path", [
    ("get", "/api/events"),
    ("get", "/api/incidents"),
    ("get", "/api/alerts"),
    ("get", "/api/graph"),
    ("get", "/api/ai/providers"),
    ("post", "/api/data/reset"),
    ("post", "/api/demo/load"),
])
def test_all_sensitive_routes_require_token(auth_client, method, path):
    fn = getattr(auth_client, method)
    r = fn(path)
    assert r.status_code == 401, f"{method.upper()} {path} leaked without a token"


def test_audit_log_requires_token(auth_client):
    assert auth_client.get("/api/audit").status_code == 401


# --------------------------------------------------------------------------
# CORS preflight
# --------------------------------------------------------------------------

PREFLIGHT_HEADERS = {
    "Origin": "http://localhost:5173",
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "authorization,content-type",
}


def test_preflight_is_not_blocked_by_auth(auth_client):
    """A browser preflight carries no Authorization header and must still pass."""
    r = auth_client.options("/api/demo/load", headers=PREFLIGHT_HEADERS)
    assert r.status_code == 200, f"preflight rejected: {r.status_code} {r.text}"


def test_preflight_advertises_authorization_header(auth_client):
    r = auth_client.options("/api/demo/load", headers=PREFLIGHT_HEADERS)
    allowed = r.headers.get("access-control-allow-headers", "").lower()
    assert "authorization" in allowed, f"allow-headers missing Authorization: {allowed!r}"


def test_preflight_allows_origin(auth_client):
    r = auth_client.options("/api/demo/load", headers=PREFLIGHT_HEADERS)
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_options_returns_no_data_body(auth_client):
    """OPTIONS must never be a data path: no JSON payload comes back."""
    r = auth_client.options("/api/events", headers=PREFLIGHT_HEADERS)
    assert r.status_code == 200
    body = r.content.strip()
    assert body in (b"", b"OK"), f"OPTIONS leaked a body: {body[:200]!r}"


def test_options_without_preflight_headers_cannot_read_data(auth_client):
    """A bare OPTIONS (no Origin) must not be treated as an authenticated GET."""
    r = auth_client.options("/api/events")
    assert r.status_code != 200 or r.content.strip() == b""