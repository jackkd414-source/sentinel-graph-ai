"""Deployment-safety regression tests.

SentinelGraph has no multi-user auth: it is a single-analyst tool. The fix
under test is that it must not be possible to expose an unauthenticated API on
a routable interface, and that enabling SG_AUTH_TOKEN actually protects /api.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from sentinelgraph.config import enforce_secure_binding, is_loopback_host

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------
# Loopback detection + binding guard
# --------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "[::1]", "0:0:0:0:0:0:0:1"])
def test_loopback_hosts_recognised(host):
    assert is_loopback_host(host) is True


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "10.0.0.1", "203.0.113.9", ""])
def test_non_loopback_hosts_not_recognised(host):
    assert is_loopback_host(host) is False


def test_binding_allows_loopback_without_auth():
    enforce_secure_binding("127.0.0.1", None)
    enforce_secure_binding("localhost", "")


def test_binding_refuses_routable_host_without_auth():
    for host in ("0.0.0.0", "192.168.1.5", "203.0.113.9"):
        with pytest.raises(RuntimeError) as exc:
            enforce_secure_binding(host, "")
        assert "SG_AUTH_TOKEN" in str(exc.value)
        assert "CORS is NOT authentication" in str(exc.value)


def test_binding_allows_routable_host_with_auth():
    enforce_secure_binding("0.0.0.0", "a-long-shared-secret")


def test_cli_serve_refuses_external_bind_without_token():
    """End-to-end: `python -m sentinelgraph serve --host 0.0.0.0` must abort."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "backend")
    env.pop("SG_AUTH_TOKEN", None)
    env["SG_HOST"] = "0.0.0.0"
    proc = subprocess.run(
        [sys.executable, "-m", "sentinelgraph", "serve", "--host", "0.0.0.0"],
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode != 0
    assert "SG_AUTH_TOKEN" in (proc.stderr + proc.stdout)


# --------------------------------------------------------------------------
# Auth middleware behaviour
# --------------------------------------------------------------------------

def test_api_open_without_token_by_default(client, monkeypatch):
    from sentinelgraph import api as api_mod
    monkeypatch.setattr(api_mod.settings, "auth_token", "")
    assert client.get("/api/projects").status_code == 200


def test_api_requires_bearer_token_when_configured(client, monkeypatch):
    from sentinelgraph import api as api_mod
    monkeypatch.setattr(api_mod.settings, "auth_token", "s3cret-token")

    assert client.get("/api/projects").status_code == 401
    assert client.get("/api/projects", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/projects", headers={"Authorization": "s3cret-token"}).status_code == 401

    ok = client.get("/api/projects", headers={"Authorization": "Bearer s3cret-token"})
    assert ok.status_code == 200


def test_health_is_exempt_from_auth(client, monkeypatch):
    from sentinelgraph import api as api_mod
    monkeypatch.setattr(api_mod.settings, "auth_token", "s3cret-token")
    assert client.get("/api/health").status_code == 200


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/events"),
    ("GET", "/api/alerts"),
    ("GET", "/api/graph"),
    ("GET", "/api/audit"),
    ("GET", "/api/artifacts"),
    ("GET", "/api/ai/providers"),
    ("GET", "/api/ai/status"),
    ("POST", "/api/data/reset"),
    ("POST", "/api/ingest/file"),
    ("POST", "/api/demo/load"),
    ("POST", "/api/ai/providers"),
    ("GET", "/api/incidents/1/report"),
    ("POST", "/api/incidents/1/report"),
])
def test_sensitive_endpoints_require_token(client, monkeypatch, method, path):
    from sentinelgraph import api as api_mod
    monkeypatch.setattr(api_mod.settings, "auth_token", "s3cret-token")
    kwargs = {"json": {}} if method == "POST" else {}
    r = client.request(method, path, **kwargs)
    assert r.status_code == 401, f"{method} {path} -> {r.status_code}"


def test_authenticated_read_paths_work(client, monkeypatch):
    from sentinelgraph import api as api_mod
    monkeypatch.setattr(api_mod.settings, "auth_token", "s3cret-token")
    h = {"Authorization": "Bearer s3cret-token"}
    for path in ("/api/events", "/api/audit", "/api/artifacts", "/api/ai/providers"):
        assert client.get(path, headers=h).status_code == 200, path


def test_wrong_scheme_is_rejected(client, monkeypatch):
    from sentinelgraph import api as api_mod
    monkeypatch.setattr(api_mod.settings, "auth_token", "s3cret-token")
    assert client.get("/api/events", headers={"Authorization": "Token s3cret-token"}).status_code == 401
