"""Authentication tests: the shared token, CORS preflight, and the analyst login.

Two credential models share one Authorization header, so they are tested
together:

  * ``SG_AUTH_TOKEN``, a shared secret for headless or scripted use;
  * a login session token from ``POST /api/auth/login``, for the browser.

These exercise the middleware directly through TestClient. Credentials are
considered sensitive: no assertion here prints or compares one inside an error
message body.
"""
from __future__ import annotations

import hashlib

import pytest

from sentinelgraph import auth
from sentinelgraph.db import cursor, fetchall, fetchone

TOKEN = "test-token-0123456789abcdef"
DEFAULT = {"username": "admin", "password": "admin123"}


@pytest.fixture()
def auth_client(client, monkeypatch):
    """Client with SG_AUTH_TOKEN active."""
    from sentinelgraph import api as api_mod

    monkeypatch.setattr(api_mod.settings, "auth_token", TOKEN)
    return client


def _login(client, username="admin", password="admin123"):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


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
    ("post", "/api/auth/password"),
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


# --------------------------------------------------------------------------
# The single analyst account
# --------------------------------------------------------------------------

def test_default_account_is_created(app_env):
    auth.ensure_default_user()
    user = auth.get_user()
    assert user is not None
    assert user["username"] == "admin"
    assert auth.authenticate(**DEFAULT) is not None
    assert auth.uses_default_password() is True


def test_ensure_default_user_is_idempotent(app_env):
    first = auth.ensure_default_user()
    second = auth.ensure_default_user()
    assert first["id"] == second["id"]
    assert fetchone("SELECT COUNT(*) AS n FROM app_users")["n"] == 1


def test_password_is_not_stored_in_readable_form(app_env):
    auth.ensure_default_user()
    row = dict(fetchone("SELECT * FROM app_users"))
    blob = " ".join(str(v) for v in row.values())
    assert "admin123" not in blob
    assert row["password_hash"] != "admin123"
    # scrypt output is 32 bytes, the salt 16; both are stored as hex.
    assert len(row["password_hash"]) == 64
    assert len(row["salt"]) == 32
    assert row["params"].startswith("scrypt$")


def test_same_password_hashes_differently_every_time(app_env):
    """A per-account salt, so two installs cannot be compared by digest."""
    first, salt_a = auth.hash_password("admin123")
    second, salt_b = auth.hash_password("admin123")
    assert salt_a != salt_b
    assert first != second
    assert auth.verify_password("admin123", first, salt_a) is True
    assert auth.verify_password("admin123", first, salt_b) is False


def test_authentication_rejects_wrong_credentials(app_env):
    auth.ensure_default_user()
    assert auth.authenticate("admin", "admin124") is None
    assert auth.authenticate("admin", "") is None
    assert auth.authenticate("nobody", "admin123") is None


def test_verify_password_survives_a_malformed_stored_value(app_env):
    assert auth.verify_password("x", "", "") is False
    assert auth.verify_password("x", "nothex", "nothex") is False


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------

def test_session_round_trip(app_env):
    auth.ensure_default_user()
    token, expires_at = auth.create_session("admin", 12)
    assert token and expires_at
    assert auth.validate_session(token) == "admin"
    auth.revoke_session(token)
    assert auth.validate_session(token) is None


def test_session_rejects_junk(app_env):
    auth.ensure_default_user()
    assert auth.validate_session(None) is None
    assert auth.validate_session("") is None
    assert auth.validate_session("not-a-real-token") is None


def test_only_the_token_hash_reaches_the_database(app_env):
    auth.ensure_default_user()
    token, _ = auth.create_session("admin", 12)
    stored = [r["token_hash"] for r in fetchall("SELECT token_hash FROM auth_sessions")]
    assert token not in stored
    assert hashlib.sha256(token.encode("utf-8")).hexdigest() in stored


def test_expired_session_is_rejected_and_cleaned_up(app_env):
    auth.ensure_default_user()
    token, _ = auth.create_session("admin", 12)
    with cursor() as cur:
        cur.execute(
            "UPDATE auth_sessions SET expires_at=? WHERE token_hash=?",
            ("2000-01-01T00:00:00.000Z", hashlib.sha256(token.encode("utf-8")).hexdigest()),
        )
    assert auth.validate_session(token) is None
    assert fetchone("SELECT COUNT(*) AS n FROM auth_sessions")["n"] == 0


# --------------------------------------------------------------------------
# Password change
# --------------------------------------------------------------------------

def test_password_change_requires_the_current_password(app_env):
    auth.ensure_default_user()
    with pytest.raises(auth.AuthError):
        auth.change_password("admin", "wrong-password", "a-new-password")
    with pytest.raises(auth.AuthError):
        auth.change_password("admin", "admin123", "short")
    with pytest.raises(auth.AuthError):
        auth.change_password("admin", "admin123", "admin123")


def test_password_change_ends_sessions_and_clears_the_default_flag(app_env):
    auth.ensure_default_user()
    token, _ = auth.create_session("admin", 12)

    auth.change_password("admin", "admin123", "a-new-password")

    # A token issued under the old password must not survive the change.
    assert auth.validate_session(token) is None
    assert auth.uses_default_password() is False
    assert auth.authenticate("admin", "a-new-password") is not None
    assert auth.authenticate("admin", "admin123") is None


# --------------------------------------------------------------------------
# Login over HTTP
# --------------------------------------------------------------------------

def test_login_returns_a_session_token(client):
    r = _login(client)
    assert r.status_code == 200
    body = r.json()
    assert body["token"]
    assert body["username"] == "admin"
    assert body["must_change_password"] is True
    # The response must never echo the password back.
    assert "admin123" not in r.text


def test_login_rejects_a_bad_password(client):
    assert _login(client, password="wrong").status_code == 401
    assert _login(client, username="nobody").status_code == 401


def test_login_requires_both_fields(client):
    assert client.post("/api/auth/login", json={"username": "admin"}).status_code == 422
    assert client.post("/api/auth/login", json={"username": "admin", "password": ""}).status_code == 422


def test_login_attempts_are_audited_without_the_password(client):
    _login(client, password="wrong")
    _login(client)
    actions = [r["action"] for r in fetchall("SELECT action FROM audit_log ORDER BY id")]
    assert "login_failed" in actions
    assert "login_ok" in actions
    blob = " ".join(str(v) for v in dict(fetchone("SELECT * FROM audit_log")).values())
    assert "admin123" not in blob


# --------------------------------------------------------------------------
# The gate with a login session
# --------------------------------------------------------------------------

def test_session_token_is_accepted_by_the_gate(auth_client):
    token = _login(auth_client).json()["token"]
    assert auth_client.get("/api/projects").status_code == 401
    assert auth_client.get("/api/projects", headers=_bearer(token)).status_code == 200


def test_me_reports_auth_not_required_on_loopback(client):
    """The local single-analyst default still needs no credential."""
    body = client.get("/api/auth/me").json()
    assert body["auth_required"] is False
    assert body["authenticated"] is False


def test_me_reports_the_session_to_an_authenticated_caller(auth_client):
    token = _login(auth_client).json()["token"]
    body = auth_client.get("/api/auth/me", headers=_bearer(token)).json()
    assert body["authenticated"] is True
    assert body["username"] == "admin"
    assert body["via"] == "session"
    assert body["must_change_password"] is True


def test_me_hides_the_default_password_state_from_a_stranger(auth_client):
    """Telling an anonymous caller that admin123 still works would be a gift."""
    body = auth_client.get("/api/auth/me").json()
    assert body["authenticated"] is False
    assert body["auth_required"] is True
    assert "must_change_password" not in body
    assert "username" not in body


def test_logout_revokes_the_session(auth_client):
    token = _login(auth_client).json()["token"]
    assert auth_client.post("/api/auth/logout", headers=_bearer(token)).status_code == 200
    assert auth_client.get("/api/projects", headers=_bearer(token)).status_code == 401


def test_logout_without_a_session_is_harmless(auth_client):
    """Clearing an already-expired credential must not report a failure."""
    assert auth_client.post("/api/auth/logout").status_code == 200


def test_password_change_endpoint_ends_the_session(auth_client):
    token = _login(auth_client).json()["token"]
    r = auth_client.post("/api/auth/password",
                         json={"current_password": "admin123", "new_password": "a-new-password"},
                         headers=_bearer(token))
    assert r.status_code == 200
    assert r.json()["reauth_required"] is True
    # The session that made the change is gone too.
    assert auth_client.get("/api/projects", headers=_bearer(token)).status_code == 401
    # The new password is the one that works now.
    assert _login(auth_client, password="a-new-password").status_code == 200
    assert _login(auth_client, password="admin123").status_code == 401


def test_password_change_endpoint_rejects_a_short_password(auth_client):
    token = _login(auth_client).json()["token"]
    r = auth_client.post("/api/auth/password",
                         json={"current_password": "admin123", "new_password": "short"},
                         headers=_bearer(token))
    assert r.status_code == 422
