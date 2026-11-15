"""Single-analyst authentication: one account, scrypt password, DB-backed sessions.

Design notes
------------
SentinelGraph is a single-analyst tool, so there is no user table with roles and
no multi-tenant concept. Exactly one account exists, created on first start with
the shipped default credential so a fresh install is usable immediately.

What is stored, and what is not:

  * The password is never stored. What is stored is ``scrypt(password, salt)``
    with a per-account random salt, so the same password produces a different
    digest on every install and two installs cannot be compared.
  * A session token is generated with ``secrets.token_urlsafe`` and only its
    SHA-256 reaches the database. A leaked database file does not hand over a
    usable session.
  * Every comparison goes through ``hmac.compare_digest``, so a wrong password
    costs the same as a right one whatever its length.
  * Nothing in this module returns a password, a hash, or a salt over the API.

The default credential is public knowledge. It exists so the product works on
first run; ``uses_default_password`` lets the UI and the startup banner say so
out loud rather than leaving the operator to remember.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import cursor, fetchone
from .timeutil import now_iso, parse_iso

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"

# scrypt parameters. n=2**14 with r=8 needs 128*n*r = 16 MiB, a deliberate cost:
# cheap enough for one interactive login, expensive enough to slow an offline
# dictionary attack against a stolen database file. maxmem is passed explicitly
# because OpenSSL's default cap sits only just above the requirement, and the
# call fails outright rather than silently weakening when it is exceeded.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024
_PARAMS = f"scrypt$n={_SCRYPT_N},r={_SCRYPT_R},p={_SCRYPT_P}"


class AuthError(ValueError):
    """Raised for a rejected credential or a refused password change."""


def _derive(password: str, salt: bytes) -> str:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
        p=_SCRYPT_P, dklen=_SCRYPT_DKLEN, maxmem=_SCRYPT_MAXMEM,
    ).hex()


def hash_password(password: str) -> tuple[str, str]:
    """Return ``(hash_hex, salt_hex)`` for a new password."""
    salt = secrets.token_bytes(16)
    return _derive(password, salt), salt.hex()


def verify_password(password: str, hash_hex: str, salt_hex: str) -> bool:
    """Constant-time password check. False on any malformed stored value."""
    if not hash_hex or not salt_hex:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(_derive(password, salt), hash_hex)


# --- the single account ----------------------------------------------------

def get_user(username: str | None = None) -> dict[str, Any] | None:
    """The account by name, or the only account when ``username`` is None."""
    if username:
        row = fetchone("SELECT * FROM app_users WHERE username=?", (username,))
    else:
        row = fetchone("SELECT * FROM app_users ORDER BY id LIMIT 1")
    return dict(row) if row else None


def ensure_default_user() -> dict[str, Any]:
    """Create the single account on first start. Idempotent."""
    existing = get_user()
    if existing:
        return existing
    hash_hex, salt_hex = hash_password(DEFAULT_PASSWORD)
    now = now_iso()
    with cursor() as cur:
        cur.execute(
            "INSERT INTO app_users (username,password_hash,salt,params,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?)",
            (DEFAULT_USERNAME, hash_hex, salt_hex, _PARAMS, now, now),
        )
    return get_user() or {}


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Return the account when the credential is correct, else None."""
    row = get_user(username)
    if not row:
        # Burn the same work as a real check. Without this, an unknown username
        # answers measurably faster than a wrong password and the response time
        # becomes a username oracle.
        _derive(password, secrets.token_bytes(16))
        return None
    if not verify_password(password, row["password_hash"], row["salt"]):
        return None
    return row


def uses_default_password() -> bool:
    """True while the shipped default credential is still in force."""
    row = get_user()
    if not row:
        return False
    return verify_password(DEFAULT_PASSWORD, row["password_hash"], row["salt"])


def change_password(username: str, current: str, new: str) -> None:
    """Replace the password after proving the current one. Ends all sessions."""
    if len(new) < 8:
        raise AuthError("Password baru minimal 8 karakter.")
    if new == current:
        raise AuthError("Password baru harus berbeda dari yang sekarang.")
    row = get_user(username)
    if not row or not verify_password(current, row["password_hash"], row["salt"]):
        raise AuthError("Password saat ini salah.")
    hash_hex, salt_hex = hash_password(new)
    with cursor() as cur:
        cur.execute(
            "UPDATE app_users SET password_hash=?,salt=?,params=?,updated_at=? WHERE id=?",
            (hash_hex, salt_hex, _PARAMS, now_iso(), row["id"]),
        )
    # A password change must invalidate anything issued under the old one,
    # otherwise a token stolen before the change keeps working after it.
    revoke_all_sessions(row["username"])


# --- sessions --------------------------------------------------------------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def create_session(username: str, ttl_hours: int) -> tuple[str, str]:
    """Issue a session token. Returns ``(token, expires_at)``."""
    token = secrets.token_urlsafe(32)
    expires_at = _iso(datetime.now(tz=timezone.utc) + timedelta(hours=max(1, ttl_hours)))
    now = now_iso()
    with cursor() as cur:
        cur.execute(
            "INSERT INTO auth_sessions (token_hash,username,created_at,expires_at,last_seen_at)"
            " VALUES (?,?,?,?,?)",
            (_hash_token(token), username, now, expires_at, now),
        )
    purge_expired()
    return token, expires_at


def validate_session(token: str | None) -> str | None:
    """Return the username behind a live session token, else None."""
    if not token:
        return None
    row = fetchone("SELECT * FROM auth_sessions WHERE token_hash=?",
                   (_hash_token(token),))
    if not row:
        return None
    stored = dict(row)
    expires = parse_iso(stored.get("expires_at"))
    if expires is None or expires <= datetime.now(tz=timezone.utc):
        revoke_session(token)
        return None
    with cursor() as cur:
        cur.execute("UPDATE auth_sessions SET last_seen_at=? WHERE token_hash=?",
                    (now_iso(), stored["token_hash"]))
    return stored["username"]


def revoke_session(token: str | None) -> None:
    if not token:
        return
    with cursor() as cur:
        cur.execute("DELETE FROM auth_sessions WHERE token_hash=?", (_hash_token(token),))


def revoke_all_sessions(username: str | None = None) -> int:
    with cursor() as cur:
        if username:
            cur.execute("DELETE FROM auth_sessions WHERE username=?", (username,))
        else:
            cur.execute("DELETE FROM auth_sessions")
        return cur.rowcount


def purge_expired() -> int:
    with cursor() as cur:
        cur.execute("DELETE FROM auth_sessions WHERE expires_at<=?", (now_iso(),))
        return cur.rowcount


def session_count() -> int:
    row = fetchone("SELECT COUNT(*) AS n FROM auth_sessions")
    return int(row["n"]) if row else 0
