"""Configuration loading for SentinelGraph AI.

Secrets are read from environment / .env only. Nothing here is ever
serialized to API responses or written to logs.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no external dependency).

    Existing environment variables always win, so an operator can override
    anything without editing the file.
    """
    if not path.is_file():
        return
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


class Settings:
    """Runtime settings. Deliberately plain so it is easy to audit."""

    def __init__(self) -> None:
        _load_dotenv(PROJECT_ROOT / ".env")

        self.host: str = os.environ.get("SG_HOST", "127.0.0.1")
        self.port: int = int(os.environ.get("SG_PORT", "8088"))
        self.debug: bool = os.environ.get("SG_DEBUG", "false").lower() == "true"

        # Shared-secret bearer token. Empty => the bearer path is off, and the
        # login gate is the only thing standing between a caller and the data.
        self.auth_token: str = os.environ.get("SG_AUTH_TOKEN", "").strip()

        # How long a login session stays valid. Short enough that a forgotten
        # browser tab does not stay authenticated for a week.
        self.session_ttl_hours: int = int(
            os.environ.get("SG_SESSION_TTL_HOURS", "12")
        )

        # Explicit opt-in for exposing the API off-host while the account still
        # carries the password printed in the README. Off by default: a demo can
        # set it, a real deployment should change the password instead.
        self.allow_default_password: bool = (
            os.environ.get("SG_ALLOW_DEFAULT_PASSWORD", "false").strip().lower()
            in {"1", "true", "yes", "on"}
        )

        origins = os.environ.get(
            "SG_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        )
        self.cors_origins: list[str] = [o.strip() for o in origins.split(",") if o.strip()]

        db_path = os.environ.get("SG_DB_PATH", "data/sentinelgraph.db")
        self.db_path: Path = self._resolve(db_path)
        self.artifact_dir: Path = self._resolve(
            os.environ.get("SG_ARTIFACT_DIR", "data/artifacts")
        )
        self.max_upload_bytes: int = int(
            os.environ.get("SG_MAX_UPLOAD_BYTES", str(32 * 1024 * 1024))
        )
        # Hard cap on the *whole* HTTP request body, enforced at the ASGI layer
        # before any parser runs. It allows for multipart boundaries and JSON
        # framing on top of the payload limit, so a file of exactly
        # SG_MAX_UPLOAD_BYTES is still accepted. Defaults to payload + 64 KiB.
        self.max_request_bytes: int = int(
            os.environ.get("SG_MAX_REQUEST_BYTES", "").strip()
            or (self.max_upload_bytes + 64 * 1024)
        )

        # Master key for encrypting provider secrets at rest.
        # Precedence: SG_MASTER_KEY (env/.env) -> key file in the data dir,
        # auto-provisioned on first use -> persistence disabled.
        self.master_key: str = os.environ.get("SG_MASTER_KEY", "").strip()
        key_file = os.environ.get("SG_MASTER_KEY_FILE", "").strip()
        self.master_key_file: Path = (
            self._resolve(key_file) if key_file else (self.db_path.parent / "master.key")
        )

        self.static_dir: Path = PROJECT_ROOT / "frontend" / "dist"

    @staticmethod
    def _resolve(value: str) -> Path:
        p = Path(value)
        return p if p.is_absolute() else (PROJECT_ROOT / p)

    def ensure_dirs(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s


def env_provider_keys() -> dict[str, str]:
    """Provider API keys from environment. Never log the values."""
    mapping = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
    }
    out: dict[str, str] = {}
    for provider, var in mapping.items():
        val = os.environ.get(var, "").strip()
        if val:
            out[provider] = val
    return out


# --------------------------------------------------------------------------
# Deployment safety: localhost-only by default
# --------------------------------------------------------------------------

_LOOPBACK_NAMES = {"127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1"}


def is_loopback_host(host: str | None) -> bool:
    """True when ``host`` binds only to the local machine."""
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h in _LOOPBACK_NAMES:
        return True
    try:
        import ipaddress

        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def enforce_secure_binding(
    host: str | None,
    auth_token: str | None,
    *,
    user_auth_available: bool = False,
    default_password_in_use: bool = False,
    allow_default_password: bool = False,
) -> None:
    """Refuse to expose the API on a non-loopback interface without real auth.

    SentinelGraph has no multi-user auth model: it is a single-analyst tool.
    Binding it to a routable interface with no authentication would publish the
    analyst's full investigation database to the network. CORS is not
    authentication and is deliberately not accepted as a substitute.

    Two things count as authentication: the shared bearer token, and the single
    analyst account. But an account still using the password printed in the
    README is not a credential anyone has to guess, so exposing that off-host is
    refused too, unless the operator says so explicitly with
    ``SG_ALLOW_DEFAULT_PASSWORD``. That keeps the default safe while leaving the
    deliberate demo deployment one documented flag away.
    """
    if is_loopback_host(host):
        return
    if (auth_token or "").strip():
        return
    if not user_auth_available:
        raise RuntimeError(
            f"Refusing to bind SentinelGraph to non-loopback host '{host}' without "
            "authentication.\n"
            "The API defaults to localhost-only. To expose it on the network you must "
            "set SG_AUTH_TOKEN; every /api request will then require "
            "'Authorization: Bearer ***'. CORS is NOT authentication.\n"
            "  Windows : set SG_AUTH_TOKEN=<long-random-value>\n"
            "  Linux   : export SG_AUTH_TOKEN=<long-random-value>\n"
            f"Then: python -m sentinelgraph serve --host {host}"
        )
    if default_password_in_use and not allow_default_password:
        raise RuntimeError(
            f"Refusing to bind SentinelGraph to non-loopback host '{host}' while the "
            "account still uses the shipped default password.\n"
            "'admin' / 'admin123' is published in the README, so it is not a secret and\n"
            "anyone who can reach this port could read the investigation database.\n"
            "Pick one:\n"
            "  1. change the password in the app (Account menu), then restart; or\n"
            "  2. set SG_AUTH_TOKEN=<long-random-value> and use the shared bearer token; or\n"
            "  3. set SG_ALLOW_DEFAULT_PASSWORD=1 to expose it anyway (deliberate demos).\n"
            f"Then: python -m sentinelgraph serve --host {host}"
        )


def warn_on_weak_exposure(
    host: str | None,
    auth_token: str | None,
    default_password_in_use: bool,
) -> str | None:
    """Return a warning when the API is exposed behind the shipped password.

    Not a refusal: the operator may have opted in with SG_ALLOW_DEFAULT_PASSWORD.
    But anyone on that network can log in with a credential printed in the
    README, so it must not happen quietly.
    """
    if is_loopback_host(host):
        return None
    if (auth_token or "").strip():
        return None
    if not default_password_in_use:
        return None
    return (
        f"WARNING: binding to '{host}' with the default password still active.\n"
        "  Anyone who can reach this port can log in as admin / admin123.\n"
        "  Change it in the app (Account menu) or set SG_AUTH_TOKEN.\n"
    )
