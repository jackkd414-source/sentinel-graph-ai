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

        # Shared-secret bearer token. Empty => no authentication, which is only
        # ever acceptable while bound to loopback (see enforce_secure_binding).
        self.auth_token: str = os.environ.get("SG_AUTH_TOKEN", "").strip()

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


def enforce_secure_binding(host: str | None, auth_token: str | None) -> None:
    """Refuse to expose the API on a non-loopback interface without auth.

    SentinelGraph has no multi-user auth model: it is a single-analyst tool.
    Binding it to a routable interface with no authentication would publish the
    analyst's full investigation database to the network. CORS is not
    authentication and is deliberately not accepted as a substitute.
    """
    if is_loopback_host(host):
        return
    if (auth_token or "").strip():
        return
    raise RuntimeError(
        f"Refusing to bind SentinelGraph to non-loopback host '{host}' without "
        "authentication.\n"
        "The API defaults to localhost-only. To expose it on the network you must "
        "set SG_AUTH_TOKEN; every /api request will then require "
        "'Authorization: Bearer <token>'. CORS is NOT authentication.\n"
        "  Windows : set SG_AUTH_TOKEN=<long-random-value>\n"
        "  Linux   : export SG_AUTH_TOKEN=<long-random-value>\n"
        f"Then: python -m sentinelgraph serve --host {host}"
    )
