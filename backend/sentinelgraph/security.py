"""Security primitives: credential encryption, masking, SSRF guards, sanitization.

Threat model for this module
---------------------------
SentinelGraph runs on the analyst's own machine. The realistic risks are:
  1. Provider API keys leaking via API responses, logs, or exports.
  2. Provider keys sitting in plaintext in the SQLite file.
  3. A malicious "custom OpenAI-compatible endpoint" being used to make the
     backend fetch internal/metadata addresses (SSRF).
  4. AI output or imported data being rendered as HTML and executing script.

Each risk has an explicit control here.
"""
from __future__ import annotations

import html
import ipaddress
import re
import socket
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings

# --------------------------------------------------------------------------
# Credential encryption
# --------------------------------------------------------------------------


class CredentialCipher:
    """Fernet (AES-128-CBC + HMAC-SHA256) wrapper for provider secrets.

    If SG_MASTER_KEY is not configured, persistence is disabled: callers must
    fall back to environment-variable credentials. We never silently store a
    key in plaintext.
    """

    def __init__(self) -> None:
        key = get_settings().master_key
        self._fernet: Fernet | None = None
        if key:
            try:
                self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
            except Exception:
                self._fernet = None

    @property
    def available(self) -> bool:
        return self._fernet is not None

    def encrypt(self, plaintext: str) -> str | None:
        if not self._fernet or not plaintext:
            return None
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str | None) -> str | None:
        if not self._fernet or not token:
            return None
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except (InvalidToken, ValueError):
            return None


def generate_master_key() -> str:
    return Fernet.generate_key().decode()


def mask_secret(value: str | None) -> str:
    """Render a credential in a way that is useful but not recoverable."""
    if not value:
        return ""
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return f"{v[:4]}{'*' * 8}{v[-4:]}"


_SECRET_PATTERNS = [
    re.compile(r"(sk-[A-Za-z0-9_\-]{8,})"),
    re.compile(r"(sk-ant-[A-Za-z0-9_\-]{8,})"),
    re.compile(r"(AIza[0-9A-Za-z_\-]{20,})"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)([^\s,;\"']{8,})"),
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([^\s\"']{8,})"),
]


def redact_secrets(text: str | None) -> str:
    """Remove anything that looks like a credential from free text.

    Applied to provider error messages before they are stored or returned.
    """
    if not text:
        return ""
    out = text
    for pat in _SECRET_PATTERNS:
        if pat.groups >= 2:
            out = pat.sub(lambda m: m.group(1) + "[REDACTED]", out)
        else:
            out = pat.sub("[REDACTED]", out)
    return out


# --------------------------------------------------------------------------
# SSRF guard for custom / third-party provider endpoints
# --------------------------------------------------------------------------

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local + cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Local model runtime is explicitly allowed when the operator opts in,
# because Ollama is a first-class supported provider.
LOCAL_PROVIDER_HOSTS = {"ollama", "custom-openai-local"}
LOCAL_ALLOWED = {
    ("127.0.0.1", 11434),
    ("localhost", 11434),
}


class SSRFError(ValueError):
    pass


def validate_provider_url(
    url: str,
    provider_type: str,
    allow_private: bool = False,
) -> str:
    """Validate a provider base URL before the backend makes any request.

    Returns the normalized URL or raises SSRFError with a safe message.
    """
    if not url:
        raise SSRFError("Base URL is required for this provider type.")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise SSRFError("Base URL must use http or https.")
    if not parsed.hostname:
        raise SSRFError("Base URL has no hostname.")
    if parsed.username or parsed.password:
        raise SSRFError("Base URL must not embed credentials.")

    host = parsed.hostname.lower()

    # Ollama on loopback is an intentional, documented exception.
    if provider_type in LOCAL_PROVIDER_HOSTS and allow_private:
        if (host, parsed.port or 80) in LOCAL_ALLOWED or host in ("127.0.0.1", "localhost"):
            return url

    for label in _resolve_host(host):
        try:
            addr = ipaddress.ip_address(label)
        except ValueError:
            continue
        for net in BLOCKED_NETWORKS:
            if addr in net:
                if allow_private and provider_type in LOCAL_PROVIDER_HOSTS:
                    break
                raise SSRFError(
                    "Base URL resolves to a private or link-local address, "
                    "which is blocked to prevent SSRF."
                )
    return url


def _resolve_host(host: str) -> list[str]:
    """Best-effort DNS resolution. Returns the literal host on failure."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    out = []
    for info in infos:
        addr = info[4][0]
        if addr not in out:
            out.append(addr)
    return out


# --------------------------------------------------------------------------
# Output sanitization
# --------------------------------------------------------------------------

_ALLOWED_TAGS = {
    "p", "br", "strong", "em", "b", "i", "u", "ul", "ol", "li",
    "h1", "h2", "h3", "h4", "h5", "h6", "table", "thead", "tbody", "tr",
    "th", "td", "code", "pre", "blockquote", "hr", "span", "div",
}
_TAG_RE = re.compile(r"<\s*(/?)\s*([a-zA-Z0-9]+)[^>]*>")


def strip_unsafe_html(text: str) -> str:
    """Escape everything except a conservative allowlist of structural tags.

    Reports are generated as HTML and opened in a browser; this keeps
    imported log content or model output from executing script.
    """
    if not text:
        return ""

    def repl(m: re.Match) -> str:
        closing, name = m.group(1), m.group(2).lower()
        if name in _ALLOWED_TAGS:
            return f"<{closing}{name}>"
        return html.escape(m.group(0))

    return _TAG_RE.sub(repl, text)


def escape_text(value: str | None) -> str:
    return html.escape(value or "")
