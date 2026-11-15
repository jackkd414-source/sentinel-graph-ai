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
import os
import re
import socket
import ssl
from urllib.parse import urlparse

import httpcore
import httpx
from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings

# --------------------------------------------------------------------------
# Credential encryption
# --------------------------------------------------------------------------


class CredentialCipher:
    """Fernet (AES-128-CBC + HMAC-SHA256) wrapper for provider secrets.

    Key resolution order:

      1. ``SG_MASTER_KEY`` (env / .env) - explicit and recommended.
      2. ``<data dir>/master.key`` - created owner-only on first use.

    Auto-provisioning exists so saving an API key works on a fresh install
    without hand-editing .env. Secrets are still encrypted before they touch
    the database and are never returned to the browser; there is no plaintext
    fallback. Point ``SG_MASTER_KEY_FILE`` elsewhere to relocate the key.
    """

    def __init__(self) -> None:
        self._fernet: Fernet | None = None
        self.key_source: str = "none"
        self.key_path: str | None = None
        key = self._resolve_key()
        if key:
            try:
                self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
            except Exception:
                self._fernet = None
                self.key_source = "invalid"

    def _resolve_key(self) -> str:
        settings = get_settings()
        env_key = (settings.master_key or "").strip()
        if env_key:
            self.key_source = "env"
            return env_key

        path = settings.master_key_file
        self.key_path = str(path)
        try:
            if path.is_file():
                stored = path.read_text(encoding="utf-8").strip()
                if stored:
                    self.key_source = "file"
                    return stored
            path.parent.mkdir(parents=True, exist_ok=True)
            generated = generate_master_key()
            path.write_text(generated + "\n", encoding="utf-8")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            self.key_source = "generated"
            return generated
        except OSError:
            # Unwritable location: fall back to env-var-only credentials.
            self.key_path = None
            return ""

    @property
    def available(self) -> bool:
        return self._fernet is not None

    def storage_info(self) -> dict[str, Any]:
        """Describe where the key comes from. Never returns the key itself."""
        return {"available": self.available, "source": self.key_source,
                "path": self.key_path}

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
#
# Controls, in order of importance:
#   1. Fail closed on an unresolvable host. An empty resolution list used to
#      mean the validation loop never ran, so the URL was accepted unchecked.
#   2. Normalise every address before testing it. IPv4-mapped IPv6
#      (::ffff:127.0.0.1) and the IPv6 transition formats (6to4, Teredo) embed
#      an IPv4 address that naive string / subnet checks do not see.
#   3. Reject anything that is not globally routable: private, loopback,
#      link-local, reserved, unspecified and multicast.
#   4. PIN the connection to the address we validated, so a second resolution
#      between validation and connect (DNS rebinding) cannot redirect the
#      socket to an internal host.
#   5. Never follow redirects to a destination we did not validate.

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
# because Ollama is a first-class supported provider. The exception is limited
# to the Ollama provider type AND a literally loopback host; nothing else may
# reach a private address.
LOCAL_PROVIDER_HOSTS = {"ollama"}
LOCAL_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


class SSRFError(ValueError):
    pass


# --- IPv6 transition mechanisms -------------------------------------------
# Each of these embeds an IPv4 destination inside an IPv6 address, which is a
# well-known way to sneak 127.0.0.1 / 10.x / 169.254.169.254 past a check that
# only inspects the IPv6 address itself. A public AI provider never legitimately
# answers on a NAT64/6to4/Teredo prefix, so the prefixes are refused outright
# and any embedded IPv4 address is validated as well (defence in depth).
NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")
SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
TEREDO = ipaddress.ip_network("2001::/32")
TRANSITION_NETWORKS = (NAT64_WELL_KNOWN, NAT64_LOCAL_USE, SIX_TO_FOUR, TEREDO)


def _embedded_ipv4_addresses(addr: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """Return every IPv4 destination embedded in an IPv6 transition address."""
    out: list[ipaddress.IPv4Address] = []
    if addr.ipv4_mapped is not None:
        out.append(addr.ipv4_mapped)
    raw = addr.packed
    if addr in NAT64_WELL_KNOWN or addr in NAT64_LOCAL_USE:
        out.append(ipaddress.IPv4Address(raw[12:16]))
    elif addr in SIX_TO_FOUR:
        out.append(ipaddress.IPv4Address(raw[2:6]))
    elif addr in TEREDO:
        # Teredo carries the server IPv4 verbatim and the client IPv4
        # bit-inverted (matches ipaddress.IPv6Address.teredo). Both are
        # validated: a private server with a public client must not pass.
        out.append(ipaddress.IPv4Address(raw[4:8]))
        out.append(ipaddress.IPv4Address(bytes(255 - b for b in raw[12:16])))
    return out


def _normalise_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address):
    """Unwrap addresses that embed an IPv4 address inside an IPv6 one.

    ``::ffff:127.0.0.1`` is an ``IPv6Address`` object, so ``addr in
    127.0.0.0/8`` is False and the classic bypass reaches loopback and the
    cloud metadata endpoint. NAT64, 6to4 and Teredo hide an IPv4 address the
    same way; every embedded address is returned so all of them get checked.
    """
    if not isinstance(addr, ipaddress.IPv6Address):
        return [addr]
    embedded = _embedded_ipv4_addresses(addr)
    return embedded or [addr]


def _is_blocked_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # Refuse IPv6 transition prefixes outright. A public AI provider has no
    # legitimate reason to live behind NAT64/6to4/Teredo, and each one embeds an
    # IPv4 destination that an IPv6-only check would miss (e.g.
    # 64:ff9b::a9fe:a9fe encodes 169.254.169.254).
    if isinstance(addr, ipaddress.IPv6Address):
        for net in TRANSITION_NETWORKS:
            if addr in net:
                return True
    # is_global covers private, loopback, link-local, reserved, unspecified,
    # multicast and the IANA special-purpose registries. Every embedded IPv4
    # address must pass too: a Teredo address can carry a private server and a
    # public client, and only checking the client would let it through.
    for candidate in _normalise_address(addr):
        if not candidate.is_global:
            return True
        for net in BLOCKED_NETWORKS:
            if candidate in net:
                return True
    return False


def _is_loopback_host(host: str) -> bool:
    h = host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h in LOCAL_ALLOWED_HOSTS:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _local_exception(host: str, provider_type: str, allow_private: bool) -> bool:
    return bool(
        allow_private
        and provider_type in LOCAL_PROVIDER_HOSTS
        and _is_loopback_host(host)
    )


def validate_and_resolve(
    url: str,
    provider_type: str,
    allow_private: bool = False,
) -> tuple[str, str]:
    """Validate a provider base URL and return ``(normalized_url, connect_host)``.

    ``connect_host`` is the exact literal the caller must connect to. For
    ordinary providers it is a validated, globally-routable IP address; for the
    allowed local runtime it is the loopback host itself.
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
    if _local_exception(host, provider_type, allow_private):
        return url, host

    resolved = _resolve_host(host)
    if not resolved:
        # Fail CLOSED: if we cannot resolve the host we cannot prove it is safe.
        raise SSRFError(
            "Base URL hostname could not be resolved; refusing to send the request."
        )

    verified: list[str] = []
    for label in resolved:
        try:
            addr = ipaddress.ip_address(label.strip().strip("[]"))
        except ValueError:
            continue
        if _is_blocked_address(addr):
            raise SSRFError(
                "Base URL resolves to a private, loopback, link-local, reserved or "
                "otherwise non-public address, which is blocked to prevent SSRF."
            )
        # Pin the literal that was actually checked. Transition addresses are
        # already refused above, so this is always the address we will connect
        # to, not a re-resolution of the hostname.
        verified.append(str(addr))
    if not verified:
        raise SSRFError("Base URL hostname did not resolve to a usable address.")
    return url, verified[0]


def validate_provider_url(
    url: str,
    provider_type: str,
    allow_private: bool = False,
) -> str:
    """Validate a provider base URL before the backend makes any request.

    Returns the normalized URL or raises SSRFError with a safe message.
    """
    return validate_and_resolve(url, provider_type, allow_private)[0]


def _strip_brackets(host: str) -> str:
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h


def _rewrite_to_pinned(request: httpx.Request, host: str, ip: str) -> httpx.Request:
    """Point ``request`` at the validated ``ip`` while preserving Host + SNI.

    Raising here (rather than silently sending) is the DNS-rebinding guard: if
    the URL host no longer matches what we validated, we refuse.
    """
    if _strip_brackets(request.url.host) != _strip_brackets(host):
        raise httpx.TransportError(
            "request host changed after SSRF validation; refusing to connect "
            "(possible DNS rebinding)."
        )
    literal = f"[{ip}]" if ":" in ip else ip
    request.url = request.url.copy_with(host=literal)
    default_port = 443 if request.url.scheme == "https" else 80
    port = request.url.port
    request.headers["Host"] = host if port in (None, default_port) else f"{host}:{port}"
    extensions = dict(request.extensions)
    extensions["sni_hostname"] = host
    request.extensions = extensions
    return request


class PinnedHTTPTransport(httpx.HTTPTransport):
    """Transport that only ever opens a socket to a pre-validated address.

    Even if DNS is re-resolved between validation and connection, the socket
    still goes to the address that passed the SSRF check.
    """

    def __init__(self, host: str, ip: str, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._host = host
        self._ip = ip

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return super().handle_request(_rewrite_to_pinned(request, self._host, self._ip))


def open_pinned_client(
    url: str,
    provider_type: str,
    allow_private: bool = False,
    timeout: float = 60.0,
) -> httpx.Client:
    """Return an httpx client bound to the validated address of ``url``."""
    _, pinned = validate_and_resolve(url, provider_type, allow_private)
    host = urlparse(url).hostname or ""
    return httpx.Client(
        transport=PinnedHTTPTransport(host, pinned),
        timeout=timeout,
        follow_redirects=False,  # never chase a redirect we did not validate
    )


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
