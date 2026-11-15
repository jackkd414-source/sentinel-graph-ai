"""SSRF hardening regressions: IPv6 transition mechanisms + real pinning.

Every test is deterministic and offline. Transition addresses are fed to the
validator through a mocked resolver, and the pinned-transport test talks only to
a localhost HTTP server this process starts itself. No request is ever made to
cloud metadata or any internal network.
"""
from __future__ import annotations

import http.server
import ipaddress
import threading

import httpx
import pytest

from sentinelgraph import security

# NOTE: test_security.py reloads sentinelgraph.security in one test, which
# replaces module attributes (including the SSRFError class object). Resolve
# both the error class and the validator through the module at call time so a
# reload cannot leave us holding a stale class that pytest.raises won't match.


# --------------------------------------------------------------------------
# IPv6 transition mechanisms (NAT64 / 6to4 / Teredo / IPv4-mapped)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("resolved,label", [
    ("64:ff9b::a9fe:a9fe", "NAT64 well-known -> 169.254.169.254"),
    ("64:ff9b::7f00:1", "NAT64 well-known -> 127.0.0.1"),
    ("64:ff9b::a00:1", "NAT64 well-known -> 10.0.0.1"),
    ("64:ff9b:1::a9fe:a9fe", "NAT64 local-use -> 169.254.169.254"),
    ("2002:a9fe:a9fe::1", "6to4 -> 169.254.169.254"),
    ("2002:0a00:0001::1", "6to4 -> 10.0.0.1"),
    ("::ffff:127.0.0.1", "IPv4-mapped -> loopback"),
    ("::ffff:169.254.169.254", "IPv4-mapped -> metadata"),
    ("2001:0:4136:e378:8000:63bf:3fff:fdd2", "Teredo (private server / public client)"),
])
def test_transition_mechanisms_are_blocked(monkeypatch, resolved, label):
    monkeypatch.setattr(security, "_resolve_host", lambda host: [resolved])
    with pytest.raises(security.SSRFError):
        security.validate_provider_url("https://transition.example/v1", "custom_openai")


def test_teredo_private_server_public_client_is_blocked():
    """A Teredo address can hide a private server behind a public client."""
    addr = ipaddress.ip_address("2001:0:0a00:0001:0000:0000:f7f7:f7f7")
    embedded = security._embedded_ipv4_addresses(addr)
    assert ipaddress.IPv4Address("10.0.0.1") in embedded
    assert security._is_blocked_address(addr) is True


def test_public_addresses_still_pass():
    for literal in ("93.184.216.34", "104.18.6.192", "2606:4700::1111"):
        assert security._is_blocked_address(ipaddress.ip_address(literal)) is False


def test_transition_prefixes_are_rejected_even_when_embedded_ip_is_public():
    """NAT64 wrapping a public IPv4 is still refused: no legitimate provider use."""
    addr = ipaddress.ip_address("64:ff9b::808:808")  # 8.8.8.8
    assert security._is_blocked_address(addr) is True


# --------------------------------------------------------------------------
# Pinned transport: prove it really sends a request to the validated socket
# --------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib API
        body = b"pinned-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence the test output
        return


@pytest.fixture()
def local_http_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_pinned_transport_completes_a_real_request(local_http_server):
    port = local_http_server
    client = security.open_pinned_client(
        f"http://127.0.0.1:{port}/", "ollama", allow_private=True, timeout=5,
    )
    try:
        r = client.get(f"http://127.0.0.1:{port}/v1/models")
        assert r.status_code == 200
        assert r.text == "pinned-ok"
    finally:
        client.close()


def test_pinned_transport_refuses_a_changed_host(local_http_server):
    """If the request host differs from the validated one, we must not connect."""
    transport = security.PinnedHTTPTransport("validated.example", "127.0.0.1")
    with pytest.raises(httpx.TransportError):
        transport.handle_request(httpx.Request("GET", "http://attacker.example/"))


def test_open_pinned_client_never_follows_redirects():
    client = security.open_pinned_client(
        "http://127.0.0.1:9/", "ollama", allow_private=True, timeout=1,
    )
    try:
        assert client.follow_redirects is False
    finally:
        client.close()