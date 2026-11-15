"""SSRF redirect regression: a redirect must never be followed to an
unvalidated destination (localhost / private / cloud metadata).

Uses a controlled loopback HTTP server that answers 302. The Ollama loopback
exception is the intended, narrow way to reach a local server in tests, so no
request is ever sent to a sensitive address.
"""
from __future__ import annotations

import http.server
import socketserver
import threading

import pytest

from sentinelgraph import security as sec


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    hits = 0
    location = ""

    def do_GET(self):  # noqa: N802
        type(self).hits += 1
        self.send_response(302)
        self.send_header("Location", type(self).location)
        self.end_headers()

    def log_message(self, *args):  # silence test output
        pass


def _serve_redirect(location: str):
    _RedirectHandler.hits = 0
    _RedirectHandler.location = location
    srv = socketserver.TCPServer(("127.0.0.1", 0), _RedirectHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


@pytest.mark.parametrize("target", [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://127.0.0.1:8088/api/ai/providers",
    "http://10.0.0.5/internal",
])
def test_redirect_is_not_followed(target):
    srv, port = _serve_redirect(target)
    client = sec.open_pinned_client(f"http://127.0.0.1:{port}", "ollama", allow_private=True)
    try:
        resp = client.get(f"http://127.0.0.1:{port}/start")
        # 302 is surfaced to the caller; the client does not chase it.
        assert resp.status_code == 302
        assert resp.headers["location"] == target
        assert _RedirectHandler.hits == 1, "client followed the redirect"
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()


def test_pinned_client_disables_redirects():
    srv, port = _serve_redirect("http://127.0.0.1:1/")
    client = sec.open_pinned_client(f"http://127.0.0.1:{port}", "ollama", allow_private=True)
    try:
        assert client.follow_redirects is False
    finally:
        client.close()
        srv.shutdown()
        srv.server_close()
