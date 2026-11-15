"""Request-body limit tests (Section 4).

The limit must apply before parsing, to both JSON and multipart, and a
chunked/streamed body (no Content-Length) must not be able to bypass it.
"""
from __future__ import annotations

import pytest


@pytest.fixture()
def small_limit(monkeypatch):
    from sentinelgraph import api as api_mod
    # Cap the ASGI request body directly; the payload limit stays at its default
    # so multipart framing does not interfere with what this file tests.
    monkeypatch.setattr(api_mod.settings, "max_request_bytes", 1024)
    return 1024


def test_json_body_over_limit_is_rejected(client, small_limit):
    body = {"text": "x" * 5000, "filename": "a.log", "source_type": "sysmon"}
    r = client.post("/api/ingest/text", json=body)
    assert r.status_code == 413, r.text
    assert "limit" in r.json()["detail"].lower()


def test_multipart_body_over_limit_is_rejected(client, small_limit):
    big = b"x" * 5000
    r = client.post("/api/ingest/file", files={"file": ("big.log", big, "text/plain")})
    assert r.status_code == 413, r.text


def test_chunked_body_cannot_bypass_the_limit():
    """No Content-Length: the streaming guard must abort mid-stream.

    Driven at the ASGI layer because Starlette's TestClient cannot stream a
    request body (it needs a declared length), which is exactly the case this
    guard exists for.
    """
    import asyncio

    from sentinelgraph.bodylimit import BodyLimitMiddleware

    consumed = {"bytes": 0, "completed": False}

    async def parser_app(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            consumed["bytes"] += len(message.get("body", b""))
            if not message.get("more_body", False):
                consumed["completed"] = True
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"parsed"})

    middleware = BodyLimitMiddleware(parser_app, max_bytes=1024)
    chunks = [b"x" * 200 for _ in range(60)]  # 12_000 bytes, no content-length

    async def run():
        sent = []
        queue = [
            {"type": "http.request", "body": c, "more_body": i < len(chunks) - 1}
            for i, c in enumerate(chunks)
        ]

        async def receive():
            return queue.pop(0)

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "method": "POST", "path": "/api/ingest/file",
                 "headers": [(b"content-type", b"application/octet-stream")]}
        await middleware(scope, receive, send)
        return sent

    sent = asyncio.run(run())
    assert sent[0]["status"] == 413, sent
    assert consumed["completed"] is False, "the parser finished despite the limit"
    assert consumed["bytes"] <= 1024 + 200, (
        f"parser consumed {consumed['bytes']} bytes before the guard stopped it"
    )


def test_normal_request_under_limit_still_works(client):
    """The limit must not break ordinary requests at the default size."""
    r = client.post("/api/ingest/text", json={
        "text": "ts,host\n2026-01-01T00:00:00Z,ws-fin-07\n",
        "filename": "small.csv",
        "source_type": "csv",
        "preview_only": True,
    })
    assert r.status_code == 200, r.text


def test_limit_is_read_at_request_time(app_env, monkeypatch):
    """Raising the limit must take effect without rebuilding the app."""
    from sentinelgraph import api as api_mod
    from fastapi.testclient import TestClient

    payload = {"text": "x" * 5000, "filename": "a.log", "source_type": "sysmon"}

    monkeypatch.setattr(api_mod.settings, "max_request_bytes", 1024)
    with TestClient(api_mod.app) as c:
        assert c.post("/api/ingest/text", json=payload).status_code == 413

    monkeypatch.setattr(api_mod.settings, "max_request_bytes", 65536)
    with TestClient(api_mod.app) as c:
        assert c.post("/api/ingest/text", json=payload).status_code != 413