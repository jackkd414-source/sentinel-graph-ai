"""Regression tests for the bounded-chunked upload path.

The original ``/api/ingest/file`` handler called ``await file.read()`` and only
checked the size afterwards, so an oversized upload was fully buffered in memory
before it was rejected. These tests pin the corrected behaviour:

  * a file exactly at the limit is accepted,
  * a file one byte over the limit is rejected with 413,
  * a rejected upload leaves no artifact and no event behind,
  * the reader stops as soon as the limit is crossed (it does not read to EOF),
  * ``/api/ingest/text`` is bounded too.
"""
from __future__ import annotations

import asyncio

import pytest


def test_upload_at_exact_limit_is_accepted(client, project_id, monkeypatch):
    from sentinelgraph import api as api_mod

    payload = b'[{"timestamp":"2026-11-03T08:00:00Z","host":"H1"}]'
    monkeypatch.setattr(api_mod.settings, "max_upload_bytes", len(payload))
    r = client.post("/api/ingest/file",
                    files={"file": ("exact.json", payload, "application/json")})
    assert r.status_code == 200, r.text


def test_upload_one_byte_over_limit_is_rejected(client, project_id, monkeypatch):
    from sentinelgraph import api as api_mod

    payload = b'[{"timestamp":"2026-11-03T08:00:00Z","host":"H1"}]'
    monkeypatch.setattr(api_mod.settings, "max_upload_bytes", len(payload) - 1)
    r = client.post("/api/ingest/file",
                    files={"file": ("over.json", payload, "application/json")})
    assert r.status_code == 413


def test_rejected_upload_leaves_no_artifact_or_event(client, project_id, monkeypatch):
    from sentinelgraph import api as api_mod

    monkeypatch.setattr(api_mod.settings, "max_upload_bytes", 50)
    before_artifacts = len(client.get("/api/artifacts").json()["artifacts"])
    before_events = client.get("/api/health").json()["counts"]["events"]

    big = b"[" + (b"{}, " * 200) + b"{}]"
    r = client.post("/api/ingest/file",
                    files={"file": ("big.json", big, "application/json")})
    assert r.status_code == 413

    assert len(client.get("/api/artifacts").json()["artifacts"]) == before_artifacts
    assert client.get("/api/health").json()["counts"]["events"] == before_events


def test_bounded_reader_stops_before_buffering_the_whole_body():
    """The reader must abort on the chunk that crosses the limit, not at EOF."""
    from fastapi import HTTPException

    from sentinelgraph import api as api_mod

    class FakeUpload:
        def __init__(self, chunks):
            self._chunks = list(chunks)
            self.reads = 0
            self.closed = False

        async def read(self, _n):
            self.reads += 1
            return self._chunks.pop(0) if self._chunks else b""

        async def close(self):
            self.closed = True

    upload = FakeUpload([b"a" * 10, b"b" * 10, b"c" * 10])  # 30 bytes, limit 15
    with pytest.raises(HTTPException) as exc:
        asyncio.run(api_mod._read_upload_bounded(upload, 15))
    assert exc.value.status_code == 413
    assert upload.reads == 2, "reader should stop on the chunk that crosses the limit"
    assert upload.closed is True, "the spooled temp file must be closed on reject"


def test_ingest_text_rejects_oversized_body(client, monkeypatch):
    from sentinelgraph import api as api_mod

    monkeypatch.setattr(api_mod.settings, "max_upload_bytes", 100)
    r = client.post("/api/ingest/text",
                    json={"text": "x" * 500, "filename": "big.txt"})
    assert r.status_code == 413


def test_upload_far_above_limit_is_rejected(client, monkeypatch):
    from sentinelgraph import api as api_mod

    monkeypatch.setattr(api_mod.settings, "max_upload_bytes", 1024)
    big = b'[{"host":"H1"}' + b"x" * 200_000 + b"]"
    r = client.post("/api/ingest/file",
                    files={"file": ("huge.json", big, "application/json")})
    assert r.status_code == 413


def test_repeated_oversized_uploads_leave_no_artifacts(client, monkeypatch):
    from sentinelgraph import api as api_mod

    monkeypatch.setattr(api_mod.settings, "max_upload_bytes", 64)
    before = len(client.get("/api/artifacts").json()["artifacts"])
    for i in range(3):
        r = client.post("/api/ingest/file",
                        files={"file": (f"big{i}.json", b"[" + b"{}," * 200 + b"{}]",
                                        "application/json")})
        assert r.status_code == 413
    after = len(client.get("/api/artifacts").json()["artifacts"])
    assert after == before


def test_upload_unsupported_encoding_rejected(client):
    # Odd-length, invalid UTF-8 and invalid UTF-16 -> 400, not 500.
    r = client.post("/api/ingest/file",
                    files={"file": ("bad.json", b"\xff\xfe\xff", "application/json")})
    assert r.status_code == 400


def test_upload_utf16_still_supported(client):
    payload = '[{"timestamp":"2026-11-03T08:00:00Z","host":"H-UTF16","event_type":"logon"}]'
    r = client.post("/api/ingest/file",
                    files={"file": ("u16.json", payload.encode("utf-16"), "application/json")})
    assert r.status_code == 200, r.text
