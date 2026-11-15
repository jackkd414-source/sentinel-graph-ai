"""ASGI-level request body limit.

``SG_MAX_UPLOAD_BYTES`` was only enforced *after* the multipart/JSON body had
already been read and parsed, so a client could stream an arbitrarily large body
and exhaust memory or the temporary-file spool before the endpoint ever ran.

This middleware sits outermost in the stack and caps the raw request body before
any parser sees it:

* a declared ``Content-Length`` over the limit is rejected immediately, without
  reading the body at all;
* a chunked/streamed body is counted as it arrives and aborted the moment it
  crosses the limit, so ``Transfer-Encoding: chunked`` cannot bypass the check;
* rejection happens before parsing, so nothing is spooled to disk and no partial
  artifact is left behind.
"""
from __future__ import annotations

import json

_413_BODY = json.dumps(
    {"detail": "Request body exceeds the configured limit (SG_MAX_UPLOAD_BYTES)."}
).encode()


class _BodyTooLarge(Exception):
    """Raised from the receive wrapper once the byte budget is exceeded."""


class BodyLimitMiddleware:
    """Reject oversized request bodies before any parser consumes them."""

    def __init__(self, app, max_bytes) -> None:
        self.app = app
        # Accept an int or a zero-arg callable so tests (and an operator who
        # changes SG_MAX_UPLOAD_BYTES at runtime) are not stuck with the value
        # captured at import time.
        self._max = max_bytes

    def _limit(self) -> int:
        value = self._max() if callable(self._max) else self._max
        return max(1, int(value))

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        limit = self._limit()
        started = False

        async def tracked_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        # Cheap fast-path: a declared length already over budget never needs to
        # be read. A malformed Content-Length is treated as hostile.
        for raw_name, raw_value in scope.get("headers") or ():
            if raw_name.lower() == b"content-length":
                try:
                    declared = int(raw_value)
                except (TypeError, ValueError):
                    await self._reject(tracked_send, started)
                    return
                if declared > limit:
                    await self._reject(tracked_send, started)
                    return
                break

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _BodyTooLarge:
            # If the app already began responding we cannot replace the response
            # status; closing the connection is the only honest outcome.
            await self._reject(tracked_send, started)

    async def _reject(self, send, started: bool) -> None:
        if started:
            return
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(_413_BODY)).encode()),
                (b"connection", b"close"),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": _413_BODY,
            "more_body": False,
        })