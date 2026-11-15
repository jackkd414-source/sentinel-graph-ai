#!/usr/bin/env python
"""A local Ollama-compatible endpoint that deliberately fabricates citations.

Why this exists
---------------
The Evidence Guard is the part of SentinelGraph that refuses to trust a model's
citations blindly. Demonstrating it needs a model that misbehaves on demand.
This tool is that model: it answers with one honest hypothesis (citing events
that really are in the incident) and one dishonest hypothesis (citing six event
IDs that do not exist anywhere).

It only supplies the bad answer. Stripping the invented IDs, marking the
hypothesis unsupported, and reporting the count are all done by the product, so
what you see is real behaviour, not a mock.

Usage
-----
    .venv/Scripts/python.exe tools/adversarial_provider.py

Then in the UI under AI Providers, add a provider of type `ollama` with base URL
http://127.0.0.1:11434 and any model name. Run AI analysis on an incident and
open the report: the guard line reports the stripped citations.

Ollama is the only provider type allowed to use a loopback address, which is why
this speaks the Ollama API rather than the OpenAI one.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 11434
MODEL = "adversarial-demo:latest"
BASE = os.environ.get("SG_BASE", "http://127.0.0.1:8088")

# Real event IDs are read from the incident at request time; these are not.
# Deliberately absent from the demo dataset so the guard has to reject them.
FAKE_IDS = [9999, 8888, 7777, 6666, 5555, 4444]

# Used only if the API is unreachable, so the honest hypothesis still cites
# something. Reloading the demo dataset can renumber events.
DEFAULT_REAL_IDS = [900, 901, 902, 903]


def build_analysis(real_ids: list[int]) -> dict:
    return {
        "summary": (
            "Email phishing masuk ke MAILGW-01, diikuti aktivitas kredensial di "
            "WS-FIN-07. PowerShell membuka koneksi keluar ke infrastruktur yang "
            "dicurigai sebagai C2, lalu beberapa berkas diakses."
        ),
        "timeline_interpretation": (
            "Rangkaian berjalan dalam 31 menit, dari email masuk sampai koneksi "
            "keluar terakhir."
        ),
        "hypotheses": [
            {
                "statement": (
                    "Proses PowerShell di WS-FIN-07 melakukan koneksi keluar ke "
                    "infrastruktur C2 setelah email phishing masuk."
                ),
                "confidence": "high",
                "supporting_event_ids": real_ids,
                "contradicting_event_ids": [],
                "reasoning": (
                    "Empat event menunjukkan urutan yang saling mendukung: proses, "
                    "resolusi DNS, dan dua koneksi jaringan ke tujuan yang sama."
                ),
            },
            {
                "statement": (
                    "Data keuangan dan HR dieksfiltrasi ke penyimpanan eksternal "
                    "melalui koneksi terenkripsi setelah akses berkas."
                ),
                "confidence": "medium",
                "supporting_event_ids": FAKE_IDS,
                "contradicting_event_ids": [],
                "reasoning": (
                    "Akses berkas diikuti koneksi keluar, sehingga dipandang "
                    "sebagai eksfiltrasi data."
                ),
            },
        ],
        "root_cause_hypothesis": {
            "statement": "Kredensial dari email phishing dipakai untuk akses awal.",
            "confidence": "medium",
        },
        "missing_information": [
            "Tidak ada bukti payload berkas yang keluar dari jaringan.",
        ],
        "next_investigation_steps": [
            "Periksa log DLP untuk koneksi keluar setelah akses berkas.",
        ],
        "uncertainty_notes": (
            "Apakah data benar-benar meninggalkan jaringan belum dapat ditetapkan "
            "dari event yang tersedia."
        ),
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, obj: dict, code: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path.startswith("/api/tags"):
            self._send({"models": [{"name": MODEL}]})
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if not self.path.startswith("/api/chat"):
            self._send({"error": "not found"}, 404)
            return
        real_ids = self._real_ids()
        self._send({
            "model": MODEL,
            "message": {"role": "assistant",
                        "content": json.dumps(build_analysis(real_ids))},
            "done": True,
            "done_reason": "stop",
            "eval_count": 512,
        })

    def log_message(self, *args) -> None:
        pass

    def _real_ids(self) -> list[int]:
        """First four event IDs of the first incident, so the honest hypothesis
        cites events that actually exist. Falls back to the demo defaults."""
        try:
            with urllib.request.urlopen(f"{BASE}/api/incidents", timeout=3) as r:
                incidents = json.load(r).get("incidents") or []
            if not incidents:
                return DEFAULT_REAL_IDS
            iid = incidents[0]["id"]
            with urllib.request.urlopen(f"{BASE}/api/incidents/{iid}", timeout=3) as r:
                events = json.load(r).get("events") or []
            ids = [e["id"] for e in events if isinstance(e.get("id"), int)]
            return ids[:4] or DEFAULT_REAL_IDS
        except Exception:
            return DEFAULT_REAL_IDS


def main() -> int:
    print(f"adversarial provider on http://127.0.0.1:{PORT}")
    print(f"  model    : {MODEL}")
    print(f"  fake ids : {FAKE_IDS}")
    print("  add an `ollama` provider pointing here, then run AI analysis")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
