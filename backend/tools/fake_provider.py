"""Adversarial provider stub: proves the platform rejects fabricated evidence.

Runs a tiny OpenAI-compatible endpoint that answers AI analysis requests with
deliberately dishonest content:
  - cites event IDs that do not exist (9999, 8888)
  - cites a mix of real and fake IDs
  - returns malformed JSON
  - returns a valid schema but claims contamination that contradicts the DB

If SentinelGraph accepted any of this wholesale, an analyst reading the report
would be misled. The tests assert every fabricated citation is dropped and
recorded, and that real IDs survive.

Usage:
    ./.venv/Scripts/python.exe backend/tools/fake_provider.py --port 8099
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Which dishonest behaviour the next /chat/completions call should exhibit.
MODE = {"value": "mixed"}

SCENARIOS = {
    # Mix of fabricated and real event IDs.
    "mixed": {
        "summary": "Attacker staged ransomware and exfiltrated payroll data.",
        "timeline_interpretation": "Phishing led to execution, then C2, then collection and transfer.",
        "hypotheses": [
            {
                "statement": "Phishing landed and credentials were harvested.",
                "confidence": "high",
                "supporting_event_ids": [9999, 1, 8888],
                "contradicting_event_ids": [7777],
                "reasoning": "Email event preceded the HTTP requests to the same domain.",
            },
            {
                "statement": "Ransomware was deployed across the estate.",
                "confidence": "high",
                "supporting_event_ids": [6666, 5555],
                "contradicting_event_ids": [],
                "reasoning": "Invented: no such events exist in the supplied set.",
            },
        ],
        "root_cause_hypothesis": {
            "statement": "Initial access via credential phishing.",
            "confidence": "medium",
        },
        "missing_information": ["No endpoint telemetry for the decoy domain."],
        "next_investigation_steps": ["Reset credentials for the affected account."],
        "uncertainty_notes": "Exfiltration volume is observed but payload contents are unknown.",
    },
    # Every citation fabricated.
    "all_fake": {
        "summary": "Total domain compromise confirmed.",
        "timeline_interpretation": "Everything was encrypted.",
        "hypotheses": [
            {
                "statement": "All file servers encrypted.",
                "confidence": "high",
                "supporting_event_ids": [7777, 6666, 5555],
                "contradicting_event_ids": [],
                "reasoning": "No supporting evidence in the dataset.",
            }
        ],
        "root_cause_hypothesis": {"statement": "Unknown.", "confidence": "low"},
        "missing_information": [],
        "next_investigation_steps": ["Declare major incident."],
        "uncertainty_notes": "",
    },
    # Not even valid JSON.
    "broken_json": None,
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):  # silence stderr noise
        pass

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.rstrip("/")
        if path.endswith("/models"):
            self._json(200, {"data": [{"id": "stub-model-1"}, {"id": "stub-model-2"}]})
            return
        # Ollama-native discovery endpoint
        if path.endswith("/api/tags"):
            self._json(200, {"models": [{"name": "stub-model-1"}, {"name": "stub-model-2"}]})
            return
        if path.endswith("/api/version"):
            self._json(200, {"version": "0.0.0-stub"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            req = {}

        if self.path.rstrip("/").endswith(("/chat/completions", "/api/chat")):
            mode = MODE["value"]
            scenario = SCENARIOS.get(mode)
            if scenario is None:  # broken_json
                content = "I cannot provide JSON, here is prose instead: the host is owned."
            else:
                content = json.dumps(scenario)

            if self.path.rstrip("/").endswith("/api/chat"):
                # Ollama-native envelope: the content sits in message.content
                self._json(200, {
                    "model": req.get("model", "stub-model-1"),
                    "created_at": "2026-01-01T00:00:00Z",
                    "message": {"role": "assistant", "content": content},
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": 100,
                    "eval_count": 50,
                })
                return

            self._json(200, {
                "id": "chatcmpl-stub",
                "object": "chat.completion",
                "model": req.get("model", "stub-model-1"),
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            })
            return

        self._json(404, {"error": "not found"})


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--mode", default="mixed", choices=list(SCENARIOS))
    args = ap.parse_args(argv)
    MODE["value"] = args.mode

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"fake provider on http://127.0.0.1:{args.port} mode={args.mode}", flush=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
