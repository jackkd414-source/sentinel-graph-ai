"""CI config must not drift from the gate we actually run by hand.

A workflow file is easy to let rot: it looks green in review and silently stops
testing what the docs promise. These checks fail the suite when that happens.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "verify.yml"


def _load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _runs() -> list[str]:
    return [step["run"] for step in _load()["jobs"]["verify"]["steps"] if "run" in step]


def test_ci_runs_the_canonical_commands():
    runs = _runs()
    assert "python -m pytest" in runs, "CI must run the canonical test command"
    assert "npm run build" in runs, "CI must typecheck + build the frontend"
    assert any("backend/requirements.txt" in r for r in runs), "CI must use pinned deps"


def test_ci_tests_the_python_version_we_verify():
    versions = [
        step["with"]["python-version"]
        for step in _load()["jobs"]["verify"]["steps"]
        if str(step.get("uses", "")).startswith("actions/setup-python")
    ]
    assert versions == ["3.11"], f"CI must test the verified interpreter, got {versions}"


def test_ci_is_valid_yaml_and_triggered():
    doc = _load()
    assert "verify" in doc["jobs"]
    # PyYAML resolves the bare key `on` to the boolean True (YAML 1.1).
    triggers = doc.get("on") or doc.get(True)
    assert triggers, "workflow has no trigger block"
    assert "push" in triggers
