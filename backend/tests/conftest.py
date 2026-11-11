"""Shared test fixtures.

Each test gets an isolated SQLite file and artifact dir.

We deliberately DO NOT reload sentinelgraph modules per test. Doing so creates
duplicate class objects (e.g. two distinct SSRFError classes) which makes
`pytest.raises` silently wrong. Instead we point the settings at a temp path,
clear the cached Settings, and reset the module-level DB handle.
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


@pytest.fixture()
def app_env(tmp_path, monkeypatch):
    from sentinelgraph import config, db

    db_file = tmp_path / f"test_{uuid.uuid4().hex[:8]}.db"
    artifact_dir = tmp_path / "artifacts"
    monkeypatch.setenv("SG_DB_PATH", str(db_file))
    monkeypatch.setenv("SG_ARTIFACT_DIR", str(artifact_dir))
    monkeypatch.setenv("SG_MASTER_KEY", "")
    monkeypatch.setenv("SG_CORS_ORIGINS", "http://localhost:5173")

    config.get_settings.cache_clear()

    # Drop every cached connection (they are per-thread now) so the new path is used.
    db.reset_connections()

    db.init_db()

    yield {"db_path": db_file, "artifact_dir": artifact_dir}

    db.reset_connections()


@pytest.fixture()
def client(app_env):
    from fastapi.testclient import TestClient

    from sentinelgraph.api import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def project_id(client) -> int:
    r = client.get("/api/projects")
    assert r.status_code == 200
    projects = r.json()["projects"]
    assert projects, "default project should exist"
    return projects[0]["id"]


@pytest.fixture()
def loaded_demo(client, project_id) -> dict:
    r = client.post(f"/api/demo/load?project_id={project_id}&reset=true")
    assert r.status_code == 200, r.text
    return r.json()
