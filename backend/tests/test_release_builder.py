"""Regression tests for the release builder (``tools/make_release.py``).

The builder is the only thing standing between a developer machine that
carries real telemetry and the archive handed to the organizers. These tests
pin the behaviour that matters:

* no ``.env`` / ``.env.*`` variant except ``.env.example`` may ship, at any
  directory depth;
* credential files, bytecode, ``.git``, virtualenvs, ``node_modules`` and
  backups must be rejected from the ZIP;
* generic account names (root, admin, user, ...) must not become PII markers,
  while the real machine hostname/username must still be detected;
* the bootstrap's bytecode must be purged before the archive is produced.

No live request and no real telemetry is involved: everything here operates on
temporary directories and synthetic ZIP entries.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import check_pii_db  # noqa: E402
import make_release as mr  # noqa: E402


# ---------------------------------------------------------------------------
# .env handling
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "name",
    [".env", ".env.local", ".env.production", ".env.staging", ".env.development"],
)
def test_env_variants_are_rejected(name):
    assert mr._is_env_file(name) is True
    assert mr._skip(Path(name)) is True


def test_env_example_is_allowed():
    assert mr._is_env_file(".env.example") is False
    assert mr._skip(Path(".env.example")) is False


def test_nested_env_is_skipped_by_build_tree(tmp_path, monkeypatch):
    src = tmp_path / "src"
    nested = src / "backend" / "sentinelgraph"
    nested.mkdir(parents=True)
    (nested / ".env.local").write_text("SECRET=value", encoding="utf-8")
    (nested / ".env.production").write_text("SECRET=value", encoding="utf-8")
    (nested / "api.py").write_text("print('ok')", encoding="utf-8")
    (src / ".env.example").write_text("TEMPLATE=1", encoding="utf-8")
    (src / "README.md").write_text("# readme", encoding="utf-8")

    monkeypatch.setattr(mr, "ROOT", src)
    out = tmp_path / "out"
    out.mkdir()
    mr.build_tree(out)

    copied = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    assert "backend/sentinelgraph/api.py" in copied
    assert "README.md" in copied
    assert ".env.example" in copied
    assert not any(".env.local" in p or ".env.production" in p for p in copied)


def test_build_tree_skips_runtime_data_dir(tmp_path, monkeypatch):
    src = tmp_path / "src"
    (src / "data").mkdir(parents=True)
    (src / "data" / ".master_key").write_text("key", encoding="utf-8")
    (src / "data" / "sentinelgraph.db").write_text("db", encoding="utf-8")
    (src / "backend").mkdir()
    (src / "backend" / "api.py").write_text("print(1)", encoding="utf-8")

    monkeypatch.setattr(mr, "ROOT", src)
    out = tmp_path / "out"
    out.mkdir()
    mr.build_tree(out)

    copied = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    assert copied == ["backend/api.py"]


# ---------------------------------------------------------------------------
# archive verification
# ---------------------------------------------------------------------------

def _zip_with(tmp_path: Path, names: list[str]) -> Path:
    archive = tmp_path / "release.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name in names:
            zf.writestr(name, "x")
    return archive


def test_verify_zip_rejects_env_variants(tmp_path):
    archive = _zip_with(
        tmp_path,
        [
            "sentinelgraph-ai/.env",
            "sentinelgraph-ai/.env.local",
            "sentinelgraph-ai/.env.production",
            "sentinelgraph-ai/backend/.env.staging",
            "sentinelgraph-ai/.env.example",
        ],
    )
    bad = mr.verify_zip(archive)
    assert "sentinelgraph-ai/.env" in bad
    assert "sentinelgraph-ai/.env.local" in bad
    assert "sentinelgraph-ai/.env.production" in bad
    assert "sentinelgraph-ai/backend/.env.staging" in bad
    assert "sentinelgraph-ai/.env.example" not in bad


def test_verify_zip_rejects_credential_files(tmp_path):
    archive = _zip_with(
        tmp_path,
        [
            "sentinelgraph-ai/data/.master_key",
            "sentinelgraph-ai/credentials.json",
            "sentinelgraph-ai/secrets.json",
            "sentinelgraph-ai/id_rsa",
            "sentinelgraph-ai/server.pem",
            "sentinelgraph-ai/api_key.txt",
            "sentinelgraph-ai/backend/sentinelgraph/api.py",
        ],
    )
    bad = mr.verify_zip(archive)
    for name in (
        "data/.master_key",
        "credentials.json",
        "secrets.json",
        "id_rsa",
        "server.pem",
        "api_key.txt",
    ):
        assert any(name in b for b in bad), name
    assert "sentinelgraph-ai/backend/sentinelgraph/api.py" not in bad


def test_verify_zip_rejects_bytecode_and_runtime_trees(tmp_path):
    names = [
        "sentinelgraph-ai/backend/sentinelgraph/__pycache__/api.cpython-311.pyc",
        "sentinelgraph-ai/backend/sentinelgraph/api.pyc",
        "sentinelgraph-ai/.git/config",
        "sentinelgraph-ai/node_modules/left-pad/index.js",
        "sentinelgraph-ai/venv/lib/python3.11/site-packages/x.py",
        "sentinelgraph-ai/backup/2024-01-01.db",
        "sentinelgraph-ai/logs/server.log",
    ]
    bad = mr.verify_zip(_zip_with(tmp_path, names))
    assert sorted(bad) == sorted(names)


def test_verify_zip_accepts_clean_archive(tmp_path):
    archive = _zip_with(
        tmp_path,
        [
            "sentinelgraph-ai/README.md",
            "sentinelgraph-ai/.env.example",
            "sentinelgraph-ai/backend/sentinelgraph/api.py",
            "sentinelgraph-ai/data/demo/demo-events.jsonl",
            "sentinelgraph-ai/frontend/dist/index.html",
        ],
    )
    assert mr.verify_zip(archive) == []


# ---------------------------------------------------------------------------
# PII marker filtering (generic identities vs real machine identity)
# ---------------------------------------------------------------------------

def test_generic_identities_are_filtered(monkeypatch):
    monkeypatch.setattr(check_pii_db, "PATTERN_MARKERS", [])
    monkeypatch.setattr(
        check_pii_db,
        "runtime_identities",
        lambda: ["root", "admin", "user", "test", "system", "administrator",
                 "USER", "Admin"],
    )
    assert mr._pii_markers() == []


def test_real_machine_identity_is_kept(monkeypatch):
    # Synthetic values, NOT this machine's real hostname/username: a release
    # test file must never carry real telemetry identity. The pair below proves
    # the "keep specific identities" branch without leaking anything.
    monkeypatch.setattr(check_pii_db, "PATTERN_MARKERS", [])
    monkeypatch.setattr(
        check_pii_db,
        "runtime_identities",
        lambda: ["WS-FIN-07", "r.santoso"],
    )
    markers = mr._pii_markers()
    assert "WS-FIN-07" in markers
    assert "r.santoso" in markers


def test_pattern_markers_are_always_kept(monkeypatch):
    monkeypatch.setattr(check_pii_db, "runtime_identities", lambda: [])
    markers = mr._pii_markers()
    # These two literals are the static detection patterns themselves; the
    # scanner cannot tell a pattern from a leak, so they are annotated.
    assert "DESKTOP-" in markers  # PII-SCAN-ALLOW static pattern literal
    assert "S-1-5-" in markers  # PII-SCAN-ALLOW static pattern literal


# ---------------------------------------------------------------------------
# bytecode purge
# ---------------------------------------------------------------------------

def test_purge_bytecode_removes_cache_and_pyc(tmp_path):
    cache = tmp_path / "backend" / "sentinelgraph" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "api.cpython-311.pyc").write_bytes(b"x")
    pyc = tmp_path / "backend" / "sentinelgraph" / "api.pyc"
    pyc.write_bytes(b"x")
    src = tmp_path / "backend" / "sentinelgraph" / "api.py"
    src.write_text("print(1)", encoding="utf-8")

    removed = mr._purge_bytecode(tmp_path)
    assert removed >= 2
    assert not cache.exists()
    assert not pyc.exists()
    assert src.exists()
