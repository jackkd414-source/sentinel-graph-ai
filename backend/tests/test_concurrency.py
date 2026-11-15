"""Concurrency regression tests.

The original defect: ``_ensure_default_project`` did SELECT-then-INSERT without
holding a lock across both statements, so two concurrent first requests both saw
"no project" and both inserted, raising
``sqlite3.IntegrityError: UNIQUE constraint failed: projects.name``.

The test forces a project-less database on every iteration and then hammers the
function from 20 threads. It repeats 20 times because a single lucky run proves
nothing about a race.
"""
from __future__ import annotations

import threading

ITERATIONS = 20
THREADS = 20


def _clear_projects():
    from sentinelgraph import db

    with db.db_lock():
        conn = db.get_conn()
        conn.execute("DELETE FROM iocs")
        conn.execute("DELETE FROM projects")
        conn.commit()


def test_default_project_creation_is_race_free(app_env):
    from sentinelgraph import api, db

    for iteration in range(ITERATIONS):
        _clear_projects()

        results: list[int] = []
        errors: list[str] = []
        barrier = threading.Barrier(THREADS)

        def worker() -> None:
            try:
                barrier.wait(timeout=10)
                results.append(api._ensure_default_project())
            except Exception as exc:  # noqa: BLE001 - we want the repr
                errors.append(f"{type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=worker) for _ in range(THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)

        assert not any(t.is_alive() for t in threads), (
            f"iteration {iteration}: deadlock - threads did not finish"
        )
        assert not errors, f"iteration {iteration}: {errors}"
        assert len(results) == THREADS, f"iteration {iteration}: {len(results)} results"

        ids = set(results)
        assert len(ids) == 1, f"iteration {iteration}: multiple project ids {ids}"

        conn = db.get_conn()
        n = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        assert n == 1, f"iteration {iteration}: {n} projects exist, expected exactly 1"

        pid = ids.pop()
        row = conn.execute("SELECT id, name FROM projects WHERE id=?", (pid,)).fetchone()
        assert row is not None, f"iteration {iteration}: returned id {pid} does not exist"
        assert row["name"] == "Kartika Demo Workspace"


def test_concurrent_project_creation_keeps_iocs_idempotent(app_env):
    """IOC seeding must not duplicate rows when many threads create/read."""
    from sentinelgraph import api, db

    _clear_projects()
    threads = [threading.Thread(target=api._ensure_default_project) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    conn = db.get_conn()
    total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    distinct = conn.execute(
        "SELECT COUNT(*) FROM (SELECT DISTINCT ioc_type, value FROM iocs)"
    ).fetchone()[0]
    assert total == distinct, f"duplicate IOC rows: {total} rows vs {distinct} distinct"