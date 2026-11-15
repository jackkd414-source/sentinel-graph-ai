"""Build a clean, PII-free release bundle of SentinelGraph AI.

The working tree intentionally holds real telemetry (data/*.db, exported
Sysmon/firewall/security JSON, .env, logs). None of that may ship. This script
copies only allowlisted source/assets, rebuilds the demo dataset from the
*synthetic* fixture, verifies the result contains no real-machine PII, and only
then produces the ZIP.

    python tools/make_release.py                 # -> release/sentinelgraph-ai(.zip)
    python tools/make_release.py --out DIR

Exit code 0 only if the release was built, scanned clean, and zipped.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

# --- allowlist ------------------------------------------------------------
# Only these top level directories may ship. Anything else at the top level
# (backups, scratch exports, alternate source trees) is ignored by default,
# which is safer than trying to enumerate every bad name.
#
# ``docs`` is deliberately absent: the release is the runnable product plus its
# demo dataset, and the documentation bundle (including the deck and screenshots
# under docs/) is a separate deliverable. The PII scans below tolerate the tree
# being missing, so nothing here depends on it.
ALLOWED_TOP_DIRS = {"backend", "frontend", "tools", "data", "scripts"}
ALLOWED_ROOT_FILES = {
    "README.md", "requirements.txt", "requirements-dev.txt", ".env.example",
    ".gitignore", "LICENSE", "LICENSE.md", "pyproject.toml", "pytest.ini",
    "setup.cfg", "tox.ini", "Makefile",
    # Deployment artefacts. The organisers must be able to run the product from
    # the archive alone, so the container definition travels with it.
    "Dockerfile", "docker-compose.yml", ".dockerignore",
}
# Dotted top-level trees (``.github``, ``.vscode``, ...) are skipped wholesale
# because they can carry CI secrets, caches and editor state. Only the exact
# repo-relative files named here are copied back in. The distributed test suite
# ships ``backend/tests/test_ci_config.py``, which asserts the workflow matches
# the documented gate, so the workflow must travel with the source release.
ALLOWED_DOT_FILES = {
    ".github/workflows/verify.yml",
}

# --- denylist (applied inside the allowlisted tree) -----------------------
EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "release", "backup", "backups",
    "logs", "data", ".idea", ".vscode", "dist", ".cache", "tmp",
}
EXCLUDE_SUFFIXES = {
    ".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3", ".log", ".pyc", ".pyo",
    ".pem", ".key", ".p12", ".pfx", ".crt", ".keystore", ".jks",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".bak",
    ".orig", ".rej", ".swp", ".tsbuildinfo",
}
EXCLUDE_NAMES = {
    ".env", ".master_key", "firewall.json", "security.json", "sysmon.json",
    "sysmon-test.json", "abstest.json", "sysmon-export.log", "credentials",
    "credentials.json", "secrets.json", "id_rsa", "id_ed25519", "api_key",
    "api_key.txt", "token", "token.txt",
}
# These belong in the bundle even though they look excluded by suffix rules.
INCLUDE_FILES = {"requirements.txt", "requirements-dev.txt", ".env.example", ".gitignore"}

# Text-ish files worth scanning for PII (binary blobs are handled separately).
TEXT_SUFFIXES = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".txt", ".css", ".html",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".ps1", ".bat", ".sh", ".csv",
    ".jsonl", ".xml", ".example", ".sql",
}
# Scanner sources legitimately contain the marker strings they look for.
PII_SCAN_SKIP = {"tools/check_pii_db.py", "tools/make_release.py"}


def _pii_markers() -> list[str]:
    from check_pii_db import _IGNORE_IDENTITIES, PATTERN_MARKERS, runtime_identities

    markers = list(PATTERN_MARKERS)
    # Generic account names (root, admin, user, test, system, administrator)
    # legitimately appear in synthetic datasets, so including them as dynamic
    # markers produces false positives. Filter them exactly the way
    # check_pii_db.py does; keep specific hostnames/usernames because those
    # really do identify this machine's telemetry.
    generic = {g.strip().lower() for g in _IGNORE_IDENTITIES}
    markers += [i for i in runtime_identities()
                if i and i.strip().lower() not in generic]
    # De-duplicate while preserving order.
    seen, out = set(), []
    for m in markers:
        if m and m.lower() not in seen:
            seen.add(m.lower())
            out.append(m)
    return out


def _top_allowed(name: str) -> bool:
    return name in ALLOWED_TOP_DIRS or name in ALLOWED_ROOT_FILES


def _is_env_file(name: str) -> bool:
    """True for ``.env`` and every ``.env.*`` variant except ``.env.example``.

    ``.env.example`` is the documented template and must ship. Everything else
    matching this pattern is a local credential file (``.env.local``,
    ``.env.production``, ``.env.staging`` ...) and must never leave the
    developer machine. The rule is name-based so it applies at any depth.
    """
    if name == ".env.example":
        return False
    return name == ".env" or name.startswith(".env.")


def _skip(path: Path) -> bool:
    name = path.name
    if name in INCLUDE_FILES:
        return False
    if _is_env_file(name):
        return True
    if path.is_dir():
        return name in EXCLUDE_DIRS
    if name in EXCLUDE_NAMES:
        return True
    if path.suffix.lower() in EXCLUDE_SUFFIXES:
        return True
    return False


def _purge_bytecode(out: Path) -> int:
    """Remove ``__pycache__`` directories and ``.pyc``/``.pyo`` files.

    The bootstrap runs ``python -m sentinelgraph`` with the release directory as
    CWD, so CPython writes bytecode next to the sources. Compiled bytecode must
    not ship: it is not source, it embeds absolute paths, and it can leak
    strings from the machine that produced it.
    """
    removed = 0
    for cache in list(out.rglob("__pycache__")):
        if cache.is_dir():
            shutil.rmtree(cache, ignore_errors=True)
            removed += 1
    for pattern in ("*.pyc", "*.pyo"):
        for path in list(out.rglob(pattern)):
            if path.is_file():
                path.unlink()
                removed += 1
    return removed


def build_tree(out: Path) -> int:
    copied = 0
    for entry in sorted(ROOT.iterdir()):
        if entry.name.startswith(".") and entry.name not in ALLOWED_ROOT_FILES:
            continue
        if not _top_allowed(entry.name):
            continue
        # Directory-level denylist applies here too, so runtime trees such as
        # ``data`` (holds the live DB and .master_key) never get walked at all.
        if _skip(entry):
            continue
        if entry.is_dir():
            for dirpath, dirnames, filenames in os.walk(entry):
                base = Path(dirpath)
                dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
                rel_dir = base.relative_to(ROOT)
                (out / rel_dir).mkdir(parents=True, exist_ok=True)
                for fname in filenames:
                    src = base / fname
                    if _skip(src):
                        continue
                    dst = out / src.relative_to(ROOT)
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
                    copied += 1
        elif not _skip(entry):
            shutil.copy2(entry, out / entry.name)
            copied += 1

    # Re-add the explicitly allowlisted files that live under a dotted top-level
    # directory (those were skipped wholesale by the loop above). Only the exact
    # repo-relative paths named in ALLOWED_DOT_FILES ship; nothing else under a
    # dotted directory is walked, so CI secrets/caches can never leak in.
    for rel in sorted(ALLOWED_DOT_FILES):
        src = ROOT / rel
        if src.is_file():
            dst = out / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied += 1

    # The built frontend is what makes the bundle runnable.
    frontend_dist = ROOT / "frontend" / "dist"
    if frontend_dist.is_dir():
        target = out / "frontend" / "dist"
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(frontend_dist, target)
        copied += sum(1 for p in target.rglob("*") if p.is_file())
    return copied


def scan_release_text(out: Path) -> list[tuple[str, str]]:
    """Return (relative path:line, marker) for PII markers in text files.

    Lines annotated with ``PII-SCAN-ALLOW`` are skipped. That annotation is the
    only accepted way to silence a hit, so every exception is explicit in the
    source and reviewable instead of being hidden in this script.
    """
    markers = _pii_markers()
    hits: list[tuple[str, str]] = []
    for path in out.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        rel = path.relative_to(out).as_posix()
        if rel in PII_SCAN_SKIP:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if "PII-SCAN-ALLOW" in line:
                continue
            for marker in markers:
                if marker in line:
                    hits.append((f"{rel}:{lineno}", marker))
                    break
    return hits


def scan_screenshots(out: Path) -> list[tuple[str, str]]:
    """Check screenshot sidecars and filenames for PII markers.

    PNG pixels cannot be text-scanned, so this covers the artefacts that can be
    checked mechanically: filenames and the .txt sidecars stored next to them.
    """
    markers = _pii_markers()
    hits: list[tuple[str, str]] = []
    shots = out / "docs" / "screenshots"
    if not shots.is_dir():
        return hits
    for path in shots.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(out).as_posix()
        for marker in markers:
            if marker in path.name:
                hits.append((rel, f"filename:{marker}"))
                break
        if path.suffix.lower() in {".txt", ".md", ".json"}:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for marker in markers:
                if marker in text:
                    hits.append((rel, f"sidecar:{marker}"))
                    break
    return hits


def make_zip(out: Path) -> Path:
    archive = out.parent / f"{out.name}.zip"
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(out.rglob("*")):
            if path.is_file():
                zf.write(path, Path(out.name) / path.relative_to(out))
    return archive


BAD_ARCHIVE_SUFFIXES = {
    ".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3", ".log", ".pyc", ".pyo",
    ".pem", ".key", ".p12", ".pfx", ".crt", ".keystore", ".jks",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".bak",
    ".orig", ".rej", ".swp", ".tsbuildinfo",
}
BAD_ARCHIVE_PARTS = {
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
    "backup", "backups", "logs", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}


def verify_zip(archive: Path) -> list[str]:
    """Nothing sensitive may exist inside the archive either.

    ``Path(".env").suffix`` is ``""``, so suffix-only matching never caught a
    plain ``.env`` or ``.env.local``. Matching is therefore name- and
    path-component-based, and ``.env.example`` stays allowed.
    """
    bad: list[str] = []
    with zipfile.ZipFile(archive) as zf:
        for name in zf.namelist():
            base = name.rsplit("/", 1)[-1]
            parts = [p for p in name.split("/") if p]
            dirs = parts[:-1]
            suffix = Path(name).suffix.lower()
            if _is_env_file(base):
                bad.append(name)
            elif base in EXCLUDE_NAMES:
                bad.append(name)
            elif suffix in BAD_ARCHIVE_SUFFIXES:
                bad.append(name)
            elif any(part in BAD_ARCHIVE_PARTS for part in dirs):
                bad.append(name)
            elif "bytecode" in name.lower():
                bad.append(name)
    return bad


def run(cmd: list[str], env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True)


def export_demo_dataset(out: Path, db_path: Path) -> int:
    """Write the shipped demo dataset from the freshly seeded scratch database.

    The release never carries a database: ``data/`` holds the live one and the
    master key, so it is never walked. That means the demo has to be materialised
    as files instead. ``demo-events.jsonl`` is the analysable extract and the
    README tells the reader how to load the built-in dataset into a database of
    their own. Returns the number of events written.
    """
    demo_dir = out / "data" / "demo"
    demo_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT ts_utc, host, user_name, event_type, source, process_name, "
            "dst_ip, domain, severity, external_id, file_path, command_line "
            "FROM events ORDER BY id"
        ).fetchall()
    finally:
        conn.close()

    cols = ["timestamp", "host", "user_name", "event_type", "source", "process_name",
            "dst_ip", "domain", "severity", "external_id", "file_path", "command_line"]
    with (demo_dir / "demo-events.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            rec = {c: v for c, v in zip(cols, row) if v not in (None, "")}
            fh.write(json.dumps(rec) + "\n")

    (demo_dir / "README.md").write_text(
        "# Demo dataset (synthetic)\n\n"
        "`demo-events.jsonl` is generated from `sentinelgraph/demo_data.py` and\n"
        "contains only synthetic values (WS-FIN-07, r.santoso, RFC 5737 IPs,\n"
        "*.example domains). No runtime database ships with this release.\n\n"
        "The dataset is also built into the application, so the quickest path is\n"
        "the \"Load demo dataset\" action on the dashboard. To seed a database\n"
        "without the UI:\n\n"
        "    python -m sentinelgraph init\n"
        "    python -m sentinelgraph load-demo\n",
        encoding="utf-8",
    )
    return len(rows)


def _reset_output_dir(out: Path) -> None:
    """Clear the previous build, tolerating a transient Windows lock.

    On Windows a just-written tree can still be held by an editor with one of its
    files open, or by the antivirus scanner or the search indexer, and
    ``shutil.rmtree`` then fails with WinError 32 even when the directory is
    empty. Retrying clears the transient cases. If the lock outlives the retries
    the cause is outside this script, so name it instead of dumping a traceback.
    """
    for attempt in range(5):
        try:
            shutil.rmtree(out)
            break
        except FileNotFoundError:
            break
        except PermissionError as exc:
            if attempt == 4:
                raise SystemExit(
                    f"Cannot clear {out}: another process is holding it.\n"
                    f"  {exc}\n"
                    "Most often an editor has a file from that folder open, or the\n"
                    "antivirus scanner is still reading the tree it just saw written.\n"
                    "Close anything open inside it and run again, or point --out at a\n"
                    "fresh directory."
                ) from exc
            time.sleep(0.5 * (attempt + 1))
    out.mkdir(parents=True, exist_ok=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="release/sentinelgraph-ai")
    ap.add_argument("--no-zip", action="store_true")
    args = ap.parse_args(argv)
    out = (ROOT / args.out).resolve()

    _reset_output_dir(out)

    copied = build_tree(out)
    print(f"[1/7] copied {copied} files -> {out}")

    leaked = [p.relative_to(out).as_posix() for p in out.rglob("*")
              if p.is_file() and (_is_env_file(p.name)
                                  or p.name in EXCLUDE_NAMES
                                  or p.suffix.lower() in {".db", ".db-wal", ".db-shm",
                                                          ".sqlite", ".sqlite3", ".log",
                                                          ".pyc", ".pyo"})]
    if leaked:
        print("[FAIL] telemetry/DB/credential/bytecode files leaked into the release:")
        for p in leaked[:20]:
            print("   ", p)
        return 1
    print("[2/7] no .db / telemetry / credential / .env.* files present")

    scratch = Path(tempfile.mkdtemp(prefix="sg-release-verify-"))
    db_path = scratch / "sentinelgraph.db"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(out / "backend")
    env["SG_DB_PATH"] = str(db_path)
    env["SG_ARTIFACT_DIR"] = str(scratch / "artifacts")
    env.pop("SG_MASTER_KEY", None)
    try:
        for step in (["init"], ["load-demo"]):
            r = run([sys.executable, "-m", "sentinelgraph", *step], env, out)
            if r.returncode != 0:
                print(f"[FAIL] bootstrap step {step} failed:\n{r.stdout}\n{r.stderr}")
                return 1
        purged = _purge_bytecode(out)
        print(f"[3/7] bootstrapped synthetic dataset in scratch dir "
              f"(purged {purged} bytecode dirs/files)")

        r = run([sys.executable, str(out / "tools" / "check_pii_db.py"),
                 "--db", str(db_path)], env, out)
        print(r.stdout.strip())
        if "TOTAL PII ROW-MATCHES: 0" not in r.stdout:
            print("[FAIL] synthetic database matches PII markers")
            return 1
        print("[4/7] database PII scan clean (0 matches)")

        shipped = export_demo_dataset(out, db_path)
        print(f"[5/7] shipped {shipped} synthetic events -> data/demo/demo-events.jsonl")

        # Text + dataset PII scan over the whole release (docs, source, demo).
        text_hits = scan_release_text(out)
        shot_hits = scan_screenshots(out)
        if text_hits or shot_hits:
            print("[FAIL] PII markers found in release files:")
            for rel, marker in (text_hits + shot_hits)[:40]:
                print(f"    {rel}  <-  {marker}")
            return 1
        shots = list((out / "docs" / "screenshots").rglob("*.png")) \
            if (out / "docs" / "screenshots").is_dir() else []
        print(f"[6/7] text/demo/screenshot scan clean "
              f"({len(shots)} PNGs, sidecars+filenames checked)")

        if args.no_zip:
            print("[7/7] --no-zip: skipping archive")
        else:
            archive = make_zip(out)
            bad = verify_zip(archive)
            if bad:
                print("[FAIL] archive contains sensitive entries:")
                for name in bad[:20]:
                    print("   ", name)
                return 1
            size_mb = archive.stat().st_size / (1024 * 1024)
            print(f"[7/7] archive OK -> {archive} ({size_mb:.2f} MB)")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    print(f"\nRELEASE OK -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())