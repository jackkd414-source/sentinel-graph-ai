"""FastAPI application: routes only, business logic lives in the modules."""
from __future__ import annotations

import hashlib
import hmac
import io
import json
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field, field_validator

from . import ai_analysis, ai_providers, attack_map, auth, correlation, demo_data, reporting
from . import provider_store as store
from .bodylimit import BodyLimitMiddleware
from .config import (
    enforce_secure_binding,
    get_settings,
    is_loopback_host,
    warn_on_weak_exposure,
)
from .db import (
    cursor, db_lock, fetchall, fetchone, get_conn, init_db, rows_to_dicts, seed_iocs,
)
from .ingest import (
    AdapterError,
    ParseResult,
    parse_csv_text,
    parse_json_text,
    parse_jsonl_text,
)
from .pipeline import analyze_project, store_import
from .security import SSRFError, validate_provider_url
from .timeutil import now_iso

settings = get_settings()
app = FastAPI(
    title="SentinelGraph AI",
    description="From Signals to Story - defensive incident investigation platform.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    # Authorization must be in the allowlist or the browser strips the bearer
    # token from cross-origin requests and every authenticated call fails.
    allow_headers=["Content-Type", "Authorization"],
)


# Routes that must answer without a credential. The SPA calls /api/auth/me on
# load to decide whether to show the login screen, so a 401 there would be
# indistinguishable from an expired session. /api/health is the liveness probe.
# Logout is here too: dropping a session that is already gone has to succeed, or
# a client clearing an expired credential would be told it failed and might keep
# the dead token.
_AUTH_EXEMPT = {"/api/health", "/api/auth/login", "/api/auth/me", "/api/auth/logout"}


def _auth_required() -> bool:
    """Authentication is mandatory whenever the API is not loopback-only.

    Local single-analyst use stays frictionless: bound to loopback with no
    token, there is nothing to authenticate against. The moment the server is
    reachable from the network, a credential is demanded.
    """
    return bool(settings.auth_token) or not is_loopback_host(settings.host)


def _bearer(request) -> str:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def _is_authenticated(request) -> bool:
    """True for the shared bearer token or for a live login session."""
    provided = _bearer(request)
    if not provided:
        return False
    token = settings.auth_token
    if token and hmac.compare_digest(provided, token):
        return True
    return auth.validate_session(provided) is not None


@app.middleware("http")
async def _require_auth(request, call_next):
    """Gate every /api route except the exempt few.

    The bearer header carries either the shared SG_AUTH_TOKEN (headless use) or
    a session token from /api/auth/login (the browser). Both are checked, so an
    operator can run either model without changing the client.
    """
    # CORS preflight must never be blocked by authentication: the browser does
    # not attach the bearer token to an OPTIONS probe. Hand it to CORSMiddleware,
    # which answers preflight itself and never forwards OPTIONS to a route
    # handler, so it cannot read data or mutate state.
    if request.method == "OPTIONS":
        return await call_next(request)

    path = request.url.path
    if not path.startswith("/api/") or path in _AUTH_EXEMPT:
        return await call_next(request)
    if not _auth_required() or _is_authenticated(request):
        return await call_next(request)
    return JSONResponse({"detail": "Unauthorized"}, status_code=401)


# Outermost middleware: refuse an oversized body before CORS, auth or any
# parser (multipart/JSON) can read or spool it. Added last => runs first.
app.add_middleware(
    BodyLimitMiddleware, max_bytes=lambda: settings.max_request_bytes,
)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    # The single analyst account is created here so a fresh install is usable
    # without hand-editing anything. It also decides whether the bind guard has
    # an authentication path to rely on.
    account = auth.ensure_default_user()
    enforce_secure_binding(
        settings.host, settings.auth_token,
        user_auth_available=bool(account),
        default_password_in_use=auth.uses_default_password(),
        allow_default_password=settings.allow_default_password,
    )
    warning = warn_on_weak_exposure(
        settings.host, settings.auth_token, auth.uses_default_password(),
    )
    if warning:
        print(warning, flush=True)
    _ensure_default_project()


def _ensure_default_project() -> int:
    """Return the single default project, creating it exactly once.

    The original code did SELECT-then-INSERT with no lock, so two concurrent
    first requests both saw "no row" and both inserted, tripping
    ``UNIQUE constraint failed: projects.name``. The whole check-and-create is
    now serialised under db_lock() and the insert is conflict-tolerant, so a
    racing writer (or a second process) cannot produce a duplicate or an error.
    """
    conn = get_conn()
    with db_lock():
        row = conn.execute("SELECT id FROM projects ORDER BY id LIMIT 1").fetchone()
        if row:
            return row["id"]
        now = now_iso()
        with cursor() as cur:
            cur.execute(
                "INSERT INTO projects (name,description,is_demo,created_at,updated_at) "
                "VALUES (?,?,?,?,?) ON CONFLICT(name) DO NOTHING",
                ("Kartika Demo Workspace",
                 "Default workspace for the SentinelGraph AI demonstration dataset.",
                 0, now, now),
            )
        # Re-read rather than trusting lastrowid: ON CONFLICT DO NOTHING leaves
        # lastrowid stale when another writer won the race.
        row = conn.execute(
            "SELECT id FROM projects WHERE name=? ORDER BY id LIMIT 1",
            ("Kartika Demo Workspace",),
        ).fetchone()
        if not row:
            row = conn.execute("SELECT id FROM projects ORDER BY id LIMIT 1").fetchone()
        if not row:
            raise RuntimeError("default project could not be created or found")
        pid = row["id"]
        seed_iocs(conn, pid)
        return pid


def _audit(action: str, target: str | None = None, detail: str | None = None,
           project_id: int | None = None) -> None:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO audit_log (project_id,action,target,detail,created_at) VALUES (?,?,?,?,?)",
            (project_id, action, target, (detail or "")[:1000], now_iso()),
        )


class LoginIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class PasswordIn(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=8, max_length=256)


@app.post("/api/auth/login")
def auth_login(payload: LoginIn) -> dict[str, Any]:
    """Exchange the analyst credential for a session token."""
    account = auth.authenticate(payload.username, payload.password)
    if not account:
        # The audit trail records the attempt but never the password.
        _audit("login_failed", payload.username)
        raise HTTPException(status_code=401, detail="Username atau password salah.")
    token, expires_at = auth.create_session(
        account["username"], settings.session_ttl_hours,
    )
    _audit("login_ok", account["username"])
    return {
        "token": token,
        "expires_at": expires_at,
        "username": account["username"],
        "must_change_password": auth.uses_default_password(),
    }


@app.post("/api/auth/logout")
def auth_logout(request: Request) -> dict[str, str]:
    """Drop the presented session. Safe to call with a stale token."""
    username = auth.validate_session(_bearer(request))
    auth.revoke_session(_bearer(request))
    if username:
        _audit("logout", username)
    return {"status": "ok"}


@app.get("/api/auth/me")
def auth_me(request: Request) -> dict[str, Any]:
    """Whether the caller is authenticated, and what the client should do.

    Deliberately exempt from the gate: the SPA calls this on load to choose
    between the login screen and the app, and a 401 here could not be told apart
    from an expired session. It also means this route must not disclose anything
    a stranger could use, so the default-password flag is only reported to an
    authenticated caller.
    """
    provided = _bearer(request)
    token = settings.auth_token
    via_shared = bool(token) and hmac.compare_digest(provided, token)
    username = None if via_shared else auth.validate_session(provided)
    authenticated = via_shared or username is not None
    account = auth.get_user() or {}
    body: dict[str, Any] = {
        "authenticated": authenticated,
        "auth_required": _auth_required(),
        "session_ttl_hours": settings.session_ttl_hours,
    }
    if authenticated:
        body["username"] = username or account.get("username")
        body["must_change_password"] = auth.uses_default_password()
        body["via"] = "shared_token" if via_shared else "session"
    return body


@app.post("/api/auth/password")
def auth_change_password(payload: PasswordIn, request: Request) -> dict[str, Any]:
    """Change the analyst password. Ends every session, including this one."""
    username = auth.validate_session(_bearer(request))
    if not username:
        raise HTTPException(status_code=401, detail="Sesi tidak valid atau sudah berakhir.")
    try:
        auth.change_password(username, payload.current_password, payload.new_password)
    except auth.AuthError as exc:
        _audit("password_change_failed", username)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit("password_changed", username)
    return {
        "status": "ok",
        "reauth_required": True,
        "detail": "Password diganti. Semua sesi diakhiri, silakan login lagi.",
    }


def _project(project_id: int | None) -> int:
    if project_id is None:
        return _ensure_default_project()
    row = fetchone("SELECT id FROM projects WHERE id=?", (project_id,))
    if not row:
        raise HTTPException(404, "Project not found")
    return row["id"]


# ==========================================================================
# Meta
# ==========================================================================

@app.get("/api/health")
def health() -> dict[str, Any]:
    conn = get_conn()
    counts = {}
    for table in ("projects", "artifacts", "events", "alerts", "incidents",
                  "graph_nodes", "graph_edges", "iocs", "reports"):
        counts[table] = conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
    return {
        "status": "ok",
        "version": app.version,
        "db": str(settings.db_path.name),
        "counts": counts,
        "ai": store.ai_status(),
        "time": now_iso(),
    }


@app.get("/api/projects")
def list_projects() -> dict[str, Any]:
    rows = rows_to_dicts(fetchall(
        "SELECT * FROM projects ORDER BY id"))
    return {"projects": rows}


# ==========================================================================
# Ingestion
# ==========================================================================

SUPPORTED_SUFFIXES = {".json", ".jsonl", ".ndjson", ".log", ".txt", ".csv"}

# Read uploads in bounded chunks so a single oversized request cannot buffer the
# whole body into memory before the size check runs.
UPLOAD_CHUNK_BYTES = 64 * 1024


async def _read_upload_bounded(file: UploadFile, limit: int) -> bytes:
    """Read an upload in bounded chunks and refuse to buffer past ``limit``.

    The previous implementation called ``await file.read()`` first and checked
    the size afterwards, so a large upload was fully materialised in RAM (and
    in any spool) before it was rejected. We now stop at the first chunk that
    would cross the limit; nothing partial is ever kept or stored.
    """
    buf = bytearray()
    try:
        while True:
            chunk = await file.read(UPLOAD_CHUNK_BYTES)
            if not chunk:
                break
            if len(buf) + len(chunk) > limit:
                raise HTTPException(
                    413,
                    f"File exceeds the {limit // (1024 * 1024)} MiB limit.",
                )
            buf.extend(chunk)
    finally:
        # Always release the spooled temp file, even on the reject path.
        await file.close()
    return bytes(buf)


class IngestTextRequest(BaseModel):
    text: str = Field(..., max_length=20_000_000)
    filename: str = Field("pasted.json", max_length=200)
    source_type: str = Field("generic", max_length=60)
    project_id: int | None = None
    preview_only: bool = False


def _detect_format(filename: str, text: str) -> str:
    low = filename.lower()
    if low.endswith((".jsonl", ".ndjson")):
        return "jsonl"
    if low.endswith(".csv"):
        return "csv"
    if low.endswith(".json"):
        return "json"
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        # a single-line-per-record file must win over a JSON array heuristic
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if len(lines) > 1:
            try:
                json.loads(text)
                return "json"
            except json.JSONDecodeError:
                return "jsonl"
        return "json"
    return "csv"


def _parse(text: str, fmt: str, filename: str) -> ParseResult:
    hint = Path(filename).stem
    try:
        if fmt == "json":
            return parse_json_text(text, hint)
        if fmt == "jsonl":
            return parse_jsonl_text(text, hint)
        return parse_csv_text(text, hint)
    except AdapterError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/ingest/text")
def ingest_text(req: IngestTextRequest) -> dict[str, Any]:
    pid = _project(req.project_id)
    if not req.text.strip():
        raise HTTPException(400, "No data supplied.")
    text_bytes = len(req.text.encode("utf-8"))
    if text_bytes > settings.max_upload_bytes:
        raise HTTPException(
            413,
            f"Text exceeds the {settings.max_upload_bytes // (1024 * 1024)} MiB limit.",
        )
    fmt = _detect_format(req.filename, req.text)
    parsed = _parse(req.text, fmt, req.filename)

    if req.preview_only:
        return {
            "preview": True,
            "format": fmt,
            "records_total": parsed.total,
            "records_ok": len(parsed.events),
            "records_failed": len(parsed.failed),
            "sample_events": parsed.events[:10],
            "failures": parsed.failed[:10],
        }

    sha = hashlib.sha256(req.text.encode()).hexdigest()
    result = store_import(
        project_id=pid,
        artifact_name=req.filename,
        source_type=req.source_type or fmt,
        parsed=parsed,
        sha256=sha,
        size_bytes=len(req.text.encode()),
        stored_path=None,
    )
    _audit("ingest_text", req.filename,
           f"fmt={fmt} ok={result['records_ok']} failed={result['records_failed']}", pid)

    # Importing telemetry must trigger detection, correlation and the graph.
    # Previously this only inserted rows, so imported events never produced a
    # single alert - the dashboard looked empty and the graph stayed bare.
    analysis = analyze_project(pid, fresh=True)
    result["analysis"] = analysis
    result["format"] = fmt
    return result


@app.post("/api/ingest/file")
async def ingest_file(
    file: UploadFile = File(...),
    source_type: str = Query("generic", max_length=60),
    project_id: int | None = Query(None),
) -> dict[str, Any]:
    pid = _project(project_id)
    name = Path(file.filename or "upload").name  # strips any path component
    suffix = Path(name).suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        raise HTTPException(
            400,
            f"Unsupported file type '{suffix}'. Supported: {', '.join(sorted(SUPPORTED_SUFFIXES))}",
        )

    raw = await _read_upload_bounded(file, settings.max_upload_bytes)
    if not raw:
        raise HTTPException(400, "Uploaded file is empty.")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            raise HTTPException(400, "File is not valid UTF-8 or UTF-16 text.")

    fmt = _detect_format(name, text)
    parsed = _parse(text, fmt, name)

    sha = hashlib.sha256(raw).hexdigest()
    safe_name = f"{sha[:16]}_{name}"
    stored = settings.artifact_dir / safe_name
    stored.write_bytes(raw)

    result = store_import(
        project_id=pid,
        artifact_name=name,
        source_type=source_type or fmt,
        parsed=parsed,
        sha256=sha,
        size_bytes=len(raw),
        stored_path=str(stored),
    )
    _audit("ingest_file", name, f"sha256={sha[:16]} ok={result['records_ok']}", pid)
    # Same as ingest_text: importing a file must run the detection pipeline,
    # otherwise the uploaded telemetry never becomes alerts.
    result["analysis"] = analyze_project(pid, fresh=True)
    result["format"] = fmt
    result["sha256"] = sha
    return result


def _purge_project_data(pid: int) -> dict[str, int]:
    """Delete every derived row belonging to a project, children first.

    The previous reset only removed six tables, leaving alert_events,
    edge_events, findings and ai_runs behind as orphans that still referenced
    deleted alerts/edges. This walks the dependency graph explicitly so a
    purge leaves no dangling references.
    """
    deleted: dict[str, int] = {}
    with cursor() as cur:
        # Leaf link tables (no project_id) - delete via their parents.
        leaf_links = (
            ("finding_events", "finding_id", "findings"),
            ("alert_events", "alert_id", "alerts"),
            ("edge_events", "edge_id", "graph_edges"),
            ("ai_run_evidence", "ai_run_id", "ai_runs"),
            ("incident_status_history", "incident_id", "incidents"),
        )
        for child, child_col, parent in leaf_links:
            n = cur.execute(
                f"DELETE FROM {child} WHERE {child_col} IN "
                f"(SELECT id FROM {parent} WHERE project_id=?)", (pid,)).rowcount
            if n:
                deleted[child] = n

        for table in ("findings", "reports", "ai_runs", "alerts", "incidents",
                      "graph_edges", "graph_nodes", "events", "artifacts"):
            n = cur.execute(
                f"DELETE FROM {table} WHERE project_id=?", (pid,)).rowcount
            if n:
                deleted[table] = n
    return deleted


@app.post("/api/demo/load")
def load_demo(project_id: int | None = Query(None),
              reset: bool = Query(False)) -> dict[str, Any]:
    """Load the built-in synthetic dataset and run the full pipeline."""
    pid = _project(project_id)
    conn = get_conn()

    if reset:
        _purge_project_data(pid)
        _audit("demo_reset", None, "All project events/artifacts cleared", pid)

    events = demo_data.all_events()
    body = json.dumps(events, indent=1)
    parsed = parse_json_text(body, "demo")
    manifest = demo_data.ground_truth_manifest()
    parsed.warnings.append(
        "SYNTHETIC DEMO DATASET. Ground truth: "
        f"{len(manifest['malicious_hosts'])} malicious hosts, "
        f"{len(manifest['benign_hosts'])} benign hosts."
    )

    import_result = store_import(
        project_id=pid,
        artifact_name="sentinelgraph-synthetic-v1.json",
        source_type="demo_synthetic",
        parsed=parsed,
        sha256=hashlib.sha256(body.encode()).hexdigest(),
        size_bytes=len(body.encode()),
        stored_path=None,
        is_synthetic=True,
        artifact_kind="demo_seed",
    )

    # degraded-timestamp + deliberately broken records go through the CSV path
    failures, degraded = demo_data.broken_records()
    csv_rows = degraded + failures
    lines = ["timestamp,host,user_name,event_type,process_name,note"]
    for r in csv_rows:
        lines.append(",".join(
            str(r.get(k, "")).replace(",", ";") for k in
            ("timestamp", "host", "user_name", "event_type", "process_name", "note")
        ))
    edge_parsed = parse_csv_text("\n".join(lines), "demo-edge-cases")
    edge_result = store_import(
        project_id=pid,
        artifact_name="sentinelgraph-edge-cases.csv",
        source_type="demo_edge_cases",
        parsed=edge_parsed,
        sha256=hashlib.sha256("\n".join(lines).encode()).hexdigest(),
        size_bytes=len("\n".join(lines).encode()),
        stored_path=None,
        is_synthetic=True,
        artifact_kind="demo_seed",
    )

    analysis = analyze_project(pid)
    _audit("demo_load", "sentinelgraph-synthetic-v1",
           f"events={analysis['events_analyzed']} alerts={analysis['alerts_created']}", pid)

    return {
        "project_id": pid,
        "import": import_result,
        "edge_case_import": edge_result,
        "analysis": analysis,
        "ground_truth": manifest,
        "notice": ("This is a SYNTHETIC dataset generated for demonstration. It does not "
                   "describe any real network or organisation."),
    }


@app.get("/api/artifacts")
def list_artifacts(project_id: int | None = None) -> dict[str, Any]:
    pid = _project(project_id)
    rows = rows_to_dicts(fetchall(
        "SELECT * FROM artifacts WHERE project_id=? ORDER BY imported_at DESC", (pid,)
    ))
    return {"artifacts": rows}


@app.delete("/api/artifacts/{artifact_id}")
def delete_artifact(artifact_id: int,
                    project_id: int | None = None) -> dict[str, Any]:
    """Remove one imported file and everything derived from its events.

    Deleting the artifact alone would leave its events orphaned
    (artifact_id is ON DELETE SET NULL), so the events are removed first and
    the pipeline is then re-run over whatever remains. That keeps alerts, the
    graph and incidents consistent with the surviving events instead of
    pointing at data the user just deleted.
    """
    pid = _project(project_id)
    conn = get_conn()
    art = conn.execute("SELECT * FROM artifacts WHERE id=? AND project_id=?",
                       (artifact_id, pid)).fetchone()
    if not art:
        raise HTTPException(404, "Artifact not found")

    event_ids = [r["id"] for r in conn.execute(
        "SELECT id FROM events WHERE artifact_id=? AND project_id=?",
        (artifact_id, pid)).fetchall()]

    with cursor() as cur:
        cur.execute("DELETE FROM events WHERE artifact_id=? AND project_id=?",
                    (artifact_id, pid))
        cur.execute("DELETE FROM artifacts WHERE id=? AND project_id=?",
                    (artifact_id, pid))

    _audit("artifact_delete", str(artifact_id),
           f"{art['name']}: {len(event_ids)} event(s) removed", pid)

    # Rebuild derived state from the events that are left.
    rebuild = analyze_project(pid, fresh=True)

    return {
        "deleted_artifact": art["name"],
        "events_removed": len(event_ids),
        "rebuild": rebuild,
    }


@app.post("/api/data/reset")
def reset_data(project_id: int | None = None,
               keep_iocs: bool = Query(True)) -> dict[str, Any]:
    """Clear all imported telemetry and derived state for a project.

    Intended for 'I imported the wrong file' situations. Security rules and
    (by default) the threat-intelligence indicators are preserved so the
    workspace stays usable without re-seeding.
    """
    pid = _project(project_id)
    deleted = _purge_project_data(pid)
    if not keep_iocs:
        with cursor() as cur:
            deleted["iocs"] = cur.execute(
                "DELETE FROM iocs WHERE project_id=?", (pid,)).rowcount
    _audit("data_reset", None,
           f"cleared {sum(deleted.values())} row(s); keep_iocs={keep_iocs}", pid)

    conn = get_conn()
    counts: dict[str, int] = {}
    for table in ("events", "alerts", "incidents", "artifacts",
                  "graph_nodes", "graph_edges", "iocs"):
        counts[table] = conn.execute(
            f"SELECT COUNT(*) c FROM {table} WHERE project_id=?", (pid,)
        ).fetchone()["c"]
    return {"cleared": deleted, "keep_iocs": keep_iocs, "counts": counts}


# ==========================================================================
# Events
# ==========================================================================

@app.get("/api/events")
def list_events(
    project_id: int | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    host: str | None = None,
    user: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> dict[str, Any]:
    pid = _project(project_id)
    where = ["project_id=?"]
    params: list[Any] = [pid]
    if host:
        where.append("host=?"); params.append(host)
    if user:
        where.append("user_name=?"); params.append(user)
    if event_type:
        where.append("event_type=?"); params.append(event_type)
    if severity:
        where.append("severity=?"); params.append(severity)
    if q:
        where.append("(raw LIKE ? OR process_name LIKE ? OR command_line LIKE ? "
                     "OR file_path LIKE ? OR domain LIKE ?)")
        like = f"%{q}%"
        params += [like] * 5
    clause = " AND ".join(where)
    conn = get_conn()
    total = conn.execute(f"SELECT COUNT(*) c FROM events WHERE {clause}", params).fetchone()["c"]
    direction = "ASC" if order == "asc" else "DESC"
    rows = rows_to_dicts(conn.execute(
        f"SELECT * FROM events WHERE {clause} "
        f"ORDER BY ts_utc IS NULL, ts_utc {direction}, id {direction} LIMIT ? OFFSET ?",
        (*params, limit, offset),
    ).fetchall())
    return {"events": rows, "total": total, "limit": limit, "offset": offset}


@app.get("/api/events/facets")
def event_facets(project_id: int | None = None) -> dict[str, Any]:
    pid = _project(project_id)
    conn = get_conn()

    def distinct(col: str) -> list[str]:
        rows = conn.execute(
            f"SELECT DISTINCT {col} v FROM events WHERE project_id=? AND {col} IS NOT NULL "
            f"AND {col}<>'' ORDER BY v LIMIT 200", (pid,)
        ).fetchall()
        return [r["v"] for r in rows]

    ts_issues = rows_to_dicts(conn.execute(
        "SELECT ts_status, COUNT(*) c FROM events WHERE project_id=? AND ts_status<>'ok' "
        "GROUP BY ts_status", (pid,)
    ).fetchall())

    return {
        "hosts": distinct("host"),
        "users": distinct("user_name"),
        "event_types": distinct("event_type"),
        "severities": distinct("severity"),
        "sources": distinct("source"),
        "timestamp_issues": ts_issues,
    }


# ==========================================================================
# Alerts & incidents
# ==========================================================================

@app.get("/api/alerts")
def list_alerts(project_id: int | None = None, limit: int = Query(200, ge=1, le=1000)) -> dict[str, Any]:
    pid = _project(project_id)
    rows = rows_to_dicts(fetchall(
        "SELECT * FROM alerts WHERE project_id=? "
        "ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, first_ts DESC LIMIT ?",
        (pid, limit),
    ))
    for r in rows:
        r["evidence"] = _alert_evidence(r["id"])
        r["evidence_event_ids"] = [e["id"] for e in r["evidence"]]
    return {"alerts": rows}


def _alert_evidence(alert_id: int) -> list[dict[str, Any]]:
    """Resolve an alert's supporting events.

    Both /api/alerts and /api/incidents/{id} expose the same shape so the
    frontend never has to branch on which endpoint it called.
    """
    return rows_to_dicts(fetchall(
        "SELECT e.* FROM events e JOIN alert_events ae ON ae.event_id = e.id "
        "WHERE ae.alert_id = ? ORDER BY e.ts_utc IS NULL, e.ts_utc, e.id",
        (alert_id,),
    ))


@app.get("/api/incidents")
def list_incidents(project_id: int | None = None) -> dict[str, Any]:
    pid = _project(project_id)
    conn = get_conn()
    rows = rows_to_dicts(conn.execute(
        "SELECT * FROM incidents WHERE project_id=? "
        "ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, first_ts DESC",
        (pid,),
    ).fetchall())
    for r in rows:
        rows_alerts = rows_to_dicts(conn.execute(
            "SELECT id, rule_id, title, severity FROM alerts WHERE incident_id=? "
            "ORDER BY severity DESC", (r["id"],)).fetchall())
        r["alerts"] = rows_alerts
        r["alert_count"] = len(rows_alerts)
        hosts = {a for a in (conn.execute(
            "SELECT DISTINCT host FROM alerts WHERE incident_id=? AND host IS NOT NULL",
            (r["id"],)).fetchall())}
        r["hosts"] = sorted({x["host"] for x in hosts})
    return {"incidents": rows}


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: int) -> dict[str, Any]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Incident not found")
    incident = dict(row)

    alerts = rows_to_dicts(conn.execute(
        """SELECT a.*, r.name AS rule_name, r.logic AS rule_logic
           FROM alerts a JOIN rules r ON r.id=a.rule_id
           WHERE a.incident_id=? ORDER BY a.first_ts""", (incident_id,)
    ).fetchall())

    event_map: dict[int, dict[str, Any]] = {}
    for a in alerts:
        evs = rows_to_dicts(conn.execute(
            """SELECT e.*, ae.role FROM alert_events ae JOIN events e ON e.id=ae.event_id
               WHERE ae.alert_id=? ORDER BY e.ts_utc IS NULL, e.ts_utc""", (a["id"],)
        ).fetchall())
        a["evidence"] = evs
        for e in evs:
            event_map[e["id"]] = e

    events = sorted(event_map.values(), key=lambda e: e.get("ts_utc") or "9999")
    history = rows_to_dicts(conn.execute(
        "SELECT * FROM incident_status_history WHERE incident_id=? ORDER BY changed_at",
        (incident_id,)).fetchall())

    return {
        "incident": incident,
        "alerts": alerts,
        "events": events,
        "timeline": [
            {
                "id": e["id"], "ts_utc": e.get("ts_utc"), "ts_status": e.get("ts_status"),
                "ts_raw": e.get("ts_raw"), "host": e.get("host"), "user": e.get("user_name"),
                "event_type": e.get("event_type"), "source": e.get("source"),
                "detail": (e.get("command_line") or e.get("file_path") or e.get("dst_ip")
                           or e.get("domain") or e.get("process_name") or e.get("action")),
                "severity": e.get("severity"),
            }
            for e in events
        ],
        "status_history": history,
        "ai_status": store.ai_status(),
        "ai_runs": ai_analysis.latest_runs(incident_id),
    }


class StatusUpdate(BaseModel):
    status: str
    note: str | None = Field(None, max_length=1000)

    @field_validator("status")
    @classmethod
    def _valid(cls, v: str) -> str:
        allowed = {"open", "investigating", "contained", "closed"}
        if v not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return v


@app.patch("/api/incidents/{incident_id}/status")
def update_status(incident_id: int, body: StatusUpdate) -> dict[str, Any]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Incident not found")
    old = row["status"]
    now = now_iso()
    with cursor() as cur:
        cur.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?",
                    (body.status, now, incident_id))
        cur.execute(
            """INSERT INTO incident_status_history
               (incident_id,from_status,to_status,note,changed_at) VALUES (?,?,?,?,?)""",
            (incident_id, old, body.status, body.note, now),
        )
    _audit("incident_status", str(incident_id), f"{old} -> {body.status}",
           row["project_id"])
    return {"id": incident_id, "status": body.status, "previous": old}


# ==========================================================================
# Graph
# ==========================================================================

@app.get("/api/graph")
def get_graph(
    project_id: int | None = None,
    include_inferred: bool = True,
    node_types: str | None = None,
    min_severity: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    pid = _project(project_id)
    types = [t.strip() for t in node_types.split(",") if t.strip()] if node_types else None
    return correlation.get_graph(pid, include_inferred, types, min_severity, search)


@app.get("/api/graph/nodes/{node_id}")
def node_detail(node_id: int) -> dict[str, Any]:
    detail = correlation.get_node_detail(node_id)
    if not detail:
        raise HTTPException(404, "Node not found")
    return detail


# ==========================================================================
# Rules
# ==========================================================================

@app.get("/api/rules")
def list_rules() -> dict[str, Any]:
    rows = rows_to_dicts(fetchall("SELECT * FROM rules ORDER BY id"))
    for r in rows:
        r["attack"] = attack_map.techniques(r["id"])
        note = attack_map.note(r["id"])
        if note:
            r["attack_note"] = note
    return {"rules": rows}


@app.patch("/api/rules/{rule_id}")
def toggle_rule(rule_id: str, enabled: bool = Body(..., embed=True)) -> dict[str, Any]:
    row = fetchone("SELECT id FROM rules WHERE id=?", (rule_id,))
    if not row:
        raise HTTPException(404, "Rule not found")
    with cursor() as cur:
        cur.execute("UPDATE rules SET enabled=? WHERE id=?", (1 if enabled else 0, rule_id))
    _audit("rule_toggle", rule_id, f"enabled={enabled}")
    return {"id": rule_id, "enabled": enabled}


@app.post("/api/analyze")
def reanalyze(project_id: int | None = None) -> dict[str, Any]:
    pid = _project(project_id)
    result = analyze_project(pid)
    _audit("reanalyze", None, json.dumps(result.get("graph")), pid)
    return result


# ==========================================================================
# AI providers
# ==========================================================================

@app.get("/api/ai/status")
def ai_status() -> dict[str, Any]:
    return {"status": store.ai_status(),
            "providers": {k: {kk: vv for kk, vv in v.items() if kk != "docs"}
                          for k, v in ai_providers.PROVIDER_TYPES.items()}}


@app.get("/api/ai/providers")
def list_providers() -> dict[str, Any]:
    return {"configs": store.list_configs(),
            "types": ai_providers.PROVIDER_TYPES,
            "encryption_available": store._cipher.available,
            "credential_storage": store._cipher.storage_info()}


class ProviderCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    provider_type: str
    model_id: str = Field(..., min_length=1, max_length=200)
    base_url: str | None = Field(None, max_length=500)
    api_key: str | None = Field(None, max_length=400)
    fast_model_id: str | None = Field(None, max_length=200)
    timeout_s: int = Field(60, ge=5, le=600)
    max_output_tokens: int | None = Field(2048, ge=64, le=32000)
    is_active: bool = False
    allow_fallback: bool = False

    @field_validator("provider_type")
    @classmethod
    def _known(cls, v: str) -> str:
        if v not in ai_providers.PROVIDER_TYPES:
            raise ValueError(f"provider_type must be one of {sorted(ai_providers.PROVIDER_TYPES)}")
        return v


@app.post("/api/ai/providers")
def create_provider(body: ProviderCreate) -> dict[str, Any]:
    try:
        cfg = store.create_config(body.model_dump())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _audit("provider_create", cfg.get("name"), f"type={body.provider_type} "
           f"model={body.model_id} secret_source={cfg.get('secret_source')}")
    return cfg


@app.patch("/api/ai/providers/{config_id}")
def update_provider(config_id: int, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    try:
        cfg = store.update_config(config_id, payload)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _audit("provider_update", str(config_id), "fields=" + ",".join(sorted(payload.keys())))
    return cfg


@app.post("/api/ai/providers/{config_id}/activate")
def activate_provider(config_id: int, active: bool = Body(True, embed=True)) -> dict[str, Any]:
    try:
        cfg = store.set_active(config_id, active)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    _audit("provider_activate", str(config_id), f"active={active}")
    return cfg


@app.delete("/api/ai/providers/{config_id}")
def delete_provider(config_id: int) -> dict[str, Any]:
    if not store.get_config(config_id):
        raise HTTPException(404, "Configuration not found")
    store.delete_config(config_id)
    _audit("provider_delete", str(config_id))
    return {"deleted": True}


@app.post("/api/ai/providers/{config_id}/test")
def test_provider(config_id: int) -> dict[str, Any]:
    """Real network request. Reports classified failure, never fakes success."""
    row = store.get_config(config_id)
    if not row:
        raise HTTPException(404, "Configuration not found")
    try:
        spec = store.build_spec(row)
    except (ValueError, SSRFError) as exc:
        result = {
            "ok": False, "provider": row["provider_type"], "model": row["model_id"],
            "error_category": "invalid_config", "error_message": str(exc),
            "latency_ms": 0, "checked_at": now_iso(),
        }
        store.record_test_result(config_id, result)
        return result

    result = ai_providers.test_connection(spec)
    store.record_test_result(config_id, result)
    _audit("provider_test", str(config_id),
           f"ok={result.get('ok')} cat={result.get('error_category')}")
    return result


@app.post("/api/ai/providers/{config_id}/models")
def provider_models(config_id: int) -> dict[str, Any]:
    row = store.get_config(config_id)
    if not row:
        raise HTTPException(404, "Configuration not found")
    try:
        spec = store.build_spec(row)
    except (ValueError, SSRFError) as exc:
        return {"ok": False, "models": [], "error": str(exc)}
    return ai_providers.list_models(spec)


@app.post("/api/ai/test-unsaved")
def test_unsaved(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Test a provider before saving it. Key is used in-memory only."""
    provider_type = body.get("provider_type", "")
    if provider_type not in ai_providers.PROVIDER_TYPES:
        raise HTTPException(400, "Unknown provider type")
    api_key = (body.get("api_key") or "").strip() or ai_providers.env_key_for(provider_type)
    base_url = (body.get("base_url") or "").strip() or None
    if base_url:
        try:
            validate_provider_url(base_url, provider_type,
                                  allow_private=provider_type == "ollama")
        except SSRFError as exc:
            raise HTTPException(400, str(exc)) from exc
    spec = ai_providers.ProviderSpec(
        provider_type=provider_type,
        model_id=body.get("model_id", ""),
        api_key=api_key,
        base_url=base_url,
        timeout_s=int(body.get("timeout_s") or 60),
        max_output_tokens=64,
        allow_private=provider_type == "ollama",
    )
    return ai_providers.test_connection(spec)


# ==========================================================================
# AI analysis
# ==========================================================================

@app.post("/api/incidents/{incident_id}/analyze")
def analyze_incident(incident_id: int, task: str = Query("summarize")) -> dict[str, Any]:
    if not fetchone("SELECT id FROM incidents WHERE id=?", (incident_id,)):
        raise HTTPException(404, "Incident not found")
    spec, row = store.active_spec()
    if spec is not None and not spec.api_key and \
            ai_providers.PROVIDER_TYPES[spec.provider_type]["needs_key"]:
        return {
            "status": "no_provider",
            "message": "The active provider has no usable credential. Configure a key or "
                       "select another provider. Core analysis remains available.",
        }
    try:
        result = ai_analysis.run_analysis(incident_id, spec, task)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _audit("ai_analyze", str(incident_id), f"status={result.get('status')}")
    return result


@app.get("/api/incidents/{incident_id}/ai-runs")
def incident_ai_runs(incident_id: int) -> dict[str, Any]:
    return {"runs": ai_analysis.latest_runs(incident_id)}


# ==========================================================================
# Reports
# ==========================================================================

@app.post("/api/incidents/{incident_id}/report")
def create_report(incident_id: int, fmt: str = Query("md", pattern="^(md|json|html)$"),
                  use_ai: bool = False) -> dict[str, Any]:
    if not fetchone("SELECT id FROM incidents WHERE id=?", (incident_id,)):
        raise HTTPException(404, "Incident not found")
    spec = None
    if use_ai:
        spec, _ = store.active_spec()
    try:
        rep = reporting.generate(incident_id, fmt, use_ai=use_ai, spec=spec)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _audit("report_generate", str(incident_id),
           f"fmt={fmt} ai={use_ai} ai_status={(rep.get('ai') or {}).get('status')}")
    return rep


@app.get("/api/incidents/{incident_id}/report")
def download_report(incident_id: int, fmt: str = Query("md", pattern="^(md|json|html)$"),
                    use_ai: bool = False) -> Response:
    if not fetchone("SELECT id FROM incidents WHERE id=?", (incident_id,)):
        raise HTTPException(404, "Incident not found")
    spec = None
    if use_ai:
        spec, _ = store.active_spec()
    try:
        rep = reporting.generate(incident_id, fmt, persist=False, use_ai=use_ai, spec=spec)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    media = {"md": "text/markdown; charset=utf-8",
             "json": "application/json",
             "html": "text/html; charset=utf-8"}[fmt]
    filename = f"{rep['incident_ref']}-report.{fmt}"
    return Response(
        content=rep["content"], media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/reports")
def list_reports(project_id: int | None = None) -> dict[str, Any]:
    pid = _project(project_id)
    rows = rows_to_dicts(fetchall(
        """SELECT r.id, r.incident_id, r.fmt, r.created_at, i.ref
           FROM reports r JOIN incidents i ON i.id=r.incident_id
           WHERE r.project_id=? ORDER BY r.id DESC LIMIT 100""", (pid,)
    ))
    return {"reports": rows}


# ==========================================================================
# Audit
# ==========================================================================

@app.get("/api/audit")
def list_audit(limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    rows = rows_to_dicts(fetchall(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)))
    return {"entries": rows}


# ==========================================================================
# Static frontend (production build)
# ==========================================================================

if settings.static_dir.is_dir():
    @app.get("/")
    def index() -> FileResponse:
        # Never let the shell be cached: index.html names the hashed bundle, so a
        # stale copy silently keeps serving an old UI after a rebuild.
        return FileResponse(settings.static_dir / "index.html",
                            headers={"Cache-Control": "no-store, must-revalidate"})

    @app.get("/assets/{path:path}")
    def assets(path: str) -> FileResponse:
        target = (settings.static_dir / "assets" / path).resolve()
        root = (settings.static_dir / "assets").resolve()
        if root not in target.parents and target != root:
            raise HTTPException(404, "Not found")
        if not target.is_file():
            raise HTTPException(404, "Not found")
        return FileResponse(target)

    @app.get("/{path:path}")
    def spa_fallback(path: str) -> FileResponse:
        if path.startswith("api/"):
            raise HTTPException(404, "Not found")
        candidate = (settings.static_dir / path).resolve()
        if settings.static_dir.resolve() in candidate.parents and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(settings.static_dir / "index.html",
                            headers={"Cache-Control": "no-store, must-revalidate"})
