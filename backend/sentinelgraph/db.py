"""SQLite storage layer for SentinelGraph AI.

Design notes
------------
* Plain sqlite3 (stdlib) - no ORM. Keeps the dependency surface small and
  makes every query auditable, which matters for an evidence-first tool.
* WAL mode + foreign keys ON.
* Schema versioning via PRAGMA user_version with idempotent migrations.

Evidence model
--------------
The DB stores *facts* (events, artifacts, entities) and *derivations*
(alerts, edges, findings, ai_runs). Derivations always carry references back
to the event/artifact rows that produced them, which is what lets the UI and
reports prove every claim.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import attack_map
from .config import get_settings

SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- ============================================================
-- Workspace / project scope
-- ============================================================
CREATE TABLE IF NOT EXISTS projects (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    description   TEXT,
    is_demo       INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- ============================================================
-- Raw evidence: imported files
-- ============================================================
CREATE TABLE IF NOT EXISTS artifacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    source_type   TEXT NOT NULL,             -- phishing_email, windows_evtx_csv, firewall_csv, ...
    artifact_kind TEXT NOT NULL DEFAULT 'file',  -- file | demo_seed
    stored_path   TEXT,                      -- NULL for built-in demo seeds
    sha256        TEXT,
    size_bytes    INTEGER,
    record_total  INTEGER NOT NULL DEFAULT 0,
    record_ok     INTEGER NOT NULL DEFAULT 0,
    record_failed INTEGER NOT NULL DEFAULT 0,
    parse_status  TEXT NOT NULL DEFAULT 'pending',  -- pending|ok|partial|failed
    parse_notes   TEXT,
    is_synthetic  INTEGER NOT NULL DEFAULT 0,
    imported_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_project ON artifacts(project_id, imported_at);

-- ============================================================
-- Normalized events (the core table)
-- ============================================================
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    artifact_id     INTEGER REFERENCES artifacts(id) ON DELETE SET NULL,
    external_id     TEXT,                       -- id from source system
    ts_raw          TEXT,                       -- exactly as found in source
    ts_utc          TEXT,                       -- normalized ISO8601 UTC, NULL if unknown
    ts_status       TEXT NOT NULL DEFAULT 'ok', -- ok | invalid | missing | assumed
    source          TEXT NOT NULL,              -- windows_security, firewall, dns, proxy, ...
    event_type      TEXT NOT NULL,              -- logon, process_create, dns_query, ...
    action          TEXT,
    severity        TEXT,                       -- info|low|medium|high|critical
    host            TEXT,
    user_name       TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    dst_port        INTEGER,
    domain          TEXT,
    url             TEXT,
    file_path       TEXT,
    file_hash       TEXT,
    process_name    TEXT,
    process_id      TEXT,
    parent_process  TEXT,
    parent_pid      TEXT,
    command_line    TEXT,
    bytes_out       INTEGER,
    raw             TEXT,                       -- original record serialized
    dedup_key       TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_project_ts ON events(project_id, ts_utc);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(project_id, host);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(project_id, user_name);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(project_id, event_type);
CREATE INDEX IF NOT EXISTS idx_events_dedup ON events(project_id, dedup_key);
CREATE INDEX IF NOT EXISTS idx_events_artifact ON events(artifact_id);

-- ============================================================
-- Threat intelligence (local IOC dataset)
-- ============================================================
CREATE TABLE IF NOT EXISTS iocs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ioc_type     TEXT NOT NULL,             -- ip | domain | hash | url
    value        TEXT NOT NULL,
    threat_label TEXT,
    confidence   TEXT NOT NULL DEFAULT 'medium',
    source       TEXT,
    note         TEXT,
    UNIQUE(project_id, ioc_type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(project_id, value);

-- ============================================================
-- Detection rules
-- ============================================================
CREATE TABLE IF NOT EXISTS rules (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    category     TEXT NOT NULL,
    description  TEXT NOT NULL,
    logic        TEXT NOT NULL,     -- human-readable condition
    severity     TEXT NOT NULL,
    version      TEXT NOT NULL,
    attack       TEXT NOT NULL DEFAULT '',  -- comma-separated ATT&CK technique IDs
    enabled      INTEGER NOT NULL DEFAULT 1
);

-- ============================================================
-- Alerts (rule output) + incidents (grouped alerts)
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    rule_id       TEXT NOT NULL REFERENCES rules(id),
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    narrative     TEXT NOT NULL,       -- why this fired
    host          TEXT,
    user_name     TEXT,
    first_ts      TEXT,
    last_ts       TEXT,
    incident_id   INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    dedup_key     TEXT,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_project ON alerts(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id   INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id   INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'supporting',  -- trigger | supporting | context
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ref           TEXT NOT NULL,          -- human ref: INC-2026-0001
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open',  -- open|investigating|contained|closed
    summary       TEXT,
    first_ts      TEXT,
    last_ts       TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE(project_id, ref)
);

CREATE INDEX IF NOT EXISTS idx_incidents_project ON incidents(project_id, severity);

CREATE TABLE IF NOT EXISTS incident_status_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    from_status TEXT,
    to_status   TEXT NOT NULL,
    note        TEXT,
    changed_at  TEXT NOT NULL
);

-- ============================================================
-- Attack graph
-- ============================================================
CREATE TABLE IF NOT EXISTS graph_nodes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    node_key    TEXT NOT NULL,       -- canonical identity, e.g. host:WS-01
    node_type   TEXT NOT NULL,       -- host|user|process|file|domain|ip|event|alert|artifact
    label       TEXT NOT NULL,
    severity    TEXT,
    attributes  TEXT,                -- JSON blob, non-essential metadata
    UNIQUE(project_id, node_key)
);

CREATE INDEX IF NOT EXISTS idx_nodes_project_type ON graph_nodes(project_id, node_type);

CREATE TABLE IF NOT EXISTS graph_edges (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    src_node_id    INTEGER NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    dst_node_id    INTEGER NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    relation       TEXT NOT NULL,     -- spawned|connected_to|resolved|authenticated|...
    status         TEXT NOT NULL,     -- observed | inferred
    method         TEXT NOT NULL,     -- how it was derived (rule/name/temporal)
    confidence     TEXT NOT NULL DEFAULT 'medium',
    first_ts       TEXT,
    last_ts        TEXT,
    dedup_key      TEXT,
    UNIQUE(project_id, src_node_id, dst_node_id, relation, dedup_key)
);

CREATE INDEX IF NOT EXISTS idx_edges_project ON graph_edges(project_id, status);
CREATE INDEX IF NOT EXISTS idx_edges_src ON graph_edges(src_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON graph_edges(dst_node_id);

CREATE TABLE IF NOT EXISTS edge_events (
    edge_id  INTEGER NOT NULL REFERENCES graph_edges(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    PRIMARY KEY (edge_id, event_id)
);

-- ============================================================
-- Findings (derived conclusions with explicit evidence class)
-- ============================================================
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    incident_id  INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,    -- observed|derived|ai_hypothesis|unknown
    title        TEXT NOT NULL,
    detail       TEXT,
    confidence   TEXT,             -- documented scale, see docs
    origin       TEXT NOT NULL,    -- rule_engine | correlation | ai | analyst
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_incident ON findings(incident_id);

CREATE TABLE IF NOT EXISTS finding_events (
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    event_id   INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, event_id)
);

-- ============================================================
-- AI runs (schema-validated, evidence-linked)
-- ============================================================
CREATE TABLE IF NOT EXISTS ai_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    incident_id    INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    task           TEXT NOT NULL,     -- summarize|hypotheses|explain|report
    provider       TEXT,
    model          TEXT,
    status         TEXT NOT NULL,     -- ok|error|no_provider|validation_failed
    latency_ms     INTEGER,
    prompt_tokens  INTEGER,
    output_tokens  INTEGER,
    request_context TEXT,             -- JSON of exactly what was sent (values, not secrets)
    result_json    TEXT,              -- validated structured output
    error_category TEXT,
    error_message  TEXT,              -- sanitized
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_runs_incident ON ai_runs(incident_id, created_at);

CREATE TABLE IF NOT EXISTS ai_run_evidence (
    ai_run_id INTEGER NOT NULL REFERENCES ai_runs(id) ON DELETE CASCADE,
    event_id  INTEGER REFERENCES events(id) ON DELETE CASCADE,
    artifact_id INTEGER REFERENCES artifacts(id) ON DELETE CASCADE
);

-- ============================================================
-- Reports
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    fmt         TEXT NOT NULL,       -- md|json|html
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_incident ON reports(incident_id, created_at);

-- ============================================================
-- Provider configs (secrets encrypted, never plaintext)
-- ============================================================
CREATE TABLE IF NOT EXISTS provider_configs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    provider_type   TEXT NOT NULL,   -- openai|anthropic|gemini|openrouter|ollama|custom_openai
    base_url        TEXT,
    model_id        TEXT NOT NULL,
    fast_model_id   TEXT,
    secret_enc      TEXT,            -- Fernet token; NULL => use env var
    secret_source   TEXT NOT NULL DEFAULT 'none',  -- db|env|none
    timeout_s       INTEGER NOT NULL DEFAULT 60,
    max_output_tokens INTEGER,
    is_active       INTEGER NOT NULL DEFAULT 0,
    allow_fallback  INTEGER NOT NULL DEFAULT 0,
    last_test_status TEXT,           -- ok|fail|untested
    last_test_at    TEXT,
    last_test_latency_ms INTEGER,
    last_test_error TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- ============================================================
-- Analyst account and login sessions
-- ============================================================
-- Single-analyst product: exactly one account is supported. The row is created
-- on first start with the shipped default credential, and the password is
-- stored as a scrypt hash with a per-account salt. There is no plaintext
-- column and no multi-user concept by design.
CREATE TABLE IF NOT EXISTS app_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,      -- scrypt(password, salt) as hex
    salt          TEXT NOT NULL,      -- per-account random salt, hex
    params        TEXT NOT NULL,      -- e.g. scrypt$n=16384,r=8,p=1
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- Only the SHA-256 of a session token is stored, so a database leak does not
-- hand over live sessions. Rows are deleted on logout, on password change and
-- when they expire.
CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash   TEXT PRIMARY KEY,    -- sha256(session token), hex
    username     TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    last_seen_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at);

-- ============================================================
-- Audit log
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
"""

RULE_SEED = [
    (
        "R-001",
        "Failed logon burst followed by success",
        "credential_access",
        "Detects N or more failed authentications for the same account/host inside a "
        "window, followed by a successful logon for that account.",
        "count(failed_logon by user) >= threshold within window AND successful logon after burst",
        "high",
        "1.0.0",
    ),
    (
        "R-002",
        "Suspicious child process after unusual parent",
        "execution",
        "A process is spawned by a parent process associated with document readers, "
        "script hosts, or email clients - a common phishing execution chain.",
        "process_create where parent_process in HIGH_RISK_PARENTS",
        "high",
        "1.0.0",
    ),
    (
        "R-003",
        "Connection to known threat indicator",
        "command_and_control",
        "Network event destination IP, domain, or URL matches an entry in the local "
        "threat-intelligence dataset.",
        "event.dst_ip|domain|url in iocs",
        "critical",
        "1.0.0",
    ),
    (
        "R-004",
        "Sensitive file access followed by outbound transfer",
        "collection_exfiltration",
        "A file access event on a sensitive path is followed within a short window by a "
        "large outbound transfer from the same host.",
        "file_access(sensitive path) then bytes_out > threshold on same host within window",
        "high",
        "1.0.0",
    ),
    (
        "R-005",
        "Cross-host activity in short window",
        "lateral_movement",
        "The same user account authenticates to multiple distinct hosts inside a short "
        "window, which requires correlation across sources to be visible.",
        "distinct(host) for user >= threshold within window",
        "medium",
        "1.0.0",
    ),
    (
        "R-006",
        "Activity deviating from synthetic baseline",
        "anomaly",
        "Event volume for a host/time-of-day bucket exceeds the observed baseline mean by "
        "more than the configured factor. Baseline is derived from the loaded data only.",
        "count(events per host per hour) > baseline_mean * factor",
        "low",
        "1.0.0",
    ),
]

IOC_SEED = [
    ("ip", "203.0.113.66", "C2 - simulated", "high", "demo-ti",
     "Documentation range (RFC 5737). Synthetic indicator."),
    ("ip", "198.51.100.23", "Phishing infrastructure - simulated", "medium", "demo-ti",
     "Documentation range (RFC 5737). Synthetic indicator."),
    ("domain", "secure-login-portal.example", "Credential phishing - simulated", "high",
     "demo-ti", "Reserved example domain. Synthetic indicator."),
    ("domain", "cdn-update-delivery.example", "Payload staging - simulated", "medium",
     "demo-ti", "Reserved example domain. Synthetic indicator."),
    ("hash", "9f2a4c8e1b6d3f7a0c5e2b9d4f8a1c6e3b7d0f2a5c8e1b4d7f0a3c6e9b2d5f8a",
     "Simulated launcher binary", "high", "demo-ti", "Synthetic SHA-256 value."),
]

# FastAPI runs sync endpoints in a thread pool, so several request threads share
# this module's SQLite state. Two things must be serialised or the app breaks:
#   - cursor(): two interleaved write transactions on one connection corrupt
#     commit() ("SystemError: error return without exception set").
#   - analyze_project(): it does DELETE-then-INSERT rebuilds of alerts,
#     incidents and the graph; two concurrent runs raise "UNIQUE constraint
#     failed: graph_nodes.project_id, graph_node_key".
# A single connection plus one reentrant lock around both is enough, and keeps
# SQLite's own write lock uncontended. _lock is reentrant because
# analyze_project holds it while calling cursor()/seed_iocs(), which take it too.
_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


@contextmanager
def db_lock() -> Iterator[None]:
    """Serialise a multi-statement DB operation against other threads."""
    with _lock:
        yield


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    """Open a connection with the pragmas we rely on."""
    settings = get_settings()
    path = db_path or settings.db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def get_conn() -> sqlite3.Connection:
    """Return the shared SQLite connection, opening it on first use.

    One connection is shared by the whole process; every access is serialised
    through _lock (see cursor() and db_lock()).
    """
    global _conn
    with _lock:
        if _conn is None:
            _conn = connect()
        return _conn


def fetchone(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    """Locked single-row read.

    A bare ``get_conn().execute()`` shares the process-wide connection without
    taking ``_lock``, so two request threads can drive the same sqlite3 object
    at once and trip ``DatabaseError('not an error')`` / ``SystemError``.
    """
    with _lock:
        return get_conn().execute(sql, params).fetchone()


def fetchall(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    """Locked multi-row read (see ``fetchone``)."""
    with _lock:
        return get_conn().execute(sql, params).fetchall()


def reset_connections() -> None:
    """Close the cached connection and forget it. Used by tests between cases."""
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:  # noqa: BLE001
                pass
            _conn = None


@contextmanager
def cursor() -> Iterator[sqlite3.Cursor]:
    with _lock:
        conn = get_conn()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()


def init_db(conn: sqlite3.Connection | None = None, force: bool = False) -> None:
    """Create schema and seed static reference data. Idempotent."""
    own = conn is None
    conn = conn or get_conn()
    try:
        conn.executescript(SCHEMA_SQL)
        _migrate(conn)
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if force or version < SCHEMA_VERSION:
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        _seed_reference(conn)
        conn.commit()
    finally:
        if own:
            pass


def _migrate(conn: sqlite3.Connection) -> None:
    """Additive migrations for databases created by an older build."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(rules)")}
    if "attack" not in cols:
        conn.execute("ALTER TABLE rules ADD COLUMN attack TEXT NOT NULL DEFAULT ''")


def _seed_reference(conn: sqlite3.Connection) -> None:
    for rule in RULE_SEED:
        conn.execute(
            """INSERT INTO rules (id,name,category,description,logic,severity,version,attack,enabled)
               VALUES (?,?,?,?,?,?,?,?,1)
               ON CONFLICT(id) DO UPDATE SET
                 name=excluded.name, category=excluded.category,
                 description=excluded.description, logic=excluded.logic,
                 severity=excluded.severity, version=excluded.version,
                 attack=excluded.attack""",
            (*rule, attack_map.ids(rule[0])),
        )


def seed_iocs(conn: sqlite3.Connection, project_id: int) -> int:
    """Insert the local threat-intel dataset for a project. Idempotent."""
    n = 0
    with _lock:
        for row in IOC_SEED:
            try:
                conn.execute(
                    """INSERT INTO iocs (project_id,ioc_type,value,threat_label,confidence,source,note)
                       VALUES (?,?,?,?,?,?,?)""",
                    (project_id, *row),
                )
                n += 1
            except sqlite3.IntegrityError:
                pass
    return n


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]
