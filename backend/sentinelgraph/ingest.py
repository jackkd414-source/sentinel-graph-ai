"""Unified event schema and source adapters.

Every source adapter maps a raw record to a normalised event dict. Missing
fields stay None - we never synthesize a host, user, or IP that was not in the
data. The parser reports per-record success so imports can be audited.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from .timeutil import normalize_ts

# Canonical normalised event keys. Adapters may only emit these.
EVENT_FIELDS = [
    "external_id", "ts_raw", "ts_utc", "ts_status", "source", "event_type",
    "action", "severity", "host", "user_name", "src_ip", "dst_ip", "dst_port",
    "domain", "url", "file_path", "file_hash", "process_name", "process_id",
    "parent_process", "parent_pid", "command_line", "bytes_out", "raw",
]


@dataclass
class ParseResult:
    events: list[dict[str, Any]] = field(default_factory=list)
    failed: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.events) + len(self.failed)


class AdapterError(ValueError):
    pass


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _s(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
        return text or None
    text = str(value).strip()
    return text or None


def _i(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(str(value).replace(",", "").strip()))
    except (TypeError, ValueError):
        return None


def _first(record: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in record and record[k] not in (None, ""):
            return record[k]
    return None


SEVERITY_ALIASES = {
    "info": "info", "informational": "info", "debug": "info",
    "low": "low", "minor": "low",
    "medium": "medium", "med": "medium", "moderate": "medium", "warning": "medium",
    "high": "high", "major": "high", "error": "high",
    "critical": "critical", "crit": "critical", "emergency": "critical",
    "alert": "critical", "fatal": "critical",
}


def _sev(value: Any) -> str | None:
    if value is None:
        return None
    return SEVERITY_ALIASES.get(str(value).strip().lower())


def base_record(raw: dict[str, Any], source: str, event_type: str) -> dict[str, Any]:
    rec = {k: None for k in EVENT_FIELDS}
    rec["source"] = source
    rec["event_type"] = event_type
    rec["raw"] = json.dumps(raw, ensure_ascii=False, default=str)
    return rec


# --------------------------------------------------------------------------
# Generic adapters: JSON / JSONL / CSV
# --------------------------------------------------------------------------

def parse_json_text(text: str, source_hint: str | None = None) -> ParseResult:
    result = ParseResult()
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AdapterError(f"Invalid JSON: {exc.msg} at line {exc.lineno}") from exc
    records: Iterable[Any]
    if isinstance(doc, dict):
        # Accept {"events": [...]} style envelopes.
        for key in ("events", "records", "data", "logs", "items"):
            if isinstance(doc.get(key), list):
                records = doc[key]
                break
        else:
            records = [doc]
    elif isinstance(doc, list):
        records = doc
    else:
        raise AdapterError("JSON root must be an object or array.")
    for idx, item in enumerate(records):
        _absorb(result, item, idx, source_hint or "json")
    return result


def parse_jsonl_text(text: str, source_hint: str | None = None) -> ParseResult:
    result = ParseResult()
    for idx, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            result.failed.append({"record": idx, "reason": f"invalid JSON: {exc.msg}"})
            continue
        _absorb(result, item, idx, source_hint or "jsonl")
    return result


def parse_csv_text(
    text: str, source_hint: str | None = None, delimiter: str | None = None
) -> ParseResult:
    result = ParseResult()
    if delimiter is None:
        sample = text[:4096]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            delimiter = dialect.delimiter
        except csv.Error:
            delimiter = ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames:
        raise AdapterError("CSV has no header row.")
    for idx, row in enumerate(reader):
        clean = {k.strip(): v for k, v in row.items() if k is not None and k.strip()}
        _absorb(result, clean, idx, source_hint or "csv")
    return result


def _absorb(result: ParseResult, item: Any, idx: int, hint: str) -> None:
    if not isinstance(item, dict):
        result.failed.append({"record": idx, "reason": "record is not an object"})
        return
    try:
        ev = normalize_record(item, source_hint=hint)
    except Exception as exc:  # noqa: BLE001 - per-record isolation is intentional
        result.failed.append({"record": idx, "reason": str(exc)[:200]})
        return

    # A record carrying no identifying information is not evidence. Storing it
    # would inflate event counts and pollute the timeline with empty rows.
    identifying = ("host", "user_name", "src_ip", "dst_ip", "domain", "file_path",
                   "process_name", "command_line")
    has_identity = any(ev.get(f) for f in identifying)
    has_time = ev.get("ts_status") != "missing"
    has_type = ev.get("event_type") not in (None, "", "generic")
    if not (has_identity or has_time or has_type):
        result.failed.append({
            "record": idx,
            "reason": "record has no timestamp, no entity and no event type - "
                      "cannot be interpreted as an event",
        })
        return
    result.events.append(ev)


# --------------------------------------------------------------------------
# Field mapping to unified schema
# --------------------------------------------------------------------------

MAP = {
    "external_id": ("event_id", "id", "EventID", "record_id", "uid"),
    "ts_raw": ("timestamp", "time", "@timestamp", "ts", "date", "TimeCreated",
               "event_time", "EventTime", "datetime"),
    "host": ("host", "hostname", "computer", "ComputerName", "asset", "src_host",
             "device_name", "WorkstationName"),
    "user_name": ("user_name", "user", "username", "Username", "AccountName",
                  "TargetUserName", "src_user", "SubjectUserName"),
    "src_ip": ("src_ip", "source_ip", "SourceIp", "IpAddress", "srcaddr", "client_ip",
               "SrcIP"),
    "dst_ip": ("dst_ip", "dest_ip", "DestinationIp", "dstaddr", "DestIP"),
    "dst_port": ("dst_port", "dest_port", "destport", "DestinationPort", "dpt"),
    "domain": ("domain", "query", "dns_query", "qname", "hostname_query"),
    "url": ("url", "uri", "request_url", "target_url"),
    "file_path": ("file_path", "path", "TargetFilename", "filename", "file"),
    "file_hash": ("file_hash", "hash", "sha256", "SHA256", "md5", "file_md5"),
    "process_name": ("process_name", "process", "Image", "NewProcessName",
                     "proc_name", "exe"),
    "process_id": ("process_id", "pid", "ProcId", "NewProcessId", "ProcessId"),
    "parent_process": ("parent_process", "ParentImage", "parent_proc",
                       "ParentProcessName"),
    "parent_pid": ("parent_pid", "ppid", "ParentProcessId"),
    "command_line": ("command_line", "CommandLine", "cmd", "ProcessCommandLine"),
    "bytes_out": ("bytes_out", "bytes", "out_bytes", "sent_bytes", "SentBytes"),
    "action": ("action", "event_action", "Activity", "outcome", "result"),
    "severity": ("severity", "level", "priority", "risk"),
}

# Guard against the class of bug where a mapping tuple omits its own canonical
# field name, which silently drops the field from every normalized event.
for _canon, _aliases in MAP.items():
    if _canon not in _aliases:
        MAP[_canon] = (_canon, *_aliases)

# Event type inference, checked against source-specific hints in priority order.
TYPE_HINTS = [
    (("logon_fail", "failed logon", "4625", "auth_fail", "invalid_password"), "logon_failed"),
    (("logon_ok", "successful logon", "4624", "auth_ok", "login_success"), "logon_success"),
    (("logoff", "4634", "logout"), "logoff"),
    (("process_create", "4688", "execve", "process started", "exec"), "process_create"),
    (("dns_query", "dns", "qname"), "dns_query"),
    (("file_access", "4663", "file_read", "open_file"), "file_access"),
    (("network", "connection", "5156", "netconn", "net_connect"), "network_connect"),
    (("email", "phish", "smtp"), "email_event"),
    (("proxy", "http", "web_request"), "http_request"),
]

SOURCE_PREFIXES = {
    "win_sec": "windows_security",
    "windows": "windows_security",
    "firewall": "firewall",
    "dns": "dns",
    "proxy": "proxy",
    "email": "email_gateway",
    "edr": "edr",
    "ot": "ot_gateway",
    "syslog": "syslog",
}


def _infer_type(record: dict[str, Any], source: str) -> str:
    blob = " ".join(
        str(v).lower() for v in record.values() if isinstance(v, (str, int))
    )
    for needles, etype in TYPE_HINTS:
        if any(n in blob for n in needles):
            return etype
    if source == "dns":
        return "dns_query"
    if source == "firewall":
        return "network_connect"
    if source == "proxy":
        return "http_request"
    return "generic"


def _infer_source(record: dict[str, Any], hint: str | None) -> str:
    explicit = _s(_first(record, "source", "log_source", "channel", "log_channel"))
    if explicit:
        low = explicit.lower()
        for prefix, canon in SOURCE_PREFIXES.items():
            if prefix in low:
                return canon
        return low.replace(" ", "_")[:40]
    if hint:
        low = hint.lower()
        for prefix, canon in SOURCE_PREFIXES.items():
            if prefix in low:
                return canon
        return low.replace(" ", "_")[:40]
    return "unknown"


def normalize_record(record: dict[str, Any], source_hint: str | None = None) -> dict[str, Any]:
    source = _infer_source(record, source_hint)
    etype = _infer_type(record, source)

    rec = base_record(record, source, etype)

    for target, aliases in MAP.items():
        val = _first(record, *aliases)
        if target == "dst_port":
            rec[target] = _i(val)
        elif target == "bytes_out":
            rec[target] = _i(val)
        elif target == "severity":
            rec[target] = _sev(val)
        else:
            rec[target] = _s(val)

    ts_value = _first(record, *MAP["ts_raw"], "timestamp", "time")
    iso, status = normalize_ts(_s(ts_value), _s(_first(record, "tz", "timezone")))
    rec["ts_raw"] = _s(ts_value)
    rec["ts_utc"] = iso
    rec["ts_status"] = status

    # An explicit event_type field from the source wins over inference.
    explicit_type = _s(_first(record, "event_type", "type", "EventType", "category"))
    if explicit_type and explicit_type.lower() not in ("", "generic"):
        rec["event_type"] = explicit_type.lower().replace(" ", "_")[:40]

    return rec
