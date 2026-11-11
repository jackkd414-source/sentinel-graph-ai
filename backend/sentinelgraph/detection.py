"""Deterministic detection engine.

Every rule here is a plain function over normalized events. No LLM, no network,
no randomness. Each rule returns alerts that carry the exact event IDs that
justify them - that is what the UI uses to render "why did this fire".

Deliberate honesty: these are correlation heuristics with published logic.
They are NOT zero-day detection. Severity reflects investigative priority, not
proof of compromise.
"""
from __future__ import annotations

import json
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from .timeutil import parse_iso

# --------------------------------------------------------------------------
# Tunables - surfaced in docs so reviewers can see exactly what we assume.
# --------------------------------------------------------------------------
FAILED_LOGON_THRESHOLD = 4          # failures before a success counts as a burst
FAILED_LOGON_WINDOW_S = 15 * 60     # burst must fit in this window
CROSS_HOST_THRESHOLD = 3            # distinct hosts for one user in window
CROSS_HOST_WINDOW_S = 20 * 60
EXFIL_WINDOW_S = 30 * 60
EXFIL_BYTES_THRESHOLD = 5_000_000   # ~5 MB outbound after sensitive access
BASELINE_FACTOR = 4.0               # x mean hourly volume => anomaly

SENSITIVE_PATHS = (
    "\\documents", "\\desktop", "\\finance", "\\hr", "\\shared",
    "/documents", "/home/", "/etc/", "confidential", "payroll", "customer",
    ".kdbx", "id_rsa", ".pst", ".ost",
)

HIGH_RISK_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe",
    "acrobat.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "chrome.exe", "firefox.exe", "edge.exe", "msedge.exe",
}

SHELL_CHILDREN = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "certutil.exe",
    "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "curl.exe", "invoke-webrequest",
}


@dataclass
class AlertDraft:
    rule_id: str
    title: str
    severity: str
    narrative: str
    host: str | None
    user_name: str | None
    first_ts: str | None
    last_ts: str | None
    event_ids: list[int] = field(default_factory=list)
    trigger_event_id: int | None = None
    dedup_key: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def _ts(ev: dict[str, Any]):
    return parse_iso(ev.get("ts_utc"))


def _ordered(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort by normalized timestamp; undated events go last, never first."""
    dated = [e for e in events if e.get("ts_utc")]
    undated = [e for e in events if not e.get("ts_utc")]
    dated.sort(key=lambda e: e["ts_utc"])
    return dated + undated


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

def rule_failed_then_success(events: list[dict[str, Any]]) -> list[AlertDraft]:
    """R-001 - failed logon burst followed by a success for the same account."""
    out: list[AlertDraft] = []
    failures: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for ev in _ordered(events):
        if ev.get("event_type") != "logon_failed":
            continue
        key = ((ev.get("user_name") or "?"), (ev.get("host") or "?"))
        failures[key].append(ev)

    for (user, host), fails in failures.items():
        if len(fails) < FAILED_LOGON_THRESHOLD:
            continue
        # find a success after the burst that fits the window
        window = [f for f in fails]
        for i in range(len(window) - FAILED_LOGON_THRESHOLD + 1):
            burst = window[i : i + FAILED_LOGON_THRESHOLD]
            t0, t1 = _ts(burst[0]), _ts(burst[-1])
            if not t0 or not t1:
                continue
            if (t1 - t0).total_seconds() > FAILED_LOGON_WINDOW_S:
                continue
            success = next(
                (
                    ev
                    for ev in _ordered(events)
                    if ev.get("event_type") == "logon_success"
                    and (ev.get("user_name") or "?") == user
                    and (ev.get("host") or "?") == host
                    and (t := _ts(ev))
                    and t >= t1
                    and (t - t0).total_seconds() <= FAILED_LOGON_WINDOW_S * 2
                ),
                None,
            )
            ids = [e["id"] for e in burst]
            trigger = None
            if success:
                ids.append(success["id"])
                trigger = success["id"]
            # The title must state exactly what happened. Claiming a success
            # occurred when the burst was never followed by one would be a
            # false statement embedded in the finding itself.
            title = (
                f"Failed logon burst then success for '{user}' on {host}"
                if success else
                f"Failed logon burst for '{user}' on {host} (no successful logon observed)"
            )
            out.append(
                AlertDraft(
                    rule_id="R-001",
                    title=title,
                    severity="high" if success else "medium",
                    narrative=(
                        f"{len(burst)} failed authentications for account '{user}' on host "
                        f"'{host}' occurred between {burst[0].get('ts_raw')} and "
                        f"{burst[-1].get('ts_raw')} (window {FAILED_LOGON_WINDOW_S // 60} min). "
                        + (
                            f"A successful logon followed at {success.get('ts_raw')}, which is "
                            "consistent with password guessing or credential stuffing. "
                            "This is a correlation finding, not proof of compromise."
                            if success
                            else "No successful logon followed inside the correlation window; "
                            "treat as an attempted intrusion."
                        )
                    ),
                    host=host if host != "?" else None,
                    user_name=user if user != "?" else None,
                    first_ts=burst[0].get("ts_utc"),
                    last_ts=(success or burst[-1]).get("ts_utc"),
                    event_ids=ids,
                    trigger_event_id=trigger,
                    dedup_key=f"R-001:{user}:{host}:{burst[0].get('ts_utc')}",
                )
            )
            break
    return out


def rule_suspicious_child(events: list[dict[str, Any]]) -> list[AlertDraft]:
    """R-002 - process spawned by a high-risk parent (phishing execution chain)."""
    out = []
    for ev in _ordered(events):
        if ev.get("event_type") != "process_create":
            continue
        parent = (ev.get("parent_process") or "").lower().strip()
        child = (ev.get("process_name") or "").lower().strip()
        if not parent:
            continue
        parent_base = parent.split("\\")[-1]
        if parent_base not in HIGH_RISK_PARENTS:
            continue
        child_base = child.split("\\")[-1]
        shell = child_base in SHELL_CHILDREN
        out.append(
            AlertDraft(
                rule_id="R-002",
                title=f"Suspicious process chain: {parent_base} -> {child_base or 'unknown'}",
                severity="high" if shell else "medium",
                narrative=(
                    f"Process '{ev.get('process_name')}' (PID {ev.get('process_id')}) was "
                    f"spawned by '{ev.get('parent_process')}' on host "
                    f"'{ev.get('host')}' at {ev.get('ts_raw')}. "
                    f"Command line: {ev.get('command_line') or 'not captured'}. "
                    + (
                        "The child is a scripting/transfer utility, a pattern consistent with "
                        "phishing payload execution. Observed fact: the parent-child relation "
                        "is in the event data. Interpretation: intent is inferred."
                        if shell
                        else "High-risk parent/child pairing; command line review is required."
                    )
                ),
                host=ev.get("host"),
                user_name=ev.get("user_name"),
                first_ts=ev.get("ts_utc"),
                last_ts=ev.get("ts_utc"),
                event_ids=[ev["id"]],
                trigger_event_id=ev["id"],
                dedup_key=f"R-002:{ev.get('host')}:{ev.get('process_id')}:{ev.get('ts_utc')}",
            )
        )
    return out


def rule_ioc_match(events: list[dict[str, Any]], iocs: list[dict[str, Any]]) -> list[AlertDraft]:
    """R-003 - network destination matches a local threat-intel indicator."""
    by_value: dict[str, dict[str, Any]] = {}
    for ioc in iocs:
        by_value[str(ioc["value"]).lower()] = ioc

    out = []
    _ioc_buckets: dict[str, AlertDraft] = {}
    for ev in _ordered(events):
        hits: list[tuple[str, str, dict[str, Any]]] = []  # (field, matched_value, ioc)
        for field_name in ("dst_ip", "domain", "url", "file_hash"):
            val = (ev.get(field_name) or "").lower().strip()
            if not val:
                continue
            if val in by_value:
                hits.append((field_name, val, by_value[val]))
                continue
            # domain suffix match only on label boundary
            if field_name in ("domain", "url"):
                for key, ioc in by_value.items():
                    if ioc["ioc_type"] == "domain" and (
                        val == key or val.endswith("." + key) or val.startswith(key + "/")
                        or f"//{key}" in val or f".{key}/" in val
                    ):
                        hits.append((field_name, key, ioc))
                        break
        if not hits:
            continue
        hit_desc = ", ".join(
            f"{field}={value}" if value == (ev.get(field) or "").lower() else f"{field}~{value}"
            for field, value, _ in hits
        )
        labels = sorted({str(ioc.get("threat_label")) for _, _, ioc in hits})
        primary = hits[0][1]
        key = f"R-003:{ev.get('host')}:{primary}"
        # One alert per (host, indicator): collapse DNS + connection events that
        # describe the same contact instead of emitting one alert per event.
        merged = _ioc_buckets.get(key)
        if merged is not None:
            merged.event_ids.append(ev["id"])
            if ev.get("ts_utc"):
                merged.first_ts = min(filter(None, [merged.first_ts, ev["ts_utc"]]))
                merged.last_ts = max(filter(None, [merged.last_ts, ev["ts_utc"]]))
            continue
        draft = AlertDraft(
            rule_id="R-003",
            title=f"Communication with known indicator on {ev.get('host') or 'unknown host'}",
            severity="critical",
            narrative=(
                f"Event matched local threat-intelligence entries: {hit_desc}. "
                f"Label(s): {'; '.join(labels) or 'unspecified'}. "
                f"Observed: destination {ev.get('dst_ip') or ev.get('domain') or ev.get('url')} "
                f"on host '{ev.get('host')}' at {ev.get('ts_raw')}. "
                "The IOC match is a fact; that the host is compromised is a hypothesis "
                "requiring process and data-flow corroboration."
            ),
            host=ev.get("host"),
            user_name=ev.get("user_name"),
            first_ts=ev.get("ts_utc"),
            last_ts=ev.get("ts_utc"),
            event_ids=[ev["id"]],
            trigger_event_id=ev["id"],
            dedup_key=key,
        )
        _ioc_buckets[key] = draft
        out.append(draft)
    return out


def rule_collect_then_exfiltrate(events: list[dict[str, Any]]) -> list[AlertDraft]:
    """R-004 - sensitive file access followed by large outbound transfer."""
    out = []
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in _ordered(events):
        if ev.get("host"):
            by_host[ev["host"]].append(ev)

    for host, evs in by_host.items():
        sensitive = [
            ev for ev in evs
            if ev.get("event_type") == "file_access"
            and ev.get("file_path")
            and any(p in (ev["file_path"] or "").lower() for p in SENSITIVE_PATHS)
        ]
        if not sensitive:
            continue
        big_flows = [
            ev for ev in evs
            if ev.get("bytes_out")
            and ev["bytes_out"] >= EXFIL_BYTES_THRESHOLD
        ]
        for acc in sensitive:
            t_acc = _ts(acc)
            if not t_acc:
                continue
            for flow in big_flows:
                t_flow = _ts(flow)
                if not t_flow:
                    continue
                delta = (t_flow - t_acc).total_seconds()
                if not (0 <= delta <= EXFIL_WINDOW_S):
                    continue
                out.append(
                    AlertDraft(
                        rule_id="R-004",
                        title=f"Sensitive file access followed by outbound transfer on {host}",
                        severity="high",
                        narrative=(
                            f"Host '{host}' accessed sensitive path '{acc.get('file_path')}' "
                            f"at {acc.get('ts_raw')}, then sent {flow['bytes_out']:,} bytes to "
                            f"{flow.get('dst_ip') or flow.get('domain') or 'unknown destination'} "
                            f"at {flow.get('ts_raw')} ({int(delta)}s later). "
                            f"Both events are observed facts. Whether data left the network is "
                            f"NOT established by these events alone - the transfer may be "
                            f"unrelated or legitimate."
                        ),
                        host=host,
                        user_name=acc.get("user_name") or flow.get("user_name"),
                        first_ts=acc.get("ts_utc"),
                        last_ts=flow.get("ts_utc"),
                        event_ids=[acc["id"], flow["id"]],
                        trigger_event_id=flow["id"],
                        dedup_key=f"R-004:{host}:{acc['id']}:{flow['id']}",
                    )
                )
                break
    return out


def rule_cross_host(events: list[dict[str, Any]]) -> list[AlertDraft]:
    """R-005 - one account authenticating to several hosts in a short window."""
    out = []
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in _ordered(events):
        if ev.get("event_type") in ("logon_success", "logon_failed") and ev.get("user_name"):
            by_user[ev["user_name"]].append(ev)

    for user, evs in by_user.items():
        timed = [e for e in evs if e.get("ts_utc")]
        timed.sort(key=lambda e: e["ts_utc"])
        n = len(timed)
        for i in range(n):
            t0 = _ts(timed[i])
            if not t0:
                continue
            j = i
            hosts: dict[str, dict[str, Any]] = {}
            while j < n:
                tj = _ts(timed[j])
                if not tj or (tj - t0).total_seconds() > CROSS_HOST_WINDOW_S:
                    break
                if timed[j].get("host"):
                    hosts.setdefault(timed[j]["host"], timed[j])
                j += 1
            if len(hosts) >= CROSS_HOST_THRESHOLD:
                ids = [e["id"] for e in timed[i:j]]
                out.append(
                    AlertDraft(
                        rule_id="R-005",
                        title=f"Account '{user}' authenticated to {len(hosts)} hosts in "
                              f"{CROSS_HOST_WINDOW_S // 60} min",
                        severity="medium",
                        narrative=(
                            f"Account '{user}' authenticated to {', '.join(sorted(hosts))} "
                            f"within {CROSS_HOST_WINDOW_S // 60} minutes. This is the earliest "
                            "observable signal of lateral movement, but administrators, service "
                            "accounts, and jump hosts produce the same pattern. Corroborate with "
                            "process and share access before escalating."
                        ),
                        host=",".join(sorted(hosts))[:200],
                        user_name=user,
                        first_ts=timed[i].get("ts_utc"),
                        last_ts=timed[j - 1].get("ts_utc") if j - 1 < n else timed[-1].get("ts_utc"),
                        event_ids=ids,
                        dedup_key=f"R-005:{user}:{timed[i].get('ts_utc')}",
                    )
                )
                return out
    return out


def rule_volume_anomaly(events: list[dict[str, Any]]) -> list[AlertDraft]:
    """R-006 - per-host hourly volume far above the observed baseline.

    Baseline is computed from the loaded dataset only. With a small demo set
    this rule is weak by construction - we say so instead of hiding it.
    """
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if not ev.get("ts_utc") or not ev.get("host"):
            continue
        hour = ev["ts_utc"][:13]  # YYYY-MM-DDTHH
        buckets[(ev["host"], hour)].append(ev)

    if len(buckets) < 6:
        return []

    counts = [len(v) for v in buckets.values()]
    mean = statistics.fmean(counts)
    if mean <= 0:
        return []
    threshold = mean * BASELINE_FACTOR

    out = []
    for (host, hour), evs in buckets.items():
        if len(evs) < threshold:
            continue
        out.append(
            AlertDraft(
                rule_id="R-006",
                title=f"Event volume spike on {host} at {hour}:00 UTC",
                severity="low",
                narrative=(
                    f"Host '{host}' produced {len(evs)} events in hour {hour} UTC, versus a "
                    f"dataset mean of {mean:.1f} events/hour and a threshold of "
                    f"{threshold:.1f} (mean x {BASELINE_FACTOR}). This flags volume, not "
                    "malice. Because the baseline is derived from a small synthetic dataset, "
                    "treat this rule as illustrative rather than production-calibrated."
                ),
                host=host,
                user_name=None,
                first_ts=min(e["ts_utc"] for e in evs),
                last_ts=max(e["ts_utc"] for e in evs),
                event_ids=[e["id"] for e in evs][:50],
                dedup_key=f"R-006:{host}:{hour}",
            )
        )
    return out


RULES: list[tuple[str, Callable[..., list[AlertDraft]]]] = [
    ("R-001", rule_failed_then_success),
    ("R-002", rule_suspicious_child),
    ("R-003", rule_ioc_match),
    ("R-004", rule_collect_then_exfiltrate),
    ("R-005", rule_cross_host),
    ("R-006", rule_volume_anomaly),
]


def run_all(
    events: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
    enabled_rules: set[str] | None = None,
) -> tuple[list[AlertDraft], list[dict[str, str]]]:
    """Execute every enabled rule.

    Returns (alerts, engine_errors). Engine errors are surfaced to the caller
    and shown in the UI rather than swallowed - a silently dead rule is worse
    than a visibly broken one.
    """
    alerts: list[AlertDraft] = []
    errors: list[dict[str, str]] = []
    for rule_id, fn in RULES:
        if enabled_rules is not None and rule_id not in enabled_rules:
            continue
        try:
            if rule_id == "R-003":
                alerts.extend(fn(events, iocs))
            else:
                alerts.extend(fn(events))
        except Exception as exc:  # noqa: BLE001
            # A broken rule must not take the pipeline down, but it must be
            # reported. We do NOT emit a fake alert; we record the failure.
            errors.append({
                "rule_id": rule_id,
                "error": f"{type(exc).__name__}: {exc}"[:300],
            })
    return alerts, errors


def rules_metadata() -> list[dict[str, Any]]:
    from .db import get_conn, rows_to_dicts
    cur = get_conn().execute("SELECT * FROM rules ORDER BY id")
    return rows_to_dicts(cur.fetchall())
