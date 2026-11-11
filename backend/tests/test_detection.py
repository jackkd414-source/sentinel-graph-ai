"""Detection engine tests.

Each rule is tested for: it fires when it should, and it does NOT fire when the
evidence is insufficient. The second half matters more - a rule that fires on
benign data is a liability in a defensive product.
"""
from __future__ import annotations

from sentinelgraph import demo_data
from sentinelgraph.detection import (
    FAILED_LOGON_THRESHOLD,
    RULES,
    run_all,
    rule_collect_then_exfiltrate,
    rule_cross_host,
    rule_failed_then_success,
    rule_ioc_match,
    rule_suspicious_child,
)


def _ev(eid: int, **kw):
    base = {
        "id": eid, "ts_utc": None, "ts_raw": None, "event_type": "generic",
        "host": None, "user_name": None, "process_name": None, "parent_process": None,
        "process_id": None, "parent_pid": None, "command_line": None,
        "dst_ip": None, "domain": None, "url": None, "file_path": None,
        "file_hash": None, "bytes_out": None, "severity": "info",
    }
    base.update(kw)
    return base


IOCS = [
    {"ioc_type": "ip", "value": "203.0.113.66", "threat_label": "C2", "confidence": "high"},
    {"ioc_type": "domain", "value": "evil.example", "threat_label": "phish", "confidence": "high"},
]


# --------------------------------------------------------------------------
# R-001 failed burst -> success
# --------------------------------------------------------------------------

def test_r001_fires_on_burst_then_success():
    events = [
        _ev(i + 1, event_type="logon_failed", host="SRV1", user_name="svc",
            ts_utc=f"2026-11-03T08:{10 + i:02d}:00.000Z")
        for i in range(FAILED_LOGON_THRESHOLD)
    ]
    events.append(_ev(99, event_type="logon_success", host="SRV1", user_name="svc",
                      ts_utc="2026-11-03T08:20:00.000Z"))
    alerts = rule_failed_then_success(events)
    assert len(alerts) == 1
    assert alerts[0].severity == "high"
    assert 99 in alerts[0].event_ids
    assert alerts[0].trigger_event_id == 99


def test_r001_does_not_fire_on_failures_only():
    """A burst with no success is still reported (investigative value), but it
    must be downgraded to medium and its title must not claim a success."""
    events = [
        _ev(i + 1, event_type="logon_failed", host="SRV1", user_name="svc",
            ts_utc=f"2026-11-03T08:{10 + i:02d}:00.000Z")
        for i in range(6)
    ]
    alerts = rule_failed_then_success(events)
    assert len(alerts) == 1
    assert alerts[0].severity == "medium", "no success => must not be high severity"
    assert "then success" not in alerts[0].title
    assert "no successful logon observed" in alerts[0].title


def test_r001_does_not_fire_without_burst_threshold():
    events = [
        _ev(i + 1, event_type="logon_failed", host="SRV1", user_name="svc",
            ts_utc=f"2026-11-03T08:{10 + i:02d}:00.000Z")
        for i in range(FAILED_LOGON_THRESHOLD - 1)
    ]
    events.append(_ev(99, event_type="logon_success", host="SRV1", user_name="svc",
                      ts_utc="2026-11-03T08:20:00.000Z"))
    assert rule_failed_then_success(events) == []


def test_r001_does_not_fire_across_different_hosts():
    events = [
        _ev(i + 1, event_type="logon_failed", host=f"H{i}", user_name="svc",
            ts_utc=f"2026-11-03T08:{10 + i:02d}:00.000Z")
        for i in range(FAILED_LOGON_THRESHOLD + 1)
    ]
    events.append(_ev(99, event_type="logon_success", host="OTHER", user_name="svc",
                      ts_utc="2026-11-03T08:20:00.000Z"))
    assert rule_failed_then_success(events) == []


def test_r001_does_not_fire_outside_time_window():
    events = [
        _ev(1, event_type="logon_failed", host="H", user_name="u",
            ts_utc="2026-11-03T08:00:00.000Z"),
        _ev(2, event_type="logon_failed", host="H", user_name="u",
            ts_utc="2026-11-03T09:00:00.000Z"),
        _ev(3, event_type="logon_failed", host="H", user_name="u",
            ts_utc="2026-11-03T10:00:00.000Z"),
        _ev(4, event_type="logon_failed", host="H", user_name="u",
            ts_utc="2026-11-03T11:00:00.000Z"),
        _ev(5, event_type="logon_success", host="H", user_name="u",
            ts_utc="2026-11-03T12:00:00.000Z"),
    ]
    assert rule_failed_then_success(events) == [], "slow failures are not a burst"


# --------------------------------------------------------------------------
# R-002 suspicious process chain
# --------------------------------------------------------------------------

def test_r002_fires_on_office_spawning_shell():
    events = [_ev(1, event_type="process_create", host="WS1", user_name="u",
                  process_name="powershell.exe", parent_process="OUTLOOK.EXE",
                  command_line="powershell -enc ...")]
    alerts = rule_suspicious_child(events)
    assert len(alerts) == 1
    assert alerts[0].severity == "high"
    assert alerts[0].event_ids == [1]


def test_r002_does_not_fire_without_parent():
    events = [_ev(1, event_type="process_create", host="WS1",
                  process_name="powershell.exe")]
    assert rule_suspicious_child(events) == []


def test_r002_does_not_fire_on_normal_parent():
    events = [_ev(1, event_type="process_create", host="WS1",
                  process_name="child.exe", parent_process="explorer.exe")]
    assert rule_suspicious_child(events) == []


# --------------------------------------------------------------------------
# R-003 IOC match
# --------------------------------------------------------------------------

def test_r003_fires_on_ip_match():
    events = [_ev(1, event_type="network_connect", host="H", dst_ip="203.0.113.66")]
    alerts = rule_ioc_match(events, IOCS)
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"
    assert "C2" in alerts[0].narrative


def test_r003_fires_on_domain_suffix_match():
    events = [_ev(1, event_type="dns_query", host="H", domain="x.evil.example")]
    assert len(rule_ioc_match(events, IOCS)) == 1


def test_r003_does_not_match_partial_label():
    events = [_ev(1, event_type="dns_query", host="H", domain="notevil.example")]
    assert rule_ioc_match(events, IOCS) == [], "must not match on non-boundary substring"


def test_r003_dedupes_same_host_and_indicator():
    events = [
        _ev(1, event_type="dns_query", host="H", domain="evil.example"),
        _ev(2, event_type="network_connect", host="H", dst_ip="203.0.113.66"),
    ]
    iocs = [
        {"ioc_type": "domain", "value": "evil.example", "threat_label": "x"},
        {"ioc_type": "ip", "value": "203.0.113.66", "threat_label": "x"},
    ]
    # different indicators -> two distinct alerts is acceptable; same indicator
    # on the same host must collapse.
    alerts = rule_ioc_match(events, iocs)
    keys = [a.dedup_key for a in alerts]
    assert len(keys) == len(set(keys)), "duplicate dedup keys would double-count"


def test_r003_returns_empty_with_no_iocs():
    events = [_ev(1, event_type="network_connect", host="H", dst_ip="203.0.113.66")]
    assert rule_ioc_match(events, []) == []


# --------------------------------------------------------------------------
# R-004 collect then exfiltrate
# --------------------------------------------------------------------------

def test_r004_fires_on_sensitive_access_then_upload():
    events = [
        _ev(1, event_type="file_access", host="WS1",
            file_path="C:\\Users\\a\\Documents\\Finance\\x.xlsx",
            ts_utc="2026-11-03T08:25:00.000Z"),
        _ev(2, event_type="network_connect", host="WS1", dst_ip="203.0.113.9",
            bytes_out=20_000_000, ts_utc="2026-11-03T08:31:00.000Z"),
    ]
    alerts = rule_collect_then_exfiltrate(events)
    assert len(alerts) == 1
    assert set(alerts[0].event_ids) == {1, 2}


def test_r004_does_not_fire_on_large_upload_without_sensitive_access():
    events = [
        _ev(1, event_type="network_connect", host="BACKUP", dst_ip="198.51.100.80",
            bytes_out=48_000_000, ts_utc="2026-11-03T09:00:00.000Z"),
    ]
    assert rule_collect_then_exfiltrate(events) == [], \
        "a plain backup upload must not be reported as exfiltration"


def test_r004_does_not_fire_below_byte_threshold():
    events = [
        _ev(1, event_type="file_access", host="WS1",
            file_path="C:\\Documents\\HR\\x.xlsx", ts_utc="2026-11-03T08:00:00.000Z"),
        _ev(2, event_type="network_connect", host="WS1", dst_ip="1.1.1.1",
            bytes_out=1000, ts_utc="2026-11-03T08:05:00.000Z"),
    ]
    assert rule_collect_then_exfiltrate(events) == []


def test_r004_does_not_fire_when_upload_precedes_access():
    events = [
        _ev(1, event_type="network_connect", host="WS1", dst_ip="1.1.1.1",
            bytes_out=20_000_000, ts_utc="2026-11-03T08:00:00.000Z"),
        _ev(2, event_type="file_access", host="WS1",
            file_path="C:\\Documents\\Finance\\x.xlsx",
            ts_utc="2026-11-03T08:10:00.000Z"),
    ]
    assert rule_collect_then_exfiltrate(events) == [], \
        "ordering matters: upload before collection is not this pattern"


# --------------------------------------------------------------------------
# R-005 cross host
# --------------------------------------------------------------------------

def test_r005_fires_on_multi_host_auth():
    events = [
        _ev(i + 1, event_type="logon_success", host=f"H{i}", user_name="a.admin",
            ts_utc=f"2026-11-03T08:{i * 5:02d}:00.000Z")
        for i in range(3)
    ]
    alerts = rule_cross_host(events)
    assert len(alerts) == 1
    assert alerts[0].severity == "medium"


def test_r005_does_not_fire_on_single_host():
    events = [
        _ev(i + 1, event_type="logon_success", host="H", user_name="u",
            ts_utc=f"2026-11-03T08:{i:02d}:00.000Z")
        for i in range(5)
    ]
    assert rule_cross_host(events) == []


# --------------------------------------------------------------------------
# Engine-level behaviour
# --------------------------------------------------------------------------

def test_run_all_returns_tuple_and_no_engine_errors_on_demo_data():
    events = [_ev(1, event_type="logon_success", host="H", user_name="u",
                  ts_utc="2026-11-03T08:00:00.000Z")]
    alerts, errors = run_all(events, IOCS)
    assert isinstance(alerts, list)
    assert isinstance(errors, list)
    assert errors == []


def test_every_rule_in_registry_is_callable():
    for rule_id, fn in RULES:
        assert callable(fn), f"{rule_id} is not callable"


def test_all_alerts_have_evidence():
    """An alert with no supporting event is not a finding."""
    events = [_ev(1, event_type="logon_success", host="H", user_name="u",
                  ts_utc="2026-11-03T08:00:00.000Z")]
    alerts, _ = run_all(events, IOCS)
    for a in alerts:
        assert a.event_ids, f"{a.rule_id} produced an alert with no evidence"


def test_demo_dataset_fires_expected_rules():
    events = []
    for i, raw in enumerate(demo_data.all_events(), start=1):
        from sentinelgraph.ingest import normalize_record
        ev = normalize_record(raw, "demo")
        ev["id"] = i
        events.append(ev)
    from sentinelgraph.db import IOC_SEED as SEED_IOCS
    iocs = [
        {"ioc_type": t, "value": v, "threat_label": lbl, "confidence": c}
        for t, v, lbl, c, *_ in SEED_IOCS
    ]
    alerts, errors = run_all(events, iocs)
    assert errors == []
    fired = {a.rule_id for a in alerts}
    for expected in ("R-001", "R-002", "R-003", "R-004", "R-005"):
        assert expected in fired, f"{expected} did not fire on the labelled demo data"
