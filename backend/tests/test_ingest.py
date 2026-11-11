"""Ingestion and normalization tests.

Focus: the parser must be honest. Missing fields stay NULL, bad timestamps are
flagged, and failures are counted - never silently coerced into plausible data.
"""
from __future__ import annotations

import json

import pytest

from sentinelgraph.ingest import (
    MAP,
    parse_csv_text,
    parse_json_text,
    parse_jsonl_text,
)
from sentinelgraph.timeutil import normalize_ts


# --------------------------------------------------------------------------
# Timestamp normalization
# --------------------------------------------------------------------------

def test_iso_with_z_is_ok():
    iso, status = normalize_ts("2026-11-03T08:12:00Z")
    assert status == "ok"
    assert iso == "2026-11-03T08:12:00.000Z"


def test_iso_with_offset_converts_to_utc():
    iso, status = normalize_ts("2026-11-03T15:12:00+07:00")
    assert status == "ok"
    assert iso == "2026-11-03T08:12:00.000Z"


def test_naive_time_is_marked_assumed_not_ok():
    iso, status = normalize_ts("2026-11-03 15:12:00")
    assert status == "assumed", "a timestamp without tz must never claim 'ok'"
    assert iso == "2026-11-03T08:12:00.000Z"  # interpreted as WIB


def test_missing_timestamp_is_reported_as_missing():
    for value in (None, "", "   "):
        iso, status = normalize_ts(value)
        assert iso is None
        assert status == "missing"


def test_garbage_timestamp_is_invalid_not_fabricated():
    for bad in ("not-a-date", "2026-13-45T99:99:99Z", "yesterday"):
        iso, status = normalize_ts(bad)
        assert iso is None, f"{bad!r} must not produce a timestamp"
        assert status == "invalid"


def test_windows_locale_timestamp_parses():
    iso, status = normalize_ts("11/3/2026 9:14:22 AM")
    assert status == "assumed"
    assert iso is not None
    assert iso.startswith("2026-11-03T02:14:22")


def test_epoch_seconds_and_millis():
    s, st1 = normalize_ts("1762157520")
    ms, st2 = normalize_ts("1762157520000")
    assert st1 == st2 == "ok"
    assert s == ms


# --------------------------------------------------------------------------
# JSON / JSONL / CSV
# --------------------------------------------------------------------------

def test_json_array_parses_all_records():
    body = json.dumps([
        {"timestamp": "2026-11-03T08:00:00Z", "host": "H1", "event_type": "logon_failed",
         "user_name": "u1"},
        {"timestamp": "2026-11-03T08:01:00Z", "host": "H2", "event_type": "logon_success",
         "user_name": "u2"},
    ])
    r = parse_json_text(body)
    assert r.total == 2
    assert len(r.events) == 2
    assert r.failed == []
    assert r.events[0]["host"] == "H1"
    assert r.events[0]["user_name"] == "u1"


def test_json_envelope_with_events_key():
    body = json.dumps({"events": [{"ts": "2026-11-03T08:00:00Z", "host": "H"}]})
    r = parse_json_text(body)
    assert len(r.events) == 1


def test_invalid_json_raises_adapter_error():
    from sentinelgraph.ingest import AdapterError
    with pytest.raises(AdapterError):
        parse_json_text("{not json")


def test_jsonl_isolates_bad_lines():
    body = "\n".join([
        json.dumps({"ts": "2026-11-03T08:00:00Z", "host": "H1"}),
        "{broken json",
        json.dumps({"ts": "2026-11-03T08:02:00Z", "host": "H2"}),
    ])
    r = parse_jsonl_text(body)
    assert len(r.events) == 2
    assert len(r.failed) == 1
    assert "invalid JSON" in r.failed[0]["reason"]


def test_csv_parses_and_counts_failures_separately():
    csv_body = (
        "timestamp,host,user_name,event_type\n"
        "2026-11-03T08:00:00Z,H1,alice,logon_failed\n"
        "not-a-date,H2,bob,logon_failed\n"
    )
    r = parse_csv_text(csv_body)
    assert r.total == 2
    assert len(r.events) == 2, "unparseable timestamp must not drop the record"
    statuses = {e["ts_status"] for e in r.events}
    assert statuses == {"ok", "invalid"}


def test_csv_semicolon_delimiter_autodetected():
    body = "timestamp;host;user_name\n2026-11-03T08:00:00Z;H1;alice\n"
    r = parse_csv_text(body)
    assert len(r.events) == 1
    assert r.events[0]["host"] == "H1"


# --------------------------------------------------------------------------
# Honesty about missing fields
# --------------------------------------------------------------------------

def test_missing_fields_stay_none_not_fabricated():
    r = parse_json_text(json.dumps([{"timestamp": "2026-11-03T08:00:00Z"}]))
    ev = r.events[0]
    for field_name in ("host", "user_name", "src_ip", "dst_ip", "process_name",
                       "file_path", "domain"):
        assert ev[field_name] is None, f"{field_name} must not be invented"


def test_map_covers_its_own_canonical_name():
    """Regression: a mapping tuple missing its own field name silently drops data."""
    for canon, aliases in MAP.items():
        assert canon in aliases, f"MAP[{canon!r}] must include {canon!r}"


def test_user_name_key_is_read_directly():
    r = parse_json_text(json.dumps([
        {"timestamp": "2026-11-03T08:00:00Z", "user_name": "svc_backup"}
    ]))
    assert r.events[0]["user_name"] == "svc_backup"


def test_alternate_user_aliases_are_mapped():
    for alias in ("user", "username", "AccountName", "TargetUserName", "SubjectUserName"):
        r = parse_json_text(json.dumps([
            {"timestamp": "2026-11-03T08:00:00Z", alias: "alice"}
        ]))
        assert r.events[0]["user_name"] == "alice", f"alias {alias} not mapped"


def test_event_type_inferred_from_source_hints():
    r = parse_json_text(json.dumps([
        {"timestamp": "2026-11-03T08:00:00Z", "EventID": 4625, "host": "H"}
    ]))
    assert r.events[0]["event_type"] == "logon_failed"


def test_non_object_record_is_counted_as_failure():
    r = parse_json_text(json.dumps(["just a string", {"ts": "2026-11-03T08:00:00Z"}]))
    assert len(r.failed) == 1
    assert len(r.events) == 1
