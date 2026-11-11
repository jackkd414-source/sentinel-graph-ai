"""Built-in synthetic demo datasets.

Ground truth is explicit so precision/recall can actually be computed instead
of asserted. Every event is generated from one of two labelled scenarios plus
deliberate noise. All IPs are from RFC 5737 documentation ranges and all
domains use reserved .example TLDs - nothing here points at real infrastructure.

Scenario A (malicious, label=malicious) - phishing-driven intrusion:
  1. email gateway flags a message with a link to a fake login portal
  2. user opens the URL (proxy)
  3. process_create: outlook.exe -> powershell.exe
  4. failed logons then success for the same account (credential guessing)
  5. host resolves + connects to a simulated C2 IP from the IOC dataset
  6. file access to a sensitive path
  7. large outbound transfer

Scenario B (benign, label=benign) - a normal working day:
  admin doing multi-host maintenance (looks like lateral movement),
  a legitimate large backup upload (looks like exfiltration),
  a normal document open by winword.exe (winword parents exist but child is
  benign), repeated failures from a stale cached credential that never succeed.

Plus deliberately broken records (invalid timestamps, missing host, duplicate)
to exercise the parser's honesty paths.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

BASE = datetime(2026, 11, 3, 8, 0, 0, tzinfo=timezone.utc)


def _t(minutes: float) -> str:
    return (BASE + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ev(**kw: Any) -> dict[str, Any]:
    return kw


def scenario_email_gateway() -> list[dict[str, Any]]:
    return [
        _ev(
            timestamp=_t(0), source="email_gateway", event_type="email_event",
            host="MAILGW-01", user_name="r.santoso", src_ip="198.51.100.23",
            action="quarantined", severity="medium", domain="secure-login-portal.example",
            url="https://secure-login-portal.example/session/verify?u=r.santoso",
            command_line=None,
            raw={"subject": "Action required: verify your corporate mailbox",
                 "sender": "it-support@secure-login-portal.example",
                 "recipient": "r.santoso@example.mil.id",
                 "attachment": "invoice_2026_11.pdf",
                 "verdict": "suspicious_link"},
        )
    ]


def scenario_a_malicious() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    # 1-2. proxy: user opens the phishing URL
    rows += [
        _ev(timestamp=_t(4), source="proxy", event_type="http_request",
            host="WS-FIN-07", user_name="r.santoso", dst_ip="198.51.100.23",
            dst_port=443, domain="secure-login-portal.example",
            url="https://secure-login-portal.example/session/verify?u=r.santoso",
            action="allowed", severity="low",
            raw={"method": "GET", "status": 200, "user_agent": "Mozilla/5.0"}),
        _ev(timestamp=_t(6), source="proxy", event_type="http_request",
            host="WS-FIN-07", user_name="r.santoso", dst_ip="198.51.100.23",
            dst_port=443, domain="secure-login-portal.example",
            url="https://secure-login-portal.example/login/submit",
            action="allowed", severity="medium",
            raw={"method": "POST", "status": 302,
                 "posted_fields": "username,password"}),
    ]

    # 3. phishing execution chain: outlook -> powershell
    rows.append(
        _ev(timestamp=_t(9), source="edr", event_type="process_create",
            host="WS-FIN-07", user_name="r.santoso",
            process_name="powershell.exe", process_id="4912",
            parent_process="OUTLOOK.EXE", parent_pid="3784",
            command_line="powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA",
            severity="high", action="process_started",
            raw={"integrity": "medium", "signature": "unsigned"})
    )

    # 4. failed logons then success (credential guessing)
    for i, m in enumerate((12, 13, 14, 15)):
        rows.append(
            _ev(timestamp=_t(m), source="windows_security", event_type="logon_failed",
                external_id="4625", host="SRV-FILE-02", user_name="svc_backup",
                src_ip="10.20.4.51", action="failure", severity="low",
                raw={"EventID": 4625, "SubStatus": "0xC000006A",
                     "LogonType": 3, "attempt": i + 1})
        )
    rows.append(
        _ev(timestamp=_t(16), source="windows_security", event_type="logon_success",
            external_id="4624", host="SRV-FILE-02", user_name="svc_backup",
            src_ip="10.20.4.51", action="success", severity="medium",
            raw={"EventID": 4624, "LogonType": 3})
    )

    # 5. DNS + C2 connection matching the IOC dataset
    rows += [
        _ev(timestamp=_t(20), source="dns", event_type="dns_query",
            host="WS-FIN-07", user_name="r.santoso",
            domain="cdn-update-delivery.example", dst_ip="203.0.113.66",
            action="query", severity="medium",
            raw={"qtype": "A", "rcode": "NOERROR"}),
        _ev(timestamp=_t(21), source="firewall", event_type="network_connect",
            host="WS-FIN-07", user_name="r.santoso",
            src_ip="10.20.4.51", dst_ip="203.0.113.66", dst_port=8443,
            action="allowed", severity="high", bytes_out=18234,
            raw={"rule": "permit-web-out", "protocol": "tcp", "sessions": 3}),
    ]

    # 6. sensitive file access (collection)
    rows += [
        _ev(timestamp=_t(25), source="windows_security", event_type="file_access",
            external_id="4663", host="WS-FIN-07", user_name="r.santoso",
            process_name="powershell.exe", process_id="4912",
            file_path="C:\\Users\\r.santoso\\Documents\\Finance\\Q4_forecast_confidential.xlsx",
            action="read", severity="medium",
            raw={"EventID": 4663, "AccessMask": "0x1"}),
        _ev(timestamp=_t(26), source="windows_security", event_type="file_access",
            external_id="4663", host="WS-FIN-07", user_name="r.santoso",
            process_name="powershell.exe", process_id="4912",
            file_path="C:\\Users\\r.santoso\\Documents\\HR\\payroll_2026.xlsx",
            action="read", severity="medium",
            raw={"EventID": 4663, "AccessMask": "0x1"}),
    ]

    # 7. large outbound transfer
    rows.append(
        _ev(timestamp=_t(31), source="firewall", event_type="network_connect",
            host="WS-FIN-07", user_name="r.santoso",
            src_ip="10.20.4.51", dst_ip="203.0.113.66", dst_port=443,
            action="allowed", severity="critical", bytes_out=14_782_464,
            raw={"rule": "permit-web-out", "protocol": "tcp",
                 "note": "sustained 3m upload"})
    )

    for r in rows:
        r.setdefault("ground_truth", "malicious")
    return rows


def scenario_b_benign() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    # admin doing maintenance on three hosts -> looks like lateral movement
    for i, host in enumerate(("SRV-FILE-02", "SRV-DC-01", "SRV-APP-05")):
        rows.append(
            _ev(timestamp=_t(120 + i * 3), source="windows_security",
                event_type="logon_success", external_id="4624", host=host,
                user_name="a.admin", src_ip="10.20.4.10", action="success",
                severity="info", raw={"EventID": 4624, "LogonType": 10,
                                      "note": "RDP maintenance window"})
        )

    # legitimate large upload (backup) - looks like exfiltration
    rows.append(
        _ev(timestamp=_t(180), source="firewall", event_type="network_connect",
            host="SRV-BACKUP-01", user_name="svc_backup",
            src_ip="10.20.4.60", dst_ip="198.51.100.80", dst_port=443,
            action="allowed", severity="info", bytes_out=48_000_000,
            raw={"rule": "permit-backup", "protocol": "tcp",
                 "note": "nightly offsite backup"})
    )

    # normal document workflow: winword is a high-risk parent, benign child
    rows.append(
        _ev(timestamp=_t(200), source="edr", event_type="process_create",
            host="WS-HR-03", user_name="d.prasetyo",
            process_name="splwow64.exe", process_id="6120",
            parent_process="WINWORD.EXE", parent_pid="5104",
            command_line="splwow64.exe 12288", severity="info",
            action="process_started", raw={"integrity": "medium"})
    )

    # repeated failures that never succeed (stale cached credential)
    for i in range(6):
        rows.append(
            _ev(timestamp=_t(240 + i), source="windows_security",
                event_type="logon_failed", external_id="4625", host="WS-HR-03",
                user_name="d.prasetyo", src_ip="10.20.4.77", action="failure",
                severity="info",
                raw={"EventID": 4625, "SubStatus": "0xC000006A",
                     "note": "cached credential after password rotation"})
        )

    for r in rows:
        r.setdefault("ground_truth", "benign")
    return rows


def broken_records() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Records that must FAIL parsing, plus records with degraded timestamps.

    Returned separately so the dataset route can inject them into the CSV/JSONL
    import path and demonstrate honest failure accounting.
    """
    failures = [
        {"timestamp": "not-a-date", "host": "WS-BAD-01", "event_type": "logon_failed",
         "user_name": "x"},
        {"timestamp": "", "host": "", "event_type": "", "note": "empty record"},
        {"ts": "2026-13-45T99:99:99Z", "host": "WS-BAD-02", "event_type": "logon_failed"},
    ]
    degraded = [
        {"timestamp": "", "host": "WS-NOTS-01", "user_name": "unknown",
         "event_type": "process_create", "process_name": "unknown.exe",
         "note": "timestamp missing in source"},
        {"timestamp": "Nov  3 09:14:22", "host": "WS-SYSLOG-01", "user_name": "svc",
         "event_type": "logon_success", "note": "syslog without year -> assumed"},
    ]
    return failures, degraded


def all_events() -> list[dict[str, Any]]:
    out = scenario_email_gateway() + scenario_a_malicious() + scenario_b_benign()
    out.sort(key=lambda e: e.get("timestamp") or "")
    return out


def ground_truth_manifest() -> dict[str, Any]:
    """Machine-readable ground truth for precision/recall measurement."""
    return {
        "dataset": "sentinelgraph-synthetic-v1",
        "synthetic": True,
        "generated_for": "SentinelGraph AI demo / evaluation",
        "malicious_hosts": ["WS-FIN-07", "SRV-FILE-02"],
        "malicious_accounts": ["r.santoso", "svc_backup"],
        "benign_hosts": ["SRV-FILE-02", "SRV-DC-01", "SRV-APP-05",
                         "SRV-BACKUP-01", "WS-HR-03"],
        "expected_rule_hits": {
            "R-001": "1 (svc_backup failed burst then success)",
            "R-002": "1 malicious (OUTLOOK->powershell) + 1 benign (WINWORD->splwow64, "
                     "expected false positive by design)",
            "R-003": "2+ (connection and DNS to 203.0.113.66 / cdn-update-delivery.example)",
            "R-004": "1 malicious (WS-FIN-07 sensitive access then 14.7MB out). "
                     "SRV-BACKUP-01 upload has no prior sensitive file access, so it must NOT fire.",
            "R-005": "1 benign (a.admin multi-host RDP) - expected false positive",
            "R-006": "dataset-dependent, low confidence by design",
        },
        "notes": [
            "IPs are RFC 5737 documentation addresses; domains use reserved .example TLD.",
            "Two deliberate false positives exist (R-002 benign parent, R-005 admin) and are "
            "counted against precision rather than hidden.",
        ],
    }


if __name__ == "__main__":  # quick manual inspection
    print(json.dumps(all_events(), indent=2)[:2000])
    print("total events:", len(all_events()))
