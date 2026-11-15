"""MITRE ATT&CK mapping for the deterministic detection rules.

The technique catalogue lives in code so names/tactics have one source of truth;
the ``rules`` table only stores the compact IDs (``attack`` column).

R-006 is deliberately unmapped: a statistical volume deviation is not a
technique - the technique depends on the activity hiding inside the spike.
Saying so is more useful to an analyst (and to a judge) than inventing a ID.
"""

from __future__ import annotations

# technique id -> (name, tactic)
ATTACK_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1005": ("Data from Local System", "Collection"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1021": ("Remote Services", "Lateral Movement"),
}

# rule id -> technique ids
RULE_ATTACK: dict[str, tuple[str, ...]] = {
    "R-001": ("T1110.001", "T1078"),
    "R-002": ("T1566.001", "T1204.002", "T1059.001"),
    "R-003": ("T1071.001", "T1105"),
    "R-004": ("T1005", "T1041"),
    "R-005": ("T1021", "T1078"),
    "R-006": (),
}

# rule id -> why no technique is attached
RULE_ATTACK_NOTE: dict[str, str] = {
    "R-006": ("Statistical volume deviation - no single ATT&CK technique; "
              "the technique depends on the activity inside the spike."),
}


def ids(rule_id: str) -> str:
    """Compact form stored in the database."""
    return ",".join(RULE_ATTACK.get(rule_id, ()))


def techniques(rule_id: str) -> list[dict[str, str]]:
    """Resolved form returned by the API."""
    return [
        {"id": t, "name": ATTACK_TECHNIQUES[t][0], "tactic": ATTACK_TECHNIQUES[t][1]}
        for t in RULE_ATTACK.get(rule_id, ())
    ]


def note(rule_id: str) -> str:
    return RULE_ATTACK_NOTE.get(rule_id, "")


def summary_line(rule_id: str) -> str:
    """One-line rendering for reports (empty when unmapped and no note)."""
    techs = techniques(rule_id)
    if techs:
        return " · ".join(f"{t['id']} {t['name']}" for t in techs)
    return note(rule_id)
