"""ATT&CK mapping must stay complete, valid, and visible through the API."""
from __future__ import annotations

import re

from sentinelgraph import attack_map
from sentinelgraph.db import RULE_SEED

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_every_rule_is_mapped_or_explicitly_explained():
    """A rule with no technique must carry a reason, so nothing is silently unmapped."""
    for rule in RULE_SEED:
        rule_id = rule[0]
        mapped = bool(attack_map.RULE_ATTACK.get(rule_id))
        explained = bool(attack_map.RULE_ATTACK_NOTE.get(rule_id))
        assert mapped or explained, f"{rule_id} has neither a technique nor a note"


def test_every_technique_id_valid_and_described():
    for rule_id, ids in attack_map.RULE_ATTACK.items():
        for tid in ids:
            assert TECHNIQUE_ID.match(tid), f"{rule_id}: malformed id {tid}"
            name, tactic = attack_map.ATTACK_TECHNIQUES[tid]
            assert name and tactic, f"{tid} missing name/tactic"


def test_no_orphan_techniques():
    """Catalogue entries that no rule references are dead weight."""
    used = {t for ids in attack_map.RULE_ATTACK.values() for t in ids}
    assert used == set(attack_map.ATTACK_TECHNIQUES)


def test_api_rules_expose_attack_metadata(client):
    rules = {r["id"]: r for r in client.get("/api/rules").json()["rules"]}
    r001 = rules["R-001"]
    assert {"id", "name", "tactic"} <= set(r001["attack"][0])
    assert "T1110.001" in {t["id"] for t in r001["attack"]}
    # R-006 is statistical: it must say so rather than invent a technique.
    assert rules["R-006"]["attack"] == []
    assert "statistical" in rules["R-006"]["attack_note"].lower()


def test_report_includes_attack_line(client, loaded_demo):
    """The exported report is what a reviewer reads; the mapping must appear there."""
    incidents = client.get("/api/incidents").json()["incidents"]
    assert incidents, "demo dataset should produce incidents"
    body = client.get(f"/api/incidents/{incidents[0]['id']}/report?fmt=md").text
    assert "ATT&CK" in body
    assert "T1" in body
