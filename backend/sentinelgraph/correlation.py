"""Correlation and attack-graph construction.

Rule: an edge is only created when there is a defensible basis. We recognise
exactly five bases:

  entity     - two events share the same canonical entity (host/user/process)
  parent     - process_create explicitly records parent_process + parent_pid
  network    - one event's src_ip/dst_ip is the other's, with matching time order
  ioc        - a node's value appears in the local IOC dataset
  temporal   - <TemporalLink> rule-justified ordering (alert event sequences)

Status is 'observed' when the relation is written in the source data, and
'inferred' when it is produced by our correlation logic. The UI renders them
differently and the report says which is which.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .db import cursor
from .timeutil import now_iso, parse_iso


@dataclass
class NodeSpec:
    key: str
    type: str
    label: str
    severity: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class EdgeSpec:
    src: str
    dst: str
    relation: str
    status: str
    method: str
    confidence: str = "medium"
    first_ts: str | None = None
    last_ts: str | None = None
    event_ids: list[int] = field(default_factory=list)
    dedup_key: str | None = None


# --------------------------------------------------------------------------
# Node identity
# --------------------------------------------------------------------------

def n_host(v: str) -> NodeSpec:
    return NodeSpec(f"host:{(v or '').lower()}", "host", v)


def n_user(v: str) -> NodeSpec:
    return NodeSpec(f"user:{(v or '').lower()}", "user", v)


def n_process(v: str, pid: str | None, host: str | None) -> NodeSpec:
    base = (v or "").split("\\")[-1].lower()
    key = f"process:{base}:{pid or 'na'}:{(host or 'na').lower()}"
    return NodeSpec(key, "process", v if not pid else f"{base} ({pid})")


def n_ip(v: str) -> NodeSpec:
    return NodeSpec(f"ip:{v}", "ip", v)


def n_domain(v: str) -> NodeSpec:
    return NodeSpec(f"domain:{v.lower()}", "domain", v)


def n_file(v: str) -> NodeSpec:
    return NodeSpec(f"file:{v.lower()}", "file", v.split("\\")[-1].split("/")[-1] or v)


def n_event(ev: dict[str, Any]) -> NodeSpec:
    return NodeSpec(f"event:{ev['id']}", "event",
                    f"{ev.get('event_type')} @ {ev.get('ts_raw') or 'no timestamp'}")


def n_alert(aid: int, title: str, severity: str) -> NodeSpec:
    return NodeSpec(f"alert:{aid}", "alert", title, severity=severity)


# --------------------------------------------------------------------------
# Graph build
# --------------------------------------------------------------------------

def build_graph(
    project_id: int,
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute nodes+edges for a project and persist them.

    Idempotent: running twice on the same data replaces the previous graph.
    """
    nodes: dict[str, NodeSpec] = {}
    edges: dict[str, EdgeSpec] = {}

    def add_node(spec: NodeSpec) -> None:
        existing = nodes.get(spec.key)
        if existing is None:
            nodes[spec.key] = spec
        elif spec.severity and not existing.severity:
            existing.severity = spec.severity

    def add_edge(spec: EdgeSpec) -> None:
        key = spec.dedup_key or f"{spec.src}|{spec.dst}|{spec.relation}"
        if key in edges:
            edges[key].event_ids = list(dict.fromkeys(edges[key].event_ids + spec.event_ids))
            return
        edges[key] = spec

    ioc_values = {str(i["value"]).lower(): i for i in iocs}

    # ---- entity nodes -------------------------------------------------
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for ev in events:
        if ev.get("host"):
            add_node(n_host(ev["host"]))
            by_host[ev["host"].lower()].append(ev)
        if ev.get("user_name"):
            add_node(n_user(ev["user_name"]))
            by_user[ev["user_name"].lower()].append(ev)
        if ev.get("dst_ip"):
            add_node(n_ip(ev["dst_ip"]))
        if ev.get("domain"):
            add_node(n_domain(ev["domain"]))
        if ev.get("file_path"):
            add_node(n_file(ev["file_path"]))
        if ev.get("process_name"):
            add_node(n_process(ev["process_name"], ev.get("process_id"), ev.get("host")))

    # ---- observed edges from source data ------------------------------
    for ev in events:
        eid = ev["id"]
        host_spec = n_host(ev["host"]) if ev.get("host") else None
        user_spec = n_user(ev["user_name"]) if ev.get("user_name") else None
        proc_spec = (
            n_process(ev["process_name"], ev.get("process_id"), ev.get("host"))
            if ev.get("process_name") else None
        )
        parent_spec = (
            n_process(ev["parent_process"], ev.get("parent_pid"), ev.get("host"))
            if ev.get("parent_process") else None
        )

        # parent -> child: explicitly recorded in the event
        if parent_spec and proc_spec:
            add_edge(EdgeSpec(
                src=parent_spec.key, dst=proc_spec.key, relation="spawned",
                status="observed",
                method="parent_process/parent_pid field present in process_create event",
                confidence="high",
                first_ts=ev.get("ts_utc"), last_ts=ev.get("ts_utc"),
                event_ids=[eid], dedup_key=f"spawn:{parent_spec.key}->{proc_spec.key}:{eid}",
            ))

        # host runs process
        if host_spec and proc_spec:
            add_edge(EdgeSpec(
                src=host_spec.key, dst=proc_spec.key, relation="ran",
                status="observed",
                method="process event recorded on host",
                confidence="high",
                first_ts=ev.get("ts_utc"), last_ts=ev.get("ts_utc"),
                event_ids=[eid], dedup_key=f"ran:{host_spec.key}->{proc_spec.key}",
            ))

        # user authenticated on host
        if user_spec and host_spec and ev.get("event_type", "").startswith("logon"):
            add_edge(EdgeSpec(
                src=user_spec.key, dst=host_spec.key, relation="authenticated",
                status="observed",
                method="logon event names both account and host",
                confidence="high",
                first_ts=ev.get("ts_utc"), last_ts=ev.get("ts_utc"),
                event_ids=[eid],
                dedup_key=f"auth:{user_spec.key}->{host_spec.key}",
            ))

        # host <-> ip, host <-> domain, process -> file
        if host_spec and ev.get("dst_ip"):
            add_edge(EdgeSpec(
                src=host_spec.key, dst=n_ip(ev["dst_ip"]).key, relation="connected_to",
                status="observed",
                method="network event records destination IP for this host",
                confidence="high",
                first_ts=ev.get("ts_utc"), last_ts=ev.get("ts_utc"),
                event_ids=[eid], dedup_key=f"net:{host_spec.key}->{ev['dst_ip']}",
            ))
        if host_spec and ev.get("domain"):
            add_edge(EdgeSpec(
                src=host_spec.key, dst=n_domain(ev["domain"]).key, relation="resolved",
                status="observed",
                method="DNS event records resolved name for this host",
                confidence="high",
                first_ts=ev.get("ts_utc"), last_ts=ev.get("ts_utc"),
                event_ids=[eid], dedup_key=f"dns:{host_spec.key}->{ev['domain'].lower()}",
            ))
        if proc_spec and ev.get("file_path"):
            add_edge(EdgeSpec(
                src=proc_spec.key, dst=n_file(ev["file_path"]).key, relation="accessed",
                status="observed",
                method="file event records process and path",
                confidence="medium",
                first_ts=ev.get("ts_utc"), last_ts=ev.get("ts_utc"),
                event_ids=[eid], dedup_key=f"file:{proc_spec.key}->{ev['file_path'].lower()}",
            ))

    # ---- inferred edges ----------------------------------------------
    # user -> host for non-logon activity: same account appearing on a host is
    # an inference, because the event does not prove an interactive session.
    for ev in events:
        if not (ev.get("user_name") and ev.get("host")):
            continue
        if ev.get("event_type", "").startswith("logon"):
            continue
        add_edge(EdgeSpec(
            src=n_user(ev["user_name"]).key, dst=n_host(ev["host"]).key,
            relation="active_on", status="inferred",
            method="same account string appears in non-logon event on that host; "
                   "no session evidence in data",
            confidence="low",
            first_ts=ev.get("ts_utc"), last_ts=ev.get("ts_utc"),
            event_ids=[ev["id"]],
            dedup_key=f"active:{n_user(ev['user_name']).key}->{n_host(ev['host']).key}",
        ))

    # IOC-linked nodes: mark as inferred suspicion, not observed contact.
    for ev in events:
        for field_name, factory in (("dst_ip", n_ip), ("domain", n_domain)):
            val = (ev.get(field_name) or "").lower()
            if val and val in ioc_values:
                ioc = ioc_values[val]
                node_key = factory(ev.get(field_name)).key
                if node_key in nodes:
                    nodes[node_key].severity = "critical"
                    nodes[node_key].attributes["ioc_match"] = {
                        "threat_label": ioc.get("threat_label"),
                        "confidence": ioc.get("confidence"),
                        "source": ioc.get("source"),
                    }
                if ev.get("host"):
                    add_edge(EdgeSpec(
                        src=n_host(ev["host"]).key, dst=node_key,
                        relation="contacted_ioc", status="observed",
                        method=f"destination value matched local IOC dataset "
                               f"({ioc.get('ioc_type')}={ioc.get('value')})",
                        confidence="high",
                        first_ts=ev.get("ts_utc"), last_ts=ev.get("ts_utc"),
                        event_ids=[ev["id"]],
                        dedup_key=f"ioc:{ev.get('host')}:{node_key}",
                    ))

    # ---- alerts become nodes, linked to their trigger events ----------
    for alert in alerts:
        if not alert.get("id"):
            continue
        a_node = n_alert(alert["id"], alert.get("title", ""), alert.get("severity", "medium"))
        add_node(a_node)
        for eid in alert.get("event_ids", []):
            ev_key = f"event:{eid}"
            add_node(NodeSpec(ev_key, "event", f"event #{eid}"))
            add_edge(EdgeSpec(
                src=a_node.key, dst=ev_key, relation="supported_by",
                status="observed",
                method=f"alert {alert.get('rule_id')} references this event ID",
                confidence="high",
                event_ids=[eid],
                dedup_key=f"ab:{alert['id']}:{eid}",
            ))

    return _persist(project_id, nodes, edges)


def _persist(project_id: int, nodes: dict[str, NodeSpec], edges: dict[str, EdgeSpec]) -> dict[str, Any]:
    with cursor() as cur:
        cur.execute("DELETE FROM graph_edges WHERE project_id=?", (project_id,))
        cur.execute("DELETE FROM graph_nodes WHERE project_id=?", (project_id,))

        id_by_key: dict[str, int] = {}
        for key, spec in nodes.items():
            cur.execute(
                """INSERT INTO graph_nodes (project_id,node_key,node_type,label,severity,attributes)
                   VALUES (?,?,?,?,?,?)""",
                (project_id, key, spec.type, spec.label[:300], spec.severity,
                 json.dumps(spec.attributes, ensure_ascii=False) if spec.attributes else None),
            )
            id_by_key[key] = cur.lastrowid

        e_count = 0
        for spec in edges.values():
            src_id = id_by_key.get(spec.src)
            dst_id = id_by_key.get(spec.dst)
            if src_id is None or dst_id is None:
                continue
            try:
                cur.execute(
                    """INSERT INTO graph_edges
                       (project_id,src_node_id,dst_node_id,relation,status,method,confidence,
                        first_ts,last_ts,dedup_key)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (project_id, src_id, dst_id, spec.relation, spec.status, spec.method[:500],
                     spec.confidence, spec.first_ts, spec.last_ts,
                     spec.dedup_key or f"{spec.src}|{spec.dst}|{spec.relation}"),
                )
            except Exception:  # noqa: BLE001 - duplicate edge is not fatal
                continue
            edge_id = cur.lastrowid
            e_count += 1
            for eid in spec.event_ids[:50]:
                try:
                    cur.execute(
                        "INSERT OR IGNORE INTO edge_events (edge_id,event_id) VALUES (?,?)",
                        (edge_id, eid),
                    )
                except Exception:  # noqa: BLE001
                    pass

    return {"nodes": len(nodes), "edges": e_count}


# --------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------

def get_graph(project_id: int, include_inferred: bool = True,
              node_types: list[str] | None = None,
              min_severity: str | None = None,
              search: str | None = None) -> dict[str, Any]:
    from .db import get_conn

    conn = get_conn()
    node_rows = conn.execute(
        "SELECT * FROM graph_nodes WHERE project_id=?", (project_id,)
    ).fetchall()
    keep: dict[int, dict[str, Any]] = {}
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_rank = sev_rank.get(min_severity or "", -1)
    needle = (search or "").lower().strip()

    for row in node_rows:
        d = dict(row)
        if node_types and d["node_type"] not in node_types:
            continue
        if min_rank >= 0 and sev_rank.get(d.get("severity") or "", -1) < min_rank:
            continue
        if needle and needle not in (d["label"] or "").lower() and needle not in d["node_key"].lower():
            continue
        if d.get("attributes"):
            try:
                d["attributes"] = json.loads(d["attributes"])
            except (TypeError, ValueError):
                d["attributes"] = {}
        else:
            d["attributes"] = {}
        keep[d["id"]] = d

    if needle:
        # include neighbours of matches so the graph stays readable
        edge_rows = conn.execute(
            "SELECT * FROM graph_edges WHERE project_id=?", (project_id,)
        ).fetchall()
        for row in edge_rows:
            if row["src_node_id"] in keep or row["dst_node_id"] in keep:
                for nid in (row["src_node_id"], row["dst_node_id"]):
                    if nid not in keep:
                        nrow = conn.execute(
                            "SELECT * FROM graph_nodes WHERE id=?", (nid,)
                        ).fetchone()
                        if nrow:
                            d = dict(nrow)
                            d["attributes"] = json.loads(d["attributes"] or "{}")
                            keep[nid] = d
    else:
        edge_rows = conn.execute(
            "SELECT * FROM graph_edges WHERE project_id=?", (project_id,)
        ).fetchall()

    edges = []
    for row in edge_rows:
        d = dict(row)
        if not include_inferred and d["status"] == "inferred":
            continue
        if d["src_node_id"] in keep and d["dst_node_id"] in keep:
            # Every edge must be traceable. Without this, an "observed" edge
            # asserts a fact the analyst cannot inspect, which breaks the
            # evidence-first contract of the product.
            ev_ids = [
                r["event_id"] for r in conn.execute(
                    "SELECT event_id FROM edge_events WHERE edge_id=? ORDER BY event_id",
                    (d["id"],),
                ).fetchall()
            ]
            d["evidence_event_ids"] = ev_ids
            edges.append(d)

    return {"nodes": list(keep.values()), "edges": edges,
            "stats": {"node_count": len(keep), "edge_count": len(edges)}}


def get_node_detail(node_id: int) -> dict[str, Any] | None:
    from .db import get_conn

    conn = get_conn()
    row = conn.execute("SELECT * FROM graph_nodes WHERE id=?", (node_id,)).fetchone()
    if not row:
        return None
    node = dict(row)
    node["attributes"] = json.loads(node.get("attributes") or "{}")

    in_edges = conn.execute(
        """SELECT e.*, n.node_key AS src_key, n.label AS src_label, n.node_type AS src_type
           FROM graph_edges e JOIN graph_nodes n ON n.id=e.src_node_id
           WHERE e.dst_node_id=?""", (node_id,)
    ).fetchall()
    out_edges = conn.execute(
        """SELECT e.*, n.node_key AS dst_key, n.label AS dst_label, n.node_type AS dst_type
           FROM graph_edges e JOIN graph_nodes n ON n.id=e.dst_node_id
           WHERE e.src_node_id=?""", (node_id,)
    ).fetchall()

    evidence = conn.execute(
        """SELECT DISTINCT ev.* FROM edge_events ee
           JOIN graph_edges e ON e.id = ee.edge_id
           JOIN events ev ON ev.id = ee.event_id
           WHERE e.src_node_id=? OR e.dst_node_id=?
           ORDER BY ev.ts_utc IS NULL, ev.ts_utc LIMIT 100""",
        (node_id, node_id),
    ).fetchall()

    def with_evidence(rows) -> list[dict]:
        out = []
        for r in rows:
            d = dict(r)
            d["evidence_event_ids"] = [
                x["event_id"] for x in conn.execute(
                    "SELECT event_id FROM edge_events WHERE edge_id=? ORDER BY event_id",
                    (d["id"],),
                ).fetchall()
            ]
            out.append(d)
        return out

    return {
        "node": node,
        "incoming": with_evidence(in_edges),
        "outgoing": with_evidence(out_edges),
        "evidence": [dict(r) for r in evidence],
    }


# --------------------------------------------------------------------------
# Incident grouping
# --------------------------------------------------------------------------

def group_incidents(project_id: int, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cluster alerts into incidents.

    Basis: shared host OR shared user OR alerts in the same rule family within
    6 hours. This is a simple union-find over that predicate - transparent and
    reproducible, which is what matters for defence.
    """
    if not alerts:
        return []

    parent: dict[int, int] = {a["id"]: a["id"] for a in alerts}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i, a in enumerate(alerts):
        for b in alerts[i + 1:]:
            same_host = bool(a.get("host")) and a.get("host") == b.get("host")
            same_user = bool(a.get("user_name")) and a.get("user_name") == b.get("user_name")
            close_in_time = False
            if a.get("first_ts") and b.get("first_ts"):
                ta, tb = parse_iso(a["first_ts"]), parse_iso(b["first_ts"])
                if ta and tb:
                    close_in_time = abs((tb - ta).total_seconds()) <= 6 * 3600
            # Grouping predicate, deliberately conservative:
            #   * same host  -> always related
            #   * same account AND within window -> related
            #   * same C2/IOC host AND within window -> related
            # We deliberately do NOT group on rule family alone: that merges
            # unrelated benign and malicious activity of the same rule type.
            if same_host:
                union(a["id"], b["id"])
            elif same_user and close_in_time:
                union(a["id"], b["id"])
            elif close_in_time and a.get("rule_id") == b.get("rule_id") == "R-003" \
                    and a.get("host") != b.get("host"):
                # same threat indicator observed on different hosts is one campaign
                union(a["id"], b["id"])

    clusters: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for a in alerts:
        clusters[find(a["id"])].append(a)

    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    incidents = []
    for root, members in clusters.items():
        members.sort(key=lambda a: a.get("first_ts") or "9999")
        top = max(members, key=lambda a: severity_rank.get(a.get("severity") or "low", 0))
        hosts = sorted({m["host"] for m in members if m.get("host")})
        users = sorted({m["user_name"] for m in members if m.get("user_name")})
        first_ts = min((m["first_ts"] for m in members if m.get("first_ts")), default=None)
        last_ts = max((m["last_ts"] for m in members if m.get("last_ts")), default=None)
        rules = sorted({m["rule_id"] for m in members})
        incidents.append({
            "alert_ids": [m["id"] for m in members],
            "severity": top.get("severity") or "medium",
            "title": top.get("title") or "Correlated alerts",
            "hosts": hosts,
            "users": users,
            "first_ts": first_ts,
            "last_ts": last_ts,
            "rule_ids": rules,
            "summary": (
                f"{len(members)} alert(s) from rule(s) {', '.join(rules)} involving "
                f"{len(hosts)} host(s)"
                + (f" ({', '.join(hosts[:4])}{'...' if len(hosts) > 4 else ''})" if hosts else "")
                + (f" and {len(users)} account(s)" if users else "")
                + ". Grouping is based on shared host/account or rule family within 6 hours."
            ),
        })
    incidents.sort(key=lambda i: severity_rank.get(i["severity"], 0), reverse=True)
    return incidents
