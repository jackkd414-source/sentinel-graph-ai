import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type GraphData, type IncidentSummary } from "../api";
import { PageHeader } from "../components/layout";
import { GraphCanvas } from "../components/GraphCanvas";
import { NodeInspector } from "../components/NodeInspector";
import { EmptyState, ErrorState, LoadingState } from "../components/ui";
import { Icons } from "../components/icons";

export function GraphPage({
  focusEventId, onFocusConsumed, onSearchEvents,
}: {
  focusEventId: number | null;
  onFocusConsumed: () => void;
  onSearchEvents: (query: string) => void;
}) {
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selected, setSelected] = useState<number | null>(null);
  const [showInferred, setShowInferred] = useState(true);
  const [showEvents, setShowEvents] = useState(false);
  const [nodeTypes, setNodeTypes] = useState<Set<string>>(new Set());
  const [scopeId, setScopeId] = useState<number | null>(null);
  const [q, setQ] = useState("");
  const [noMatch, setNoMatch] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [g, inc] = await Promise.all([api.graph({ include_inferred: true }), api.incidents()]);
      setGraph(g);
      setIncidents(inc.incidents);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load the attack graph");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  // Consume an external "focus this event node" request (from the Events page).
  useEffect(() => {
    if (focusEventId == null || !graph) return;
    setShowEvents(true);
    const node = graph.nodes.find((n) => n.node_key === `event:${focusEventId}`);
    setSelected(node ? node.id : null);
    onFocusConsumed();
  }, [focusEventId, graph, onFocusConsumed]);

  const scopeHosts = useMemo(() => {
    const inc = incidents.find((i) => i.id === scopeId);
    return inc ? inc.hosts : null;
  }, [incidents, scopeId]);

  const nodeTypeList = useMemo(() => {
    const s = new Set<string>();
    graph?.nodes.forEach((n) => s.add(n.node_type));
    return [...s].sort();
  }, [graph]);

  const toggleType = (t: string) => {
    const next = new Set(nodeTypes);
    if (next.has(t)) next.delete(t); else next.add(t);
    setNodeTypes(next);
  };

  const findEntity = () => {
    if (!graph || !q.trim()) return;
    const needle = q.trim().toLowerCase();
    const hit = graph.nodes.find(
      (n) => n.label.toLowerCase().includes(needle) || n.node_key.toLowerCase().includes(needle),
    );
    if (hit) { setSelected(hit.id); setNoMatch(false); if (hit.node_type === "event") setShowEvents(true); }
    else setNoMatch(true);
  };

  // Relationship table (ref-2 style): source → destination per edge, with the
  // relation, whether it is observed or inferred, and how many events prove it.
  const nodeById = useMemo(
    () => new Map((graph?.nodes ?? []).map((n) => [n.id, n])),
    [graph],
  );
  const relRows = useMemo(
    () => (graph?.edges ?? []).map((e) => ({
      id: e.id,
      ts: e.first_ts,
      src: nodeById.get(e.src_node_id),
      dst: nodeById.get(e.dst_node_id),
      relation: e.relation,
      status: e.status,
      evidence: e.evidence_event_ids?.length ?? 0,
    })),
    [graph, nodeById],
  );

  if (loading && !graph) return <LoadingState label="Building attack graph…" />;
  if (error && !graph) return <div className="tw-content"><ErrorState message={error} onRetry={load} /></div>;

  return (
    <div className="tw-content-flush">
      <div style={{ padding: "24px var(--tw-content-pad) 16px" }}>
        <PageHeader
          title="Attack Graph"
          subtitle="Entity relationships derived from events. Solid edges are observed; dashed edges are inferred."
          actions={<button className="tw-btn tw-btn-sm" onClick={() => void load()}>Refresh</button>}
        />
      </div>

      <div className="tw-graph-toolbar">
        <div className="tw-search" style={{ width: 230 }}>
          <input className="tw-input" placeholder="Find entity (host, user, ip…)" value={q}
                 onChange={(e) => { setQ(e.target.value); setNoMatch(false); }}
                 onKeyDown={(e) => { if (e.key === "Enter") findEntity(); }} aria-label="Find entity" />
        </div>
        <button className="tw-btn tw-btn-sm" onClick={findEntity} disabled={!q.trim()}>Find</button>
        {noMatch ? <span className="faint" style={{ fontSize: "var(--tw-fs-meta)" }}>no matching entity</span> : null}
        <span style={{ width: 1, height: 16, background: "var(--tw-border)" }} />
        <select className="tw-select" style={{ width: 210 }} value={scopeId ?? ""}
                onChange={(e) => setScopeId(e.target.value ? Number(e.target.value) : null)}
                aria-label="Scope to incident">
          <option value="">Global graph (all incidents)</option>
          {incidents.map((i) => <option key={i.id} value={i.id}>{i.ref} — {i.title.slice(0, 40)}</option>)}
        </select>
        <label className="tw-check">
          <input type="checkbox" checked={showInferred} onChange={(e) => setShowInferred(e.target.checked)} />
          Inferred edges
        </label>
        <label className="tw-check">
          <input type="checkbox" checked={showEvents} onChange={(e) => setShowEvents(e.target.checked)} />
          Event nodes
        </label>
        <span className="spacer" />
        {nodeTypeList.map((t) => (
          <button key={t} className={`tw-chip tw-chip-plain tw-rel-chip ${nodeTypes.has(t) ? "off" : ""}`}
                  style={{ cursor: "pointer", textTransform: "none" }} onClick={() => toggleType(t)}>
            {t}
          </button>
        ))}
      </div>

      {graph && graph.nodes.length === 0 ? (
        <div className="tw-content">
          <EmptyState title="No graph yet"
                      detail="Load the demo dataset or import events, then run analysis to build the attack graph." />
        </div>
      ) : (
        <div className="tw-graph-shell with-side" style={{ flex: 1, minHeight: 0 }}>
          {graph ? (
            <GraphCanvas
              data={graph}
              selectedId={selected}
              onSelect={setSelected}
              showInferred={showInferred}
              highlightTypes={nodeTypes}
              showEvents={showEvents}
              focusHosts={scopeHosts}
              onClearFocus={() => setScopeId(null)}
              onOpenEvidence={(n) => onSearchEvents(n.label)}
            />
          ) : null}

          <aside className="tw-graph-side">
            {selected ? <NodeInspector nodeId={selected} onClose={() => setSelected(null)} /> : null}

            <div className="tw-side-card">
              <div className="tw-card-head">
                {Icons.link({ style: { width: 16, height: 16 } })}
                <span className="tw-card-title">Relationships</span>
                <span className="faint" style={{ fontSize: "var(--tw-fs-meta)" }}>{relRows.length} edges</span>
              </div>
              <div className="tw-table-wrap" style={{ overflowY: "auto", flex: 1, minHeight: 0 }}>
                <table className="tw-table tw-rel-table">
                  <thead>
                    <tr>
                      <th style={{ width: 74 }}>Time</th>
                      <th>Source</th>
                      <th>Destination</th>
                    </tr>
                  </thead>
                  <tbody>
                    {relRows.length === 0 ? (
                      <tr><td colSpan={3}><span className="faint">no relationships</span></td></tr>
                    ) : relRows.map((r) => (
                      <tr key={r.id} className="clickable" onClick={() => r.src && setSelected(r.src.id)}>
                        <td><span className="mono faint">{(r.ts || "").slice(5, 16).replace("T", " ") || "—"}</span></td>
                        <td>
                          <span className="mono" style={{ color: "var(--tw-primary)" }}>{r.src?.label ?? "—"}</span>
                          <div className="faint" style={{ fontSize: 10 }}>{r.src?.node_type ?? ""}</div>
                          <div style={{ marginTop: 3 }}>
                            <span className={`tw-chip ${r.status === "inferred" ? "tw-status-inferred" : "tw-status-observed"}`}
                                  style={{ fontSize: 9.5, padding: "0 6px" }}>{r.relation}</span>
                          </div>
                        </td>
                        <td>
                          <span className="mono">{r.dst?.label ?? "—"}</span>
                          <div className="faint" style={{ fontSize: 10 }}>{r.dst?.node_type ?? ""}</div>
                          <div className="faint" style={{ fontSize: 9.5, marginTop: 3 }}>
                            {r.evidence} event{r.evidence === 1 ? "" : "s"} · {r.status}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </aside>
        </div>
      )}
    </div>
  );
}
