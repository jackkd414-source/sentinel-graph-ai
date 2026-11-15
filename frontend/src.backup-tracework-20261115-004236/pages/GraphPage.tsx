import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type GraphData, type IncidentSummary } from "../api";
import { PageHeader } from "../components/layout";
import { GraphCanvas } from "../components/GraphCanvas";
import { NodeInspector } from "../components/NodeInspector";
import { EmptyState, ErrorState, LoadingState } from "../components/ui";

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
        <div className={`tw-graph-shell ${selected ? "with-inspector" : ""}`} style={{ flex: 1, minHeight: 0 }}>
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
          {selected ? <NodeInspector nodeId={selected} onClose={() => setSelected(null)} /> : null}
        </div>
      )}
    </div>
  );
}
