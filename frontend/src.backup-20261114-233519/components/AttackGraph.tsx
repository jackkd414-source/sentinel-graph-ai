// Interactive attack-graph renderer.
//
// Built on raw SVG rather than a graph library: the requirement is that
// observed and inferred relationships are *visually distinct at a glance* and
// that every node is traceable to evidence. A custom layout gives exact control
// over both, with zero added dependency surface.
//
// Layout strategy (fix for the "nodes escape the viewport" bug):
//   * node positions are computed in world coordinates from bounded bands;
//   * the view is then *auto-fitted* to the bounding box of the visible nodes,
//     so the graph is always centred and fully in frame regardless of how many
//     nodes there are or how far the outer bands grow;
//   * dense graphs are capped and the overflow is grouped into one aggregate
//     node per entity type instead of silently spilling off-screen.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { GraphData, GraphEdge, GraphNode } from "../api";

const TYPE_STYLE: Record<string, { color: string; r: number; label: string }> = {
  host:    { color: "#2fdfe0", r: 15, label: "Host" },
  user:    { color: "#4a9eff", r: 13, label: "User" },
  process: { color: "#ffb020", r: 12, label: "Process" },
  file:    { color: "#a97bff", r: 11, label: "File" },
  domain:  { color: "#34d399", r: 11, label: "Domain" },
  ip:      { color: "#ff8b3d", r: 11, label: "IP" },
  event:   { color: "#6c88a8", r: 7,  label: "Event" },
  alert:   { color: "#ff4d5e", r: 14, label: "Alert" },
  artifact:{ color: "#9db4d0", r: 10, label: "Artifact" },
};

const RELATION_COLOR: Record<string, string> = {
  spawned: "#ff8b3d",
  ran: "#2fdfe0",
  authenticated: "#4a9eff",
  connected_to: "#ff4d5e",
  resolved: "#34d399",
  accessed: "#a97bff",
  active_on: "#a97bff",
  contacted_ioc: "#ff4d5e",
  supported_by: "#6c88a8",
};

// Fixed world viewport the SVG coordinate system uses (viewBox). Auto-fit maps
// the node bounding box into this box.
const VIEW_W = 960;
const VIEW_H = 680;
const FIT_PAD = 52;
const K_MIN = 0.12;
// Auto-fit may go well below the manual-zoom floor on dense graphs.
const K_FIT_MIN = 0.03;
const K_MAX = 3.5;
/** Hard cap on drawn nodes; the overflow is grouped, never dropped silently. */
const DEFAULT_MAX_NODES = 320;

interface Props {
  data: GraphData;
  selectedId: number | null;
  onSelect: (id: number | null) => void;
  showInferred: boolean;
  highlightTypes: Set<string>;
  /** Event nodes are numerous and visually dominant; hidden unless asked for. */
  showEvents?: boolean;
  /** Maximum nodes to draw before grouping the overflow. */
  maxNodes?: number;
  /** Restrict the view to one incident's hosts and their direct neighbours. */
  focusHosts?: string[] | null;
  onClearFocus?: () => void;
  /** Drill-down for "Evidence →". Defaults to plain selection when omitted. */
  onOpenEvidence?: (node: GraphNode) => void;
}

interface Pt { x: number; y: number }

/** A node as drawn: real nodes plus one synthetic aggregate per overflow type. */
interface RenderNode extends GraphNode {
  aggregateCount?: number;
}

function nodeRadius(n: RenderNode): number {
  const base = TYPE_STYLE[n.node_type]?.r ?? 10;
  return n.aggregateCount ? base + 5 + Math.min(10, Math.log2(n.aggregateCount) * 1.6) : base;
}

export function AttackGraph({
  data, selectedId, onSelect, showInferred, highlightTypes, showEvents = false,
  maxNodes = DEFAULT_MAX_NODES, focusHosts = null, onClearFocus, onOpenEvidence,
}: Props) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [hoverId, setHoverId] = useState<number | null>(null);
  const dragRef = useRef<{ startX: number; startY: number; origX: number; origY: number } | null>(null);
  const [dragMoved, setDragMoved] = useState(false);
  const [hiddenRel, setHiddenRel] = useState<Set<string>>(new Set());

  // Single drill-down entry point: without a handler the button just re-selects,
  // which used to look like a dead button.
  const openEvidence = onOpenEvidence ?? ((n: RenderNode) => onSelect(n.id));

  const visibleEdges = useMemo(
    () => data.edges.filter((e) => showInferred || e.status === "observed"),
    [data.edges, showInferred],
  );

  /** Relation kinds present in the data, for the edge filter legend. */
  const relations = useMemo(
    () => [...new Set(data.edges.map((e) => e.relation))].sort(),
    [data.edges],
  );

  // Event nodes add ~30 nodes that visually swamp the entity graph. They are
  // reachable through the filter chips, but off by default.
  const visibleNodes = useMemo(
    () => (showEvents ? data.nodes : data.nodes.filter((n) => n.node_type !== "event")),
    [data.nodes, showEvents],
  );

  // ---- incident focus filter --------------------------------------------
  // Kept subgraph = the incident's host nodes plus everything one hop away.
  const focused = useMemo(() => {
    if (!focusHosts || focusHosts.length === 0) {
      return { nodes: visibleNodes, edges: visibleEdges, active: false };
    }
    const wanted = new Set(focusHosts.map((h) => h.toLowerCase()));
    const hostIds = new Set<number>();
    for (const n of visibleNodes) {
      if (n.node_type === "host" && wanted.has((n.label || "").toLowerCase())) hostIds.add(n.id);
    }
    const keep = new Set<number>(hostIds);
    for (const e of visibleEdges) {
      if (hostIds.has(e.src_node_id)) keep.add(e.dst_node_id);
      if (hostIds.has(e.dst_node_id)) keep.add(e.src_node_id);
    }
    return {
      nodes: visibleNodes.filter((n) => keep.has(n.id)),
      edges: visibleEdges.filter((e) => keep.has(e.src_node_id) && keep.has(e.dst_node_id)),
      active: true,
    };
  }, [visibleNodes, visibleEdges, focusHosts]);

  // ---- density cap + entity grouping ------------------------------------
  const { renderNodes, renderEdges, hiddenTotal } = useMemo(() => {
    const pool = focused.nodes;
    const degree = new Map<number, number>();
    for (const e of focused.edges) {
      degree.set(e.src_node_id, (degree.get(e.src_node_id) || 0) + 1);
      degree.set(e.dst_node_id, (degree.get(e.dst_node_id) || 0) + 1);
    }
    const ranked = [...pool].sort(
      (a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0) || a.id - b.id,
    );

    const kept = new Set<number>();
    const hiddenByType = new Map<string, number>();
    // Global cap: `maxNodes` bounds the whole render, not each type (a per-type
    // cap let a 2.8k-node graph render 740 nodes and fall outside the viewBox).
    for (const n of ranked) {
      if (kept.size < maxNodes) {
        kept.add(n.id);
      } else {
        hiddenByType.set(n.node_type, (hiddenByType.get(n.node_type) || 0) + 1);
      }
    }

    const keptNodes: RenderNode[] = pool.filter((n) => kept.has(n.id));
    const groups: RenderNode[] = [...hiddenByType.entries()].map(([type, count], i) => ({
      id: -(1000 + i),
      project_id: keptNodes[0]?.project_id ?? 0,
      node_key: `__group__:${type}`,
      node_type: type,
      label: `${TYPE_STYLE[type]?.label ?? type} ×${count}`,
      severity: null,
      attributes: { aggregate: true, count },
      aggregateCount: count,
    }));

    const renderNodes = [...keptNodes, ...groups];
    const ids = new Set(renderNodes.map((n) => n.id));
    const renderEdges = focused.edges.filter(
      (e) => ids.has(e.src_node_id) && ids.has(e.dst_node_id),
    );
    const hiddenTotal = [...hiddenByType.values()].reduce((a, b) => a + b, 0);
    return { renderNodes, renderEdges, hiddenTotal };
  }, [focused, maxNodes]);

  const nodeById = useMemo(() => {
    const m = new Map<number, RenderNode>();
    renderNodes.forEach((n) => m.set(n.id, n));
    return m;
  }, [renderNodes]);

  // Layout: explicit radial bands, one per entity class. Bands are assigned
  // fixed radii so the structure is visually obvious; within a band nodes are
  // distributed by angle, ordered by graph degree so hubs land predictably.
  // Aggregate (grouped) nodes are placed on the same band as their type.
  const positions = useMemo(() => {
    const bandOf: Record<string, number> = {
      alert: 90, host: 165, user: 225, process: 290, file: 290,
      domain: 350, ip: 350, artifact: 350, event: 420,
    };

    const degree = new Map<number, number>();
    for (const e of renderEdges) {
      degree.set(e.src_node_id, (degree.get(e.src_node_id) || 0) + 1);
      degree.set(e.dst_node_id, (degree.get(e.dst_node_id) || 0) + 1);
    }

    const byBand = new Map<number, RenderNode[]>();
    for (const n of renderNodes) {
      const band = bandOf[n.node_type] ?? 420;
      if (!byBand.has(band)) byBand.set(band, []);
      byBand.get(band)!.push(n);
    }

    const pos = new Map<number, Pt>();
    const cx = VIEW_W / 2;
    const cy = VIEW_H / 2;

    for (const [band, nodes] of byBand) {
      nodes.sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0) || a.id - b.id);
      const count = Math.max(1, nodes.length);
      const maxR = Math.max(...nodes.map(nodeRadius));
      // grow the radius if this band holds more nodes than fit comfortably
      const minR = (count * (maxR * 2 + 30)) / (2 * Math.PI);
      const radius = Math.max(band, minR);
      nodes.forEach((n, i) => {
        const angle = (i / count) * Math.PI * 2 - Math.PI / 2 + (band / 900);
        pos.set(n.id, {
          x: cx + Math.cos(angle) * radius,
          y: cy + Math.sin(angle) * radius,
        });
      });
    }
    return pos;
  }, [renderNodes, renderEdges]);

  // ---- auto-fit ----------------------------------------------------------
  // Compute the bounding box of the drawn nodes (with their radii) and derive a
  // scale + translation that centres it inside the fixed viewBox. This is the
  // core fix: the view is no longer pinned to a fixed coordinate window that
  // the outer bands immediately outgrow.
  const fitView = useCallback(() => {
    const pts = renderNodes
      .map((n) => ({ p: positions.get(n.id), r: nodeRadius(n) + 14 }))
      .filter((x): x is { p: Pt; r: number } => !!x.p);
    if (pts.length === 0) {
      setView({ x: 0, y: 0, k: 1 });
      return;
    }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const { p, r } of pts) {
      minX = Math.min(minX, p.x - r);
      minY = Math.min(minY, p.y - r);
      maxX = Math.max(maxX, p.x + r);
      maxY = Math.max(maxY, p.y + r);
    }
    const bw = Math.max(1, maxX - minX);
    const bh = Math.max(1, maxY - minY);
    // Fit must never be blocked by the manual-zoom floor: a dense graph needs a
    // much smaller scale than K_MIN to bring every node inside the viewBox.
    const k = Math.min(
      K_MAX,
      Math.max(K_FIT_MIN, Math.min((VIEW_W - FIT_PAD * 2) / bw, (VIEW_H - FIT_PAD * 2) / bh)),
    );
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    setView({ x: VIEW_W / 2 - cx * k, y: VIEW_H / 2 - cy * k, k });
  }, [renderNodes, positions]);

  // Re-fit whenever the node set (and therefore its bounds) changes.
  const fitSignature = useMemo(
    () => renderNodes.map((n) => n.id).sort((a, b) => a - b).join(","),
    [renderNodes],
  );
  useEffect(() => { fitView(); }, [fitSignature, fitView]);

  const connected = useMemo(() => {
    const focus = selectedId ?? hoverId;
    if (!focus) return null;
    const set = new Set<number>([focus]);
    for (const e of renderEdges) {
      if (e.src_node_id === focus) set.add(e.dst_node_id);
      if (e.dst_node_id === focus) set.add(e.src_node_id);
    }
    return set;
  }, [selectedId, hoverId, renderEdges]);

  const onWheel = useCallback((ev: React.WheelEvent) => {
    ev.preventDefault();
    setView((v) => {
      const k = Math.min(K_MAX, Math.max(K_MIN, v.k * (ev.deltaY < 0 ? 1.12 : 0.89)));
      return { ...v, k };
    });
  }, []);

  const onPointerDown = (ev: React.PointerEvent) => {
    if ((ev.target as Element).closest("[data-node-id]")) return;
    (ev.target as Element).setPointerCapture?.(ev.pointerId);
    dragRef.current = { startX: ev.clientX, startY: ev.clientY, origX: view.x, origY: view.y };
    setDragMoved(false);
  };

  const onPointerMove = (ev: React.PointerEvent) => {
    const d = dragRef.current;
    if (!d) return;
    const dx = ev.clientX - d.startX;
    const dy = ev.clientY - d.startY;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) setDragMoved(true);
    setView((v) => ({ ...v, x: d.origX + dx, y: d.origY + dy }));
  };

  const onPointerUp = () => { dragRef.current = null; };

  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const handler = (e: WheelEvent) => e.preventDefault();
    el.addEventListener("wheel", handler, { passive: false });
    return () => el.removeEventListener("wheel", handler);
  }, []);

  const reset = () => { onSelect(null); fitView(); };

  const edgeVisible = (e: GraphEdge) => {
    const s = nodeById.get(e.src_node_id);
    const d = nodeById.get(e.dst_node_id);
    if (!s || !d) return false;
    if (highlightTypes.size > 0 && !highlightTypes.has(s.node_type) && !highlightTypes.has(d.node_type)) {
      return false;
    }
    return true;
  };

  const selected = selectedId != null ? nodeById.get(selectedId) : undefined;

  if (visibleNodes.length === 0 && data.nodes.length === 0) {
    return (
      <div className="empty">
        <strong>No graph data</strong>
        <div>Load the demo dataset or import events, then run analysis to build the attack graph.</div>
      </div>
    );
  }

  return (
    <div style={{ position: "relative", width: "100%", height: "100%", minHeight: 260 }}>
      <svg
        ref={svgRef}
        width="100%"
        height="100%"
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        preserveAspectRatio="xMidYMid meet"
        style={{ display: "block", cursor: dragRef.current ? "grabbing" : "grab",
                 background: "radial-gradient(circle at 50% 45%, #0d1a2b 0%, #070d18 70%)" }}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={onPointerUp}
      >
        <defs>
          <marker id="arrow-observed" viewBox="0 0 10 10" refX="9" refY="5"
                  markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#2a4a70" />
          </marker>
          <marker id="arrow-inferred" viewBox="0 0 10 10" refX="9" refY="5"
                  markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#5a3f8f" />
          </marker>
          <marker id="arrow-hot" viewBox="0 0 10 10" refX="9" refY="5"
                  markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#2fdfe0" />
          </marker>
        </defs>

        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
          {/* edges first so nodes draw on top */}
          {renderEdges.filter((e) => !hiddenRel.has(e.relation) && edgeVisible(e)).map((e) => {
            const s = positions.get(e.src_node_id);
            const d = positions.get(e.dst_node_id);
            if (!s || !d) return null;
            const isHot = connected
              ? (e.src_node_id === (selectedId ?? hoverId) || e.dst_node_id === (selectedId ?? hoverId))
              : false;
            const dim = connected !== null && !isHot;
            const color = isHot ? "#2fdfe0" : (RELATION_COLOR[e.relation] || "#2a4a70");
            const inferred = e.status === "inferred";
            return (
              <g key={e.id} opacity={dim ? 0.12 : 1}>
                <line
                  x1={s.x} y1={s.y} x2={d.x} y2={d.y}
                  stroke={color}
                  strokeWidth={isHot ? 2 : 1.1}
                  strokeDasharray={inferred ? "4 4" : undefined}
                  markerEnd={`url(#${isHot ? "arrow-hot" : inferred ? "arrow-inferred" : "arrow-observed"})`}
                />
                {isHot && (
                  <text
                    x={(s.x + d.x) / 2}
                    y={(s.y + d.y) / 2 - 3}
                    fill={inferred ? "#a97bff" : "#5d84ab"}
                    fontSize={9}
                    textAnchor="middle"
                    stroke="#070d18"
                    strokeWidth={2.6}
                    paintOrder="stroke"
                    style={{ pointerEvents: "none", userSelect: "none" }}
                  >
                    {e.relation}
                  </text>
                )}
              </g>
            );
          })}

          {/* nodes */}
          {renderNodes.map((n) => {
            const p = positions.get(n.id);
            if (!p) return null;
            const style = TYPE_STYLE[n.node_type] || TYPE_STYLE.event;
            const r = nodeRadius(n);
            if (highlightTypes.size > 0 && !highlightTypes.has(n.node_type)) {
              return (
                <circle key={n.id} cx={p.x} cy={p.y} r={3} fill="#12253c" opacity={0.5} />
              );
            }
            const isSelected = selectedId === n.id;
            const isHover = hoverId === n.id;
            const dim = connected !== null && !connected.has(n.id);
            const stroke = n.aggregateCount ? "#7d93ad"
              : n.severity === "critical" ? "#ff4d5e"
              : n.severity === "high" ? "#ff8b3d"
              : style.color;
            return (
              <g
                key={n.id}
                data-node-id={n.id}
                transform={`translate(${p.x} ${p.y})`}
                opacity={dim ? 0.18 : 1}
                style={{ cursor: n.aggregateCount ? "default" : "pointer" }}
                onPointerDown={(ev) => ev.stopPropagation()}
                onClick={() => {
                  if (n.aggregateCount) return;
                  if (!dragMoved) onSelect(isSelected ? null : n.id);
                }}
                onDoubleClick={() => {
                  if (n.aggregateCount) return;
                  openEvidence(n);
                }}
                onMouseEnter={() => setHoverId(n.id)}
                onMouseLeave={() => setHoverId(null)}
              >
                {isSelected && (
                  <circle r={r + 7} fill="none" stroke="#2fdfe0" strokeWidth={1.4} opacity={0.85} />
                )}
                <circle
                  r={r}
                  fill="#0b1421"
                  stroke={stroke}
                  strokeWidth={isSelected || isHover ? 2.2 : n.aggregateCount ? 1 : 1.5}
                  strokeDasharray={n.aggregateCount ? "3 3" : undefined}
                />
                {n.node_type === "alert" && (
                  <path d="M0 -5.5 L5 3.5 L-5 3.5 Z" fill="none" stroke={stroke} strokeWidth={1.4} />
                )}
                {n.node_type === "host" && (
                  <rect x={-5} y={-4} width={10} height={8} rx={1} fill="none"
                        stroke={stroke} strokeWidth={1.3} />
                )}
                {n.node_type === "user" && (
                  <>
                    <circle cy={-3} r={2.4} fill="none" stroke={stroke} strokeWidth={1.3} />
                    <path d="M-4.5 5 a4.5 4.5 0 0 1 9 0" fill="none" stroke={stroke} strokeWidth={1.3} />
                  </>
                )}
                {view.k > 0.55 && (
                  <text
                    y={r + 11}
                    textAnchor="middle"
                    fill={isSelected ? "#2fdfe0" : "#a8c4e0"}
                    fontSize={9.5}
                    stroke="#070d18"
                    strokeWidth={2.8}
                    paintOrder="stroke"
                    style={{ userSelect: "none", pointerEvents: "none" }}
                  >
                    {n.label.length > 18 ? n.label.slice(0, 17) + "…" : n.label}
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      {/* controls */}
      <div style={{
        position: "absolute", top: 10, right: 10, display: "flex",
        flexDirection: "column", gap: 5,
      }}>
        <button className="btn btn-sm btn-icon" title="Zoom in" aria-label="Zoom in"
                onClick={() => setView((v) => ({ ...v, k: Math.min(K_MAX, v.k * 1.25) }))}>+</button>
        <button className="btn btn-sm btn-icon" title="Zoom out" aria-label="Zoom out"
                onClick={() => setView((v) => ({ ...v, k: Math.max(K_MIN, v.k / 1.25) }))}>−</button>
        <button className="btn btn-sm btn-icon" title="Fit graph to view" aria-label="Fit to view"
                onClick={fitView}>⤢</button>
        <button className="btn btn-sm btn-icon" title="Reset view" aria-label="Reset view"
                onClick={reset}>⟲</button>
      </div>

      {/* selected node quick actions (evidence navigation) */}
      {selected && !selected.aggregateCount && (
        <div style={{
          position: "absolute", top: 10, left: 10, background: "rgba(11,20,33,0.94)",
          border: "1px solid var(--line)", borderRadius: 5, padding: "8px 10px",
          fontSize: 11, color: "var(--fg)", display: "flex", alignItems: "center", gap: 10,
        }}>
          <span><strong>{selected.node_type}</strong> · {selected.label}</span>
          <button className="btn btn-sm" onClick={() => openEvidence(selected)}>
            Evidence →
          </button>
        </div>
      )}

      {/* incident focus chip */}
      {focused.active && (
        <div style={{
          position: "absolute", top: 10, left: 10, marginTop: selected ? 46 : 0,
          background: "rgba(20,40,64,0.95)", border: "1px solid #2fdfe0",
          borderRadius: 5, padding: "5px 9px", fontSize: 11, color: "#9fdfe6",
          display: "flex", alignItems: "center", gap: 8,
        }}>
          Incident filter active · {renderNodes.filter((n) => !n.aggregateCount).length} nodes
          {onClearFocus && (
            <button className="btn btn-sm" onClick={onClearFocus} title="Clear incident filter">✕</button>
          )}
        </div>
      )}

      {/* legend — capped to the graph box so it can never be cropped */}
      <div style={{
        position: "absolute", bottom: 10, left: 10, background: "rgba(11,20,33,0.94)",
        border: "1px solid var(--line)", borderRadius: 5, padding: "9px 11px",
        fontSize: 10.5, lineHeight: 1.75, color: "var(--fg-muted)",
        maxHeight: "calc(100% - 20px)", maxWidth: "calc(100% - 20px)",
        overflowY: "auto", overscrollBehavior: "contain",
      }}>
        <div style={{ fontWeight: 650, letterSpacing: 0.8, marginBottom: 4, color: "var(--fg-dim)" }}>
          LEGEND
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 14px" }}>
          {Object.entries(TYPE_STYLE).map(([k, v]) => (
            <div key={k} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{
                width: 7, height: 7, borderRadius: "50%", border: `1.5px solid ${v.color}`,
                display: "inline-block",
              }} />
              {v.label}
            </div>
          ))}
        </div>
        <div style={{ marginTop: 6, paddingTop: 6, borderTop: "1px solid var(--line-soft)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3"
              stroke="#2fdfe0" strokeWidth="1.6" /></svg>
            observed relationship
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3"
              stroke="#7a5fb0" strokeWidth="1.6" strokeDasharray="4 4" /></svg>
            inferred (needs verification)
          </div>
        </div>
        {relations.length > 0 && (
          <div style={{ marginTop: 6, paddingTop: 6, borderTop: "1px solid var(--line-soft)" }}>
            <div style={{ fontWeight: 650, letterSpacing: 0.6, marginBottom: 4, color: "var(--fg-dim)" }}>
              RELATIONS
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4, maxWidth: 216 }}>
              {relations.map((rel) => {
                const off = hiddenRel.has(rel);
                return (
                  <button key={rel} className="chip chip-info"
                          title={off ? `Show ${rel} edges` : `Hide ${rel} edges`}
                          aria-pressed={!off}
                          onClick={() => setHiddenRel((prev) => {
                            const next = new Set(prev);
                            if (next.has(rel)) next.delete(rel); else next.add(rel);
                            return next;
                          })}
                          style={{ cursor: "pointer", opacity: off ? 0.34 : 1,
                                   textDecoration: off ? "line-through" : "none",
                                   border: "1px solid var(--line)", fontSize: 9.5 }}>
                    {rel}
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      <div style={{
        position: "absolute", bottom: 10, right: 10, fontFamily: "var(--mono)",
        fontSize: 10, color: "var(--fg-faint)", textAlign: "right",
      }}>
        {renderNodes.filter((n) => !n.aggregateCount).length} nodes · {renderEdges.length} edges · zoom {(view.k * 100).toFixed(0)}%
        {hiddenTotal > 0 && (
          <div style={{ color: "#ffb020" }}>{hiddenTotal} grouped (density cap)</div>
        )}
      </div>
    </div>
  );
}
