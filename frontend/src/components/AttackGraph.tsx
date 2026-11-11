// Interactive attack-graph renderer.
//
// Built on raw SVG rather than a graph library: the requirement is that
// observed and inferred relationships are *visually distinct at a glance* and
// that every node is traceable to evidence. A custom layout gives exact control
// over both, with zero added dependency surface.

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

interface Props {
  data: GraphData;
  selectedId: number | null;
  onSelect: (id: number | null) => void;
  showInferred: boolean;
  highlightTypes: Set<string>;
  /** Event nodes are numerous and visually dominant; hidden unless asked for. */
  showEvents?: boolean;
}

interface Pt { x: number; y: number }

export function AttackGraph({
  data, selectedId, onSelect, showInferred, highlightTypes, showEvents = false,
}: Props) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [hoverId, setHoverId] = useState<number | null>(null);
  const dragRef = useRef<{ startX: number; startY: number; origX: number; origY: number } | null>(null);
  const [dragMoved, setDragMoved] = useState(false);

  const visibleEdges = useMemo(
    () => data.edges.filter((e) => showInferred || e.status === "observed"),
    [data.edges, showInferred],
  );

  // Event nodes add ~30 nodes that visually swamp the entity graph. They are
  // reachable through the filter chips, but off by default.
  const visibleNodes = useMemo(
    () => (showEvents ? data.nodes : data.nodes.filter((n) => n.node_type !== "event")),
    [data.nodes, showEvents],
  );

  const nodeById = useMemo(() => {
    const m = new Map<number, GraphNode>();
    visibleNodes.forEach((n) => m.set(n.id, n));
    return m;
  }, [visibleNodes]);

  // Layout: explicit radial bands, one per entity class.
  //
  // Bands are assigned fixed radii so the structure is visually obvious:
  //   alerts            -> inner (they are the entry point of an investigation)
  //   hosts             -> band 1
  //   users             -> band 2
  //   processes/files   -> band 3
  //   external ip/domain-> band 4 (perimeter)
  //   events            -> outer band, only when the analyst enables them
  //
  // Within a band, nodes are distributed by angle, ordered by their graph
  // degree (highest degree first) so hubs land at predictable positions. The
  // result is deterministic: the same data always renders identically.
  const positions = useMemo(() => {
    const bandOf: Record<string, number> = {
      alert: 90, host: 165, user: 225, process: 290, file: 290,
      domain: 350, ip: 350, artifact: 350, event: 420,
    };

    const degree = new Map<number, number>();
    for (const e of visibleEdges) {
      degree.set(e.src_node_id, (degree.get(e.src_node_id) || 0) + 1);
      degree.set(e.dst_node_id, (degree.get(e.dst_node_id) || 0) + 1);
    }

    const byBand = new Map<number, GraphNode[]>();
    for (const n of visibleNodes) {
      const band = bandOf[n.node_type] ?? 420;
      if (!byBand.has(band)) byBand.set(band, []);
      byBand.get(band)!.push(n);
    }

    const pos = new Map<number, Pt>();
    const cx = 480;
    const cy = 340;

    for (const [band, nodes] of byBand) {
      nodes.sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0));
      const count = nodes.length;
      // grow the radius if this band holds more nodes than fit comfortably
      const nodeR = TYPE_STYLE[nodes[0].node_type]?.r ?? 10;
      const minR = (count * (nodeR * 2 + 34)) / (2 * Math.PI);
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
  }, [visibleNodes, visibleEdges]);

  const connected = useMemo(() => {
    const focus = selectedId ?? hoverId;
    if (!focus) return null;
    const set = new Set<number>([focus]);
    for (const e of visibleEdges) {
      if (e.src_node_id === focus) set.add(e.dst_node_id);
      if (e.dst_node_id === focus) set.add(e.src_node_id);
    }
    return set;
  }, [selectedId, hoverId, visibleEdges]);

  const onWheel = useCallback((ev: React.WheelEvent) => {
    ev.preventDefault();
    setView((v) => {
      const k = Math.min(3.5, Math.max(0.25, v.k * (ev.deltaY < 0 ? 1.12 : 0.89)));
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

  const reset = () => { setView({ x: 0, y: 0, k: 1 }); onSelect(null); };

  const edgeVisible = (e: GraphEdge) => {
    const s = nodeById.get(e.src_node_id);
    const d = nodeById.get(e.dst_node_id);
    if (!s || !d) return false;
    if (highlightTypes.size > 0 && !highlightTypes.has(s.node_type) && !highlightTypes.has(d.node_type)) {
      return false;
    }
    return true;
  };

  if (visibleNodes.length === 0 && data.nodes.length === 0) {
    return (
      <div className="empty">
        <strong>No graph data</strong>
        <div>Load the demo dataset or import events, then run analysis to build the attack graph.</div>
      </div>
    );
  }

  return (
    <div style={{ position: "relative", width: "100%", height: "100%", minHeight: 420 }}>
      <svg
        ref={svgRef}
        width="100%"
        height="100%"
        viewBox="0 0 960 680"
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
          {visibleEdges.filter(edgeVisible).map((e) => {
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
          {visibleNodes.map((n) => {
            const p = positions.get(n.id);
            if (!p) return null;
            const style = TYPE_STYLE[n.node_type] || TYPE_STYLE.event;
            if (highlightTypes.size > 0 && !highlightTypes.has(n.node_type)) {
              return (
                <circle key={n.id} cx={p.x} cy={p.y} r={3} fill="#12253c" opacity={0.5} />
              );
            }
            const isSelected = selectedId === n.id;
            const isHover = hoverId === n.id;
            const dim = connected !== null && !connected.has(n.id);
            const stroke = n.severity === "critical" ? "#ff4d5e"
              : n.severity === "high" ? "#ff8b3d"
              : style.color;
            return (
              <g
                key={n.id}
                data-node-id={n.id}
                transform={`translate(${p.x} ${p.y})`}
                opacity={dim ? 0.18 : 1}
                style={{ cursor: "pointer" }}
                onPointerDown={(ev) => ev.stopPropagation()}
                onClick={() => { if (!dragMoved) onSelect(isSelected ? null : n.id); }}
                onMouseEnter={() => setHoverId(n.id)}
                onMouseLeave={() => setHoverId(null)}
              >
                {isSelected && (
                  <circle r={style.r + 7} fill="none" stroke="#2fdfe0" strokeWidth={1.4} opacity={0.85} />
                )}
                <circle
                  r={style.r}
                  fill="#0b1421"
                  stroke={stroke}
                  strokeWidth={isSelected || isHover ? 2.2 : 1.5}
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
                    y={style.r + 11}
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
        <button className="btn btn-sm btn-icon" title="Zoom in"
                onClick={() => setView((v) => ({ ...v, k: Math.min(3.5, v.k * 1.25) }))}>+</button>
        <button className="btn btn-sm btn-icon" title="Zoom out"
                onClick={() => setView((v) => ({ ...v, k: Math.max(0.25, v.k / 1.25) }))}>−</button>
        <button className="btn btn-sm btn-icon" title="Reset view" onClick={reset}>⟲</button>
      </div>

      {/* legend */}
      <div style={{
        position: "absolute", bottom: 10, left: 10, background: "rgba(11,20,33,0.94)",
        border: "1px solid var(--line)", borderRadius: 5, padding: "9px 11px",
        fontSize: 10.5, lineHeight: 1.75, color: "var(--fg-muted)",
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
      </div>

      <div style={{
        position: "absolute", bottom: 10, right: 10, fontFamily: "var(--mono)",
        fontSize: 10, color: "var(--fg-faint)",
      }}>
        {visibleNodes.length} nodes · {visibleEdges.length} edges · zoom {(view.k * 100).toFixed(0)}%
      </div>
    </div>
  );
}
