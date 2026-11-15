// TRACEWORK GraphCanvas — the signature attack-graph surface.
//
// Raw SVG (no graph dependency): observed vs inferred relationships must be
// distinguishable at a glance, and every node stays traceable to evidence.
// Layout: explicit radial bands, auto-fitted to the visible bounding box so the
// graph is always centred and fully in frame; dense graphs are capped and the
// overflow grouped per entity type rather than spilling off-screen.
//
// Light canvas, muted entity palette, solid = observed, dashed = inferred.

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { GraphData, GraphEdge, GraphNode } from "../api";
import { Icons } from "./icons";
import { EntityTypeIndicator } from "./ui";

interface EntityStyle { color: string; r: number; label: string; }

export const ENTITY_STYLE: Record<string, EntityStyle> = {
  host:     { color: "#176b5b", r: 15, label: "Host" },
  user:     { color: "#3c7384", r: 13, label: "User" },
  process:  { color: "#b9652e", r: 12, label: "Process" },
  file:     { color: "#6b5aa6", r: 11, label: "File" },
  domain:   { color: "#2f765a", r: 11, label: "Domain" },
  ip:       { color: "#a77828", r: 11, label: "IP" },
  event:    { color: "#65726d", r: 7,  label: "Event" },
  alert:    { color: "#b63d49", r: 14, label: "Alert" },
  artifact: { color: "#5b6b7a", r: 10, label: "Artifact" },
};

const RELATION_COLOR: Record<string, string> = {
  spawned: "#b9652e",
  ran: "#176b5b",
  authenticated: "#3c7384",
  connected_to: "#b63d49",
  resolved: "#2f765a",
  accessed: "#6b5aa6",
  active_on: "#6b5aa6",
  contacted_ioc: "#b63d49",
  supported_by: "#8a9490",
};

const OBSERVED_EDGE = "#7d8c86";
const HOT = "#176b5b";

const VIEW_W = 960;
const VIEW_H = 680;
const FIT_PAD = 56;
const K_MIN = 0.12;
const K_FIT_MIN = 0.03;
const K_MAX = 3.5;
const DEFAULT_MAX_NODES = 320;

interface Props {
  data: GraphData;
  selectedId: number | null;
  onSelect: (id: number | null) => void;
  showInferred: boolean;
  highlightTypes: Set<string>;
  showEvents?: boolean;
  maxNodes?: number;
  focusHosts?: string[] | null;
  onClearFocus?: () => void;
  onOpenEvidence?: (node: GraphNode) => void;
}

interface Pt { x: number; y: number; }
interface RenderNode extends GraphNode { aggregateCount?: number; }

function nodeRadius(n: RenderNode): number {
  const base = ENTITY_STYLE[n.node_type]?.r ?? 10;
  return n.aggregateCount ? base + 5 + Math.min(10, Math.log2(n.aggregateCount) * 1.6) : base;
}

/** Entity glyph, drawn centred on (0,0). Shape encodes the entity class. */
function Glyph({ type, r, color }: { type: string; r: number; color: string }) {
  const s = r * 0.62;
  switch (type) {
    case "host":
      return <rect x={-s} y={-s * 0.85} width={s * 2} height={s * 1.7} rx={2} fill="none" stroke={color} strokeWidth={1.3} />;
    case "user":
      return (
        <>
          <circle cy={-s * 0.55} r={s * 0.5} fill="none" stroke={color} strokeWidth={1.3} />
          <path d={`M${-s * 0.95} ${s} a${s * 0.95} ${s * 0.95} 0 0 1 ${s * 1.9} 0`} fill="none" stroke={color} strokeWidth={1.3} />
        </>
      );
    case "process":
      return <path d={`M0 ${-s} L${s} ${-s * 0.35} L${s * 0.62} ${s} L${-s * 0.62} ${s} L${-s} ${-s * 0.35} Z`} fill="none" stroke={color} strokeWidth={1.3} />;
    case "file":
      return (
        <>
          <path d={`M${-s * 0.75} ${-s} h${s * 1.05} l${s * 0.5} ${s * 0.5} v${s * 1.5} h${-s * 1.55} Z`} fill="none" stroke={color} strokeWidth={1.3} />
          <path d={`M${-s * 0.4} ${-s * 0.2} h${s * 0.85} M${-s * 0.4} ${s * 0.35} h${s * 0.85}`} stroke={color} strokeWidth={1.1} />
        </>
      );
    case "domain":
      return <path d={`M0 ${-s} L${s} 0 L0 ${s} L${-s} 0 Z`} fill="none" stroke={color} strokeWidth={1.3} />;
    case "ip":
      return (
        <>
          <circle r={s} fill="none" stroke={color} strokeWidth={1.3} />
          <path d={`M${-s * 0.5} 0 h${s} M0 ${-s * 0.5} v${s}`} stroke={color} strokeWidth={1.1} />
        </>
      );
    case "alert":
      return <path d={`M0 ${-s} L${s * 0.92} ${s * 0.72} L${-s * 0.92} ${s * 0.72} Z`} fill="none" stroke={color} strokeWidth={1.4} />;
    case "artifact":
      return <rect x={-s * 0.8} y={-s * 0.8} width={s * 1.6} height={s * 1.6} rx={2} fill="none" stroke={color} strokeWidth={1.3} />;
    default:
      return <circle r={Math.max(2, s * 0.4)} fill={color} />;
  }
}

export function GraphCanvas({
  data, selectedId, onSelect, showInferred, highlightTypes, showEvents = false,
  maxNodes = DEFAULT_MAX_NODES, focusHosts = null, onClearFocus, onOpenEvidence,
}: Props) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const [dims, setDims] = useState({ w: VIEW_W, h: VIEW_H });
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [hoverId, setHoverId] = useState<number | null>(null);
  const dragRef = useRef<{ startX: number; startY: number; origX: number; origY: number } | null>(null);
  const [dragging, setDragging] = useState(false);
  const [dragMoved, setDragMoved] = useState(false);
  const [hiddenRel, setHiddenRel] = useState<Set<string>>(new Set());

  // Track the real canvas size so the drawing space can match its aspect ratio
  // (the fixed layout space is widened/narrowed, never letterboxed or cropped).
  useLayoutEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const measure = () => {
      const r = el.getBoundingClientRect();
      if (r.width > 1 && r.height > 1) {
        setDims((d) => (Math.abs(d.w - r.width) < 0.5 && Math.abs(d.h - r.height) < 0.5
          ? d : { w: r.width, h: r.height }));
      }
    };
    // Measure now, again next frame (flex/grid can settle late), and observe
    // real resizes; web-font swap can also change the box once.
    measure();
    const raf = requestAnimationFrame(measure);
    const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(measure) : null;
    ro?.observe(el);
    document.fonts?.ready.then(measure).catch(() => {});
    return () => { cancelAnimationFrame(raf); ro?.disconnect(); };
  }, []);

  const vb = useMemo(() => {
    const base = VIEW_W / VIEW_H;
    const ar = dims.h > 0 ? dims.w / dims.h : base;
    if (ar >= base) {
      const w = VIEW_H * ar;
      return { x: VIEW_W / 2 - w / 2, y: 0, w, h: VIEW_H };
    }
    const h = VIEW_W / ar;
    return { x: 0, y: VIEW_H / 2 - h / 2, w: VIEW_W, h };
  }, [dims]);

  const openEvidence = onOpenEvidence ?? ((n: RenderNode) => onSelect(n.id));

  const visibleEdges = useMemo(
    () => data.edges.filter((e) => showInferred || e.status === "observed"),
    [data.edges, showInferred],
  );
  const relations = useMemo(
    () => [...new Set(data.edges.map((e) => e.relation))].sort(),
    [data.edges],
  );
  const visibleNodes = useMemo(
    () => (showEvents ? data.nodes : data.nodes.filter((n) => n.node_type !== "event")),
    [data.nodes, showEvents],
  );

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
    for (const n of ranked) {
      if (kept.size < maxNodes) kept.add(n.id);
      else hiddenByType.set(n.node_type, (hiddenByType.get(n.node_type) || 0) + 1);
    }
    const keptNodes: RenderNode[] = pool.filter((n) => kept.has(n.id));
    const groups: RenderNode[] = [...hiddenByType.entries()].map(([type, count], i) => ({
      id: -(1000 + i),
      project_id: keptNodes[0]?.project_id ?? 0,
      node_key: `__group__:${type}`,
      node_type: type,
      label: `${ENTITY_STYLE[type]?.label ?? type} ×${count}`,
      severity: null,
      attributes: { aggregate: true, count },
      aggregateCount: count,
    }));
    const nodes = [...keptNodes, ...groups];
    const ids = new Set(nodes.map((n) => n.id));
    const edges = focused.edges.filter((e) => ids.has(e.src_node_id) && ids.has(e.dst_node_id));
    return {
      renderNodes: nodes,
      renderEdges: edges,
      hiddenTotal: [...hiddenByType.values()].reduce((a, b) => a + b, 0),
    };
  }, [focused, maxNodes]);

  const nodeById = useMemo(() => {
    const m = new Map<number, RenderNode>();
    renderNodes.forEach((n) => m.set(n.id, n));
    return m;
  }, [renderNodes]);

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
      const minR = (count * (maxR * 2 + 30)) / (2 * Math.PI);
      const radius = Math.max(band, minR);
      nodes.forEach((n, i) => {
        const angle = (i / count) * Math.PI * 2 - Math.PI / 2 + band / 900;
        pos.set(n.id, { x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius });
      });
    }
    return pos;
  }, [renderNodes, renderEdges]);

  const fitView = useCallback(() => {
    const pts = renderNodes
      .map((n) => ({ p: positions.get(n.id), r: nodeRadius(n) + 16 }))
      .filter((x): x is { p: Pt; r: number } => !!x.p);
    if (pts.length === 0) { setView({ x: 0, y: 0, k: 1 }); return; }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const { p, r } of pts) {
      minX = Math.min(minX, p.x - r); minY = Math.min(minY, p.y - r);
      maxX = Math.max(maxX, p.x + r); maxY = Math.max(maxY, p.y + r);
    }
    const bw = Math.max(1, maxX - minX);
    const bh = Math.max(1, maxY - minY);
    const k = Math.min(
      K_MAX,
      Math.max(K_FIT_MIN, Math.min((vb.w - FIT_PAD * 2) / bw, (vb.h - FIT_PAD * 2) / bh)),
    );
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    setView({ x: vb.x + vb.w / 2 - cx * k, y: vb.y + vb.h / 2 - cy * k, k });
  }, [renderNodes, positions, vb]);

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
    const factor = ev.deltaY < 0 ? 1.12 : 0.89;
    setView((v) => {
      const k = Math.min(K_MAX, Math.max(K_MIN, v.k * factor));
      // Anchor zoom on the visible centre so the drawing does not drift away.
      const cx = vb.x + vb.w / 2;
      const cy = vb.y + vb.h / 2;
      const wx = (cx - v.x) / v.k;
      const wy = (cy - v.y) / v.k;
      return { k, x: cx - wx * k, y: cy - wy * k };
    });
  }, [vb]);

  const onPointerDown = (ev: React.PointerEvent) => {
    if ((ev.target as Element).closest("[data-node-id]")) return;
    (ev.target as Element).setPointerCapture?.(ev.pointerId);
    dragRef.current = { startX: ev.clientX, startY: ev.clientY, origX: view.x, origY: view.y };
    setDragging(true);
    setDragMoved(false);
  };
  const onPointerMove = (ev: React.PointerEvent) => {
    const d = dragRef.current;
    if (!d) return;
    const rect = svgRef.current?.getBoundingClientRect();
    const sx = rect && rect.width > 0 ? vb.w / rect.width : 1;
    const sy = rect && rect.height > 0 ? vb.h / rect.height : 1;
    const dx = (ev.clientX - d.startX) * sx;
    const dy = (ev.clientY - d.startY) * sy;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) setDragMoved(true);
    setView((v) => ({ ...v, x: d.origX + dx, y: d.origY + dy }));
  };
  const onPointerUp = () => { dragRef.current = null; setDragging(false); };

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
    if (highlightTypes.size > 0 && !highlightTypes.has(s.node_type) && !highlightTypes.has(d.node_type)) return false;
    return true;
  };

  const selected = selectedId != null ? nodeById.get(selectedId) : undefined;

  if (visibleNodes.length === 0 && data.nodes.length === 0) {
    return (
      <div className="tw-empty">
        <strong>No graph data</strong>
        <p>Load the demo dataset or import events, then run analysis to build the attack graph.</p>
      </div>
    );
  }

  return (
    <div className="tw-graph-canvas" ref={wrapRef}>
      <svg
        ref={svgRef}
        className={`tw-graph-svg ${dragging ? "grabbing" : ""}`}
        width={Math.round(dims.w)}
        height={Math.round(dims.h)}
        viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`}
        preserveAspectRatio="xMidYMid meet"
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={onPointerUp}
      >
        <defs>
          <marker id="gc-observed" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill={OBSERVED_EDGE} />
          </marker>
          <marker id="gc-inferred" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#8a7bb5" />
          </marker>
          <marker id="gc-hot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill={HOT} />
          </marker>
        </defs>

        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
          {renderEdges.filter((e) => !hiddenRel.has(e.relation) && edgeVisible(e)).map((e) => {
            const s = positions.get(e.src_node_id);
            const d = positions.get(e.dst_node_id);
            if (!s || !d) return null;
            const focus = selectedId ?? hoverId;
            const isHot = connected ? (e.src_node_id === focus || e.dst_node_id === focus) : false;
            const dim = connected !== null && !isHot;
            const color = isHot ? HOT : (RELATION_COLOR[e.relation] || OBSERVED_EDGE);
            const inferred = e.status === "inferred";
            return (
              <g key={e.id} opacity={dim ? 0.14 : 1}>
                <line
                  x1={s.x} y1={s.y} x2={d.x} y2={d.y}
                  stroke={color}
                  strokeWidth={isHot ? 2 : 1.15}
                  strokeDasharray={inferred ? "4 4" : undefined}
                  markerEnd={`url(#${isHot ? "gc-hot" : inferred ? "gc-inferred" : "gc-observed"})`}
                />
                {isHot && (
                  <text x={(s.x + d.x) / 2} y={(s.y + d.y) / 2 - 3}
                        fill={inferred ? "#6b5aa6" : "#465650"} fontSize={9} textAnchor="middle"
                        stroke="#ffffff" strokeWidth={3} paintOrder="stroke"
                        style={{ pointerEvents: "none", userSelect: "none" }}>
                    {e.relation}
                  </text>
                )}
              </g>
            );
          })}

          {renderNodes.map((n) => {
            const p = positions.get(n.id);
            if (!p) return null;
            const style = ENTITY_STYLE[n.node_type] || ENTITY_STYLE.event;
            const r = nodeRadius(n);
            if (highlightTypes.size > 0 && !highlightTypes.has(n.node_type)) {
              return <circle key={n.id} cx={p.x} cy={p.y} r={3} fill="#c7d2cb" opacity={0.6} />;
            }
            const isSelected = selectedId === n.id;
            const isHover = hoverId === n.id;
            const dim = connected !== null && !connected.has(n.id);
            const stroke = n.aggregateCount ? "#8a9490"
              : n.severity === "critical" ? "#b63d49"
              : n.severity === "high" ? "#b9652e"
              : style.color;
            return (
              <g key={n.id} data-node-id={n.id} transform={`translate(${p.x} ${p.y})`}
                 opacity={dim ? 0.2 : 1}
                 style={{ cursor: n.aggregateCount ? "default" : "pointer" }}
                 onPointerDown={(ev) => ev.stopPropagation()}
                 onClick={() => { if (!n.aggregateCount && !dragMoved) onSelect(isSelected ? null : n.id); }}
                 onDoubleClick={() => { if (!n.aggregateCount) openEvidence(n); }}
                 onMouseEnter={() => setHoverId(n.id)}
                 onMouseLeave={() => setHoverId(null)}>
                {isSelected && <circle r={r + 7} fill="none" stroke={HOT} strokeWidth={1.5} opacity={0.9} />}
                <circle r={r} fill={isSelected ? "#e8f1ed" : "#ffffff"} stroke={stroke}
                        strokeWidth={isSelected || isHover ? 2.2 : n.aggregateCount ? 1 : 1.6}
                        strokeDasharray={n.aggregateCount ? "3 3" : undefined} />
                <Glyph type={n.node_type} r={r} color={stroke} />
                {view.k > 0.55 && (
                  <text y={r + 11} textAnchor="middle"
                        fill={isSelected ? HOT : "#465650"} fontSize={9.5}
                        stroke="#ffffff" strokeWidth={3} paintOrder="stroke"
                        style={{ userSelect: "none", pointerEvents: "none" }}>
                    {n.label.length > 18 ? n.label.slice(0, 17) + "…" : n.label}
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      <div className="tw-graph-controls">
        <button className="tw-btn tw-btn-sm tw-btn-icon" title="Zoom in" aria-label="Zoom in"
                onClick={() => setView((v) => ({ ...v, k: Math.min(K_MAX, v.k * 1.25) }))}>
          {Icons.plus({ style: { width: 15, height: 15 } })}
        </button>
        <button className="tw-btn tw-btn-sm tw-btn-icon" title="Zoom out" aria-label="Zoom out"
                onClick={() => setView((v) => ({ ...v, k: Math.max(K_MIN, v.k / 1.25) }))}>
          {Icons.minus({ style: { width: 15, height: 15 } })}
        </button>
        <button className="tw-btn tw-btn-sm tw-btn-icon" title="Fit graph to view" aria-label="Fit to view"
                onClick={fitView}>
          {Icons.fit({ style: { width: 15, height: 15 } })}
        </button>
        <button className="tw-btn tw-btn-sm tw-btn-icon" title="Reset view" aria-label="Reset view" onClick={reset}>
          {Icons.reset({ style: { width: 15, height: 15 } })}
        </button>
      </div>

      {selected && !selected.aggregateCount && (
        <div className="tw-graph-quick">
          <EntityTypeIndicator type={selected.node_type} />
          <span className="truncate" style={{ maxWidth: 200 }}>{selected.label}</span>
          <button className="tw-btn tw-btn-sm" onClick={() => openEvidence(selected)}>Evidence →</button>
        </div>
      )}

      {focused.active && (
        <div className="tw-graph-quick" style={{ top: selected ? 60 : 12 }}>
          <span>Incident filter · {renderNodes.filter((n) => !n.aggregateCount).length} nodes</span>
          {onClearFocus && (
            <button className="tw-btn tw-btn-sm tw-btn-ghost tw-btn-icon" title="Clear incident filter"
                    onClick={onClearFocus}>
              {Icons.close({ style: { width: 12, height: 12 } })}
            </button>
          )}
        </div>
      )}

      <div className="tw-graph-legend">
        <div className="tw-section-title" style={{ marginBottom: 5 }}>Legend</div>
        <div className="tw-legend-grid">
          {Object.entries(ENTITY_STYLE).map(([k, v]) => (
            <div key={k} className="tw-legend-row">
              <span className="tw-legend-swatch" style={{ color: v.color }} />
              {v.label}
            </div>
          ))}
        </div>
        <div style={{ marginTop: 7, paddingTop: 7, borderTop: "1px solid var(--tw-border)" }}>
          <div className="tw-legend-row">
            <svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke={OBSERVED_EDGE} strokeWidth="1.6" /></svg>
            observed relationship
          </div>
          <div className="tw-legend-row">
            <svg width="26" height="6"><line x1="0" y1="3" x2="26" y2="3" stroke="#8a7bb5" strokeWidth="1.6" strokeDasharray="4 4" /></svg>
            inferred (needs verification)
          </div>
        </div>
        {relations.length > 0 && (
          <div style={{ marginTop: 7, paddingTop: 7, borderTop: "1px solid var(--tw-border)" }}>
            <div className="tw-section-title" style={{ marginBottom: 5 }}>Relations</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4, maxWidth: 210 }}>
              {relations.map((rel) => {
                const off = hiddenRel.has(rel);
                return (
                  <button key={rel} className={`tw-chip tw-chip-plain tw-rel-chip ${off ? "off" : ""}`}
                          title={off ? `Show ${rel} edges` : `Hide ${rel} edges`}
                          aria-pressed={!off}
                          onClick={() => setHiddenRel((prev) => {
                            const next = new Set(prev);
                            if (next.has(rel)) next.delete(rel); else next.add(rel);
                            return next;
                          })}>
                    {rel}
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      <div className="tw-graph-stats">
        {renderNodes.filter((n) => !n.aggregateCount).length} nodes · {renderEdges.length} edges · zoom {(view.k * 100).toFixed(0)}%
        {hiddenTotal > 0 && <div style={{ color: "var(--tw-warning)" }}>{hiddenTotal} grouped (density cap)</div>}
      </div>
    </div>
  );
}
