import { useCallback, useEffect, useMemo, useState } from "react";
import { api, downloadReport, type AiResult, type AiRun, type IncidentDetail, type GraphData } from "../api";
import { AttackGraph } from "../components/AttackGraph";
import {
  Empty, ErrorBanner, Loading, SeverityChip, StatusChip, TsBadge, fmtBytes, fmtTime,
} from "../components/ui";

interface Props {
  incidentId: number | null;
}

const TABS = ["Overview", "Attack graph", "Timeline", "Evidence", "AI analysis", "Report"] as const;
type Tab = typeof TABS[number];

export function IncidentView({ incidentId }: Props) {
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("Overview");
  const [selectedNode, setSelectedNode] = useState<number | null>(null);
  const [showInferred, setShowInferred] = useState(true);
  const [nodeTypes, setNodeTypes] = useState<Set<string>>(new Set());
  const [showEvents, setShowEvents] = useState(false);

  const load = useCallback(async () => {
    if (!incidentId) { setDetail(null); return; }
    setLoading(true);
    setError(null);
    try {
      const [d, g] = await Promise.all([
        api.incident(incidentId),
        api.graph({ include_inferred: true }),
      ]);
      setDetail(d);
      setGraph(g);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load incident");
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => { void load(); }, [load]);

  if (!incidentId) {
    return (
      <Empty title="No incident selected"
             detail="Pick an incident from the Incidents list to open the investigation workspace." />
    );
  }
  if (loading && !detail) return <Loading label="Loading incident…" />;
  if (error && !detail) return <ErrorBanner message={error} onRetry={load} />;
  if (!detail) return null;

  const inc = detail.incident;

  const setStatus = async (status: string) => {
    try {
      await api.setStatus(inc.id, status, "Changed from investigation workspace");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Status update failed");
    }
  };

  return (
    <div className="content flush">
      <div style={{ padding: "16px 20px 12px", borderBottom: "1px solid var(--line)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 11, flexWrap: "wrap" }}>
          <span className="mono" style={{ color: "var(--cyan)", fontSize: 13, fontWeight: 600 }}>
            {inc.ref}
          </span>
          <SeverityChip severity={inc.severity} />
          <span className="chip chip-info">{inc.status}</span>
          <h2 style={{ fontSize: 15, margin: 0, fontWeight: 600, flex: 1, minWidth: 200 }}>
            {inc.title}
          </h2>
          <select className="select" style={{ width: 150 }}
                  value={inc.status}
                  onChange={(e) => void setStatus(e.target.value)}>
            <option value="open">open</option>
            <option value="investigating">investigating</option>
            <option value="contained">contained</option>
            <option value="closed">closed</option>
          </select>
        </div>
        <div className="mono faint" style={{ fontSize: 11, marginTop: 7 }}>
          window {fmtTime(inc.first_ts)} → {fmtTime(inc.last_ts)} · {detail.alerts.length} alert(s) ·
          {" "}{detail.events.length} evidence event(s)
        </div>
      </div>

      <div className="tabs">
        {TABS.map((t) => (
          <button key={t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {t}
            {t === "Evidence" ? <span className="count">{detail.events.length}</span> : null}
            {t === "Timeline" ? <span className="count">{detail.timeline.length}</span> : null}
            {t === "AI analysis" ? <span className="count">{detail.ai_runs.length}</span> : null}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: tab === "Attack graph" ? "hidden" : "auto", padding: tab === "Attack graph" ? 0 : 20 }}>
        {error ? <ErrorBanner message={error} onRetry={load} /> : null}

        {tab === "Overview" && <OverviewTab detail={detail} />}

        {tab === "Attack graph" && (
          <div style={{ display: "grid", gridTemplateColumns: selectedNode ? "1fr 380px" : "1fr",
                        gridTemplateRows: "minmax(0, 1fr)", height: "100%" }}>
            <div style={{ position: "relative", minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column" }}>
              <GraphToolbar
                showInferred={showInferred}
                setShowInferred={setShowInferred}
                nodeTypes={nodeTypes}
                setNodeTypes={setNodeTypes}
                graph={graph}
                showEvents={showEvents}
                setShowEvents={setShowEvents}
              />
              <div style={{ flex: 1, minHeight: 0 }}>
                {graph ? (
                  <AttackGraph
                    data={graph}
                    selectedId={selectedNode}
                    onSelect={setSelectedNode}
                    showInferred={showInferred}
                    highlightTypes={nodeTypes}
                    showEvents={showEvents}
                    onOpenEvidence={() => setTab("Evidence")}
                  />
                ) : <Loading label="Building layout…" />}
              </div>
            </div>
            {selectedNode ? (
              <NodePanel nodeId={selectedNode} onClose={() => setSelectedNode(null)} />
            ) : null}
          </div>
        )}

        {tab === "Timeline" && <TimelineTab detail={detail} />}
        {tab === "Evidence" && <EvidenceTab detail={detail} />}
        {tab === "AI analysis" && <AiTab detail={detail} onReload={load} />}
        {tab === "Report" && <ReportTab incidentId={inc.id} />}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

function OverviewTab({ detail }: { detail: IncidentDetail }) {
  const hosts = [...new Set(detail.events.map((e) => e.host).filter(Boolean))] as string[];
  const users = [...new Set(detail.events.map((e) => e.user_name).filter(Boolean))] as string[];

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="banner banner-warn">
        <span>
          <strong>Evidence boundary.</strong> Rule-based findings below are deterministic
          correlations over normalized events. They indicate suspicious behaviour; they do
          <em> not</em> by themselves prove compromise or data exfiltration.
        </span>
      </div>

      <div className="grid grid-3">
        <div className="panel">
          <div className="panel-head"><span className="panel-title">Affected assets</span></div>
          <div className="panel-body" style={{ fontSize: 12.5 }}>
            {hosts.length === 0 ? <span className="dim">none identified</span> :
              hosts.map((h) => (
                <div key={h} className="mono" style={{ marginBottom: 3, color: "var(--cyan-dim)" }}>{h}</div>
              ))}
          </div>
        </div>
        <div className="panel">
          <div className="panel-head"><span className="panel-title">Accounts involved</span></div>
          <div className="panel-body" style={{ fontSize: 12.5 }}>
            {users.length === 0 ? <span className="dim">none identified</span> :
              users.map((u) => (
                <div key={u} className="mono" style={{ marginBottom: 3 }}>{u}</div>
              ))}
          </div>
        </div>
        <div className="panel">
          <div className="panel-head"><span className="panel-title">Status history</span></div>
          <div className="panel-body" style={{ fontSize: 12, lineHeight: 1.8 }}>
            {detail.status_history.map((h) => (
              <div key={h.id}>
                <span className="mono faint">{fmtTime(h.changed_at)}</span>
                <br />
                <span style={{ color: "var(--fg-dim)" }}>
                  {h.from_status || "(new)"} → <strong>{h.to_status}</strong>
                </span>
                {h.note ? <div className="faint" style={{ fontSize: 11 }}>{h.note}</div> : null}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Findings — why this fired</span>
          <span className="spacer" />
          <span className="mono faint" style={{ fontSize: 10.5 }}>deterministic rule engine</span>
        </div>
        <div className="panel-body col" style={{ gap: 12 }}>
          {detail.alerts.map((a) => (
            <div key={a.id} style={{
              borderLeft: `3px solid var(--${a.severity === "info" ? "info" : a.severity})`,
              paddingLeft: 12, paddingBottom: 10,
              borderBottom: "1px solid var(--line-soft)",
            }}>
              <div style={{ display: "flex", gap: 9, alignItems: "center", marginBottom: 5, flexWrap: "wrap" }}>
                <span className="mono" style={{ color: "var(--cyan-dim)", fontSize: 11.5 }}>{a.rule_id}</span>
                <SeverityChip severity={a.severity} />
                <strong style={{ fontSize: 13 }}>{a.title}</strong>
              </div>
              <div style={{ fontSize: 12.5, color: "var(--fg-dim)", lineHeight: 1.65 }}>{a.narrative}</div>
              {a.rule_logic ? (
                <div className="mono faint" style={{ fontSize: 10.5, marginTop: 5 }}>
                  logic: {a.rule_logic}
                </div>
              ) : null}
              <div className="mono" style={{ fontSize: 11, marginTop: 6, color: "var(--cyan-dim)" }}>
                supporting events: {a.evidence.map((e) => `#${e.id}`).join(", ") || "none"}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function GraphToolbar({ showInferred, setShowInferred, nodeTypes, setNodeTypes, graph,
                        showEvents, setShowEvents }: {
  showInferred: boolean; setShowInferred: (v: boolean) => void;
  nodeTypes: Set<string>; setNodeTypes: (s: Set<string>) => void;
  graph: GraphData | null;
  showEvents: boolean; setShowEvents: (v: boolean) => void;
}) {
  const types = useMemo(() => {
    const s = new Set<string>();
    graph?.nodes.forEach((n) => s.add(n.node_type));
    return [...s].sort();
  }, [graph]);

  const toggle = (t: string) => {
    const next = new Set(nodeTypes);
    if (next.has(t)) next.delete(t); else next.add(t);
    setNodeTypes(next);
  };

  const inferredCount = graph?.edges.filter((e) => e.status === "inferred").length ?? 0;

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12, padding: "9px 14px",
      borderBottom: "1px solid var(--line)", background: "var(--bg-elevated)", flexWrap: "wrap",
    }}>
      <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, cursor: "pointer" }}>
        <input type="checkbox" checked={showInferred}
               onChange={(e) => setShowInferred(e.target.checked)} />
        Show inferred edges
        <span className="mono faint" style={{ fontSize: 10.5 }}>({inferredCount})</span>
      </label>
      <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, cursor: "pointer" }}>
        <input type="checkbox" checked={showEvents}
               onChange={(e) => setShowEvents(e.target.checked)} />
        Show event nodes
      </label>
      <span style={{ width: 1, height: 16, background: "var(--line)" }} />
      <span className="faint" style={{ fontSize: 11 }}>Filter types:</span>
      {types.map((t) => (
        <button
          key={t}
          className={`chip ${nodeTypes.has(t) ? "chip-observed" : "chip-info"}`}
          style={{ cursor: "pointer", border: "1px solid var(--line)" }}
          onClick={() => toggle(t)}
        >
          {t}
        </button>
      ))}
      {nodeTypes.size > 0 ? (
        <button className="btn btn-sm" onClick={() => setNodeTypes(new Set())}>clear</button>
      ) : null}
    </div>
  );
}

function NodePanel({ nodeId, onClose }: { nodeId: number; onClose: () => void }) {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.nodeDetail>> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setData(null);
    setError(null);
    api.nodeDetail(nodeId)
      .then((d) => { if (alive) setData(d); })
      .catch((e) => { if (alive) setError(e instanceof Error ? e.message : "Failed"); });
    return () => { alive = false; };
  }, [nodeId]);

  return (
    <div style={{
      borderLeft: "1px solid var(--line)", background: "var(--bg-elevated)",
      overflowY: "auto", display: "flex", flexDirection: "column",
    }}>
      <div className="panel-head" style={{ position: "sticky", top: 0, background: "var(--bg-elevated)", zIndex: 2 }}>
        <span className="panel-title">Node detail</span>
        <span className="spacer" />
        <button className="btn btn-sm btn-icon" onClick={onClose}>✕</button>
      </div>
      {error ? <div style={{ padding: 14 }}><ErrorBanner message={error} /></div> : null}
      {!data && !error ? <Loading /> : null}
      {data ? (
        <div style={{ padding: 14, fontSize: 12.5 }}>
          <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 3, wordBreak: "break-word" }}>
            {data.node.label}
          </div>
          <div className="mono faint" style={{ fontSize: 10.5, marginBottom: 10 }}>
            {data.node.node_type} · {data.node.node_key}
          </div>
          {data.node.severity ? (
            <div style={{ marginBottom: 10 }}><SeverityChip severity={data.node.severity} /></div>
          ) : null}

          {data.node.attributes && Object.keys(data.node.attributes).length > 0 ? (
            <div className="panel" style={{ padding: 9, marginBottom: 12, background: "var(--panel)" }}>
              <div className="mono" style={{ fontSize: 10.5, color: "var(--fg-muted)", marginBottom: 4 }}>
                ATTRIBUTES
              </div>
              <pre className="mono" style={{ margin: 0, fontSize: 10.5, whiteSpace: "pre-wrap",
                                             color: "var(--fg-dim)" }}>
                {JSON.stringify(data.node.attributes, null, 1)}
              </pre>
            </div>
          ) : null}

          <Section title={`Incoming relations (${data.incoming.length})`}>
            {data.incoming.map((e) => (
              <div key={e.id} style={{ marginBottom: 7, fontSize: 11.5 }}>
                <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                  <span className="mono" style={{ color: "var(--cyan-dim)" }}>{e.src_label}</span>
                  <span className="faint">→ {e.relation} →</span>
                </div>
                <div style={{ marginTop: 2 }}>
                  <StatusChip status={e.status as "observed" | "inferred"} />
                  <span className="faint" style={{ fontSize: 10.5, marginLeft: 6 }}>{e.method}</span>
                </div>
                <div className="mono" style={{ fontSize: 10, marginTop: 3 }}>
                  {e.evidence_event_ids && e.evidence_event_ids.length > 0 ? (
                    <span style={{ color: "var(--green)" }}>
                      evidence: {e.evidence_event_ids.map((x) => `#${x}`).join(", ")}
                    </span>
                  ) : (
                    <span className="faint">derived relation — no single source event</span>
                  )}
                </div>
              </div>
            ))}
            {data.incoming.length === 0 ? <span className="faint">none</span> : null}
          </Section>

          <Section title={`Outgoing relations (${data.outgoing.length})`}>
            {data.outgoing.map((e) => (
              <div key={e.id} style={{ marginBottom: 7, fontSize: 11.5 }}>
                <div className="faint">→ {e.relation} →</div>
                <div className="mono" style={{ color: "var(--cyan-dim)" }}>{e.dst_label}</div>
                <div style={{ marginTop: 2 }}>
                  <StatusChip status={e.status as "observed" | "inferred"} />
                  <span className="faint" style={{ fontSize: 10.5, marginLeft: 6 }}>{e.method}</span>
                </div>
                <div className="mono" style={{ fontSize: 10, marginTop: 3 }}>
                  {e.evidence_event_ids && e.evidence_event_ids.length > 0 ? (
                    <span style={{ color: "var(--green)" }}>
                      evidence: {e.evidence_event_ids.map((x) => `#${x}`).join(", ")}
                    </span>
                  ) : (
                    <span className="faint">derived relation — no single source event</span>
                  )}
                </div>
              </div>
            ))}
            {data.outgoing.length === 0 ? <span className="faint">none</span> : null}
          </Section>

          <Section title={`Supporting events (${data.evidence.length})`}>
            {data.evidence.slice(0, 20).map((ev) => (
              <div key={ev.id} style={{
                marginBottom: 6, paddingBottom: 6, borderBottom: "1px solid var(--line-soft)",
                fontSize: 11,
              }}>
                <div style={{ display: "flex", gap: 7, alignItems: "center" }}>
                  <span className="mono" style={{ color: "var(--cyan-dim)" }}>#{ev.id}</span>
                  <TsBadge status={ev.ts_status} raw={ev.ts_utc} />
                </div>
                <div className="mono faint" style={{ fontSize: 10.5, wordBreak: "break-all" }}>
                  {ev.event_type} · {ev.host || "?"}
                  {ev.process_name ? ` · ${ev.process_name}` : ""}
                </div>
              </div>
            ))}
            {data.evidence.length === 0 ? <span className="faint">No event evidence linked.</span> : null}
          </Section>
        </div>
      ) : null}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div className="mono" style={{
        fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase",
        color: "var(--fg-muted)", marginBottom: 6, fontWeight: 650,
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function TimelineTab({ detail }: { detail: IncidentDetail }) {
  const [hostFilter, setHostFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");

  const hosts = [...new Set(detail.timeline.map((t) => t.host).filter(Boolean))] as string[];
  const types = [...new Set(detail.timeline.map((t) => t.event_type))].sort();

  const rows = detail.timeline.filter(
    (t) => (!hostFilter || t.host === hostFilter) && (!typeFilter || t.event_type === typeFilter),
  );

  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row" style={{ flexWrap: "wrap" }}>
        <select className="select" style={{ width: 180 }} value={hostFilter}
                onChange={(e) => setHostFilter(e.target.value)}>
          <option value="">All hosts</option>
          {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <select className="select" style={{ width: 180 }} value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}>
          <option value="">All event types</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <span className="faint mono" style={{ fontSize: 11 }}>
          {rows.length} of {detail.timeline.length} events
        </span>
      </div>

      <div className="panel">
        {rows.length === 0 ? <Empty title="No events match the filter" /> : (
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 230 }}>Time (UTC)</th>
                <th style={{ width: 130 }}>Host</th>
                <th style={{ width: 110 }}>User</th>
                <th style={{ width: 130 }}>Event</th>
                <th>Detail</th>
                <th style={{ width: 56 }}>ID</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.id}>
                  <td><TsBadge status={t.ts_status} raw={t.ts_utc || t.ts_raw} /></td>
                  <td className="mono dim">{t.host || "—"}</td>
                  <td className="mono dim">{t.user || "—"}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{t.event_type}</td>
                  <td className="mono truncate" style={{ maxWidth: 420, fontSize: 11 }}
                      title={t.detail || ""}>
                    {t.detail || "—"}
                  </td>
                  <td className="mono" style={{ color: "var(--cyan-dim)" }}>#{t.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function EvidenceTab({ detail }: { detail: IncidentDetail }) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const byEvent = useMemo(() => {
    const m = new Map<number, { event: typeof detail.events[0]; alerts: string[] }>();
    for (const a of detail.alerts) {
      for (const e of a.evidence || []) {
        if (!m.has(e.id)) m.set(e.id, { event: e, alerts: [] });
        m.get(e.id)!.alerts.push(a.rule_id);
      }
    }
    return m;
  }, [detail]);

  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="banner banner-info">
        <span>
          Each row is a raw event that supports at least one finding. Expand a row to see the
          original record exactly as it was stored after normalization.
        </span>
      </div>
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Evidence events</span>
          <span className="spacer" />
          <span className="mono faint" style={{ fontSize: 10.5 }}>
            {byEvent.size} unique event(s)
          </span>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 56 }}>ID</th>
              <th style={{ width: 170 }}>Time</th>
              <th style={{ width: 120 }}>Host</th>
              <th style={{ width: 120 }}>Event type</th>
              <th style={{ width: 120 }}>Supports</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {[...byEvent.values()].map(({ event, alerts }) => (
              <>
                <tr key={event.id} className="clickable"
                    onClick={() => setExpanded(expanded === event.id ? null : event.id)}>
                  <td className="mono" style={{ color: "var(--cyan-dim)" }}>#{event.id}</td>
                  <td><TsBadge status={event.ts_status} raw={event.ts_utc || event.ts_raw} /></td>
                  <td className="mono dim">{event.host || "—"}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{event.event_type}</td>
                  <td className="mono" style={{ fontSize: 10.5, color: "var(--cyan-dim)" }}>
                    {alerts.join(", ")}
                  </td>
                  <td className="mono truncate" style={{ maxWidth: 380, fontSize: 11 }}>
                    {event.command_line || event.file_path || event.domain ||
                     event.process_name || event.action || "—"}
                  </td>
                </tr>
                {expanded === event.id ? (
                  <tr key={`${event.id}-raw`}>
                    <td colSpan={6} style={{ background: "var(--bg)", padding: 12 }}>
                      <div className="mono" style={{ fontSize: 10.5, color: "var(--fg-muted)",
                                                     marginBottom: 5 }}>
                        RAW RECORD (as stored)
                      </div>
                      <pre className="mono" style={{
                        margin: 0, fontSize: 10.5, whiteSpace: "pre-wrap",
                        color: "var(--fg-dim)", maxHeight: 260, overflow: "auto",
                      }}>
                        {prettyRaw(event.raw)}
                      </pre>
                      <div className="mono faint" style={{ fontSize: 10.5, marginTop: 7 }}>
                        ts_raw={event.ts_raw || "(none)"} · ts_status={event.ts_status} ·
                        bytes_out={fmtBytes(event.bytes_out)}
                      </div>
                    </td>
                  </tr>
                ) : null}
              </>
            ))}
          </tbody>
        </table>
        {byEvent.size === 0 ? <Empty title="No linked evidence" /> : null}
      </div>
    </div>
  );
}

function prettyRaw(raw: string | null): string {
  if (!raw) return "(no raw record stored)";
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}

function AiTab({ detail, onReload }: { detail: IncidentDetail; onReload: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [issues, setIssues] = useState<string[]>([]);
  const [errorCat, setErrorCat] = useState<string | null>(null);

  const latest = detail.ai_runs[0];
  const result = latest?.result_json && !("raw_output" in latest.result_json)
    ? (latest.result_json as AiResult) : null;

  const run = async () => {
    setBusy(true); setMsg(null); setIssues([]); setErrorCat(null);
    try {
      const r = await api.analyzeIncident(detail.incident.id);
      if (r.status === "no_provider") {
        setMsg(r.message || "No AI provider configured.");
      } else if (r.status === "error") {
        setErrorCat(r.error_category || "error");
        setMsg(r.error_message || "Provider call failed.");
      } else if (r.status === "validation_failed") {
        setMsg("The model returned output that did not match the required schema. "
             + "It was NOT applied as findings.");
        setIssues(r.issues || []);
      } else {
        setMsg(`Analysis complete with ${r.provider}/${r.model} (${r.latency_ms} ms).`);
        setIssues(r.issues || []);
      }
      await onReload();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="banner banner-warn">
        <span>
          <strong>AI output is interpretation, not evidence.</strong> Only the events in this
          incident are sent, and every referenced event ID is verified against the database
          before storage. Invented references are stripped and reported.
        </span>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Run analysis</span>
          <span className="spacer" />
          <span className="mono faint" style={{ fontSize: 10.5 }}>
            provider: {detail.ai_status.mode === "ai_enabled"
              ? `${detail.ai_status.provider}/${detail.ai_status.model}`
              : "none (core mode)"}
          </span>
          <button className="btn btn-primary btn-sm" onClick={() => void run()} disabled={busy}>
            {busy ? "Running…" : "Analyze with AI"}
          </button>
        </div>
        <div className="panel-body" style={{ fontSize: 12.5 }}>
          {detail.ai_status.mode !== "ai_enabled" ? (
            <div className="dim">
              No AI provider is active. Configure one under <strong>AI Providers</strong>, or
              continue using the deterministic engine — detection, correlation, graph, timeline
              and reports all work without AI.
            </div>
          ) : (
            <div className="dim">
              Model: <span className="mono">{detail.ai_status.model}</span>
              {detail.ai_status.last_test_status
                ? <span className="faint"> · last connection test: {detail.ai_status.last_test_status}</span>
                : null}
            </div>
          )}
        </div>
      </div>

      {msg ? (
        <div className={`banner ${errorCat ? "banner-err" : "banner-info"}`}>
          <span>{msg}{errorCat ? ` (${errorCat})` : ""}</span>
        </div>
      ) : null}

      {issues.length > 0 ? (
        <div className="banner banner-warn">
          <div>
            <strong>Validation notes:</strong>
            <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>
              {issues.map((i, k) => <li key={k}>{i}</li>)}
            </ul>
          </div>
        </div>
      ) : null}

      {result ? (
        <div className="col" style={{ gap: 12 }}>
          <div className="panel">
            <div className="panel-head">
              <span className="panel-title">Summary</span>
              <span className="spacer" />
              <span className="mono faint" style={{ fontSize: 10.5 }}>
                {latest.provider}/{latest.model} · {latest.latency_ms} ms
              </span>
            </div>
            <div className="panel-body" style={{ fontSize: 13, lineHeight: 1.7 }}>
              {result.summary || <span className="dim">(empty)</span>}
              <div className="dim" style={{ fontSize: 11.5, marginTop: 9, fontStyle: "italic" }}>
                Summary is free-form model text and is not verified against the event
                store. Only hypotheses carrying event citations were checked.
              </div>
              {result.timeline_interpretation ? (
                <div style={{ marginTop: 10, color: "var(--fg-dim)" }}>
                  <strong style={{ fontSize: 11.5, letterSpacing: 0.5,
                                   textTransform: "uppercase", color: "var(--fg-muted)" }}>
                    Timeline interpretation
                  </strong>
                  <div style={{ marginTop: 3 }}>{result.timeline_interpretation}</div>
                </div>
              ) : null}
            </div>
          </div>

          {result.hypotheses.length > 0 ? (
            <div className="panel">
              <div className="panel-head"><span className="panel-title">Hypotheses</span></div>
              <div className="panel-body col" style={{ gap: 11 }}>
                {result.hypotheses.map((h, i) => (
                  <div key={i} style={{
                    borderLeft: "3px solid var(--purple)", paddingLeft: 11,
                  }}>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                      <span className={`chip ${h.confidence === "high" ? "chip-high"
                        : h.confidence === "medium" ? "chip-medium" : "chip-info"}`}>
                        {h.confidence} confidence
                      </span>
                      {h.evidence_status === "unsupported" ? (
                        <span className="chip chip-high"
                              title="Every citation from the model referenced events that do not exist in this incident. Treat as an unverified claim.">
                          no surviving evidence
                        </span>
                      ) : h.evidence_status === "contested" ? (
                        <span className="chip chip-medium">evidence contested</span>
                      ) : h.evidence_status === "supported" ? (
                        <span className="chip chip-observed">evidence-linked</span>
                      ) : null}
                    </div>
                    <div style={{ fontSize: 13, lineHeight: 1.6 }}>{h.statement}</div>
                    {h.reasoning ? (
                      <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>{h.reasoning}</div>
                    ) : null}
                    <div className="mono" style={{ fontSize: 10.5, marginTop: 5 }}>
                      <span style={{ color: "var(--green)" }}>
                        supports: {h.supporting_event_ids.map((x) => `#${x}`).join(", ") || "none"}
                      </span>
                      {"  "}
                      <span style={{ color: "var(--high)" }}>
                        contradicts: {h.contradicting_event_ids.map((x) => `#${x}`).join(", ") || "none"}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {result.missing_information.length > 0 || result.next_investigation_steps.length > 0 ? (
            <div className="grid grid-2">
              {result.missing_information.length > 0 ? (
                <div className="panel">
                  <div className="panel-head"><span className="panel-title">Still unknown</span></div>
                  <div className="panel-body" style={{ fontSize: 12.5 }}>
                    <ul style={{ margin: 0, paddingLeft: 17, lineHeight: 1.75 }}>
                      {result.missing_information.map((m, i) => <li key={i}>{m}</li>)}
                    </ul>
                  </div>
                </div>
              ) : null}
              {result.next_investigation_steps.length > 0 ? (
                <div className="panel">
                  <div className="panel-head">
                    <span className="panel-title">Next steps (advisory)</span>
                  </div>
                  <div className="panel-body" style={{ fontSize: 12.5 }}>
                    <ul style={{ margin: 0, paddingLeft: 17, lineHeight: 1.75 }}>
                      {result.next_investigation_steps.map((s, i) => <li key={i}>{s}</li>)}
                    </ul>
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}

          {result.uncertainty_notes ? (
            <div className="banner banner-warn">
              <span><strong>Uncertainty:</strong> {result.uncertainty_notes}</span>
            </div>
          ) : null}
        </div>
      ) : latest && latest.status !== "ok" && latest.status !== "ok_with_warnings" ? (
        <RunHistory runs={detail.ai_runs} />
      ) : null}

      {detail.ai_runs.length > 1 && result ? <RunHistory runs={detail.ai_runs} /> : null}
    </div>
  );
}

function RunHistory({ runs }: { runs: AiRun[] }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <span className="panel-title">Run history</span>
        <span className="spacer" />
        <span className="mono faint" style={{ fontSize: 10.5 }}>most recent first</span>
      </div>
      <table className="table">
        <thead>
          <tr>
            <th style={{ width: 60 }}>ID</th>
            <th style={{ width: 150 }}>Provider / model</th>
            <th style={{ width: 130 }}>Status</th>
            <th style={{ width: 80 }}>Latency</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((r) => (
            <tr key={r.id}>
              <td className="mono dim">#{r.id}</td>
              <td className="mono" style={{ fontSize: 11 }}>
                {r.provider || "—"}{r.model ? ` / ${r.model}` : ""}
              </td>
              <td className="mono" style={{
                fontSize: 11,
                color: r.status.startsWith("ok") ? "var(--green)" : "var(--high)",
              }}>
                {r.status}
              </td>
              <td className="mono dim">{r.latency_ms ? `${r.latency_ms}ms` : "—"}</td>
              <td className="dim truncate" style={{ maxWidth: 320, fontSize: 11 }}>
                {r.error_message || r.error_category || "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ReportTab({ incidentId }: { incidentId: number }) {
  const [fmt, setFmt] = useState<"md" | "html" | "json">("md");
  const [content, setContent] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = async (f: typeof fmt) => {
    setBusy(true); setError(null);
    try {
      const r = await api.report(incidentId, f);
      setContent(r.content);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Report generation failed");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { void generate(fmt); }, [incidentId, fmt]);

  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row" style={{ flexWrap: "wrap" }}>
        <select className="select" style={{ width: 160 }} value={fmt}
                onChange={(e) => setFmt(e.target.value as typeof fmt)}>
          <option value="md">Markdown</option>
          <option value="html">HTML (printable)</option>
          <option value="json">JSON</option>
        </select>
        <button className="btn btn-sm" onClick={() => void generate(fmt)} disabled={busy}>
          {busy ? "Generating…" : "Regenerate"}
        </button>
        <button className="btn btn-sm btn-primary"
                        onClick={() => void downloadReport(api.reportUrl(incidentId, fmt),
                          `incident-${incidentId}-report.${fmt}`)}>
                  Download
                </button>
        {fmt === "html" ? (
          <button className="btn btn-sm" onClick={() => {
            const w = window.open("", "_blank");
            if (w && content) { w.document.write(content); w.document.close(); }
          }}>
            Open printable view
          </button>
        ) : null}
      </div>
      {error ? <ErrorBanner message={error} onRetry={() => void generate(fmt)} /> : null}
      {busy && !content ? <Loading label="Generating report…" /> : null}
      {content ? (
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">{fmt.toUpperCase()} report</span>
            <span className="spacer" />
            <span className="mono faint" style={{ fontSize: 10.5 }}>
              generated from stored data only · {content.length.toLocaleString()} chars
            </span>
          </div>
          <div className="panel-body" style={{ padding: 0 }}>
            {fmt === "md" ? (
              <pre className="mono" style={{
                margin: 0, padding: 16, fontSize: 11.5, whiteSpace: "pre-wrap",
                color: "var(--fg-dim)", maxHeight: 640, overflow: "auto", lineHeight: 1.65,
              }}>
                {content}
              </pre>
            ) : fmt === "html" ? (
              <iframe title="Report preview" srcDoc={content}
                      style={{ width: "100%", height: 640, border: "none", background: "#070d18" }} />
            ) : (
              <pre className="mono" style={{
                margin: 0, padding: 16, fontSize: 11, whiteSpace: "pre-wrap",
                color: "var(--fg-dim)", maxHeight: 640, overflow: "auto",
              }}>
                {content}
              </pre>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}
