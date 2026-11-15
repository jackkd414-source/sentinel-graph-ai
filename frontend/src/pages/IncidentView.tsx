import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import {
  api, downloadReport,
  type AiResult, type AiRun, type EventRow, type GraphData, type IncidentDetail,
} from "../api";
import { GraphCanvas } from "../components/GraphCanvas";
import { NodeInspector } from "../components/NodeInspector";
import { Tabs, DataTable, PanelHeader, FilterBar, type Column } from "../components/data";
import {
  EmptyState, ErrorState, LoadingState, SeverityIndicator, StatusIndicator,
  EvidenceReference, SourceLabel, Timestamp, fmtBytes, fmtTime,
} from "../components/ui";
import { Icons } from "../components/icons";
import {
  Callout, Card, ChipTimeline, Donut, Stat, Stats, type ChipTimelineItem,
} from "../components/widgets";

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "timeline", label: "Timeline" },
  { key: "graph", label: "Attack graph" },
  { key: "evidence", label: "Evidence" },
  { key: "ai", label: "AI analysis" },
  { key: "report", label: "Report" },
] as const;
type TabKey = typeof TABS[number]["key"];

export function IncidentView({ incidentId }: { incidentId: number | null }) {
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<TabKey>("overview");

  const [selectedNode, setSelectedNode] = useState<number | null>(null);
  const [showInferred, setShowInferred] = useState(true);
  const [nodeTypes, setNodeTypes] = useState<Set<string>>(new Set());
  const [showEvents, setShowEvents] = useState(false);
  const [scoped, setScoped] = useState(false);

  const load = useCallback(async () => {
    if (!incidentId) { setDetail(null); return; }
    setLoading(true);
    setError(null);
    try {
      const [d, g] = await Promise.all([api.incident(incidentId), api.graph({ include_inferred: true })]);
      setDetail(d);
      setGraph(g);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load incident");
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => { void load(); }, [load]);

  const jumpToGraph = useCallback((eventId: number) => {
    setShowEvents(true);
    const node = graph?.nodes.find((n) => n.node_key === `event:${eventId}`);
    setTab("graph");
    setSelectedNode(node ? node.id : null);
  }, [graph]);

  if (!incidentId) {
    return (
      <div className="tw-content">
        <EmptyState title="No incident selected"
                    detail="Pick an incident from the Incidents list to open the investigation workspace." />
      </div>
    );
  }
  if (loading && !detail) return <div className="tw-content"><LoadingState label="Loading incident…" /></div>;
  if (error && !detail) return <div className="tw-content"><ErrorState message={error} onRetry={load} /></div>;
  if (!detail) return null;

  const inc = detail.incident;
  const hosts = [...new Set(detail.events.map((e) => e.host).filter(Boolean))] as string[];

  const setStatus = async (status: string) => {
    try {
      await api.setStatus(inc.id, status, "Changed from investigation workspace");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Status update failed");
    }
  };

  const tabs = TABS.map((t) => ({
    key: t.key, label: t.label,
    count: t.key === "evidence" ? detail.events.length
      : t.key === "timeline" ? detail.timeline.length
      : t.key === "ai" ? detail.ai_runs.length : undefined,
  }));

  return (
    <div className="tw-content-flush">
      <div className="tw-inc-head">
        <div className="tw-inc-head-row">
          <span className="tw-inc-ref">{inc.ref}</span>
          <SeverityIndicator severity={inc.severity} />
          <StatusIndicator status={inc.status} />
          <h1 className="tw-inc-title">{inc.title}</h1>
          <label className="tw-check">
            <span className="tw-sr">Incident status</span>
            <select className="tw-select" style={{ width: 150 }} value={inc.status}
                    onChange={(e) => void setStatus(e.target.value)}>
              {["open", "investigating", "contained", "closed"].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
        </div>
        <div className="tw-inc-meta">
          <span>Window <b className="mono">{fmtTime(inc.first_ts)}</b> → <b className="mono">{fmtTime(inc.last_ts)}</b></span>
          <span><b>{detail.alerts.length}</b> detection(s)</span>
          <span><b>{detail.events.length}</b> evidence event(s)</span>
          <span><b>{hosts.length}</b> affected asset(s)</span>
        </div>
      </div>

      <Tabs tabs={tabs} active={tab} onChange={setTab} />

      <div style={{ flex: 1, minHeight: 0, overflowY: tab === "graph" ? "hidden" : "auto",
                    display: tab === "graph" ? "flex" : "block", flexDirection: "column" }}>
        {error ? <div style={{ padding: 16 }}><ErrorState message={error} onRetry={load} /></div> : null}

        {tab !== "graph" ? (
          <div style={{ padding: 24 }}>
            {tab === "overview" && <OverviewTab detail={detail} onOpenEvidence={jumpToGraph} />}
            {tab === "timeline" && <TimelineTab detail={detail} onJumpToGraph={jumpToGraph} />}
            {tab === "evidence" && <EvidenceTab detail={detail} />}
            {tab === "ai" && <AiTab detail={detail} onReload={load} />}
            {tab === "report" && <ReportTab incidentId={inc.id} />}
          </div>
        ) : (
          <>
            <GraphToolbar
              showInferred={showInferred} setShowInferred={setShowInferred}
              showEvents={showEvents} setShowEvents={setShowEvents}
              nodeTypes={nodeTypes} setNodeTypes={setNodeTypes}
              graph={graph} scoped={scoped} setScoped={setScoped}
            />
            <div className={`tw-graph-shell ${selectedNode ? "with-inspector" : ""}`} style={{ flex: 1, minHeight: 0 }}>
              {graph ? (
                <GraphCanvas
                  data={graph}
                  selectedId={selectedNode}
                  onSelect={setSelectedNode}
                  showInferred={showInferred}
                  highlightTypes={nodeTypes}
                  showEvents={showEvents}
                  focusHosts={scoped ? hosts : null}
                  onClearFocus={() => setScoped(false)}
                  onOpenEvidence={() => setTab("evidence")}
                />
              ) : (
                <div className="tw-graph-canvas"><LoadingState label="Building layout…" /></div>
              )}
              {selectedNode ? <NodeInspector nodeId={selectedNode} onClose={() => setSelectedNode(null)} /> : null}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- overview -- */

function OverviewTab({ detail, onOpenEvidence }: { detail: IncidentDetail; onOpenEvidence: (id: number) => void }) {
  const hosts = [...new Set(detail.events.map((e) => e.host).filter(Boolean))] as string[];
  const users = [...new Set(detail.events.map((e) => e.user_name).filter(Boolean))] as string[];
  const evidenceCount = detail.alerts.reduce((n, a) => n + (a.evidence?.length || 0), 0);

  const alertEventIds = new Set<number>();
  for (const a of detail.alerts) for (const e of a.evidence || []) alertEventIds.add(e.id);

  const sevCounts = detail.alerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});

  const timeline: ChipTimelineItem[] = detail.events.slice(0, 6).map((e) => ({
    id: e.id,
    time: (e.ts_utc || e.ts_raw || "").slice(11, 19) || "-",
    text: (e.command_line || e.file_path || e.domain || e.process_name || e.action || e.event_type || "").slice(0, 64),
    tone: alertEventIds.has(e.id) ? "var(--tw-critical)" : "var(--tw-low)",
    chip: <span className="tw-chip tw-chip-plain">{alertEventIds.has(e.id) ? "Alert" : "Event"}</span>,
  }));

  const icon = (name: keyof typeof Icons) => Icons[name]({ style: { width: 16, height: 16 } });

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="tw-banner tw-banner-warn">
        <span>
          <strong>Evidence boundary.</strong> The findings below are deterministic correlations over
          normalized events. They indicate suspicious behaviour; they do <em>not</em> by themselves
          prove compromise or data exfiltration.
        </span>
      </div>

      <div className="tw-inc-top">
        <Card title="Incident summary" icon={icon("info")}>
          <p className="dim" style={{ lineHeight: 1.65 }}>
            {detail.alerts[0]?.narrative || detail.incident.title}
          </p>
          <div style={{ marginTop: 14 }}>
            <Callout>
              Investigated with {evidenceCount} evidence reference{evidenceCount === 1 ? "" : "s"}
            </Callout>
          </div>
        </Card>

        <Card title="Impacted assets" icon={icon("server")}>
          <Stats>
            <Stat value={hosts.length} label="Hosts" />
            <Stat value={users.length} label="Users" />
            <Stat value={detail.events.length} label="Events" />
          </Stats>
        </Card>

        <Card title="Detection rules" icon={icon("rules")}>
          {detail.alerts.length === 0 ? <span className="faint">none</span> : (
            <div className="col" style={{ gap: 12 }}>
              {detail.alerts.map((a) => (
                <div key={a.id}>
                  <div className="mono" style={{ color: "var(--tw-primary)", fontWeight: 600 }}>{a.rule_id}</div>
                  <div style={{ fontSize: "var(--tw-fs-secondary)", color: "var(--tw-text-secondary)", lineHeight: 1.5 }}>
                    {a.title}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Timeline" icon={icon("clock")}
              action={<span className="faint" style={{ fontSize: "var(--tw-fs-meta)" }}>{detail.events.length} events</span>}>
          {timeline.length === 0 ? <span className="faint">no events</span> : <ChipTimeline items={timeline} />}
        </Card>
      </div>

      <div className="tw-inc-row2">
        <Card title="Findings, why this fired" icon={icon("alert")}>
          {detail.alerts.length === 0 ? <EmptyState title="No findings" /> : (
            <div className="col" style={{ gap: 14 }}>
              {detail.alerts.map((a) => (
                <div key={a.id} className={`tw-finding tw-finding-${a.severity}`}>
                  <div className="row" style={{ gap: 9, marginBottom: 6, flexWrap: "wrap" }}>
                    <span className="mono" style={{ color: "var(--tw-primary)" }}>{a.rule_id}</span>
                    <SeverityIndicator severity={a.severity} />
                    <span className="tw-finding-title">{a.title}</span>
                  </div>
                  <div className="tw-finding-narrative">{a.narrative}</div>
                  {a.rule_logic ? (
                    <div className="mono faint" style={{ marginTop: 6 }}>logic: {a.rule_logic}</div>
                  ) : null}
                  <div className="row" style={{ gap: 6, marginTop: 8, flexWrap: "wrap" }}>
                    <span className="faint" style={{ fontSize: "var(--tw-fs-meta)" }}>supporting events</span>
                    {a.evidence.length === 0 ? <span className="faint mono">none</span>
                      : a.evidence.map((e) => (
                        <EvidenceReference key={e.id} id={e.id} onOpen={onOpenEvidence} />
                      ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <div className="tw-inc-side">
          <Card title="Detection posture" icon={icon("target")}>
            {detail.alerts.length === 0 ? <span className="faint">no findings</span> : (
              <Donut
                caption="Total alerts"
                center={detail.alerts.length}
                slices={(["critical", "high", "medium", "low"] as const)
                  .filter((s) => sevCounts[s])
                  .map((s) => ({
                    label: s[0].toUpperCase() + s.slice(1),
                    value: sevCounts[s] || 0,
                    color: `var(--tw-${s})`,
                  }))}
              />
            )}
          </Card>

          <Card title="Investigation status" icon={icon("eye")}>
            {detail.status_history.length === 0 ? <span className="faint">no changes recorded</span> : (
              <div className="col" style={{ gap: 10 }}>
                {detail.status_history.map((h) => (
                  <div key={h.id} style={{ fontSize: "var(--tw-fs-secondary)" }}>
                    <span className="mono faint">{fmtTime(h.changed_at)}</span>
                    <div>{h.from_status || "(new)"} → <strong>{h.to_status}</strong></div>
                    {h.note ? <div className="faint" style={{ fontSize: "var(--tw-fs-meta)" }}>{h.note}</div> : null}
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------- graph chrome -- */

function GraphToolbar({
  showInferred, setShowInferred, showEvents, setShowEvents,
  nodeTypes, setNodeTypes, graph, scoped, setScoped,
}: {
  showInferred: boolean; setShowInferred: (v: boolean) => void;
  showEvents: boolean; setShowEvents: (v: boolean) => void;
  nodeTypes: Set<string>; setNodeTypes: (s: Set<string>) => void;
  graph: GraphData | null; scoped: boolean; setScoped: (v: boolean) => void;
}) {
  const types = useMemo(() => {
    const s = new Set<string>();
    graph?.nodes.forEach((n) => s.add(n.node_type));
    return [...s].sort();
  }, [graph]);
  const inferredCount = graph?.edges.filter((e) => e.status === "inferred").length ?? 0;

  const toggle = (t: string) => {
    const next = new Set(nodeTypes);
    if (next.has(t)) next.delete(t); else next.add(t);
    setNodeTypes(next);
  };

  return (
    <div className="tw-graph-toolbar">
      <label className="tw-check">
        <input type="checkbox" checked={showInferred} onChange={(e) => setShowInferred(e.target.checked)} />
        Show inferred edges <span className="faint mono">({inferredCount})</span>
      </label>
      <label className="tw-check">
        <input type="checkbox" checked={showEvents} onChange={(e) => setShowEvents(e.target.checked)} />
        Show event nodes
      </label>
      <label className="tw-check">
        <input type="checkbox" checked={scoped} onChange={(e) => setScoped(e.target.checked)} />
        Scope to this incident
      </label>
      <span style={{ width: 1, height: 16, background: "var(--tw-border)" }} />
      <span className="faint" style={{ fontSize: "var(--tw-fs-meta)" }}>Filter types</span>
      {types.map((t) => (
        <button key={t} className={`tw-chip tw-chip-plain tw-rel-chip ${nodeTypes.has(t) ? "off" : ""}`}
                style={{ cursor: "pointer", textTransform: "none" }}
                onClick={() => toggle(t)}>
          {t}
        </button>
      ))}
      {nodeTypes.size > 0 ? (
        <button className="tw-btn tw-btn-sm" onClick={() => setNodeTypes(new Set())}>Clear filter</button>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------- timeline -- */

function TimelineTab({ detail, onJumpToGraph }: { detail: IncidentDetail; onJumpToGraph: (id: number) => void }) {
  const [hostFilter, setHostFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [q, setQ] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);

  const hosts = [...new Set(detail.timeline.map((t) => t.host).filter(Boolean))] as string[];
  const types = [...new Set(detail.timeline.map((t) => t.event_type))].sort();

  const rows = detail.timeline.filter((t) => {
    if (hostFilter && t.host !== hostFilter) return false;
    if (typeFilter && t.event_type !== typeFilter) return false;
    if (sevFilter && (t.severity || "info") !== sevFilter) return false;
    if (q && !`${t.event_type} ${t.detail || ""} ${t.host || ""} ${t.user || ""}`
      .toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="col" style={{ gap: 16 }}>
      <FilterBar>
        <input className="tw-input" style={{ width: 200 }} placeholder="Search events…"
               value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="tw-select" style={{ width: 170 }} value={hostFilter}
                onChange={(e) => setHostFilter(e.target.value)} aria-label="Filter by host">
          <option value="">All hosts</option>
          {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <select className="tw-select" style={{ width: 170 }} value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)} aria-label="Filter by event type">
          <option value="">All event types</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select className="tw-select" style={{ width: 150 }} value={sevFilter}
                onChange={(e) => setSevFilter(e.target.value)} aria-label="Filter by severity">
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="faint mono">{rows.length} of {detail.timeline.length}</span>
      </FilterBar>

      <div className="tw-panel">
        {rows.length === 0 ? <EmptyState title="No events match the filter" /> : (
          <div className="tw-table-wrap">
            <table className="tw-table">
              <thead>
                <tr>
                  <th style={{ width: 168 }}>Timestamp</th>
                  <th style={{ width: 140 }}>Host</th>
                  <th style={{ width: 120 }}>User</th>
                  <th style={{ width: 110 }}>Severity</th>
                  <th style={{ width: 140 }}>Event type</th>
                  <th>Detail</th>
                  <th style={{ width: 130 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((t) => (
                  <Fragment key={t.id}>
                    <tr className="clickable"
                        onClick={() => setExpanded(expanded === t.id ? null : t.id)}>
                      <td><Timestamp status={t.ts_status} raw={t.ts_utc || t.ts_raw} /></td>
                      <td className="mono">{t.host || "-"}</td>
                      <td className="mono">{t.user || "-"}</td>
                      <td>{t.severity ? <SeverityIndicator severity={t.severity} /> : <span className="faint">-</span>}</td>
                      <td className="mono">{t.event_type}</td>
                      <td className="truncate" style={{ maxWidth: 380 }} title={t.detail || ""}>
                        {t.detail || "-"} <SourceLabel>{t.source}</SourceLabel>
                      </td>
                      <td>
                        <button className="tw-btn tw-btn-sm" onClick={(e) => { e.stopPropagation(); onJumpToGraph(t.id); }}>
                          Graph →
                        </button>
                      </td>
                    </tr>
                    {expanded === t.id ? (
                      <tr key={`${t.id}-raw`}>
                        <td colSpan={7} style={{ background: "var(--tw-surface-muted)" }}>
                          <div className="tw-section-title">Raw event #{t.id}</div>
                          <pre className="tw-raw">{prettyRaw(detail.events.find((e) => e.id === t.id)?.raw ?? null)}</pre>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- evidence -- */

function EvidenceTab({ detail }: { detail: IncidentDetail }) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const byEvent = useMemo(() => {
    const m = new Map<number, { event: EventRow; alerts: string[] }>();
    for (const a of detail.alerts) {
      for (const e of a.evidence || []) {
        if (!m.has(e.id)) m.set(e.id, { event: e, alerts: [] });
        m.get(e.id)!.alerts.push(a.rule_id);
      }
    }
    return m;
  }, [detail]);

  const cols: Column<{ event: EventRow; alerts: string[] }>[] = [
    { key: "id", header: "Event", width: 66, render: (r) => <EvidenceReference id={r.event.id} /> },
    { key: "ts", header: "Timestamp", width: 172, render: (r) => <Timestamp status={r.event.ts_status} raw={r.event.ts_utc || r.event.ts_raw} /> },
    { key: "host", header: "Host", width: 130, render: (r) => <span className="mono">{r.event.host || "-"}</span> },
    { key: "type", header: "Event type", width: 140, render: (r) => <span className="mono">{r.event.event_type}</span> },
    { key: "supports", header: "Supports", width: 120, render: (r) => <span className="mono" style={{ color: "var(--tw-primary)" }}>{r.alerts.join(", ")}</span> },
    { key: "detail", header: "Detail", render: (r) => (
      <span className="mono truncate" style={{ display: "block", maxWidth: 380 }}>
        {r.event.command_line || r.event.file_path || r.event.domain || r.event.process_name || r.event.action || "-"}
      </span>) },
  ];

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="tw-banner tw-banner-info">
        <span>
          Each row is a raw event that supports at least one finding. Expand a row to see the record
          exactly as it was stored after normalization.
        </span>
      </div>
      <div className="tw-panel">
        <PanelHeader title="Evidence events" sub={`${byEvent.size} unique event(s)`} />
        <DataTable
          columns={cols}
          rows={[...byEvent.values()]}
          rowKey={(r) => r.event.id}
          selectedKey={expanded}
          onRowClick={(r) => setExpanded(expanded === r.event.id ? null : r.event.id)}
          empty={<EmptyState title="No linked evidence" />}
        />
        {expanded != null ? (
          <div style={{ padding: 16, borderTop: "1px solid var(--tw-border)" }}>
            <div className="tw-section-title">Raw record, event #{expanded}</div>
            <pre className="tw-raw">{prettyRaw(byEvent.get(expanded)?.event.raw ?? null)}</pre>
            <div className="mono faint" style={{ marginTop: 8 }}>
              ts_status={byEvent.get(expanded)?.event.ts_status} · bytes_out={fmtBytes(byEvent.get(expanded)?.event.bytes_out)}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function prettyRaw(raw: string | null): string {
  if (!raw) return "(no raw record stored)";
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}

/* ------------------------------------------------------------- ai tab --- */

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
      if (r.status === "no_provider") setMsg(r.message || "No AI provider configured.");
      else if (r.status === "error") {
        setErrorCat(r.error_category || "error");
        setMsg(r.error_message || "Provider call failed.");
      } else if (r.status === "validation_failed") {
        setMsg("The model returned output that did not match the required schema. It was NOT applied as findings.");
        setIssues(r.issues || []);
      } else {
        setMsg(`Analysis complete with ${r.provider}/${r.model} (${r.latency_ms} ms).`);
        setIssues(r.issues || []);
      }
      await onReload();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Analysis failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="col" style={{ gap: 18 }}>
      <div className="tw-banner tw-banner-warn">
        <span>
          <strong>AI output is interpretation, not evidence.</strong> Only the events in this incident
          are sent, and every referenced event ID is verified against the database before storage.
          Invented references are stripped and reported.
        </span>
      </div>

      <div className="tw-panel">
        <PanelHeader title="Run analysis"
          sub={detail.ai_status.mode === "ai_enabled"
            ? `provider: ${detail.ai_status.provider}/${detail.ai_status.model}`
            : "no provider, core mode"}
          actions={
            <button className="tw-btn tw-btn-sm tw-btn-primary" onClick={() => void run()} disabled={busy}>
              {busy ? "Running…" : "Analyze with AI"}
            </button>
          } />
        <div className="tw-panel-body faint" style={{ fontSize: "var(--tw-fs-secondary)", lineHeight: 1.6 }}>
          {detail.ai_status.mode !== "ai_enabled" ? (
            <>No AI provider is active. Configure one under <strong>AI Providers</strong>, or continue
              using the deterministic engine, detection, correlation, graph, timeline and reports all
              work without AI.</>
          ) : (
            <>Model: <span className="mono">{detail.ai_status.model}</span>
              {detail.ai_status.last_test_status
                ? <span className="faint"> · last connection test: {detail.ai_status.last_test_status}</span> : null}</>
          )}
        </div>
      </div>

      {msg ? (
        <div className={`tw-banner ${errorCat ? "tw-banner-err" : "tw-banner-info"}`}>
          <span>{msg}{errorCat ? ` (${errorCat})` : ""}</span>
        </div>
      ) : null}

      {issues.length > 0 ? (
        <div className="tw-banner tw-banner-warn">
          <div>
            <strong>Validation notes</strong>
            <ul style={{ margin: "6px 0 0 16px", padding: 0 }}>{issues.map((i, k) => <li key={k}>{i}</li>)}</ul>
          </div>
        </div>
      ) : null}

      {result ? (
        <>
          <div className="tw-panel">
            <PanelHeader title="Summary" sub={`${latest.provider}/${latest.model} · ${latest.latency_ms} ms`} />
            <div className="tw-panel-body" style={{ lineHeight: 1.7 }}>
              {result.summary || <span className="faint">(empty)</span>}
              <div className="faint" style={{ fontSize: "var(--tw-fs-meta)", marginTop: 10, fontStyle: "italic" }}>
                Summary is free-form model text and is not verified against the event store. Only
                hypotheses carrying event citations were checked.
              </div>
              {result.timeline_interpretation ? (
                <div style={{ marginTop: 12, color: "var(--tw-text-secondary)" }}>
                  <div className="tw-section-title">Timeline interpretation</div>
                  {result.timeline_interpretation}
                </div>
              ) : null}
            </div>
          </div>

          {result.hypotheses.length > 0 ? (
            <div className="tw-panel">
              <PanelHeader title="Hypotheses" sub="AI-generated, distinct from observed facts" />
              <div className="tw-panel-body col" style={{ gap: 14 }}>
                {result.hypotheses.map((h, i) => (
                  <div key={i} className="tw-hyp">
                    <div className="tw-hyp-tags">
                      <span className="tw-chip tw-chip-plain">{h.confidence} confidence</span>
                      {h.evidence_status === "unsupported"
                        ? <span className="tw-chip tw-sev tw-sev-high" title="Every citation referenced events that do not exist in this incident.">no surviving evidence</span>
                        : h.evidence_status === "contested" ? <span className="tw-chip tw-sev tw-sev-medium">evidence contested</span>
                        : h.evidence_status === "supported" ? <span className="tw-chip tw-status tw-status-observed">evidence-linked</span>
                        : null}
                    </div>
                    <div className="tw-hyp-statement">{h.statement}</div>
                    {h.reasoning ? <div className="tw-hyp-reasoning">{h.reasoning}</div> : null}
                    <div className="tw-cites">
                      <span className="sup">supports: {h.supporting_event_ids.map((x) => `#${x}`).join(", ") || "none"}</span>
                      <span className="con">contradicts: {h.contradicting_event_ids.map((x) => `#${x}`).join(", ") || "none"}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {result.missing_information.length > 0 || result.next_investigation_steps.length > 0 ? (
            <div className="tw-grid tw-grid-2">
              {result.missing_information.length > 0 ? (
                <div className="tw-panel">
                  <PanelHeader title="Still unknown" />
                  <div className="tw-panel-body">
                    <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8 }}>
                      {result.missing_information.map((m, i) => <li key={i}>{m}</li>)}
                    </ul>
                  </div>
                </div>
              ) : null}
              {result.next_investigation_steps.length > 0 ? (
                <div className="tw-panel">
                  <PanelHeader title="Next steps" sub="advisory" />
                  <div className="tw-panel-body">
                    <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8 }}>
                      {result.next_investigation_steps.map((s, i) => <li key={i}>{s}</li>)}
                    </ul>
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}

          {result.uncertainty_notes ? (
            <div className="tw-banner tw-banner-warn"><span><strong>Uncertainty:</strong> {result.uncertainty_notes}</span></div>
          ) : null}
        </>
      ) : latest && latest.status !== "ok" && latest.status !== "ok_with_warnings" ? (
        <RunHistory runs={detail.ai_runs} />
      ) : null}

      {detail.ai_runs.length > 1 && result ? <RunHistory runs={detail.ai_runs} /> : null}
    </div>
  );
}

function RunHistory({ runs }: { runs: AiRun[] }) {
  const cols: Column<AiRun>[] = [
    { key: "id", header: "Run", width: 64, render: (r) => <span className="mono">#{r.id}</span> },
    { key: "pm", header: "Provider / model", width: 200, render: (r) => (
      <span className="mono">{r.provider || "-"}{r.model ? ` / ${r.model}` : ""}</span>) },
    { key: "status", header: "Status", width: 150, render: (r) => (
      <span className="mono" style={{ color: r.status.startsWith("ok") ? "var(--tw-success)" : "var(--tw-high)" }}>{r.status}</span>) },
    { key: "lat", header: "Latency", width: 90, render: (r) => <span className="mono num">{r.latency_ms ? `${r.latency_ms}ms` : "-"}</span> },
    { key: "note", header: "Note", render: (r) => (
      <span className="truncate" style={{ display: "block", maxWidth: 320 }}>{r.error_message || r.error_category || "-"}</span>) },
  ];
  return (
    <div className="tw-panel">
      <PanelHeader title="Run history" sub="most recent first" />
      <DataTable columns={cols} rows={runs} rowKey={(r) => r.id} />
    </div>
  );
}

/* ------------------------------------------------------------- report --- */

function ReportTab({ incidentId }: { incidentId: number }) {
  const [fmt, setFmt] = useState<"md" | "html" | "json">("md");
  const [content, setContent] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = useCallback(async (f: typeof fmt) => {
    setBusy(true); setError(null);
    try {
      const r = await api.report(incidentId, f);
      setContent(r.content);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Report generation failed");
    } finally { setBusy(false); }
  }, [incidentId]);

  useEffect(() => { void generate(fmt); }, [generate, fmt]);

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="row" style={{ flexWrap: "wrap" }}>
        <select className="tw-select" style={{ width: 170 }} value={fmt}
                onChange={(e) => setFmt(e.target.value as typeof fmt)} aria-label="Report format">
          <option value="md">Markdown</option>
          <option value="html">HTML (printable)</option>
          <option value="json">JSON</option>
        </select>
        <button className="tw-btn tw-btn-sm" onClick={() => void generate(fmt)} disabled={busy}>
          {busy ? "Generating…" : "Regenerate"}
        </button>
        <button className="tw-btn tw-btn-sm tw-btn-primary"
                onClick={() => void downloadReport(api.reportUrl(incidentId, fmt), `incident-${incidentId}-report.${fmt}`)}>
          {Icons.download({ style: { width: 14, height: 14 } })} Download
        </button>
        {fmt === "html" ? (
          <button className="tw-btn tw-btn-sm" onClick={() => {
            const w = window.open("", "_blank");
            if (w && content) { w.document.write(content); w.document.close(); }
          }}>Open printable view</button>
        ) : null}
      </div>

      {error ? <ErrorState message={error} onRetry={() => void generate(fmt)} /> : null}
      {busy && !content ? <LoadingState label="Generating report…" /> : null}

      {content ? (
        <div className="tw-panel">
          <PanelHeader title={`${fmt.toUpperCase()} report`}
                       sub={`generated from stored data only · ${content.length.toLocaleString()} chars`} />
          <div className="tw-panel-body tight">
            {fmt === "html" ? (
              <iframe title="Report preview" srcDoc={content}
                      style={{ width: "100%", height: 640, border: "none", background: "#fff" }} />
            ) : (
              <pre className="tw-raw" style={{ borderRadius: 0, border: 0, maxHeight: 640, background: "var(--tw-surface-sunken)", color: "var(--tw-text-secondary)" }}>
                {content}
              </pre>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}
