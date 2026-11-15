import { useCallback, useEffect, useState } from "react";
import { api, type EventFacets, type EventRow } from "../api";
import { PageHeader } from "../components/layout";
import { DataTable, FilterBar, InspectorPanel, type Column } from "../components/data";
import {
  EmptyState, ErrorState, LoadingState, SeverityIndicator, SourceLabel, Timestamp, fmtBytes,
} from "../components/ui";
import { Icons } from "../components/icons";

const PAGE = 50;

export function EventsExplorer({
  initialQuery = "", onOpenGraphForEvent,
}: { initialQuery?: string; onOpenGraphForEvent?: (eventId: number) => void }) {
  const [rows, setRows] = useState<EventRow[]>([]);
  const [facets, setFacets] = useState<EventFacets | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [q, setQ] = useState(initialQuery);
  const [host, setHost] = useState("");
  const [user, setUser] = useState("");
  const [type, setType] = useState("");
  const [severity, setSeverity] = useState("");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [selected, setSelected] = useState<EventRow | null>(null);

  const load = useCallback(async (nextOffset: number) => {
    setLoading(true); setError(null);
    try {
      const [r, f] = await Promise.all([
        api.events({ limit: PAGE, offset: nextOffset, q, host, user, event_type: type, severity, order }),
        facets ? Promise.resolve(facets) : api.eventFacets(),
      ]);
      setRows(r.events);
      setTotal(r.total);
      setOffset(nextOffset);
      if (!facets) setFacets(f);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load events");
    } finally { setLoading(false); }
  }, [q, host, user, type, severity, order, facets]);

  useEffect(() => { void load(0); /* reload on filter change */
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, host, user, type, severity, order]);

  const reset = () => { setQ(""); setHost(""); setUser(""); setType(""); setSeverity(""); setFrom(""); setTo(""); };

  // The events endpoint has no server-side time bounds, so From/To filter the
  // rows already loaded for the current page (labelled as such in the UI).
  const timeFiltered = rows.filter((e) => {
    if (!from && !to) return true;
    const t = e.ts_utc ? Date.parse(e.ts_utc) : NaN;
    if (Number.isNaN(t)) return false;
    if (from && t < Date.parse(from)) return false;
    if (to && t > Date.parse(to) + 86_399_000) return false;
    return true;
  });

  const totalIssues = facets?.timestamp_issues.reduce((a, b) => a + b.c, 0) ?? 0;

  const cols: Column<EventRow>[] = [
    { key: "id", header: "ID", width: 60, render: (e) => <span className="mono" style={{ color: "var(--tw-primary)" }}>#{e.id}</span> },
    { key: "ts", header: "Timestamp", width: 172, render: (e) => <Timestamp status={e.ts_status} raw={e.ts_utc || e.ts_raw} /> },
    { key: "type", header: "Event type", width: 150, render: (e) => <span className="mono">{e.event_type}</span> },
    { key: "sev", header: "Severity", width: 96, render: (e) => e.severity
      ? <SeverityIndicator severity={e.severity} /> : <span className="faint">—</span> },
    { key: "src", header: "Source", width: 130, render: (e) => <SourceLabel>{e.source}</SourceLabel> },
    { key: "host", header: "Host", width: 130, render: (e) => <span className="mono">{e.host || "—"}</span> },
    { key: "user", header: "User", width: 118, render: (e) => <span className="mono">{e.user_name || "—"}</span> },
    { key: "desc", header: "Description", render: (e) => (
      <span className="mono truncate" style={{ display: "block", maxWidth: 360 }}>
        {e.command_line || e.file_path || e.domain || e.process_name || e.action || e.dst_ip || "—"}
      </span>) },
  ];

  return (
    <>
      <PageHeader title="Events" subtitle="Every normalized event, searchable down to the raw record." />

      {totalIssues > 0 ? (
        <div className="tw-banner tw-banner-warn" style={{ marginBottom: 16 }}>
          <span>
            <strong>{totalIssues} event(s) have degraded timestamps.</strong> They are kept (dropping
            them would lose evidence) but flagged as {facets?.timestamp_issues.map((t) => `${t.ts_status} (${t.c})`).join(", ")}.
            Unparseable timestamps are never replaced with a guessed value.
          </span>
        </div>
      ) : null}

      <FilterBar>
        <input className="tw-input" style={{ width: 220 }} placeholder="Search raw / process / file / domain…"
               value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search events" />
        <select className="tw-select" style={{ width: 150 }} value={host} onChange={(e) => setHost(e.target.value)} aria-label="Host">
          <option value="">All hosts</option>
          {facets?.hosts.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <select className="tw-select" style={{ width: 140 }} value={user} onChange={(e) => setUser(e.target.value)} aria-label="User">
          <option value="">All users</option>
          {facets?.users.map((u) => <option key={u} value={u}>{u}</option>)}
        </select>
        <select className="tw-select" style={{ width: 160 }} value={type} onChange={(e) => setType(e.target.value)} aria-label="Event type">
          <option value="">All event types</option>
          {facets?.event_types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select className="tw-select" style={{ width: 140 }} value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">All severities</option>
          {facets?.severities.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="faint" style={{ fontSize: "var(--tw-fs-meta)" }}>Time (page):</span>
        <input className="tw-input" type="date" style={{ width: 148 }} value={from}
               onChange={(e) => setFrom(e.target.value)} aria-label="From date" />
        <input className="tw-input" type="date" style={{ width: 148 }} value={to}
               onChange={(e) => setTo(e.target.value)} aria-label="To date" />
        <button className="tw-btn tw-btn-sm" onClick={reset}>Reset</button>
        <span className="spacer" />
        <select className="tw-select" style={{ width: 130 }} value={order}
                onChange={(e) => setOrder(e.target.value as "asc" | "desc")} aria-label="Sort order">
          <option value="desc">Newest first</option>
          <option value="asc">Oldest first</option>
        </select>
      </FilterBar>

      {error ? <div style={{ marginTop: 16 }}><ErrorState message={error} onRetry={() => void load(offset)} /></div> : null}

      <div className="tw-panel" style={{ marginTop: 16 }}>
        <div className="tw-panel-head">
          <span className="tw-panel-title">Normalized events</span>
          <span className="spacer" />
          <span className="mono faint">
            {total === 0 ? "0" : `${offset + 1}–${Math.min(offset + PAGE, total)} of ${total}`}
          </span>
        </div>
        {loading && rows.length === 0 ? <LoadingState label="Loading events…" /> : (
          <DataTable
            columns={cols}
            rows={timeFiltered}
            rowKey={(e) => e.id}
            onRowClick={(e) => setSelected(e)}
            selectedKey={selected?.id ?? null}
            empty={<EmptyState title="No events" detail="Adjust the filters, or import data first." />}
          />
        )}
        {rows.length > 0 ? (
          <div className="row" style={{ padding: 12, borderTop: "1px solid var(--tw-border)" }}>
            <button className="tw-btn tw-btn-sm" disabled={offset === 0 || loading}
                    onClick={() => void load(Math.max(0, offset - PAGE))}>← Prev</button>
            <button className="tw-btn tw-btn-sm" disabled={offset + PAGE >= total || loading}
                    onClick={() => void load(offset + PAGE)}>Next →</button>
            <span className="spacer" />
            {loading ? <span className="tw-spinner" /> : null}
          </div>
        ) : null}
      </div>

      {selected ? (
        <div className="tw-drawer">
          <InspectorPanel title={`Event #${selected.id}`} onClose={() => setSelected(null)}
            actions={
              <>
                <button className="tw-btn tw-btn-sm tw-btn-icon" title="Copy event ID"
                        aria-label="Copy event ID"
                        onClick={() => void navigator.clipboard?.writeText(String(selected.id))}>
                  {Icons.copy({ style: { width: 13, height: 13 } })}
                </button>
                {onOpenGraphForEvent ? (
                  <button className="tw-btn tw-btn-sm"
                          onClick={() => { onOpenGraphForEvent(selected.id); setSelected(null); }}>
                    Graph →
                  </button>
                ) : null}
              </>
            }>
            <dl className="tw-kv" style={{ marginBottom: 16 }}>
              <dt>Timestamp</dt><dd><Timestamp status={selected.ts_status} raw={selected.ts_utc || selected.ts_raw} /></dd>
              <dt>Event type</dt><dd className="mono">{selected.event_type}</dd>
              <dt>Severity</dt><dd>{selected.severity ? <SeverityIndicator severity={selected.severity} /> : "—"}</dd>
              <dt>Source</dt><dd><SourceLabel>{selected.source}</SourceLabel></dd>
              <dt>Host</dt><dd className="mono">{selected.host || "—"}</dd>
              <dt>User</dt><dd className="mono">{selected.user_name || "—"}</dd>
              <dt>Process</dt><dd className="mono">{selected.process_name || "—"}</dd>
              <dt>Destination</dt><dd className="mono">{selected.dst_ip || "—"}{selected.dst_port ? `:${selected.dst_port}` : ""}</dd>
              <dt>Domain</dt><dd className="mono">{selected.domain || "—"}</dd>
              <dt>File</dt><dd className="mono" style={{ wordBreak: "break-all" }}>{selected.file_path || "—"}</dd>
              <dt>Hash</dt><dd className="mono" style={{ wordBreak: "break-all" }}>{selected.file_hash || "—"}</dd>
              <dt>Bytes out</dt><dd className="mono">{fmtBytes(selected.bytes_out)}</dd>
            </dl>
            <div className="tw-section-title">Raw record (as stored)</div>
            <pre className="tw-raw">{prettyRaw(selected.raw)}</pre>
          </InspectorPanel>
        </div>
      ) : null}
    </>
  );
}

function prettyRaw(raw: string | null): string {
  if (!raw) return "(no raw record)";
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}
