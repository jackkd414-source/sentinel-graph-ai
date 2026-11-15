import { useCallback, useEffect, useState } from "react";
import { api, type IncidentSummary } from "../api";
import { PageHeader } from "../components/layout";
import { DataTable, FilterBar, type Column } from "../components/data";
import { EmptyState, ErrorState, LoadingState, SeverityIndicator, StatusIndicator, fmtTime } from "../components/ui";

export function IncidentsList({ onOpen }: { onOpen: (id: number) => void }) {
  const [items, setItems] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sev, setSev] = useState("");
  const [status, setStatus] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.incidents();
      setItems(r.incidents);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load incidents");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const rows = items.filter(
    (i) => (!sev || i.severity === sev) && (!status || i.status === status),
  );

  const cols: Column<IncidentSummary>[] = [
    { key: "ref", header: "Incident", width: 92, render: (i) => (
      <span className="mono" style={{ color: "var(--tw-primary)" }}>{i.ref}</span>) },
    { key: "title", header: "Title", className: "primary", render: (i) => (
      <span className="truncate" style={{ display: "block", maxWidth: 420 }} title={i.title}>{i.title}</span>) },
    { key: "sev", header: "Severity", width: 96, render: (i) => <SeverityIndicator severity={i.severity} /> },
    { key: "status", header: "Status", width: 122, render: (i) => <StatusIndicator status={i.status} /> },
    { key: "alerts", header: "Alerts", width: 74, align: "right", render: (i) => (
      <span className="mono num">{i.alert_count}</span>) },
    { key: "hosts", header: "Affected assets", width: 220, render: (i) => (
      <span className="mono truncate" style={{ display: "block", maxWidth: 220 }}
            title={i.hosts.join(", ")}>{i.hosts.join(", ") || "-"}</span>) },
    { key: "first", header: "First seen", width: 158, render: (i) => (
      <span className="mono num">{fmtTime(i.first_ts)}</span>) },
  ];

  return (
    <>
      <PageHeader
        title="Incidents"
        subtitle="Correlated groups of detections that share a host or account."
        actions={<button className="tw-btn tw-btn-sm" onClick={() => void load()}>Refresh</button>}
      />

      <FilterBar>
        <select className="tw-select" style={{ width: 168 }} value={sev}
                onChange={(e) => setSev(e.target.value)} aria-label="Filter by severity">
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="tw-select" style={{ width: 168 }} value={status}
                onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
          <option value="">All statuses</option>
          {["open", "investigating", "contained", "closed"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="faint mono">{rows.length} of {items.length}</span>
      </FilterBar>

      <div className="tw-panel" style={{ marginTop: 16 }}>
        {loading ? <LoadingState label="Loading incidents…" />
          : error ? <div style={{ padding: 16 }}><ErrorState message={error} onRetry={load} /></div>
          : (
            <DataTable
              columns={cols}
              rows={rows}
              rowKey={(i) => i.id}
              onRowClick={(i) => onOpen(i.id)}
              empty={<EmptyState title="No incidents"
                                 detail="Load the demo dataset or import events, then run analysis." />}
            />
          )}
      </div>
    </>
  );
}
