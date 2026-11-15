import { useCallback, useEffect, useState } from "react";
import { api, downloadReport, type IncidentSummary } from "../api";
import { PageHeader } from "../components/layout";
import { DataTable, PanelHeader, type Column } from "../components/data";
import { EmptyState, ErrorState, LoadingState, fmtTime } from "../components/ui";
import { Icons } from "../components/icons";

interface ReportRow { id: number; incident_id: number; fmt: string; created_at: string; ref: string; }

export function ReportsPage({ onOpenIncident }: { onOpenIncident: (id: number) => void }) {
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [incidentId, setIncidentId] = useState<number | null>(null);
  const [fmt, setFmt] = useState<"md" | "html" | "json">("md");
  const [content, setContent] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [r, inc] = await Promise.all([api.reports(), api.incidents()]);
      setReports(r.reports);
      setIncidents(inc.incidents);
      setIncidentId((prev) => prev ?? inc.incidents[0]?.id ?? null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load reports");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const generate = async () => {
    if (!incidentId) return;
    setBusy(true); setError(null);
    try {
      const r = await api.report(incidentId, fmt);
      setContent(r.content);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Report generation failed");
    } finally { setBusy(false); }
  };

  const cols: Column<ReportRow>[] = [
    { key: "ref", header: "Incident", width: 110, render: (r) => (
      <span className="mono" style={{ color: "var(--tw-primary)" }}>{r.ref}</span>) },
    { key: "fmt", header: "Format", width: 100, render: (r) => <span className="tw-chip tw-chip-plain">{r.fmt}</span> },
    { key: "created", header: "Generated", width: 180, render: (r) => <span className="mono num">{fmtTime(r.created_at)}</span> },
    { key: "status", header: "Status", width: 130, render: () => <span className="tw-chip tw-status tw-status-contained">stored</span> },
    { key: "actions", header: "Actions", render: (r) => (
      <div className="row" style={{ gap: 6 }}>
        <button className="tw-btn tw-btn-sm" onClick={() => onOpenIncident(r.incident_id)}>Open incident</button>
        <button className="tw-btn tw-btn-sm" onClick={() =>
          void downloadReport(api.reportUrl(r.incident_id, r.fmt as "md" | "html" | "json"),
            `incident-${r.ref}-report.${r.fmt}`)}>
          {Icons.download({ style: { width: 13, height: 13 } })} Download
        </button>
      </div>) },
  ];

  return (
    <>
      <PageHeader
        title="Reports"
        subtitle="Investigation reports generated from stored data only — facts and hypotheses stay separated."
        actions={<button className="tw-btn tw-btn-sm" onClick={() => void load()}>Refresh</button>}
      />

      {error ? <div style={{ marginBottom: 16 }}><ErrorState message={error} onRetry={load} /></div> : null}

      <div className="tw-panel" style={{ marginBottom: 20 }}>
        <PanelHeader title="Generate a report" />
        <div className="tw-panel-body">
          <div className="row wrap" style={{ alignItems: "flex-end" }}>
            <div>
              <label className="tw-label">Incident</label>
              <select className="tw-select" style={{ width: 320 }} value={incidentId ?? ""}
                      onChange={(e) => setIncidentId(e.target.value ? Number(e.target.value) : null)}>
                {incidents.length === 0 ? <option value="">No incidents available</option> : null}
                {incidents.map((i) => <option key={i.id} value={i.id}>{i.ref} — {i.title.slice(0, 44)}</option>)}
              </select>
            </div>
            <div>
              <label className="tw-label">Format</label>
              <select className="tw-select" style={{ width: 170 }} value={fmt}
                      onChange={(e) => setFmt(e.target.value as typeof fmt)}>
                <option value="md">Markdown</option>
                <option value="html">HTML (printable)</option>
                <option value="json">JSON</option>
              </select>
            </div>
            <button className="tw-btn tw-btn-primary" disabled={busy || !incidentId} onClick={() => void generate()}>
              {busy ? "Generating…" : "Generate"}
            </button>
            {content && incidentId ? (
              <button className="tw-btn"
                      onClick={() => void downloadReport(api.reportUrl(incidentId, fmt), `incident-${incidentId}-report.${fmt}`)}>
                {Icons.download({ style: { width: 14, height: 14 } })} Download
              </button>
            ) : null}
          </div>
        </div>
      </div>

      {content ? (
        <div className="tw-panel" style={{ marginBottom: 20 }}>
          <PanelHeader title={`${fmt.toUpperCase()} report`}
                       sub={`generated from stored data only · ${content.length.toLocaleString()} chars`} />
          <div className="tw-panel-body tight">
            {fmt === "html" ? (
              <iframe title="Report preview" srcDoc={content}
                      style={{ width: "100%", height: 560, border: "none", background: "#fff" }} />
            ) : (
              <pre className="tw-raw" style={{ borderRadius: 0, border: 0, maxHeight: 560 }}>
                {content}
              </pre>
            )}
          </div>
        </div>
      ) : null}

      <div className="tw-panel">
        <PanelHeader title="Stored reports" sub={`${reports.length} total`} />
        {loading ? <LoadingState label="Loading reports…" /> : (
          <DataTable columns={cols} rows={reports} rowKey={(r) => r.id}
                     empty={<EmptyState title="No reports yet" detail="Generate one from an incident above." />} />
        )}
      </div>
    </>
  );
}
