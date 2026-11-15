import { useCallback, useEffect, useState } from "react";
import { api, type Alert, type Health, type IncidentSummary } from "../api";
import { PageHeader } from "../components/layout";
import {
  DataTable, MetricItem, MetricStrip, PanelHeader, type Column,
} from "../components/data";
import {
  EmptyState, ErrorState, LoadingState, SeverityIndicator, StatusIndicator, fmtTime, SEVERITIES,
} from "../components/ui";
import { Icons } from "../components/icons";
import { Donut } from "../components/widgets";

interface Props {
  onOpenIncident: (id: number) => void;
  onLoadDemo: () => Promise<void>;
  demoBusy: boolean;
  reloadKey: number;
}

export function Dashboard({ onOpenIncident, onLoadDemo, demoBusy, reloadKey }: Props) {
  const [health, setHealth] = useState<Health | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, inc, al] = await Promise.all([api.health(), api.incidents(), api.alerts()]);
      setHealth(h);
      setIncidents(inc.incidents);
      setAlerts(al.alerts);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load the dashboard");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load, reloadKey]);

  if (loading && !health) return <LoadingState label="Loading workspace…" />;
  if (error && !health) return <ErrorState message={error} onRetry={load} />;
  if (!health) return null;

  const c = health.counts;
  const isEmpty = c.events === 0;
  const sevCounts = alerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});
  const openIncidents = incidents.filter((i) => i.status === "open").length;
  const affected = new Set(alerts.flatMap((a) => (a.host ? [a.host] : []))).size;

  const incidentCols: Column<IncidentSummary>[] = [
    { key: "sev", header: "Severity", width: 96, render: (i) => <SeverityIndicator severity={i.severity} /> },
    { key: "ref", header: "Incident", width: 92, render: (i) => <span className="mono" style={{ color: "var(--tw-primary)" }}>{i.ref}</span> },
    { key: "title", header: "Title", className: "primary", render: (i) => (
      <span className="truncate" style={{ display: "block", maxWidth: 320 }} title={i.title}>{i.title}</span>
    ) },
    { key: "asset", header: "Affected asset", width: 150, render: (i) => (
      <span className="mono truncate" style={{ display: "block", maxWidth: 150 }}
            title={i.hosts.join(", ")}>{i.hosts[0] || "—"}</span>
    ) },
    { key: "last", header: "Last activity", width: 158, render: (i) => <span className="mono num">{fmtTime(i.last_ts)}</span> },
    { key: "status", header: "Status", width: 118, render: (i) => <StatusIndicator status={i.status} /> },
  ];

  const alertCols: Column<Alert>[] = [
    { key: "rule", header: "Rule", width: 64, render: (a) => <span className="mono" style={{ color: "var(--tw-primary)" }}>{a.rule_id}</span> },
    { key: "finding", header: "Finding", className: "primary", render: (a) => (
      <span className="truncate" style={{ display: "block", maxWidth: 420 }} title={a.title}>{a.title}</span>
    ) },
    { key: "sev", header: "Severity", width: 96, render: (a) => <SeverityIndicator severity={a.severity} /> },
    { key: "host", header: "Host", width: 140, render: (a) => <span className="mono">{a.host || "—"}</span> },
    { key: "first", header: "First seen", width: 158, render: (a) => <span className="mono num">{fmtTime(a.first_ts)}</span> },
    { key: "ev", header: "Evidence", width: 84, align: "right", render: (a) => (
      <span className="mono num" style={{ color: "var(--tw-primary)" }}>{a.evidence.length}</span>
    ) },
  ];

  return (
    <>
      <PageHeader
        title="Security overview"
        subtitle="A clear view of events, investigations, and detection activity."
        meta={<>Last updated <span className="mono">{fmtTime(health.time)}</span> UTC</>}
        actions={
          <>
            <button className="tw-btn tw-btn-sm" onClick={() => void load()} disabled={loading}>
              {Icons.refresh({ style: { width: 14, height: 14 } })}
              Refresh
            </button>
            <button className="tw-btn tw-btn-sm tw-btn-primary" onClick={() => void onLoadDemo()} disabled={demoBusy}>
              {demoBusy ? "Loading…" : "Load demo dataset"}
            </button>
          </>
        }
      />

      {isEmpty ? (
        <div className="tw-banner tw-banner-info" style={{ marginBottom: 20 }}>
          <span style={{ flex: 1 }}>
            <strong>Workspace is empty.</strong> Load the built-in synthetic dataset to explore the
            full pipeline (import → detection → correlation → graph → report). All demo material is
            clearly labelled as synthetic.
          </span>
          <button className="tw-btn tw-btn-sm tw-btn-primary" onClick={() => void onLoadDemo()} disabled={demoBusy}>
            Load demo dataset
          </button>
        </div>
      ) : null}

      {error ? <div style={{ marginBottom: 20 }}><ErrorState message={error} onRetry={load} /></div> : null}

      <MetricStrip>
        <MetricItem label="Events normalized" value={c.events} sub={`${c.artifacts} artifact(s)`} />
        <MetricItem label="Active alerts" value={c.alerts}
                    sub={`${sevCounts.critical || 0} critical`} critical={!!sevCounts.critical} />
        <MetricItem label="Incidents" value={c.incidents} sub={`${openIncidents} open`} />
        <MetricItem label="Affected assets" value={affected} sub={`${c.iocs} IOC(s) loaded`} />
      </MetricStrip>

      <div className="tw-dash-split" style={{ marginTop: 20 }}>
        <div className="tw-panel">
          <PanelHeader title="Recent incidents"
                       sub={`${incidents.length} total · grouped by shared host / account`} />
          <DataTable
            columns={incidentCols}
            rows={incidents.slice(0, 8)}
            rowKey={(i) => i.id}
            onRowClick={(i) => onOpenIncident(i.id)}
            empty={<EmptyState title="No incidents yet"
                               detail="Import data or load the demo dataset, then run analysis." />}
          />
        </div>

        <div className="tw-dash-aside">
          <div className="tw-panel">
            <PanelHeader title="Detection posture" sub="by alert severity" />
            <div className="tw-panel-body">
              {alerts.length === 0 ? (
                <div className="faint">No alerts on the current dataset.</div>
              ) : (
                <Donut
                  caption="Total alerts"
                  slices={SEVERITIES.filter((s) => sevCounts[s]).map((s) => ({
                    label: s[0]!.toUpperCase() + s.slice(1),
                    value: sevCounts[s] || 0,
                    color: `var(--tw-${s})`,
                  }))}
                />
              )}
            </div>
          </div>

          <div className="tw-panel">
            <PanelHeader title="System status" />
            <div className="tw-panel-body">
              <div className="tw-syslist">
                <SysRow label="Detection engine" value="rule engine (deterministic)" ok />
                <SysRow label="Database" value={health.db} ok />
                <SysRow label="Correlation engine" value={`${c.graph_nodes} nodes / ${c.graph_edges} edges`} ok />
                <SysRow label="Reports stored" value={String(c.reports)} ok />
              </div>
              <div style={{ marginTop: 14, paddingTop: 13, borderTop: "1px solid var(--tw-border)" }}>
                <div className="row" style={{ gap: 8 }}>
                  <span className={`tw-dot ${health.ai.mode === "ai_enabled" ? "tw-dot-ok"
                    : health.ai.mode === "missing_credential" ? "tw-dot-warn" : "tw-dot-idle"}`} />
                  <strong style={{ fontSize: "var(--tw-fs-secondary)" }}>
                    {health.ai.mode === "ai_enabled" ? health.ai.label : "AI provider not configured"}
                  </strong>
                </div>
                <div className="faint" style={{ fontSize: "var(--tw-fs-secondary)", marginTop: 4, lineHeight: 1.6 }}>
                  {health.ai.mode === "ai_enabled"
                    ? health.ai.detail
                    : "Core detection and investigation remain available without AI."}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="tw-panel" style={{ marginTop: 20 }}>
        <PanelHeader title="Recent detections" sub="every detection links to stored event IDs" />
        <DataTable
          columns={alertCols}
          rows={alerts.slice(0, 10)}
          rowKey={(a) => a.id}
          onRowClick={(a) => a.incident_id && onOpenIncident(a.incident_id)}
          empty={<EmptyState title="No detections" detail="Nothing fired on the current dataset." />}
        />
      </div>
    </>
  );
}

function SysRow({ label, value, ok }: { label: string; value: string; ok?: boolean }) {
  return (
    <div className="tw-sysrow">
      <span className={`tw-dot ${ok ? "tw-dot-ok" : "tw-dot-idle"}`} />
      <span className="tw-syslabel">{label}</span>
      <span className="tw-sysval">{value}</span>
    </div>
  );
}
