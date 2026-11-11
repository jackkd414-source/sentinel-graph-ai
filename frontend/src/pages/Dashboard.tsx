import { useEffect, useState } from "react";
import { api, type Alert, type Health, type IncidentSummary } from "../api";
import { Empty, ErrorBanner, Loading, SeverityChip, fmtTime } from "../components/ui";

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

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, inc, al] = await Promise.all([
        api.health(), api.incidents(), api.alerts(),
      ]);
      setHealth(h);
      setIncidents(inc.incidents);
      setAlerts(al.alerts);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load dashboard");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [reloadKey]);

  if (loading && !health) return <Loading label="Loading workspace…" />;
  if (error && !health) return <ErrorBanner message={error} onRetry={load} />;
  if (!health) return null;

  const c = health.counts;
  const isEmpty = c.events === 0;
  const severityCounts = alerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});
  const order = ["critical", "high", "medium", "low", "info"];
  const maxSev = Math.max(1, ...order.map((s) => severityCounts[s] || 0));

  const aiDot = health.ai.mode === "ai_enabled" ? "dot-ok"
    : health.ai.mode === "missing_credential" ? "dot-warn" : "dot-idle";

  return (
    <div className="col" style={{ gap: 16 }}>
      {isEmpty ? (
        <div className="banner banner-info">
          <span>
            <strong>Workspace is empty.</strong> Load the built-in synthetic dataset to
            explore the full pipeline (import → detection → correlation → graph → report).
            All data is clearly labelled as synthetic demo material.
          </span>
          <button className="btn btn-primary btn-sm" onClick={() => void onLoadDemo()}
                  disabled={demoBusy}>
            {demoBusy ? "Loading…" : "Load demo dataset"}
          </button>
        </div>
      ) : null}

      {error ? <ErrorBanner message={error} onRetry={load} /> : null}

      <div className="grid grid-4">
        <Stat label="Events normalized" value={c.events} sub={`${c.artifacts} artifact(s)`} />
        <Stat label="Active alerts" value={c.alerts}
              sub={`${severityCounts.critical || 0} critical`}
              accent={severityCounts.critical ? "var(--critical)" : undefined} />
        <Stat label="Incidents" value={c.incidents}
              sub={`${incidents.filter((i) => i.status === "open").length} open`} />
        <Stat label="Affected assets" value={new Set(alerts.flatMap((a) => a.host ? [a.host] : [])).size}
              sub={`${c.iocs} IOC(s) loaded`} />
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1.45fr 1fr" }}>
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">Recent incidents</span>
            <span className="spacer" />
            <span className="mono faint" style={{ fontSize: 10.5 }}>
              grouped by shared host / account
            </span>
          </div>
          {incidents.length === 0 ? (
            <Empty title="No incidents yet"
                   detail="Import data or load the demo dataset, then run analysis." />
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 74 }}>Ref</th>
                  <th>Title</th>
                  <th style={{ width: 92 }}>Severity</th>
                  <th style={{ width: 96 }}>Status</th>
                  <th style={{ width: 76 }}>Alerts</th>
                </tr>
              </thead>
              <tbody>
                {incidents.slice(0, 8).map((i) => (
                  <tr key={i.id} className="clickable" onClick={() => onOpenIncident(i.id)}>
                    <td className="mono" style={{ color: "var(--cyan)" }}>{i.ref}</td>
                    <td className="truncate" style={{ maxWidth: 340 }} title={i.title}>{i.title}</td>
                    <td><SeverityChip severity={i.severity} /></td>
                    <td><span className="mono faint" style={{ fontSize: 11 }}>{i.status}</span></td>
                    <td className="mono dim">{i.alert_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="col" style={{ gap: 14 }}>
          <div className="panel">
            <div className="panel-head"><span className="panel-title">Severity distribution</span></div>
            <div className="panel-body" style={{ paddingTop: 12 }}>
              {alerts.length === 0 ? (
                <div className="dim" style={{ fontSize: 12.5 }}>No alerts.</div>
              ) : (
                order.filter((s) => severityCounts[s]).map((s) => (
                  <div key={s} style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 7 }}>
                    <span style={{ width: 62 }}><SeverityChip severity={s as Alert["severity"]} /></span>
                    <div style={{ flex: 1, height: 7, background: "var(--bg)", borderRadius: 4, overflow: "hidden" }}>
                      <div style={{
                        width: `${((severityCounts[s] || 0) / maxSev) * 100}%`,
                        height: "100%",
                        background: `var(--${s === "info" ? "info" : s})`,
                        borderRadius: 4,
                      }} />
                    </div>
                    <span className="mono dim" style={{ width: 22, textAlign: "right" }}>
                      {severityCounts[s]}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="panel">
            <div className="panel-head"><span className="panel-title">Analysis engine</span></div>
            <div className="panel-body" style={{ fontSize: 12.5, lineHeight: 1.7 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <span className={`status-dot ${aiDot}`} />
                <strong style={{ fontSize: 12.5 }}>{health.ai.label}</strong>
              </div>
              <div className="dim" style={{ fontSize: 12 }}>{health.ai.detail}</div>
              <div style={{
                marginTop: 10, paddingTop: 9, borderTop: "1px solid var(--line-soft)",
                fontFamily: "var(--mono)", fontSize: 11, color: "var(--fg-faint)",
              }}>
                detection: rule engine (deterministic)<br />
                graph: {c.graph_nodes} nodes / {c.graph_edges} edges<br />
                db: {health.db}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Latest alerts</span>
          <span className="spacer" />
          <span className="mono faint" style={{ fontSize: 10.5 }}>every alert links to event IDs</span>
        </div>
        {alerts.length === 0 ? (
          <Empty title="No alerts" detail="Nothing fired on the current dataset." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 60 }}>Rule</th>
                <th>Alert</th>
                <th style={{ width: 92 }}>Severity</th>
                <th style={{ width: 130 }}>Host</th>
                <th style={{ width: 150 }}>First seen (UTC)</th>
                <th style={{ width: 70 }}>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 10).map((a) => (
                <tr key={a.id} className={a.incident_id ? "clickable" : ""}
                    onClick={() => a.incident_id && onOpenIncident(a.incident_id)}>
                  <td className="mono" style={{ color: "var(--cyan-dim)" }}>{a.rule_id}</td>
                  <td className="truncate" style={{ maxWidth: 380 }} title={a.title}>{a.title}</td>
                  <td><SeverityChip severity={a.severity} /></td>
                  <td className="mono dim">{a.host || "—"}</td>
                  <td className="mono dim">{fmtTime(a.first_ts)}</td>
                  <td className="mono" style={{ color: "var(--cyan-dim)" }}>
                    {a.evidence.length}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, sub, accent }: {
  label: string; value: number; sub?: string; accent?: string;
}) {
  return (
    <div className="panel" style={{ padding: "13px 15px" }}>
      <div style={{
        fontSize: 10, letterSpacing: 1, textTransform: "uppercase",
        color: "var(--fg-muted)", fontWeight: 650, marginBottom: 6,
      }}>
        {label}
      </div>
      <div style={{
        fontSize: 25, fontWeight: 600, lineHeight: 1.1, color: accent || "var(--fg)",
        fontFamily: "var(--mono)",
      }}>
        {value}
      </div>
      {sub ? <div className="faint" style={{ fontSize: 11, marginTop: 3 }}>{sub}</div> : null}
    </div>
  );
}
