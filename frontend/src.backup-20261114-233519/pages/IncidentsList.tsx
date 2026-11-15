import { useEffect, useState } from "react";
import { api, type IncidentSummary } from "../api";
import { Empty, ErrorBanner, Loading, SeverityChip, fmtTime } from "../components/ui";

export function IncidentsList({ onOpen }: { onOpen: (id: number) => void }) {
  const [items, setItems] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sev, setSev] = useState("");
  const [status, setStatus] = useState("");

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.incidents();
      setItems(r.incidents);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load incidents");
    } finally { setLoading(false); }
  };

  useEffect(() => { void load(); }, []);

  const rows = items.filter(
    (i) => (!sev || i.severity === sev) && (!status || i.status === status),
  );

  if (loading) return <Loading />;
  if (error) return <ErrorBanner message={error} onRetry={load} />;

  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row" style={{ flexWrap: "wrap" }}>
        <select className="select" style={{ width: 170 }} value={sev}
                onChange={(e) => setSev(e.target.value)}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) =>
            <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="select" style={{ width: 170 }} value={status}
                onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          {["open", "investigating", "contained", "closed"].map((s) =>
            <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="faint mono" style={{ fontSize: 11 }}>
          {rows.length} of {items.length} incidents
        </span>
        <span className="spacer" />
        <button className="btn btn-sm" onClick={load}>Refresh</button>
      </div>

      {rows.length === 0 ? (
        <div className="panel">
          <Empty title="No incidents" detail="Load the demo dataset or import events, then run analysis." />
        </div>
      ) : (
        <div className="panel">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 74 }}>Ref</th>
                <th>Title</th>
                <th style={{ width: 92 }}>Severity</th>
                <th style={{ width: 100 }}>Status</th>
                <th style={{ width: 70 }}>Alerts</th>
                <th style={{ width: 210 }}>Hosts</th>
                <th style={{ width: 165 }}>First seen (UTC)</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.id} className="clickable" onClick={() => onOpen(i.id)}>
                  <td className="mono" style={{ color: "var(--cyan)" }}>{i.ref}</td>
                  <td className="truncate" style={{ maxWidth: 380 }} title={i.title}>{i.title}</td>
                  <td><SeverityChip severity={i.severity} /></td>
                  <td className="mono faint" style={{ fontSize: 11 }}>{i.status}</td>
                  <td className="mono dim">{i.alert_count}</td>
                  <td className="mono dim truncate" style={{ maxWidth: 210, fontSize: 11 }}
                      title={i.hosts.join(", ")}>
                    {i.hosts.join(", ") || "—"}
                  </td>
                  <td className="mono dim">{fmtTime(i.first_ts)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
