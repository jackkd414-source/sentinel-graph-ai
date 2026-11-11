import { useEffect, useState } from "react";
import { api, type Artifact, type Rule } from "../api";
import { Empty, ErrorBanner, Loading, SeverityChip, fmtBytes, fmtTime } from "../components/ui";

export function ArtifactsPage({ onImport, reloadKey }: {
  onImport: () => void; reloadKey: number;
}) {
  const [items, setItems] = useState<Artifact[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [resetting, setResetting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.artifacts();
      setItems(r.artifacts);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load artifacts");
    } finally { setLoading(false); }
  };

  const removeArtifact = async (a: Artifact) => {
    if (!window.confirm(
      `Delete "${a.name}"?\n\nThis removes the imported file and every event it produced, ` +
      `then rebuilds alerts, incidents and the attack graph from what is left. ` +
      `This cannot be undone.`)) return;
    setBusy(a.id); setError(null); setNotice(null);
    try {
      const r = await api.deleteArtifact(a.id);
      setNotice(`Deleted "${r.deleted_artifact}" — ${r.events_removed} event(s) removed, ` +
        `derived data rebuilt.`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed");
    } finally { setBusy(null); }
  };

  const clearAll = async (keepIocs: boolean) => {
    if (!window.confirm(
      keepIocs
        ? "Clear ALL imported data (events, alerts, incidents, graph, artifacts)?\n\nThreat-intelligence indicators are kept."
        : "Clear ALL imported data AND the threat-intelligence indicators?\n\nThe workspace will be empty.")) return;
    setResetting(true); setError(null); setNotice(null);
    try {
      const r = await api.resetData(keepIocs);
      const n = Object.values(r.cleared).reduce((s, v) => s + v, 0);
      setNotice(`Cleared ${n} row(s). ` +
        `Remaining: ${r.counts.events} events, ${r.counts.alerts} alerts, ${r.counts.incidents} incidents.`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Reset failed");
    } finally { setResetting(false); }
  };

  useEffect(() => { void load(); }, [reloadKey]);

  if (loading) return <Loading />;
  if (error) return <ErrorBanner message={error} onRetry={load} />;

  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row">
        <span className="dim" style={{ fontSize: 12.5, flex: 1 }}>
          Every import is recorded with record counts, parse status, and a SHA-256 of the
          exact bytes received.
        </span>
        <button className="btn btn-primary btn-sm" onClick={onImport}>Import data</button>
      </div>

      {notice ? (
        <div className="banner banner-info"><span>{notice}</span></div>
      ) : null}

      <div className="banner banner-info">
        <span>
          <strong>What the SHA-256 proves:</strong> it verifies that a stored copy is identical
          to the bytes that were imported. It does <em>not</em> prove the original file was
          unmodified before it reached this tool.
        </span>
      </div>

      {items.length === 0 ? (
        <div className="panel"><Empty title="No artifacts" detail="Import a file or load the demo dataset." /></div>
      ) : (
        <div className="panel">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th style={{ width: 130 }}>Type</th>
                <th style={{ width: 100 }}>Records</th>
                <th style={{ width: 96 }}>Parse</th>
                <th style={{ width: 84 }}>Size</th>
                <th style={{ width: 90 }}>Synthetic</th>
                <th style={{ width: 170 }}>Imported (UTC)</th>
                <th style={{ width: 190 }}>SHA-256</th>
                <th style={{ width: 84 }}></th>
              </tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id}>
                  <td className="mono" style={{ fontSize: 11.5 }}>{a.name}</td>
                  <td className="mono faint" style={{ fontSize: 10.5 }}>{a.source_type}</td>
                  <td className="mono dim">
                    {a.record_ok}/{a.record_total}
                    {a.record_failed > 0 ? (
                      <span style={{ color: "var(--high)" }}> ({a.record_failed} rejected)</span>
                    ) : null}
                  </td>
                  <td>
                    <span className={`chip ${a.parse_status === "ok" ? "chip-observed"
                      : a.parse_status === "partial" ? "chip-medium" : "chip-critical"}`}>
                      {a.parse_status}
                    </span>
                  </td>
                  <td className="mono dim">{fmtBytes(a.size_bytes)}</td>
                  <td className="mono" style={{ fontSize: 11,
                    color: a.is_synthetic ? "var(--medium)" : "var(--fg-muted)" }}>
                    {a.is_synthetic ? "yes" : "no"}
                  </td>
                  <td className="mono dim">{fmtTime(a.imported_at)}</td>
                  <td className="mono faint" style={{ fontSize: 10 }} title={a.sha256 || ""}>
                    {(a.sha256 || "—").slice(0, 24)}…
                  </td>
                  <td>
                    <button className="btn btn-sm" disabled={busy === a.id}
                      title="Delete this import and every event it produced, then rebuild alerts and the graph"
                      onClick={() => void removeArtifact(a)}>
                      {busy === a.id ? "…" : "Delete"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Clear all imported data</span>
        </div>
        <div className="panel-body col" style={{ gap: 10 }}>
          <span className="dim" style={{ fontSize: 12.5 }}>
            Removes every imported event, alert, incident, graph node and artifact.
            Detection rules and the {items.length ? "threat-intelligence indicators" : "IOC"} set
            are kept. Use this when you imported the wrong file and want to start over.
          </span>
          <div className="row" style={{ gap: 8 }}>
            <button className="btn btn-sm" disabled={resetting}
              onClick={() => void clearAll(true)}>
              {resetting ? "Clearing…" : "Clear data (keep IOCs)"}
            </button>
            <button className="btn btn-sm" disabled={resetting}
              onClick={() => void clearAll(false)}>
              {resetting ? "Clearing…" : "Clear data + IOCs"}
            </button>
          </div>
        </div>
      </div>

      {items.some((a) => a.parse_status !== "ok") ? (
        <div className="panel">
          <div className="panel-head"><span className="panel-title">Parse notes</span></div>
          <div className="panel-body" style={{ fontSize: 12 }}>
            {items.filter((a) => a.parse_notes).map((a) => (
              <div key={a.id} style={{ marginBottom: 8 }}>
                <div className="mono" style={{ color: "var(--cyan-dim)", fontSize: 11 }}>{a.name}</div>
                <div className="dim mono" style={{ fontSize: 10.5, wordBreak: "break-word" }}>
                  {a.parse_notes}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function RulesPage({ onReanalyzed }: { onReanalyzed: () => void }) {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.rules();
      setRules(r.rules);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load rules");
    } finally { setLoading(false); }
  };

  useEffect(() => { void load(); }, []);

  const toggle = async (id: string, enabled: boolean) => {
    setBusy(id);
    try {
      await api.toggleRule(id, enabled);
      await api.reanalyze();
      onReanalyzed();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Toggle failed");
    } finally { setBusy(null); }
  };

  if (loading) return <Loading />;
  if (error) return <ErrorBanner message={error} onRetry={load} />;

  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="banner banner-info">
        <span>
          Rules are deterministic functions over normalized events. Toggling one re-runs the
          full pipeline immediately, so you can see exactly which alerts depend on it.
        </span>
      </div>
      <div className="grid grid-2">
        {rules.map((r) => (
          <div key={r.id} className="panel" style={{ padding: 0 }}>
            <div className="panel-head">
              <span className="mono" style={{ color: "var(--cyan)", fontSize: 12 }}>{r.id}</span>
              <SeverityChip severity={r.severity} />
              <span className="spacer" />
              <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11.5 }}>
                <input type="checkbox" checked={r.enabled === 1} disabled={busy === r.id}
                       onChange={(e) => void toggle(r.id, e.target.checked)} />
                {r.enabled ? "enabled" : "disabled"}
              </label>
            </div>
            <div className="panel-body" style={{ fontSize: 12.5 }}>
              <div style={{ fontWeight: 600, marginBottom: 5 }}>{r.name}</div>
              <div className="dim" style={{ lineHeight: 1.6, marginBottom: 8 }}>{r.description}</div>
              <div className="mono faint" style={{ fontSize: 10.5, marginBottom: 6 }}>
                CATEGORY: {r.category} · v{r.version}
              </div>
              <div className="mono" style={{
                fontSize: 10.5, background: "var(--bg)", padding: "7px 9px",
                borderRadius: 4, color: "var(--fg-dim)", wordBreak: "break-word",
              }}>
                {r.logic}
              </div>
            </div>
          </div>
        ))}
      </div>
      <div className="dim" style={{ fontSize: 11.5, lineHeight: 1.6 }}>
        These are correlation heuristics with published logic. SentinelGraph does not claim
        zero-day detection; each rule states the behaviour it matches and the thresholds it uses.
      </div>
    </div>
  );
}
