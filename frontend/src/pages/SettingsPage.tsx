import { useCallback, useEffect, useState } from "react";
import { api, type Health, type Project } from "../api";
import { PageHeader } from "../components/layout";
import { DataTable, PanelHeader, type Column } from "../components/data";
import { EmptyState, ErrorState, LoadingState, fmtTime } from "../components/ui";
import { clearToken, getToken, hasToken, setToken } from "../auth";

interface AuditEntry { id: number; action: string; target: string | null; detail: string | null; created_at: string; }

export function SettingsPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tokenInput, setTokenInput] = useState("");
  const [tokenSet, setTokenSet] = useState(hasToken());

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [h, p, a] = await Promise.all([api.health(), api.projects(), api.audit()]);
      setHealth(h);
      setProjects(p.projects);
      setAudit(a.entries);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load settings");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const saveToken = () => {
    setToken(tokenInput.trim());
    setTokenInput("");
    setTokenSet(hasToken());
    void load();
  };
  const dropToken = () => {
    clearToken();
    setTokenSet(false);
    void load();
  };

  if (loading && !health) return <LoadingState label="Loading settings…" />;
  if (error && !health) return <ErrorState message={error} onRetry={load} />;
  if (!health) return null;

  const auditCols: Column<AuditEntry>[] = [
    { key: "id", header: "ID", width: 60, render: (e) => <span className="mono">#{e.id}</span> },
    { key: "action", header: "Action", width: 190, render: (e) => <span className="mono" style={{ color: "var(--tw-primary)" }}>{e.action}</span> },
    { key: "target", header: "Target", width: 200, render: (e) => <span className="mono">{e.target || "—"}</span> },
    { key: "detail", header: "Detail", render: (e) => (
      <span className="truncate" style={{ display: "block", maxWidth: 380 }}>{e.detail || "—"}</span>) },
    { key: "at", header: "When", width: 168, render: (e) => <span className="mono num">{fmtTime(e.created_at)}</span> },
  ];

  return (
    <>
      <PageHeader title="Settings"
        subtitle="Application configuration, session and connection state."
        actions={<button className="tw-btn tw-btn-sm" onClick={() => void load()}>Refresh</button>} />

      {error ? <div style={{ marginBottom: 16 }}><ErrorState message={error} onRetry={load} /></div> : null}

      <div className="tw-set-grid">
        <div className="col" style={{ gap: 16 }}>
          <div className="tw-panel">
            <PanelHeader title="Application" />
            <div className="tw-panel-body">
              <dl className="tw-kv">
                <dt>Version</dt><dd className="mono">{health.version}</dd>
                <dt>Database</dt><dd className="mono">{health.db}</dd>
                <dt>Workspace</dt><dd className="mono">{projects[0]?.name || "—"}{projects[0]?.is_demo ? " (demo)" : ""}</dd>
                <dt>Server time</dt><dd className="mono">{fmtTime(health.time)} UTC</dd>
              </dl>
            </div>
          </div>

          <div className="tw-panel">
            <PanelHeader title="API connection" />
            <div className="tw-panel-body">
              <div className="tw-syslist">
                <div className="tw-sysrow">
                  <span className={`tw-dot ${health.status === "ok" ? "tw-dot-ok" : "tw-dot-err"}`} />
                  <span className="tw-syslabel">Backend health</span>
                  <span className="tw-sysval">{health.status}</span>
                </div>
                <div className="tw-sysrow">
                  <span className="tw-dot tw-dot-ok" />
                  <span className="tw-syslabel">Endpoint</span>
                  <span className="tw-sysval">{window.location.origin}</span>
                </div>
                <div className="tw-sysrow">
                  <span className={`tw-dot ${health.ai.mode === "ai_enabled" ? "tw-dot-ok" : "tw-dot-idle"}`} />
                  <span className="tw-syslabel">Analysis mode</span>
                  <span className="tw-sysval">{health.ai.mode}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="col" style={{ gap: 16 }}>
          <div className="tw-panel">
            <PanelHeader title="Session" />
            <div className="tw-panel-body">
              <p className="faint" style={{ fontSize: "var(--tw-fs-secondary)", lineHeight: 1.6, marginBottom: 12 }}>
                Required only when the server runs with <span className="mono">SG_AUTH_TOKEN</span>. The token is
                held in session storage for this tab and is never rendered back.
              </p>
              <div className="row" style={{ gap: 8, marginBottom: 10 }}>
                <span className={`tw-dot ${tokenSet ? "tw-dot-ok" : "tw-dot-idle"}`} />
                <strong style={{ fontSize: "var(--tw-fs-secondary)" }}>
                  {tokenSet ? "Session token configured" : "No session token set"}
                </strong>
              </div>
              <div className="row" style={{ gap: 8 }}>
                <input className="tw-input" type="password" placeholder="Bearer token"
                       value={tokenInput} onChange={(e) => setTokenInput(e.target.value)} />
                <button className="tw-btn tw-btn-sm tw-btn-primary" onClick={saveToken} disabled={!tokenInput.trim()}>Save</button>
                <button className="tw-btn tw-btn-sm" onClick={dropToken} disabled={!tokenSet}>Clear</button>
              </div>
              <div className="mono faint" style={{ marginTop: 8 }}>
                {getToken() ? `stored (${getToken().length} chars, masked)` : "—"}
              </div>
            </div>
          </div>

          <div className="tw-panel">
            <PanelHeader title="Data" />
            <div className="tw-panel-body">
              <dl className="tw-kv">
                <dt>Projects</dt><dd className="mono">{health.counts.projects}</dd>
                <dt>Artifacts</dt><dd className="mono">{health.counts.artifacts}</dd>
                <dt>Events</dt><dd className="mono">{health.counts.events}</dd>
                <dt>Reports</dt><dd className="mono">{health.counts.reports}</dd>
              </dl>
            </div>
          </div>
        </div>
      </div>

      <div className="tw-panel" style={{ marginTop: 20 }}>
        <PanelHeader title="Audit log" sub="most recent first" />
        <DataTable columns={auditCols} rows={audit} rowKey={(e) => e.id}
                   empty={<EmptyState title="No audit entries" />} />
      </div>
    </>
  );
}
