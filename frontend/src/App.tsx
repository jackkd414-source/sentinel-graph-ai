import { useCallback, useEffect, useState } from "react";
import { api, type Health } from "./api";
import { Icon } from "./components/ui";
import { AttackGraph } from "./components/AttackGraph";
import { Dashboard } from "./pages/Dashboard";
import { IncidentsList } from "./pages/IncidentsList";
import { IncidentView } from "./pages/IncidentView";
import { EventsExplorer } from "./pages/EventsExplorer";
import { ArtifactsPage, RulesPage } from "./pages/ArtifactsRules";
import { ProvidersPage } from "./pages/ProvidersPage";
import { ImportPage } from "./pages/ImportPage";
import "./styles.css";

type Page =
  | { kind: "dashboard" }
  | { kind: "incidents" }
  | { kind: "incident"; id: number }
  | { kind: "graph" }
  | { kind: "events" }
  | { kind: "evidence" }
  | { kind: "rules" }
  | { kind: "providers" }
  | { kind: "import" };

const TITLES: Record<Page["kind"], { title: string; sub: string }> = {
  dashboard: { title: "Dashboard", sub: "workspace overview" },
  incidents: { title: "Incidents", sub: "correlated alert groups" },
  incident: { title: "Investigation", sub: "evidence · graph · timeline" },
  graph: { title: "Attack Graph", sub: "entities and relationships" },
  events: { title: "Events", sub: "normalized event store" },
  evidence: { title: "Evidence", sub: "imported artifacts" },
  rules: { title: "Detection Rules", sub: "deterministic engine" },
  providers: { title: "AI Providers", sub: "model configuration" },
  import: { title: "Import", sub: "ingest security data" },
};

export function App() {
  const [page, setPage] = useState<Page>({ kind: "dashboard" });
  const [health, setHealth] = useState<Health | null>(null);
  const [demoBusy, setDemoBusy] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [toast, setToast] = useState<string | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);

  const refreshHealth = useCallback(async () => {
    try {
      const h = await api.health();
      setHealth(h);
      setBootError(null);
    } catch (e) {
      setBootError(e instanceof Error
        ? `Cannot reach the API: ${e.message}`
        : "Cannot reach the API");
    }
  }, []);

  useEffect(() => { void refreshHealth(); }, [refreshHealth]);

  const triggerReload = () => {
    setReloadKey((k) => k + 1);
    void refreshHealth();
  };

  const loadDemo = async () => {
    setDemoBusy(true);
    try {
      const r = await api.demoLoad(undefined, true);
      setToast(
        `Demo loaded: ${r.analysis.events_analyzed} events → ` +
        `${r.analysis.alerts_created} alerts → ${r.analysis.incidents_created} incidents. ` +
        `${r.edge_case_import.records_failed} malformed record(s) rejected as designed.`,
      );
      triggerReload();
      setPage({ kind: "dashboard" });
      window.setTimeout(() => setToast(null), 9000);
    } catch (e) {
      setToast(e instanceof Error ? `Demo load failed: ${e.message}` : "Demo load failed");
    } finally {
      setDemoBusy(false);
    }
  };

  const nav = (next: Page) => setPage(next);
  const isActive = (kinds: Page["kind"][]) => kinds.includes(page.kind);

  const c = health?.counts;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><Icon.shield /></span>
          <div className="brand-text">
            <span className="brand-name">SentinelGraph AI</span>
            <span className="brand-tag">From Signals to Story</span>
          </div>
        </div>

        <nav className="nav">
          <div className="nav-section">Investigate</div>
          <NavItem active={isActive(["dashboard"])} onClick={() => nav({ kind: "dashboard" })}
                   icon={<Icon.dashboard />} label="Dashboard" />
          <NavItem active={isActive(["incidents", "incident"])}
                   onClick={() => nav({ kind: "incidents" })}
                   icon={<Icon.incident />} label="Incidents"
                   badge={c ? String(c.incidents) : undefined} />
          <NavItem active={isActive(["graph"])} onClick={() => nav({ kind: "graph" })}
                   icon={<Icon.graph />} label="Attack Graph" />
          <NavItem active={isActive(["events"])} onClick={() => nav({ kind: "events" })}
                   icon={<Icon.timeline />} label="Events"
                   badge={c ? String(c.events) : undefined} />

          <div className="nav-section">Data</div>
          <NavItem active={isActive(["import"])} onClick={() => nav({ kind: "import" })}
                   icon={<Icon.upload />} label="Import" />
          <NavItem active={isActive(["evidence"])} onClick={() => nav({ kind: "evidence" })}
                   icon={<Icon.evidence />} label="Evidence"
                   badge={c ? String(c.artifacts) : undefined} />

          <div className="nav-section">Engine</div>
          <NavItem active={isActive(["rules"])} onClick={() => nav({ kind: "rules" })}
                   icon={<Icon.rules />} label="Detection Rules" />
          <NavItem active={isActive(["providers"])} onClick={() => nav({ kind: "providers" })}
                   icon={<Icon.settings />} label="AI Providers"
                   badge={health ? (health.ai.mode === "ai_enabled" ? "on" : "off") : undefined}
                   hot={health?.ai.mode === "missing_credential"} />
        </nav>

        <div className="sidebar-foot">
          {health ? (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                <span className={`status-dot ${
                  health.ai.mode === "ai_enabled" ? "dot-ok"
                  : health.ai.mode === "missing_credential" ? "dot-warn" : "dot-idle"}`} />
                <span>{health.ai.mode === "ai_enabled" ? "AI enabled" : "core mode"}</span>
              </div>
              <div style={{ fontSize: 10 }}>v{health.version} · {health.db}</div>
            </>
          ) : <span>connecting…</span>}
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <h1>{TITLES[page.kind].title}</h1>
          </div>
          <span className="topbar-sub">{TITLES[page.kind].sub}</span>
          <div className="topbar-right">
            <button className="btn btn-sm" onClick={triggerReload} title="Refresh data">
              <Icon.refresh /> Refresh
            </button>
            <button className="btn btn-sm btn-primary" onClick={() => void loadDemo()}
                    disabled={demoBusy} title="Load the built-in synthetic dataset">
              {demoBusy ? <span className="spinner" /> : <Icon.shield />}
              {demoBusy ? "Loading…" : "Load demo"}
            </button>
          </div>
        </header>

        {bootError ? (
          <div style={{ padding: 20 }}>
            <div className="banner banner-err">
              <span>
                <strong>{bootError}</strong>
                <br />
                Make sure the backend is running:
                <span className="mono"> ./.venv/Scripts/python.exe -m sentinelgraph serve</span>
              </span>
            </div>
          </div>
        ) : null}

        {toast ? (
          <div style={{ padding: "12px 20px 0" }}>
            <div className="banner banner-ok">
              <span style={{ flex: 1 }}>{toast}</span>
              <button className="btn btn-sm" onClick={() => setToast(null)}>Dismiss</button>
            </div>
          </div>
        ) : null}

        <div className={page.kind === "incident" || page.kind === "graph" ? "content flush" : "content"}>
          {page.kind === "dashboard" && (
            <Dashboard
              reloadKey={reloadKey}
              demoBusy={demoBusy}
              onLoadDemo={loadDemo}
              onOpenIncident={(id) => nav({ kind: "incident", id })}
            />
          )}
          {page.kind === "incidents" && (
            <IncidentsList onOpen={(id) => nav({ kind: "incident", id })} />
          )}
          {page.kind === "incident" && (
            <IncidentView incidentId={page.id} />
          )}
          {page.kind === "graph" && <GlobalGraph />}
          {page.kind === "events" && <EventsExplorer />}
          {page.kind === "evidence" && (
            <ArtifactsPage onImport={() => nav({ kind: "import" })} reloadKey={reloadKey} />
          )}
          {page.kind === "rules" && <RulesPage onReanalyzed={triggerReload} />}
          {page.kind === "providers" && <ProvidersPage />}
          {page.kind === "import" && <ImportPage onImported={triggerReload} />}
        </div>
      </main>
    </div>
  );
}

function NavItem({ active, onClick, icon, label, badge, hot }: {
  active: boolean; onClick: () => void; icon: React.ReactNode;
  label: string; badge?: string; hot?: boolean;
}) {
  return (
    <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}>
      {icon}
      <span>{label}</span>
      {badge ? <span className={`nav-badge ${hot ? "hot" : ""}`}>{badge}</span> : null}
    </button>
  );
}

/* Global graph view: same renderer, full-workspace filters. */
function GlobalGraph() {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.graph>> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showInferred, setShowInferred] = useState(true);
  const [search, setSearch] = useState("");
  const [types, setTypes] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<number | null>(null);
  const [showEvents, setShowEvents] = useState(false);

  const load = useCallback(async () => {
    try {
      setError(null);
      const g = await api.graph({
        include_inferred: true,
        search: search || undefined,
      });
      setData(g);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load graph");
    }
  }, [search]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{
        display: "flex", gap: 10, padding: "10px 16px", borderBottom: "1px solid var(--line)",
        background: "var(--bg-elevated)", alignItems: "center", flexWrap: "wrap",
      }}>
        <input className="input" style={{ width: 240 }} placeholder="Search entity…"
               value={search}
               onChange={(e) => setSearch(e.target.value)} />
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
          <input type="checkbox" checked={showInferred}
                 onChange={(e) => setShowInferred(e.target.checked)} />
          Show inferred
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
          <input type="checkbox" checked={showEvents}
                 onChange={(e) => setShowEvents(e.target.checked)} />
          Show event nodes
        </label>
        <span style={{ width: 1, height: 15, background: "var(--line)" }} />
        {data ? (
          [...new Set(data.nodes.map((n) => n.node_type))].sort().map((t) => (
            <button key={t} className={`chip ${types.has(t) ? "chip-observed" : "chip-info"}`}
                    style={{ cursor: "pointer", border: "1px solid var(--line)" }}
                    onClick={() => {
                      const next = new Set(types);
                      if (next.has(t)) next.delete(t); else next.add(t);
                      setTypes(next);
                    }}>
              {t}
            </button>
          ))
        ) : null}
      </div>
      {error ? <div style={{ padding: 16 }} className="banner banner-err">{error}</div> : null}
      <div style={{ flex: 1, minHeight: 0, display: "grid",
                    gridTemplateColumns: selected ? "1fr 380px" : "1fr" }}>
        <div style={{ minWidth: 0 }}>
          {data ? (
            <AttackGraph data={data} selectedId={selected} onSelect={setSelected}
                         showInferred={showInferred} highlightTypes={types}
                         showEvents={showEvents} />
          ) : <div className="loading-row"><span className="spinner" />Building graph…</div>}
        </div>
      </div>
    </div>
  );
}
