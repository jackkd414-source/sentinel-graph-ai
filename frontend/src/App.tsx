import { useCallback, useEffect, useState } from "react";
import { api, type Health, type Project } from "./api";
import { AppShell, GlobalSearch, Sidebar, Topbar, type NavGroup } from "./components/layout";
import { Icons } from "./components/icons";
import { ErrorState, Notification } from "./components/ui";
import { Dashboard } from "./pages/Dashboard";
import { IncidentsList } from "./pages/IncidentsList";
import { IncidentView } from "./pages/IncidentView";
import { GraphPage } from "./pages/GraphPage";
import { EventsExplorer } from "./pages/EventsExplorer";
import { ImportPage } from "./pages/ImportPage";
import { EvidenceRepository, DetectionRules } from "./pages/ArtifactsRules";
import { ProvidersPage } from "./pages/ProvidersPage";
import { ReportsPage } from "./pages/ReportsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TutorialPage } from "./pages/TutorialPage";
import { LangSwitch } from "./i18n";
import { clearToken, getToken, hasToken, setToken } from "./auth";
import type { RouteKey } from "./routes";

const initials = (name?: string) =>
  (name || "SentinelGraph AI")
    .split(/\s+/).filter(Boolean).slice(0, 2)
    .map((w) => w[0]!.toUpperCase()).join("") || "SG";

export function App() {
  const [route, setRouteState] = useState<RouteKey>(
    () => (localStorage.getItem("sg.route") as RouteKey) || "dashboard",
  );
  /** Remembered so a language switch (which remounts the app) stays on the page. */
  const setRoute = useCallback((r: RouteKey) => {
    localStorage.setItem("sg.route", r);
    setRouteState(r);
  }, []);
  const [incidentId, setIncidentId] = useState<number | null>(null);
  const [eventsQuery, setEventsQuery] = useState("");
  const [graphFocusEvent, setGraphFocusEvent] = useState<number | null>(null);
  const [search, setSearch] = useState("");

  const [health, setHealth] = useState<Health | null>(null);
  const [project, setProject] = useState<Project | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [demoBusy, setDemoBusy] = useState(false);
  const [toast, setToast] = useState<{ kind: "ok" | "err" | "info"; message: string } | null>(null);
  const [tokenOpen, setTokenOpen] = useState(false);

  const refresh = useCallback(() => setReloadKey((k) => k + 1), []);

  const loadShell = useCallback(async () => {
    try {
      const h = await api.health();
      setHealth(h);
      setBootError(null);
    } catch (e) {
      setBootError(e instanceof Error ? e.message : "Cannot reach the backend");
    }
    try {
      const p = await api.projects();
      setProject(p.projects[0] ?? null);
    } catch { /* workspace indicator is non-critical */ }
  }, []);

  useEffect(() => { void loadShell(); }, [loadShell, reloadKey]);

  useEffect(() => {
    const onUnauth = () => setTokenOpen(true);
    const onAuth = () => void loadShell();
    window.addEventListener("sg:unauthorized", onUnauth);
    window.addEventListener("sg:auth-change", onAuth);
    return () => {
      window.removeEventListener("sg:unauthorized", onUnauth);
      window.removeEventListener("sg:auth-change", onAuth);
    };
  }, [loadShell]);

  const openIncident = useCallback((id: number, _ref?: string) => {
    setIncidentId(id);
    setRoute("incident");
  }, []);

  const loadDemo = useCallback(async () => {
    setDemoBusy(true);
    try {
      const r = await api.demoLoad();
      setToast({ kind: "ok", message: `Demo dataset loaded: ${r.analysis.events_analyzed} events, ${r.analysis.alerts_created} alerts, ${r.analysis.incidents_created} incidents.` });
      refresh();
    } catch (e) {
      setToast({ kind: "err", message: e instanceof Error ? e.message : "Failed to load the demo dataset" });
    } finally { setDemoBusy(false); }
  }, [refresh]);

  const submitSearch = () => {
    setEventsQuery(search);
    setRoute("events");
  };

  const c = health?.counts;
  const navGroups: NavGroup[] = [
    { label: "Workspace", items: [
      { key: "dashboard", label: "Dashboard", icon: Icons.dashboard({}) },
    ] },
    { label: "Investigate", items: [
      { key: "incidents", label: "Incidents", icon: Icons.incidents({}),
        badge: c ? <span className="tw-nav-badge">{c.incidents}</span> : undefined },
      { key: "graph", label: "Attack Graph", icon: Icons.graph({}) },
      { key: "events", label: "Events", icon: Icons.events({}),
        badge: c ? <span className="tw-nav-badge">{c.events}</span> : undefined },
    ] },
    { label: "Evidence", items: [
      { key: "import", label: "Imports", icon: Icons.imports({}) },
      { key: "evidence", label: "Evidence Repository", icon: Icons.evidence({}),
        badge: c ? <span className="tw-nav-badge">{c.artifacts}</span> : undefined },
    ] },
    { label: "Engine", items: [
      { key: "rules", label: "Detection Rules", icon: Icons.rules({}) },
      { key: "providers", label: "AI Providers", icon: Icons.providers({}),
        badge: health ? (
          <span className={`tw-nav-badge ${health.ai.mode === "ai_enabled" ? "on"
            : health.ai.mode === "missing_credential" ? "warn" : ""}`}>
            {health.ai.mode === "ai_enabled" ? "on" : health.ai.mode === "missing_credential" ? "!" : "off"}
          </span>) : undefined },
    ] },
    { label: "System", items: [
      { key: "reports", label: "Reports", icon: Icons.reports({}) },
      { key: "settings", label: "Settings", icon: Icons.settings({}) },
    ] },
    { label: "Learn", items: [
      { key: "tutorial", label: "Tutorial", icon: Icons.info({}) },
    ] },
  ];

  const sidebar = (
    <Sidebar
      groups={navGroups}
      active={route}
      onNavigate={(k) => setRoute(k as RouteKey)}
      footer={
        <>
          <span className="row" style={{ gap: 6 }}>
            <span className={`tw-dot ${health?.status === "ok" ? "tw-dot-ok" : "tw-dot-err"}`} />
            {health?.status === "ok" ? "System Healthy" : "Backend unreachable"}
          </span>
          <LangSwitch />
          <span className="mono">v{health?.version || "—"}</span>
        </>
      }
    />
  );

  const topbar = (
    <Topbar
      search={<GlobalSearch value={search} onChange={setSearch} onSubmit={submitSearch} />}
      right={
        <>
          <button className="tw-ws" onClick={() => setRoute("settings")} title="Workspace">
            {Icons.building({ style: { width: 15, height: 15 } })}
            <b>{project?.name || "Default Workspace"}</b>
            {Icons.chevronDown({ style: { width: 13, height: 13 } })}
          </button>
          <span className="tw-conn">
            <span className={`tw-dot ${health?.status === "ok" ? "tw-dot-ok" : "tw-dot-err"}`} />
            {health?.status === "ok" ? "Connected" : "Offline"}
          </span>
          <button className="tw-icon-btn" title="Alerts" aria-label="Alerts" onClick={() => setRoute("events")}>
            {Icons.bell({ style: { width: 17, height: 17 } })}
          </button>
          <button className="tw-avatar" title={hasToken() ? "Session token set" : "Sign in"}
                  aria-label="Session" onClick={() => setTokenOpen(true)}>
            {initials(project?.name)}
          </button>
        </>
      }
    />
  );

  return (
    <AppShell sidebar={sidebar} topbar={topbar}>
      {toast ? (
        <div className="tw-toast-wrap">
          <Notification kind={toast.kind} message={toast.message} onClose={() => setToast(null)} />
        </div>
      ) : null}

      {bootError ? (
        <div className="tw-content">
          <ErrorState message={bootError} onRetry={() => void loadShell()} />
        </div>
      ) : route === "dashboard" ? (
        <div className="tw-content">
          <Dashboard onOpenIncident={openIncident} onLoadDemo={loadDemo} demoBusy={demoBusy}
                     reloadKey={reloadKey} onNavigate={setRoute} />
        </div>
      ) : route === "incidents" ? (
        <div className="tw-content"><IncidentsList onOpen={openIncident} /></div>
      ) : route === "incident" ? (
        <IncidentView incidentId={incidentId} />
      ) : route === "graph" ? (
        <GraphPage focusEventId={graphFocusEvent} onFocusConsumed={() => setGraphFocusEvent(null)}
                   onSearchEvents={(q) => { setEventsQuery(q); setRoute("events"); }} />
      ) : route === "events" ? (
        <div className="tw-content">
          <EventsExplorer initialQuery={eventsQuery}
                          onOpenGraphForEvent={(id) => { setGraphFocusEvent(id); setRoute("graph"); }} />
        </div>
      ) : route === "import" ? (
        <div className="tw-content"><ImportPage onImported={refresh} /></div>
      ) : route === "evidence" ? (
        <div className="tw-content">
          <EvidenceRepository onImport={() => setRoute("import")} reloadKey={reloadKey} />
        </div>
      ) : route === "rules" ? (
        <div className="tw-content"><DetectionRules onReanalyzed={refresh} /></div>
      ) : route === "providers" ? (
        <div className="tw-content"><ProvidersPage /></div>
      ) : route === "reports" ? (
        <div className="tw-content"><ReportsPage onOpenIncident={openIncident} /></div>
      ) : route === "tutorial" ? (
        <div className="tw-content"><TutorialPage onNavigate={setRoute} /></div>
      ) : (
        <div className="tw-content"><SettingsPage /></div>
      )}

      {tokenOpen ? (
        <TokenDialog onClose={() => { setTokenOpen(false); void loadShell(); }} />
      ) : null}
    </AppShell>
  );
}

function TokenDialog({ onClose }: { onClose: () => void }) {
  const [value, setValue] = useState("");
  return (
    <div className="tw-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="tw-dialog" role="dialog" aria-modal="true" aria-label="Session token">
        <div className="tw-dialog-head">Session token</div>
        <div className="tw-dialog-body">
          <p className="faint" style={{ fontSize: "var(--tw-fs-secondary)", lineHeight: 1.6, marginBottom: 12 }}>
            Required only when the server runs with <span className="mono">SG_AUTH_TOKEN</span>. It is kept in
            session storage for this tab and never rendered back.
          </p>
          <input className="tw-input" type="password" placeholder="Bearer token" autoFocus
                 value={value} onChange={(e) => setValue(e.target.value)}
                 onKeyDown={(e) => { if (e.key === "Enter" && value.trim()) { setToken(value); onClose(); } }} />
          {getToken() ? (
            <div className="row" style={{ marginTop: 10, gap: 8 }}>
              <span className="tw-dot tw-dot-ok" />
              <span className="faint" style={{ fontSize: "var(--tw-fs-meta)" }}>
                A token is currently set ({getToken().length} chars, masked).
              </span>
            </div>
          ) : null}
        </div>
        <div className="tw-dialog-foot">
          {getToken() ? (
            <button className="tw-btn" onClick={() => { clearToken(); onClose(); }}>Clear token</button>
          ) : null}
          <button className="tw-btn" onClick={onClose}>Cancel</button>
          <button className="tw-btn tw-btn-primary" disabled={!value.trim()}
                  onClick={() => { setToken(value); onClose(); }}>Save</button>
        </div>
      </div>
    </div>
  );
}
