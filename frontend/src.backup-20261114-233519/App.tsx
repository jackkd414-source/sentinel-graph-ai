import { useCallback, useEffect, useState } from "react";
import { api, type GraphNode, type Health } from "./api";
import { clearToken, hasToken, setToken } from "./auth";
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
  const [eventsQuery, setEventsQuery] = useState("");
  const [eventsSeq, setEventsSeq] = useState(0);
  const [toast, setToast] = useState<string | null>(null);
    const [bootError, setBootError] = useState<string | null>(null);
      const [tokenOpen, setTokenOpen] = useState(false);
      const [tokenValue, setTokenValue] = useState("");
      const [signedIn, setSignedIn] = useState(hasToken());
      const [needsAuth, setNeedsAuth] = useState(false);

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

  // React to token changes and 401s from any API call. The token itself never
  // enters the UI or an error message - only its presence is tracked.
  useEffect(() => {
    const onAuthChange = () => { setSignedIn(hasToken()); void refreshHealth(); };
    const onUnauthorized = () => { setNeedsAuth(true); setTokenOpen(true); };
    window.addEventListener("sg:auth-change", onAuthChange);
    window.addEventListener("sg:unauthorized", onUnauthorized);
    return () => {
      window.removeEventListener("sg:auth-change", onAuthChange);
      window.removeEventListener("sg:unauthorized", onUnauthorized);
    };
  }, [refreshHealth]);

  const applyToken = () => {
    setToken(tokenValue);
    setTokenValue("");
    setNeedsAuth(false);
    setTokenOpen(false);
  };

  const signOut = () => {
    clearToken();
    setTokenValue("");
    setSignedIn(false);
    setTokenOpen(false);
  };

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
                      {signedIn ? (
                        <button className="btn btn-sm" onClick={signOut} title="Forget the session token">
                          Sign out
                        </button>
                      ) : (
                        <button className="btn btn-sm" onClick={() => setTokenOpen((v) => !v)}
                                title="Set the SG_AUTH_TOKEN access token">
                          Token
                        </button>
                      )}
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

                {tokenOpen && !signedIn ? (
                          <div style={{ padding: "12px 20px 0" }}>
                            <div className="banner banner-warn" style={{ display: "flex", gap: 8, alignItems: "center" }}>
                              <span style={{ flex: 1 }}>
                                {needsAuth
                                  ? "This server requires an access token (SG_AUTH_TOKEN)."
                                  : "Optional: set the access token for a SG_AUTH_TOKEN deployment."}
                              </span>
                              <input className="input" type="password" style={{ width: 240 }}
                                     placeholder="Bearer token" autoComplete="off"
                                     value={tokenValue}
                                     onChange={(e) => setTokenValue(e.target.value)}
                                     onKeyDown={(e) => { if (e.key === "Enter") applyToken(); }} />
                              <button className="btn btn-sm btn-primary" onClick={applyToken}
                                      disabled={!tokenValue.trim()}>
                                Save
                              </button>
                            </div>
                          </div>
                        ) : null}

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
          {page.kind === "graph" && (
            <GlobalGraph
              onOpenIncident={(id) => nav({ kind: "incident", id })}
              onOpenEntity={(label) => {
                setEventsQuery(label);
                setEventsSeq((n) => n + 1);
                nav({ kind: "events" });
              }} />
          )}
          {page.kind === "events" && (
            <EventsExplorer key={eventsSeq} initialQuery={eventsQuery} />
          )}
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
function GlobalGraph({ onOpenEntity, onOpenIncident }: {
  onOpenEntity: (label: string) => void;
  onOpenIncident: (id: number) => void;
}) {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.graph>> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showInferred, setShowInferred] = useState(true);
  const [search, setSearch] = useState("");
  const [types, setTypes] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<number | null>(null);
  const [showEvents, setShowEvents] = useState(false);
  const [incidents, setIncidents] = useState<Awaited<ReturnType<typeof api.incidents>>["incidents"]>([]);
  const [focusIncident, setFocusIncident] = useState<string>("");
  const [focusHosts, setFocusHosts] = useState<string[] | null>(null);
  const [detail, setDetail] = useState<Awaited<ReturnType<typeof api.nodeDetail>> | null>(null);

  // "Evidence →" must lead somewhere useful: an alert opens its incident, an
  // entity opens the event search pre-filled with its value.
  const openEvidence = async (n: GraphNode) => {
    if (n.node_type === "alert") {
      const alertId = Number(n.node_key.split(":")[1]);
      try {
        const { alerts } = await api.alerts();
        const hit = alerts.find((a) => a.id === alertId);
        if (hit?.incident_id) { onOpenIncident(hit.incident_id); return; }
      } catch { /* fall through to the event search */ }
    }
    const value = n.node_key.includes(":")
      ? n.node_key.slice(n.node_key.indexOf(":") + 1)
      : n.label;
    onOpenEntity(n.node_type === "event" ? n.label : value);
  };

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

  // Incidents drive the "filter graph by incident" control.
  useEffect(() => {
    api.incidents().then((r) => setIncidents(r.incidents)).catch(() => setIncidents([]));
  }, []);

  // Selecting a node loads its evidence so the graph is traceable end to end.
  useEffect(() => {
    if (selected == null) { setDetail(null); return; }
    let alive = true;
    api.nodeDetail(selected)
      .then((d) => { if (alive) setDetail(d); })
      .catch(() => { if (alive) setDetail(null); });
    return () => { alive = false; };
  }, [selected]);

  const chooseIncident = (value: string) => {
    setFocusIncident(value);
    const inc = incidents.find((i) => String(i.id) === value);
    setFocusHosts(inc && inc.hosts.length ? inc.hosts : null);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{
        display: "flex", gap: 10, padding: "10px 16px", borderBottom: "1px solid var(--line)",
        background: "var(--bg-elevated)", alignItems: "center", flexWrap: "wrap",
      }}>
        <input className="input" style={{ width: 240 }} placeholder="Search entity…"
               value={search}
               onChange={(e) => setSearch(e.target.value)} />
        <select className="input" style={{ width: 260 }}
                title="Filter the graph to one incident's hosts and their neighbours"
                value={focusIncident} onChange={(e) => chooseIncident(e.target.value)}>
          <option value="">All incidents (no filter)</option>
          {incidents.map((i) => (
            <option key={i.id} value={String(i.id)}>
              {i.ref} · {i.title.length > 44 ? i.title.slice(0, 43) + "…" : i.title}
            </option>
          ))}
        </select>
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
                    gridTemplateColumns: selected ? "1fr 380px" : "1fr",
                    gridTemplateRows: "minmax(0, 1fr)" }}>
        <div style={{ minWidth: 0, minHeight: 0 }}>
          {data ? (
            <AttackGraph data={data} selectedId={selected} onSelect={setSelected}
                         showInferred={showInferred} highlightTypes={types}
                         showEvents={showEvents}
                         focusHosts={focusHosts}
                         onClearFocus={() => { setFocusHosts(null); setFocusIncident(""); }}
                         onOpenEvidence={(n) => void openEvidence(n)} />
          ) : <div className="loading-row"><span className="spinner" />Building graph…</div>}
        </div>
        {selected ? (
          <div style={{ borderLeft: "1px solid var(--line)", background: "var(--bg-elevated)",
                        overflow: "auto", padding: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <strong>Node detail</strong>
              <button className="btn btn-sm" onClick={() => setSelected(null)}>Close</button>
            </div>
            {!detail ? (
              <div className="loading-row" style={{ marginTop: 10 }}>
                <span className="spinner" />Loading evidence…
              </div>
            ) : (
              <>
                <div style={{ marginTop: 10, fontSize: 12.5 }}>
                  <div><span className="chip chip-info">{detail.node.node_type}</span></div>
                  <div style={{ marginTop: 6, fontWeight: 600 }}>{detail.node.label}</div>
                  <div style={{ color: "var(--fg-muted)", fontFamily: "var(--mono)", fontSize: 11 }}>
                    {detail.incoming.length} incoming · {detail.outgoing.length} outgoing
                  </div>
                </div>
                <div style={{ marginTop: 12, fontWeight: 650, fontSize: 11, letterSpacing: 0.8,
                              color: "var(--fg-dim)" }}>
                  EVIDENCE ({detail.evidence.length})
                </div>
                {detail.evidence.length === 0 ? (
                  <div style={{ marginTop: 6, fontSize: 12, color: "var(--fg-muted)" }}>
                    No direct evidence rows. This node is a derived entity.
                  </div>
                ) : (
                  <div style={{ marginTop: 6, display: "flex", flexDirection: "column", gap: 6 }}>
                    {detail.evidence.slice(0, 12).map((ev) => (
                      <div key={ev.id} style={{ border: "1px solid var(--line)", borderRadius: 5,
                                                padding: "6px 8px", fontSize: 11.5 }}>
                        <div style={{ fontFamily: "var(--mono)", color: "var(--fg-muted)" }}>
                          {ev.ts_utc || ev.ts_raw || "no timestamp"} · {ev.source}
                        </div>
                        <div style={{ marginTop: 2 }}>
                          <strong>{ev.event_type}</strong>
                          {ev.host ? ` · ${ev.host}` : ""}
                          {ev.user_name ? ` · ${ev.user_name}` : ""}
                        </div>
                        {ev.command_line || ev.file_path || ev.domain || ev.url ? (
                          <div style={{ marginTop: 2, color: "var(--fg-muted)",
                                        fontFamily: "var(--mono)", fontSize: 10.5,
                                        overflowWrap: "anywhere" }}>
                            {(ev.command_line || ev.file_path || ev.domain || ev.url || "").slice(0, 160)}
                          </div>
                        ) : null}
                      </div>
                    ))}
                    {detail.evidence.length > 12 && (
                      <div style={{ fontSize: 11, color: "var(--fg-faint)" }}>
                        … {detail.evidence.length - 12} more
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}
