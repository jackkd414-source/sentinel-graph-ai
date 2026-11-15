import { useCallback, useEffect, useState } from "react";
import { api, type AuthMe, type Health, type Project } from "./api";
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
import { clearToken, setToken } from "./auth";
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
  const [authMe, setAuthMe] = useState<AuthMe | null>(null);
  const [accountOpen, setAccountOpen] = useState(false);

  const refresh = useCallback(() => setReloadKey((k) => k + 1), []);

  const loadShell = useCallback(async () => {
    // Ask about auth first: when the server demands a credential, probing the
    // rest of the API would only produce a 401 and a spurious error state.
    let me: AuthMe | null = null;
    try {
      me = await api.authMe();
      setAuthMe(me);
    } catch {
      setAuthMe(null);
    }
    try {
      const h = await api.health();
      setHealth(h);
      setBootError(null);
    } catch (e) {
      setBootError(e instanceof Error ? e.message : "Cannot reach the backend");
    }
    if (me?.auth_required && !me.authenticated) return;
    try {
      const p = await api.projects();
      setProject(p.projects[0] ?? null);
    } catch { /* workspace indicator is non-critical */ }
  }, []);

  useEffect(() => { void loadShell(); }, [loadShell, reloadKey]);

  useEffect(() => {
    // A 401 means the session died or never existed. Re-asking /api/auth/me
    // decides which, and drops the shell back to the login screen if needed.
    const onUnauth = () => void loadShell();
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
          <span className="mono">v{health?.version || "-"}</span>
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
          <button className="tw-avatar"
                  title={authMe?.username ? `Signed in as ${authMe.username}` : "Account"}
                  aria-label="Account" onClick={() => setAccountOpen(true)}>
            {initials(authMe?.username || project?.name)}
          </button>
        </>
      }
    />
  );

  // A server that demands a credential gets nothing but the login screen. No
  // shell, no navigation, no data: there is nothing to show until it answers.
  if (authMe?.auth_required && !authMe.authenticated) {
    return <LoginScreen onSignedIn={() => { void loadShell(); refresh(); }} />;
  }

  return (
    <AppShell sidebar={sidebar} topbar={topbar}>
      {toast ? (
        <div className="tw-toast-wrap">
          <Notification kind={toast.kind} message={toast.message} onClose={() => setToast(null)} />
        </div>
      ) : null}

      {authMe?.must_change_password ? (
        <div className="tw-banner tw-banner-warn">
          Password bawaan masih dipakai. Siapa pun yang bisa membuka alamat ini dapat
          masuk sebagai <span className="mono">admin</span>. Ganti lewat menu akun di
          kanan atas.
        </div>
      ) : null}

      {bootError ? (
        <div className="tw-content">
          <ErrorState message={bootError} onRetry={() => void loadShell()} />
        </div>
      ) : route === "dashboard" ? (
        <div className="tw-content">
          <Dashboard onOpenIncident={openIncident} onLoadDemo={loadDemo} demoBusy={demoBusy}
                     reloadKey={reloadKey} />
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

      {accountOpen ? (
        <AccountDialog
          me={authMe}
          onClose={() => setAccountOpen(false)}
          onSignOut={() => { setAccountOpen(false); clearToken(); void loadShell(); }}
          onPasswordChanged={() => { setAccountOpen(false); clearToken(); void loadShell(); }}
        />
      ) : null}
    </AppShell>
  );
}

/** Blocking login screen, shown whenever the server demands a credential. */
function LoginScreen({ onSignedIn }: { onSignedIn: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [useToken, setUseToken] = useState(false);
  const [tokenValue, setTokenValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = useToken ? tokenValue.trim().length > 0
    : username.trim().length > 0 && password.length > 0;

  const submit = async () => {
    if (busy || !canSubmit) return;
    setError(null);
    if (useToken) {
      setToken(tokenValue.trim());
      onSignedIn();
      return;
    }
    setBusy(true);
    try {
      const r = await api.login(username.trim(), password);
      setToken(r.token);
      onSignedIn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Login gagal.");
    } finally {
      setBusy(false);
    }
  };

  const onKey = (e: React.KeyboardEvent) => { if (e.key === "Enter") void submit(); };

  return (
    <div className="tw-backdrop">
      <div className="tw-dialog" role="dialog" aria-modal="true" aria-label="Masuk">
        <div className="tw-dialog-head">SentinelGraph AI</div>
        <div className="tw-dialog-body">
          <p className="faint" style={{ fontSize: "var(--tw-fs-secondary)", lineHeight: 1.6, marginBottom: 12 }}>
            Masuk untuk melanjutkan. Sesi disimpan di tab ini saja dan berakhir saat tab ditutup.
          </p>
          {useToken ? (
            <input className="tw-input" type="password" placeholder="Bearer token" autoFocus
                   value={tokenValue} onChange={(e) => setTokenValue(e.target.value)} onKeyDown={onKey} />
          ) : (
            <>
              <input className="tw-input" placeholder="Username" autoFocus value={username}
                     onChange={(e) => setUsername(e.target.value)} onKeyDown={onKey} />
              <input className="tw-input" type="password" placeholder="Password"
                     style={{ marginTop: 8 }} value={password}
                     onChange={(e) => setPassword(e.target.value)} onKeyDown={onKey} />
            </>
          )}
          {error ? (
            <div className="tw-banner tw-banner-err" style={{ marginTop: 10 }}>{error}</div>
          ) : null}
          <button className="tw-btn tw-btn-ghost" style={{ marginTop: 12 }}
                  onClick={() => { setUseToken(!useToken); setError(null); }}>
            {useToken ? "Pakai username dan password" : "Pakai bearer token"}
          </button>
        </div>
        <div className="tw-dialog-foot">
          <button className="tw-btn tw-btn-primary" disabled={busy || !canSubmit}
                  onClick={() => void submit()}>
            {busy ? "Memeriksa..." : "Masuk"}
          </button>
        </div>
      </div>
    </div>
  );
}

/** The single account: sign out, and change the password. */
function AccountDialog({ me, onClose, onSignOut, onPasswordChanged }: {
  me: AuthMe | null;
  onClose: () => void;
  onSignOut: () => void;
  onPasswordChanged: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const submit = async () => {
    if (busy || !current || next.length < 8) return;
    setBusy(true);
    setError(null);
    try {
      await api.changePassword(current, next);
      // The server ends every session on a password change, including this one,
      // so the stored credential is now dead. Show the confirmation briefly,
      // then drop to the login screen rather than leaving a broken session.
      setDone(true);
      clearToken();
      window.setTimeout(onPasswordChanged, 1200);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Gagal mengganti password.");
    } finally {
      setBusy(false);
    }
  };

  const signOut = async () => {
    try {
      await api.logout();
    } catch { /* the session may already be gone; clearing locally is enough */ }
    onSignOut();
  };

  return (
    <div className="tw-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="tw-dialog" role="dialog" aria-modal="true" aria-label="Akun">
        <div className="tw-dialog-head">Akun</div>
        <div className="tw-dialog-body">
          <div className="row" style={{ gap: 8, marginBottom: 12 }}>
            <span className={`tw-dot ${me?.authenticated ? "tw-dot-ok" : "tw-dot-warn"}`} />
            <span>
              {me?.authenticated
                ? <>Masuk sebagai <b>{me.username || "admin"}</b></>
                : "Belum login"}
            </span>
          </div>

          {me?.via === "shared_token" ? (
            <p className="faint" style={{ fontSize: "var(--tw-fs-meta)", marginBottom: 12 }}>
              Sesi ini memakai bearer token bersama, bukan login.
            </p>
          ) : null}

          {done ? (
            <div className="tw-banner tw-banner-ok">
              Password diganti. Semua sesi diakhiri, silakan login lagi.
            </div>
          ) : (
            <>
              {me?.must_change_password ? (
                <div className="tw-banner tw-banner-warn" style={{ marginBottom: 12 }}>
                  Password bawaan masih dipakai. Siapa pun yang bisa membuka alamat ini
                  dapat masuk sebagai <span className="mono">admin</span>.
                </div>
              ) : null}
              <input className="tw-input" type="password" placeholder="Password sekarang"
                     value={current} onChange={(e) => setCurrent(e.target.value)} />
              <input className="tw-input" type="password" placeholder="Password baru (minimal 8 karakter)"
                     style={{ marginTop: 8 }} value={next}
                     onChange={(e) => setNext(e.target.value)} />
              {error ? (
                <div className="tw-banner tw-banner-err" style={{ marginTop: 10 }}>{error}</div>
              ) : null}
            </>
          )}
        </div>
        <div className="tw-dialog-foot">
          {me?.authenticated ? (
            <button className="tw-btn" onClick={() => void signOut()}>Keluar</button>
          ) : null}
          <button className="tw-btn" onClick={onClose}>Tutup</button>
          {!done ? (
            <button className="tw-btn tw-btn-primary" disabled={busy || !current || next.length < 8}
                    onClick={() => void submit()}>
              {busy ? "Menyimpan..." : "Ganti password"}
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
