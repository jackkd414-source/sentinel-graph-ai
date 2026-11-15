import { useEffect, useState } from "react";
import { api, authFetch, type ProviderConfig, type ProviderTypeMeta, type TestResult } from "../api";
import { ErrorBanner, Loading } from "../components/ui";

export function ProvidersPage() {
  const [configs, setConfigs] = useState<ProviderConfig[]>([]);
  const [types, setTypes] = useState<Record<string, ProviderTypeMeta>>({});
  const [encOk, setEncOk] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [testing, setTesting] = useState<number | null>(null);
  const [results, setResults] = useState<Record<number, TestResult>>({});
  const [showForm, setShowForm] = useState(false);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.providers();
      setConfigs(r.configs);
      setTypes(r.types);
      setEncOk(r.encryption_available);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load providers");
    } finally { setLoading(false); }
  };

  useEffect(() => { void load(); }, []);

  const test = async (id: number) => {
    setTesting(id);
    try {
      const r = await api.testProvider(id);
      setResults((p) => ({ ...p, [id]: r }));
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Test failed");
    } finally { setTesting(null); }
  };

  const activate = async (id: number, active: boolean) => {
    try {
      await api.activateProvider(id, active);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Activation failed");
    }
  };

  const remove = async (id: number) => {
    if (!window.confirm("Delete this provider configuration? The stored credential is deleted too.")) return;
    try {
      await api.deleteProvider(id);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed");
    }
  };

  if (loading) return <Loading />;

  return (
    <div className="col" style={{ gap: 14 }}>
      {error ? <ErrorBanner message={error} onRetry={load} /> : null}
      {notice ? <div className="banner banner-ok">{notice}</div> : null}

      {!encOk ? (
        <div className="banner banner-warn">
          <span>
            <strong>Secure credential storage is not configured (SG_MASTER_KEY unset).</strong>{" "}
            API keys cannot be saved to the database. Either generate a master key
            (<span className="mono">python -m sentinelgraph keys</span>) and add it to{" "}
            <span className="mono">.env</span>, or provide credentials via environment
            variables. SentinelGraph will never store a key in plaintext.
          </span>
        </div>
      ) : null}

      <div className="row">
        <span className="dim" style={{ fontSize: 12.5, flex: 1 }}>
          Provider configuration is stored server-side. Keys are encrypted at rest and never
          returned to the browser — only a masked hint is shown.
        </span>
        <button className="btn btn-primary btn-sm" onClick={() => setShowForm(!showForm)}>
          {showForm ? "Cancel" : "+ Add provider"}
        </button>
      </div>

      {showForm ? (
        <ProviderForm
          types={types}
          encOk={encOk}
          onDone={(msg) => {
            setShowForm(false);
            setNotice(msg);
            void load();
          }}
          onError={setError}
        />
      ) : null}

      {configs.length === 0 ? (
        <div className="panel" style={{ padding: 28, textAlign: "center" }}>
          <div style={{ fontSize: 13.5, color: "var(--fg-dim)", marginBottom: 6 }}>
            No AI provider configured
          </div>
          <div className="dim" style={{ fontSize: 12.5, maxWidth: 520, margin: "0 auto" }}>
            SentinelGraph runs fully without AI: detection, correlation, attack graph,
            timeline and reports are all available. Configure a provider to add
            model-assisted interpretation.
          </div>
        </div>
      ) : (
        <div className="col" style={{ gap: 11 }}>
          {configs.map((c) => {
            const r = results[c.id];
            return (
              <div key={c.id} className="panel">
                <div className="panel-head">
                  <span className="panel-title">{c.name}</span>
                  <span className="chip chip-info">{c.provider_type}</span>
                  {c.is_active ? <span className="chip chip-observed">active</span> : null}
                  <span className="spacer" />
                  {!c.is_active ? (
                    <button className="btn btn-sm" onClick={() => void activate(c.id, true)}>
                      Set active
                    </button>
                  ) : (
                    <button className="btn btn-sm" onClick={() => void activate(c.id, false)}>
                      Deactivate
                    </button>
                  )}
                  <button className="btn btn-sm btn-primary" disabled={testing === c.id}
                          onClick={() => void test(c.id)}>
                    {testing === c.id ? "Testing…" : "Test connection"}
                  </button>
                  <button className="btn btn-sm btn-danger" onClick={() => void remove(c.id)}>
                    Delete
                  </button>
                </div>
                <div className="panel-body" style={{ fontSize: 12.5 }}>
                  <div className="grid grid-3" style={{ gap: 10 }}>
                    <Field label="Model" value={c.model_id} mono />
                    <Field label="Base URL" value={c.base_url || "(provider default)"} mono />
                    <Field label="Credential" value={
                      c.credential_configured
                        ? `${c.credential_hint} (${c.secret_source})`
                        : "not configured"
                    } mono />
                    <Field label="Timeout" value={`${c.timeout_s}s`} />
                    <Field label="Max output" value={c.max_output_tokens ? `${c.max_output_tokens} tokens` : "provider default"} />
                    <Field label="Last test" value={
                      c.last_test_status
                        ? `${c.last_test_status}${c.last_test_latency_ms ? ` · ${c.last_test_latency_ms}ms` : ""}`
                        : "never tested"
                    } />
                  </div>
                  {c.last_test_error ? (
                    <div className="mono" style={{ fontSize: 10.5, color: "var(--high)",
                                                   marginTop: 8 }}>
                      last error: {c.last_test_error}
                    </div>
                  ) : null}
                  {r ? (
                    <div className={`banner ${r.ok ? "banner-ok" : "banner-err"}`}
                         style={{ marginTop: 10, marginBottom: 0 }}>
                      <span>
                        <strong>{r.ok ? "Connection OK" : "Connection failed"}</strong>
                        {" — "}{r.provider}/{r.model} · {r.latency_ms}ms
                        {r.error_category ? ` · ${r.error_category}` : ""}
                        {r.error_message ? `: ${r.error_message}` : ""}
                        {r.ok && r.sample_reply ? ` · reply: "${r.sample_reply}"` : ""}
                      </span>
                    </div>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="mono" style={{ fontSize: 10, letterSpacing: 0.7, color: "var(--fg-muted)",
                                     textTransform: "uppercase", marginBottom: 2 }}>
        {label}
      </div>
      <div className={mono ? "mono" : ""} style={{ fontSize: 11.5, color: "var(--fg-dim)",
                                                   wordBreak: "break-all" }}>
        {value}
      </div>
    </div>
  );
}

const PRESETS: Record<string, { model: string; fast: string }> = {
  openai: { model: "gpt-4o-mini", fast: "" },
  anthropic: { model: "claude-3-5-haiku-latest", fast: "" },
  gemini: { model: "gemini-2.0-flash", fast: "" },
  openrouter: { model: "", fast: "" },
  ollama: { model: "llama3.1", fast: "" },
  custom_openai: { model: "", fast: "" },
};

function ProviderForm({ types, encOk, onDone, onError }: {
  types: Record<string, ProviderTypeMeta>;
  encOk: boolean;
  onDone: (msg: string) => void;
  onError: (msg: string) => void;
}) {
  const [type, setType] = useState("openai");
  const [name, setName] = useState("Primary provider");
  const [model, setModel] = useState(PRESETS.openai.model);
  const [fastModel, setFastModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [timeout, setTimeoutS] = useState(60);
  const [maxTokens, setMaxTokens] = useState(2048);
  const [active, setActive] = useState(true);
  const [busy, setBusy] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [models, setModels] = useState<string[] | null>(null);

  const meta = types[type];
  const needsKey = meta?.needs_key ?? true;

  const onTypeChange = (t: string) => {
    setType(t);
    setModel(PRESETS[t]?.model || "");
    setBaseUrl("");
    setModels(null);
    setTestResult(null);
  };

  const doTest = async () => {
    setBusy(true); setTestResult(null);
    try {
      const res = await authFetch("/api/ai/test-unsaved", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider_type: type, model_id: model, api_key: apiKey || undefined,
          base_url: baseUrl || undefined, timeout_s: timeout,
        }),
      });
      const body = (await res.json()) as TestResult;
      setTestResult(body);
    } catch (e) {
      onError(e instanceof Error ? e.message : "Test failed");
    } finally { setBusy(false); }
  };

  const save = async () => {
    setBusy(true);
    try {
      await api.createProvider({
        name, provider_type: type, model_id: model,
        fast_model_id: fastModel || null,
        base_url: baseUrl || null,
        api_key: apiKey || null,
        timeout_s: timeout, max_output_tokens: maxTokens,
        is_active: active,
      });
      onDone(`Provider "${name}" saved.` +
             (active ? " It is now the active provider." : ""));
    } catch (e) {
      onError(e instanceof Error ? e.message : "Save failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="panel">
      <div className="panel-head"><span className="panel-title">New provider configuration</span></div>
      <div className="panel-body">
        <div className="grid grid-2">
          <div>
            <div className="field">
              <label className="label">Provider type</label>
              <select className="select" value={type} onChange={(e) => onTypeChange(e.target.value)}>
                {Object.entries(types).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label className="label">Configuration name</label>
              <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="field">
              <label className="label">Model ID</label>
              <input className="input" value={model} onChange={(e) => setModel(e.target.value)}
                     placeholder="e.g. gpt-4o-mini" />
              <div className="hint">
                Model IDs are entered manually because provider catalogues change.
                Nothing is hardcoded to a model that may not exist on your account.
              </div>
            </div>
            <div className="field">
              <label className="label">Fast model ID (optional)</label>
              <input className="input" value={fastModel}
                     onChange={(e) => setFastModel(e.target.value)}
                     placeholder="cheaper model for light tasks" />
            </div>
          </div>

          <div>
            <div className="field">
              <label className="label">Base URL</label>
              <input className="input" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
                     placeholder={meta?.base_url || "provider default"} />
              <div className="hint">
                Leave empty to use the documented default: <span className="mono">{meta?.base_url}</span>
              </div>
            </div>
            <div className="field">
              <label className="label">
                API key {needsKey ? "" : "(not required)"}
              </label>
              <input className="input" type="password" value={apiKey}
                     onChange={(e) => setApiKey(e.target.value)}
                     placeholder={needsKey ? "sk-…" : "not required for this provider"}
                     disabled={!needsKey} />
              <div className="hint">
                {encOk
                  ? "Encrypted with AES before being stored. Only a masked hint is ever shown."
                  : "Storage disabled: no master key configured. Use an environment variable instead."}
              </div>
            </div>
            <div className="row" style={{ gap: 10 }}>
              <div className="field" style={{ flex: 1 }}>
                <label className="label">Timeout (s)</label>
                <input className="input" type="number" value={timeout}
                       onChange={(e) => setTimeoutS(Number(e.target.value))} />
              </div>
              <div className="field" style={{ flex: 1 }}>
                <label className="label">Max output tokens</label>
                <input className="input" type="number" value={maxTokens}
                       onChange={(e) => setMaxTokens(Number(e.target.value))} />
              </div>
            </div>
            <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12.5,
                            marginBottom: 10 }}>
              <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} />
              Make this the active provider
            </label>
          </div>
        </div>

        {testResult ? (
          <div className={`banner ${testResult.ok ? "banner-ok" : "banner-err"}`}>
            <span>
              <strong>{testResult.ok ? "Connection OK" : "Connection failed"}</strong>
              {" — "}{testResult.provider}/{testResult.model} · {testResult.latency_ms}ms
              {testResult.error_category ? ` · ${testResult.error_category}` : ""}
              {testResult.error_message ? `: ${testResult.error_message}` : ""}
            </span>
          </div>
        ) : null}

        {models && models.length > 0 ? (
          <div className="field">
            <label className="label">Discovered models (click to use)</label>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5, maxHeight: 120, overflow: "auto" }}>
              {models.map((m) => (
                <button key={m} className="chip chip-info" style={{ cursor: "pointer" }}
                        onClick={() => setModel(m)}>{m}</button>
              ))}
            </div>
          </div>
        ) : null}

        <div className="row" style={{ marginTop: 4 }}>
          <button className="btn btn-sm" onClick={() => void doTest()} disabled={busy || !model}>
            Test before saving
          </button>
          <span className="faint" style={{ fontSize: 11 }}>
            Model listing becomes available after saving.
          </span>
          <span className="spacer" />
          <button className="btn btn-primary" onClick={() => void save()} disabled={busy || !model || !name}>
            {busy ? "Saving…" : "Save provider"}
          </button>
        </div>
      </div>
    </div>
  );
}
