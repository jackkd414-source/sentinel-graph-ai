import { useCallback, useEffect, useState } from "react";
import { api, authFetch, type ProviderConfig, type ProviderTypeMeta, type TestResult } from "../api";
import { PageHeader } from "../components/layout";
import { ProviderCard } from "../components/ProviderCard";
import { ConfirmDialog, EmptyState, ErrorState, FormField, LoadingState } from "../components/ui";

const PRESETS: Record<string, string> = {
  openai: "gpt-4o-mini",
  anthropic: "claude-3-5-haiku-latest",
  gemini: "gemini-2.0-flash",
  openrouter: "",
  ollama: "llama3.1",
  custom_openai: "",
};

export function ProvidersPage() {
  const [configs, setConfigs] = useState<ProviderConfig[]>([]);
  const [types, setTypes] = useState<Record<string, ProviderTypeMeta>>({});
  const [encOk, setEncOk] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [testing, setTesting] = useState<number | null>(null);
  const [results, setResults] = useState<Record<number, TestResult>>({});
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<ProviderConfig | null>(null);
  const [confirmDel, setConfirmDel] = useState<ProviderConfig | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.providers();
      setConfigs(r.configs);
      setTypes(r.types);
      setEncOk(r.encryption_available);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load providers");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

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
    try { await api.activateProvider(id, active); await load(); }
    catch (e) { setError(e instanceof Error ? e.message : "Activation failed"); }
  };

  const remove = async (id: number) => {
    try { await api.deleteProvider(id); await load(); }
    catch (e) { setError(e instanceof Error ? e.message : "Delete failed"); }
  };

  if (loading) return <LoadingState label="Loading providers…" />;

  return (
    <>
      <PageHeader
        title="AI Providers"
        subtitle="Provider configuration is stored server-side. Keys are encrypted at rest and never returned to the browser."
        actions={
          <button className="tw-btn tw-btn-sm tw-btn-primary"
                  onClick={() => { setEditing(null); setFormOpen(!formOpen); }}>
            {formOpen && !editing ? "Cancel" : "+ Add provider"}
          </button>
        }
      />

      {error ? <div style={{ marginBottom: 16 }}><ErrorState message={error} onRetry={load} /></div> : null}
      {notice ? <div className="tw-banner tw-banner-ok" style={{ marginBottom: 16 }}><span>{notice}</span></div> : null}

      {!encOk ? (
        <div className="tw-banner tw-banner-warn" style={{ marginBottom: 16 }}>
          <span>
            <strong>Secure credential storage is not configured (SG_MASTER_KEY unset).</strong> API keys
            cannot be saved to the database. Generate a master key (<span className="mono">python -m sentinelgraph keys</span>)
            and add it to <span className="mono">.env</span>, or provide credentials via environment variables.
            SentinelGraph will never store a key in plaintext.
          </span>
        </div>
      ) : null}

      {formOpen ? (
        <ProviderForm
          types={types} encOk={encOk} initial={editing}
          onCancel={() => { setFormOpen(false); setEditing(null); }}
          onDone={(msg) => { setFormOpen(false); setEditing(null); setNotice(msg); void load(); }}
          onError={setError}
        />
      ) : null}

      {configs.length === 0 ? (
        <div className="tw-panel">
          <EmptyState title="No AI provider configured"
            detail="SentinelGraph runs fully without AI: detection, correlation, attack graph, timeline and reports are all available. Configure a provider to add model-assisted interpretation." />
        </div>
      ) : (
        <div className="col" style={{ gap: 16 }}>
          {configs.map((c) => (
            <ProviderCard
              key={c.id}
              config={c}
              result={results[c.id]}
              testing={testing === c.id}
              onTest={() => void test(c.id)}
              onActivate={() => void activate(c.id, !c.is_active)}
              onDelete={() => setConfirmDel(c)}
              onEdit={() => { setEditing(c); setFormOpen(true); }}
            />
          ))}
        </div>
      )}

      <ConfirmDialog
        open={!!confirmDel}
        title={`Delete “${confirmDel?.name}”?`}
        body="This removes the provider configuration and the stored credential. It cannot be undone."
        confirmLabel="Delete provider"
        danger
        onCancel={() => setConfirmDel(null)}
        onConfirm={() => { const c = confirmDel; setConfirmDel(null); if (c) void remove(c.id); }}
      />
    </>
  );
}

function ProviderForm({
  types, encOk, initial, onDone, onError, onCancel,
}: {
  types: Record<string, ProviderTypeMeta>;
  encOk: boolean;
  initial: ProviderConfig | null;
  onDone: (msg: string) => void;
  onError: (msg: string) => void;
  onCancel: () => void;
}) {
  const [type, setType] = useState(initial?.provider_type || "openai");
  const [name, setName] = useState(initial?.name || "Primary provider");
  const [model, setModel] = useState(initial?.model_id || PRESETS.openai);
  const [fastModel, setFastModel] = useState(initial?.fast_model_id || "");
  const [baseUrl, setBaseUrl] = useState(initial?.base_url || "");
  const [apiKey, setApiKey] = useState("");
  const [timeout, setTimeoutS] = useState(initial?.timeout_s ?? 60);
  const [maxTokens, setMaxTokens] = useState(initial?.max_output_tokens ?? 2048);
  const [active, setActive] = useState(initial ? initial.is_active === 1 : true);
  const [busy, setBusy] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);

  const meta = types[type];
  const needsKey = meta?.needs_key ?? true;

  const onTypeChange = (t: string) => {
    setType(t); setModel(PRESETS[t] || ""); setBaseUrl(""); setTestResult(null);
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
      setTestResult((await res.json()) as TestResult);
    } catch (e) {
      onError(e instanceof Error ? e.message : "Test failed");
    } finally { setBusy(false); }
  };

  const save = async () => {
    setBusy(true);
    try {
      const body: Record<string, unknown> = {
        name, provider_type: type, model_id: model,
        fast_model_id: fastModel || null, base_url: baseUrl || null,
        timeout_s: timeout, max_output_tokens: maxTokens, is_active: active,
      };
      if (apiKey) body.api_key = apiKey;
      if (initial) {
        await api.updateProvider(initial.id, body);
        onDone(`Provider “${name}” updated.`);
      } else {
        await api.createProvider(body);
        onDone(`Provider “${name}” saved.` + (active ? " It is now the active provider." : ""));
      }
    } catch (e) {
      onError(e instanceof Error ? e.message : "Save failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="tw-panel" style={{ marginBottom: 16 }}>
      <div className="tw-panel-head">
        <span className="tw-panel-title">{initial ? `Edit “${initial.name}”` : "New provider configuration"}</span>
        <span className="spacer" />
        <button className="tw-btn tw-btn-sm tw-btn-ghost" onClick={onCancel}>Cancel</button>
      </div>
      <div className="tw-panel-body">
        <div className="tw-grid tw-grid-2">
          <div>
            <FormField label="Provider type">
              <select className="tw-select" value={type} onChange={(e) => onTypeChange(e.target.value)}
                      disabled={!!initial}>
                {Object.entries(types).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>
            </FormField>
            <FormField label="Configuration name">
              <input className="tw-input" value={name} onChange={(e) => setName(e.target.value)} />
            </FormField>
            <FormField label="Model ID"
              hint="Model IDs are entered manually because provider catalogues change. Nothing is hardcoded to a model that may not exist on your account.">
              <input className="tw-input" value={model} onChange={(e) => setModel(e.target.value)} placeholder="e.g. gpt-4o-mini" />
            </FormField>
            <FormField label="Fast model ID (optional)">
              <input className="tw-input" value={fastModel} onChange={(e) => setFastModel(e.target.value)}
                     placeholder="cheaper model for light tasks" />
            </FormField>
          </div>
          <div>
            <FormField label="Base URL" hint={<>Leave empty to use the documented default: <span className="mono">{meta?.base_url}</span></>}>
              <input className="tw-input" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
                     placeholder={meta?.base_url || "provider default"} />
            </FormField>
            <FormField label={`API key${needsKey ? "" : " (not required)"}`}
              hint={encOk
                ? "Encrypted with AES before being stored. Only a masked hint is ever shown."
                : "Storage disabled: no master key configured. Use an environment variable instead."}
              hintWarn={!encOk}>
              <input className="tw-input" type="password" value={apiKey}
                     onChange={(e) => setApiKey(e.target.value)}
                     placeholder={initial ? "leave blank to keep the current key" : needsKey ? "sk-…" : "not required for this provider"}
                     disabled={!needsKey} />
            </FormField>
            <div className="row" style={{ gap: 12 }}>
              <FormField label="Timeout (s)">
                <input className="tw-input" type="number" value={timeout}
                       onChange={(e) => setTimeoutS(Number(e.target.value))} />
              </FormField>
              <FormField label="Max output tokens">
                <input className="tw-input" type="number" value={maxTokens}
                       onChange={(e) => setMaxTokens(Number(e.target.value))} />
              </FormField>
            </div>
            <label className="tw-check" style={{ marginBottom: 12 }}>
              <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} />
              Make this the active provider
            </label>
          </div>
        </div>

        {testResult ? (
          <div className={`tw-banner ${testResult.ok ? "tw-banner-ok" : "tw-banner-err"}`}>
            <span>
              <strong>{testResult.ok ? "Connection OK" : "Connection failed"}</strong>
              {" — "}{testResult.provider}/{testResult.model} · {testResult.latency_ms}ms
              {testResult.error_category ? ` · ${testResult.error_category}` : ""}
              {testResult.error_message ? `: ${testResult.error_message}` : ""}
            </span>
          </div>
        ) : null}

        <div className="row" style={{ marginTop: 8 }}>
          <button className="tw-btn tw-btn-sm" onClick={() => void doTest()} disabled={busy || !model}>
            Test before saving
          </button>
          <span className="spacer" />
          <button className="tw-btn tw-btn-primary" onClick={() => void save()} disabled={busy || !model || !name}>
            {busy ? "Saving…" : initial ? "Save changes" : "Save provider"}
          </button>
        </div>
      </div>
    </div>
  );
}
