// TRACEWORK ProviderCard, one AI provider configuration, presented as system
// configuration (not a chat surface). Credentials are always masked.

import type { ProviderConfig, TestResult } from "../api";
import { fmtTime } from "./ui";

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="tw-section-title" style={{ marginBottom: 2 }}>{label}</div>
      <div className={mono ? "mono" : ""} style={{ fontSize: "var(--tw-fs-secondary)", wordBreak: "break-all" }}>
        {value}
      </div>
    </div>
  );
}

export function ProviderCard({
  config, result, testing, onTest, onActivate, onDelete, onEdit,
}: {
  config: ProviderConfig;
  result?: TestResult;
  testing: boolean;
  onTest: () => void;
  onActivate: () => void;
  onDelete: () => void;
  onEdit: () => void;
}) {
  const ok = config.last_test_status === "ok";
  return (
    <div className="tw-panel">
      <div className="tw-panel-head">
        <span className="tw-panel-title">{config.name}</span>
        <span className="tw-chip tw-chip-plain">{config.provider_type}</span>
        {config.is_active ? <span className="tw-chip tw-status tw-status-observed">active</span> : null}
        <span className="spacer" />
        <button className="tw-btn tw-btn-sm" onClick={onEdit}>Edit</button>
        <button className="tw-btn tw-btn-sm" onClick={onActivate}>
          {config.is_active ? "Deactivate" : "Set active"}
        </button>
        <button className="tw-btn tw-btn-sm tw-btn-primary" disabled={testing} onClick={onTest}>
          {testing ? "Testing…" : "Test connection"}
        </button>
        <button className="tw-btn tw-btn-sm tw-btn-danger" onClick={onDelete}>Delete</button>
      </div>
      <div className="tw-panel-body">
        <div className="tw-provider-grid">
          <Field label="Endpoint" value={config.base_url || "(provider default)"} mono />
          <Field label="Model ID" value={config.model_id} mono />
          <Field label="Fast model" value={config.fast_model_id || "-"} mono />
          <Field label="Credential" mono
                 value={config.credential_configured
                   ? `${config.credential_hint} (${config.secret_source})`
                   : "not configured"} />
          <Field label="Timeout" value={`${config.timeout_s}s`} />
          <Field label="Max output" value={config.max_output_tokens ? `${config.max_output_tokens} tokens` : "provider default"} />
          <Field label="Connection" value={config.last_test_status || "never tested"} />
          <Field label="Last tested" value={config.last_test_at ? fmtTime(config.last_test_at) : "never"} />
          <Field label="Latency" value={config.last_test_latency_ms != null ? `${config.last_test_latency_ms} ms` : "-"} />
        </div>

        {config.last_test_error ? (
          <div className="mono" style={{ marginTop: 10, color: "var(--tw-high)" }}>last error: {config.last_test_error}</div>
        ) : null}

        {result ? (
          <div className={`tw-banner ${result.ok ? "tw-banner-ok" : "tw-banner-err"}`} style={{ marginTop: 12 }}>
            <span>
              <strong>{result.ok ? "Connection OK" : "Connection failed"}</strong>
              {", "}{result.provider}/{result.model} · {result.latency_ms}ms
              {result.error_category ? ` · ${result.error_category}` : ""}
              {result.error_message ? `: ${result.error_message}` : ""}
              {result.ok && result.sample_reply ? ` · reply: “${result.sample_reply}”` : ""}
            </span>
          </div>
        ) : null}

        {!result && config.last_test_status ? (
          <div className="row" style={{ marginTop: 12, gap: 7 }}>
            <span className={`tw-dot ${ok ? "tw-dot-ok" : "tw-dot-warn"}`} />
            <span className="faint" style={{ fontSize: "var(--tw-fs-meta)" }}>
              {ok ? "Last connection test succeeded." : "Last connection test did not succeed."}
            </span>
          </div>
        ) : null}
      </div>
    </div>
  );
}
