import { useState } from "react";
import { api, type IngestResult } from "../api";
import { PageHeader } from "../components/layout";
import { PanelHeader } from "../components/data";
import { ErrorState, FormField, LoadingState } from "../components/ui";

const SAMPLE = `[
  {
    "timestamp": "2026-11-03T08:12:00Z",
    "source": "windows_security",
    "event_type": "logon_failed",
    "EventID": 4625,
    "host": "SRV-FILE-02",
    "user_name": "svc_backup",
    "src_ip": "10.20.4.51"
  }
]`;

export function ImportPage({ onImported }: { onImported: () => void }) {
  const [text, setText] = useState("");
  const [filename, setFilename] = useState("pasted.json");
  const [sourceType, setSourceType] = useState("generic");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<Record<string, unknown> | null>(null);
  const [result, setResult] = useState<IngestResult | null>(null);

  const run = async (previewOnly: boolean) => {
    setBusy(true); setError(null);
    if (!previewOnly) setPreview(null);
    try {
      const r = await api.ingestText({ text, filename, source_type: sourceType, preview_only: previewOnly });
      if (previewOnly) { setPreview(r as unknown as Record<string, unknown>); setResult(null); }
      else {
        setResult(r);
        setPreview(null);
        onImported();
        await api.reanalyze();
        onImported();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
    } finally { setBusy(false); }
  };

  const pickFile = async (f: File | null) => {
    if (!f) return;
    if (f.size > 20_000_000) {
      setError("File is larger than the 20 MB text-import limit. Use the API upload endpoint for larger artifacts.");
      return;
    }
    setText(await f.text());
    setFilename(f.name);
  };

  return (
    <>
      <PageHeader title="Imports" subtitle="Paste or drop JSON, JSONL/NDJSON, CSV, or simple text logs." />

      {error ? <div style={{ marginBottom: 16 }}><ErrorState message={error} /></div> : null}

      <div className="tw-banner tw-banner-info" style={{ marginBottom: 16 }}>
        <span>
          Files are parsed in memory and stored as normalized events; the source record is preserved
          verbatim. Unparseable records are counted and reported, not silently dropped.
        </span>
      </div>

      <div className="tw-panel">
        <PanelHeader title="Paste or drop data" />
        <div className="tw-panel-body">
          <div className="row wrap" style={{ marginBottom: 12, alignItems: "flex-end" }}>
            <FormField label="Filename">
              <input className="tw-input" style={{ width: 220 }} value={filename}
                     onChange={(e) => setFilename(e.target.value)} placeholder="filename.json" />
            </FormField>
            <FormField label="Source type">
              <select className="tw-select" style={{ width: 190 }} value={sourceType}
                      onChange={(e) => setSourceType(e.target.value)}>
                <option value="generic">Auto-detect source</option>
                <option value="windows_security">Windows Security</option>
                <option value="firewall">Firewall</option>
                <option value="dns">DNS</option>
                <option value="proxy">Proxy</option>
                <option value="email_gateway">Email gateway</option>
                <option value="edr">EDR</option>
              </select>
            </FormField>
            <label className="tw-btn tw-btn-sm" style={{ cursor: "pointer" }}>
              Choose file
              <input type="file" accept=".json,.jsonl,.ndjson,.csv,.log,.txt" style={{ display: "none" }}
                     onChange={(e) => void pickFile(e.target.files?.[0] ?? null)} />
            </label>
            <button className="tw-btn tw-btn-sm" onClick={() => { setText(SAMPLE); setFilename("sample.json"); }}>
              Insert sample
            </button>
          </div>

          <textarea className="tw-textarea" rows={12} value={text} style={{ width: "100%" }}
                    onChange={(e) => setText(e.target.value)}
                    placeholder="Paste a JSON array, JSONL lines, or CSV here…" />

          <div className="row" style={{ marginTop: 12 }}>
            <button className="tw-btn tw-btn-sm" disabled={busy || !text.trim()} onClick={() => void run(true)}>
              {busy ? "Working…" : "Preview"}
            </button>
            <button className="tw-btn tw-btn-sm tw-btn-primary" disabled={busy || !text.trim()} onClick={() => void run(false)}>
              Import &amp; analyze
            </button>
            <span className="spacer" />
            <span className="faint mono">{text.length.toLocaleString()} chars</span>
          </div>
        </div>
      </div>

      {busy && !preview && !result ? <div style={{ marginTop: 16 }}><LoadingState label="Parsing…" /></div> : null}

      {preview ? (
        <div className="tw-panel" style={{ marginTop: 16 }}>
          <PanelHeader title="Preview (not saved)"
            sub={`${String(preview.records_ok)} ok · ${String(preview.records_failed)} rejected · format ${String(preview.format)}`} />
          <div className="tw-panel-body">
            <pre className="tw-raw">{JSON.stringify(preview.sample_events, null, 2)}</pre>
            {Array.isArray(preview.failures) && (preview.failures as unknown[]).length > 0 ? (
              <div style={{ marginTop: 12 }}>
                <div className="tw-section-title">Rejected records</div>
                <pre className="tw-code">{JSON.stringify(preview.failures, null, 2)}</pre>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      {result ? (
        <div className="tw-panel" style={{ marginTop: 16 }}>
          <PanelHeader title="Import result" />
          <div className="tw-panel-body">
            <div className="tw-grid tw-grid-4" style={{ gap: 14 }}>
              <KV label="Records read" value={String(result.records_total)} />
              <KV label="Accepted" value={String(result.records_ok)} />
              <KV label="Rejected" value={String(result.records_failed)} />
              <KV label="Inserted" value={String(result.events_inserted)} />
              <KV label="Duplicates skipped" value={String(result.events_duplicated)} />
              <KV label="Parse status" value={String(result.parse_status)} />
              <KV label="Format" value={String(result.format)} />
              <KV label="Artifact" value={`#${String(result.artifact_id)}`} />
            </div>

            {result.analysis ? (
              <div style={{ marginTop: 16, paddingTop: 14, borderTop: "1px solid var(--tw-border)" }}>
                <div className="tw-section-title">Analysis</div>
                <div className="tw-grid tw-grid-4" style={{ gap: 14 }}>
                  <KV label="Events analysed" value={String(result.analysis.events_analyzed)} />
                  <KV label="Alerts created" value={String(result.analysis.alerts_created)} />
                  <KV label="Incidents" value={String(result.analysis.incidents_created)} />
                  <KV label="Graph" value={`${result.analysis.graph?.nodes ?? 0} / ${result.analysis.graph?.edges ?? 0}`} />
                </div>
                {(result.analysis.engine_errors ?? []).length > 0 ? (
                  <div className="tw-banner tw-banner-warn" style={{ marginTop: 12 }}>
                    <span>{result.analysis.engine_errors.length} rule(s) failed during analysis — results may be incomplete.</span>
                  </div>
                ) : null}
                {result.analysis.alerts_created === 0 ? (
                  <div className="tw-banner tw-banner-info" style={{ marginTop: 12 }}>
                    <span>
                      No detection rules fired on this data. That is a finding, not an error: the rule
                      engine ran over {result.analysis.events_analyzed} events and found no pattern
                      matching R-001..R-006. Check the Events page to confirm the fields the rules need
                      (user, process, dst_ip) were parsed.
                    </span>
                  </div>
                ) : null}
              </div>
            ) : null}

            {Array.isArray(result.failures) && (result.failures as unknown[]).length > 0 ? (
              <pre className="tw-code" style={{ marginTop: 14, color: "var(--tw-high)" }}>
                {JSON.stringify(result.failures, null, 2)}
              </pre>
            ) : null}
          </div>
        </div>
      ) : null}
    </>
  );
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="tw-section-title" style={{ marginBottom: 2 }}>{label}</div>
      <div className="mono" style={{ fontSize: "var(--tw-fs-body)" }}>{value}</div>
    </div>
  );
}
