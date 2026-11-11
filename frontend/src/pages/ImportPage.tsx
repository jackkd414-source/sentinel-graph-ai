import { useState } from "react";
import { api, type IngestResult } from "../api";
import { ErrorBanner } from "../components/ui";

interface Props { onImported: () => void }

const SAMPLE = `[
  {
    "timestamp": "2026-11-03T08:12:00Z",
    "source": "windows_security",
    "event_type": "logon_failed",
    "EventID": 4625,
    "host": "SRV-FILE-02",
    "user_name": "svc_backup",
    "src_ip": "10.20.4.51"
  },
  {
    "timestamp": "2026-11-03T08:13:00Z",
    "source": "windows_security",
    "event_type": "logon_failed",
    "EventID": 4625,
    "host": "SRV-FILE-02",
    "user_name": "svc_backup",
    "src_ip": "10.20.4.51"
  }
]`;

export function ImportPage({ onImported }: Props) {
  const [text, setText] = useState("");
  const [filename, setFilename] = useState("pasted.json");
  const [sourceType, setSourceType] = useState("generic");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<Record<string, unknown> | null>(null);
  const [result, setResult] = useState<IngestResult | null>(null);

  const run = async (previewOnly: boolean) => {
    setBusy(true); setError(null);
    if (!previewOnly) { setPreview(null); }
    try {
      const r = await api.ingestText({
        text, filename, source_type: sourceType, preview_only: previewOnly,
      });
      if (previewOnly) { setPreview(r as unknown as Record<string, unknown>); setResult(null); }
      else {
        setResult(r);
        setPreview(null);
        onImported();
        // run analysis so the new events produce alerts immediately
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
    const content = await f.text();
    setText(content);
    setFilename(f.name);
  };

  return (
    <div className="col" style={{ gap: 14 }}>
      {error ? <ErrorBanner message={error} /> : null}

      <div className="banner banner-info">
        <span>
          Supported here: JSON, JSONL/NDJSON, CSV, and simple text logs. Files are parsed in
          memory and stored as normalized events; the source record is preserved verbatim.
          Unparseable records are counted and reported, not silently dropped.
        </span>
      </div>

      <div className="panel">
        <div className="panel-head"><span className="panel-title">Paste or drop data</span></div>
        <div className="panel-body">
          <div className="row" style={{ marginBottom: 10, flexWrap: "wrap" }}>
            <input className="input" style={{ width: 220 }} value={filename}
                   onChange={(e) => setFilename(e.target.value)}
                   placeholder="filename.json" />
            <select className="select" style={{ width: 180 }} value={sourceType}
                    onChange={(e) => setSourceType(e.target.value)}>
              <option value="generic">Auto-detect source</option>
              <option value="windows_security">Windows Security</option>
              <option value="firewall">Firewall</option>
              <option value="dns">DNS</option>
              <option value="proxy">Proxy</option>
              <option value="email_gateway">Email gateway</option>
              <option value="edr">EDR</option>
            </select>
            <label className="btn btn-sm" style={{ cursor: "pointer" }}>
              Choose file
              <input type="file" accept=".json,.jsonl,.ndjson,.csv,.log,.txt"
                     style={{ display: "none" }}
                     onChange={(e) => void pickFile(e.target.files?.[0] ?? null)} />
            </label>
            <button className="btn btn-sm" onClick={() => { setText(SAMPLE); setFilename("sample.json"); }}>
              Insert sample
            </button>
          </div>

          <textarea className="textarea" rows={12} value={text}
                    onChange={(e) => setText(e.target.value)}
                    placeholder="Paste JSON array, JSONL lines, or CSV here…"
                    style={{ width: "100%" }} />

          <div className="row" style={{ marginTop: 10 }}>
            <button className="btn btn-sm" disabled={busy || !text.trim()}
                    onClick={() => void run(true)}>
              {busy ? "Working…" : "Preview"}
            </button>
            <button className="btn btn-primary btn-sm" disabled={busy || !text.trim()}
                    onClick={() => void run(false)}>
              Import &amp; analyze
            </button>
            <span className="spacer" />
            <span className="faint mono" style={{ fontSize: 10.5 }}>
              {text.length.toLocaleString()} chars
            </span>
          </div>
        </div>
      </div>

      {preview ? (
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">Preview (not saved)</span>
            <span className="spacer" />
            <span className="mono faint" style={{ fontSize: 10.5 }}>
              {String(preview.records_ok)} ok · {String(preview.records_failed)} rejected ·
              format {String(preview.format)}
            </span>
          </div>
          <div className="panel-body">
            <pre className="mono" style={{
              margin: 0, fontSize: 10.5, whiteSpace: "pre-wrap", color: "var(--fg-dim)",
              maxHeight: 300, overflow: "auto",
            }}>
              {JSON.stringify(preview.sample_events, null, 2)}
            </pre>
            {Array.isArray(preview.failures) && (preview.failures as unknown[]).length > 0 ? (
              <div style={{ marginTop: 10 }}>
                <div className="mono" style={{ fontSize: 10.5, color: "var(--high)" }}>
                  REJECTED RECORDS
                </div>
                <pre className="mono" style={{
                  margin: 0, fontSize: 10.5, color: "var(--high)", whiteSpace: "pre-wrap",
                }}>
                  {JSON.stringify(preview.failures, null, 2)}
                </pre>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      {result ? (
        <div className="panel">
          <div className="panel-head"><span className="panel-title">Import result</span></div>
          <div className="panel-body" style={{ fontSize: 12.5 }}>
            <div className="grid grid-4" style={{ gap: 10 }}>
              <KV label="Records read" value={String(result.records_total)} />
              <KV label="Accepted" value={String(result.records_ok)} />
              <KV label="Rejected" value={String(result.records_failed)} />
              <KV label="Inserted" value={String(result.events_inserted)} />
              <KV label="Duplicates skipped" value={String(result.events_duplicated)} />
              <KV label="Parse status" value={String(result.parse_status)} />
              <KV label="Format" value={String(result.format)} />
              <KV label="Artifact" value={`#${String(result.artifact_id)}`} />

          {result.analysis ? (
            <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid var(--border)" }}>
              <KV label="Events analysed" value={String(result.analysis.events_analyzed)} />
              <KV label="Alerts created" value={String(result.analysis.alerts_created)} />
              <KV label="Incidents" value={String(result.analysis.incidents_created)} />
              <KV label="Graph"
                  value={`${result.analysis.graph?.nodes ?? 0} nodes / ${result.analysis.graph?.edges ?? 0} edges`} />
              {(result.analysis.engine_errors ?? []).length > 0 ? (
                <div className="banner banner-warn" style={{ marginTop: 8 }}>
                  <span>
                    {result.analysis.engine_errors.length} rule(s) failed during analysis —
                    results may be incomplete.
                  </span>
                </div>
              ) : null}
              {result.analysis.alerts_created === 0 ? (
                <div className="banner banner-info" style={{ marginTop: 8 }}>
                  <span>
                    No detection rules fired on this data. That is a finding, not an error:
                    the rule engine ran over {result.analysis.events_analyzed} events and found
                    no pattern matching R-001..R-006. Check the Events page to confirm the
                    fields the rules need (user, process, dst_ip) were parsed.
                  </span>
                </div>
              ) : null}
            </div>
          ) : null}
            </div>
            {Array.isArray(result.failures) && (result.failures as unknown[]).length > 0 ? (
              <pre className="mono" style={{
                marginTop: 10, fontSize: 10.5, color: "var(--high)", whiteSpace: "pre-wrap",
              }}>
                {JSON.stringify(result.failures, null, 2)}
              </pre>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="mono" style={{ fontSize: 10, letterSpacing: 0.7, color: "var(--fg-muted)",
                                     textTransform: "uppercase", marginBottom: 2 }}>
        {label}
      </div>
      <div className="mono" style={{ fontSize: 14, color: "var(--fg)" }}>{value}</div>
    </div>
  );
}
