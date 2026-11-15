import { useCallback, useEffect, useState } from "react";
import { api, type Artifact, type Rule } from "../api";
import { PageHeader } from "../components/layout";
import { DataTable, InspectorPanel, PanelHeader, type Column } from "../components/data";
import {
  ConfirmDialog, EmptyState, ErrorState, LoadingState, SeverityIndicator, SourceLabel, StatusIndicator,
  fmtBytes, fmtTime,
} from "../components/ui";
import { Icons } from "../components/icons";

/* ---------------------------------------------- Evidence repository ----- */

export function EvidenceRepository({ onImport, reloadKey }: { onImport: () => void; reloadKey: number }) {
  const [items, setItems] = useState<Artifact[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<Artifact | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<null | { title: string; body: string; label: string; run: () => Promise<void> }>(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.artifacts();
      setItems(r.artifacts);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load artifacts");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load, reloadKey]);

  const removeArtifact = (a: Artifact) => setConfirm({
    title: `Delete “${a.name}”?`,
    body: "This removes the imported file and every event it produced, then rebuilds alerts, "
        + "incidents and the attack graph from what is left. This cannot be undone.",
    label: "Delete artifact",
    run: async () => {
      setBusy(true); setNotice(null);
      const r = await api.deleteArtifact(a.id);
      setNotice(`Deleted “${r.deleted_artifact}”, ${r.events_removed} event(s) removed, derived data rebuilt.`);
      setSelected(null);
      await load();
      setBusy(false);
    },
  });

  const clearAll = (keepIocs: boolean) => setConfirm({
    title: keepIocs ? "Clear all imported data?" : "Clear all data AND threat indicators?",
    body: keepIocs
      ? "Removes every imported event, alert, incident, graph node and artifact. Threat-intelligence indicators are kept."
      : "Removes every imported event, alert, incident, graph node, artifact AND the threat-intelligence indicators. The workspace becomes empty.",
    label: "Clear data",
    run: async () => {
      setBusy(true); setNotice(null);
      const r = await api.resetData(keepIocs);
      const n = Object.values(r.cleared).reduce((s, v) => s + v, 0);
      setNotice(`Cleared ${n} row(s). Remaining: ${r.counts.events} events, ${r.counts.alerts} alerts, ${r.counts.incidents} incidents.`);
      await load();
      setBusy(false);
    },
  });

  const cols: Column<Artifact>[] = [
    { key: "name", header: "Artifact", className: "primary", render: (a) => (
      <span className="mono truncate" style={{ display: "block", maxWidth: 220 }} title={a.name}>{a.name}</span>) },
    { key: "kind", header: "Type", width: 110, render: (a) => <span className="mono faint">{a.artifact_kind}</span> },
    { key: "source", header: "Source", width: 130, render: (a) => <SourceLabel>{a.source_type}</SourceLabel> },
    { key: "records", header: "Records", width: 104, render: (a) => (
      <span className="mono num">{a.record_ok}/{a.record_total}
        {a.record_failed > 0 ? <span style={{ color: "var(--tw-high)" }}> ({a.record_failed}✗)</span> : null}
      </span>) },
    { key: "parse", header: "Parse", width: 100, render: (a) => <StatusIndicator status={a.parse_status} /> },
    { key: "size", header: "Size", width: 90, align: "right", render: (a) => <span className="mono num">{fmtBytes(a.size_bytes)}</span> },
    { key: "imported", header: "Imported", width: 160, render: (a) => <span className="mono num">{fmtTime(a.imported_at)}</span> },
    { key: "sha", header: "SHA-256", width: 120, render: (a) => (
      <span className="mono faint" title={a.sha256 || ""}>{(a.sha256 || "-").slice(0, 14)}…</span>) },
  ];

  return (
    <>
      <PageHeader
        title="Evidence Repository"
        subtitle="Every import, with record counts, parse status and the SHA-256 of the exact bytes received."
        actions={
          <>
            <button className="tw-btn tw-btn-sm" onClick={() => void load()}>Refresh</button>
            <button className="tw-btn tw-btn-sm tw-btn-primary" onClick={onImport}>Import data</button>
          </>
        }
      />

      {notice ? <div className="tw-banner tw-banner-info" style={{ marginBottom: 16 }}><span>{notice}</span></div> : null}

      <div className="tw-banner tw-banner-info" style={{ marginBottom: 16 }}>
        <span>
          <strong>What the SHA-256 proves:</strong> it verifies that a stored copy is identical to the
          bytes that were imported. It does <em>not</em> prove the original file was unmodified before
          it reached this tool.
        </span>
      </div>

      {error ? <div style={{ marginBottom: 16 }}><ErrorState message={error} onRetry={load} /></div> : null}

      <div className="tw-panel">
        {loading ? <LoadingState label="Loading artifacts…" /> : (
          <DataTable
            columns={cols}
            rows={items}
            rowKey={(a) => a.id}
            onRowClick={(a) => setSelected(a)}
            selectedKey={selected?.id ?? null}
            empty={<EmptyState title="No artifacts" detail="Import a file or load the demo dataset." />}
          />
        )}
      </div>

      <div className="tw-panel" style={{ marginTop: 16 }}>
        <PanelHeader title="Clear imported data" />
        <div className="tw-panel-body col" style={{ gap: 12 }}>
          <span className="faint" style={{ fontSize: "var(--tw-fs-secondary)" }}>
            Removes every imported event, alert, incident, graph node and artifact. Use this when you
            imported the wrong file and want to start over.
          </span>
          <div className="row" style={{ gap: 8 }}>
            <button className="tw-btn tw-btn-sm" disabled={busy} onClick={() => clearAll(true)}>Clear data (keep IOCs)</button>
            <button className="tw-btn tw-btn-sm tw-btn-danger" disabled={busy} onClick={() => clearAll(false)}>Clear data + IOCs</button>
          </div>
        </div>
      </div>

      {selected ? (
        <div className="tw-drawer">
          <InspectorPanel title="Artifact detail" onClose={() => setSelected(null)}
            actions={
              <button className="tw-btn tw-btn-sm tw-btn-danger tw-btn-icon" title="Delete artifact"
                      aria-label="Delete artifact" disabled={busy}
                      onClick={() => removeArtifact(selected)}>
                {Icons.trash({ style: { width: 13, height: 13 } })}
              </button>
            }>
            <div className="tw-inspector-title mono">{selected.name}</div>
            <div className="row" style={{ gap: 7, marginTop: 8, flexWrap: "wrap" }}>
              <StatusIndicator status={selected.parse_status} />
              <span className="tw-chip tw-chip-plain">{selected.artifact_kind}</span>
              {selected.is_synthetic ? <span className="tw-chip tw-sev tw-sev-medium">synthetic</span> : null}
            </div>
            <dl className="tw-kv" style={{ marginTop: 16 }}>
              <dt>Source</dt><dd><SourceLabel>{selected.source_type}</SourceLabel></dd>
              <dt>Records</dt><dd className="mono">{selected.record_ok} ok / {selected.record_failed} rejected / {selected.record_total} total</dd>
              <dt>Size</dt><dd className="mono">{fmtBytes(selected.size_bytes)}</dd>
              <dt>Imported</dt><dd className="mono">{fmtTime(selected.imported_at)}</dd>
              <dt>Stored path</dt><dd className="mono" style={{ wordBreak: "break-all" }}>{selected.stored_path || "-"}</dd>
            </dl>
            <div style={{ marginTop: 16 }}>
              <div className="tw-section-title">SHA-256</div>
              <pre className="tw-code">{selected.sha256 || "(none recorded)"}</pre>
            </div>
            {selected.parse_notes ? (
              <div style={{ marginTop: 16 }}>
                <div className="tw-section-title">Parse notes</div>
                <pre className="tw-code">{selected.parse_notes}</pre>
              </div>
            ) : null}
          </InspectorPanel>
        </div>
      ) : null}

      <ConfirmDialog
        open={!!confirm}
        title={confirm?.title || ""}
        body={confirm?.body || ""}
        confirmLabel={confirm?.label}
        danger
        onCancel={() => setConfirm(null)}
        onConfirm={() => {
          const c = confirm;
          setConfirm(null);
          if (c) void c.run().catch((e) => setError(e instanceof Error ? e.message : "Operation failed"))
            .finally(() => setBusy(false));
        }}
      />
    </>
  );
}

/* ------------------------------------------------ Detection rules ------- */

export function DetectionRules({ onReanalyzed }: { onReanalyzed: () => void }) {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [selected, setSelected] = useState<Rule | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.rules();
      setRules(r.rules);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load rules");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const toggle = async (id: string, enabled: boolean) => {
    setBusy(id);
    try {
      await api.toggleRule(id, enabled);
      await api.reanalyze();
      onReanalyzed();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Toggle failed");
    } finally { setBusy(null); }
  };

  const cols: Column<Rule>[] = [
    { key: "id", header: "Rule", width: 70, render: (r) => <span className="mono" style={{ color: "var(--tw-primary)" }}>{r.id}</span> },
    { key: "name", header: "Name", className: "primary", render: (r) => (
      <span className="truncate" style={{ display: "block", maxWidth: 200 }} title={r.name}>{r.name}</span>) },
    { key: "cat", header: "Category", width: 130, render: (r) => <span className="mono faint">{r.category}</span> },
    { key: "sev", header: "Severity", width: 88, render: (r) => <SeverityIndicator severity={r.severity} /> },
    { key: "status", header: "Status", width: 116, render: (r) => (
      <label className="tw-switch" onClick={(e) => e.stopPropagation()} title={r.enabled ? "Disable rule" : "Enable rule"}>
        <input type="checkbox" checked={r.enabled === 1} disabled={busy === r.id}
               onChange={(e) => void toggle(r.id, e.target.checked)} />
        <span className="tw-switch-track" />
        <span className="tw-switch-label">{r.enabled ? "enabled" : "disabled"}</span>
      </label>) },
    { key: "desc", header: "Description", render: (r) => (
      <span className="truncate" style={{ display: "block", maxWidth: 260 }} title={r.description}>{r.description}</span>) },
  ];

  return (
    <>
      <PageHeader
        title="Detection Rules"
        subtitle="Deterministic functions over normalized events. Toggling one re-runs the full pipeline."
      />
      <div className="tw-banner tw-banner-info" style={{ marginBottom: 16 }}>
        <span>
          These are correlation heuristics with published logic. SentinelGraph does not claim zero-day
          detection; each rule states the behaviour it matches and the thresholds it uses.
        </span>
      </div>
      {error ? <div style={{ marginBottom: 16 }}><ErrorState message={error} onRetry={load} /></div> : null}
      <div className="tw-panel">
        {loading ? <LoadingState label="Loading rules…" /> : (
          <DataTable
            columns={cols}
            rows={rules}
            rowKey={(r) => r.id}
            onRowClick={(r) => setSelected(r)}
            selectedKey={selected?.id ?? null}
            empty={<EmptyState title="No rules registered" />}
          />
        )}
      </div>

      {selected ? (
        <div className="tw-drawer">
          <InspectorPanel title="Rule detail" onClose={() => setSelected(null)}>
            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
              <span className="mono" style={{ color: "var(--tw-primary)" }}>{selected.id}</span>
              <SeverityIndicator severity={selected.severity} />
              <span className={`tw-chip tw-status tw-status-${selected.enabled ? "contained" : "closed"}`}>
                {selected.enabled ? "enabled" : "disabled"}</span>
            </div>
            <div className="tw-inspector-title" style={{ marginTop: 10 }}>{selected.name}</div>
            <p className="faint" style={{ fontSize: "var(--tw-fs-secondary)", lineHeight: 1.6, marginTop: 8 }}>{selected.description}</p>
            <div className="tw-section-title" style={{ marginTop: 16 }}>Logic</div>
            <pre className="tw-code">{selected.logic}</pre>
            <dl className="tw-kv" style={{ marginTop: 16 }}>
              <dt>Category</dt><dd>{selected.category}</dd>
              <dt>Version</dt><dd className="mono">v{selected.version}</dd>
            </dl>
            {selected.attack?.length ? (
              <div style={{ marginTop: 16 }}>
                <div className="tw-section-title">MITRE ATT&amp;CK</div>
                <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                  {selected.attack.map((t) => (
                    <span key={t.id} className="tw-chip tw-chip-plain mono" title={t.tactic}>{t.id}</span>
                  ))}
                </div>
              </div>
            ) : selected.attack_note ? (
              <div style={{ marginTop: 16 }}>
                <div className="tw-section-title">MITRE ATT&amp;CK</div>
                <p className="faint" style={{ fontSize: "var(--tw-fs-meta)", lineHeight: 1.5 }}>{selected.attack_note}</p>
              </div>
            ) : null}
          </InspectorPanel>
        </div>
      ) : null}
    </>
  );
}
