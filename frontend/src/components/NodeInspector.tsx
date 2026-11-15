// Shared node inspector for the attack graph (used by the global graph page and
// the incident workspace). Renders entity facts, observed/inferred relations and
// the supporting evidence events for one graph node.

import { useEffect, useState } from "react";
import { api, type NodeDetail } from "../api";
import { InspectorPanel } from "./data";
import {
  ErrorState, LoadingState, SeverityIndicator, EvidenceReference, Timestamp, fmtTime,
} from "./ui";

export function NodeInspector({ nodeId, onClose }: { nodeId: number; onClose: () => void }) {
  const [data, setData] = useState<NodeDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setData(null); setError(null);
    api.nodeDetail(nodeId)
      .then((d) => { if (alive) setData(d); })
      .catch((e) => { if (alive) setError(e instanceof Error ? e.message : "Failed to load node"); });
    return () => { alive = false; };
  }, [nodeId]);

  return (
    <InspectorPanel title="Node inspector" onClose={onClose}>
      {error ? <ErrorState message={error} /> : null}
      {!data && !error ? <LoadingState /> : null}
      {data ? (
        <div className="col" style={{ gap: 16 }}>
          <div>
            <div className="tw-inspector-title">{data.node.label}</div>
            <div className="row" style={{ gap: 7, marginTop: 6, flexWrap: "wrap" }}>
              <span className={`tw-chip tw-entity tw-entity-${data.node.node_type}`}>{data.node.node_type}</span>
              {data.node.severity ? <SeverityIndicator severity={data.node.severity} /> : null}
            </div>
            <div className="mono faint" style={{ marginTop: 6, wordBreak: "break-all" }}>{data.node.node_key}</div>
          </div>

          <dl className="tw-kv">
            <dt>First seen</dt><dd className="mono">{fmtTime(data.node.attributes?.first_ts as string) || "—"}</dd>
            <dt>Last seen</dt><dd className="mono">{fmtTime(data.node.attributes?.last_ts as string) || "—"}</dd>
            <dt>Evidence events</dt><dd className="mono">{data.evidence.length}</dd>
          </dl>

          <p className="faint" style={{ fontSize: "var(--tw-fs-meta)", lineHeight: 1.6, margin: 0 }}>
            Solid relations are observed directly in events; dashed relations are inferred and marked
            for verification. Derived relations carry no single source event.
          </p>

          {data.node.attributes && Object.keys(data.node.attributes).length > 0 ? (
            <div>
              <div className="tw-section-title">Attributes</div>
              <pre className="tw-code">{JSON.stringify(data.node.attributes, null, 2)}</pre>
            </div>
          ) : null}

          <RelationSection title={`Incoming relations (${data.incoming.length})`}
            rows={data.incoming.map((e) => ({ key: e.id, other: e.src_label, relation: e.relation,
              status: e.status, method: e.method, evidence: e.evidence_event_ids }))} />
          <RelationSection title={`Outgoing relations (${data.outgoing.length})`}
            rows={data.outgoing.map((e) => ({ key: e.id, other: e.dst_label, relation: e.relation,
              status: e.status, method: e.method, evidence: e.evidence_event_ids }))} />

          <div>
            <div className="tw-section-title">Supporting events ({data.evidence.length})</div>
            {data.evidence.length === 0 ? <span className="faint">No event evidence linked.</span> : (
              <div className="col" style={{ gap: 8 }}>
                {data.evidence.slice(0, 20).map((ev) => (
                  <div key={ev.id} style={{ fontSize: "var(--tw-fs-secondary)" }}>
                    <div className="row" style={{ gap: 7 }}>
                      <EvidenceReference id={ev.id} />
                      <Timestamp status={ev.ts_status} raw={ev.ts_utc} />
                    </div>
                    <div className="mono faint" style={{ marginTop: 2, wordBreak: "break-all" }}>
                      {ev.event_type} · {ev.host || "?"}{ev.process_name ? ` · ${ev.process_name}` : ""}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : null}
    </InspectorPanel>
  );
}

function RelationSection({
  title, rows,
}: {
  title: string;
  rows: { key: number; other: string; relation: string; status: string; method: string; evidence?: number[] }[];
}) {
  return (
    <div>
      <div className="tw-section-title">{title}</div>
      {rows.length === 0 ? <span className="faint">none</span> : (
        <div className="col" style={{ gap: 10 }}>
          {rows.map((r) => (
            <div key={r.key} style={{ fontSize: "var(--tw-fs-secondary)" }}>
              <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                <span className="mono" style={{ color: "var(--tw-primary)" }}>{r.other}</span>
                <span className="faint">→ {r.relation} →</span>
              </div>
              <div className="row" style={{ gap: 7, marginTop: 3, flexWrap: "wrap" }}>
                <span className={`tw-chip tw-status tw-status-${r.status}`}>{r.status}</span>
                <span className="faint" style={{ fontSize: "var(--tw-fs-meta)" }}>{r.method}</span>
              </div>
              <div className="mono" style={{ marginTop: 3 }}>
                {r.evidence && r.evidence.length > 0
                  ? <span style={{ color: "var(--tw-success)" }}>evidence: {r.evidence.map((x) => `#${x}`).join(", ")}</span>
                  : <span className="faint">derived relation — no single source event</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
