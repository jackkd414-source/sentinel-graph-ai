import { useCallback, useEffect, useState } from "react";
import { api, type EventFacets, type EventRow } from "../api";
import { Empty, ErrorBanner, Loading, SeverityChip, TsBadge } from "../components/ui";

const PAGE = 50;

export function EventsExplorer() {
  const [rows, setRows] = useState<EventRow[]>([]);
  const [facets, setFacets] = useState<EventFacets | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [q, setQ] = useState("");
  const [host, setHost] = useState("");
  const [user, setUser] = useState("");
  const [type, setType] = useState("");
  const [severity, setSeverity] = useState("");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = useCallback(async (nextOffset = offset) => {
    setLoading(true); setError(null);
    try {
      const [r, f] = await Promise.all([
        api.events({ limit: PAGE, offset: nextOffset, q, host, user,
                     event_type: type, severity, order }),
        facets ? Promise.resolve(facets) : api.eventFacets(),
      ]);
      setRows(r.events);
      setTotal(r.total);
      setOffset(nextOffset);
      if (!facets) setFacets(f);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load events");
    } finally { setLoading(false); }
  }, [q, host, user, type, severity, order, offset, facets]);

  useEffect(() => { void load(0); /* eslint-disable-next-line react-hooks/exhaustive-deps */ },
    [q, host, user, type, severity, order]);

  const reset = () => { setQ(""); setHost(""); setUser(""); setType(""); setSeverity(""); };

  const totalIssues = facets?.timestamp_issues.reduce((a, b) => a + b.c, 0) ?? 0;

  return (
    <div className="col" style={{ gap: 12 }}>
      {totalIssues > 0 ? (
        <div className="banner banner-warn">
          <span>
            <strong>{totalIssues} event(s) have degraded timestamps.</strong> They are kept
            (dropping them would lose evidence) but marked as{" "}
            {facets?.timestamp_issues.map((t) => `${t.ts_status} (${t.c})`).join(", ")}.
            Unparseable timestamps are never replaced with a guessed value.
          </span>
        </div>
      ) : null}

      <div className="panel" style={{ padding: 12 }}>
        <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
          <input className="input" style={{ width: 230 }} placeholder="Search raw / process / file / domain…"
                 value={q} onChange={(e) => setQ(e.target.value)} />
          <select className="select" style={{ width: 150 }} value={host}
                  onChange={(e) => setHost(e.target.value)}>
            <option value="">All hosts</option>
            {facets?.hosts.map((h) => <option key={h} value={h}>{h}</option>)}
          </select>
          <select className="select" style={{ width: 140 }} value={user}
                  onChange={(e) => setUser(e.target.value)}>
            <option value="">All users</option>
            {facets?.users.map((u) => <option key={u} value={u}>{u}</option>)}
          </select>
          <select className="select" style={{ width: 160 }} value={type}
                  onChange={(e) => setType(e.target.value)}>
            <option value="">All event types</option>
            {facets?.event_types.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <select className="select" style={{ width: 130 }} value={severity}
                  onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {facets?.severities.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <button className="btn btn-sm" onClick={reset}>Reset</button>
          <span className="spacer" />
          <select className="select" style={{ width: 120 }} value={order}
                  onChange={(e) => setOrder(e.target.value as "asc" | "desc")}>
            <option value="desc">Newest first</option>
            <option value="asc">Oldest first</option>
          </select>
        </div>
      </div>

      {error ? <ErrorBanner message={error} onRetry={() => void load(offset)} /> : null}

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Normalized events</span>
          <span className="spacer" />
          <span className="mono faint" style={{ fontSize: 10.5 }}>
            {total === 0 ? "0" : `${offset + 1}–${Math.min(offset + PAGE, total)} of ${total}`}
          </span>
        </div>
        {loading && rows.length === 0 ? <Loading /> : rows.length === 0 ? (
          <Empty title="No events" detail="Adjust the filters, or import data first." />
        ) : (
          <>
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 54 }}>ID</th>
                  <th style={{ width: 168 }}>Time (UTC)</th>
                  <th style={{ width: 100 }}>Source</th>
                  <th style={{ width: 130 }}>Type</th>
                  <th style={{ width: 130 }}>Host</th>
                  <th style={{ width: 110 }}>User</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <>
                    <tr key={e.id} className="clickable"
                        onClick={() => setExpanded(expanded === e.id ? null : e.id)}>
                      <td className="mono" style={{ color: "var(--cyan-dim)" }}>#{e.id}</td>
                      <td><TsBadge status={e.ts_status} raw={e.ts_utc || e.ts_raw} /></td>
                      <td className="mono faint" style={{ fontSize: 10.5 }}>{e.source}</td>
                      <td className="mono" style={{ fontSize: 11 }}>
                        {e.event_type}
                        {e.severity ? <span style={{ marginLeft: 5 }}>
                          <SeverityChip severity={e.severity} />
                        </span> : null}
                      </td>
                      <td className="mono dim">{e.host || "—"}</td>
                      <td className="mono dim">{e.user_name || "—"}</td>
                      <td className="mono truncate" style={{ maxWidth: 380, fontSize: 11 }}>
                        {e.command_line || e.file_path || e.domain || e.process_name ||
                         e.action || e.dst_ip || "—"}
                      </td>
                    </tr>
                    {expanded === e.id ? (
                      <tr key={`${e.id}-d`}>
                        <td colSpan={7} style={{ background: "var(--bg)", padding: 12 }}>
                          <pre className="mono" style={{
                            margin: 0, fontSize: 10.5, whiteSpace: "pre-wrap",
                            color: "var(--fg-dim)", maxHeight: 300, overflow: "auto",
                          }}>
                            {fmtRaw(e.raw)}
                          </pre>
                        </td>
                      </tr>
                    ) : null}
                  </>
                ))}
              </tbody>
            </table>
            <div className="row" style={{ padding: 10, borderTop: "1px solid var(--line-soft)" }}>
              <button className="btn btn-sm" disabled={offset === 0 || loading}
                      onClick={() => void load(Math.max(0, offset - PAGE))}>← Prev</button>
              <button className="btn btn-sm" disabled={offset + PAGE >= total || loading}
                      onClick={() => void load(offset + PAGE)}>Next →</button>
              <span className="spacer" />
              {loading ? <span className="spinner" /> : null}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function fmtRaw(raw: string | null): string {
  if (!raw) return "(no raw record)";
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}
