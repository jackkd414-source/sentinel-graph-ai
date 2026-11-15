// TRACEWORK data-display components: DataTable, TableToolbar, FilterBar, Tabs,
// MetricStrip/MetricItem, PanelHeader, InspectorPanel, Timeline.

import type { ReactNode } from "react";
import { Icons } from "./icons";
import { EmptyState, Timestamp, SeverityIndicator } from "./ui";

export interface Column<T> {
  key: string;
  header: ReactNode;
  width?: number | string;
  align?: "left" | "right";
  className?: string;
  render: (row: T, index: number) => ReactNode;
}

export function DataTable<T>({
  columns, rows, rowKey, onRowClick, empty, selectedKey,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string | number;
  onRowClick?: (row: T) => void;
  empty?: ReactNode;
  selectedKey?: string | number | null;
}) {
  if (rows.length === 0) {
    return <>{empty ?? <EmptyState title="Nothing to show" />}</>;
  }
  return (
    <div className="tw-table-wrap">
      <table className="tw-table">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={c.className}
                  style={{ width: c.width, textAlign: c.align }}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const k = rowKey(r, i);
            return (
              <tr key={k}
                  className={`${onRowClick ? "clickable" : ""} ${selectedKey === k ? "selected" : ""}`}
                  onClick={onRowClick ? () => onRowClick(r) : undefined}>
                {columns.map((c) => (
                  <td key={c.key} className={c.className} style={{ textAlign: c.align }}>
                    {c.render(r, i)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function TableToolbar({ children }: { children: ReactNode }) {
  return <div className="tw-toolbar">{children}</div>;
}

export function FilterBar({ children }: { children: ReactNode }) {
  return (
    <div className="tw-toolbar">
      {Icons.filter({ style: { width: 14, height: 14, color: "var(--tw-text-muted)" } })}
      {children}
    </div>
  );
}

export function Tabs<T extends string>({
  tabs, active, onChange,
}: {
  tabs: { key: T; label: string; count?: number }[];
  active: T;
  onChange: (t: T) => void;
}) {
  return (
    <div className="tw-tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.key} role="tab" aria-selected={active === t.key}
                className={`tw-tab ${active === t.key ? "active" : ""}`}
                onClick={() => onChange(t.key)}>
          {t.label}
          {t.count != null ? <span className="tw-tab-count">{t.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

export function MetricStrip({ children }: { children: ReactNode }) {
  return <div className="tw-metrics">{children}</div>;
}

export function MetricItem({
  label, value, sub, critical,
}: { label: string; value: ReactNode; sub?: ReactNode; critical?: boolean }) {
  return (
    <div className="tw-metric">
      <div className="tw-metric-label">{label}</div>
      <div className={`tw-metric-value${critical ? " critical" : ""}`}>{value}</div>
      {sub ? <div className="tw-metric-sub">{sub}</div> : null}
    </div>
  );
}

export function PanelHeader({
  title, sub, actions,
}: { title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="tw-panel-head">
      <span className="tw-panel-title">{title}</span>
      {sub ? <span className="tw-panel-sub">{sub}</span> : null}
      <span className="spacer" />
      {actions}
    </div>
  );
}

export function InspectorPanel({
  title, onClose, children, actions,
}: { title: ReactNode; onClose?: () => void; children: ReactNode; actions?: ReactNode }) {
  return (
    <aside className="tw-inspector" aria-label="Inspector">
      <div className="tw-inspector-head">
        <span className="tw-section-title" style={{ margin: 0 }}>{title}</span>
        <span className="spacer" />
        {actions}
        {onClose ? (
          <button className="tw-btn tw-btn-sm tw-btn-ghost tw-btn-icon" aria-label="Close inspector"
                  onClick={onClose}>
            {Icons.close({ style: { width: 13, height: 13 } })}
          </button>
        ) : null}
      </div>
      <div className="tw-inspector-body">{children}</div>
    </aside>
  );
}

export interface TimelineEntry {
  id: number | string;
  ts: string | null;
  tsStatus?: string;
  severity?: string | null;
  title: string;
  body?: ReactNode;
}

export function Timeline({ items }: { items: TimelineEntry[] }) {
  if (items.length === 0) {
    return <EmptyState title="No events in this window" />;
  }
  return (
    <div className="tw-timeline">
      {items.map((it) => (
        <div className="tw-tl-item" key={it.id}>
          <span className={`tw-tl-dot ${it.severity || ""}`} />
          <div className="tw-tl-time"><Timestamp status={it.tsStatus} raw={it.ts} /></div>
          <div className="tw-tl-title">
            {it.severity ? <span style={{ marginRight: 8 }}><SeverityIndicator severity={it.severity} /></span> : null}
            {it.title}
          </div>
          {it.body ? <div className="tw-tl-body">{it.body}</div> : null}
        </div>
      ))}
    </div>
  );
}
