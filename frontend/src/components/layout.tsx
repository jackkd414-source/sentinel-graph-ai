// TRACEWORK application shell: AppShell, Sidebar, Topbar, PageHeader, Breadcrumbs.

import type { ReactNode } from "react";
import { BrandMark, Icons } from "./icons";

export interface NavItem {
  key: string;
  label: string;
  icon: ReactNode;
  badge?: ReactNode;
}
export interface NavGroup { label: string; items: NavItem[]; }

export function AppShell({
  sidebar, topbar, children,
}: { sidebar: ReactNode; topbar: ReactNode; children: ReactNode }) {
  return (
    <div className="tw-app">
      {sidebar}
      <div className="tw-main">
        {topbar}
        {children}
      </div>
    </div>
  );
}

export function Sidebar({
  groups, active, onNavigate, footer,
}: {
  groups: NavGroup[];
  active: string;
  onNavigate: (key: string) => void;
  footer: ReactNode;
}) {
  return (
    <aside className="tw-sidebar" aria-label="Primary">
      <div className="tw-brand">
        {BrandMark({ className: "tw-brand-mark", style: { width: 30, height: 30 } })}
        <div className="tw-brand-text">
          <span className="tw-brand-name">SentinelGraph AI</span>
          <span className="tw-brand-tag">From Signals to Story</span>
        </div>
      </div>

      <nav className="tw-nav">
        {groups.map((g) => (
          <div key={g.label}>
            <div className="tw-nav-group">{g.label}</div>
            {g.items.map((it) => (
              <button
                key={it.key}
                className={`tw-nav-item ${active === it.key ? "active" : ""}`}
                aria-current={active === it.key ? "page" : undefined}
                onClick={() => onNavigate(it.key)}
              >
                {it.icon}
                <span className="tw-nav-label">{it.label}</span>
                {it.badge != null ? it.badge : null}
              </button>
            ))}
          </div>
        ))}
      </nav>

      <div className="tw-sidebar-foot">{footer}</div>
    </aside>
  );
}

export function Topbar({ search, right }: { search: ReactNode; right: ReactNode }) {
  return (
    <header className="tw-topbar">
      {search}
      <span className="spacer" />
      <div className="tw-topbar-right">{right}</div>
    </header>
  );
}

export function Breadcrumbs({
  items, onNavigate,
}: { items: { label: string; key?: string }[]; onNavigate: (key: string) => void }) {
  return (
    <nav className="tw-crumbs" aria-label="Breadcrumb">
      {items.map((c, i) => {
        const last = i === items.length - 1;
        return (
          <span key={`${c.label}-${i}`} style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
            {i > 0 ? <span className="sep">{Icons.chevronRight({ style: { width: 12, height: 12 } })}</span> : null}
            {last || !c.key ? (
              <span className="here">{c.label}</span>
            ) : (
              <button onClick={() => onNavigate(c.key!)}>{c.label}</button>
            )}
          </span>
        );
      })}
    </nav>
  );
}

export function PageHeader({
  title, subtitle, actions, meta,
}: { title: string; subtitle?: string; actions?: ReactNode; meta?: ReactNode }) {
  return (
    <div className="tw-page-head">
      <div className="tw-page-titles">
        <h1 className="tw-page-title">{title}</h1>
        {subtitle ? <div className="tw-page-sub">{subtitle}</div> : null}
        {meta ? <div className="tw-page-sub" style={{ marginTop: 6 }}>{meta}</div> : null}
      </div>
      {actions ? <div className="tw-page-actions">{actions}</div> : null}
    </div>
  );
}

/** Global search wired to real data (Events). Placeholder only when idle. */
export function GlobalSearch({
  value, onChange, onSubmit,
}: { value: string; onChange: (v: string) => void; onSubmit: () => void }) {
  return (
    <div className="tw-search-lg">
      {Icons.search({ style: { width: 16, height: 16, flexShrink: 0 } })}
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter") onSubmit(); }}
        placeholder="Search events, incidents, or entities…"
        aria-label="Global search"
      />
      <kbd>Ctrl + K</kbd>
    </div>
  );
}
