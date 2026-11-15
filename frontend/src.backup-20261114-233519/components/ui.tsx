// Shared presentational primitives. Small on purpose - no icon library.

import type { ReactNode } from "react";
import type { Severity, TsStatus } from "../api";

const S = { fill: "none", stroke: "currentColor", strokeWidth: 1.7,
  strokeLinecap: "round" as const, strokeLinejoin: "round" as const };

export const Icon = {
  dashboard: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
  ),
  incident: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <path d="M12 3 2.5 20h19L12 3z" />
      <path d="M12 9.5v4.5M12 17.2v.1" />
    </svg>
  ),
  graph: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <circle cx="6" cy="6" r="2.6" />
      <circle cx="18" cy="8" r="2.6" />
      <circle cx="11" cy="18" r="2.6" />
      <path d="M8.3 7.2 15.5 7.6M7.4 8.4l2.6 7.2M16.6 10.2l-3.9 5.8" />
    </svg>
  ),
  timeline: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <path d="M3 12h18" />
      <circle cx="7" cy="12" r="2" />
      <circle cx="14" cy="12" r="2" />
      <path d="M7 12V6M14 12v6" />
    </svg>
  ),
  evidence: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <path d="M5 3h9l5 5v13H5V3z" />
      <path d="M14 3v5h5" />
    </svg>
  ),
  report: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <path d="M5 4h14v16H5z" />
      <path d="M8.5 9h7M8.5 12.5h7M8.5 16h4" />
    </svg>
  ),
  rules: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <path d="M4 7h10M4 12h16M4 17h7" />
      <circle cx="18" cy="7" r="2" />
      <circle cx="14" cy="17" r="2" />
    </svg>
  ),
  settings: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1" />
    </svg>
  ),
  upload: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <path d="M12 16V4M7 9l5-5 5 5" />
      <path d="M4 16v4h16v-4" />
    </svg>
  ),
  search: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <circle cx="11" cy="11" r="6.5" />
      <path d="M16 16l4.5 4.5" />
    </svg>
  ),
  refresh: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <path d="M20 12a8 8 0 1 1-2.6-5.9" />
      <path d="M20 4v4.5h-4.5" />
    </svg>
  ),
  download: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <path d="M12 4v12M7 11l5 5 5-5" />
      <path d="M4 20h16" />
    </svg>
  ),
  spark: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <path d="M12 3v4M12 17v4M3 12h4M17 12h4M6.3 6.3l2.8 2.8M14.9 14.9l2.8 2.8M17.7 6.3l-2.8 2.8M9.1 14.9l-2.8 2.8" />
    </svg>
  ),
  shield: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
         strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2.5 4.5 5.5v6c0 5 3.2 8.6 7.5 10 4.3-1.4 7.5-5 7.5-10v-6L12 2.5z" />
      <path d="M12 8.5v4M12 15.4v.1" />
    </svg>
  ),
  close: () => (
    <svg viewBox="0 0 24 24" className="icon" {...S}>
      <path d="M6 6l12 12M18 6L6 18" />
    </svg>
  ),
};

export function SeverityChip({ severity }: { severity: Severity | null | undefined }) {
  const s = (severity || "info") as Severity;
  return <span className={`chip chip-${s}`}>{s}</span>;
}

export function StatusChip({ status }: { status: "observed" | "inferred" }) {
  return <span className={`chip chip-${status}`}>{status}</span>;
}

export function TsBadge({ status, raw }: { status: TsStatus; raw?: string | null }) {
  if (status === "ok") {
    return <span className="mono" style={{ color: "var(--fg-dim)" }}>{raw || "—"}</span>;
  }
  const label = status === "assumed" ? "TIME ASSUMED" : status === "invalid" ? "TIME INVALID" : "NO TIME";
  const color = status === "assumed" ? "var(--medium)" : "var(--critical)";
  return (
    <span className="mono" style={{ color, fontSize: 11 }} title={
      status === "assumed"
        ? "Parsed without an explicit timezone; interpreted using the configured default."
        : status === "invalid"
          ? `Could not parse the source timestamp: ${raw || "(empty)"}`
          : "No timestamp present in the source record."
    }>
      [{label}]
    </span>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="loading-row">
      <span className="spinner" />
      <span>{label}</span>
    </div>
  );
}

export function Empty({ title, detail, icon }: {
  title: string; detail?: string; icon?: ReactNode;
}) {
  return (
    <div className="empty">
      <svg viewBox="0 0 24 24" className="empty-icon" fill="none"
           stroke="currentColor" strokeWidth={1.2}>
        <circle cx="12" cy="12" r="9" />
        <path d="M8 15h8M9 9.5h.1M15 9.5h.1" strokeLinecap="round" />
      </svg>
      <strong>{title}</strong>
      {detail ? <div style={{ maxWidth: 460, margin: "0 auto", lineHeight: 1.6 }}>{detail}</div> : null}
      {icon}
    </div>
  );
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="banner banner-err">
      <span style={{ flex: 1 }}>{message}</span>
      {onRetry ? (
        <button className="btn btn-sm" onClick={onRetry}>Retry</button>
      ) : null}
    </div>
  );
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
         `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`;
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  return `${(n / 1024 ** 3).toFixed(2)} GiB`;
}
