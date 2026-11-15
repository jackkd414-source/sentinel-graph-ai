// TRACEWORK shared UI primitives: indicators, states, overlays, helpers.
// Every visual decision here is token-driven; pages never re-invent styling.

import { useEffect, useRef, useState, type ReactNode } from "react";
import { Icons } from "./icons";

/* ------------------------------------------------------------- helpers -- */

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
    `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`
  );
}

export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export function sevRank(s: string | null | undefined): number {
  const i = SEVERITIES.indexOf((s || "") as (typeof SEVERITIES)[number]);
  return i === -1 ? 99 : i;
}

/* ---------------------------------------------------------- indicators -- */

/** Severity as colour + explicit text label (never colour alone). */
export function SeverityIndicator({ severity }: { severity: string | null | undefined }) {
  const s = (severity || "info").toLowerCase();
  return <span className={`tw-chip tw-sev tw-sev-${s}`}>{s}</span>;
}

export function StatusIndicator({ status }: { status: string }) {
  const s = (status || "").toLowerCase().replace(/\s+/g, "-");
  return <span className={`tw-chip tw-status tw-status-${s}`}>{status}</span>;
}

export function EntityTypeIndicator({ type }: { type: string }) {
  return <span className={`tw-chip tw-entity tw-entity-${type}`}>{type}</span>;
}

/** A citation to a stored event. Clicking jumps to the evidence surface. */
export function EvidenceReference({
  id, onOpen, label,
}: { id: number; onOpen?: (id: number) => void; label?: string }) {
  return (
    <button
      type="button"
      className="tw-evref"
      title={`Evidence event #${id}`}
      onClick={onOpen ? () => onOpen(id) : undefined}
      disabled={!onOpen}
    >
      {Icons.evidence({ style: { width: 11, height: 11 } })}
      {label ?? `#${id}`}
    </button>
  );
}

export function SourceLabel({ children }: { children: ReactNode }) {
  return <span className="tw-source">{children}</span>;
}

/** Timestamp with a flag when the source timestamp could not be normalised. */
export function Timestamp({ status, raw }: { status?: string; raw?: string | null }) {
  const bad = status && status !== "ok";
  return (
    <span className="mono num nowrap" style={{ color: bad ? "var(--tw-warning)" : undefined }}
          title={raw ? `raw: ${raw}` : undefined}>
      {fmtTime(raw)}
      {bad ? " ⚠" : ""}
    </span>
  );
}

/* -------------------------------------------------------------- states -- */

export function EmptyState({
  title, detail, icon,
}: { title: string; detail?: string; icon?: ReactNode }) {
  return (
    <div className="tw-empty">
      {icon ?? Icons.layers({ style: { width: 30, height: 30 } })}
      <strong>{title}</strong>
      {detail ? <p>{detail}</p> : null}
    </div>
  );
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="tw-loading">
      <span className="tw-spinner" />
      {label}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="tw-banner tw-banner-err" role="alert">
      <span style={{ flex: 1 }}>{message}</span>
      {onRetry ? (
        <button className="tw-btn tw-btn-sm" onClick={onRetry}>Retry</button>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------ overlays -- */

export function Tooltip({ label, children }: { label: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <span className="tw-tip"
          onMouseEnter={() => setOpen(true)}
          onMouseLeave={() => setOpen(false)}
          onFocus={() => setOpen(true)}
          onBlur={() => setOpen(false)}>
      {children}
      {open ? <span role="tooltip" className="tw-tip-bubble">{label}</span> : null}
    </span>
  );
}

export function Notification({
  kind, message, onClose,
}: { kind: "ok" | "err" | "info"; message: string; onClose: () => void }) {
  useEffect(() => {
    const t = window.setTimeout(onClose, kind === "err" ? 9000 : 6000);
    return () => window.clearTimeout(t);
  }, [kind, message, onClose]);
  return (
    <div className={`tw-toast ${kind === "info" ? "" : kind}`} role="status">
      <span style={{ flex: 1 }}>{message}</span>
      <button className="tw-btn tw-btn-sm tw-btn-ghost tw-btn-icon" aria-label="Dismiss" onClick={onClose}>
        {Icons.close({ style: { width: 13, height: 13 } })}
      </button>
    </div>
  );
}

export function ConfirmDialog({
  open, title, body, confirmLabel = "Confirm", danger, onConfirm, onCancel,
}: {
  open: boolean; title: string; body: string; confirmLabel?: string;
  danger?: boolean; onConfirm: () => void; onCancel: () => void;
}) {
  const okRef = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    if (!open) return;
    okRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onCancel(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onCancel]);
  if (!open) return null;
  return (
    <div className="tw-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
      <div className="tw-dialog" role="dialog" aria-modal="true" aria-label={title}>
        <div className="tw-dialog-head">{title}</div>
        <div className="tw-dialog-body">{body}</div>
        <div className="tw-dialog-foot">
          <button className="tw-btn" onClick={onCancel}>Cancel</button>
          <button ref={okRef} className={`tw-btn ${danger ? "tw-btn-danger" : "tw-btn-primary"}`}
                  onClick={onConfirm}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- forms -- */

export function FormField({
  label, hint, hintWarn, children,
}: { label: string; hint?: ReactNode; hintWarn?: boolean; children: ReactNode }) {
  return (
    <div className="tw-field">
      <label className="tw-label">{label}</label>
      {children}
      {hint ? <div className={`tw-hint${hintWarn ? " warn" : ""}`}>{hint}</div> : null}
    </div>
  );
}

export function SearchInput({
  value, onChange, placeholder = "Search…", width = 240, onEnter,
}: {
  value: string; onChange: (v: string) => void; placeholder?: string;
  width?: number; onEnter?: () => void;
}) {
  return (
    <div className="tw-search" style={{ width }}>
      {Icons.search({ style: { width: 15, height: 15 } })}
      <input className="tw-input" value={value} placeholder={placeholder}
             onChange={(e) => onChange(e.target.value)}
             onKeyDown={(e) => { if (e.key === "Enter" && onEnter) onEnter(); }} />
    </div>
  );
}

/** Re-exported severity list so pages share one ordering. */
export { SEVERITIES };
