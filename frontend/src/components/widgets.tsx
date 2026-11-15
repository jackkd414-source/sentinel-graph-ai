// Ref-1 skin widgets: callout, big stat, donut, chip timeline. Token-driven.

import type { ReactNode } from "react";
import { Icons } from "./icons";

export function Card({
  title, icon, action, children, flush,
}: {
  title?: string;
  icon?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  flush?: boolean;
}) {
  return (
    <section className="tw-card">
      {title ? (
        <div className="tw-card-head">
          {icon ?? null}
          <span className="tw-card-title">{title}</span>
          {action ?? null}
        </div>
      ) : null}
      <div className={`tw-card-body ${flush ? "flush" : ""}`}>{children}</div>
    </section>
  );
}

export function Callout({
  children, tone = "ok", icon,
}: { children: ReactNode; tone?: "ok" | "warn" | "plain"; icon?: ReactNode }) {
  return (
    <div className={`tw-callout ${tone === "ok" ? "" : tone}`}>
      {icon ?? Icons.check({ style: { width: 14, height: 14 } })}
      <span>{children}</span>
    </div>
  );
}

export function OkChip({ label, tone = "ok" }: { label: string; tone?: "ok" | "warn" }) {
  return (
    <span className={`tw-ok-chip ${tone === "warn" ? "warn" : ""}`}>
      {Icons.check({ style: { width: 11, height: 11 } })}
      {label}
    </span>
  );
}

export function Stats({ children }: { children: ReactNode }) {
  return <div className="tw-stats">{children}</div>;
}

export function Stat({ value, label }: { value: ReactNode; label: string }) {
  return (
    <div>
      <div className="tw-stat-value">{value}</div>
      <div className="tw-stat-label">{label}</div>
    </div>
  );
}

export interface DonutSlice { label: string; value: number; color: string; }

export function Donut({
  slices, center, caption = "Total",
}: { slices: DonutSlice[]; center?: ReactNode; caption?: string }) {
  const total = slices.reduce((a, s) => a + s.value, 0);
  const R = 54;
  const C = 2 * Math.PI * R;
  let acc = 0;
  return (
    <div className="tw-donut">
      <svg className="tw-donut-svg" viewBox="0 0 140 140" role="img" aria-label={`${caption}: ${total}`}>
        <g transform="translate(70 70) rotate(-90)">
          <circle r={R} fill="none" stroke="var(--tw-surface-sunken)" strokeWidth="15" />
          {total > 0 ? slices.map((s) => {
            const len = (s.value / total) * C;
            const node = (
              <circle key={s.label} r={R} fill="none" stroke={s.color} strokeWidth="15"
                      strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-acc} />
            );
            acc += len;
            return node;
          }) : null}
        </g>
        <text className="tw-donut-total" x="70" y="72" textAnchor="middle">{center ?? total}</text>
        <text className="tw-donut-cap" x="70" y="88" textAnchor="middle">{caption}</text>
      </svg>
      <div className="tw-donut-legend">
        {slices.map((s) => (
          <div className="tw-donut-row" key={s.label}>
            <span className="tw-donut-key" style={{ background: s.color }} />
            <span>{s.label}</span>
            <b>{s.value}</b>
          </div>
        ))}
      </div>
    </div>
  );
}

export interface ChipTimelineItem {
  id: string | number;
  time: string;
  text: string;
  tone: string;
  chip: ReactNode;
}

export function ChipTimeline({ items }: { items: ChipTimelineItem[] }) {
  return (
    <div className="tw-tl2">
      {items.map((it) => (
        <div className="tw-tl2-item" key={it.id}>
          <div className="tw-tl2-time">{it.time}</div>
          <div className="tw-tl2-rail">
            <span className="tw-tl2-dot" style={{ background: it.tone }} />
          </div>
          <div className="tw-tl2-text">
            {it.text} {it.chip}
          </div>
        </div>
      ))}
    </div>
  );
}
