// TRACEWORK icon set. Hand-drawn geometric strokes — no icon dependency.
// All icons inherit `currentColor` and default to a 16px box via CSS.

import type { SVGProps } from "react";

type P = SVGProps<SVGSVGElement>;

const base = (props: P): P => ({
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  className: "tw-icon",
  "aria-hidden": true,
  ...props,
});

/** Custom brand mark: evidence nodes bound together — not a generic shield. */
export function BrandMark(props: P) {
  return (
    <svg {...base({ strokeWidth: 1.5, ...props })}>
      <circle cx="6" cy="7" r="2.4" />
      <circle cx="18" cy="6.5" r="2.4" />
      <circle cx="12" cy="17.5" r="2.4" />
      <path d="M8.1 8.1 15.9 7.3M7.1 9.1l3.5 6.3M16.6 8.7l-3.4 6.7" />
      <circle cx="12" cy="11.6" r="1.1" fill="currentColor" stroke="none" />
    </svg>
  );
}

export const Icons = {
  dashboard: (p: P) => (
    <svg {...base(p)}><rect x="3" y="3" width="7.5" height="7.5" rx="1.4" /><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.4" /><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.4" /><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.4" /></svg>
  ),
  incidents: (p: P) => (
    <svg {...base(p)}><path d="M12 3.2 2.8 19.8h18.4L12 3.2z" /><path d="M12 9.4v4.6M12 16.6v.05" /></svg>
  ),
  graph: (p: P) => (
    <svg {...base(p)}><circle cx="6" cy="6.5" r="2.4" /><circle cx="18" cy="8" r="2.4" /><circle cx="11.5" cy="18" r="2.4" /><path d="M8.3 7.3 15.6 7.7M7.6 8.7l2.8 6.9M16.4 10.2l-3.6 5.8" /></svg>
  ),
  events: (p: P) => (
    <svg {...base(p)}><path d="M4 6.5h16M4 12h16M4 17.5h10" /></svg>
  ),
  imports: (p: P) => (
    <svg {...base(p)}><path d="M12 15.5V4M7.5 8.5 12 4l4.5 4.5" /><path d="M4 15.5v3.5h16v-3.5" /></svg>
  ),
  evidence: (p: P) => (
    <svg {...base(p)}><path d="M6 3h8l4 4v14H6V3z" /><path d="M14 3v4h4" /><path d="M9 12h6M9 15.5h6" /></svg>
  ),
  rules: (p: P) => (
    <svg {...base(p)}><path d="M4 7h9M4 12h16M4 17h7" /><circle cx="17.5" cy="7" r="2.2" /><circle cx="14.5" cy="17" r="2.2" /></svg>
  ),
  providers: (p: P) => (
    <svg {...base(p)}><circle cx="12" cy="12" r="3" /><path d="M12 3v3.2M12 17.8V21M3 12h3.2M17.8 12H21M5.5 5.5l2.3 2.3M16.2 16.2l2.3 2.3M18.5 5.5l-2.3 2.3M7.8 16.2l-2.3 2.3" /></svg>
  ),
  settings: (p: P) => (
    <svg {...base(p)}><circle cx="12" cy="12" r="3" /><path d="M4 7h6M4 12h4M4 17h9" /><path d="M18 5.5v13" /></svg>
  ),
  reports: (p: P) => (
    <svg {...base(p)}><rect x="5" y="3.5" width="14" height="17" rx="1.4" /><path d="M8.5 9h7M8.5 12.5h7M8.5 16h4.5" /></svg>
  ),
  search: (p: P) => (
    <svg {...base(p)}><circle cx="11" cy="11" r="6.2" /><path d="M15.6 15.6 20 20" /></svg>
  ),
  refresh: (p: P) => (
    <svg {...base(p)}><path d="M20 12a8 8 0 1 1-2.4-5.7" /><path d="M20 4.5V9h-4.5" /></svg>
  ),
  close: (p: P) => (<svg {...base(p)}><path d="M6 6l12 12M18 6L6 18" /></svg>),
  chevronRight: (p: P) => (<svg {...base(p)}><path d="M9 5l7 7-7 7" /></svg>),
  chevronDown: (p: P) => (<svg {...base(p)}><path d="M6 9l6 6 6-6" /></svg>),
  plus: (p: P) => (<svg {...base(p)}><path d="M12 5v14M5 12h14" /></svg>),
  minus: (p: P) => (<svg {...base(p)}><path d="M5 12h14" /></svg>),
  fit: (p: P) => (<svg {...base(p)}><path d="M4 9V5.5A1.5 1.5 0 0 1 5.5 4H9M15 4h3.5A1.5 1.5 0 0 1 20 5.5V9M20 15v3.5a1.5 1.5 0 0 1-1.5 1.5H15M9 20H5.5A1.5 1.5 0 0 1 4 18.5V15" /></svg>),
  reset: (p: P) => (<svg {...base(p)}><path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1" /><path d="M4 4v4.2h4.2" /></svg>),
  download: (p: P) => (<svg {...base(p)}><path d="M12 4v11.5M7.5 11 12 15.5 16.5 11" /><path d="M4 19.5h16" /></svg>),
  copy: (p: P) => (<svg {...base(p)}><rect x="9" y="9" width="11" height="11" rx="1.6" /><path d="M5 15H4V4h11v1" /></svg>),
  check: (p: P) => (<svg {...base(p)}><path d="M5 12.5 10 17.5 19.5 7" /></svg>),
  alert: (p: P) => (<svg {...base(p)}><path d="M12 4 3.2 19.5h17.6L12 4z" /><path d="M12 10v4M12 16.6v.05" /></svg>),
  info: (p: P) => (<svg {...base(p)}><circle cx="12" cy="12" r="8.5" /><path d="M12 11v5.5M12 7.8v.05" /></svg>),
  clock: (p: P) => (<svg {...base(p)}><circle cx="12" cy="12" r="8.5" /><path d="M12 7.5V12l3 2" /></svg>),
  link: (p: P) => (<svg {...base(p)}><path d="M9.5 14.5 14.5 9.5" /><path d="M8 11 6.4 12.6a3.4 3.4 0 0 0 4.8 4.8L12.8 16M16 13l1.6-1.6a3.4 3.4 0 0 0-4.8-4.8L11.2 8" /></svg>),
  external: (p: P) => (<svg {...base(p)}><path d="M14 4h6v6" /><path d="M20 4 11 13" /><path d="M18 14v5.5a.5.5 0 0 1-.5.5H5a.5.5 0 0 1-.5-.5V7a.5.5 0 0 1 .5-.5H11" /></svg>),
  database: (p: P) => (<svg {...base(p)}><ellipse cx="12" cy="6" rx="7.5" ry="3" /><path d="M4.5 6v12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V6" /><path d="M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3" /></svg>),
  server: (p: P) => (<svg {...base(p)}><rect x="3.5" y="4" width="17" height="7" rx="1.6" /><rect x="3.5" y="13" width="17" height="7" rx="1.6" /><path d="M7 7.5h.05M7 16.5h.05" /></svg>),
  cpu: (p: P) => (<svg {...base(p)}><rect x="6.5" y="6.5" width="11" height="11" rx="1.6" /><path d="M10 3.5v3M14 3.5v3M10 17.5v3M14 17.5v3M3.5 10h3M3.5 14h3M17.5 10h3M17.5 14h3" /></svg>),
  layers: (p: P) => (<svg {...base(p)}><path d="M12 3.5 3.5 8 12 12.5 20.5 8 12 3.5z" /><path d="M3.5 12 12 16.5 20.5 12M3.5 16 12 20.5 20.5 16" /></svg>),
  filter: (p: P) => (<svg {...base(p)}><path d="M4 5h16l-6.2 7.4V19l-3.6-2v-4.6L4 5z" /></svg>),
  sortAsc: (p: P) => (<svg {...base(p)}><path d="M7 4v16M4 17l3 3 3-3" /><path d="M13 7h7M13 12h5M13 17h3" /></svg>),
  sortDesc: (p: P) => (<svg {...base(p)}><path d="M7 20V4M4 7l3-3 3 3" /><path d="M13 7h3M13 12h5M13 17h7" /></svg>),
  play: (p: P) => (<svg {...base(p)}><path d="M7 4.5 19 12 7 19.5V4.5z" /></svg>),
  eye: (p: P) => (<svg {...base(p)}><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" /><circle cx="12" cy="12" r="2.8" /></svg>),
  trash: (p: P) => (<svg {...base(p)}><path d="M4 6.5h16M9 6.5V4.5h6v2M6.5 6.5 7.5 20h9l1-13.5" /></svg>),
  bolt: (p: P) => (<svg {...base(p)}><path d="M13 3 5 13h6l-1 8 8-10h-6l1-8z" /></svg>),
  target: (p: P) => (<svg {...base(p)}><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="3.6" /><path d="M12 3.5v3M12 17.5v3M3.5 12h3M17.5 12h3" /></svg>),
  bell: (p: P) => (<svg {...base(p)}><path d="M6.5 9.5a5.5 5.5 0 0 1 11 0c0 4 1.5 5.5 1.5 5.5H5s1.5-1.5 1.5-5.5z" /><path d="M10 18.5a2 2 0 0 0 4 0" /></svg>),
  building: (p: P) => (<svg {...base(p)}><rect x="4" y="4" width="16" height="17" rx="1.4" /><path d="M8 8h2M14 8h2M8 12h2M14 12h2M10 21v-4h4v4" /></svg>),
  user: (p: P) => (<svg {...base(p)}><circle cx="12" cy="8" r="3.4" /><path d="M5 20c0-3.6 3.1-6 7-6s7 2.4 7 6" /></svg>),
  file: (p: P) => (<svg {...base(p)}><path d="M6 3h8l4 4v14H6V3z" /><path d="M14 3v4h4" /></svg>),
  globe: (p: P) => (<svg {...base(p)}><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.6 2.4 2.6 14.6 0 17M12 3.5c-2.6 2.4-2.6 14.6 0 17" /></svg>),
  calendar: (p: P) => (<svg {...base(p)}><rect x="4" y="5.5" width="16" height="15" rx="1.6" /><path d="M4 10h16M8.5 3.5v4M15.5 3.5v4" /></svg>),
  arrowLeft: (p: P) => (<svg {...base(p)}><path d="M19 12H5M11 6l-6 6 6 6" /></svg>),
} as const;

export type IconName = keyof typeof Icons;
