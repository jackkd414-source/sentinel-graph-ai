# TRACEWORK — SentinelGraph AI design system

> *An investigation workstation built around evidence, relationships, and clarity.*

TRACEWORK is the interface language of SentinelGraph AI. It exists so the product
reads as a serious forensic tool: precise, quiet, readable, and engineered with
intention — not a generic dashboard.

## 1. Principles

1. **Evidence before AI.** AI output is always labelled as interpretation, visually
   separated from stored facts. Nothing generated is presented as evidence.
2. **Human-controlled.** No action happens implicitly. Destructive actions confirm.
3. **Facts vs. hypotheses.** Observed relationships are solid; inferred ones are
   dashed and explicitly marked "needs verification".
4. **Readability over decoration.** Whitespace, alignment, separators and type
   hierarchy do the work — not cards, glows or gradients.
5. **Quiet severity.** Severity is a muted colour *plus* a word; never colour alone.

## 2. Tokens

All visual values live in `frontend/src/styles/tokens.css` as `--tw-*` custom
properties. Nothing is hard-coded in components.

| Group | Tokens |
| --- | --- |
| Surfaces | `--tw-canvas` `#F2F4F1`, `--tw-surface` `#FFFFFF`, `--tw-surface-muted` `#F7F8F5`, `--tw-surface-selected` `#E8F1ED`, `--tw-surface-sunken` |
| Text | `--tw-text-primary` `#192421`, `--tw-text-secondary` `#465650`, `--tw-text-muted` `#65726D`, `--tw-text-disabled` `#A4ADA7` |
| Borders | `--tw-border` `#DCE3DE`, `--tw-border-strong` `#C7D2CB` |
| Brand | `--tw-primary` `#176B5B`, `--tw-primary-hover` `#125548`, `--tw-primary-soft` `#E8F1ED` |
| Severity | critical `#B63D49`/`#FCEBED`, high `#B9652E`/`#FBF0E8`, medium `#92721B`/`#F7F3E3`, low `#3C7384`/`#EAF3F5` |
| Status | success `#2F765A`, warning `#A77828`, danger `#B63D49` |
| Entities | host, user, process, file, domain, ip, event, alert, artifact (muted, distinct) |
| Spacing | `--tw-s1`…`--tw-s10` (4 → 56 px) |
| Radius | `--tw-r-sm` 4, `--tw-r` 6, `--tw-r-lg` 8 |
| Type | `--tw-font-sans` (Inter → system), `--tw-font-mono` (ui-monospace → Consolas) |
| Shell | `--tw-sidebar-w` 228 px, `--tw-topbar-h` 64 px |

Typography scale: page title 22 px, panel title 15 px, body 13 px, secondary 12.5 px,
meta 11 px, micro-label 10 px uppercase. Mono is reserved for identifiers, hashes,
timestamps, file paths and raw records.

## 3. Layout

- **AppShell**: `grid` of a 228 px `Sidebar` + `Topbar` + content column. The whole
  app is `100vh` and never scrolls as a page; the content region scrolls.
- **Sidebar**: brand mark + grouped navigation (`WORKSPACE / INVESTIGATE / EVIDENCE /
  ENGINE / SYSTEM`) with count badges, plus a connection/version footer.
- **Topbar**: breadcrumbs, global event search, workspace indicator, connection state,
  session control.
- **PageHeader**: title, one-line purpose, and page-level actions.
- Content max width is unconstrained; pages use `.tw-grid-2/3/4` and split panels.

## 4. Components

`components/` is the only place UI is styled. Pages compose, never re-invent.

- `icons.tsx` — hand-drawn geometric stroke set + brand mark (no icon dependency).
- `ui.tsx` — `SeverityIndicator`, `StatusIndicator`, `EntityTypeIndicator`,
  `EvidenceReference`, `SourceLabel`, `Timestamp`, `EmptyState`, `LoadingState`,
  `ErrorState`, `Notification`, `ConfirmDialog`, `Tooltip`, `FormField`, `SearchInput`,
  and the `fmtTime`/`fmtBytes` helpers.
- `layout.tsx` — `AppShell`, `Sidebar`, `Topbar`, `Breadcrumbs`, `PageHeader`.
- `data.tsx` — `DataTable`, `TableToolbar`, `FilterBar`, `Tabs`, `MetricStrip`/`MetricItem`,
  `PanelHeader`, `InspectorPanel`, `Timeline`.
- `GraphCanvas.tsx` — the attack-graph surface (raw SVG, fit-to-view, pan/zoom, legend,
  observed vs inferred edges, entity shapes).
- `NodeInspector.tsx` — shared node detail used by both graph surfaces.
- `ProviderCard.tsx` — one AI provider configuration.

## 5. Non-negotiables

- No gradients, glassmorphism, neon, glow, or cyberpunk styling.
- No emoji as icons; no decorative charts without data; no fake statistics.
- No placeholder buttons — every control performs a real action.
- Light theme only; raw records use a light sunken surface, not a dark block.
- `prefers-reduced-motion` is respected.

## Skin 2 — adopted from the operator's reference (2026-11-15)

The product owner supplied two reference screenshots and chose to adopt their
language across the whole app, superseding the "no cards / no charts" guidance
of the original brief:

- **Dark investigation rail.** The sidebar is a deep-teal rail (`#0D322D`) with
  light nav text, a teal active accent and a `System Healthy · vX` footer. The
  working area stays light: canvas `#F5F7F5`, white surfaces.
- **Search-first topbar.** One large rounded search (with a `Ctrl + K` hint),
  then workspace, connection state, an alerts bell and a session avatar.
- **Elevated cards.** Panels are 12px-radius cards with a soft shadow and a
  hairline border; the metric strip is a card as well.
- **Widgets.** `Donut` (detection posture), `Stats`/`Stat` (big numbers),
  `Callout` (evidence-reference banner), `ChipTimeline` (time + coloured dot +
  inline type chip), `OkChip` (status pills) — all in `components/widgets.tsx`.
- **Attack graph.** The graph keeps its raw-SVG canvas and gains a right-hand
  `Relationships` rail listing every edge as Time / Source / Destination with
  the relation and how many events prove it.

Tokens for this layer live at the end of `tokens.css`; the overrides are the
`SKIN 2` sections of `base.css`, `components.css` and `pages.css`.
