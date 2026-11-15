/**
 * In-product guidance for the dashboard.
 *
 * Goal: a first-time analyst should understand what this tool does, what order
 * to do it in, and what the jargon means — without opening the docs or the
 * source. Everything here is driven by real workspace counts and real buttons.
 */
import { Icons } from "./icons";
import type { RouteKey } from "../routes";

export interface FlowStep {
  key: string;
  n: number;
  title: string;
  body: string;
  stat: string;
  route: RouteKey;
}

/** The four stages of the pipeline, each clickable, each showing live counts. */
export function WorkflowStrip({ steps, onGo }: { steps: FlowStep[]; onGo: (r: RouteKey) => void }) {
  return (
    <div className="tw-flow">
      {steps.map((s) => (
        <button key={s.key} type="button" className="tw-flow-card" onClick={() => onGo(s.route)}>
          <span className="tw-flow-n">{s.n}</span>
          <span className="tw-flow-body">
            <span className="tw-flow-title">{s.title}</span>
            <span className="tw-flow-text">{s.body}</span>
            <span className="tw-flow-stat mono">{s.stat}</span>
          </span>
          <span className="tw-flow-go" aria-hidden>{Icons.chevronRight({ style: { width: 14, height: 14 } })}</span>
        </button>
      ))}
    </div>
  );
}

export interface StartHereProps {
  isEmpty: boolean;
  counts: { events: number; alerts: number; incidents: number; reports: number };
  nextIncident: { id: number; ref: string; title: string } | null;
  demoBusy: boolean;
  onLoadDemo: () => void;
  onGo: (r: RouteKey) => void;
  onOpenIncident: (id: number) => void;
  onDismiss: () => void;
}

/** State-aware "do this next" panel. Teaches the workflow in place. */
export function StartHere(p: StartHereProps) {
  const { counts: c, isEmpty } = p;
  return (
    <section className="tw-start">
      <header className="tw-start-head">
        <div>
          <h2 className="tw-start-title">
            {isEmpty ? "Start here" : "Where to go next"}
          </h2>
          <p className="tw-start-sub">
            {isEmpty
              ? "SentinelGraph turns raw telemetry into an investigation you can defend. Four stages, in order:"
              : "You have evidence loaded. Each card below is one stage of the investigation — click any of them."}
          </p>
        </div>
        <button className="tw-start-x" type="button" onClick={p.onDismiss}
                title="Hide this guide (bring it back from Settings)">
          {Icons.close({ style: { width: 14, height: 14 } })}
        </button>
      </header>

      <WorkflowStrip
        onGo={p.onGo}
        steps={[
          { key: "import", n: 1, route: "import", title: "Bring evidence in",
            body: "Import Sysmon / log exports, or load the synthetic demo set. Nothing is analysed until it is stored.",
            stat: `${c.events} event(s) stored` },
          { key: "rules", n: 2, route: "rules", title: "See what fired",
            body: "Deterministic rules scan the stored events. A hit is a lead with cited evidence — not a verdict.",
            stat: `${c.alerts} alert(s)` },
          { key: "incidents", n: 3, route: "incidents", title: "Investigate",
            body: "Alerts that share a host or account become one incident, with a timeline and an attack graph.",
            stat: `${c.incidents} incident(s)` },
          { key: "reports", n: 4, route: "reports", title: "Write it up",
            body: "Generate a report where every claim cites stored events. Facts and guesses stay separated.",
            stat: `${c.reports} report(s)` },
        ]}
      />

      <div className="tw-start-next">
        {isEmpty ? (
          <>
            <span className="tw-start-nexttext">
              <strong>No data yet.</strong> The demo dataset is synthetic and clearly labelled —
              it is the fastest way to see the whole pipeline working.
            </span>
            <button className="tw-btn tw-btn-sm tw-btn-primary" type="button"
                    onClick={p.onLoadDemo} disabled={p.demoBusy}>
              {p.demoBusy ? "Loading…" : "Load demo dataset"}
            </button>
          </>
        ) : p.nextIncident ? (
          <>
            <span className="tw-start-nexttext">
              <strong>Next step:</strong> open{" "}
              <span className="mono">{p.nextIncident.ref}</span> — {p.nextIncident.title}
            </span>
            <button className="tw-btn tw-btn-sm tw-btn-primary" type="button"
                    onClick={() => p.onOpenIncident(p.nextIncident!.id)}>
              Investigate {p.nextIncident.ref}
            </button>
          </>
        ) : (
          <>
            <span className="tw-start-nexttext">
              <strong>Nothing is waiting on you.</strong> Import more telemetry or re-check the rules.
            </span>
            <button className="tw-btn tw-btn-sm" type="button" onClick={() => p.onGo("import")}>
              Go to Imports
            </button>
          </>
        )}
      </div>

      <details className="tw-start-terms" open>
        <summary>What the words mean</summary>
        <KeyTerms />
      </details>
    </section>
  );
}

const TERMS: Array<[string, string]> = [
  ["Event", "One normalised log line. The raw material everything else is built from."],
  ["Alert", "A detection rule matched these events. A lead worth checking, not a conclusion."],
  ["Incident", "Alerts sharing a host or account, merged so you investigate once, not ten times."],
  ["Evidence", "The stored events behind a claim. Open any finding and you land on them."],
  ["AI", "Helps read and write up. It never decides what is true — the evidence does."],
];

/** Plain-language glossary so nobody has to open a manual to read the screen. */
export function KeyTerms() {
  return (
    <div className="tw-terms">
      {TERMS.map(([term, text]) => (
        <div className="tw-term" key={term}>
          <span className="tw-term-name">{term}</span>
          <span className="tw-term-text">{text}</span>
        </div>
      ))}
      <p className="tw-terms-note">
        Facts and hypotheses are always kept visually apart: what was observed is
        marked separately from what is inferred.
      </p>
    </div>
  );
}
