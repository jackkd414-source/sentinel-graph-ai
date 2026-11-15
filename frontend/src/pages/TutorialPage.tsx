/**
 * Usage tutorial — a separate tab so nobody has to leave the app to learn it.
 *
 * English is the source text here; the i18n layer (src/i18n.tsx) renders it in
 * Indonesian when that language is selected, like every other screen.
 */
import { PageHeader } from "../components/layout";
import { Icons } from "../components/icons";
import type { RouteKey } from "../routes";

interface Step {
  n: number;
  title: string;
  body: string[];
  cta?: { label: string; route: RouteKey };
}

const STEPS: Step[] = [
  {
    n: 1,
    title: "Open the app",
    body: [
      "The workspace opens on the Dashboard. Every number there is live — it reflects the database, not a mock.",
      "Nothing works without data, so this is always the first step.",
    ],
    cta: { label: "Go to Dashboard", route: "dashboard" },
  },
  {
    n: 2,
    title: "Get data in",
    body: [
      "Load the demo dataset from the Dashboard, or import your own Sysmon / JSON / CSV export under Imports.",
      "Everything you import is stored with its SHA-256, so you can prove later exactly which bytes were analysed.",
      "The demo dataset is synthetic and labelled as such. Use it freely to explore.",
    ],
    cta: { label: "Go to Imports", route: "import" },
  },
  {
    n: 3,
    title: "Read the detections",
    body: [
      "Open Detection Rules and read what fired.",
      "Each alert cites the exact events that triggered it. A detection is a lead to check, never a conclusion.",
      "You can toggle a rule off and the whole pipeline re-runs — useful to see what one rule contributes.",
    ],
    cta: { label: "Go to Detection Rules", route: "rules" },
  },
  {
    n: 4,
    title: "Open an incident",
    body: [
      "Alerts that share a host or account are already grouped into one incident. Open the one that matters.",
      "Inside an incident you get the summary, the timeline, the findings and the linked evidence in one place.",
      "Mark it as investigating or closed as you work. Status is yours to set — the tool does not guess it.",
    ],
    cta: { label: "Open Incidents", route: "incidents" },
  },
  {
    n: 5,
    title: "Follow the attack graph",
    body: [
      "The graph shows how entities relate, derived from the events themselves.",
      "Solid edges are observed relationships; dashed edges are inferred. Hover or click a node for detail.",
      "Start from the incident scope and switch to the global graph when you want the wider picture.",
    ],
    cta: { label: "Go to Attack Graph", route: "graph" },
  },
  {
    n: 6,
    title: "Check the evidence",
    body: [
      "Open Evidence Repository to see the exact stored records behind any claim.",
      "The raw record is shown as stored — nothing is paraphrased, so you can verify by hand.",
      "If a citation points at an event that is missing, the report says so instead of hiding it.",
    ],
    cta: { label: "Go to Evidence Repository", route: "evidence" },
  },
  {
    n: 7,
    title: "Write the report",
    body: [
      "Pick an incident and generate Markdown, HTML or JSON. Every claim in the output cites stored events.",
      "Facts are stated as facts; anything inferred is marked as a hypothesis. Nothing is invented to fill a gap.",
    ],
    cta: { label: "Go to Reports", route: "reports" },
  },
  {
    n: 8,
    title: "Add AI (optional)",
    body: [
      "The app runs completely without AI. Detection, correlation, the graph, the timeline and reports all work.",
      "If you want model-written narrative, add a provider under AI Providers. Keys are encrypted before storage.",
      "AI never replaces the evidence: its output is fenced, labelled, and clearly marked as interpretation.",
    ],
    cta: { label: "Go to AI Providers", route: "providers" },
  },
  {
    n: 9,
    title: "Tune the rules",
    body: [
      "Rules are deterministic functions over normalized events.",
      "Read one, understand what it matches, and disable the ones that do not fit your environment.",
    ],
    cta: { label: "Go to Detection Rules", route: "rules" },
  },
];

export function TutorialPage({ onNavigate }: { onNavigate: (r: RouteKey) => void }) {
  return (
    <>
      <PageHeader
        title="How to use SentinelGraph"
        subtitle="A guided tour of the whole workflow — no manual needed. Work through it top to bottom, or jump to a step."
      />

      <ol className="tw-tut-index">
        {STEPS.map((s) => (
          <li key={s.n}>
            <a href={`#tw-step-${s.n}`}>{s.title}</a>
          </li>
        ))}
      </ol>

      <div className="tw-tut">
        {STEPS.map((s) => (
          <section className="tw-tut-step" id={`tw-step-${s.n}`} key={s.n}>
            <span className="tw-tut-n">{s.n}</span>
            <div className="tw-tut-body">
              <h2 className="tw-tut-title">{s.title}</h2>
              {s.body.map((p) => <p className="tw-tut-text" key={p}>{p}</p>)}
              {s.cta ? (
                <button className="tw-btn tw-btn-sm" type="button"
                        onClick={() => onNavigate(s.cta!.route)}>
                  {s.cta.label}
                  {Icons.chevronRight({ style: { width: 13, height: 13 } })}
                </button>
              ) : null}
            </div>
          </section>
        ))}

        <p className="tw-tut-end">
          That is the whole loop. Import, detect, investigate, report — repeat.
        </p>
      </div>
    </>
  );
}
