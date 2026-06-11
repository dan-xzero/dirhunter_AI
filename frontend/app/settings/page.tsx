import { Database, Lock, MessageSquare, Sparkles } from "lucide-react";
import { PageHeader } from "@/components/ui";

type SettingItem = {
  label: string;
  envVar: string;
  description: string;
  secret?: boolean;
};

type SettingGroup = {
  icon: React.ReactNode;
  title: string;
  summary: string;
  items: SettingItem[];
};

const GROUPS: SettingGroup[] = [
  {
    icon: <Database className="h-5 w-5" />,
    title: "Storage",
    summary: "Where findings and scan history are persisted.",
    items: [
      { label: "Database engine", envVar: "USE_PG", description: "Primary datastore for findings, scans, and triage events." },
      { label: "Dual write", envVar: "USE_PG", description: "Mirror writes to Postgres alongside the legacy store during migration." },
      { label: "Legacy HTML reports", envVar: "USE_LEGACY_HTML", description: "Keep generating the original static HTML report output." }
    ]
  },
  {
    icon: <Sparkles className="h-5 w-5" />,
    title: "Validation",
    summary: "Models and budget for LLM-assisted review.",
    items: [
      { label: "Vision model", envVar: "OPENAI_MODEL_VISION", description: "Model used to review screenshots and visual evidence." },
      { label: "Validator model", envVar: "OPENAI_MODEL_VALIDATOR", description: "Model that classifies findings as valid, likely FP, or inconclusive." },
      { label: "Spend budget", envVar: "LLM_BUDGET_USD", description: "Per-run ceiling for LLM spend before validation pauses." }
    ]
  },
  {
    icon: <MessageSquare className="h-5 w-5" />,
    title: "Slack",
    summary: "Digest delivery and portal deep links.",
    items: [
      { label: "Digest delivery", envVar: "USE_NEW_SLACK", description: "Send the new structured findings digest to Slack." },
      { label: "Portal base URL", envVar: "PORTAL_BASE_URL", description: "Base URL used to build deep links from Slack into this portal." },
      { label: "Signing secret", envVar: "SLACK_SIGNING_SECRET", description: "Verifies inbound Slack requests.", secret: true }
    ]
  }
];

export default function SettingsPage() {
  return (
    <main id="main-content" className="space-y-5">
      <section className="glass rounded-3xl p-6">
        <PageHeader
          eyebrow="Configuration"
          title="Settings"
          description="These values are configured via environment variables on the server and shown here read-only for reference. Update them in your deployment environment, then restart the affected services."
        />
      </section>

      <div className="grid gap-5 lg:grid-cols-3">
        {GROUPS.map((group) => (
          <SettingsCard key={group.title} {...group} />
        ))}
      </div>
    </main>
  );
}

function SettingsCard({ icon, title, summary, items }: SettingGroup) {
  return (
    <section className="glass rounded-2xl p-5">
      <div className="flex items-center gap-3 text-teal">
        {icon}
        <h2 className="text-xl font-semibold text-ink">{title}</h2>
      </div>
      <p className="mt-2 text-sm text-muted">{summary}</p>
      <dl className="mt-5 space-y-3">
        {items.map((item) => (
          <div key={`${title}-${item.label}`} className="rounded-2xl border border-line bg-panel-soft p-4">
            <dt className="flex items-center justify-between gap-2">
              <span className="text-sm font-medium text-ink">{item.label}</span>
              {item.secret ? (
                <span className="inline-flex items-center gap-1 rounded-full border border-amber/35 bg-amber-dim px-2 py-0.5 text-xs text-amber">
                  <Lock className="h-3 w-3" />
                  Secret
                </span>
              ) : null}
            </dt>
            <dd className="mt-2">
              <code className="font-mono text-xs text-muted">{item.secret ? maskSecret(item.envVar) : item.envVar}</code>
              <p className="mt-2 text-xs leading-5 text-muted">{item.description}</p>
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function maskSecret(envVar: string) {
  return `${envVar} = ••••••••`;
}
