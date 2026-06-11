import clsx from "clsx";
import { formatStatus } from "@/lib/status";

const tones = {
  new: "border-teal/35 bg-teal-dim text-teal",
  changed: "border-amber/35 bg-amber-dim text-amber",
  existing: "border-line-hard bg-panel-soft text-muted",
  valid: "border-teal/35 bg-teal-dim text-teal",
  likely_fp: "border-rose/35 bg-rose-dim text-rose",
  inconclusive: "border-amber/35 bg-amber-dim text-amber",
  not_validated: "border-line-hard bg-panel-soft text-muted",
  untriaged: "border-line-hard bg-panel-soft text-muted",
  completed: "border-teal/35 bg-teal-dim text-teal",
  running: "border-amber/35 bg-amber-dim text-amber",
  failed: "border-rose/35 bg-rose-dim text-rose",
  fp: "border-rose/35 bg-rose-dim text-rose",
  tp: "border-teal/35 bg-teal-dim text-teal",
  needs_review: "border-amber/35 bg-amber-dim text-amber"
};

export function Chip({ value, className }: { value?: string | null; className?: string }) {
  const key = (value || "unknown") as keyof typeof tones;
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium",
        tones[key] ?? "border-blue/35 bg-blue-dim text-blue",
        className
      )}
    >
      {formatStatus(value)}
    </span>
  );
}
