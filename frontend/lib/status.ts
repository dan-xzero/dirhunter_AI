export const STATUS_LABELS: Record<string, string> = {
  new: "New",
  existing: "Recurring",
  recurring: "Recurring",
  changed: "Changed",
  valid: "Valid",
  likely_fp: "Likely FP",
  inconclusive: "Inconclusive",
  not_validated: "Not validated",
  unknown: "Unknown",
  untriaged: "Untriaged",
  tp: "Valid",
  fp: "False positive",
  needs_review: "Needs review",
  completed: "Completed",
  running: "Running",
  failed: "Failed"
};

export function formatStatus(value?: string | null): string {
  const key = value || "unknown";
  return STATUS_LABELS[key] ?? key.replaceAll("_", " ");
}

export function emptyStatusBreakdown() {
  return { new: 0, recurring: 0, changed: 0 };
}
