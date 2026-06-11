"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from "react";
import { Check, Copy, ExternalLink, RefreshCcw, RotateCcw, X } from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Chip } from "@/components/chip";
import { Dialog, useDialogTitleId } from "@/components/dialog";
import { Button, IconButton } from "@/components/ui";
import { fetchFinding, revalidateFinding, screenshotUrl, triageFinding } from "@/lib/api";
import type { Finding } from "@/lib/types";

type TriageLabel = "tp" | "fp" | "needs_review";

export function FindingPanel({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const titleId = useDialogTitleId();
  const closeRef = useRef<HTMLButtonElement>(null);
  const [note, setNote] = useState("");
  const [copiedEvidence, setCopiedEvidence] = useState(false);
  const [lastAction, setLastAction] = useState<{ applied: TriageLabel; previous: TriageLabel | null } | null>(null);

  const detailQuery = useQuery({
    queryKey: ["finding", finding?.id],
    queryFn: () => fetchFinding(finding!.id),
    enabled: Boolean(finding?.id)
  });
  const activeFinding = detailQuery.data ?? finding;

  const triageMutation = useMutation({
    mutationFn: ({ id, label, note }: { id: number; label: TriageLabel; note?: string; isUndo?: boolean }) =>
      triageFinding(id, label, note),
    onSuccess: async (_result, variables) => {
      setNote("");
      if (!variables.isUndo) {
        const previous = (activeFinding?.triage_events.at(-1)?.label as TriageLabel | undefined) ?? null;
        setLastAction({ applied: variables.label, previous });
      } else {
        setLastAction(null);
      }
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["findings"] }),
        queryClient.invalidateQueries({ queryKey: ["finding", variables.id] })
      ]);
    }
  });

  const revalidateMutation = useMutation({
    mutationFn: (id: number) => revalidateFinding(id),
    onSuccess: async (updated) => {
      queryClient.setQueryData(["finding", updated.id], updated);
      await queryClient.invalidateQueries({ queryKey: ["findings"] });
    }
  });

  useEffect(() => {
    setLastAction(null);
  }, [finding?.id]);

  function applyTriage(label: TriageLabel) {
    if (!activeFinding) return;
    triageMutation.mutate({ id: activeFinding.id, label, note });
  }

  function undoTriage() {
    if (!activeFinding || !lastAction) return;
    triageMutation.mutate({ id: activeFinding.id, label: lastAction.previous ?? "needs_review", isUndo: true });
  }

  function onPanelKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    if (!activeFinding) return;
    const target = event.target as HTMLElement | null;
    if (target?.closest("input, textarea, select, [contenteditable='true']")) return;
    const key = event.key.toLowerCase();
    if (key === "v" || key === "f" || key === "n") {
      event.preventDefault();
      applyTriage(key === "v" ? "tp" : key === "f" ? "fp" : "needs_review");
    }
  }

  const cves = useMemo(
    () => activeFinding?.tech_detections.flatMap((tech) => tech.cves.map((cve) => ({ ...cve, tech: tech.name }))) ?? [],
    [activeFinding]
  );

  async function copyEvidence() {
    if (!activeFinding) return;
    const text = buildEvidenceText(activeFinding);
    await navigator.clipboard.writeText(text);
    setCopiedEvidence(true);
    window.setTimeout(() => setCopiedEvidence(false), 1800);
  }

  const open = Boolean(activeFinding);
  const latestTriage = activeFinding?.triage_events.at(-1);
  const securityHeaders = summarizeSecurityHeaders(activeFinding?.headers ?? {});

  return (
    <Dialog
      open={open}
      onClose={onClose}
      labelledBy={titleId}
      initialFocusRef={closeRef}
      className="absolute inset-y-0 right-0 flex w-full max-w-2xl flex-col border-l border-line-hard bg-void/95 shadow-2xl backdrop-blur-xl outline-none"
    >
      {activeFinding ? (
        <div className="flex h-full flex-col p-5" onKeyDown={onPanelKeyDown}>
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-sm uppercase tracking-[0.24em] text-muted">{activeFinding.domain.host}</p>
              <h2 id={titleId} className="mt-2 break-words text-2xl font-semibold text-ink">
                {activeFinding.ai_tag}
              </h2>
            </div>
            <IconButton ref={closeRef} onClick={onClose} aria-label="Close finding details">
              <X className="h-5 w-5" />
            </IconButton>
          </div>

          <div className="thin-scrollbar mt-5 flex-1 space-y-5 overflow-y-auto pr-2">
            <div className="flex flex-wrap gap-2">
              <Chip value={activeFinding.finding_status} />
              <Chip value={latestTriage?.label ?? activeFinding.validation?.llm_verdict ?? "not_validated"} />
            </div>

            {activeFinding.similar_fp_count > 0 ? (
              <div className="rounded-2xl border border-rose/30 bg-rose-dim p-4 text-sm leading-6 text-rose">
                Similar past false positives: {activeFinding.similar_fp_count}. This finding matches prior human FP patterns by
                URL or path/category, so review quickly before spending time on it.
              </div>
            ) : null}

            <a
              href={activeFinding.url}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-2 break-all rounded-2xl border border-line bg-panel-soft p-4 text-sm text-blue transition hover:border-blue/40"
            >
              <ExternalLink className="h-4 w-4 shrink-0" />
              {activeFinding.url}
            </a>

            <div className="grid grid-cols-3 gap-3">
              <Metric label="HTTP" value={activeFinding.status_code ?? "-"} />
              <Metric label="Length" value={activeFinding.content_length ?? "-"} />
              <Metric label="Priority" value={activeFinding.ai_priority} />
            </div>

            <Button variant="primary" size="lg" onClick={copyEvidence} className="w-full">
              {copiedEvidence ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              {copiedEvidence ? "Evidence copied" : "Copy evidence summary"}
            </Button>

            <section className="rounded-2xl border border-line bg-panel-soft p-4">
              <h3 className="text-sm uppercase tracking-[0.2em] text-muted">Screenshot</h3>
              {activeFinding.screenshot_path ? (
                <img
                  src={screenshotUrl(activeFinding.id)}
                  alt={`Screenshot of ${activeFinding.url}`}
                  loading="lazy"
                  className="mt-3 max-h-80 w-full rounded-xl border border-line object-contain"
                />
              ) : (
                <p className="mt-3 rounded-xl border border-line bg-void/50 p-4 text-sm leading-6 text-muted">
                  No browser screenshot was captured for this response. Text, XML, JSON, and downloadable findings are reviewed
                  through headers, body evidence, and LLM validation instead of placeholder images.
                </p>
              )}
            </section>

            <section className="rounded-2xl border border-line bg-panel-soft p-4">
              <h3 className="text-sm uppercase tracking-[0.2em] text-muted">Response Details</h3>
              <div className="mt-3 grid gap-3">
                <div>
                  <h4 className="text-xs uppercase tracking-[0.18em] text-muted">Security Header Summary</h4>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {securityHeaders.map((header) => (
                      <SecurityHeaderBadge key={header.label} {...header} />
                    ))}
                  </div>
                </div>

                <EvidenceBlock title="Headers" empty="No response headers were captured.">
                  {Object.entries(activeFinding.headers ?? {}).map(([key, value]) => (
                    <HeaderRow key={key} name={key} value={value} />
                  ))}
                </EvidenceBlock>

                <EvidenceBlock title="Download Metadata" empty="No downloadable/file metadata was captured.">
                  {Object.entries(flattenMeta(activeFinding.download_meta ?? {})).map(([key, value]) => (
                    <HeaderRow key={key} name={key} value={value} />
                  ))}
                </EvidenceBlock>

                <EvidenceBlock title="Identity" empty="No hash or change metadata was captured.">
                  {[
                    activeFinding.path ? <HeaderRow key="path" name="path" value={activeFinding.path} /> : null,
                    <HeaderRow key="content_changed" name="content_changed" value={activeFinding.content_changed ? "yes" : "no"} />,
                    activeFinding.sha1_hash ? <HeaderRow key="sha1" name="sha1_hash" value={activeFinding.sha1_hash} /> : null,
                    activeFinding.fuzzy_hash ? <HeaderRow key="fuzzy" name="fuzzy_hash" value={activeFinding.fuzzy_hash} /> : null
                  ]}
                </EvidenceBlock>
              </div>
            </section>

            <section className="rounded-2xl border border-line bg-panel-soft p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm uppercase tracking-[0.2em] text-muted">Validation</h3>
                  {activeFinding.validation?.category_corrected ? (
                    <p className="mt-2 text-xs text-muted">Corrected category: {activeFinding.validation.category_corrected}</p>
                  ) : null}
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => revalidateMutation.mutate(activeFinding.id)}
                  disabled={revalidateMutation.isPending}
                >
                  <RefreshCcw className="h-3.5 w-3.5" />
                  {revalidateMutation.isPending ? "Validating" : "Revalidate"}
                </Button>
              </div>
              <p className="mt-3 text-sm leading-6 text-ink">
                {activeFinding.validation?.llm_reasoning ?? "No LLM validation has been recorded for this finding yet."}
              </p>
              {activeFinding.validation ? (
                <p className="mt-3 font-mono text-xs text-muted">
                  {Math.round(activeFinding.validation.llm_confidence * 100)}% confidence · {activeFinding.validation.model}
                </p>
              ) : null}
              {revalidateMutation.isError ? (
                <p className="mt-3 text-xs text-rose">
                  {revalidateMutation.error instanceof Error ? revalidateMutation.error.message : "Revalidation failed"}
                </p>
              ) : null}
              {revalidateMutation.isSuccess ? <p className="mt-3 text-xs text-teal">Validation refreshed.</p> : null}
            </section>

            <section className="rounded-2xl border border-line bg-panel-soft p-4">
              <h3 className="text-sm uppercase tracking-[0.2em] text-muted">Security Signals</h3>
              <div className="mt-3 grid gap-3">
                <EvidenceBlock title="Secrets" empty="No secret-like values were extracted.">
                  {activeFinding.secrets.map((secret) => (
                    <div key={secret.id} className="rounded-xl border border-rose/20 bg-rose-dim p-3">
                      <div className="flex flex-wrap gap-2">
                        <Chip value={secret.risk} />
                        <span className="font-mono text-xs text-ink">{secret.type}</span>
                      </div>
                      {secret.snippet ? <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-xs text-muted">{secret.snippet}</pre> : null}
                      {secret.reason ? <p className="mt-2 text-xs text-muted">{secret.reason}</p> : null}
                    </div>
                  ))}
                </EvidenceBlock>

                <EvidenceBlock title="Technology" empty="No technology detections were extracted.">
                  {activeFinding.tech_detections.map((tech) => (
                    <div key={tech.id} className="rounded-xl border border-line bg-void/45 p-3">
                      <p className="font-medium text-ink">
                        {tech.name}
                        {tech.version ? <span className="text-muted"> · {tech.version}</span> : null}
                      </p>
                      <p className="mt-1 text-xs text-muted">
                        {Math.round(tech.confidence * 100)}% confidence{tech.source ? ` · ${tech.source}` : ""}
                      </p>
                    </div>
                  ))}
                </EvidenceBlock>

                <EvidenceBlock title="CVEs" empty="No CVEs were mapped from detected technology.">
                  {cves.map((cve) => (
                    <div key={`${cve.tech}-${cve.cve_id}`} className="rounded-xl border border-amber/20 bg-amber-dim p-3 text-sm text-ink">
                      {cve.cve_id}
                      <span className="text-muted"> · {cve.tech}{cve.severity ? ` · ${cve.severity}` : ""}</span>
                    </div>
                  ))}
                </EvidenceBlock>
              </div>
            </section>

            <section className="rounded-2xl border border-line bg-panel-soft p-4">
              <h3 className="text-sm uppercase tracking-[0.2em] text-muted">Body Evidence</h3>
              <pre className="mt-3 max-h-60 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-5 text-muted">
                {activeFinding.body_excerpt || "No body excerpt captured."}
              </pre>
            </section>

            <section className="rounded-2xl border border-line bg-panel-soft p-4">
              <h3 className="text-sm uppercase tracking-[0.2em] text-muted">Triage</h3>
              <textarea
                value={note}
                onChange={(event) => setNote(event.target.value)}
                placeholder="Optional note for this label"
                className="mt-3 min-h-20 w-full rounded-xl border border-line bg-void/50 p-3 text-sm text-ink outline-none focus:border-teal/45"
              />
              <div className="mt-3 grid grid-cols-3 gap-2">
                <Button variant="subtle" disabled={triageMutation.isPending} onClick={() => applyTriage("tp")}>
                  Valid
                </Button>
                <Button variant="subtle" disabled={triageMutation.isPending} onClick={() => applyTriage("fp")}>
                  False Positive
                </Button>
                <Button variant="subtle" disabled={triageMutation.isPending} onClick={() => applyTriage("needs_review")}>
                  Needs Review
                </Button>
              </div>
              {lastAction ? (
                <div className="mt-3 flex items-center justify-between gap-3 rounded-xl border border-teal/30 bg-teal-dim px-3 py-2 text-xs text-teal">
                  <span>Marked as {labelText(lastAction.applied)}.</span>
                  <button
                    type="button"
                    onClick={undoTriage}
                    disabled={triageMutation.isPending}
                    className="inline-flex items-center gap-1 font-medium underline disabled:opacity-50"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                    Undo
                  </button>
                </div>
              ) : null}
              {triageMutation.isError ? (
                <p className="mt-3 text-xs text-rose">
                  {triageMutation.error instanceof Error ? triageMutation.error.message : "Triage failed"}
                </p>
              ) : null}
              <p className="mt-3 text-xs text-muted">
                Keyboard (while this panel is focused): V = valid, F = false positive, N = needs review. Every action can be undone.
              </p>
              <div className="mt-4 space-y-2">
                {activeFinding.triage_events.length > 0 ? (
                  activeFinding.triage_events.map((event) => (
                    <div key={event.id} className="rounded-xl border border-line bg-void/45 p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Chip value={event.label} />
                        <span className="text-xs text-muted">
                          {event.user} · {new Date(event.labeled_at).toLocaleString()}
                        </span>
                      </div>
                      {event.note ? <p className="mt-2 text-sm text-ink">{event.note}</p> : null}
                    </div>
                  ))
                ) : (
                  <p className="rounded-xl border border-line bg-void/45 p-3 text-sm text-muted">No human triage yet.</p>
                )}
              </div>
            </section>
          </div>
        </div>
      ) : null}
    </Dialog>
  );
}

function labelText(label: TriageLabel) {
  return label === "tp" ? "valid" : label === "fp" ? "false positive" : "needs review";
}

function EvidenceBlock({ title, empty, children }: { title: string; empty: string; children: ReactNode }) {
  const items = Array.isArray(children) ? children.filter(Boolean) : children;
  const hasItems = Array.isArray(items) ? items.length > 0 : Boolean(items);
  return (
    <div>
      <h4 className="text-xs uppercase tracking-[0.18em] text-muted">{title}</h4>
      <div className="mt-2 space-y-2">{hasItems ? items : <p className="text-sm text-muted">{empty}</p>}</div>
    </div>
  );
}

function HeaderRow({ name, value }: { name: string; value: unknown }) {
  return (
    <div className="grid gap-2 rounded-xl border border-line bg-void/45 p-3 text-xs md:grid-cols-[10rem_minmax(0,1fr)]">
      <span className="break-words font-mono uppercase tracking-[0.12em] text-muted">{name}</span>
      <span className="break-words font-mono text-ink">{formatValue(value)}</span>
    </div>
  );
}

function SecurityHeaderBadge({ label, present, detail }: { label: string; present: boolean; detail: string }) {
  return (
    <span
      title={detail}
      className={`rounded-full border px-2.5 py-1 text-xs font-medium ${
        present ? "border-teal/35 bg-teal-dim text-teal" : "border-amber/35 bg-amber-dim text-amber"
      }`}
    >
      {label}: {present ? "set" : "missing"}
    </span>
  );
}

function summarizeSecurityHeaders(headers: Record<string, unknown>) {
  const normalized = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
  return [
    {
      label: "HSTS",
      present: Boolean(normalized["strict-transport-security"]),
      detail: "Strict-Transport-Security reduces downgrade and SSL stripping risk."
    },
    {
      label: "CSP",
      present: Boolean(normalized["content-security-policy"]),
      detail: "Content-Security-Policy reduces XSS and injection blast radius."
    },
    {
      label: "XFO",
      present: Boolean(normalized["x-frame-options"]),
      detail: "X-Frame-Options helps prevent clickjacking."
    },
    {
      label: "XCTO",
      present: Boolean(normalized["x-content-type-options"]),
      detail: "X-Content-Type-Options prevents MIME sniffing."
    },
    {
      label: "Referrer",
      present: Boolean(normalized["referrer-policy"]),
      detail: "Referrer-Policy controls sensitive URL leakage in Referer headers."
    }
  ];
}

function flattenMeta(meta: Record<string, unknown>) {
  const flattened: Record<string, unknown> = {};
  Object.entries(meta).forEach(([key, value]) => {
    if (value === null || value === undefined || value === "" || (Array.isArray(value) && value.length === 0)) {
      return;
    }
    if (typeof value === "object" && !Array.isArray(value)) {
      Object.entries(value as Record<string, unknown>).slice(0, 8).forEach(([childKey, childValue]) => {
        flattened[`${key}.${childKey}`] = childValue;
      });
      return;
    }
    flattened[key] = value;
  });
  return flattened;
}

function buildEvidenceText(finding: Finding): string {
  const headers = Object.entries(finding.headers ?? {})
    .map(([key, value]) => `${key}: ${formatValue(value)}`)
    .join("\n");
  const latestTriage = finding.triage_events.at(-1);
  return [
    `URL: ${finding.url}`,
    `Domain: ${finding.domain.host}`,
    `Status: ${finding.status_code ?? "-"} / Length: ${finding.content_length ?? "-"}`,
    `Category: ${finding.ai_tag}`,
    `Finding status: ${finding.finding_status}`,
    `Review state: ${latestTriage?.label ?? finding.validation?.llm_verdict ?? "not_validated"}`,
    `Confidence: ${finding.validation ? `${Math.round(finding.validation.llm_confidence * 100)}%` : "-"}`,
    `Reason: ${finding.validation?.llm_reasoning ?? "-"}`,
    `Path: ${finding.path ?? "-"}`,
    `SHA1: ${finding.sha1_hash ?? "-"}`,
    `Headers:\n${headers || "-"}`
  ].join("\n");
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-2xl border border-line bg-panel-soft p-3">
      <p className="text-xs uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-2 font-mono text-sm text-ink">{value}</p>
    </div>
  );
}
