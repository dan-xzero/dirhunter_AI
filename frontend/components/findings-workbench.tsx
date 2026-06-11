"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { RefreshCcw, Search, SlidersHorizontal } from "lucide-react";
import { Chip } from "@/components/chip";
import { FindingPanel } from "@/components/finding-panel";
import { Button, EmptyState, ErrorState, Select, Skeleton } from "@/components/ui";
import { fetchFinding, fetchFindings } from "@/lib/api";
import type { Finding } from "@/lib/types";

const PAGE_SIZE = 100;
const SEARCH_DEBOUNCE_MS = 300;
const TAG_OPTIONS = ["Admin Panel", "Development/Test", "API Documentation", "Login Panel", "Other", "Unknown"];

type Filters = {
  q: string;
  status: string;
  verdict: string;
  triage: string;
  tag: string;
  includeLikelyFp: boolean;
  includeUnvalidated: boolean;
  offset: number;
};

export function FindingsWorkbench({ scanId }: { scanId?: string }) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const parentRef = useRef<HTMLDivElement>(null);
  const findingParam = searchParams.get("finding");
  const linkedFindingId = findingParam && Number.isFinite(Number(findingParam)) ? Number(findingParam) : null;

  const filters = useMemo<Filters>(
    () => ({
      q: searchParams.get("q") ?? "",
      status: searchParams.get("status") ?? "",
      verdict: searchParams.get("verdict") ?? "",
      triage: searchParams.get("triage") ?? "",
      tag: searchParams.get("tag") ?? "",
      includeLikelyFp: searchParams.get("include_likely_fp") === "true",
      includeUnvalidated: searchParams.get("include_unvalidated") === "true",
      offset: Number(searchParams.get("offset") ?? "0") || 0
    }),
    [searchParams]
  );

  const hasActiveFilters =
    Boolean(filters.q) ||
    Boolean(filters.status) ||
    Boolean(filters.verdict) ||
    Boolean(filters.triage) ||
    Boolean(filters.tag) ||
    filters.includeLikelyFp ||
    filters.includeUnvalidated;

  function setFilter(key: keyof Filters, value: string | boolean | number) {
    const params = new URLSearchParams(searchParams.toString());
    const paramKey =
      key === "includeLikelyFp" ? "include_likely_fp" : key === "includeUnvalidated" ? "include_unvalidated" : key;
    const isEmpty = value === "" || value === false || value === 0;
    if (isEmpty) {
      params.delete(String(paramKey));
    } else {
      params.set(String(paramKey), String(value));
    }
    if (key !== "offset") {
      params.delete("offset");
    }
    const next = params.toString();
    router.replace(next ? `${pathname}?${next}` : pathname, { scroll: false });
  }

  function clearFilters() {
    const params = new URLSearchParams(searchParams.toString());
    const finding = params.get("finding");
    const reset = new URLSearchParams();
    if (finding) reset.set("finding", finding);
    const next = reset.toString();
    router.replace(next ? `${pathname}?${next}` : pathname, { scroll: false });
  }

  function setSelectedFinding(finding: Finding | null) {
    setSelected(finding);
    const params = new URLSearchParams(searchParams.toString());
    if (finding) {
      params.set("finding", String(finding.id));
    } else {
      params.delete("finding");
    }
    const next = params.toString();
    router.replace(next ? `${pathname}?${next}` : pathname, { scroll: false });
  }

  // Debounced search: keep a local input value and commit to the URL/query after a pause.
  const [searchInput, setSearchInput] = useState(filters.q);
  const lastCommitted = useRef(filters.q);

  useEffect(() => {
    if (filters.q !== lastCommitted.current) {
      setSearchInput(filters.q);
      lastCommitted.current = filters.q;
    }
  }, [filters.q]);

  useEffect(() => {
    if (searchInput === filters.q) return;
    const timer = setTimeout(() => {
      lastCommitted.current = searchInput;
      setFilter("q", searchInput);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInput]);

  const searchPending = searchInput !== filters.q;

  const query = useQuery({
    queryKey: ["findings", scanId, filters],
    queryFn: () =>
      fetchFindings({
        scan_id: scanId,
        q: filters.q,
        status: filters.status,
        verdict: filters.verdict,
        triage: filters.triage,
        tag: filters.tag,
        include_likely_fp: filters.includeLikelyFp,
        include_unvalidated: filters.includeUnvalidated,
        limit: PAGE_SIZE,
        offset: filters.offset
      })
  });
  const linkedFinding = useQuery({
    queryKey: ["finding", linkedFindingId],
    queryFn: () => fetchFinding(linkedFindingId!),
    enabled: linkedFindingId !== null
  });

  useEffect(() => {
    if (linkedFinding.data && matchesFilters(linkedFinding.data, filters, scanId)) {
      setSelected(linkedFinding.data);
    } else if (linkedFinding.data) {
      setSelectedFinding(null);
    } else if (linkedFindingId === null) {
      setSelected(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linkedFinding.data, linkedFindingId, filters, scanId]);

  const rows = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 74,
    overscan: 8
  });
  const virtualRows = rowVirtualizer.getVirtualItems();
  const showingStart = total === 0 ? 0 : filters.offset + 1;
  const showingEnd = Math.min(filters.offset + rows.length, total);
  const canPrev = filters.offset > 0;
  const canNext = filters.offset + PAGE_SIZE < total;

  const dataReady = !query.isLoading && !query.isError;
  const isEmpty = dataReady && rows.length === 0;
  const showResults = dataReady && rows.length > 0;

  return (
    <section className="grid gap-5 lg:grid-cols-[18rem_minmax(0,1fr)]">
      <button
        type="button"
        onClick={() => setFiltersOpen((open) => !open)}
        aria-expanded={filtersOpen}
        aria-controls="findings-filters"
        className="flex items-center justify-center gap-2 rounded-2xl border border-line bg-panel-soft px-4 py-3 text-sm text-ink transition hover:border-line-hard lg:hidden"
      >
        <SlidersHorizontal className="h-4 w-4" />
        {filtersOpen ? "Hide filters" : "Filters"}
        {hasActiveFilters ? <span className="ml-1 rounded-full bg-teal-dim px-2 py-0.5 text-xs text-teal">on</span> : null}
      </button>

      <aside id="findings-filters" className={`glass h-fit rounded-2xl p-4 ${filtersOpen ? "block" : "hidden"} lg:block`}>
        <div className="flex items-center justify-between">
          <p className="text-sm uppercase tracking-[0.24em] text-muted">Filters</p>
          {hasActiveFilters ? (
            <button type="button" onClick={clearFilters} className="text-xs font-medium text-teal hover:underline">
              Clear all
            </button>
          ) : null}
        </div>
        <label className="mt-4 block text-sm text-muted">
          Search
          <span className="mt-2 flex items-center gap-2 rounded-xl border border-line bg-panel-soft px-3 py-2 focus-within:border-teal/45">
            <Search className="h-4 w-4 text-muted" />
            <input
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
              className="min-w-0 flex-1 bg-transparent text-sm text-ink outline-none"
              placeholder="domain, URL, text"
              aria-label="Search findings"
            />
          </span>
        </label>
        <FilterSelect label="Status" value={filters.status} onChange={(status) => setFilter("status", status)}>
          <option value="">All</option>
          <option value="new">New</option>
          <option value="existing">Recurring</option>
          <option value="changed">Changed</option>
        </FilterSelect>
        <FilterSelect label="LLM verdict" value={filters.verdict} onChange={(verdict) => setFilter("verdict", verdict)}>
          <option value="">All</option>
          <option value="valid">LLM valid</option>
          <option value="likely_fp">Likely FP</option>
          <option value="inconclusive">Inconclusive</option>
        </FilterSelect>
        <FilterSelect label="Category" value={filters.tag} onChange={(tag) => setFilter("tag", tag)}>
          <option value="">All</option>
          {TAG_OPTIONS.map((tag) => (
            <option key={tag} value={tag}>
              {tag}
            </option>
          ))}
        </FilterSelect>
        <FilterSelect label="Human triage" value={filters.triage} onChange={(triage) => setFilter("triage", triage)}>
          <option value="">All</option>
          <option value="tp">Marked valid</option>
          <option value="fp">False positive</option>
          <option value="needs_review">Needs review</option>
        </FilterSelect>
        <Toggle
          checked={filters.includeLikelyFp}
          label="Show likely false positives"
          detail="Hidden by default to keep the queue actionable."
          onChange={(checked) => setFilter("includeLikelyFp", checked)}
        />
        <Toggle
          checked={filters.includeUnvalidated}
          label="Show legacy / not validated"
          detail="Migrated records are hidden by default."
          onChange={(checked) => setFilter("includeUnvalidated", checked)}
        />
      </aside>

      <div className="glass min-w-0 overflow-hidden rounded-2xl">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-4">
          <div>
            <p className="text-sm uppercase tracking-[0.24em] text-muted">Findings</p>
            {showResults ? (
              <>
                <h1 className="mt-1 text-2xl font-semibold text-ink">{total} results</h1>
                <p className="mt-1 text-xs text-muted">
                  Showing {showingStart}-{showingEnd} of {total}. Legacy and likely-FP rows stay hidden unless enabled.
                </p>
              </>
            ) : (
              <p className="mt-1 text-sm text-muted">Validated, actionable findings.</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            {searchPending || query.isFetching ? <span className="text-sm text-muted">Refreshing</span> : null}
            <Button variant="ghost" size="sm" onClick={() => query.refetch()}>
              <RefreshCcw className="h-4 w-4" />
              Refresh
            </Button>
          </div>
        </div>

        {showResults ? (
          <div
            className="hidden grid-cols-[1.1fr_0.8fr_1fr_0.6fr_0.7fr_1.7fr] gap-3 border-b border-line bg-obsidian/80 px-5 py-3 text-xs uppercase tracking-[0.18em] text-muted lg:grid"
            role="row"
          >
            <span>Domain</span>
            <span>Category</span>
            <span>Review State</span>
            <span>Confidence</span>
            <span>Signals</span>
            <span>URL</span>
          </div>
        ) : null}

        {query.isLoading ? (
          <div className="space-y-3 p-5">
            {Array.from({ length: 6 }).map((_, index) => (
              <Skeleton key={index} className="h-16 w-full" />
            ))}
          </div>
        ) : null}

        {query.isError ? (
          <div className="p-5">
            <ErrorState
              title="Unable to load findings"
              message={
                query.error instanceof Error
                  ? `${query.error.message}. The backend may be unavailable.`
                  : "The backend may be unavailable."
              }
              onRetry={() => query.refetch()}
            />
          </div>
        ) : null}

        {isEmpty ? (
          <div className="p-5">
            {hasActiveFilters ? (
              <EmptyState
                title="No findings match your filters"
                detail="Your current filters are too narrow. Try clearing them or enabling legacy / likely-FP rows."
                action={
                  <Button variant="subtle" size="sm" onClick={clearFilters}>
                    Clear filters
                  </Button>
                }
              />
            ) : (
              <EmptyState
                title="No findings yet"
                detail="There are no actionable findings for this view. New findings appear here after a scan completes and is validated."
              />
            )}
          </div>
        ) : null}

        {showResults ? (
          <>
            <div ref={parentRef} className="thin-scrollbar hidden h-[calc(100vh-18rem)] overflow-auto lg:block">
              <div className="relative" style={{ height: rowVirtualizer.getTotalSize() }}>
                {virtualRows.map((virtualRow) => {
                  const finding = rows[virtualRow.index];
                  return (
                    <button
                      key={finding.id}
                      type="button"
                      onClick={() => setSelectedFinding(finding)}
                      className="absolute left-0 grid w-full grid-cols-[1.1fr_0.8fr_1fr_0.6fr_0.7fr_1.7fr] gap-3 border-b border-line/70 px-5 py-3 text-left text-sm transition hover:bg-teal-dim"
                      style={{ transform: `translateY(${virtualRow.start}px)`, minHeight: virtualRow.size }}
                    >
                      <DomainCell finding={finding} />
                      <span className="self-center">
                        <Chip value={finding.ai_tag} />
                      </span>
                      <ReviewState finding={finding} />
                      <Confidence finding={finding} />
                      <Signals finding={finding} />
                      <span className="self-center truncate font-mono text-xs text-muted">{finding.url}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            <ul className="divide-y divide-line/70 lg:hidden">
              {rows.map((finding) => (
                <li key={finding.id}>
                  <FindingCard finding={finding} onSelect={() => setSelectedFinding(finding)} />
                </li>
              ))}
            </ul>
          </>
        ) : null}

        {showResults ? (
          <div className="flex items-center justify-between border-t border-line px-5 py-4 text-sm text-muted">
            <span>
              Page {Math.floor(filters.offset / PAGE_SIZE) + 1} of {Math.max(1, Math.ceil(total / PAGE_SIZE))}
            </span>
            <div className="flex gap-2">
              <Button
                variant="ghost"
                size="sm"
                disabled={!canPrev}
                onClick={() => setFilter("offset", Math.max(0, filters.offset - PAGE_SIZE))}
              >
                Previous
              </Button>
              <Button
                variant="ghost"
                size="sm"
                disabled={!canNext}
                onClick={() => setFilter("offset", filters.offset + PAGE_SIZE)}
              >
                Next
              </Button>
            </div>
          </div>
        ) : null}
      </div>

      <FindingPanel finding={selected} onClose={() => setSelectedFinding(null)} />
    </section>
  );
}

function FindingCard({ finding, onSelect }: { finding: Finding; onSelect: () => void }) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className="flex w-full flex-col gap-3 px-5 py-4 text-left transition hover:bg-teal-dim"
    >
      <div className="flex items-start justify-between gap-3">
        <span className="min-w-0">
          <span className="block truncate font-medium text-ink">{finding.domain.host}</span>
          <span className="mt-1 block truncate font-mono text-xs text-muted">{finding.url}</span>
        </span>
        <Confidence finding={finding} />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Chip value={finding.ai_tag} />
        <Chip value={finding.finding_status} />
        <Chip value={finding.triage_events.at(-1)?.label ?? finding.validation?.llm_verdict ?? "not_validated"} />
      </div>
      <Signals finding={finding} />
    </button>
  );
}

function DomainCell({ finding }: { finding: Finding }) {
  return (
    <span className="min-w-0 self-center">
      <span className="block truncate font-medium text-ink">{finding.domain.host}</span>
    </span>
  );
}

function ReviewState({ finding }: { finding: Finding }) {
  const latestTriage = finding.triage_events.at(-1);
  return (
    <span className="flex flex-wrap items-center gap-1 self-center">
      <Chip value={finding.finding_status} />
      <Chip value={latestTriage?.label ?? finding.validation?.llm_verdict ?? "not_validated"} />
    </span>
  );
}

function matchesFilters(finding: Finding, filters: Filters, scanId?: string) {
  const latestTriage = finding.triage_events.at(-1);
  const verdict = finding.validation?.llm_verdict;

  if (scanId && finding.scan_id !== Number(scanId)) return false;
  if (filters.status && finding.finding_status !== filters.status) return false;
  if (filters.tag && finding.ai_tag !== filters.tag) return false;

  if (filters.triage) {
    if (latestTriage?.label !== filters.triage) return false;
  } else if (!filters.includeLikelyFp && latestTriage?.label === "fp") {
    return false;
  }

  if (filters.verdict) {
    if (verdict !== filters.verdict) return false;
  } else {
    if (!filters.includeLikelyFp && verdict === "likely_fp") return false;
    if (!filters.includeUnvalidated && !finding.validation) return false;
  }

  if (filters.q) {
    const needle = filters.q.toLowerCase();
    const haystack = [finding.domain.host, finding.url, finding.body_excerpt ?? ""].join(" ").toLowerCase();
    if (!haystack.includes(needle)) return false;
  }

  return true;
}

function Confidence({ finding }: { finding: Finding }) {
  const confidence = finding.validation?.llm_confidence;
  return (
    <span className="self-center font-mono text-sm text-ink">
      {typeof confidence === "number" ? `${Math.round(confidence * 100)}%` : "-"}
    </span>
  );
}

function Signals({ finding }: { finding: Finding }) {
  const cveCount = finding.tech_detections.reduce((sum, tech) => sum + tech.cves.length, 0);
  return (
    <span className="flex flex-wrap gap-1 self-center text-xs">
      {finding.secrets.length > 0 ? <SignalBadge tone="rose" label={`${finding.secrets.length} secrets`} /> : null}
      {cveCount > 0 ? <SignalBadge tone="amber" label={`${cveCount} CVEs`} /> : null}
      {finding.screenshot_path ? <SignalBadge tone="blue" label="shot" /> : null}
      {finding.secrets.length === 0 && cveCount === 0 && !finding.screenshot_path ? <span className="text-muted">-</span> : null}
    </span>
  );
}

function SignalBadge({ label, tone }: { label: string; tone: "rose" | "amber" | "blue" }) {
  const tones = {
    rose: "border-rose/30 bg-rose-dim text-rose",
    amber: "border-amber/30 bg-amber-dim text-amber",
    blue: "border-blue/30 bg-blue-dim text-blue"
  };
  return <span className={`rounded-full border px-2 py-1 ${tones[tone]}`}>{label}</span>;
}

function Toggle({
  checked,
  label,
  detail,
  onChange
}: {
  checked: boolean;
  label: string;
  detail: string;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="mt-4 flex items-start gap-3 rounded-xl border border-line bg-panel-soft p-3 text-sm text-muted">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="mt-1" />
      <span>
        {label}
        <span className="mt-1 block text-xs text-muted">{detail}</span>
      </span>
    </label>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  children
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  children: ReactNode;
}) {
  return (
    <label className="mt-4 block text-sm text-muted">
      {label}
      <Select value={value} onChange={(event) => onChange(event.target.value)} className="mt-2">
        {children}
      </Select>
    </label>
  );
}
