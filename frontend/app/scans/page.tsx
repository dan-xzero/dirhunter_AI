"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CalendarClock } from "lucide-react";
import { Chip } from "@/components/chip";
import { EmptyState, ErrorState, PageHeader, Skeleton } from "@/components/ui";
import { fetchScans } from "@/lib/api";
import { emptyCriticalityBreakdown, emptyStatusBreakdown } from "@/lib/status";
import type { Scan } from "@/lib/types";

export default function ScansPage() {
  const scans = useQuery({ queryKey: ["scans", 100], queryFn: () => fetchScans(100) });

  return (
    <main id="main-content" className="space-y-5">
      <section className="glass rounded-3xl p-6">
        <PageHeader
          eyebrow="Scan history"
          title="Every scan, with its own findings."
          description="Open any scan to see only the findings from that run. Counts below are raw New, Recurring, and Changed totals; each scan detail view hides likely false positives by default."
        />
      </section>

      <section className="space-y-3">
        {scans.isLoading ? (
          <>
            <Skeleton className="h-28 w-full rounded-2xl" />
            <Skeleton className="h-28 w-full rounded-2xl" />
            <Skeleton className="h-28 w-full rounded-2xl" />
          </>
        ) : scans.isError ? (
          <ErrorState
            title="Unable to load scans"
            message={
              scans.error instanceof Error
                ? `${scans.error.message}. The backend may be unavailable.`
                : "The backend may be unavailable."
            }
            onRetry={() => scans.refetch()}
          />
        ) : scans.data && scans.data.items.length === 0 ? (
          <EmptyState
            title="No scans found"
            detail="There are no recorded scans yet. Once DirHunter completes a run, it will show up here."
          />
        ) : (
          scans.data?.items.map((scan) => <ScanCard key={scan.id} scan={scan} />)
        )}
      </section>
    </main>
  );
}

function ScanCard({ scan }: { scan: Scan }) {
  const breakdown = scan.status_breakdown ?? emptyStatusBreakdown();
  const criticality = scan.criticality_breakdown ?? emptyCriticalityBreakdown();
  const started = new Date(scan.started_at).toLocaleString();
  const finished = scan.finished_at ? new Date(scan.finished_at).toLocaleString() : "Still running";
  const urlsScanned = typeof scan.stats?.urls_scanned === "number" ? scan.stats.urls_scanned : 0;

  return (
    <Link
      href={`/scans/${scan.id}`}
      className="glass group grid gap-4 rounded-2xl p-5 transition hover:border-teal/35 lg:grid-cols-[minmax(0,1fr)_auto]"
    >
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="font-mono text-xl font-semibold text-ink">Scan #{scan.id}</h2>
          <Chip value={scan.status} />
          <span className="rounded-full border border-line px-2.5 py-1 text-xs text-muted">{scan.trigger}</span>
        </div>
        <div className="mt-4 grid gap-3 text-sm text-muted md:grid-cols-2">
          <p className="flex items-center gap-2">
            <CalendarClock className="h-4 w-4 text-teal" />
            Started: {started}
          </p>
          <p>Finished: {finished}</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <CountPill label="URLs" value={urlsScanned} />
        <CountPill label="Critical" value={criticality.critical} tone="rose" />
        <CountPill label="High" value={criticality.high} tone="amber" />
        <CountPill label="Medium" value={criticality.medium} tone="blue" />
        <CountPill label="Raw New" value={breakdown.new} />
        <CountPill label="Raw Recurring" value={breakdown.recurring} />
        <CountPill label="Raw Changed" value={breakdown.changed} />
        <ArrowRight className="h-5 w-5 text-muted transition group-hover:translate-x-1 group-hover:text-teal" />
      </div>
    </Link>
  );
}

function CountPill({ label, value, tone = "default" }: { label: string; value: number; tone?: "default" | "rose" | "amber" | "blue" }) {
  const tones = {
    default: "border-line bg-panel-soft text-ink",
    rose: "border-rose/30 bg-rose-dim text-rose",
    amber: "border-amber/30 bg-amber-dim text-amber",
    blue: "border-blue/30 bg-blue-dim text-blue"
  };
  return (
    <span className={`rounded-2xl border px-4 py-3 text-center ${tones[tone]}`}>
      <span className="block text-xs uppercase tracking-[0.18em] text-muted">{label}</span>
      <span className="mt-1 block font-mono text-lg">{value}</span>
    </span>
  );
}
