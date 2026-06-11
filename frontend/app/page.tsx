"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, ShieldCheck, TriangleAlert } from "lucide-react";
import { Chip } from "@/components/chip";
import { StatCard } from "@/components/stat-card";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui";
import { fetchOverview, fetchScans } from "@/lib/api";
import { formatStatus } from "@/lib/status";

export default function OverviewPage() {
  const overview = useQuery({ queryKey: ["overview"], queryFn: fetchOverview });
  const scans = useQuery({ queryKey: ["scans", 5], queryFn: () => fetchScans(5) });

  const stats = overview.data;
  const verdictTotal = Object.values(stats?.by_verdict ?? {}).reduce((sum, count) => sum + count, 0);

  return (
    <main id="main-content" className="space-y-5">
      <section className="glass rounded-3xl p-6">
        <div className="max-w-3xl">
          <p className="text-sm uppercase tracking-[0.32em] text-teal">Less noise, faster validation</p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-ink md:text-5xl">
            Start with the real queue.
          </h1>
          <p className="mt-4 max-w-2xl text-base leading-7 text-muted">
            Actionable means LLM-reviewed and not suppressed as likely false positive. Raw legacy rows are still available, but no longer dominate the dashboard.
          </p>
          <Link
            href="/findings"
            className="mt-6 inline-flex items-center gap-2 rounded-2xl border border-teal/35 bg-teal-dim px-5 py-3 text-sm font-medium text-teal transition hover:bg-teal/15"
          >
            Open findings queue <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>

      {overview.isError ? (
        <ErrorState
          title="Unable to load dashboard metrics"
          message={
            overview.error instanceof Error
              ? `${overview.error.message}. The backend may be unavailable.`
              : "The backend may be unavailable."
          }
          onRetry={() => overview.refetch()}
        />
      ) : (
        <>
          <section className="grid gap-4 md:grid-cols-4">
            <StatCard
              label="Actionable"
              value={stats?.actionable_findings}
              detail="Validated and not likely FP"
              loading={overview.isLoading}
            />
            <StatCard
              label="Needs Triage"
              value={stats?.needs_triage}
              detail="LLM inconclusive only"
              loading={overview.isLoading}
            />
            <StatCard
              label="Suppressed FP"
              value={stats?.likely_fp_count}
              detail="Hidden from default queue"
              loading={overview.isLoading}
            />
            <StatCard label="Valid" value={stats?.valid_count} detail="LLM-valid findings" loading={overview.isLoading} />
          </section>

          <section className="glass rounded-2xl p-5">
            {overview.isLoading ? (
              <div className="space-y-4">
                <Skeleton className="h-4 w-40" />
                <Skeleton className="h-3 w-full" />
                <Skeleton className="h-3 w-2/3" />
              </div>
            ) : (
              <>
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <p className="text-sm uppercase tracking-[0.24em] text-muted">Data scope</p>
                    <p className="mt-2 text-sm text-muted">
                      {stats?.total_findings ?? 0} total / {stats?.legacy_findings ?? 0} legacy unreviewed /{" "}
                      {stats?.validated_findings ?? 0} LLM-reviewed.
                    </p>
                  </div>
                  <p className="text-sm text-muted">
                    Human FP labels:{" "}
                    {stats && stats.triage_label_count > 0
                      ? `${Math.round(stats.human_fp_label_ratio * 100)}% of ${stats.triage_label_count} labels`
                      : "no sample yet"}
                  </p>
                </div>
                <div className="mt-4 overflow-hidden rounded-full border border-line bg-void/60">
                  <div className="flex h-3" role="img" aria-label={verdictBarLabel(stats?.by_verdict)}>
                    {Object.entries(stats?.by_verdict ?? {}).map(([verdict, count]) => (
                      <div
                        key={verdict}
                        title={`${formatStatus(verdict)}: ${count}`}
                        className={verdict === "likely_fp" ? "bg-rose" : verdict === "inconclusive" ? "bg-amber" : "bg-teal"}
                        style={{ width: `${verdictTotal ? (count / verdictTotal) * 100 : 0}%` }}
                      />
                    ))}
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-3">
                  {Object.entries(stats?.by_verdict ?? {}).map(([verdict, count]) => (
                    <span key={verdict} className="flex items-center gap-1.5 text-xs text-muted">
                      <span
                        aria-hidden="true"
                        className={`h-2.5 w-2.5 rounded-full ${
                          verdict === "likely_fp" ? "bg-rose" : verdict === "inconclusive" ? "bg-amber" : "bg-teal"
                        }`}
                      />
                      {formatStatus(verdict)}: <span className="font-mono text-ink">{count}</span>
                    </span>
                  ))}
                </div>
              </>
            )}
          </section>
        </>
      )}

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="glass rounded-2xl p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-xl font-semibold text-ink">Recent Scans</h2>
            <ShieldCheck className="h-5 w-5 text-teal" />
          </div>
          {scans.isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          ) : scans.isError ? (
            <ErrorState
              title="Couldn't load recent scans"
              message={scans.error instanceof Error ? scans.error.message : undefined}
              onRetry={() => scans.refetch()}
            />
          ) : scans.data && scans.data.items.length === 0 ? (
            <EmptyState title="No scans yet" detail="Recent scan runs will appear here once DirHunter starts scanning." />
          ) : (
            <div className="space-y-3">
              {scans.data?.items.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="flex items-center justify-between rounded-2xl border border-line bg-panel-soft p-4 transition hover:border-teal/35"
                >
                  <div>
                    <p className="font-mono text-sm text-ink">Scan #{scan.id}</p>
                    <p className="mt-1 text-sm text-muted">{new Date(scan.started_at).toLocaleString()}</p>
                  </div>
                  <Chip value={scan.status} />
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="glass rounded-2xl p-5">
          <TriangleAlert className="h-6 w-6 text-amber" />
          <h2 className="mt-4 text-xl font-semibold text-ink">Next Best Action</h2>
          <p className="mt-3 text-sm leading-6 text-muted">
            Start with the needs-triage queue. Every LLM-inconclusive finding can be marked from the side panel, and those labels feed future validation prompts.
          </p>
          <Link href="/findings?verdict=inconclusive" className="mt-5 inline-flex text-sm font-medium text-teal">
            Review inconclusive findings <ArrowRight className="ml-2 h-4 w-4" />
          </Link>
        </div>
      </section>
    </main>
  );
}

function verdictBarLabel(byVerdict?: Record<string, number>) {
  const entries = Object.entries(byVerdict ?? {});
  if (entries.length === 0) return "Verdict distribution: no data";
  return `Verdict distribution: ${entries.map(([verdict, count]) => `${formatStatus(verdict)} ${count}`).join(", ")}`;
}
