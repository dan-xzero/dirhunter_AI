"use client";

import { Suspense } from "react";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { FindingsWorkbench } from "@/components/findings-workbench";
import { StatCard } from "@/components/stat-card";
import { fetchFindings, fetchScan } from "@/lib/api";
import { emptyCriticalityBreakdown } from "@/lib/status";

export default function ScanPage() {
  const params = useParams<{ id: string }>();
  const scan = useQuery({ queryKey: ["scan", params.id], queryFn: () => fetchScan(params.id) });
  const actionable = useQuery({
    queryKey: ["scan-actionable-findings", params.id],
    queryFn: () => fetchFindings({ scan_id: params.id, include_unvalidated: false, include_likely_fp: false, limit: 1 })
  });
  const suppressed = useQuery({
    queryKey: ["scan-suppressed-findings", params.id],
    queryFn: () => fetchFindings({ scan_id: params.id, verdict: "likely_fp", limit: 1 })
  });

  const breakdown = scan.data?.status_breakdown;
  const criticality = scan.data?.criticality_breakdown ?? emptyCriticalityBreakdown();
  const rawTotal = scan.data ? (breakdown ? breakdown.new + breakdown.recurring + breakdown.changed : 0) : undefined;
  const urlsScanned = typeof scan.data?.stats?.urls_scanned === "number" ? scan.data.stats.urls_scanned : 0;

  return (
    <main id="main-content" className="space-y-5">
      <section className="grid gap-4 md:grid-cols-4 xl:grid-cols-7">
        <StatCard
          label="Scan"
          value={`#${params.id}`}
          detail={scan.isError ? "Failed to load scan" : (scan.data?.trigger ?? "")}
          loading={scan.isLoading}
          error={scan.isError}
        />
        <StatCard
          label="Actionable"
          value={actionable.data?.total}
          detail="Default queue after LLM suppression"
          loading={actionable.isLoading}
          error={actionable.isError}
        />
        <StatCard
          label="Suppressed FP"
          value={suppressed.data?.total}
          detail="Likely false positives kept for audit"
          loading={suppressed.isLoading}
          error={suppressed.isError}
        />
        <StatCard
          label="High"
          value={criticality.high}
          detail={`${criticality.critical} critical`}
          loading={scan.isLoading}
          error={scan.isError}
        />
        <StatCard
          label="Medium"
          value={criticality.medium}
          detail={`${criticality.low} low`}
          loading={scan.isLoading}
          error={scan.isError}
        />
        <StatCard
          label="URLs Scanned"
          value={urlsScanned}
          detail="Wordlist candidates attempted"
          loading={scan.isLoading}
          error={scan.isError}
        />
        <StatCard
          label="Raw Findings"
          value={rawTotal}
          detail={
            breakdown
              ? `New ${breakdown.new} / Recurring ${breakdown.recurring} / Changed ${breakdown.changed}`
              : undefined
          }
          loading={scan.isLoading}
          error={scan.isError}
        />
      </section>
      <Suspense fallback={<div className="glass rounded-2xl p-5 text-sm text-muted">Loading scan findings...</div>}>
        <FindingsWorkbench scanId={params.id} />
      </Suspense>
    </main>
  );
}
