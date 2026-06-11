"use client";

import { Suspense } from "react";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { FindingsWorkbench } from "@/components/findings-workbench";
import { StatCard } from "@/components/stat-card";
import { fetchFindings, fetchScan } from "@/lib/api";

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
  const rawTotal = scan.data ? (breakdown ? breakdown.new + breakdown.recurring + breakdown.changed : 0) : undefined;

  return (
    <main id="main-content" className="space-y-5">
      <section className="grid gap-4 md:grid-cols-4">
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
