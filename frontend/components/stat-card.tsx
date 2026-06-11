import { ReactNode } from "react";
import { Skeleton } from "@/components/ui";

export function StatCard({
  label,
  value,
  detail,
  loading = false,
  error = false
}: {
  label: string;
  value?: ReactNode;
  detail?: ReactNode;
  loading?: boolean;
  error?: boolean;
}) {
  return (
    <section className="glass rounded-2xl p-5">
      <p className="text-sm uppercase tracking-[0.24em] text-muted">{label}</p>
      <div className="mt-4 text-3xl font-semibold text-ink">
        {loading ? (
          <Skeleton className="h-9 w-20" />
        ) : error ? (
          <span className="text-rose" title="Failed to load">
            n/a
          </span>
        ) : (
          value
        )}
      </div>
      {loading ? (
        <Skeleton className="mt-3 h-4 w-32" />
      ) : detail ? (
        <div className="mt-3 text-sm text-muted">{detail}</div>
      ) : null}
    </section>
  );
}
