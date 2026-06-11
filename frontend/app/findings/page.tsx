import { Suspense } from "react";
import { FindingsWorkbench } from "@/components/findings-workbench";

export default function FindingsPage() {
  return (
    <main id="main-content">
      <Suspense fallback={<div className="glass rounded-2xl p-5 text-sm text-muted">Loading findings...</div>}>
        <FindingsWorkbench />
      </Suspense>
    </main>
  );
}
