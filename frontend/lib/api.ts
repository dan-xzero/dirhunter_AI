import type { Finding, FindingList, OverviewStats, Scan, ScanList } from "./types";

const configuredApiBase = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();
export const API_BASE = configuredApiBase && configuredApiBase !== "/" ? configuredApiBase.replace(/\/$/, "") : "";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {})
    },
    cache: "no-store"
  });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export function fetchOverview() {
  return api<OverviewStats>("/api/stats/overview");
}

export function fetchScans(limit = 25, offset = 0) {
  return api<ScanList>(`/api/scans?limit=${limit}&offset=${offset}`);
}

export function fetchScan(scanId: string | number) {
  return api<Scan>(`/api/scans/${scanId}`);
}

export type FindingFilters = {
  scan_id?: string | number;
  domain?: string;
  status?: string;
  tag?: string;
  triage?: string;
  verdict?: string;
  criticality?: string;
  include_likely_fp?: boolean;
  include_unvalidated?: boolean;
  q?: string;
  limit?: number;
  offset?: number;
};

export function fetchFindings(filters: FindingFilters = {}) {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  });
  return api<FindingList>(`/api/findings?${params.toString()}`);
}

export function fetchFinding(findingId: number) {
  return api<Finding>(`/api/findings/${findingId}`);
}

export function triageFinding(findingId: number, label: "tp" | "fp" | "needs_review", note?: string) {
  return api(`/api/findings/${findingId}/triage`, {
    method: "POST",
    body: JSON.stringify({ label, note })
  });
}

export function revalidateFinding(findingId: number) {
  return api<Finding>(`/api/findings/${findingId}/revalidate`, {
    method: "POST"
  });
}

export function screenshotUrl(findingId: number) {
  return `${API_BASE}/api/screenshots/${findingId}`;
}
