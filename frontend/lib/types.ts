export type Domain = {
  id: number;
  host: string;
  env: string;
  tags: string[];
};

export type Validation = {
  llm_verdict: "valid" | "likely_fp" | "inconclusive" | string;
  llm_confidence: number;
  llm_reasoning?: string | null;
  category_corrected?: string | null;
  model: string;
  tokens_used: number;
  cost_usd: number;
  validated_at: string;
};

export type TriageEvent = {
  id: number;
  user: string;
  label: "tp" | "fp" | "needs_review" | string;
  note?: string | null;
  labeled_at: string;
};

export type Finding = {
  id: number;
  scan_id?: number | null;
  domain: Domain;
  url: string;
  path?: string | null;
  status_code?: number | null;
  content_length?: number | null;
  sha1_hash?: string | null;
  fuzzy_hash?: string | null;
  ai_tag: string;
  ai_priority: number;
  finding_status: string;
  first_seen: string;
  last_seen: string;
  times_seen: number;
  content_changed: boolean;
  screenshot_path?: string | null;
  headers: Record<string, unknown>;
  body_excerpt?: string | null;
  download_meta: Record<string, unknown>;
  validation?: Validation | null;
  triage_events: TriageEvent[];
  secrets: Array<{ id: number; type: string; risk: string; snippet?: string | null; reason?: string | null }>;
  tech_detections: Array<{
    id: number;
    name: string;
    version?: string | null;
    source?: string | null;
    confidence: number;
    cves: Array<{ cve_id: string; severity?: string | null }>;
  }>;
  similar_fp_count: number;
};

export type FindingList = {
  items: Finding[];
  total: number;
  limit: number;
  offset: number;
};

export type Scan = {
  id: number;
  started_at: string;
  finished_at?: string | null;
  trigger: string;
  status: string;
  wordlist?: string | null;
  args: Record<string, unknown>;
  stats: Record<string, unknown>;
  status_breakdown?: {
    new: number;
    recurring: number;
    changed: number;
  } | null;
};

export type ScanList = {
  items: Scan[];
  total: number;
  limit: number;
  offset: number;
};

export type OverviewStats = {
  total_scans: number;
  total_findings: number;
  validated_findings: number;
  legacy_findings: number;
  actionable_findings: number;
  needs_triage: number;
  valid_count: number;
  likely_fp_count: number;
  human_fp_label_ratio: number;
  triage_label_count: number;
  latest_scan?: Scan | null;
  by_status: Record<string, number>;
  raw_by_status: Record<string, number>;
  by_verdict: Record<string, number>;
};
