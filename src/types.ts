export type AdapterName = "codex" | "claude-code";

export interface SuiteCase {
  id: string;
  repository: string;
  commit: string;
  finding_limit: number;
}

export interface SuiteConfig {
  id: string;
  description: string;
  prompt_version: string;
  pricing_catalog: string;
  cases: SuiteCase[];
  profiles: string[];
}

export interface ModelProfile {
  id: string;
  adapter: AdapterName;
  model: string;
  pricing_key: string;
  cost_mode: "token" | "subscription";
  execution: "docker" | "local";
  harness_version?: string;
}

export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  provenance: "harness" | "transcript" | "manual" | "unavailable";
}

export interface RunMetadata {
  schema_version: "1.0";
  run_id: string;
  suite_id: string;
  case_id: string;
  profile_id: string;
  adapter: AdapterName;
  model: string;
  pricing_key: string;
  cost_mode: "token" | "subscription";
  repository: string;
  commit: string;
  prompt_sha256: string;
  state: "prepared" | "running" | "complete" | "incomplete" | "invalid";
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  usage: TokenUsage;
  cost_usd: number | null;
  cost_basis: "api_equivalent" | "subscription_allocated" | "manual" | "unavailable";
  errors: string[];
}

export interface FindingLocation {
  path: string;
  start_line: number;
  end_line: number;
  symbol: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  confidence: "high" | "medium" | "low";
  cwe: string;
  category: string;
  locations: FindingLocation[];
  entry_point: string;
  source_to_sink: string[];
  preconditions: string[];
  exploitability: string;
  impact: string;
  evidence: string[];
  validation: { status: "confirmed" | "supported" | "unverified"; commands: string[]; observations: string[] };
  remediation: string;
  regression_test: string;
  uncertainty: string;
}

export interface SecurityReport {
  schema_version: "1.0";
  scan_summary: Record<string, unknown>;
  attack_surface: unknown[];
  findings: Finding[];
  top_risks: string[];
  uncertainties: string[];
  next_steps: string[];
  overall_risk: Finding["severity"];
}

export interface ReviewScores {
  validity: number;
  evidence: number;
  exploitability: number;
  severity_calibration: number;
  remediation: number;
  regression_test: number;
}

export interface ReviewDecision {
  schema_version: "1.0";
  review_id: string;
  reviewer_id: string;
  blinded_finding_id: string;
  disposition: "accepted" | "rejected" | "duplicate";
  scores: ReviewScores;
  hallucinated_references: number;
  unsafe_payload: boolean;
  duplicate_of: string | null;
  notes: string;
  created_at: string;
}

export interface ScanReviewDecision {
  schema_version: "1.0";
  review_id: string;
  reviewer_id: string;
  blinded_scan_id: string;
  attack_surface_mapping: number;
  prioritization_quality: number;
  notes: string;
  created_at: string;
}
