export type AdapterName = "codex" | "claude-code";

export type CaseDifficulty = "easy" | "medium" | "hard";

export interface SuiteCase {
  id: string;
  repository: string;
  /** Vulnerable commit to scan directly. Set this OR fix_commit, not both. */
  commit?: string;
  /** Security-fix commit. The harness scans fix_commit~1 and derives ground truth from the fix diff. */
  fix_commit?: string;
  /** Optional analyst hint used only to stratify the detection report. */
  difficulty?: CaseDifficulty;
  /**
   * Accepted CWE id(s) for the patched vulnerability, copied from the advisory
   * (e.g. "CWE-79"). When set, a location hit only counts as detected if some
   * on-target finding reports a matching CWE; otherwise it scores location-only.
   */
  cwe?: string | string[];
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
  /**
   * Model training-data cutoff (ISO date). Cases whose fix commit predates it
   * are flagged as memorization-risk in the detection report.
   */
  training_cutoff?: string;
}

export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  provenance: "harness" | "transcript" | "manual" | "unavailable";
}

/**
 * "scan" runs target the vulnerable commit (fix_commit~1). "control" runs
 * target fix_commit itself: the bug is provably gone, so any finding that
 * lands on the patched region is a confirmed false positive. Absent = "scan".
 */
export type RunVariant = "scan" | "control";

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
  variant?: RunVariant;
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

export interface TruthRegion {
  file: string;
  start_line: number;
  end_line: number;
}

export interface TruthCase {
  schema_version: "1.0";
  case_id: string;
  repository: string;
  fix_commit: string;
  scan_commit: string;
  /** Committer date of fix_commit (ISO). Compared to profile training cutoffs. */
  fix_committed_at: string;
  difficulty: CaseDifficulty | "unknown";
  /** Accepted CWE ids from the suite case (advisory metadata), normalized. */
  expected_cwe: string[];
  /** Vulnerable-line regions in scan-commit (pre-image) coordinates. */
  regions: TruthRegion[];
  /** The same fix hunks in fix-commit (post-image) coordinates, for control runs. */
  control_regions: TruthRegion[];
}

export type SemanticMatch = "match" | "mismatch" | "not_configured";

export interface RunScore {
  schema_version: "1.1";
  suite_id: string;
  case_id: string;
  profile_id: string;
  run_id: string;
  variant: RunVariant;
  state: RunMetadata["state"];
  difficulty: CaseDifficulty | "unknown";
  /** Location hit + CWE agreement (when the case configures expected CWEs). */
  detected: boolean;
  /** Any span-capped finding location overlaps a truth region. */
  located: boolean;
  /** CWE agreement of on-target findings against the case's expected CWEs. */
  semantic: SemanticMatch;
  localization: "exact" | "fuzzy" | "none";
  matched_regions: number;
  total_regions: number;
  total_findings: number;
  findings_on_target: number;
  /** Findings whose only truth overlap came from a location wider than the span cap. */
  findings_oversized_only: number;
  /** On-target finding counts by model-reported confidence, for calibration. */
  on_target_by_confidence: Record<Finding["confidence"], { on_target: number; total: number }>;
  /** True when the fix commit predates the profile's training cutoff (memorization possible). */
  contamination_risk: boolean | null;
}
