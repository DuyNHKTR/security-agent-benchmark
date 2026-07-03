import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { writeJsonAtomic } from "../src/lib/fs.js";
import { buildComparisonReport } from "../src/lib/reporting.js";
import { buildReviewQueue } from "../src/lib/review.js";
import type { ReviewDecision, RunMetadata, ScanReviewDecision } from "../src/types.js";
import { validReport } from "./helpers.js";

test("builds blinded queue and scored comparison artifacts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "bench-report-"));
  const suiteId = "suite";
  const runDir = path.join(root, "runs", suiteId, "simple", "secret-model-profile", "run-1");
  const metadata: RunMetadata = {
    schema_version: "1.0", run_id: "run-1", suite_id: suiteId, case_id: "simple",
    profile_id: "secret-model-profile", adapter: "codex", model: "secret-model", pricing_key: "secret",
    cost_mode: "token",
    repository: "local", commit: "a".repeat(40), prompt_sha256: "b".repeat(64), state: "complete",
    started_at: "2026-01-01T00:00:00.000Z", completed_at: "2026-01-01T00:01:00.000Z", duration_ms: 60_000,
    usage: { input_tokens: 100, output_tokens: 50, cache_read_tokens: 0, cache_write_tokens: 0, provenance: "harness" },
    cost_usd: 10, cost_basis: "api_equivalent", errors: []
  };
  await writeJsonAtomic(path.join(runDir, "run.json"), metadata);
  await writeJsonAtomic(path.join(runDir, "report.json"), validReport());
  const failedRunDir = path.join(root, "runs", suiteId, "complex", "secret-model-profile", "run-2");
  await writeJsonAtomic(path.join(failedRunDir, "run.json"), { ...metadata, run_id: "run-2", case_id: "complex", state: "invalid", cost_usd: 5, errors: ["malformed report"] });
  await buildReviewQueue(root, suiteId);
  const reviewRoot = path.join(root, ".bench", "reviews", suiteId);
  const queueText = await readFile(path.join(reviewRoot, "queue.json"), "utf8");
  assert.doesNotMatch(queueText, /secret-model/);
  const queue = JSON.parse(queueText) as { items: Array<{ blinded_finding_id: string }>; scans: Array<{ blinded_scan_id: string }> };
  const findingDecision: ReviewDecision = {
    schema_version: "1.0", review_id: "r1", reviewer_id: "adjudicated", blinded_finding_id: queue.items[0].blinded_finding_id,
    disposition: "accepted", scores: { validity: 4, evidence: 3, exploitability: 3, severity_calibration: 2, remediation: 2, regression_test: 1 },
    hallucinated_references: 0, unsafe_payload: false, duplicate_of: null, notes: "validated", created_at: "2026-01-01T00:00:00.000Z"
  };
  const scanDecision: ScanReviewDecision = {
    schema_version: "1.0", review_id: "s1", reviewer_id: "adjudicated", blinded_scan_id: queue.scans[0].blinded_scan_id,
    attack_surface_mapping: 4, prioritization_quality: 5, notes: "good", created_at: "2026-01-01T00:00:00.000Z"
  };
  await writeJsonAtomic(path.join(reviewRoot, "adjudicated.json"), { schema_version: "1.0", items: [findingDecision] });
  await writeJsonAtomic(path.join(reviewRoot, "adjudicated-scans.json"), { schema_version: "1.0", items: [scanDecision] });
  const outputDir = await buildComparisonReport(root, suiteId);
  const comparison = JSON.parse(await readFile(path.join(outputDir, "comparison.json"), "utf8"));
  assert.equal(comparison.profiles[0].validated_security_value, 45);
  assert.equal(comparison.profiles[0].validated_security_value_per_dollar, 3);
  assert.equal(comparison.profiles[0].schema_compliance, 0.5);
  assert.equal(comparison.profiles[0].runs, 2);
  assert.equal(comparison.profiles[0].attack_surface_mapping, 4);
  await readFile(path.join(outputDir, "comparison.csv"), "utf8");
  await readFile(path.join(outputDir, "comparison.html"), "utf8");
});
