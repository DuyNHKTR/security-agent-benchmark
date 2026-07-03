import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Finding, ReviewDecision, RunMetadata, SecurityReport } from "../types.js";
import { ensureDir, readJson, writeJsonAtomic } from "./fs.js";
import { loadReviewData } from "./review.js";

const severityWeight: Record<Finding["severity"], number> = { critical: 5, high: 3, medium: 1.5, low: 0.5, informational: 0 };

function finalFindingScore(decision: ReviewDecision, finding: Finding): number {
  if (decision.disposition !== "accepted") return 0;
  let score = Object.values(decision.scores).reduce((sum, value) => sum + value, 0);
  score -= decision.hallucinated_references * 3;
  if (decision.unsafe_payload) score -= 10;
  if (["critical", "high"].includes(finding.severity) && (decision.scores.evidence < 2 || decision.scores.exploitability < 2)) score = Math.min(score, 6);
  return Math.max(0, score);
}

async function reviewerAgreement(root: string, suiteId: string): Promise<{ disposition_agreement: number | null; cohen_kappa: number | null }> {
  const dir = path.join(root, ".bench", "reviews", suiteId, "reviewers");
  let files: string[];
  try { files = (await readdir(dir)).filter((item) => item.endsWith(".jsonl") && !item.endsWith(".scans.jsonl")); } catch { return { disposition_agreement: null, cohen_kappa: null }; }
  if (files.length !== 2) return { disposition_agreement: null, cohen_kappa: null };
  const parse = async (file: string) => (await readFile(path.join(dir, file), "utf8")).split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as ReviewDecision);
  const [a, b] = await Promise.all(files.map(parse));
  const byId = new Map(b.map((item) => [item.blinded_finding_id, item.disposition]));
  const pairs = a.filter((item) => byId.has(item.blinded_finding_id)).map((item) => [item.disposition, byId.get(item.blinded_finding_id)!] as const);
  if (!pairs.length) return { disposition_agreement: null, cohen_kappa: null };
  const observed = pairs.filter(([left, right]) => left === right).length / pairs.length;
  const categories: ReviewDecision["disposition"][] = ["accepted", "rejected", "duplicate"];
  const expected = categories.reduce((sum, category) => sum + (pairs.filter(([left]) => left === category).length / pairs.length) * (pairs.filter(([, right]) => right === category).length / pairs.length), 0);
  return { disposition_agreement: observed, cohen_kappa: expected === 1 ? 1 : (observed - expected) / (1 - expected) };
}

export async function buildComparisonReport(root: string, suiteId: string): Promise<string> {
  const { mapping, decisions, scanDecisions } = await loadReviewData(root, suiteId);
  const decisionById = new Map(decisions.map((item) => [item.blinded_finding_id, item]));
  const scanById = new Map(scanDecisions.map((item) => [item.blinded_scan_id, item]));
  const profileData = new Map<string, {
    runDirs: Set<string>; submitted: number; accepted: number; rejected: number; duplicates: number;
    highAccepted: number; weightedValue: number; attackScores: number[]; priorityScores: number[];
  }>();
  async function collectRuns(dir: string): Promise<void> {
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await collectRuns(full);
      else if (entry.name === "run.json") {
        const run = await readJson<RunMetadata>(full);
        const data = profileData.get(run.profile_id) ?? { runDirs: new Set(), submitted: 0, accepted: 0, rejected: 0, duplicates: 0, highAccepted: 0, weightedValue: 0, attackScores: [], priorityScores: [] };
        data.runDirs.add(path.dirname(full));
        profileData.set(run.profile_id, data);
      }
    }
  }
  await collectRuns(path.join(root, "runs", suiteId));
  for (const item of mapping.filter((entry) => entry.kind === "finding")) {
    const decision = decisionById.get(item.blinded_finding_id);
    if (!decision) throw new Error(`Missing adjudication for ${item.blinded_finding_id}`);
    const report = await readJson<SecurityReport>(path.join(item.run_dir, "report.json"));
    const finding = report.findings.find((candidate) => candidate.id === item.finding_id);
    if (!finding) throw new Error(`Finding ${item.finding_id} missing from ${item.run_dir}`);
    const data = profileData.get(item.profile_id) ?? { runDirs: new Set(), submitted: 0, accepted: 0, rejected: 0, duplicates: 0, highAccepted: 0, weightedValue: 0, attackScores: [], priorityScores: [] };
    data.runDirs.add(item.run_dir);
    data.submitted++;
    data[decision.disposition === "accepted" ? "accepted" : decision.disposition === "rejected" ? "rejected" : "duplicates"]++;
    if (decision.disposition === "accepted" && ["critical", "high"].includes(finding.severity)) data.highAccepted++;
    data.weightedValue += finalFindingScore(decision, finding) * severityWeight[finding.severity];
    profileData.set(item.profile_id, data);
  }
  for (const item of mapping.filter((entry) => entry.kind === "scan")) {
    const scan = scanById.get(item.blinded_scan_id);
    if (!scan) throw new Error(`Missing scan adjudication for ${item.blinded_scan_id}`);
    const data = profileData.get(item.profile_id) ?? { runDirs: new Set(), submitted: 0, accepted: 0, rejected: 0, duplicates: 0, highAccepted: 0, weightedValue: 0, attackScores: [], priorityScores: [] };
    data.runDirs.add(item.run_dir); data.attackScores.push(scan.attack_surface_mapping); data.priorityScores.push(scan.prioritization_quality);
    profileData.set(item.profile_id, data);
  }
  const profiles = [];
  for (const [profileId, data] of profileData) {
    const runs = await Promise.all([...data.runDirs].map((dir) => readJson<RunMetadata>(path.join(dir, "run.json"))));
    const knownCosts = runs.map((run) => run.cost_usd).filter((cost): cost is number => cost !== null);
    const totalCost = knownCosts.length === runs.length ? knownCosts.reduce((sum, cost) => sum + cost, 0) : null;
    const totalDuration = runs.reduce((sum, run) => sum + (run.duration_ms ?? 0), 0);
    const totalInput = runs.reduce((sum, run) => sum + run.usage.input_tokens, 0);
    const totalOutput = runs.reduce((sum, run) => sum + run.usage.output_tokens, 0);
    profiles.push({
      profile_id: profileId, runs: runs.length, submitted_findings: data.submitted, accepted_findings: data.accepted,
      rejected_findings: data.rejected, duplicate_findings: data.duplicates,
      precision: data.accepted + data.rejected ? data.accepted / (data.accepted + data.rejected) : null,
      validated_high_critical_yield: data.highAccepted, validated_security_value: data.weightedValue,
      total_cost_usd: totalCost,
      validated_security_value_per_dollar: totalCost && totalCost > 0 ? data.weightedValue / totalCost : null,
      cost_per_valid_high_critical: totalCost !== null && data.highAccepted ? totalCost / data.highAccepted : null,
      attack_surface_mapping: data.attackScores.length ? data.attackScores.reduce((a, b) => a + b, 0) / data.attackScores.length : null,
      prioritization_quality: data.priorityScores.length ? data.priorityScores.reduce((a, b) => a + b, 0) / data.priorityScores.length : null,
      schema_compliance: runs.length ? runs.filter((run) => run.state === "complete").length / runs.length : null,
      duration_ms: totalDuration, input_tokens: totalInput, output_tokens: totalOutput
    });
  }
  profiles.sort((a, b) => (b.validated_security_value_per_dollar ?? -1) - (a.validated_security_value_per_dollar ?? -1));
  const result = { schema_version: "1.0", suite_id: suiteId, generated_at: new Date().toISOString(), reviewer_agreement: await reviewerAgreement(root, suiteId), profiles };
  const outputDir = path.join(root, "runs", suiteId, "reports");
  await ensureDir(outputDir);
  await writeJsonAtomic(path.join(outputDir, "comparison.json"), result);
  const headers = Object.keys(profiles[0] ?? { profile_id: "" });
  const csv = [headers.join(","), ...profiles.map((row) => headers.map((key) => JSON.stringify(row[key as keyof typeof row] ?? "")).join(","))].join("\n");
  await writeFile(path.join(outputDir, "comparison.csv"), `${csv}\n`, "utf8");
  const escape = (value: unknown) => String(value ?? "N/A").replace(/[&<>]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[char]!);
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>${escape(suiteId)} benchmark</title><style>body{font:14px system-ui;margin:32px;color:#202124}table{border-collapse:collapse;width:100%}th,td{border:1px solid #dadce0;padding:8px;text-align:right}th:first-child,td:first-child{text-align:left}th{background:#f1f3f4}</style></head><body><h1>${escape(suiteId)}</h1><p>Generated ${escape(result.generated_at)}</p><table><thead><tr>${headers.map((header) => `<th>${escape(header)}</th>`).join("")}</tr></thead><tbody>${profiles.map((row) => `<tr>${headers.map((key) => `<td>${escape(row[key as keyof typeof row])}</td>`).join("")}</tr>`).join("")}</tbody></table></body></html>`;
  await writeFile(path.join(outputDir, "comparison.html"), html, "utf8");
  return outputDir;
}
