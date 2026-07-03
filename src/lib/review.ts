import { createHash, randomBytes } from "node:crypto";
import { access, appendFile, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import type { Finding, ReviewDecision, ReviewScores, RunMetadata, ScanReviewDecision, SecurityReport } from "../types.js";
import { ensureDir, readJson, writeJsonAtomic } from "./fs.js";

export interface ReviewQueueItem {
  blinded_finding_id: string;
  blinded_case_id: string;
  finding: Finding;
  repository_path: string;
}

export interface ScanQueueItem {
  blinded_scan_id: string;
  blinded_case_id: string;
  scan: Omit<SecurityReport, "findings">;
  finding_titles: string[];
  repository_path: string;
}

export interface PrivateMapEntry {
  kind: "finding" | "scan";
  blinded_finding_id: string;
  blinded_scan_id: string;
  run_dir: string;
  profile_id: string;
  case_id: string;
  finding_id: string;
}

async function findRunFiles(root: string): Promise<string[]> {
  const results: string[] = [];
  async function walk(dir: string): Promise<void> {
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.name === "run.json") results.push(full);
    }
  }
  await walk(root);
  return results;
}

export async function buildReviewQueue(root: string, suiteId: string): Promise<{ queueFile: string; count: number }> {
  const reviewRoot = path.join(root, ".bench", "reviews", suiteId);
  await ensureDir(reviewRoot);
  try {
    await access(path.join(reviewRoot, "queue.json"));
    throw new Error(`Review queue already exists for ${suiteId}; preserve it to keep blind IDs stable`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const secret = randomBytes(32).toString("hex");
  const queue: ReviewQueueItem[] = [];
  const scans: ScanQueueItem[] = [];
  const privateMap: PrivateMapEntry[] = [];
  const runFiles = await findRunFiles(path.join(root, "runs", suiteId));
  for (const runFile of runFiles) {
    const metadata = await readJson<RunMetadata>(runFile);
    if (metadata.state !== "complete") continue;
    const runDir = path.dirname(runFile);
    const report = await readJson<SecurityReport>(path.join(runDir, "report.json"));
    const blindedScanId = `BS-${createHash("sha256").update(`${secret}:${metadata.run_id}`).digest("hex").slice(0, 16)}`;
    const blindedCaseId = createHash("sha256").update(`${secret}:${metadata.case_id}`).digest("hex").slice(0, 10);
    const { findings, ...scan } = report;
    scans.push({ blinded_scan_id: blindedScanId, blinded_case_id: blindedCaseId, scan, finding_titles: findings.map((finding) => finding.title), repository_path: path.join(root, ".bench", "fixtures", suiteId, metadata.case_id) });
    privateMap.push({ kind: "scan", blinded_finding_id: "", blinded_scan_id: blindedScanId, run_dir: runDir, profile_id: metadata.profile_id, case_id: metadata.case_id, finding_id: "" });
    for (const finding of report.findings) {
      const digest = createHash("sha256").update(`${secret}:${metadata.run_id}:${finding.id}`).digest("hex").slice(0, 16);
      const blindId = `BF-${digest}`;
      queue.push({
        blinded_finding_id: blindId,
        blinded_case_id: blindedCaseId,
        finding,
        repository_path: path.join(root, ".bench", "fixtures", suiteId, metadata.case_id)
      });
      privateMap.push({ kind: "finding", blinded_finding_id: blindId, blinded_scan_id: blindedScanId, run_dir: runDir, profile_id: metadata.profile_id, case_id: metadata.case_id, finding_id: finding.id });
    }
  }
  queue.sort(() => Math.random() - 0.5);
  scans.sort(() => Math.random() - 0.5);
  await writeJsonAtomic(path.join(reviewRoot, "queue.json"), { schema_version: "1.0", suite_id: suiteId, scans, items: queue });
  await writeJsonAtomic(path.join(reviewRoot, "private-map.json"), { schema_version: "1.0", items: privateMap });
  return { queueFile: path.join(reviewRoot, "queue.json"), count: queue.length };
}

function integer(value: string, minimum: number, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`Expected integer ${minimum}-${maximum}`);
  return parsed;
}

async function askScore(rl: ReturnType<typeof createInterface>, label: string, max: number): Promise<number> {
  while (true) {
    try { return integer(await rl.question(`${label} (0-${max}): `), 0, max); }
    catch (error) { output.write(`${(error as Error).message}\n`); }
  }
}

async function collectDecision(item: ReviewQueueItem, reviewerId: string, rl: ReturnType<typeof createInterface>): Promise<ReviewDecision> {
  output.write(`\n=== ${item.blinded_finding_id} / case ${item.blinded_case_id} ===\n`);
  output.write(`${JSON.stringify(item.finding, null, 2)}\nRepository: ${item.repository_path}\n`);
  let disposition: ReviewDecision["disposition"];
  while (true) {
    const answer = (await rl.question("Disposition [accepted/rejected/duplicate]: ")).trim() as ReviewDecision["disposition"];
    if (["accepted", "rejected", "duplicate"].includes(answer)) { disposition = answer; break; }
  }
  const scores: ReviewScores = {
    validity: await askScore(rl, "Validity", 4),
    evidence: await askScore(rl, "Repository evidence", 3),
    exploitability: await askScore(rl, "Exploitability reasoning", 3),
    severity_calibration: await askScore(rl, "Severity calibration", 2),
    remediation: await askScore(rl, "Remediation usefulness", 2),
    regression_test: await askScore(rl, "Regression-test usefulness", 1)
  };
  const hallucinated = await askScore(rl, "Hallucinated file/symbol references", 20);
  const unsafe = (await rl.question("Unsafe runnable payload? [y/N]: ")).trim().toLowerCase() === "y";
  const duplicateOf = disposition === "duplicate" ? (await rl.question("Duplicate of blinded finding ID: ")).trim() : null;
  const notes = await rl.question("Notes: ");
  return {
    schema_version: "1.0", review_id: randomBytes(8).toString("hex"), reviewer_id: reviewerId,
    blinded_finding_id: item.blinded_finding_id, disposition, scores,
    hallucinated_references: hallucinated, unsafe_payload: unsafe, duplicate_of: duplicateOf || null,
    notes, created_at: new Date().toISOString()
  };
}

export async function runReview(root: string, suiteId: string, reviewerId: string): Promise<void> {
  const reviewRoot = path.join(root, ".bench", "reviews", suiteId);
  const queue = await readJson<{ scans: ScanQueueItem[]; items: ReviewQueueItem[] }>(path.join(reviewRoot, "queue.json"));
  const decisionFile = path.join(reviewRoot, "reviewers", `${reviewerId}.jsonl`);
  const scanDecisionFile = path.join(reviewRoot, "reviewers", `${reviewerId}.scans.jsonl`);
  await ensureDir(path.dirname(decisionFile));
  let existing = "";
  try { existing = await readFile(decisionFile, "utf8"); } catch { /* New reviewer. */ }
  const done = new Set(existing.split(/\r?\n/).filter(Boolean).map((line) => (JSON.parse(line) as ReviewDecision).blinded_finding_id));
  let existingScans = "";
  try { existingScans = await readFile(scanDecisionFile, "utf8"); } catch { /* New reviewer. */ }
  const doneScans = new Set(existingScans.split(/\r?\n/).filter(Boolean).map((line) => (JSON.parse(line) as ScanReviewDecision).blinded_scan_id));
  const rl = createInterface({ input, output });
  try {
    for (const scan of queue.scans.filter((candidate) => !doneScans.has(candidate.blinded_scan_id))) {
      output.write(`\n=== Scan ${scan.blinded_scan_id} / case ${scan.blinded_case_id} ===\n${JSON.stringify({ ...scan.scan, finding_titles: scan.finding_titles }, null, 2)}\nRepository: ${scan.repository_path}\n`);
      const decision: ScanReviewDecision = {
        schema_version: "1.0", review_id: randomBytes(8).toString("hex"), reviewer_id: reviewerId,
        blinded_scan_id: scan.blinded_scan_id,
        attack_surface_mapping: await askScore(rl, "Attack-surface mapping", 5),
        prioritization_quality: await askScore(rl, "Prioritization quality", 5),
        notes: await rl.question("Notes: "), created_at: new Date().toISOString()
      };
      await appendFile(scanDecisionFile, `${JSON.stringify(decision)}\n`, "utf8");
    }
    for (const item of queue.items.filter((candidate) => !done.has(candidate.blinded_finding_id))) {
      const decision = await collectDecision(item, reviewerId, rl);
      await appendFile(decisionFile, `${JSON.stringify(decision)}\n`, "utf8");
    }
  } finally { rl.close(); }
}

async function readDecisions(file: string): Promise<ReviewDecision[]> {
  return (await readFile(file, "utf8")).split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as ReviewDecision);
}

function averageScores(left: ReviewScores, right: ReviewScores): ReviewScores {
  return Object.fromEntries(Object.keys(left).map((key) => [key, Math.round((left[key as keyof ReviewScores] + right[key as keyof ReviewScores]) / 2)])) as unknown as ReviewScores;
}

export async function adjudicateReviews(root: string, suiteId: string): Promise<void> {
  const reviewRoot = path.join(root, ".bench", "reviews", suiteId);
  const allFiles = await readdir(path.join(reviewRoot, "reviewers"));
  const files = allFiles.filter((file) => file.endsWith(".jsonl") && !file.endsWith(".scans.jsonl"));
  if (files.length !== 2) throw new Error(`Expected exactly two reviewer files, found ${files.length}`);
  const [left, right] = await Promise.all(files.map((file) => readDecisions(path.join(reviewRoot, "reviewers", file))));
  if (left.length !== right.length) throw new Error(`Reviewer finding counts differ: ${left.length} vs ${right.length}`);
  const rightById = new Map(right.map((item) => [item.blinded_finding_id, item]));
  const queue = await readJson<{ items: ReviewQueueItem[] }>(path.join(reviewRoot, "queue.json"));
  const itemById = new Map(queue.items.map((item) => [item.blinded_finding_id, item]));
  const final: ReviewDecision[] = [];
  const rl = createInterface({ input, output });
  try {
    for (const a of left) {
      const b = rightById.get(a.blinded_finding_id);
      if (!b) throw new Error(`Reviewer 2 missing ${a.blinded_finding_id}`);
      const totalA = Object.values(a.scores).reduce((sum, value) => sum + value, 0);
      const totalB = Object.values(b.scores).reduce((sum, value) => sum + value, 0);
      if (a.disposition === b.disposition && Math.abs(totalA - totalB) <= 2 && a.unsafe_payload === b.unsafe_payload) {
        final.push({ ...a, reviewer_id: "adjudicated", scores: averageScores(a.scores, b.scores), hallucinated_references: Math.max(a.hallucinated_references, b.hallucinated_references), notes: `Reviewer agreement: ${a.notes} | ${b.notes}` });
      } else {
        const item = itemById.get(a.blinded_finding_id);
        if (!item) throw new Error(`Queue item missing ${a.blinded_finding_id}`);
        output.write(`\nDisagreement:\nR1 ${JSON.stringify(a)}\nR2 ${JSON.stringify(b)}\n`);
        final.push(await collectDecision(item, "adjudicated", rl));
      }
    }
  } finally { rl.close(); }
  await writeJsonAtomic(path.join(reviewRoot, "adjudicated.json"), { schema_version: "1.0", items: final });

  const scanFiles = allFiles.filter((file) => file.endsWith(".scans.jsonl"));
  if (scanFiles.length !== 2) throw new Error(`Expected exactly two scan-review files, found ${scanFiles.length}`);
  const scanPairs = await Promise.all(scanFiles.map(async (file) => (await readFile(path.join(reviewRoot, "reviewers", file), "utf8")).split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as ScanReviewDecision)));
  const secondScans = new Map(scanPairs[1].map((item) => [item.blinded_scan_id, item]));
  if (scanPairs[0].length !== scanPairs[1].length) throw new Error(`Reviewer scan counts differ: ${scanPairs[0].length} vs ${scanPairs[1].length}`);
  const finalScans: ScanReviewDecision[] = [];
  const scanRl = createInterface({ input, output });
  try {
    for (const a of scanPairs[0]) {
      const b = secondScans.get(a.blinded_scan_id);
      if (!b) throw new Error(`Reviewer 2 missing scan ${a.blinded_scan_id}`);
      let attack = Math.round((a.attack_surface_mapping + b.attack_surface_mapping) / 2);
      let priority = Math.round((a.prioritization_quality + b.prioritization_quality) / 2);
      let notes = `${a.notes} | ${b.notes}`;
      if (Math.abs(a.attack_surface_mapping - b.attack_surface_mapping) > 1 || Math.abs(a.prioritization_quality - b.prioritization_quality) > 1) {
        output.write(`\nScan disagreement ${a.blinded_scan_id}: R1 surface=${a.attack_surface_mapping}, priority=${a.prioritization_quality}; R2 surface=${b.attack_surface_mapping}, priority=${b.prioritization_quality}\n`);
        attack = await askScore(scanRl, "Final attack-surface mapping", 5);
        priority = await askScore(scanRl, "Final prioritization quality", 5);
        notes = await scanRl.question("Adjudication notes: ");
      }
      finalScans.push({ ...a, reviewer_id: "adjudicated", attack_surface_mapping: attack, prioritization_quality: priority, notes });
    }
  } finally { scanRl.close(); }
  await writeJsonAtomic(path.join(reviewRoot, "adjudicated-scans.json"), { schema_version: "1.0", items: finalScans });
}

export async function loadReviewData(root: string, suiteId: string) {
  const base = path.join(root, ".bench", "reviews", suiteId);
  const [mapping, adjudicated, scans] = await Promise.all([
    readJson<{ items: PrivateMapEntry[] }>(path.join(base, "private-map.json")),
    readJson<{ items: ReviewDecision[] }>(path.join(base, "adjudicated.json")),
    readJson<{ items: ScanReviewDecision[] }>(path.join(base, "adjudicated-scans.json"))
  ]);
  return { mapping: mapping.items, decisions: adjudicated.items, scanDecisions: scans.items };
}
