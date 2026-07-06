import { readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type {
  CaseDifficulty, Finding, RunMetadata, RunScore, RunVariant, SecurityReport,
  SemanticMatch, SuiteConfig, TruthCase, TruthRegion
} from "../types.js";
import { loadProfiles } from "./config.js";
import { ensureDir, readJson, writeJsonAtomic } from "./fs.js";
import { prepareFixture } from "./fixtures.js";
import { deriveTruth, normalizeCwe } from "./truth.js";
import { mcnemarExact, wilsonInterval, type Interval } from "./stats.js";

const DEFAULT_TOLERANCE = 5;
// A finding whose locations total more than this many lines earns no detection
// credit: a range like 1..5000 — or hundreds of small ranges tiling the repo —
// would otherwise always "hit". Capping the per-finding total (not each
// location) closes the tiling bypass, and subsumes the single-location case.
// The prompt demands exact locations; the scorer enforces it. 0 disables.
const DEFAULT_SPAN_CAP = 40;

export interface ScoreOptions {
  tolerance: number;
  spanCap: number;
  expectedCwe: string[];
}

export const defaultScoreOptions = (): ScoreOptions => ({ tolerance: DEFAULT_TOLERANCE, spanCap: DEFAULT_SPAN_CAP, expectedCwe: [] });

function normalizePath(value: string): string {
  return value.replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "").toLowerCase();
}

function samefile(a: string, b: string): boolean {
  return normalizePath(a) === normalizePath(b);
}

function rangesOverlap(a1: number, a2: number, b1: number, b2: number, tolerance: number): boolean {
  return a1 <= b2 + tolerance && b1 <= a2 + tolerance;
}

/**
 * Memorization flag: was the fix commit inside the model's training window?
 * A date-only cutoff means "trained on data through that day", so it compares
 * against the END of that day (UTC) — a fix committed later the same day is
 * still risk. Returns null when the cutoff is unset or either date is unparseable.
 */
export function fixPredatesCutoff(fixCommittedAt: string, cutoff: string | undefined): boolean | null {
  if (cutoff === undefined || cutoff === null) return null;
  const trimmed = String(cutoff).trim();
  if (!trimmed) return null;
  const fixDate = Date.parse(fixCommittedAt);
  const cutoffDate = Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(trimmed) ? `${trimmed}T23:59:59.999Z` : trimmed);
  if (Number.isNaN(fixDate) || Number.isNaN(cutoffDate)) return null;
  return fixDate <= cutoffDate;
}

const confidenceLevels: Finding["confidence"][] = ["high", "medium", "low"];

export type ConfidenceCalibration = Record<Finding["confidence"], { on_target: number; total: number }>;

const emptyCalibration = (): ConfidenceCalibration => ({
  high: { on_target: 0, total: 0 },
  medium: { on_target: 0, total: 0 },
  low: { on_target: 0, total: 0 }
});

export interface ScoreResult {
  detected: boolean;
  located: boolean;
  semantic: SemanticMatch;
  localization: "exact" | "fuzzy" | "none";
  matched_regions: number;
  total_regions: number;
  total_findings: number;
  findings_on_target: number;
  findings_oversized_only: number;
  on_target_by_confidence: ConfidenceCalibration;
}

/**
 * Pure scorer: does the report locate any vulnerable region from the fix diff?
 * - A finding whose locations total more lines than the span cap earns no
 *   credit (anti-gaming: covers both one giant range and many tiled ranges);
 *   findings whose truth overlaps were all discarded this way are counted in
 *   `findings_oversized_only` — on a control run they also void discrimination.
 * - `located` is the raw location hit. `detected` additionally requires an
 *   on-target finding to report one of the case's expected CWEs (when the
 *   suite configures them), so right-lines-wrong-reason scores location-only.
 * - `localization` is taken from the findings that earned `detected` (the
 *   CWE-qualifying ones when a CWE is configured), so a wrong-CWE exact hit
 *   cannot inflate strict recall past a right-CWE fuzzy hit.
 */
export function scoreReport(regions: TruthRegion[], report: SecurityReport, options: Partial<ScoreOptions> = {}): ScoreResult {
  const { tolerance, spanCap, expectedCwe } = { ...defaultScoreOptions(), ...options };
  const regionHit = regions.map(() => false);
  const findingExact = report.findings.map(() => false);
  const findingFuzzy = report.findings.map(() => false);
  const findingOversizedHit = report.findings.map(() => false);
  report.findings.forEach((finding, findingIndex) => {
    const totalSpan = finding.locations.reduce((sum, location) => sum + (location.end_line - location.start_line + 1), 0);
    const oversized = spanCap > 0 && totalSpan > spanCap;
    for (const location of finding.locations) {
      regions.forEach((region, regionIndex) => {
        if (!samefile(location.path, region.file)) return;
        if (!rangesOverlap(location.start_line, location.end_line, region.start_line, region.end_line, tolerance)) return;
        if (oversized) {
          findingOversizedHit[findingIndex] = true;
          return;
        }
        regionHit[regionIndex] = true;
        if (rangesOverlap(location.start_line, location.end_line, region.start_line, region.end_line, 0)) findingExact[findingIndex] = true;
        else findingFuzzy[findingIndex] = true;
      });
    }
  });

  const findingHit = report.findings.map((finding, index) => findingExact[index] || findingFuzzy[index]);
  const located = regionHit.some(Boolean);
  const expected = new Set(expectedCwe);
  const findingQualifies = report.findings.map((finding, index) => {
    if (!findingHit[index]) return false;
    if (!expected.size) return true;
    const cwe = normalizeCwe(finding.cwe);
    return cwe !== null && expected.has(cwe);
  });
  const detected = findingQualifies.some(Boolean);
  let semantic: SemanticMatch = "not_configured";
  if (located && expected.size) semantic = detected ? "match" : "mismatch";

  // Localization credit comes from the findings that produced the detection;
  // for loc-only results it falls back to the raw hits (display only).
  const creditSet = detected ? findingQualifies : findingHit;
  const exact = report.findings.some((finding, index) => creditSet[index] && findingExact[index]);
  const fuzzy = report.findings.some((finding, index) => creditSet[index] && findingFuzzy[index]);

  const calibration = emptyCalibration();
  report.findings.forEach((finding, index) => {
    const level = confidenceLevels.includes(finding.confidence) ? finding.confidence : "low";
    calibration[level].total += 1;
    if (findingHit[index]) calibration[level].on_target += 1;
  });

  return {
    detected,
    located,
    semantic,
    localization: exact ? "exact" : fuzzy ? "fuzzy" : "none",
    matched_regions: regionHit.filter(Boolean).length,
    total_regions: regions.length,
    total_findings: report.findings.length,
    findings_on_target: findingHit.filter(Boolean).length,
    findings_oversized_only: findingOversizedHit.filter((hit, index) => hit && !findingHit[index]).length,
    on_target_by_confidence: calibration
  };
}

async function collectRunFiles(dir: string): Promise<string[]> {
  const results: string[] = [];
  async function walk(current: string): Promise<void> {
    let entries;
    try { entries = await readdir(current, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.name === "run.json") results.push(full);
    }
  }
  await walk(dir);
  return results;
}

interface ControlAggregate {
  cases_with_control: number;
  control_findings_total: number;
  /** Findings that landed on a patched region while scanning the fixed commit. */
  confirmed_false_positives: number;
  /** Cases detected on the vulnerable commit AND clean at the patched site on the fixed commit. */
  discrimination_passed: number;
  /** Cases with both a complete scan and control run (discrimination denominator). */
  discrimination_evaluated: number;
}

interface Aggregate {
  profile_id: string;
  cases_expected: number;
  cases_with_run: number;
  detected: number;
  located_only: number;
  exact: number;
  fuzzy: number;
  no_result: number;
  recall: number | null;
  recall_ci95: Interval | null;
  /** Recall counting only exact (tolerance-0) localizations. */
  recall_strict: number | null;
  recall_strict_ci95: Interval | null;
  recall_by_difficulty: Record<string, { detected: number; total: number }>;
  findings_total: number;
  findings_on_target: number;
  on_target_rate: number | null;
  findings_oversized_only: number;
  calibration: ConfidenceCalibration;
  contaminated_cases: number | null;
  control: ControlAggregate;
}

interface PairwiseComparison {
  profile_a: string;
  profile_b: string;
  /** Cases only A detected / only B detected (paired over the same case set). */
  only_a: number;
  only_b: number;
  both: number;
  neither: number;
  mcnemar_p: number | null;
}

export interface DetectionReportOptions {
  tolerance?: number;
  spanCap?: number;
}

export async function buildDetectionReport(root: string, suite: SuiteConfig, options: DetectionReportOptions = {}): Promise<string> {
  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE;
  const spanCap = options.spanCap ?? DEFAULT_SPAN_CAP;
  const cases = suite.cases.filter((candidate) => candidate.fix_commit);
  if (!cases.length) throw new Error("Suite has no fix_commit cases; detection scoring needs ground-truth cases");

  const truthByCase = new Map<string, TruthCase>();
  for (const fixture of cases) {
    const cache = await prepareFixture(root, suite.id, fixture);
    truthByCase.set(fixture.id, await deriveTruth(root, cache, suite.id, fixture));
  }
  const difficultyByCase = new Map(cases.map((candidate) => [candidate.id, (candidate.difficulty ?? "unknown") as CaseDifficulty | "unknown"]));

  // Latest complete run per (profile, case, variant); otherwise the latest run of any state.
  const runFiles = await collectRunFiles(path.join(root, "runs", suite.id));
  const latest = new Map<string, { metadata: RunMetadata; dir: string }>();
  for (const runFile of runFiles) {
    const metadata = await readJson<RunMetadata>(runFile);
    if (!truthByCase.has(metadata.case_id)) continue;
    const variant: RunVariant = metadata.variant ?? "scan";
    const key = `${metadata.profile_id}::${metadata.case_id}::${variant}`;
    const previous = latest.get(key);
    const better = !previous
      || (metadata.state === "complete" && previous.metadata.state !== "complete")
      || (metadata.state === previous.metadata.state && metadata.run_id > previous.metadata.run_id);
    if (better) latest.set(key, { metadata, dir: path.dirname(runFile) });
  }

  const configuredProfiles = await loadProfiles(root, suite);
  const cutoffByProfile = new Map(configuredProfiles.map((profile) => [profile.id, profile.training_cutoff ?? null]));
  const profileIds = [...new Set([
    ...configuredProfiles.map((profile) => profile.id),
    ...[...latest.values()].map((entry) => entry.metadata.profile_id)
  ])].sort();

  const contaminationRisk = (profileId: string, truth: TruthCase): boolean | null =>
    fixPredatesCutoff(truth.fix_committed_at, cutoffByProfile.get(profileId) ?? undefined);

  const scores: RunScore[] = [];
  for (const profileId of profileIds) {
    for (const fixture of cases) {
      const truth = truthByCase.get(fixture.id)!;
      const difficulty = difficultyByCase.get(fixture.id) ?? "unknown";
      for (const variant of ["scan", "control"] as RunVariant[]) {
        const entry = latest.get(`${profileId}::${fixture.id}::${variant}`);
        // Control runs are opt-in: absent control run is simply not scored.
        if (!entry && variant === "control") continue;
        const base = {
          schema_version: "1.1" as const, suite_id: suite.id, case_id: fixture.id, profile_id: profileId,
          variant, difficulty, contamination_risk: contaminationRisk(profileId, truth)
        };
        if (!entry || entry.metadata.state !== "complete") {
          scores.push({
            ...base, run_id: entry?.metadata.run_id ?? "", state: entry?.metadata.state ?? "prepared",
            detected: false, located: false, semantic: "not_configured", localization: "none",
            matched_regions: 0, total_regions: (variant === "scan" ? truth.regions : truth.control_regions).length,
            total_findings: 0, findings_on_target: 0, findings_oversized_only: 0,
            on_target_by_confidence: emptyCalibration()
          });
          continue;
        }
        const report = await readJson<SecurityReport>(path.join(entry.dir, "report.json"));
        const regions = variant === "scan" ? truth.regions : truth.control_regions;
        const result = scoreReport(regions, report, { tolerance, spanCap, expectedCwe: truth.expected_cwe });
        const runScore: RunScore = { ...base, run_id: entry.metadata.run_id, state: entry.metadata.state, ...result };
        scores.push(runScore);
        await writeJsonAtomic(path.join(entry.dir, "score.json"), runScore);
      }
    }
  }

  const scanScores = scores.filter((score) => score.variant === "scan");
  const controlScores = scores.filter((score) => score.variant === "control");

  const aggregates: Aggregate[] = profileIds.map((profileId) => {
    const rows = scanScores.filter((score) => score.profile_id === profileId);
    const withRun = rows.filter((score) => score.state === "complete");
    const detected = rows.filter((score) => score.detected).length;
    const exact = rows.filter((score) => score.detected && score.localization === "exact").length;
    const byDifficulty: Record<string, { detected: number; total: number }> = {};
    for (const score of rows) {
      const bucket = byDifficulty[score.difficulty] ?? { detected: 0, total: 0 };
      bucket.total += 1;
      if (score.detected) bucket.detected += 1;
      byDifficulty[score.difficulty] = bucket;
    }
    const findingsTotal = rows.reduce((sum, score) => sum + score.total_findings, 0);
    const onTarget = rows.reduce((sum, score) => sum + score.findings_on_target, 0);
    const calibration = emptyCalibration();
    for (const score of rows) {
      for (const level of confidenceLevels) {
        calibration[level].on_target += score.on_target_by_confidence[level].on_target;
        calibration[level].total += score.on_target_by_confidence[level].total;
      }
    }
    const contaminationKnown = rows.filter((score) => score.contamination_risk !== null);
    const controls = controlScores.filter((score) => score.profile_id === profileId && score.state === "complete");
    // Deletion-only fixes leave no patched lines (total_regions === 0): there is
    // no site to test on the fixed commit, so such controls are unevaluable for
    // discrimination rather than an automatic pass.
    const discriminationPairs = controls.filter((control) =>
      control.total_regions > 0 && rows.some((scan) => scan.case_id === control.case_id && scan.state === "complete"));
    const control: ControlAggregate = {
      cases_with_control: controls.length,
      control_findings_total: controls.reduce((sum, score) => sum + score.total_findings, 0),
      confirmed_false_positives: controls.reduce((sum, score) => sum + score.findings_on_target, 0),
      discrimination_evaluated: discriminationPairs.length,
      discrimination_passed: discriminationPairs.filter((control) => {
        const scan = rows.find((row) => row.case_id === control.case_id)!;
        // A vague oversized overlap on the patched region is not "clean":
        // it voids discrimination even though it earns no confirmed-FP count.
        return scan.detected && !control.located && control.findings_oversized_only === 0;
      }).length
    };
    return {
      profile_id: profileId, cases_expected: cases.length, cases_with_run: withRun.length,
      detected, located_only: rows.filter((score) => score.located && !score.detected).length,
      exact, fuzzy: rows.filter((score) => score.detected && score.localization === "fuzzy").length,
      no_result: rows.filter((score) => score.state !== "complete").length,
      recall: cases.length ? detected / cases.length : null,
      recall_ci95: wilsonInterval(detected, cases.length),
      recall_strict: cases.length ? exact / cases.length : null,
      recall_strict_ci95: wilsonInterval(exact, cases.length),
      recall_by_difficulty: byDifficulty,
      findings_total: findingsTotal, findings_on_target: onTarget,
      on_target_rate: findingsTotal ? onTarget / findingsTotal : null,
      findings_oversized_only: rows.reduce((sum, score) => sum + score.findings_oversized_only, 0),
      calibration,
      contaminated_cases: contaminationKnown.length ? contaminationKnown.filter((score) => score.contamination_risk).length : null,
      control
    };
  });
  aggregates.sort((a, b) => (b.recall ?? -1) - (a.recall ?? -1));

  // Paired comparison over the identical case set (refusal/no-run counts as
  // not-detected: intention-to-treat, because a refusal is a real outcome).
  const pairwise: PairwiseComparison[] = [];
  for (let i = 0; i < profileIds.length; i++) {
    for (let j = i + 1; j < profileIds.length; j++) {
      const rowsA = new Map(scanScores.filter((score) => score.profile_id === profileIds[i]).map((score) => [score.case_id, score]));
      const rowsB = new Map(scanScores.filter((score) => score.profile_id === profileIds[j]).map((score) => [score.case_id, score]));
      let onlyA = 0, onlyB = 0, both = 0, neither = 0;
      for (const fixture of cases) {
        const a = rowsA.get(fixture.id)?.detected ?? false;
        const b = rowsB.get(fixture.id)?.detected ?? false;
        if (a && b) both++;
        else if (a) onlyA++;
        else if (b) onlyB++;
        else neither++;
      }
      pairwise.push({
        profile_a: profileIds[i], profile_b: profileIds[j],
        only_a: onlyA, only_b: onlyB, both, neither,
        mcnemar_p: mcnemarExact(onlyA, onlyB)
      });
    }
  }

  const outputDir = path.join(root, "runs", suite.id, "reports");
  await ensureDir(outputDir);
  const payload = {
    schema_version: "1.1", suite_id: suite.id, generated_at: new Date().toISOString(),
    tolerance_lines: tolerance, span_cap_lines: spanCap,
    cases: cases.map((candidate) => {
      const truth = truthByCase.get(candidate.id)!;
      return {
        case_id: candidate.id, difficulty: candidate.difficulty ?? "unknown",
        regions: truth.regions.length, expected_cwe: truth.expected_cwe, fix_committed_at: truth.fix_committed_at
      };
    }),
    profiles: aggregates, pairwise, matrix: scores
  };
  await writeJsonAtomic(path.join(outputDir, "detection.json"), payload);

  const headers = [
    "profile_id", "recall", "recall_ci95_lower", "recall_ci95_upper", "recall_strict", "detected", "located_only",
    "cases_expected", "cases_with_run", "exact", "fuzzy", "no_result", "on_target_rate", "findings_oversized_only",
    "confirmed_false_positives", "discrimination_passed", "discrimination_evaluated", "contaminated_cases"
  ];
  const csvRows = aggregates.map((row) => {
    const flat: Record<string, unknown> = {
      ...row,
      recall_ci95_lower: row.recall_ci95?.lower ?? "",
      recall_ci95_upper: row.recall_ci95?.upper ?? "",
      confirmed_false_positives: row.control.confirmed_false_positives,
      discrimination_passed: row.control.discrimination_passed,
      discrimination_evaluated: row.control.discrimination_evaluated
    };
    return headers.map((key) => JSON.stringify(flat[key] ?? "")).join(",");
  });
  await writeFile(path.join(outputDir, "detection.csv"), `${[headers.join(","), ...csvRows].join("\n")}\n`, "utf8");
  await writeFile(path.join(outputDir, "detection.html"), renderHtml(payload), "utf8");
  return outputDir;
}

function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]!);
}

function pct(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `${Math.round(value * 100)}%`;
}

function ci(value: Interval | null): string {
  return value ? `${Math.round(value.lower * 100)}–${Math.round(value.upper * 100)}%` : "—";
}

interface DetectionPayload {
  suite_id: string; generated_at: string; tolerance_lines: number; span_cap_lines: number;
  cases: { case_id: string; difficulty: string; regions: number; expected_cwe: string[]; fix_committed_at: string }[];
  profiles: Aggregate[];
  pairwise: PairwiseComparison[];
  matrix: RunScore[];
}

function renderHtml(payload: DetectionPayload): string {
  const scanCells = new Map(payload.matrix.filter((score) => score.variant === "scan").map((score) => [`${score.profile_id}::${score.case_id}`, score]));
  const profileIds = payload.profiles.map((profile) => profile.profile_id);
  const hasControls = payload.profiles.some((profile) => profile.control.cases_with_control > 0);

  const bars = payload.profiles.map((profile) => {
    const width = Math.round((profile.recall ?? 0) * 100);
    const interval = profile.recall_ci95;
    const whisker = interval
      ? `<span class="ci" style="left:${(interval.lower * 100).toFixed(1)}%;width:${((interval.upper - interval.lower) * 100).toFixed(1)}%"></span>`
      : "";
    return `<div class="bar-row"><span class="bar-label">${esc(profile.profile_id)}</span><span class="bar-track"><span class="bar-fill" style="width:${width}%"></span>${whisker}</span><span class="bar-value">${pct(profile.recall)} <small>(${profile.detected}/${profile.cases_expected} · 95% CI ${ci(interval)})</small></span></div>`;
  }).join("");

  const heatHead = `<tr><th>Vulnerability (case)</th><th>Diff.</th><th>CWE</th>${profileIds.map((id) => `<th>${esc(id)}</th>`).join("")}</tr>`;
  const heatBody = payload.cases.map((caseInfo) => {
    const row = profileIds.map((profileId) => {
      const score = scanCells.get(`${profileId}::${caseInfo.case_id}`);
      const mark = score?.contamination_risk ? `<sup title="fix predates this model's training cutoff — memorization possible">†</sup>` : "";
      if (!score || score.state !== "complete") return `<td class="cell miss-run" title="${esc(score?.state ?? "no run")}">no run${mark}</td>`;
      if (score.located && !score.detected) return `<td class="cell loc-only" title="right location, CWE mismatch (${score.total_findings} findings)">loc-only${mark}</td>`;
      if (!score.detected) return `<td class="cell miss" title="${score.total_findings} findings, none on target${score.findings_oversized_only ? `; ${score.findings_oversized_only} oversized-only overlap(s) discarded` : ""}">miss${mark}</td>`;
      const label = score.localization === "exact" ? "exact" : "≈fuzzy";
      return `<td class="cell hit ${score.localization}" title="${score.matched_regions}/${score.total_regions} regions">${label}${mark}</td>`;
    }).join("");
    return `<tr><td class="case">${esc(caseInfo.case_id)}</td><td class="diff">${esc(caseInfo.difficulty)}</td><td class="diff">${esc(caseInfo.expected_cwe.join(", ") || "—")}</td>${row}</tr>`;
  }).join("");

  const summaryHead = `<tr><th>Model</th><th>Recall</th><th>95% CI</th><th>Strict recall</th><th>Detected</th><th>Loc-only</th><th>Exact</th><th>Fuzzy</th><th>No run</th><th>On-target findings</th><th>Oversized-only</th><th>Contam. cases</th></tr>`;
  const summaryBody = payload.profiles.map((profile) => `<tr><td class="case">${esc(profile.profile_id)}</td><td>${pct(profile.recall)}</td><td>${ci(profile.recall_ci95)}</td><td>${pct(profile.recall_strict)}</td><td>${profile.detected}/${profile.cases_expected}</td><td>${profile.located_only}</td><td>${profile.exact}</td><td>${profile.fuzzy}</td><td>${profile.no_result}</td><td>${pct(profile.on_target_rate)} <small>(${profile.findings_on_target}/${profile.findings_total})</small></td><td>${profile.findings_oversized_only}</td><td>${profile.contaminated_cases ?? "—"}</td></tr>`).join("");

  const calibrationHead = `<tr><th>Model</th><th>High conf.</th><th>Medium conf.</th><th>Low conf.</th></tr>`;
  const calibrationBody = payload.profiles.map((profile) => {
    const cell = (level: keyof ConfidenceCalibration) => {
      const bucket = profile.calibration[level];
      return bucket.total ? `${pct(bucket.on_target / bucket.total)} <small>(${bucket.on_target}/${bucket.total})</small>` : "—";
    };
    return `<tr><td class="case">${esc(profile.profile_id)}</td><td>${cell("high")}</td><td>${cell("medium")}</td><td>${cell("low")}</td></tr>`;
  }).join("");

  const controlSection = hasControls ? `
<h2>Negative controls — scans of the patched commit</h2>
<div class="scroll"><table><thead><tr><th>Model</th><th>Control runs</th><th>Confirmed false positives</th><th>Control findings</th><th>Discrimination</th></tr></thead><tbody>
${payload.profiles.map((profile) => {
    const control = profile.control;
    const discrimination = control.discrimination_evaluated ? `${control.discrimination_passed}/${control.discrimination_evaluated}` : "—";
    return `<tr><td class="case">${esc(profile.profile_id)}</td><td>${control.cases_with_control}</td><td>${control.confirmed_false_positives}</td><td>${control.control_findings_total}</td><td>${discrimination}</td></tr>`;
  }).join("")}
</tbody></table></div>
<p class="meta">A confirmed false positive is a finding placed on the patched region while scanning the fixed commit — the bug is provably gone there. Discrimination = cases where the model flagged the vulnerable commit and stayed clean at the patched site on the fixed commit; flagging both suggests pattern-matching or memorization rather than analysis.</p>` : "";

  const pairwiseSection = payload.pairwise.length ? `
<h2>Pairwise comparison (exact McNemar, paired by case)</h2>
<div class="scroll"><table><thead><tr><th>A</th><th>B</th><th>Only A</th><th>Only B</th><th>Both</th><th>Neither</th><th>p-value</th></tr></thead><tbody>
${payload.pairwise.map((pair) => `<tr><td class="case">${esc(pair.profile_a)}</td><td class="case">${esc(pair.profile_b)}</td><td>${pair.only_a}</td><td>${pair.only_b}</td><td>${pair.both}</td><td>${pair.neither}</td><td>${pair.mcnemar_p === null ? "—" : pair.mcnemar_p.toFixed(3)}</td></tr>`).join("")}
</tbody></table></div>
<p class="meta">Same cases, paired outcomes; refusals count as not-detected. p ≥ 0.05 means the suite cannot distinguish the two models — add cases before reading a ranking from the bars above.</p>` : "";

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(payload.suite_id)} detection</title><style>
:root{--bg:#fff;--fg:#1f2328;--muted:#6b7280;--line:#d0d7de;--head:#f6f8fa;--hit:#1a7f37;--hitbg:#dafbe1;--fuzzybg:#fff8c5;--locbg:#ffe8d1;--loc:#953800;--miss:#cf222e;--missbg:#ffebe9;--norun:#eaeef2;--track:#eaeef2;--fill:#0969da;--cifg:#1f2328}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#30363d;--head:#161b22;--hitbg:#1b3226;--fuzzybg:#3a3212;--locbg:#3a2a12;--loc:#e0955a;--missbg:#3a1a1c;--norun:#21262d;--track:#21262d;--fill:#4493f8;--cifg:#e6edf3}}
*{box-sizing:border-box}body{font:14px/1.5 system-ui,sans-serif;margin:0;padding:32px;background:var(--bg);color:var(--fg)}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:32px 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.meta{color:var(--muted);font-size:12px;margin-bottom:8px}
.bar-row{display:flex;align-items:center;gap:12px;margin:6px 0}.bar-label{width:180px;font-weight:600;text-align:right}
.bar-track{flex:1;height:22px;background:var(--track);border-radius:4px;overflow:hidden;position:relative}.bar-fill{display:block;height:100%;background:var(--fill)}
.ci{position:absolute;top:9px;height:4px;border-radius:2px;background:var(--cifg);opacity:.55}
.bar-value{width:260px}small{color:var(--muted)}
.scroll{overflow-x:auto}table{border-collapse:collapse;min-width:100%;font-size:13px}
th,td{border:1px solid var(--line);padding:6px 10px;text-align:center}th{background:var(--head)}
td.case,td.diff{text-align:left}th:first-child,td.case{text-align:left}
.cell{font-weight:600}.hit{color:var(--hit);background:var(--hitbg)}.fuzzy{background:var(--fuzzybg)}.loc-only{color:var(--loc);background:var(--locbg)}.miss{color:var(--miss);background:var(--missbg)}.miss-run{color:var(--muted);background:var(--norun)}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin:10px 0;font-size:12px;color:var(--muted)}.legend span{display:inline-flex;align-items:center;gap:6px}.swatch{width:12px;height:12px;border-radius:3px;display:inline-block}
sup{margin-left:2px}
</style></head><body>
<h1>${esc(payload.suite_id)} — vulnerability detection</h1>
<div class="meta">Generated ${esc(payload.generated_at)} · line tolerance ±${payload.tolerance_lines} · location span cap ${payload.span_cap_lines || "off"} · ground truth from security-fix diffs</div>
<h2>Recall — share of known vulnerabilities each model detected</h2>
${bars}
<h2>Detection matrix</h2>
<div class="legend"><span><i class="swatch" style="background:var(--hitbg)"></i>exact — flagged the fixed line</span><span><i class="swatch" style="background:var(--fuzzybg)"></i>fuzzy — within ±${payload.tolerance_lines} lines</span><span><i class="swatch" style="background:var(--locbg)"></i>loc-only — right lines, wrong CWE</span><span><i class="swatch" style="background:var(--missbg)"></i>miss — findings, none on target</span><span><i class="swatch" style="background:var(--norun)"></i>no run — refused/incomplete/absent</span><span>† — fix predates model's training cutoff</span></div>
<div class="scroll"><table><thead>${heatHead}</thead><tbody>${heatBody}</tbody></table></div>
<h2>Summary</h2>
<div class="scroll"><table><thead>${summaryHead}</thead><tbody>${summaryBody}</tbody></table></div>
${controlSection}
<h2>Confidence calibration — on-target rate by model-reported confidence</h2>
<div class="scroll"><table><thead>${calibrationHead}</thead><tbody>${calibrationBody}</tbody></table></div>
<p class="meta">A well-calibrated model's high-confidence findings hit known vulnerabilities more often than its low-confidence ones. Off-target findings may still be real bugs outside the seeded set, so read rates as directional.</p>
${pairwiseSection}
<p class="meta">Detected = a span-capped finding location overlaps the fix-diff lines and (when the case sets an expected CWE) an on-target finding reports a matching CWE. Strict recall counts only tolerance-0 localizations. "On-target findings" is a directional precision signal, not a false-positive rate — confirmed false positives come from the negative-control runs.</p>
</body></html>`;
}
