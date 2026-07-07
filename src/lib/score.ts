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
import { fmt, locales, reportLangs, type ReportLang, type ReportStrings } from "./report-i18n.js";
import { findBrowser, printToPdf } from "./pdf.js";

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
  /** Print detection.pdf / detection.vi.pdf via a local headless Chrome/Edge (default true; best-effort). */
  pdf?: boolean;
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

  // English keeps the historical name; other languages get a suffixed sibling.
  const htmlName = (lang: ReportLang) => (lang === "en" ? "detection.html" : `detection.${lang}.html`);
  const pdfName = (lang: ReportLang) => (lang === "en" ? "detection.pdf" : `detection.${lang}.pdf`);
  for (const lang of reportLangs) {
    await writeFile(path.join(outputDir, htmlName(lang)), renderHtml(payload, lang), "utf8");
  }
  if (options.pdf ?? true) {
    const browser = findBrowser();
    if (!browser) {
      console.warn("PDF export skipped: no Chrome/Edge/Chromium found — set BENCH_BROWSER to a browser executable, or pass --no-pdf to silence this.");
    } else {
      for (const lang of reportLangs) {
        try {
          await printToPdf(browser, path.join(outputDir, htmlName(lang)), path.join(outputDir, pdfName(lang)));
        } catch (error) {
          console.warn(`PDF export skipped for ${htmlName(lang)}: ${(error as Error).message}`);
        }
      }
    }
  }
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

function discriminationLabel(profile: Aggregate): string {
  const control = profile.control;
  return control.discrimination_evaluated ? `${control.discrimination_passed}/${control.discrimination_evaluated}` : "—";
}

export function renderHtml(payload: DetectionPayload, lang: ReportLang): string {
  const t: ReportStrings = locales[lang];
  const scanCells = new Map(payload.matrix.filter((score) => score.variant === "scan").map((score) => [`${score.profile_id}::${score.case_id}`, score]));
  const profileIds = payload.profiles.map((profile) => profile.profile_id);
  const hasControls = payload.profiles.some((profile) => profile.control.cases_with_control > 0);

  const tiles = payload.profiles.map((profile) => `<div class="tile">
<div class="tile-label">${esc(profile.profile_id)}</div>
<div class="tile-value">${pct(profile.recall)}</div>
<div class="tile-sub">${esc(fmt(t.tileDetected, { detected: profile.detected, expected: profile.cases_expected }))} · ${esc(fmt(t.tileCi, { ci: ci(profile.recall_ci95) }))}</div>
<div class="tile-stats"><span>${esc(t.tileStrict)} <b>${pct(profile.recall_strict)}</b></span><span>${esc(t.tileOnTarget)} <b>${pct(profile.on_target_rate)}</b></span><span>${esc(t.tileDiscrimination)} <b>${discriminationLabel(profile)}</b></span></div>
</div>`).join("");

  const bars = payload.profiles.map((profile) => {
    const width = Math.round((profile.recall ?? 0) * 100);
    const interval = profile.recall_ci95;
    const whisker = interval
      ? `<span class="ci" style="left:${(interval.lower * 100).toFixed(1)}%;width:${((interval.upper - interval.lower) * 100).toFixed(1)}%"></span>`
      : "";
    return `<div class="bar-row"><span class="bar-label">${esc(profile.profile_id)}</span><span class="bar-track"><span class="bar-fill" style="width:${width}%"></span>${whisker}</span><span class="bar-value">${pct(profile.recall)} <small>${esc(fmt(t.barDetail, { detected: profile.detected, expected: profile.cases_expected, ci: ci(interval) }))}</small></span></div>`;
  }).join("");

  const heatHead = `<tr><th>${esc(t.thCase)}</th><th>${esc(t.thDifficulty)}</th><th>${esc(t.thCwe)}</th>${profileIds.map((id) => `<th>${esc(id)}</th>`).join("")}</tr>`;
  const heatBody = payload.cases.map((caseInfo) => {
    const row = profileIds.map((profileId) => {
      const score = scanCells.get(`${profileId}::${caseInfo.case_id}`);
      const mark = score?.contamination_risk ? `<sup title="${esc(t.titleContamination)}">†</sup>` : "";
      if (!score || score.state !== "complete") return `<td class="cell miss-run" title="${esc(score?.state ?? t.cellNoRun)}">${esc(t.cellNoRun)}${mark}</td>`;
      if (score.located && !score.detected) return `<td class="cell loc-only" title="${esc(fmt(t.titleLocOnly, { findings: score.total_findings }))}">${esc(t.cellLocOnly)}${mark}</td>`;
      if (!score.detected) {
        const oversized = score.findings_oversized_only ? fmt(t.titleMissOversized, { oversized: score.findings_oversized_only }) : "";
        return `<td class="cell miss" title="${esc(fmt(t.titleMiss, { findings: score.total_findings }) + oversized)}">${esc(t.cellMiss)}${mark}</td>`;
      }
      const label = score.localization === "exact" ? t.cellExact : t.cellFuzzy;
      return `<td class="cell hit ${score.localization}" title="${esc(fmt(t.titleHit, { matched: score.matched_regions, total: score.total_regions }))}">${esc(label)}${mark}</td>`;
    }).join("");
    return `<tr><td class="case">${esc(caseInfo.case_id)}</td><td class="diff">${esc(caseInfo.difficulty)}</td><td class="diff">${esc(caseInfo.expected_cwe.join(", ") || "—")}</td>${row}</tr>`;
  }).join("");

  const summaryHead = `<tr><th>${esc(t.thModel)}</th><th>${esc(t.thRecall)}</th><th>${esc(t.thCi)}</th><th>${esc(t.thStrict)}</th><th>${esc(t.thDetected)}</th><th>${esc(t.thLocOnly)}</th><th>${esc(t.thExact)}</th><th>${esc(t.thFuzzy)}</th><th>${esc(t.thNoRun)}</th><th>${esc(t.thOnTarget)}</th><th>${esc(t.thOversized)}</th><th>${esc(t.thContaminated)}</th></tr>`;
  const summaryBody = payload.profiles.map((profile) => `<tr><td class="case">${esc(profile.profile_id)}</td><td>${pct(profile.recall)}</td><td>${ci(profile.recall_ci95)}</td><td>${pct(profile.recall_strict)}</td><td>${profile.detected}/${profile.cases_expected}</td><td>${profile.located_only}</td><td>${profile.exact}</td><td>${profile.fuzzy}</td><td>${profile.no_result}</td><td>${pct(profile.on_target_rate)} <small>(${profile.findings_on_target}/${profile.findings_total})</small></td><td>${profile.findings_oversized_only}</td><td>${profile.contaminated_cases ?? "—"}</td></tr>`).join("");

  const calibrationHead = `<tr><th>${esc(t.thModel)}</th><th>${esc(t.thHighConf)}</th><th>${esc(t.thMediumConf)}</th><th>${esc(t.thLowConf)}</th></tr>`;
  const calibrationBody = payload.profiles.map((profile) => {
    const cell = (level: keyof ConfidenceCalibration) => {
      const bucket = profile.calibration[level];
      return bucket.total ? `${pct(bucket.on_target / bucket.total)} <small>(${bucket.on_target}/${bucket.total})</small>` : "—";
    };
    return `<tr><td class="case">${esc(profile.profile_id)}</td><td>${cell("high")}</td><td>${cell("medium")}</td><td>${cell("low")}</td></tr>`;
  }).join("");

  const controlSection = hasControls ? `
<h2>${esc(t.controlsHeading)}</h2>
<div class="scroll"><table><thead><tr><th>${esc(t.thModel)}</th><th>${esc(t.thControlRuns)}</th><th>${esc(t.thConfirmedFp)}</th><th>${esc(t.thControlFindings)}</th><th>${esc(t.thDiscrimination)}</th></tr></thead><tbody>
${payload.profiles.map((profile) => `<tr><td class="case">${esc(profile.profile_id)}</td><td>${profile.control.cases_with_control}</td><td>${profile.control.confirmed_false_positives}</td><td>${profile.control.control_findings_total}</td><td>${discriminationLabel(profile)}</td></tr>`).join("")}
</tbody></table></div>
<p class="note">${esc(t.controlsNote)}</p>` : "";

  const pairwiseSection = payload.pairwise.length ? `
<h2>${esc(t.pairwiseHeading)}</h2>
<div class="scroll"><table><thead><tr><th>A</th><th>B</th><th>${esc(t.thOnlyA)}</th><th>${esc(t.thOnlyB)}</th><th>${esc(t.thBoth)}</th><th>${esc(t.thNeither)}</th><th>${esc(t.thPValue)}</th></tr></thead><tbody>
${payload.pairwise.map((pair) => `<tr><td class="case">${esc(pair.profile_a)}</td><td class="case">${esc(pair.profile_b)}</td><td>${pair.only_a}</td><td>${pair.only_b}</td><td>${pair.both}</td><td>${pair.neither}</td><td>${pair.mcnemar_p === null ? "—" : pair.mcnemar_p.toFixed(3)}</td></tr>`).join("")}
</tbody></table></div>
<p class="note">${esc(t.pairwiseNote)}</p>` : "";

  const lightVars = `--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--line:#e1e0d9;--head:#f3f2ef;--fill:#2a78d6;--track:#cde2fb;--ciw:#0b0b0b;--hitbg:#dbf1db;--fuzzybg:#fdf0d2;--locbg:#fbe6de;--missbg:#f8dcdc;--norunbg:#f0efec`;
  const darkVars = `--page:#0d0d0d;--surface:#1a1a19;--ink:#ffffff;--ink2:#c3c2b7;--muted:#898781;--line:#2c2c2a;--head:#232321;--fill:#3987e5;--track:#104281;--ciw:#ffffff;--hitbg:#163c16;--fuzzybg:#524019;--locbg:#4e342a;--missbg:#472222;--norunbg:#232322`;

  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(fmt(t.docTitle, { suite: payload.suite_id }))}</title><style>
:root{${lightVars}}
@media(prefers-color-scheme:dark){:root{${darkVars}}}
*{box-sizing:border-box}
body{font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;background:var(--page);color:var(--ink)}
.page{max-width:1080px;margin:0 auto;padding:40px 32px 56px}
h1{font-size:24px;font-weight:650;margin:0 0 6px;letter-spacing:-.01em}
.subtitle{color:var(--ink2);margin:0 0 10px;font-size:14px}
.meta{color:var(--muted);font-size:12px;margin:0}
h2{font-size:13px;margin:36px 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;margin-top:28px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.tile-label{font-size:13px;font-weight:600;color:var(--ink2);margin-bottom:6px;overflow-wrap:anywhere}
.tile-value{font-size:34px;font-weight:600;line-height:1.1}
.tile-sub{color:var(--muted);font-size:12px;margin-top:4px}
.tile-stats{display:flex;flex-wrap:wrap;gap:4px 14px;margin-top:12px;padding-top:10px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}
.tile-stats b{color:var(--ink);font-weight:600}
.bar-row{display:flex;align-items:center;gap:12px;margin:8px 0}
.bar-label{width:190px;font-weight:600;text-align:right;font-size:13px;color:var(--ink2);overflow-wrap:anywhere}
.bar-track{flex:1;height:20px;background:var(--track);border-radius:4px;overflow:hidden;position:relative}
.bar-fill{display:block;height:100%;background:var(--fill);border-radius:0 4px 4px 0}
.ci{position:absolute;top:8px;height:4px;border-radius:2px;background:var(--ciw);opacity:.55}
.bar-value{width:290px;font-size:13px}
small{color:var(--muted)}
.scroll{overflow-x:auto;background:var(--surface);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;min-width:100%;font-size:13px}
th,td{border-bottom:1px solid var(--line);padding:8px 12px;text-align:center;font-variant-numeric:tabular-nums}
th{background:var(--head);color:var(--ink2);font-weight:600;font-size:12px}
tr:last-child td{border-bottom:0}
th:first-child,td.case{text-align:left}td.diff{text-align:left;color:var(--ink2)}
.cell{font-weight:600;font-size:12px}
.hit{background:var(--hitbg)}.fuzzy{background:var(--fuzzybg)}.loc-only{background:var(--locbg)}.miss{background:var(--missbg)}.miss-run{background:var(--norunbg);color:var(--muted)}
.legend{display:flex;gap:8px 18px;flex-wrap:wrap;margin:10px 0 12px;font-size:12px;color:var(--ink2)}
.legend span{display:inline-flex;align-items:center;gap:6px}
.swatch{width:12px;height:12px;border-radius:3px;display:inline-block;border:1px solid var(--line)}
.note{color:var(--muted);font-size:12px;margin:10px 0 0;max-width:860px}
sup{margin-left:2px}
@page{margin:14mm 12mm}
@media print{
:root{${lightVars}}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{background:#fff}
.page{max-width:none;padding:0}
.scroll{overflow:visible;border-radius:6px}
thead{display:table-header-group}
tr,.tile,.bar-row{break-inside:avoid}
h2{break-after:avoid}
.tiles{grid-template-columns:repeat(3,1fr)}
}
</style></head><body>
<div class="page">
<header><h1>${esc(fmt(t.reportTitle, { suite: payload.suite_id }))}</h1><p class="subtitle">${esc(t.reportSubtitle)}</p><p class="meta">${esc(fmt(t.metaLine, { date: payload.generated_at, tolerance: payload.tolerance_lines, spanCap: payload.span_cap_lines || t.spanCapOff }))}</p></header>
<div class="tiles">${tiles}</div>
<h2>${esc(t.recallHeading)}</h2>
${bars}
<h2>${esc(t.matrixHeading)}</h2>
<div class="legend"><span><i class="swatch" style="background:var(--hitbg)"></i>${esc(t.legendExact)}</span><span><i class="swatch" style="background:var(--fuzzybg)"></i>${esc(fmt(t.legendFuzzy, { tolerance: payload.tolerance_lines }))}</span><span><i class="swatch" style="background:var(--locbg)"></i>${esc(t.legendLocOnly)}</span><span><i class="swatch" style="background:var(--missbg)"></i>${esc(t.legendMiss)}</span><span><i class="swatch" style="background:var(--norunbg)"></i>${esc(t.legendNoRun)}</span><span>${esc(t.legendDagger)}</span></div>
<div class="scroll"><table><thead>${heatHead}</thead><tbody>${heatBody}</tbody></table></div>
<h2>${esc(t.summaryHeading)}</h2>
<div class="scroll"><table><thead>${summaryHead}</thead><tbody>${summaryBody}</tbody></table></div>
${controlSection}
<h2>${esc(t.calibrationHeading)}</h2>
<div class="scroll"><table><thead>${calibrationHead}</thead><tbody>${calibrationBody}</tbody></table></div>
<p class="note">${esc(t.calibrationNote)}</p>
${pairwiseSection}
<p class="note">${esc(t.methodologyNote)}</p>
</div>
</body></html>`;
}
