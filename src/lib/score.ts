import { readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { CaseDifficulty, RunMetadata, RunScore, SecurityReport, SuiteConfig, TruthCase, TruthRegion } from "../types.js";
import { ensureDir, readJson, writeJsonAtomic } from "./fs.js";
import { prepareFixture } from "./fixtures.js";
import { deriveTruth } from "./truth.js";

const DEFAULT_TOLERANCE = 5;

function normalizePath(value: string): string {
  return value.replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "").toLowerCase();
}

function samefile(a: string, b: string): boolean {
  const left = normalizePath(a);
  const right = normalizePath(b);
  return left === right || left.endsWith(`/${right}`) || right.endsWith(`/${left}`);
}

function rangesOverlap(a1: number, a2: number, b1: number, b2: number, tolerance: number): boolean {
  return a1 <= b2 + tolerance && b1 <= a2 + tolerance;
}

export interface ScoreResult {
  detected: boolean;
  localization: "exact" | "fuzzy" | "none";
  matched_regions: number;
  total_regions: number;
  total_findings: number;
  findings_on_target: number;
}

/** Pure scorer: does the report locate any vulnerable region from the fix diff? */
export function scoreReport(regions: TruthRegion[], report: SecurityReport, tolerance = DEFAULT_TOLERANCE): ScoreResult {
  const regionHit = regions.map(() => false);
  const findingHit = report.findings.map(() => false);
  let exact = false;
  let fuzzy = false;
  report.findings.forEach((finding, findingIndex) => {
    for (const location of finding.locations) {
      regions.forEach((region, regionIndex) => {
        if (!samefile(location.path, region.file)) return;
        if (rangesOverlap(location.start_line, location.end_line, region.start_line, region.end_line, 0)) {
          regionHit[regionIndex] = true; findingHit[findingIndex] = true; exact = true;
        } else if (rangesOverlap(location.start_line, location.end_line, region.start_line, region.end_line, tolerance)) {
          regionHit[regionIndex] = true; findingHit[findingIndex] = true; fuzzy = true;
        }
      });
    }
  });
  const matched = regionHit.filter(Boolean).length;
  return {
    detected: matched > 0,
    localization: exact ? "exact" : fuzzy ? "fuzzy" : "none",
    matched_regions: matched,
    total_regions: regions.length,
    total_findings: report.findings.length,
    findings_on_target: findingHit.filter(Boolean).length
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

interface Aggregate {
  profile_id: string;
  cases_expected: number;
  cases_with_run: number;
  detected: number;
  exact: number;
  fuzzy: number;
  no_result: number;
  recall: number | null;
  recall_by_difficulty: Record<string, { detected: number; total: number }>;
  findings_total: number;
  findings_on_target: number;
  on_target_rate: number | null;
}

export async function buildDetectionReport(root: string, suite: SuiteConfig, tolerance = DEFAULT_TOLERANCE): Promise<string> {
  const cases = suite.cases.filter((candidate) => candidate.fix_commit);
  if (!cases.length) throw new Error("Suite has no fix_commit cases; detection scoring needs ground-truth cases");

  const truthByCase = new Map<string, TruthCase>();
  for (const fixture of cases) {
    const cache = await prepareFixture(root, suite.id, fixture);
    truthByCase.set(fixture.id, await deriveTruth(root, cache, suite.id, fixture));
  }
  const difficultyByCase = new Map(cases.map((candidate) => [candidate.id, (candidate.difficulty ?? "unknown") as CaseDifficulty | "unknown"]));

  // Latest complete run per (profile, case); otherwise the latest run of any state.
  const runFiles = await collectRunFiles(path.join(root, "runs", suite.id));
  const latest = new Map<string, { metadata: RunMetadata; dir: string }>();
  for (const runFile of runFiles) {
    const metadata = await readJson<RunMetadata>(runFile);
    if (!truthByCase.has(metadata.case_id)) continue;
    const key = `${metadata.profile_id}::${metadata.case_id}`;
    const previous = latest.get(key);
    const better = !previous
      || (metadata.state === "complete" && previous.metadata.state !== "complete")
      || (metadata.state === previous.metadata.state && metadata.run_id > previous.metadata.run_id);
    if (better) latest.set(key, { metadata, dir: path.dirname(runFile) });
  }

  const profileIds = [...new Set([...latest.values()].map((entry) => entry.metadata.profile_id))].sort();
  const scores: RunScore[] = [];
  for (const profileId of profileIds) {
    for (const fixture of cases) {
      const entry = latest.get(`${profileId}::${fixture.id}`);
      const truth = truthByCase.get(fixture.id)!;
      const difficulty = difficultyByCase.get(fixture.id) ?? "unknown";
      if (!entry || entry.metadata.state !== "complete") {
        scores.push({
          schema_version: "1.0", suite_id: suite.id, case_id: fixture.id, profile_id: profileId,
          run_id: entry?.metadata.run_id ?? "", state: entry?.metadata.state ?? "prepared", difficulty,
          detected: false, localization: "none", matched_regions: 0, total_regions: truth.regions.length,
          total_findings: 0, findings_on_target: 0
        });
        continue;
      }
      const report = await readJson<SecurityReport>(path.join(entry.dir, "report.json"));
      const result = scoreReport(truth.regions, report, tolerance);
      const runScore: RunScore = {
        schema_version: "1.0", suite_id: suite.id, case_id: fixture.id, profile_id: profileId,
        run_id: entry.metadata.run_id, state: entry.metadata.state, difficulty, ...result
      };
      scores.push(runScore);
      await writeJsonAtomic(path.join(entry.dir, "score.json"), runScore);
    }
  }

  const aggregates: Aggregate[] = profileIds.map((profileId) => {
    const rows = scores.filter((score) => score.profile_id === profileId);
    const withRun = rows.filter((score) => score.state === "complete");
    const detected = rows.filter((score) => score.detected).length;
    const byDifficulty: Record<string, { detected: number; total: number }> = {};
    for (const score of rows) {
      const bucket = byDifficulty[score.difficulty] ?? { detected: 0, total: 0 };
      bucket.total += 1;
      if (score.detected) bucket.detected += 1;
      byDifficulty[score.difficulty] = bucket;
    }
    const findingsTotal = rows.reduce((sum, score) => sum + score.total_findings, 0);
    const onTarget = rows.reduce((sum, score) => sum + score.findings_on_target, 0);
    return {
      profile_id: profileId, cases_expected: cases.length, cases_with_run: withRun.length,
      detected, exact: rows.filter((score) => score.localization === "exact").length,
      fuzzy: rows.filter((score) => score.localization === "fuzzy").length,
      no_result: rows.filter((score) => score.state !== "complete").length,
      recall: cases.length ? detected / cases.length : null,
      recall_by_difficulty: byDifficulty,
      findings_total: findingsTotal, findings_on_target: onTarget,
      on_target_rate: findingsTotal ? onTarget / findingsTotal : null
    };
  });
  aggregates.sort((a, b) => (b.recall ?? -1) - (a.recall ?? -1));

  const outputDir = path.join(root, "runs", suite.id, "reports");
  await ensureDir(outputDir);
  const payload = {
    schema_version: "1.0", suite_id: suite.id, generated_at: new Date().toISOString(),
    tolerance_lines: tolerance, cases: cases.map((candidate) => ({ case_id: candidate.id, difficulty: candidate.difficulty ?? "unknown", regions: truthByCase.get(candidate.id)!.regions.length })),
    profiles: aggregates, matrix: scores
  };
  await writeJsonAtomic(path.join(outputDir, "detection.json"), payload);

  const headers = ["profile_id", "recall", "detected", "cases_expected", "cases_with_run", "exact", "fuzzy", "no_result", "on_target_rate"];
  const csv = [headers.join(","), ...aggregates.map((row) => headers.map((key) => JSON.stringify((row as unknown as Record<string, unknown>)[key] ?? "")).join(","))].join("\n");
  await writeFile(path.join(outputDir, "detection.csv"), `${csv}\n`, "utf8");
  await writeFile(path.join(outputDir, "detection.html"), renderHtml(payload), "utf8");
  return outputDir;
}

function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]!);
}

function pct(value: number | null): string {
  return value === null ? "—" : `${Math.round(value * 100)}%`;
}

function renderHtml(payload: {
  suite_id: string; generated_at: string; tolerance_lines: number;
  cases: { case_id: string; difficulty: string; regions: number }[];
  profiles: Aggregate[];
  matrix: RunScore[];
}): string {
  const cells = new Map(payload.matrix.map((score) => [`${score.profile_id}::${score.case_id}`, score]));
  const profileIds = payload.profiles.map((profile) => profile.profile_id);

  const bars = payload.profiles.map((profile) => {
    const width = Math.round((profile.recall ?? 0) * 100);
    return `<div class="bar-row"><span class="bar-label">${esc(profile.profile_id)}</span><span class="bar-track"><span class="bar-fill" style="width:${width}%"></span></span><span class="bar-value">${pct(profile.recall)} <small>(${profile.detected}/${profile.cases_expected})</small></span></div>`;
  }).join("");

  const heatHead = `<tr><th>Vulnerability (case)</th><th>Diff.</th>${profileIds.map((id) => `<th>${esc(id)}</th>`).join("")}</tr>`;
  const heatBody = payload.cases.map((caseInfo) => {
    const row = profileIds.map((profileId) => {
      const score = cells.get(`${profileId}::${caseInfo.case_id}`);
      if (!score || score.state !== "complete") return `<td class="cell miss-run" title="${esc(score?.state ?? "no run")}">no run</td>`;
      if (!score.detected) return `<td class="cell miss" title="${score.total_findings} findings, none on target">miss</td>`;
      const label = score.localization === "exact" ? "exact" : "≈fuzzy";
      return `<td class="cell hit ${score.localization}" title="${score.matched_regions}/${score.total_regions} regions">${label}</td>`;
    }).join("");
    return `<tr><td class="case">${esc(caseInfo.case_id)}</td><td class="diff">${esc(caseInfo.difficulty)}</td>${row}</tr>`;
  }).join("");

  const summaryHead = `<tr><th>Model</th><th>Recall</th><th>Detected</th><th>Exact</th><th>Fuzzy</th><th>No run</th><th>On-target findings</th></tr>`;
  const summaryBody = payload.profiles.map((profile) => `<tr><td class="case">${esc(profile.profile_id)}</td><td>${pct(profile.recall)}</td><td>${profile.detected}/${profile.cases_expected}</td><td>${profile.exact}</td><td>${profile.fuzzy}</td><td>${profile.no_result}</td><td>${pct(profile.on_target_rate)} <small>(${profile.findings_on_target}/${profile.findings_total})</small></td></tr>`).join("");

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(payload.suite_id)} detection</title><style>
:root{--bg:#fff;--fg:#1f2328;--muted:#6b7280;--line:#d0d7de;--head:#f6f8fa;--hit:#1a7f37;--hitbg:#dafbe1;--fuzzybg:#fff8c5;--miss:#cf222e;--missbg:#ffebe9;--norun:#eaeef2;--track:#eaeef2;--fill:#0969da}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#30363d;--head:#161b22;--hitbg:#1b3226;--fuzzybg:#3a3212;--missbg:#3a1a1c;--norun:#21262d;--track:#21262d;--fill:#4493f8}}
*{box-sizing:border-box}body{font:14px/1.5 system-ui,sans-serif;margin:0;padding:32px;background:var(--bg);color:var(--fg)}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:32px 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.meta{color:var(--muted);font-size:12px;margin-bottom:8px}
.bar-row{display:flex;align-items:center;gap:12px;margin:6px 0}.bar-label{width:180px;font-weight:600;text-align:right}
.bar-track{flex:1;height:22px;background:var(--track);border-radius:4px;overflow:hidden}.bar-fill{display:block;height:100%;background:var(--fill)}
.bar-value{width:140px}small{color:var(--muted)}
.scroll{overflow-x:auto}table{border-collapse:collapse;min-width:100%;font-size:13px}
th,td{border:1px solid var(--line);padding:6px 10px;text-align:center}th{background:var(--head)}
td.case,td.diff{text-align:left}th:first-child,td.case{text-align:left}
.cell{font-weight:600}.hit{color:var(--hit);background:var(--hitbg)}.fuzzy{background:var(--fuzzybg)}.miss{color:var(--miss);background:var(--missbg)}.miss-run{color:var(--muted);background:var(--norun)}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin:10px 0;font-size:12px;color:var(--muted)}.legend span{display:inline-flex;align-items:center;gap:6px}.swatch{width:12px;height:12px;border-radius:3px;display:inline-block}
</style></head><body>
<h1>${esc(payload.suite_id)} — vulnerability detection</h1>
<div class="meta">Generated ${esc(payload.generated_at)} · line tolerance ±${payload.tolerance_lines} · ground truth from security-fix diffs</div>
<h2>Recall — share of known vulnerabilities each model located</h2>
${bars}
<h2>Detection matrix</h2>
<div class="legend"><span><i class="swatch" style="background:var(--hitbg)"></i>exact — flagged the fixed line</span><span><i class="swatch" style="background:var(--fuzzybg)"></i>fuzzy — within ±${payload.tolerance_lines} lines</span><span><i class="swatch" style="background:var(--missbg)"></i>miss — reported findings, none on target</span><span><i class="swatch" style="background:var(--norun)"></i>no run — refused/incomplete/absent</span></div>
<div class="scroll"><table><thead>${heatHead}</thead><tbody>${heatBody}</tbody></table></div>
<h2>Summary</h2>
<div class="scroll"><table><thead>${summaryHead}</thead><tbody>${summaryBody}</tbody></table></div>
<p class="meta">Recall counts a vulnerability as detected when a finding's location overlaps the fix-diff lines. "On-target findings" is the share of all reported findings that landed on a known vulnerability — a rough precision signal, but unmatched findings may be real bugs outside the seeded set, so read it as directional, not as a false-positive rate.</p>
</body></html>`;
}
