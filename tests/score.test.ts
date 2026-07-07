import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseUnifiedDiff, mergeRegions, normalizeCwe, expectedCwes } from "../src/lib/truth.js";
import { scoreReport, buildDetectionReport, fixPredatesCutoff } from "../src/lib/score.js";
import { fmt, locales, reportLangs } from "../src/lib/report-i18n.js";
import { findBrowser } from "../src/lib/pdf.js";
import { wilsonInterval, mcnemarExact } from "../src/lib/stats.js";
import { writeJsonAtomic } from "../src/lib/fs.js";
import { requireSuccess } from "../src/lib/process.js";
import type { RunMetadata, SuiteConfig } from "../src/types.js";
import { validReport } from "./helpers.js";

test("parses pre-image regions and ignores test/doc noise", () => {
  const diff = [
    "diff --git a/src/app.js b/src/app.js",
    "--- a/src/app.js",
    "+++ b/src/app.js",
    "@@ -10,2 +10,3 @@",
    "diff --git a/test/app.test.js b/test/app.test.js",
    "--- a/test/app.test.js",
    "+++ b/test/app.test.js",
    "@@ -5,0 +6,4 @@",
    "diff --git a/src/util.js b/src/util.js",
    "--- a/src/util.js",
    "+++ b/src/util.js",
    "@@ -40,0 +41,1 @@"
  ].join("\n");
  const regions = mergeRegions(parseUnifiedDiff(diff));
  assert.deepEqual(regions, [
    { file: "src/app.js", start_line: 10, end_line: 11 },
    { file: "src/util.js", start_line: 40, end_line: 41 }
  ]);
});

test("parses post-image regions for control runs, including renames and deletions", () => {
  const diff = [
    "diff --git a/src/app.js b/src/app.js",
    "--- a/src/app.js",
    "+++ b/src/app.js",
    "@@ -10,2 +12,3 @@",
    "diff --git a/src/old.js b/src/renamed.js",
    "--- a/src/old.js",
    "+++ b/src/renamed.js",
    "@@ -4,1 +7,2 @@",
    "diff --git a/src/gone.js b/src/gone.js",
    "--- a/src/gone.js",
    "+++ /dev/null",
    "@@ -1,3 +0,0 @@",
    "diff --git a/src/trim.js b/src/trim.js",
    "--- a/src/trim.js",
    "+++ b/src/trim.js",
    "@@ -20,2 +19,0 @@"
  ].join("\n");
  const regions = mergeRegions(parseUnifiedDiff(diff, "post"));
  // Pure deletions produce no post-image region: no patched line exists there,
  // so nothing at that offset can be a confirmed false positive.
  assert.deepEqual(regions, [
    { file: "src/app.js", start_line: 12, end_line: 14 },
    { file: "src/renamed.js", start_line: 7, end_line: 8 }
  ]);
  // The same deletion still anchors a pre-image window for scan scoring.
  assert.ok(parseUnifiedDiff(diff, "pre").some((region) => region.file === "src/trim.js"));
});

test("normalizes advisory CWE ids", () => {
  assert.equal(normalizeCwe("CWE-79"), "CWE-79");
  assert.equal(normalizeCwe("cwe-0089"), "CWE-89");
  assert.equal(normalizeCwe("89"), "CWE-89");
  assert.equal(normalizeCwe("none"), null);
  assert.deepEqual(
    expectedCwes({ id: "c", repository: "r", cwe: ["CWE-79", "cwe-79", "352"], finding_limit: 5 }),
    ["CWE-79", "CWE-352"]
  );
  assert.throws(() => expectedCwes({ id: "c", repository: "r", cwe: "bogus", finding_limit: 5 }));
});

test("scores exact, fuzzy, and miss against ground-truth regions", () => {
  const regions = [{ file: "src/server.js", start_line: 10, end_line: 12 }];
  const exact = scoreReport(regions, validReport());
  assert.equal(exact.detected, true);
  assert.equal(exact.located, true);
  assert.equal(exact.localization, "exact");
  assert.equal(exact.semantic, "not_configured");

  const fuzzyReport = validReport();
  fuzzyReport.findings[0].locations[0].start_line = 15;
  fuzzyReport.findings[0].locations[0].end_line = 15;
  assert.equal(scoreReport(regions, fuzzyReport).localization, "fuzzy");
  assert.equal(scoreReport(regions, fuzzyReport, { tolerance: 1 }).localization, "none");

  const missReport = validReport();
  missReport.findings[0].locations[0].path = "src/other.js";
  const miss = scoreReport(regions, missReport);
  assert.equal(miss.detected, false);
  assert.equal(miss.findings_on_target, 0);

  const ambiguousBasename = validReport();
  ambiguousBasename.findings[0].locations[0].path = "server.js";
  assert.equal(scoreReport(regions, ambiguousBasename).detected, false);
});

test("span cap denies credit to broad locations, including tiling across many small ones", () => {
  const regions = [{ file: "src/server.js", start_line: 10, end_line: 12 }];
  const broad = validReport();
  broad.findings[0].locations[0].start_line = 1;
  broad.findings[0].locations[0].end_line = 5000;
  const capped = scoreReport(regions, broad);
  assert.equal(capped.detected, false);
  assert.equal(capped.located, false);
  assert.equal(capped.findings_oversized_only, 1);
  // Disabling the cap restores the old permissive behavior.
  assert.equal(scoreReport(regions, broad, { spanCap: 0 }).detected, true);
  // The cap is on the finding's TOTAL cited lines: adding a precise location to
  // a giant one does not restore credit (no mixing around the cap)...
  broad.findings[0].locations.push({ path: "src/server.js", start_line: 11, end_line: 11, symbol: "getItem" });
  assert.equal(scoreReport(regions, broad).detected, false);
  // ...and tiling a file with many under-cap locations earns nothing either.
  const tiling = validReport();
  tiling.findings[0].locations = Array.from({ length: 50 }, (unused, index) => ({
    path: "src/server.js", start_line: index * 40 + 1, end_line: index * 40 + 40, symbol: "tile"
  }));
  const tiled = scoreReport(regions, tiling);
  assert.equal(tiled.detected, false);
  assert.equal(tiled.located, false);
  assert.equal(tiled.findings_oversized_only, 1);
  assert.equal(tiled.findings_on_target, 0);
  // Two tight locations (source + sink) within the total cap keep full credit.
  const paired = validReport();
  paired.findings[0].locations = [
    { path: "src/server.js", start_line: 11, end_line: 11, symbol: "source" },
    { path: "src/db.js", start_line: 80, end_line: 84, symbol: "sink" }
  ];
  assert.equal(scoreReport(regions, paired).detected, true);
});

test("expected CWE splits detected from location-only hits", () => {
  const regions = [{ file: "src/server.js", start_line: 10, end_line: 12 }];
  const report = validReport(); // finding reports CWE-89
  const match = scoreReport(regions, report, { expectedCwe: ["CWE-89"] });
  assert.equal(match.detected, true);
  assert.equal(match.semantic, "match");

  const mismatch = scoreReport(regions, report, { expectedCwe: ["CWE-79"] });
  assert.equal(mismatch.detected, false);
  assert.equal(mismatch.located, true);
  assert.equal(mismatch.semantic, "mismatch");
});

test("localization credit follows the CWE-qualifying finding, not a wrong-CWE exact hit", () => {
  const regions = [{ file: "src/server.js", start_line: 10, end_line: 12 }];
  const report = validReport();
  // Finding A: exact location, wrong CWE.
  report.findings[0].cwe = "CWE-79";
  // Finding B: fuzzy location (within tolerance), correct CWE.
  const b = structuredClone(report.findings[0]);
  b.id = "SEC-002";
  b.cwe = "CWE-89";
  b.locations = [{ path: "src/server.js", start_line: 15, end_line: 15, symbol: "getItem" }];
  report.findings.push(b);
  const result = scoreReport(regions, report, { expectedCwe: ["CWE-89"] });
  assert.equal(result.detected, true);
  assert.equal(result.semantic, "match");
  // Strict recall must not be inflated by the wrong-CWE exact hit.
  assert.equal(result.localization, "fuzzy");
});

test("tracks on-target counts per confidence bucket", () => {
  const regions = [{ file: "src/server.js", start_line: 10, end_line: 12 }];
  const report = validReport();
  const offTarget = structuredClone(report.findings[0]);
  offTarget.id = "SEC-002";
  offTarget.confidence = "low";
  offTarget.locations = [{ path: "src/other.js", start_line: 1, end_line: 2, symbol: "x" }];
  report.findings.push(offTarget);
  const result = scoreReport(regions, report);
  assert.deepEqual(result.on_target_by_confidence.high, { on_target: 1, total: 1 });
  assert.deepEqual(result.on_target_by_confidence.low, { on_target: 0, total: 1 });
});

test("date-only training cutoff covers the whole cutoff day", () => {
  assert.equal(fixPredatesCutoff("2026-01-31T18:00:00Z", "2026-01-31"), true);
  assert.equal(fixPredatesCutoff("2026-02-01T00:00:00Z", "2026-01-31"), false);
  assert.equal(fixPredatesCutoff("2026-01-31T18:00:00Z", "2026-01-31T12:00:00Z"), false);
  assert.equal(fixPredatesCutoff("2026-01-31T18:00:00Z", undefined), null);
  assert.equal(fixPredatesCutoff("2026-01-31T18:00:00Z", "not-a-date"), null);
});

test("wilson interval and exact mcnemar behave at small n", () => {
  assert.equal(wilsonInterval(0, 0), null);
  const full = wilsonInterval(5, 5)!;
  assert.ok(full.lower > 0.5 && full.upper === 1);
  const half = wilsonInterval(1, 2)!;
  assert.ok(half.lower > 0 && half.upper < 1);

  assert.equal(mcnemarExact(0, 0), null);
  assert.equal(mcnemarExact(1, 0), 1);
  const p = mcnemarExact(8, 0)!;
  assert.ok(p < 0.01 && p > 0);
  assert.equal(mcnemarExact(3, 3), 1);
});

test("derives ground truth from a fix commit and builds a detection report", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "bench-score-"));
  const source = path.join(root, "source");
  const git = (args: string[]) => requireSuccess("git", args, source);
  await requireSuccess("git", ["init", source]);
  await git(["config", "user.email", "t@example.invalid"]);
  await git(["config", "user.name", "T"]);
  await writeFile(path.join(source, "app.js"), "const a = 1;\nconst pwd = 'hardcoded-secret';\nmodule.exports = a;\n");
  await git(["add", "app.js"]);
  await git(["commit", "-m", "vulnerable"]);
  await writeFile(path.join(source, "app.js"), "const a = 1;\nconst pwd = process.env.PWD;\nmodule.exports = a;\n");
  await git(["add", "app.js"]);
  await git(["commit", "-m", "fix: remove hardcoded secret"]);
  const fixSha = await git(["rev-parse", "HEAD"]);

  // Second case: a deletion-only fix (no patched lines remain), so its control
  // run has no evaluable discrimination site.
  await writeFile(path.join(source, "eval.js"), "const x = 1;\neval(userInput);\nmodule.exports = x;\n");
  await git(["add", "eval.js"]);
  await git(["commit", "-m", "vulnerable eval"]);
  await writeFile(path.join(source, "eval.js"), "const x = 1;\nmodule.exports = x;\n");
  await git(["add", "eval.js"]);
  await git(["commit", "-m", "fix: drop eval"]);
  const deletionFixSha = await git(["rev-parse", "HEAD"]);

  const suite: SuiteConfig = {
    id: "s", description: "", prompt_version: "v1", pricing_catalog: "",
    cases: [
      { id: "c1", repository: source, fix_commit: fixSha, difficulty: "easy", cwe: "CWE-798", finding_limit: 5 },
      { id: "c2", repository: source, fix_commit: deletionFixSha, difficulty: "easy", finding_limit: 5 }
    ],
    profiles: ["missing-profile.yaml"]
  };
  await writeFile(path.join(root, "missing-profile.yaml"), [
    "id: model-y",
    "adapter: codex",
    "model: y",
    "pricing_key: y",
    "cost_mode: token",
    "execution: docker",
    "training_cutoff: 2099-01-01",
    ""
  ].join("\n"));

  const baseMetadata = (profile: string, run: string, caseId = "c1"): RunMetadata => ({
    schema_version: "1.0", run_id: run, suite_id: "s", case_id: caseId, profile_id: profile,
    adapter: "codex", model: "x", pricing_key: "x", cost_mode: "token", repository: source,
    commit: "a".repeat(40), prompt_sha256: "b".repeat(64), state: "complete",
    started_at: null, completed_at: null, duration_ms: null,
    usage: { input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0, provenance: "unavailable" },
    cost_usd: null, cost_basis: "unavailable", errors: []
  });

  // Scan run: hits the vulnerable line with the right CWE.
  const scanDir = path.join(root, "runs", "s", "c1", "model-x", "run-1");
  await writeJsonAtomic(path.join(scanDir, "run.json"), baseMetadata("model-x", "run-1"));
  const report = validReport();
  report.findings[0].cwe = "CWE-798";
  report.findings[0].locations[0] = { path: "app.js", start_line: 2, end_line: 2, symbol: "pwd" };
  await writeJsonAtomic(path.join(scanDir, "report.json"), report);

  // Control run: clean report on the patched commit (no findings on the fix).
  const controlDir = path.join(root, "runs", "s", "c1", "model-x", "run-2");
  await writeJsonAtomic(path.join(controlDir, "run.json"), { ...baseMetadata("model-x", "run-2"), variant: "control" });
  const controlReport = validReport();
  controlReport.findings = [];
  await writeJsonAtomic(path.join(controlDir, "report.json"), controlReport);

  // c2 scan run: hits the deleted eval line (pre-image region).
  const scan2Dir = path.join(root, "runs", "s", "c2", "model-x", "run-3");
  await writeJsonAtomic(path.join(scan2Dir, "run.json"), baseMetadata("model-x", "run-3", "c2"));
  const scan2Report = validReport();
  scan2Report.findings[0].locations[0] = { path: "eval.js", start_line: 2, end_line: 2, symbol: "eval" };
  await writeJsonAtomic(path.join(scan2Dir, "report.json"), scan2Report);

  // c2 control run: the fix only deleted lines, so no patched site exists and
  // this control must not count toward discrimination no matter what it reports.
  const control2Dir = path.join(root, "runs", "s", "c2", "model-x", "run-4");
  await writeJsonAtomic(path.join(control2Dir, "run.json"), { ...baseMetadata("model-x", "run-4", "c2"), variant: "control" });
  const control2Report = validReport();
  control2Report.findings[0].locations[0] = { path: "eval.js", start_line: 1, end_line: 2, symbol: "x" };
  await writeJsonAtomic(path.join(control2Dir, "report.json"), control2Report);

  const outputDir = await buildDetectionReport(root, suite, { pdf: false });
  const detection = JSON.parse(await readFile(path.join(outputDir, "detection.json"), "utf8"));
  assert.equal(detection.profiles[0].profile_id, "model-x");
  assert.equal(detection.profiles[0].recall, 1);
  assert.equal(detection.profiles[0].detected, 2);
  assert.ok(detection.profiles[0].recall_ci95.lower > 0);
  assert.equal(detection.profiles[0].control.cases_with_control, 2);
  assert.equal(detection.profiles[0].control.confirmed_false_positives, 0);
  // Only c1 is evaluable: c2's deletion-only fix has no patched site, so its
  // control run must not appear in the discrimination denominator or passes.
  assert.equal(detection.profiles[0].control.discrimination_evaluated, 1);
  assert.equal(detection.profiles[0].control.discrimination_passed, 1);
  assert.equal(detection.profiles[1].profile_id, "model-y");
  assert.equal(detection.profiles[1].recall, 0);
  assert.equal(detection.profiles[1].no_result, 2);
  // model-y's configured cutoff (2099) is after both fix commits → contamination risk.
  assert.equal(detection.profiles[1].contaminated_cases, 2);
  assert.equal(detection.profiles[0].contaminated_cases, null); // no cutoff configured for model-x
  const scanRow = detection.matrix.find((row: { profile_id: string; variant: string; case_id: string }) => row.profile_id === "model-x" && row.variant === "scan" && row.case_id === "c1");
  assert.equal(scanRow.localization, "exact");
  assert.equal(scanRow.semantic, "match");
  const pair = detection.pairwise[0];
  assert.equal(pair.only_a + pair.only_b, 2);
  assert.equal(typeof pair.mcnemar_p, "number");
  const html = await readFile(path.join(outputDir, "detection.html"), "utf8");
  assert.match(html, /<html lang="en">/);
  assert.match(html, /detection matrix/i);
  assert.match(html, /Negative controls/);
  assert.match(html, /Confidence calibration/);
  assert.match(html, /McNemar/);
  // Vietnamese sibling: same report, translated chrome, identical state labels.
  const htmlVi = await readFile(path.join(outputDir, "detection.vi.html"), "utf8");
  assert.match(htmlVi, /<html lang="vi">/);
  assert.match(htmlVi, /Ma trận phát hiện/);
  assert.match(htmlVi, /Đối chứng âm/);
  assert.match(htmlVi, /McNemar/);
  assert.match(htmlVi, /class="cell hit exact"/);

  // A vague oversized control finding that overlaps the patched region earns no
  // confirmed-FP count but must void discrimination (it is not "clean").
  const vagueControl = validReport();
  vagueControl.findings[0].locations = [{ path: "app.js", start_line: 1, end_line: 500, symbol: "everything" }];
  await writeJsonAtomic(path.join(controlDir, "report.json"), vagueControl);
  const rescored = JSON.parse(await readFile(path.join(await buildDetectionReport(root, suite, { pdf: false }), "detection.json"), "utf8"));
  const modelX = rescored.profiles.find((profile: { profile_id: string }) => profile.profile_id === "model-x");
  assert.equal(modelX.control.confirmed_false_positives, 0);
  assert.equal(modelX.control.discrimination_evaluated, 1);
  assert.equal(modelX.control.discrimination_passed, 0);
});

test("report locales cover every key in every language", () => {
  const reference = Object.keys(locales.en).sort();
  for (const lang of reportLangs) {
    assert.deepEqual(Object.keys(locales[lang]).sort(), reference, `locale ${lang} key set`);
    for (const [key, value] of Object.entries(locales[lang])) {
      assert.ok(typeof value === "string" && value.trim().length > 0, `locale ${lang}.${key} is non-empty`);
    }
  }
  // Placeholder sets must match across languages so fmt() fills both templates.
  for (const key of reference) {
    const placeholders = (value: string) => (value.match(/\{\w+\}/g) ?? []).sort();
    assert.deepEqual(
      placeholders(locales.vi[key as keyof typeof locales.vi]),
      placeholders(locales.en[key as keyof typeof locales.en]),
      `placeholders of ${key}`
    );
  }
});

test("fmt interpolates and leaves unknown placeholders visible", () => {
  assert.equal(fmt("{a}/{b} done", { a: 3, b: 4 }), "3/4 done");
  assert.equal(fmt("missing {nope}", {}), "missing {nope}");
});

test("findBrowser prefers BENCH_BROWSER, then falls through install locations", () => {
  const chrome = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  const env = {
    BENCH_BROWSER: "X:\\custom\\browser.exe",
    ProgramFiles: "C:\\Program Files",
    "ProgramFiles(x86)": "C:\\Program Files (x86)"
  } as NodeJS.ProcessEnv;
  const existing = (present: string[]) => (candidate: string) => present.includes(candidate);
  assert.equal(findBrowser({ env, platform: "win32", exists: existing(["X:\\custom\\browser.exe", chrome]) }), "X:\\custom\\browser.exe");
  assert.equal(findBrowser({ env, platform: "win32", exists: existing([chrome, edge]) }), chrome);
  assert.equal(findBrowser({ env, platform: "win32", exists: existing([edge]) }), edge);
  assert.equal(findBrowser({ env, platform: "win32", exists: () => false }), null);
  assert.equal(findBrowser({ env: {}, platform: "linux", exists: existing(["/usr/bin/chromium"]) }), "/usr/bin/chromium");
});
