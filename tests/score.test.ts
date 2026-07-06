import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseUnifiedDiff, mergeRegions } from "../src/lib/truth.js";
import { scoreReport, buildDetectionReport } from "../src/lib/score.js";
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

test("scores exact, fuzzy, and miss against ground-truth regions", () => {
  const regions = [{ file: "src/server.js", start_line: 10, end_line: 12 }];
  const exact = scoreReport(regions, validReport());
  assert.equal(exact.detected, true);
  assert.equal(exact.localization, "exact");

  const fuzzyReport = validReport();
  fuzzyReport.findings[0].locations[0].start_line = 15;
  fuzzyReport.findings[0].locations[0].end_line = 15;
  assert.equal(scoreReport(regions, fuzzyReport).localization, "fuzzy");
  assert.equal(scoreReport(regions, fuzzyReport, 1).localization, "none");

  const missReport = validReport();
  missReport.findings[0].locations[0].path = "src/other.js";
  const miss = scoreReport(regions, missReport);
  assert.equal(miss.detected, false);
  assert.equal(miss.findings_on_target, 0);

  const ambiguousBasename = validReport();
  ambiguousBasename.findings[0].locations[0].path = "server.js";
  assert.equal(scoreReport(regions, ambiguousBasename).detected, false);
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

  const suite: SuiteConfig = {
    id: "s", description: "", prompt_version: "v1", pricing_catalog: "",
    cases: [{ id: "c1", repository: source, fix_commit: fixSha, difficulty: "easy", finding_limit: 5 }],
    profiles: ["missing-profile.yaml"]
  };
  await writeFile(path.join(root, "missing-profile.yaml"), [
    "id: model-y",
    "adapter: codex",
    "model: y",
    "pricing_key: y",
    "cost_mode: token",
    "execution: docker",
    ""
  ].join("\n"));

  const runDir = path.join(root, "runs", "s", "c1", "model-x", "run-1");
  const metadata: RunMetadata = {
    schema_version: "1.0", run_id: "run-1", suite_id: "s", case_id: "c1", profile_id: "model-x",
    adapter: "codex", model: "x", pricing_key: "x", cost_mode: "token", repository: source,
    commit: "a".repeat(40), prompt_sha256: "b".repeat(64), state: "complete",
    started_at: null, completed_at: null, duration_ms: null,
    usage: { input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0, provenance: "unavailable" },
    cost_usd: null, cost_basis: "unavailable", errors: []
  };
  await writeJsonAtomic(path.join(runDir, "run.json"), metadata);
  const report = validReport();
  report.findings[0].locations[0] = { path: "app.js", start_line: 2, end_line: 2, symbol: "pwd" };
  await writeJsonAtomic(path.join(runDir, "report.json"), report);

  const outputDir = await buildDetectionReport(root, suite);
  const detection = JSON.parse(await readFile(path.join(outputDir, "detection.json"), "utf8"));
  assert.equal(detection.profiles[0].profile_id, "model-x");
  assert.equal(detection.profiles[0].recall, 1);
  assert.equal(detection.profiles[0].detected, 1);
  assert.equal(detection.profiles[1].profile_id, "model-y");
  assert.equal(detection.profiles[1].recall, 0);
  assert.equal(detection.profiles[1].no_result, 1);
  assert.equal(detection.matrix[0].localization, "exact");
  const html = await readFile(path.join(outputDir, "detection.html"), "utf8");
  assert.match(html, /detection matrix/i);
  assert.match(html, /exact/);
});
