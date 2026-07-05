import path from "node:path";
import type { SuiteCase, SuiteConfig, TruthCase, TruthRegion } from "../types.js";
import { writeJsonAtomic } from "./fs.js";
import { prepareFixture } from "./fixtures.js";
import { runProcess, requireSuccess } from "./process.js";

// Paths whose diff hunks are not treated as vulnerable-code ground truth. A
// security fix routinely touches tests, docs, and lockfiles alongside the real
// change; counting those as the vulnerability location would create false truth.
const IGNORE_DIR = /(^|\/)(tests?|spec|specs|__tests__|__mocks__|docs?|doc|examples?|example|samples?|fixtures?|testdata|vendor|third_party|node_modules|dist|build)(\/|$)/i;
const IGNORE_EXT = /\.(md|markdown|rst|txt|lock|snap|map|min\.js|min\.css)$/i;
const IGNORE_NAME = /(^|\/)(CHANGELOG|CHANGES|HISTORY|NEWS|AUTHORS|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|go\.sum|poetry\.lock|Cargo\.lock)$/i;

function ignored(file: string): boolean {
  return IGNORE_DIR.test(file) || IGNORE_EXT.test(file) || IGNORE_NAME.test(file);
}

/**
 * Parse `git diff --unified=0` and return, per changed file, the line ranges in
 * the PRE-image (the vulnerable commit) that the fix modified. Those ranges are
 * where the vulnerability lived. Pure additions (the fix inserts a check) are
 * anchored to the insertion point as a two-line window.
 */
export function parseUnifiedDiff(diff: string): TruthRegion[] {
  const regions: TruthRegion[] = [];
  let file = "";
  for (const line of diff.split(/\r?\n/)) {
    if (line.startsWith("--- ")) {
      const raw = line.slice(4).trim();
      file = raw === "/dev/null" ? "" : raw.replace(/^a\//, "");
    } else if (line.startsWith("@@")) {
      const match = /^@@ -(\d+)(?:,(\d+))? \+/.exec(line);
      if (!match || !file || ignored(file)) continue;
      const start = Number(match[1]);
      const count = match[2] === undefined ? 1 : Number(match[2]);
      if (count === 0) regions.push({ file, start_line: Math.max(1, start), end_line: Math.max(1, start) + 1 });
      else regions.push({ file, start_line: start, end_line: start + count - 1 });
    }
  }
  return regions;
}

export function mergeRegions(regions: TruthRegion[]): TruthRegion[] {
  const byFile = new Map<string, TruthRegion[]>();
  for (const region of regions) {
    const list = byFile.get(region.file) ?? [];
    list.push(region);
    byFile.set(region.file, list);
  }
  const merged: TruthRegion[] = [];
  for (const [file, list] of byFile) {
    list.sort((a, b) => a.start_line - b.start_line);
    let current: TruthRegion | null = null;
    for (const region of list) {
      if (current && region.start_line <= current.end_line + 1) {
        current.end_line = Math.max(current.end_line, region.end_line);
      } else {
        current = { file, start_line: region.start_line, end_line: region.end_line };
        merged.push(current);
      }
    }
  }
  return merged;
}

export async function deriveTruth(root: string, cache: string, suiteId: string, fixture: SuiteCase): Promise<TruthCase> {
  if (!fixture.fix_commit) throw new Error(`Case ${fixture.id} has no fix_commit; ground truth needs a security-fix commit`);
  const scan = (await requireSuccess("git", ["rev-parse", `${fixture.fix_commit}~1`], cache)).toLowerCase();
  const result = await runProcess("git", ["diff", "--unified=0", "--no-color", "--no-ext-diff", scan, fixture.fix_commit], { cwd: cache });
  if (result.exitCode !== 0) throw new Error(`git diff failed for ${fixture.id}: ${result.stderr.trim()}`);
  const regions = mergeRegions(parseUnifiedDiff(result.stdout));
  if (!regions.length) throw new Error(`Case ${fixture.id}: fix ${fixture.fix_commit} touched no scorable source lines (only tests/docs?). Pick a fix whose diff changes application code.`);
  const truth: TruthCase = {
    schema_version: "1.0",
    case_id: fixture.id,
    repository: fixture.repository,
    fix_commit: fixture.fix_commit,
    scan_commit: scan,
    difficulty: fixture.difficulty ?? "unknown",
    regions
  };
  await writeJsonAtomic(path.join(root, ".bench", "truth", suiteId, `${fixture.id}.json`), truth);
  return truth;
}

export async function buildTruthForSuite(root: string, suite: SuiteConfig): Promise<TruthCase[]> {
  const known = suite.cases.filter((candidate) => candidate.fix_commit);
  if (!known.length) throw new Error("Suite has no fix_commit cases; nothing to derive ground truth from");
  const built: TruthCase[] = [];
  for (const fixture of known) {
    const cache = await prepareFixture(root, suite.id, fixture);
    built.push(await deriveTruth(root, cache, suite.id, fixture));
  }
  return built;
}
