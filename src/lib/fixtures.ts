import { access, rm } from "node:fs/promises";
import path from "node:path";
import type { RunVariant, SuiteCase } from "../types.js";
import { ensureDir } from "./fs.js";
import { requireSuccess } from "./process.js";

async function exists(file: string): Promise<boolean> {
  try { await access(file); return true; } catch { return false; }
}

/**
 * The commit a model actually scans. For a plain case that is `commit`; for a
 * known-fix case it is the parent of `fix_commit` (the last vulnerable state).
 * A control run scans `fix_commit` itself — the patched code — so findings on
 * the fixed region are confirmed false positives.
 * Requires the fixture cache to already contain fix_commit (post-fetch).
 */
export async function scanCommit(cache: string, fixture: SuiteCase, variant: RunVariant = "scan"): Promise<string> {
  if (fixture.fix_commit) {
    const target = variant === "control" ? fixture.fix_commit : `${fixture.fix_commit}~1`;
    return (await requireSuccess("git", ["rev-parse", target], cache)).toLowerCase();
  }
  if (variant === "control") throw new Error(`Case ${fixture.id} has no fix_commit; control runs need a known-fix case`);
  if (!fixture.commit) throw new Error(`Case ${fixture.id} has neither commit nor fix_commit`);
  return fixture.commit.toLowerCase();
}

export async function prepareFixture(root: string, suiteId: string, fixture: SuiteCase): Promise<string> {
  const cache = path.join(root, ".bench", "fixtures", suiteId, fixture.id);
  await ensureDir(path.dirname(cache));
  if (!(await exists(path.join(cache, ".git")))) {
    await rm(cache, { recursive: true, force: true });
    await requireSuccess("git", ["clone", "--no-checkout", fixture.repository, cache], root);
  }
  await requireSuccess("git", ["fetch", "--force", "--tags", "origin"], cache);
  const target = await scanCommit(cache, fixture);
  await requireSuccess("git", ["checkout", "--force", "--detach", target], cache);
  const actual = await requireSuccess("git", ["rev-parse", "HEAD"], cache);
  if (actual.toLowerCase() !== target) throw new Error(`Fixture commit mismatch: ${actual}`);
  return cache;
}

export async function createWorkspace(cache: string, target: string, commit: string): Promise<void> {
  await rm(target, { recursive: true, force: true });
  await ensureDir(path.dirname(target));
  await requireSuccess("git", ["clone", "--local", "--no-hardlinks", cache, target]);
  await requireSuccess("git", ["checkout", "--force", "--detach", commit], target);
  await rm(path.join(target, ".git"), { recursive: true, force: true });
}
