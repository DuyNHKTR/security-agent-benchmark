import { access, rm } from "node:fs/promises";
import path from "node:path";
import type { SuiteCase } from "../types.js";
import { ensureDir } from "./fs.js";
import { requireSuccess } from "./process.js";

async function exists(file: string): Promise<boolean> {
  try { await access(file); return true; } catch { return false; }
}

/**
 * The commit a model actually scans. For a plain case that is `commit`; for a
 * known-fix case it is the parent of `fix_commit` (the last vulnerable state).
 * Requires the fixture cache to already contain fix_commit (post-fetch).
 */
export async function scanCommit(cache: string, fixture: SuiteCase): Promise<string> {
  if (fixture.fix_commit) {
    return (await requireSuccess("git", ["rev-parse", `${fixture.fix_commit}~1`], cache)).toLowerCase();
  }
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
}
