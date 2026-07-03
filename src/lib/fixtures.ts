import { access, rm } from "node:fs/promises";
import path from "node:path";
import type { SuiteCase } from "../types.js";
import { ensureDir } from "./fs.js";
import { requireSuccess } from "./process.js";

async function exists(file: string): Promise<boolean> {
  try { await access(file); return true; } catch { return false; }
}

export async function prepareFixture(root: string, suiteId: string, fixture: SuiteCase): Promise<string> {
  const cache = path.join(root, ".bench", "fixtures", suiteId, fixture.id);
  await ensureDir(path.dirname(cache));
  if (!(await exists(path.join(cache, ".git")))) {
    await rm(cache, { recursive: true, force: true });
    await requireSuccess("git", ["clone", "--no-checkout", fixture.repository, cache], root);
  }
  await requireSuccess("git", ["fetch", "--force", "--tags", "origin"], cache);
  await requireSuccess("git", ["checkout", "--force", "--detach", fixture.commit], cache);
  const actual = await requireSuccess("git", ["rev-parse", "HEAD"], cache);
  if (actual.toLowerCase() !== fixture.commit.toLowerCase()) throw new Error(`Fixture commit mismatch: ${actual}`);
  return cache;
}

export async function createWorkspace(cache: string, target: string, commit: string): Promise<void> {
  await rm(target, { recursive: true, force: true });
  await ensureDir(path.dirname(target));
  await requireSuccess("git", ["clone", "--local", "--no-hardlinks", cache, target]);
  await requireSuccess("git", ["checkout", "--force", "--detach", commit], target);
}
