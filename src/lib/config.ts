import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse } from "yaml";
import type { ModelProfile, SuiteConfig } from "../types.js";
import { resolveFrom } from "./fs.js";

async function loadYaml<T>(file: string): Promise<T> {
  return parse(await readFile(file, "utf8")) as T;
}

function validateProfile(profile: ModelProfile, source: string): ModelProfile {
  if (!profile.id || !profile.model || !["codex", "claude-code"].includes(profile.adapter)) {
    throw new Error(`Invalid model profile: ${source}`);
  }
  if (!["token", "subscription"].includes(profile.cost_mode) || !["docker", "local"].includes(profile.execution)) {
    throw new Error(`Invalid cost_mode or execution in profile: ${source}`);
  }
  if (profile.adapter === "claude-code" && (profile.cost_mode !== "subscription" || profile.execution !== "local")) {
    throw new Error(`Claude Code profile must use subscription cost and local execution: ${source}`);
  }
  return profile;
}

export async function loadSuite(root: string, file: string): Promise<{ suite: SuiteConfig; file: string }> {
  const resolved = resolveFrom(root, file);
  const suite = await loadYaml<SuiteConfig>(resolved);
  if (!suite.id || !Array.isArray(suite.cases) || !Array.isArray(suite.profiles)) {
    throw new Error(`Invalid suite manifest: ${resolved}`);
  }
  return { suite, file: resolved };
}

export async function loadProfiles(root: string, suite: SuiteConfig): Promise<ModelProfile[]> {
  return Promise.all(suite.profiles.map(async (entry) => {
    const profile = await loadYaml<ModelProfile>(resolveFrom(root, entry));
    return validateProfile(profile, entry);
  }));
}

export async function selectProfile(root: string, suite: SuiteConfig, idOrPath: string): Promise<ModelProfile> {
  if (idOrPath.endsWith(".yaml") || idOrPath.endsWith(".yml")) {
    return validateProfile(await loadYaml<ModelProfile>(resolveFrom(root, idOrPath)), idOrPath);
  }
  const profile = (await loadProfiles(root, suite)).find((candidate) => candidate.id === idOrPath);
  if (!profile) throw new Error(`Profile not found in suite: ${idOrPath}`);
  return profile;
}

const FULL_SHA = /^[a-fA-F0-9]{40,64}$/;

export function suiteCase(suite: SuiteConfig, id: string) {
  const selected = suite.cases.find((candidate) => candidate.id === id);
  if (!selected) throw new Error(`Case not found in suite: ${id}`);
  const hasCommit = typeof selected.commit === "string" && FULL_SHA.test(selected.commit);
  const hasFix = typeof selected.fix_commit === "string" && FULL_SHA.test(selected.fix_commit);
  if (selected.commit && selected.fix_commit) {
    throw new Error(`Case ${id} must set either commit or fix_commit, not both`);
  }
  if (!hasCommit && !hasFix) {
    throw new Error(`Case ${id} must use a full immutable commit SHA in commit or fix_commit`);
  }
  return selected;
}

export function relativeToRoot(root: string, file: string): string {
  return path.relative(root, file).replaceAll("\\", "/");
}
