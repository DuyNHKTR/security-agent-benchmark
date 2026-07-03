import { access, copyFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { ModelProfile, RunMetadata, SuiteCase, SuiteConfig, TokenUsage } from "../types.js";
import { createRunId, ensureDir, readJson, resolveFrom, sha256, writeJsonAtomic, writeTextAtomic } from "./fs.js";
import { createWorkspace, prepareFixture } from "./fixtures.js";
import { renderPrompt } from "./prompt.js";
import { calculateCost } from "./pricing.js";
import { runProcess } from "./process.js";
import { validateReport } from "./schema.js";
import { usageFromJsonLines } from "./usage.js";

export interface PreparedRun {
  dir: string;
  target: string;
  prompt: string;
  metadata: RunMetadata;
}

const emptyUsage = (): TokenUsage => ({ input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0, provenance: "unavailable" });

export async function prepareRun(root: string, suite: SuiteConfig, fixture: SuiteCase, profile: ModelProfile): Promise<PreparedRun> {
  const runId = createRunId();
  const dir = path.join(root, "runs", suite.id, fixture.id, profile.id, runId);
  const target = path.join(dir, "target");
  await ensureDir(dir);
  const cache = await prepareFixture(root, suite.id, fixture);
  await createWorkspace(cache, target, fixture.commit);
  const prompt = await renderPrompt(root, suite.prompt_version, fixture, profile.adapter, {
    target,
    output: dir,
    execution: profile.execution
  });
  await writeTextAtomic(path.join(dir, "prompt.txt"), prompt);
  const metadata: RunMetadata = {
    schema_version: "1.0",
    run_id: runId,
    suite_id: suite.id,
    case_id: fixture.id,
    profile_id: profile.id,
    adapter: profile.adapter,
    model: profile.model,
    pricing_key: profile.pricing_key,
    cost_mode: profile.cost_mode,
    repository: fixture.repository,
    commit: fixture.commit,
    prompt_sha256: sha256(prompt),
    state: "prepared",
    started_at: null,
    completed_at: null,
    duration_ms: null,
    usage: emptyUsage(),
    cost_usd: null,
    cost_basis: "unavailable",
    errors: []
  };
  await writeJsonAtomic(path.join(dir, "run.json"), metadata);
  return { dir, target, prompt, metadata };
}

function dockerEnvironment(root: string, run: PreparedRun): NodeJS.ProcessEnv {
  return {
    ...process.env,
    BENCH_ROOT: root,
    BENCH_TARGET_DIR: run.target,
    BENCH_OUTPUT_DIR: run.dir
  };
}

export async function executeCodex(root: string, suite: SuiteConfig, fixture: SuiteCase, profile: ModelProfile, run: PreparedRun): Promise<void> {
  const started = Date.now();
  run.metadata.state = "running";
  run.metadata.started_at = new Date(started).toISOString();
  await writeJsonAtomic(path.join(run.dir, "run.json"), run.metadata);
  const codexArgs = [
    "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
    "--dangerously-bypass-approvals-and-sandbox", "--model", profile.model,
    "--cd", profile.execution === "docker" ? "/workspace/target" : run.target,
    "--output-schema", profile.execution === "docker" ? "/benchmark/schemas/report.schema.json" : path.join(root, "schemas", "report.schema.json"),
    "--json", "--output-last-message", profile.execution === "docker" ? "/output/report.json" : path.join(run.dir, "report.json"), "-"
  ];
  const command = profile.execution === "docker" ? "docker" : "codex";
  const args = profile.execution === "docker"
    ? ["compose", "-f", path.join(root, "docker", "compose.yml"), "run", "--rm", "-T", "agent", "codex", ...codexArgs]
    : codexArgs;
  const rawLog = path.join(run.dir, "raw-events.jsonl");
  const result = await runProcess(command, args, {
    cwd: root,
    env: dockerEnvironment(root, run),
    stdin: run.prompt,
    stdoutFile: rawLog,
    inherit: true
  });
  const ended = Date.now();
  run.metadata.completed_at = new Date(ended).toISOString();
  run.metadata.duration_ms = ended - started;
  run.metadata.usage = await usageFromJsonLines(rawLog, "harness");
  run.metadata.cost_usd = await calculateCost(resolveFrom(root, suite.pricing_catalog), profile.pricing_key, run.metadata.usage, profile.cost_mode);
  run.metadata.cost_basis = run.metadata.cost_usd === null ? "unavailable" : profile.cost_mode === "subscription" ? "subscription_allocated" : "api_equivalent";
  if (result.exitCode !== 0) {
    run.metadata.state = "incomplete";
    run.metadata.errors.push(`Codex exited with ${result.exitCode}: ${result.stderr.trim()}`);
  } else {
    try {
      await validateReport(root, path.join(run.dir, "report.json"), fixture.finding_limit);
      run.metadata.state = "complete";
      await writeFile(path.join(run.dir, "COMPLETED"), `${run.metadata.completed_at}\n`, "utf8");
    } catch (error) {
      run.metadata.state = "invalid";
      run.metadata.errors.push((error as Error).message);
    }
  }
  await writeJsonAtomic(path.join(run.dir, "run.json"), run.metadata);
  if (run.metadata.state !== "complete") throw new Error(run.metadata.errors.join("\n") || "Run did not complete");
}

export async function prepareClaudeInstructions(root: string, run: PreparedRun, profile: ModelProfile): Promise<string> {
  if (profile.execution !== "local") throw new Error("Claude subscription profiles must use local execution");
  const versionCheck = profile.harness_version
    ? `$actualClaudeVersion = (claude --version).Split(' ')[0]; if ($actualClaudeVersion -ne '${profile.harness_version}') { throw "Expected Claude Code ${profile.harness_version}, found $actualClaudeVersion" }`
    : "";
  const command = `${versionCheck}; node "${path.join(root, "dist", "src", "cli.js")}" internal mark-start "${run.dir}"; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; Push-Location "${run.target}"; try { claude --safe-mode --permission-mode auto --model "${profile.model}" --add-dir "${run.dir}" } finally { Pop-Location }`;
  const instructions = [
    "# Claude Code subscription run", "", "1. Confirm `claude` is logged in with the intended Claude subscription.", "2. Run the launch command below.", "3. Paste the complete contents of `prompt.txt` once.", "4. Do not interact until Claude creates `COMPLETED` and returns to the prompt.", "5. Exit Claude, then run `bench run validate` for this run directory.", "", "```powershell", command, "```", "", `Run directory: ${run.dir}`, ""
  ].join("\n");
  await writeTextAtomic(path.join(run.dir, "CLAUDE_RUN.md"), instructions);
  return instructions;
}

export async function markRunStarted(runDir: string): Promise<void> {
  const file = path.join(runDir, "run.json");
  const metadata = await readJson<RunMetadata>(file);
  if (metadata.state !== "prepared") throw new Error(`Cannot start run in state ${metadata.state}`);
  metadata.state = "running";
  metadata.started_at = new Date().toISOString();
  await writeJsonAtomic(file, metadata);
}

export async function validateExistingRun(root: string, runDir: string, suite: SuiteConfig): Promise<RunMetadata> {
  const metadataFile = path.join(runDir, "run.json");
  const metadata = await readJson<RunMetadata>(metadataFile);
  const fixture = suite.cases.find((candidate) => candidate.id === metadata.case_id);
  if (!fixture) throw new Error(`Case ${metadata.case_id} not found in suite`);
  await validateReport(root, path.join(runDir, "report.json"), fixture.finding_limit);
  try { await access(path.join(runDir, "COMPLETED")); } catch {
    await writeFile(path.join(runDir, "COMPLETED"), `${new Date().toISOString()}\n`, "utf8");
  }
  if (!metadata.started_at) metadata.started_at = new Date().toISOString();
  metadata.completed_at = new Date().toISOString();
  metadata.duration_ms = metadata.started_at ? Date.parse(metadata.completed_at) - Date.parse(metadata.started_at) : null;
  metadata.state = "complete";
  if (metadata.cost_mode === "subscription") {
    metadata.cost_usd = await calculateCost(resolveFrom(root, suite.pricing_catalog), metadata.pricing_key, metadata.usage, "subscription");
    metadata.cost_basis = metadata.cost_usd === null ? "unavailable" : "subscription_allocated";
  }
  await writeJsonAtomic(metadataFile, metadata);
  return metadata;
}

export async function importManualUsage(root: string, runDir: string, suite: SuiteConfig, usage: Omit<TokenUsage, "provenance">): Promise<void> {
  const file = path.join(runDir, "run.json");
  const metadata = await readJson<RunMetadata>(file);
  metadata.usage = { ...usage, provenance: "manual" };
  metadata.cost_usd = await calculateCost(resolveFrom(root, suite.pricing_catalog), metadata.pricing_key, metadata.usage, metadata.cost_mode);
  metadata.cost_basis = metadata.cost_usd === null ? "unavailable" : metadata.cost_mode === "subscription" ? "subscription_allocated" : "api_equivalent";
  await writeJsonAtomic(file, metadata);
}

export async function importUsageTranscript(root: string, runDir: string, suite: SuiteConfig, transcriptFile: string): Promise<void> {
  const destination = path.join(runDir, "raw-transcript.jsonl");
  await copyFile(transcriptFile, destination);
  const usage = await usageFromJsonLines(destination, "transcript");
  if (usage.provenance === "unavailable") throw new Error("No token usage object found in transcript");
  const file = path.join(runDir, "run.json");
  const metadata = await readJson<RunMetadata>(file);
  metadata.usage = usage;
  metadata.cost_usd = await calculateCost(resolveFrom(root, suite.pricing_catalog), metadata.pricing_key, usage, metadata.cost_mode);
  metadata.cost_basis = metadata.cost_usd === null ? "unavailable" : metadata.cost_mode === "subscription" ? "subscription_allocated" : "api_equivalent";
  await writeJsonAtomic(file, metadata);
}
