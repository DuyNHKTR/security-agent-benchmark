#!/usr/bin/env node
import path from "node:path";
import { existsSync } from "node:fs";
import { loadSuite, selectProfile, suiteCase } from "./lib/config.js";
import { prepareFixture } from "./lib/fixtures.js";
import { buildComparisonReport } from "./lib/reporting.js";
import { adjudicateReviews, buildReviewQueue, runReview } from "./lib/review.js";
import { executeCodex, importManualUsage, prepareClaudeInstructions, prepareRun, validateExistingRun } from "./lib/runs.js";
import { validateReport } from "./lib/schema.js";

function findRoot(start: string): string {
  if (process.env.BENCHMARK_ROOT && existsSync(path.join(process.env.BENCHMARK_ROOT, "schemas", "report.schema.json"))) {
    return path.resolve(process.env.BENCHMARK_ROOT);
  }
  let current = path.resolve(start);
  while (true) {
    if (existsSync(path.join(current, "package.json")) && existsSync(path.join(current, "schemas", "report.schema.json"))) return current;
    const parent = path.dirname(current);
    if (parent === current) throw new Error("Run bench from inside the benchmark repository");
    current = parent;
  }
}

function option(args: string[], name: string, fallback?: string): string {
  const index = args.indexOf(name);
  if (index >= 0 && args[index + 1]) return args[index + 1];
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing required option ${name}`);
}

function numberOption(args: string[], name: string): number {
  const value = Number(option(args, name));
  if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a non-negative number`);
  return value;
}

function usage(exitCode = 2): never {
  console.error(`Security Agent Benchmark

Commands:
  bench suite prepare <suite.yaml>
  bench run codex <case> --profile <id> [--suite <suite.yaml>]
  bench run claude prepare <case> --profile <id> [--suite <suite.yaml>]
  bench run validate <run-dir> [--suite <suite.yaml>]
  bench run usage <run-dir> --input N --output N --cache-read N --cache-write N [--suite <suite.yaml>]
  bench run usage-from-transcript <run-dir> <transcript.jsonl> [--suite <suite.yaml>]
  bench review build [--suite <suite.yaml>]
  bench review start --reviewer <id> [--suite <suite.yaml>]
  bench review adjudicate [--suite <suite.yaml>]
  bench report build [--suite <suite.yaml>]
`);
  process.exit(exitCode);
}

async function main(): Promise<void> {
  const root = findRoot(process.cwd());
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) usage(0);
  if (!args.length) usage();
  const defaultSuite = "configs/suites/example.yaml";

  if (args[0] === "internal" && args[1] === "validate-report") {
    const file = path.resolve(args[2] ?? "");
    await validateReport(root, file, numberOption(args, "--limit"));
    console.log(`Valid report: ${file}`);
    return;
  }

  if (args[0] === "internal" && args[1] === "mark-start") {
    const { markRunStarted } = await import("./lib/runs.js");
    await markRunStarted(path.resolve(args[2] ?? ""));
    return;
  }

  if (args[0] === "suite" && args[1] === "prepare") {
    const { suite } = await loadSuite(root, args[2] ?? defaultSuite);
    for (const fixture of suite.cases) {
      suiteCase(suite, fixture.id);
      const location = await prepareFixture(root, suite.id, fixture);
      console.log(`Prepared ${fixture.id}: ${location}`);
    }
    return;
  }

  const suiteFile = option(args, "--suite", defaultSuite);
  const { suite } = await loadSuite(root, suiteFile);

  if (args[0] === "run" && args[1] === "codex") {
    const fixture = suiteCase(suite, args[2] ?? "");
    const profile = await selectProfile(root, suite, option(args, "--profile"));
    if (profile.adapter !== "codex") throw new Error(`Profile ${profile.id} does not use the codex adapter`);
    const run = await prepareRun(root, suite, fixture, profile);
    console.log(`Run directory: ${run.dir}`);
    await executeCodex(root, suite, fixture, profile, run);
    console.log(`Completed: ${run.dir}`);
    return;
  }

  if (args[0] === "run" && args[1] === "claude" && args[2] === "prepare") {
    const fixture = suiteCase(suite, args[3] ?? "");
    const profile = await selectProfile(root, suite, option(args, "--profile"));
    if (profile.adapter !== "claude-code") throw new Error(`Profile ${profile.id} does not use the claude-code adapter`);
    const run = await prepareRun(root, suite, fixture, profile);
    console.log(await prepareClaudeInstructions(root, run, profile));
    return;
  }

  if (args[0] === "run" && args[1] === "validate") {
    const runDir = path.resolve(args[2] ?? "");
    const metadata = await validateExistingRun(root, runDir, suite);
    console.log(`Validated ${metadata.run_id}`);
    return;
  }

  if (args[0] === "run" && args[1] === "usage") {
    const runDir = path.resolve(args[2] ?? "");
    await importManualUsage(root, runDir, suite, {
      input_tokens: numberOption(args, "--input"), output_tokens: numberOption(args, "--output"),
      cache_read_tokens: numberOption(args, "--cache-read"), cache_write_tokens: numberOption(args, "--cache-write")
    });
    console.log(`Imported usage: ${runDir}`);
    return;
  }

  if (args[0] === "run" && args[1] === "usage-from-transcript") {
    const { importUsageTranscript } = await import("./lib/runs.js");
    await importUsageTranscript(root, path.resolve(args[2] ?? ""), suite, path.resolve(args[3] ?? ""));
    console.log(`Imported transcript usage: ${path.resolve(args[2] ?? "")}`);
    return;
  }

  if (args[0] === "review" && args[1] === "build") {
    const result = await buildReviewQueue(root, suite.id);
    console.log(`Created ${result.count} blinded finding reviews: ${result.queueFile}`);
    return;
  }

  if (args[0] === "review" && args[1] === "start") {
    await runReview(root, suite.id, option(args, "--reviewer"));
    return;
  }

  if (args[0] === "review" && args[1] === "adjudicate") {
    await adjudicateReviews(root, suite.id);
    console.log("Adjudication complete");
    return;
  }

  if (args[0] === "report" && args[1] === "build") {
    console.log(`Reports: ${await buildComparisonReport(root, suite.id)}`);
    return;
  }

  usage();
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
