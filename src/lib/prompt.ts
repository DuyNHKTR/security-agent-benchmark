import { readFile } from "node:fs/promises";
import path from "node:path";
import type { AdapterName, SuiteCase } from "../types.js";

export async function renderPrompt(
  root: string,
  promptVersion: string,
  fixture: SuiteCase,
  adapter: AdapterName,
  paths: { target: string; output: string; execution: "docker" | "local" }
): Promise<string> {
  const template = await readFile(path.join(root, "prompts", `security-scan-${promptVersion}.txt`), "utf8");
  const container = paths.execution === "docker";
  const targetRoot = container ? "/workspace/target" : paths.target;
  const schemaPath = container ? "/benchmark/schemas/report.schema.json" : path.join(root, "schemas", "report.schema.json");
  const reportPath = container ? "/output/report.json" : path.join(paths.output, "report.json");
  const temporaryPath = container ? "/output/report.tmp" : path.join(paths.output, "report.tmp");
  const completedPath = container ? "/output/COMPLETED" : path.join(paths.output, "COMPLETED");
  const validator = container ? "/benchmark/dist/src/cli.js" : path.join(root, "dist", "src", "cli.js");
  const delivery = adapter === "claude-code"
    ? `Write the final JSON atomically to ${reportPath} (write ${temporaryPath} first, then rename it). After writing, run \`node "${validator}" internal validate-report "${reportPath}" --limit {{FINDING_LIMIT}}\`, fix any reported errors, and create ${completedPath} only after validation succeeds.`
    : "The harness captures your final JSON response. Ensure the final response contains only the schema-conforming JSON object.";
  return template
    .replaceAll("{{TARGET_ROOT}}", targetRoot)
    .replaceAll("{{SCHEMA_PATH}}", schemaPath)
    .replaceAll("{{FINDING_LIMIT}}", String(fixture.finding_limit))
    .replaceAll("{{DELIVERY_INSTRUCTION}}", delivery.replaceAll("{{FINDING_LIMIT}}", String(fixture.finding_limit)));
}
