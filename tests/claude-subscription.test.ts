import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { prepareClaudeInstructions, type PreparedRun } from "../src/lib/runs.js";
import type { ModelProfile } from "../src/types.js";

test("Claude launch uses local subscription session without API or print mode", async () => {
  const root = path.resolve(import.meta.dirname, "..", "..");
  const dir = await mkdtemp(path.join(os.tmpdir(), "bench-claude-"));
  const run = {
    dir,
    target: path.join(dir, "target"),
    prompt: "prompt",
    metadata: {}
  } as PreparedRun;
  const profile: ModelProfile = {
    id: "claude-subscription",
    adapter: "claude-code",
    model: "claude-fable-5",
    pricing_key: "claude-subscription",
    cost_mode: "subscription",
    execution: "local",
    harness_version: "2.1.198"
  };
  const instructions = await prepareClaudeInstructions(root, run, profile);
  assert.match(instructions, /Claude Code subscription run/);
  assert.match(instructions, /--permission-mode auto/);
  assert.match(instructions, /--safe-mode/);
  assert.doesNotMatch(instructions, /docker|ANTHROPIC_API_KEY|(?:^|\s)-p(?:\s|$)|--print/i);
});
