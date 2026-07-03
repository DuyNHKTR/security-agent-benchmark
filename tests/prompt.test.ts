import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { renderPrompt } from "../src/lib/prompt.js";

const root = path.resolve(import.meta.dirname, "..", "..");
const fixture = { id: "simple", repository: "local", commit: "a".repeat(40), finding_limit: 5 };

test("canonical prompt is model-neutral and differs only in transport", async () => {
  const codex = await renderPrompt(root, "v1", fixture, "codex", { target: "ignored", output: "ignored", execution: "docker" });
  const claude = await renderPrompt(root, "v1", fixture, "claude-code", { target: "C:\\fixture", output: "C:\\output", execution: "local" });
  for (const prompt of [codex, claude]) {
    assert.match(prompt, /Work autonomously until the assessment is complete/);
    assert.match(prompt, /Report at most 5 findings/);
    assert.doesNotMatch(prompt, /GPT|Fable|Opus|Anthropic|OpenAI/i);
  }
  const semanticCore = (value: string) => value.slice(value.indexOf("Work autonomously"), value.indexOf("Return exactly"));
  assert.equal(semanticCore(codex), semanticCore(claude));
});
