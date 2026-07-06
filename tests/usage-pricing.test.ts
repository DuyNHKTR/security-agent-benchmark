import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { calculateCost } from "../src/lib/pricing.js";
import { usageFromJsonLines } from "../src/lib/usage.js";

test("normalizes final usage event and computes API-equivalent cost", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "bench-usage-"));
  const events = path.join(dir, "events.jsonl");
  await writeFile(events, `${JSON.stringify({ usage: { input_tokens: 10, output_tokens: 5 } })}\n${JSON.stringify({ result: { usage: { input_tokens: 1_000_000, output_tokens: 500_000, cache_read_tokens: 100_000, cache_write_tokens: 0 } } })}\n`);
  const usage = await usageFromJsonLines(events, "harness");
  assert.equal(usage.input_tokens, 1_000_000);
  const catalog = path.join(dir, "pricing.yaml");
  await writeFile(catalog, "version: test\ncurrency: USD\nrates:\n  model:\n    input_per_million: 2\n    output_per_million: 8\n    cache_read_per_million: 1\n");
  // codex (OpenAI-style): input_tokens includes the 100k cache hits, so they are billed once at
  // the cache-read rate → (1M-100k)*2 + 500k*8 + 100k*1 = 5.9
  assert.equal(await calculateCost(catalog, "model", usage, "token", "codex"), 5.9);
  // claude-code (Anthropic-style): input_tokens already excludes cache, so no subtraction →
  // 1M*2 + 500k*8 + 100k*1 = 6.1
  assert.equal(await calculateCost(catalog, "model", usage, "token", "claude-code"), 6.1);
  assert.equal(await calculateCost(catalog, "missing", usage, "token", "codex"), null);
});

test("allocates subscription cost per completed scan", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "bench-subscription-"));
  const catalog = path.join(dir, "pricing.yaml");
  await writeFile(catalog, "version: test\ncurrency: USD\nrates: {}\nsubscriptions:\n  claude:\n    monthly_usd: 200\n    scans_per_month: 40\n");
  const usage = { input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0, provenance: "unavailable" as const };
  assert.equal(await calculateCost(catalog, "claude", usage, "subscription", "claude-code"), 5);
});
