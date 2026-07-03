import { readFile } from "node:fs/promises";
import type { TokenUsage } from "../types.js";

const aliases: Record<keyof Omit<TokenUsage, "provenance">, string[]> = {
  input_tokens: ["input_tokens", "inputTokens", "prompt_tokens"],
  output_tokens: ["output_tokens", "outputTokens", "completion_tokens"],
  cache_read_tokens: ["cache_read_tokens", "cacheReadTokens", "cached_input_tokens"],
  cache_write_tokens: ["cache_write_tokens", "cacheWriteTokens", "cache_creation_input_tokens"]
};

function findUsage(value: unknown, found: Record<string, number>[]): void {
  if (!value || typeof value !== "object") return;
  const object = value as Record<string, unknown>;
  const candidate: Record<string, number> = {};
  for (const [canonical, names] of Object.entries(aliases)) {
    const matched = names.find((name) => typeof object[name] === "number");
    if (matched) candidate[canonical] = object[matched] as number;
  }
  if (Object.keys(candidate).length >= 2) found.push(candidate);
  for (const nested of Object.values(object)) findUsage(nested, found);
}

export async function usageFromJsonLines(file: string, provenance: TokenUsage["provenance"]): Promise<TokenUsage> {
  const text = await readFile(file, "utf8");
  const candidates: Record<string, number>[] = [];
  for (const line of text.split(/\r?\n/).filter(Boolean)) {
    try { findUsage(JSON.parse(line), candidates); } catch { /* Raw harness logs may contain non-JSON status lines. */ }
  }
  const last = candidates.at(-1) ?? {};
  return {
    input_tokens: last.input_tokens ?? 0,
    output_tokens: last.output_tokens ?? 0,
    cache_read_tokens: last.cache_read_tokens ?? 0,
    cache_write_tokens: last.cache_write_tokens ?? 0,
    provenance: candidates.length ? provenance : "unavailable"
  };
}
