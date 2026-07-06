import { readFile } from "node:fs/promises";
import { parse } from "yaml";
import type { AdapterName, TokenUsage } from "../types.js";

interface Rate {
  input_per_million: number;
  output_per_million: number;
  cache_read_per_million?: number;
  cache_write_per_million?: number;
}

interface Catalog {
  version: string;
  currency: "USD";
  rates: Record<string, Rate>;
  subscriptions?: Record<string, { monthly_usd: number; scans_per_month: number }>;
}

export async function calculateCost(
  catalogFile: string,
  pricingKey: string,
  usage: TokenUsage,
  mode: "token" | "subscription",
  adapter: AdapterName
): Promise<number | null> {
  const catalog = parse(await readFile(catalogFile, "utf8")) as Catalog;
  if (mode === "subscription") {
    const subscription = catalog.subscriptions?.[pricingKey];
    if (!subscription || subscription.monthly_usd < 0 || subscription.scans_per_month <= 0) return null;
    return subscription.monthly_usd / subscription.scans_per_month;
  }
  const rate = catalog.rates?.[pricingKey];
  if (!rate || usage.provenance === "unavailable") return null;
  // Per-category billing, following ccusage / litellm: cache-hit tokens are charged at the
  // cache-read rate, not the full input rate. Whether input_tokens already excludes cache hits
  // is provider-specific: OpenAI-style usage (codex) reports them INSIDE input_tokens, so
  // subtract to avoid double-counting (litellm #19681 / #6215); Anthropic-style (claude-code)
  // already excludes them, so it must not subtract (ccusage).
  const uncachedInputTokens = adapter === "codex"
    ? Math.max(0, usage.input_tokens - usage.cache_read_tokens)
    : usage.input_tokens;
  const total = uncachedInputTokens * rate.input_per_million
    + usage.output_tokens * rate.output_per_million
    + usage.cache_read_tokens * (rate.cache_read_per_million ?? rate.input_per_million)
    + usage.cache_write_tokens * (rate.cache_write_per_million ?? rate.input_per_million);
  return total / 1_000_000;
}
