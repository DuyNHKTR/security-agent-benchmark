import { readFile } from "node:fs/promises";
import { parse } from "yaml";
import type { TokenUsage } from "../types.js";

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
  mode: "token" | "subscription"
): Promise<number | null> {
  const catalog = parse(await readFile(catalogFile, "utf8")) as Catalog;
  if (mode === "subscription") {
    const subscription = catalog.subscriptions?.[pricingKey];
    if (!subscription || subscription.monthly_usd < 0 || subscription.scans_per_month <= 0) return null;
    return subscription.monthly_usd / subscription.scans_per_month;
  }
  const rate = catalog.rates?.[pricingKey];
  if (!rate || usage.provenance === "unavailable") return null;
  const total = usage.input_tokens * rate.input_per_million
    + usage.output_tokens * rate.output_per_million
    + usage.cache_read_tokens * (rate.cache_read_per_million ?? rate.input_per_million)
    + usage.cache_write_tokens * (rate.cache_write_per_million ?? rate.input_per_million);
  return total / 1_000_000;
}
