/** Small-sample statistics for the detection report. No dependencies. */

export interface Interval {
  lower: number;
  upper: number;
}

/**
 * Wilson score interval for a binomial proportion. Preferred over the normal
 * approximation because detection suites are small (n often < 30) and recall
 * sits near 0 or 1, where the naive interval collapses or exits [0, 1].
 */
export function wilsonInterval(successes: number, trials: number, z = 1.96): Interval | null {
  if (trials <= 0) return null;
  const p = successes / trials;
  const z2 = z * z;
  const denominator = 1 + z2 / trials;
  const center = (p + z2 / (2 * trials)) / denominator;
  const margin = (z / denominator) * Math.sqrt((p * (1 - p)) / trials + z2 / (4 * trials * trials));
  return { lower: Math.max(0, center - margin), upper: Math.min(1, center + margin) };
}

/**
 * Exact McNemar test (two-sided binomial) on paired detection outcomes.
 * b = cases only model A detected, c = cases only model B detected.
 * Returns null when there are no discordant pairs (the test is undefined).
 */
export function mcnemarExact(b: number, c: number): number | null {
  const n = b + c;
  if (n === 0) return null;
  const k = Math.min(b, c);
  // Two-sided exact binomial with p = 0.5: 2 * P(X <= k), capped at 1.
  let tail = 0;
  for (let i = 0; i <= k; i++) tail += binomialPmfHalf(i, n);
  return Math.min(1, 2 * tail);
}

/** P(X = k) for X ~ Binomial(n, 0.5), computed in log space to avoid overflow. */
function binomialPmfHalf(k: number, n: number): number {
  return Math.exp(logChoose(n, k) - n * Math.LN2);
}

function logChoose(n: number, k: number): number {
  return logFactorial(n) - logFactorial(k) - logFactorial(n - k);
}

const logFactorialCache: number[] = [0, 0];

function logFactorial(n: number): number {
  for (let i = logFactorialCache.length; i <= n; i++) {
    logFactorialCache[i] = logFactorialCache[i - 1] + Math.log(i);
  }
  return logFactorialCache[n];
}
