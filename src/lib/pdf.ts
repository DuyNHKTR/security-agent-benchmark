import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { runProcess } from "./process.js";

/**
 * PDF export rides on a locally installed Chromium-based browser instead of a
 * bundled one (no Puppeteer dependency): headless Chrome/Edge prints the same
 * HTML the report already emits. PDFs are best-effort — a missing browser must
 * never fail scoring.
 */

function defaultCandidates(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): string[] {
  const candidates: string[] = [];
  if (env.BENCH_BROWSER) candidates.push(env.BENCH_BROWSER);
  if (platform === "win32") {
    const roots = [env["ProgramFiles"], env["ProgramFiles(x86)"], env["LOCALAPPDATA"]].filter(Boolean) as string[];
    for (const root of roots) {
      candidates.push(path.join(root, "Google", "Chrome", "Application", "chrome.exe"));
      candidates.push(path.join(root, "Microsoft", "Edge", "Application", "msedge.exe"));
    }
  } else if (platform === "darwin") {
    candidates.push("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    candidates.push("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge");
    candidates.push("/Applications/Chromium.app/Contents/MacOS/Chromium");
  } else {
    candidates.push("/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/microsoft-edge");
  }
  return candidates;
}

/**
 * First existing browser executable: BENCH_BROWSER wins, then the standard
 * Chrome/Edge/Chromium install paths for the platform. Null when none exist.
 */
export function findBrowser(options: {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  exists?: (candidate: string) => boolean;
} = {}): string | null {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const exists = options.exists ?? existsSync;
  return defaultCandidates(env, platform).find((candidate) => exists(candidate)) ?? null;
}

// Printing a local static page takes seconds; a hung browser (profile lock,
// broken install, BENCH_BROWSER pointing at a non-browser) must not block
// scoring forever — best-effort means the caller gets an error, not a hang.
const PRINT_TIMEOUT_MS = 60_000;

/** Print an HTML file to PDF via headless Chromium. Throws on a non-zero exit or timeout. */
export async function printToPdf(browser: string, htmlPath: string, pdfPath: string): Promise<void> {
  const result = await runProcess(browser, [
    "--headless=new",
    "--disable-gpu",
    "--no-pdf-header-footer",
    // A separate profile dir keeps the print independent of the user's browser session.
    `--user-data-dir=${path.join(os.tmpdir(), "bench-pdf-profile")}`,
    `--print-to-pdf=${pdfPath}`,
    pathToFileURL(htmlPath).href
  ], { timeoutMs: PRINT_TIMEOUT_MS });
  if (result.exitCode !== 0 || !existsSync(pdfPath)) {
    throw new Error(`PDF print failed (exit ${result.exitCode}): ${result.stderr.trim().split("\n").pop() ?? "unknown error"}`);
  }
}
