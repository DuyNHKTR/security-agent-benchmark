import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { validateReport } from "../src/lib/schema.js";
import { validReport } from "./helpers.js";

const root = path.resolve(import.meta.dirname, "..", "..");

test("validates canonical report and finding cap", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "bench-schema-"));
  const file = path.join(dir, "report.json");
  await writeFile(file, JSON.stringify(validReport()));
  const report = await validateReport(root, file, 1);
  assert.equal(report.findings[0].id, "SEC-001");
  await assert.rejects(() => validateReport(root, file, 0), /limit is 0/);
});

test("rejects malformed locations", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "bench-schema-"));
  const report = validReport();
  report.findings[0].locations[0].end_line = 2;
  const file = path.join(dir, "report.json");
  await writeFile(file, JSON.stringify(report));
  await assert.rejects(() => validateReport(root, file, 1), /end_line precedes/);
});
