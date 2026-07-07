import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { runProcess } from "../src/lib/process.js";

test("waits for redirected stdout to finish writing", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "bench-process-"));
  const output = path.join(dir, "stdout.log");
  const expected = "x".repeat(4 * 1024 * 1024);
  const result = await runProcess(
    process.execPath,
    ["-e", `process.stdout.write("x".repeat(${expected.length}))`],
    { stdoutFile: output }
  );

  assert.equal(result.exitCode, 0);
  assert.equal((await readFile(output, "utf8")).length, expected.length);
});

test("kills a child that outlives timeoutMs and rejects", async () => {
  const started = Date.now();
  await assert.rejects(
    runProcess(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { timeoutMs: 500 }),
    /timed out after 500ms/
  );
  assert.ok(Date.now() - started < 10_000, "rejects promptly instead of waiting for the child's own exit");
});
