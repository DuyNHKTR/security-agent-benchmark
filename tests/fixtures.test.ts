import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { prepareFixture, createWorkspace } from "../src/lib/fixtures.js";
import { requireSuccess } from "../src/lib/process.js";

test("pins a local fixture and creates an independent workspace", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "bench-git-"));
  const source = path.join(root, "source");
  await requireSuccess("git", ["init", source]);
  await requireSuccess("git", ["config", "user.email", "test@example.invalid"], source);
  await requireSuccess("git", ["config", "user.name", "Benchmark Test"], source);
  await writeFile(path.join(source, "app.js"), "console.log('fixture');\n");
  await requireSuccess("git", ["add", "app.js"], source);
  await requireSuccess("git", ["commit", "-m", "fixture"], source);
  const commit = await requireSuccess("git", ["rev-parse", "HEAD"], source);
  const cache = await prepareFixture(root, "suite", { id: "simple", repository: source, commit, finding_limit: 1 });
  const target = path.join(root, "run", "target");
  await createWorkspace(cache, target, commit);
  assert.equal(await requireSuccess("git", ["rev-parse", "HEAD"], target), commit);
});
