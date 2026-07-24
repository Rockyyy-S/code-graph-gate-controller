import assert from "node:assert/strict";
import test from "node:test";
import { runBestEffort } from "../lib/best-effort.mjs";

test("单项发布失败不会阻断后续开放 PR 撤销", async () => {
  const visited = [];
  const failures = await runBestEffort([1, 2, 3], async (value) => {
    visited.push(value);
    if (value === 2) {
      throw new Error("PR 2 failed");
    }
  });

  assert.deepEqual(visited, [1, 2, 3]);
  assert.equal(failures.length, 1);
  assert.match(failures[0].message, /PR 2 failed/u);
});
