import assert from "node:assert/strict";
import test from "node:test";
import { runProcessWithDeadline } from "../lib/run-process-with-deadline.mjs";

test("绝对 deadline 终止挂起进程并返回稳定 ETIMEDOUT", async () => {
  const result = await runProcessWithDeadline({
    args: ["-e", "setInterval(() => {}, 1_000)"],
    cwd: process.cwd(),
    executable: process.execPath,
    killGraceMs: 50,
    outputLimitBytes: 1024,
    timeoutMs: 50,
  });

  assert.equal(result.status, "invalid");
  assert.deepEqual(result.termination, {
    kind: "spawn-error",
    stableCode: "ETIMEDOUT",
  });
});
