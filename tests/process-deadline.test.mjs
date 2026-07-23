import assert from "node:assert/strict";
import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { runProcessWithDeadline } from "../lib/run-process-with-deadline.mjs";

test("正常退出后清理继承进程组的后台后代", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "process-tree-success-"));
  const marker = path.join(root, "descendant-survived.txt");
  context.after(() => rm(root, { force: true, recursive: true }));
  const descendant = `setTimeout(() => require("node:fs").writeFileSync(${JSON.stringify(marker)}, "survived"), 500); setInterval(() => {}, 1_000);`;
  const parent = `const child = require("node:child_process").spawn(process.execPath, ["-e", ${JSON.stringify(descendant)}], { stdio: "ignore" }); child.unref();`;

  const result = await runProcessWithDeadline({
    args: ["-e", parent],
    cwd: root,
    executable: process.execPath,
    killGraceMs: 50,
    outputLimitBytes: 1024,
    timeoutMs: 2_000,
  });
  await new Promise((resolve) => setTimeout(resolve, 600));

  assert.equal(result.status, "pass");
  await assert.rejects(() => access(marker));
});

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

test("绝对 deadline 同时终止继承进程组的后代进程", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "process-tree-deadline-"));
  const marker = path.join(root, "descendant-survived.txt");
  context.after(() => rm(root, { force: true, recursive: true }));
  const descendant = `setTimeout(() => require("node:fs").writeFileSync(${JSON.stringify(marker)}, "survived"), 500); setInterval(() => {}, 1_000);`;
  const parent = `require("node:child_process").spawn(process.execPath, ["-e", ${JSON.stringify(descendant)}], { stdio: "ignore" }); setInterval(() => {}, 1_000);`;

  const result = await runProcessWithDeadline({
    args: ["-e", parent],
    cwd: root,
    executable: process.execPath,
    killGraceMs: 50,
    outputLimitBytes: 1024,
    timeoutMs: 50,
  });
  await new Promise((resolve) => setTimeout(resolve, 600));

  assert.equal(result.status, "invalid");
  await assert.rejects(() => access(marker));
});
