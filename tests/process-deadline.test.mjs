import assert from "node:assert/strict";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { runProcessWithDeadline } from "../lib/run-process-with-deadline.mjs";

const requestedStressRounds = Number.parseInt(
  process.env.CODEGRAPH_PROCESS_DEADLINE_STRESS_ROUNDS ?? "1",
  10,
);
/** 压力轮数固定限制为 1–20，避免环境值把 blocking 测试扩成无界负载。 */
const stressRounds = Number.isSafeInteger(requestedStressRounds) &&
  requestedStressRounds >= 1 && requestedStressRounds <= 20
  ? requestedStressRounds
  : 1;
/** Windows helper 与目标进程树共享同一个有界终止证明预算。 */
const cleanupGraceMs = process.platform === "win32" ? 10_000 : 2_000;

/** 等待终态证明所指向的 PID 确认消失。 */
async function assertProcessGone(pid, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
    } catch {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`PID ${pid} 在终态证明后仍存活。`);
}

/** 构造先保持存活、后尝试写 marker 的后代脚本。 */
function createReadyDescendant(marker, delayMs = 750) {
  return [
    `setTimeout(() => require("node:fs").writeFileSync(${JSON.stringify(marker)}, "survived"), ${delayMs});`,
    "setInterval(() => {}, 1_000);",
  ].join("");
}

/** 执行一个真实 descendant-ready/PID 正向握手的 Windows 进程树场景。 */
async function runReadyScenario(kind, round) {
  const root = await mkdtemp(path.join(tmpdir(), `controller-${kind}-${round}-`));
  const marker = path.join(root, "descendant-survived.txt");
  const readyPath = path.join(root, "descendant.pid");
  const descendant = createReadyDescendant(marker, kind === "timeout" ? 5_000 : 750);
  const directParent = [
    "const { spawn } = require(\"node:child_process\");",
    "const { writeFileSync } = require(\"node:fs\");",
    `const child = spawn(process.execPath, ["-e", ${JSON.stringify(descendant)}], { stdio: "ignore" });`,
    `writeFileSync(${JSON.stringify(readyPath)}, String(child.pid));`,
    "child.unref();",
    ...(kind === "timeout" ? ["setInterval(() => {}, 1_000);"] : []),
  ].join("");
  const intermediate = [
    "const { spawn } = require(\"node:child_process\");",
    "const { writeFileSync } = require(\"node:fs\");",
    `const child = spawn(process.execPath, ["-e", ${JSON.stringify(descendant)}], ` +
      "{ detached: true, stdio: \"ignore\" });",
    `writeFileSync(${JSON.stringify(readyPath)}, String(child.pid));`,
    "child.unref();",
  ].join("");
  const orphanParent = [
    "const { spawn } = require(\"node:child_process\");",
    `const child = spawn(process.execPath, ["-e", ${JSON.stringify(intermediate)}], ` +
      "{ stdio: \"ignore\" });",
    "child.once(\"exit\", () => process.exit(0));",
  ].join("");
  try {
    const result = await runProcessWithDeadline({
      args: ["-e", kind === "orphan-grandchild" ? orphanParent : directParent],
      cwd: root,
      executable: process.execPath,
      killGraceMs: cleanupGraceMs,
      outputLimitBytes: 1024,
      timeoutMs: kind === "timeout" ? 3_000 : 8_000,
      windowsDescendantReadyPath: readyPath,
    });
    const descendantPid = Number.parseInt(await readFile(readyPath, "utf8"), 10);
    assert.equal(result.status, kind === "timeout" ? "invalid" : "pass");
    assert.equal(
      result.termination.kind,
      kind === "timeout" ? "spawn-error" : "exit",
    );
    if (kind === "timeout") {
      assert.equal(result.termination.stableCode, "ETIMEDOUT");
    } else {
      assert.equal(result.termination.code, 0);
    }
    assert.equal(result.windowsJob?.activeProcesses, 0);
    assert.equal(result.windowsJob?.descendantPid, descendantPid);
    assert.equal(result.windowsJob?.terminalProof, "query-information-job-object");
    assert.ok(Number.isSafeInteger(result.windowsJob?.rootPid));
    await assertProcessGone(descendantPid);
    await new Promise((resolve) => setTimeout(resolve, kind === "timeout" ? 100 : 900));
    await assert.rejects(() => access(marker));
  } finally {
    await rm(root, { force: true, maxRetries: 5, recursive: true, retryDelay: 100 });
  }
}

test("绝对 deadline 对无后代进程返回稳定 ETIMEDOUT", async () => {
  const result = await runProcessWithDeadline({
    args: ["-e", "setInterval(() => {}, 1_000)"],
    cwd: process.cwd(),
    executable: process.execPath,
    killGraceMs: cleanupGraceMs,
    outputLimitBytes: 1024,
    timeoutMs: 50,
  });

  assert.equal(result.status, "invalid");
  assert.deepEqual(result.termination, {
    kind: "spawn-error",
    stableCode: "ETIMEDOUT",
  });
  if (process.platform === "win32") {
    assert.equal(result.windowsJob?.activeProcesses, 0);
  }
});

test(
  "ready-handshaked timeout、正常根退出后台后代与 orphan grandchild 逐轮并行收敛",
  { timeout: stressRounds * 30_000 },
  async () => {
    if (process.platform !== "win32") {
      assert.notEqual(process.platform, "win32");
      return;
    }
    for (let round = 1; round <= stressRounds; round += 1) {
      await Promise.all([
        runReadyScenario("timeout", round),
        runReadyScenario("normal-exit-background", round),
        runReadyScenario("orphan-grandchild", round),
      ]);
    }
  },
);

test("Windows Job bootstrap 缺失 ready proof 时 fail closed", async () => {
  if (process.platform !== "win32") {
    assert.notEqual(process.platform, "win32");
    return;
  }
  const result = await runProcessWithDeadline({
    args: [],
    cwd: process.cwd(),
    executable: path.join(tmpdir(), "missing-codegraph-bootstrap.exe"),
    killGraceMs: cleanupGraceMs,
    outputLimitBytes: 1024,
    timeoutMs: 1_000,
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.termination.stableCode, "EPROCESSBOOTSTRAP");
});

test("Windows Job 缺失 descendant attestation 时不发布伪终态", async () => {
  if (process.platform !== "win32") {
    assert.notEqual(process.platform, "win32");
    return;
  }
  const root = await mkdtemp(path.join(tmpdir(), "controller-cleanup-fail-"));
  try {
    const result = await runProcessWithDeadline({
      args: ["-e", "process.exit(0)"],
      cwd: root,
      executable: process.execPath,
      killGraceMs: cleanupGraceMs,
      outputLimitBytes: 1024,
      timeoutMs: 1_000,
      windowsDescendantReadyPath: path.join(root, "missing-descendant.pid"),
    });

    assert.equal(result.status, "invalid");
    assert.equal(result.termination.stableCode, "EPROCESSCLEANUP");
    assert.equal(result.windowsJob, undefined);
  } finally {
    await rm(root, { force: true, maxRetries: 5, recursive: true, retryDelay: 100 });
  }
});
