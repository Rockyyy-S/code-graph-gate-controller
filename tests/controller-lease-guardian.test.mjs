import assert from "node:assert/strict";
import test from "node:test";
import { runControllerLeaseGuardian } from "../bin/run-controller-lease-guardian.mjs";
import { ControllerRevisionDriftError } from "../bin/run-controller.mjs";

test("lease guardian 在单次 cycle 失败后继续执行后续撤销轮次", async () => {
  let cycles = 0;
  let now = 0;
  const originalNow = Date.now;
  Date.now = () => now;
  try {
    await runControllerLeaseGuardian({
      delay: async (milliseconds) => {
        now += milliseconds;
      },
      pollIntervalMs: 10,
      runCycle: async () => {
        cycles += 1;
        if (cycles === 1) {
          throw new Error("monitor invalid");
        }
      },
      runtimeMs: 25,
    });
  } finally {
    Date.now = originalNow;
  }

  assert.equal(cycles, 3);
});

test("lease guardian 连续失败时向 workflow 传播最后一个撤销错误", async () => {
  let now = 0;
  const originalNow = Date.now;
  Date.now = () => now;
  try {
    await assert.rejects(
      runControllerLeaseGuardian({
        delay: async (milliseconds) => {
          now += milliseconds;
        },
        pollIntervalMs: 10,
        runCycle: async () => {
          throw new Error("cannot revoke");
        },
        runtimeMs: 25,
      }),
      /cannot revoke/u,
    );
  } finally {
    Date.now = originalNow;
  }
});

test("默认分支可信 revision 漂移后旧 guardian 立即让位", async () => {
  let cycles = 0;
  let delayed = false;
  const drift = new Error("monitor invalid", { cause: new ControllerRevisionDriftError() });

  await assert.rejects(
    runControllerLeaseGuardian({
      delay: async () => {
        delayed = true;
      },
      pollIntervalMs: 10,
      runCycle: async () => {
        cycles += 1;
        throw drift;
      },
      runtimeMs: 25,
    }),
    (error) => error?.cause instanceof ControllerRevisionDriftError,
  );

  assert.equal(cycles, 1);
  assert.equal(delayed, false);
});

test("lease guardian 使用 abort signal 约束正在执行的单轮 cycle", async () => {
  const startedAt = Date.now();
  await assert.rejects(
    runControllerLeaseGuardian({
      cycleTimeoutMs: 20,
      pollIntervalMs: 10,
      runCycle: async ({ signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason), { once: true });
      }),
      runtimeMs: 30,
    }),
    /deadline|abort|timeout/iu,
  );
  assert.ok(Date.now() - startedAt < 250);
});

test("cycle timeout 后等待同一轮独立撤销完成再返回", async () => {
  let revocationComplete = false;
  const startedAt = Date.now();

  await assert.rejects(
    runControllerLeaseGuardian({
      cycleTimeoutMs: 10,
      pollIntervalMs: 10,
      revocationWaitMs: 100,
      runCycle: async ({ signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => {
          setTimeout(() => {
            revocationComplete = true;
            reject(signal.reason);
          }, 20);
        }, { once: true });
      }),
      runtimeMs: 20,
    }),
    /deadline|abort|timeout/iu,
  );

  assert.equal(revocationComplete, true);
  assert.ok(Date.now() - startedAt >= 25);
});

test("cycle 忽略 abort 并正常结束时仍传播原 deadline 错误", async () => {
  let cleanupComplete = false;

  await assert.rejects(
    runControllerLeaseGuardian({
      cycleTimeoutMs: 10,
      pollIntervalMs: 10,
      revocationWaitMs: 100,
      runCycle: async ({ signal }) => new Promise((resolve) => {
        signal.addEventListener("abort", () => {
          setTimeout(() => {
            cleanupComplete = true;
            resolve("cleanup-finished");
          }, 20);
        }, { once: true });
      }),
      runtimeMs: 20,
    }),
    /deadline/u,
  );

  assert.equal(cleanupComplete, true);
});

test("紧急撤销未结算时 guardian 立即终止且不启动重叠 cycle", async () => {
  let cycles = 0;
  const startedAt = Date.now();

  await assert.rejects(
    runControllerLeaseGuardian({
      cycleTimeoutMs: 10,
      pollIntervalMs: 10,
      revocationWaitMs: 10,
      runCycle: async () => {
        cycles += 1;
        return new Promise(() => {});
      },
      runtimeMs: 100,
    }),
    /未结算|紧急撤销/u,
  );

  assert.equal(cycles, 1);
  assert.ok(Date.now() - startedAt < 100);
});
