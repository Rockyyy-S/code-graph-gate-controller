import assert from "node:assert/strict";
import test from "node:test";
import {
  dispatchSuccessorController,
  runControllerLeaseGuardian,
} from "../bin/run-controller-lease-guardian.mjs";
import { ControllerRevisionDriftError } from "../bin/run-controller.mjs";

/** 以虚拟时钟覆盖正常 lease 与多轮 cycle，避免真实等待。 */
async function withFakeLease(run) {
  let now = 0;
  const originalNow = Date.now;
  Date.now = () => now;
  try {
    return await run({
      advance: async (milliseconds) => {
        now += milliseconds;
      },
    });
  } finally {
    Date.now = originalNow;
  }
}

/** 创建可安全启动三轮 cycle 后单次 handoff 的短 lease 参数。 */
function createNormalLeaseOptions(advance, overrides = {}) {
  return {
    cycleTimeoutMs: 2,
    delay: advance,
    handoffLeadMs: 2,
    pollIntervalMs: 10,
    revocationWaitMs: 2,
    runtimeMs: 35,
    ...overrides,
  };
}

test("正常 lease 结束前只 dispatch 一次 successor，且不伪报 cycle deadline", async () => {
  await withFakeLease(async ({ advance }) => {
    let cycles = 0;
    let dispatches = 0;

    await runControllerLeaseGuardian(createNormalLeaseOptions(advance, {
      dispatchSuccessor: async () => {
        dispatches += 1;
      },
      runCycle: async () => {
        cycles += 1;
      },
    }));

    assert.equal(cycles, 3);
    assert.equal(dispatches, 1);
  });
});

test("单次 cycle 失败后恢复成功，lease handoff 不保留过期错误", async () => {
  await withFakeLease(async ({ advance }) => {
    let cycles = 0;
    let dispatches = 0;

    await runControllerLeaseGuardian(createNormalLeaseOptions(advance, {
      dispatchSuccessor: async () => {
        dispatches += 1;
      },
      runCycle: async () => {
        cycles += 1;
        if (cycles === 1) {
          throw new Error("monitor invalid");
        }
      },
    }));

    assert.equal(cycles, 3);
    assert.equal(dispatches, 1);
  });
});

test("连续失败仍只 handoff 一次，并向 workflow 传播最后错误", async () => {
  await withFakeLease(async ({ advance }) => {
    let cycles = 0;
    let dispatches = 0;

    await assert.rejects(
      runControllerLeaseGuardian(createNormalLeaseOptions(advance, {
        dispatchSuccessor: async () => {
          dispatches += 1;
        },
        runCycle: async () => {
          cycles += 1;
          throw new Error(`cannot revoke ${cycles}`);
        },
      })),
      /cannot revoke 3/u,
    );

    assert.equal(cycles, 3);
    assert.equal(dispatches, 1);
  });
});

test("handoff 失败可观察，并与最后一个 cycle 错误聚合", async () => {
  await withFakeLease(async ({ advance }) => {
    await assert.rejects(
      runControllerLeaseGuardian(createNormalLeaseOptions(advance, {
        dispatchSuccessor: async () => {
          throw new Error("dispatch unavailable");
        },
        runCycle: async () => {
          throw new Error("cycle invalid");
        },
      })),
      (error) => {
        assert.ok(error instanceof AggregateError);
        assert.equal(error.errors.length, 2);
        assert.match(error.errors[0].message, /cycle invalid/u);
        assert.match(error.errors[1].message, /dispatch unavailable/u);
        return true;
      },
    );
  });
});

test("无 cycle 错误时 handoff 失败仍以单元素 AggregateError fail closed", async () => {
  await withFakeLease(async ({ advance }) => {
    await assert.rejects(
      runControllerLeaseGuardian(createNormalLeaseOptions(advance, {
        dispatchSuccessor: async () => {
          throw new Error("dispatch unavailable");
        },
        runCycle: async () => undefined,
      })),
      (error) => {
        assert.ok(error instanceof AggregateError);
        assert.equal(error.errors.length, 1);
        assert.match(error.errors[0].message, /dispatch unavailable/u);
        return true;
      },
    );
  });
});

test("默认分支可信 revision 漂移后旧 guardian 立即让位且不 handoff", async () => {
  let cycles = 0;
  let delayed = false;
  let dispatches = 0;
  const drift = new Error("monitor invalid", { cause: new ControllerRevisionDriftError() });

  await assert.rejects(
    runControllerLeaseGuardian({
      cycleTimeoutMs: 2,
      delay: async () => {
        delayed = true;
      },
      dispatchSuccessor: async () => {
        dispatches += 1;
      },
      handoffLeadMs: 2,
      pollIntervalMs: 10,
      revocationWaitMs: 2,
      runCycle: async () => {
        cycles += 1;
        throw drift;
      },
      runtimeMs: 35,
    }),
    (error) => error?.cause instanceof ControllerRevisionDriftError,
  );

  assert.equal(cycles, 1);
  assert.equal(delayed, false);
  assert.equal(dispatches, 0);
});

test("真实 cycle timeout 后 abort 并等待独立撤销完成，再 fail closed", async () => {
  let revocationComplete = false;
  let dispatches = 0;
  const startedAt = Date.now();

  await assert.rejects(
    runControllerLeaseGuardian({
      cycleTimeoutMs: 10,
      dispatchSuccessor: async () => {
        dispatches += 1;
      },
      handoffLeadMs: 1,
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
      runtimeMs: 200,
    }),
    /cycle deadline/u,
  );

  assert.equal(revocationComplete, true);
  assert.equal(dispatches, 0);
  assert.ok(Date.now() - startedAt >= 25);
});

test("cycle 忽略 abort 并正常结束时仍传播原 deadline 错误", async () => {
  let cleanupComplete = false;

  await assert.rejects(
    runControllerLeaseGuardian({
      cycleTimeoutMs: 10,
      dispatchSuccessor: async () => assert.fail("真实 timeout 不得走正常 handoff"),
      handoffLeadMs: 1,
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
      runtimeMs: 200,
    }),
    /cycle deadline/u,
  );

  assert.equal(cleanupComplete, true);
});

test("紧急撤销未结算时立即终止且不启动重叠 cycle 或 successor", async () => {
  let cycles = 0;
  let dispatches = 0;
  const startedAt = Date.now();

  await assert.rejects(
    runControllerLeaseGuardian({
      cycleTimeoutMs: 10,
      dispatchSuccessor: async () => {
        dispatches += 1;
      },
      handoffLeadMs: 1,
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
  assert.equal(dispatches, 0);
  assert.ok(Date.now() - startedAt < 100);
});

test("successor dispatch 固定使用同仓 controller workflow、main 与 actions token", async () => {
  const calls = [];
  await dispatchSuccessorController({
    request: async (...args) => {
      calls.push(args);
      return null;
    },
    token: "repository-token",
  });

  assert.deepEqual(calls, [[
    "repos/Rockyyy-S/code-graph-gate-controller/actions/workflows/controller.yml/dispatches",
    {
      body: { ref: "main" },
      method: "POST",
      timeoutMs: 5_000,
      token: "repository-token",
    },
  ]]);
});
