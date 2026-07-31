import assert from "node:assert/strict";
import test from "node:test";
import {
  classifyCheckReplay,
  planCheckLifecycle,
  planCheckReplay,
} from "../lib/check-replay-policy.mjs";

const casKey = "1303415307:head:context:implementation:3";
const lifecycleKey = "check-lifecycle-v1:1303415307:9:head:architecture-required";

/** 创建 Controller App 历史 check fixture。 */
function createCheck({
  conclusion = "success",
  id = 1,
  replayConflict = false,
  replayDigest = "a".repeat(64),
  status = "completed",
} = {}) {
  return {
    conclusion,
    id,
    output: {
      summary: JSON.stringify({
        ...(replayConflict ? { casKey, replayConflict: true } : {}),
        replayDigest,
        ...(replayConflict ? {} : { result: { casKey } }),
      }),
    },
    status,
  };
}

test("相同 CAS 与 replay digest 仅幂等重放一次", () => {
  assert.equal(
    classifyCheckReplay({
      casKey,
      checks: [createCheck()],
      conclusion: "success",
      replayDigest: "a".repeat(64),
      status: "completed",
    }),
    "idempotent",
  );
});

test("同一 CAS 的不同 replay digest 必须判为冲突", () => {
  assert.equal(
    classifyCheckReplay({
      casKey,
      checks: [createCheck()],
      conclusion: "success",
      replayDigest: "b".repeat(64),
      status: "completed",
    }),
    "conflict",
  );
});

test("已发布的相同冲突 failure 不重复创建 check", () => {
  assert.equal(
    classifyCheckReplay({
      casKey,
      checks: [
        createCheck(),
        createCheck({
          conclusion: "failure",
          id: 2,
          replayConflict: true,
          replayDigest: "b".repeat(64),
        }),
      ],
      conclusion: "success",
      replayDigest: "b".repeat(64),
      status: "completed",
    }),
    "idempotent-conflict",
  );
});

test("较新的 drift failure 会让历史相同 evidence success 重新发布", () => {
  assert.equal(
    classifyCheckReplay({
      casKey,
      checks: [
        createCheck({ id: 1 }),
        {
          conclusion: "failure",
          id: 2,
          output: {
            summary: JSON.stringify({ status: "drift-monitor-invalid" }),
          },
          status: "completed",
        },
      ],
      conclusion: "success",
      replayDigest: "a".repeat(64),
      status: "completed",
    }),
    "publish",
  );
});

test("无 CAS 的 pending 状态不参与 evidence 幂等判断", () => {
  assert.equal(
    classifyCheckReplay({
      casKey: null,
      checks: [createCheck()],
      conclusion: null,
      replayDigest: null,
      status: "in_progress",
    }),
    "publish",
  );
});

test("稳定 pending CAS 与 replay digest 在 guardian 重跑时保持幂等", () => {
  const pendingCasKey = "1303415307:head:pending:5:100:1";
  const pendingReplayDigest = "b".repeat(64);
  assert.equal(
    classifyCheckReplay({
      casKey: pendingCasKey,
      checks: [{
        conclusion: null,
        id: 2,
        output: {
          summary: JSON.stringify({
            casKey: pendingCasKey,
            replayDigest: pendingReplayDigest,
            status: "pending",
          }),
        },
        status: "in_progress",
      }],
      conclusion: null,
      replayDigest: pendingReplayDigest,
      status: "in_progress",
    }),
    "idempotent",
  );
});

test("同一 workflow run 的 pending 可以原位转换为稳定 terminal failure", () => {
  const pendingCasKey = "1303415307:head:pending:5:100:1";
  const pending = {
    conclusion: null,
    id: 8,
    output: {
      summary: JSON.stringify({
        casKey: pendingCasKey,
        replayDigest: "b".repeat(64),
        status: "pending",
      }),
    },
    status: "in_progress",
  };
  const plan = planCheckReplay({
    casKey: pendingCasKey,
    checks: [pending],
    conclusion: "failure",
    replayDigest: "c".repeat(64),
    status: "completed",
  });

  assert.equal(plan.action, "transition");
  assert.equal(plan.check, pending);
  assert.equal(
    classifyCheckReplay({
      casKey: pendingCasKey,
      checks: [pending],
      conclusion: "failure",
      replayDigest: "c".repeat(64),
      status: "completed",
    }),
    "transition",
  );
});

test("既有 terminal failure 即使后面存在旧 storm 记录也保持幂等", () => {
  const terminalCasKey = "1303415307:head:pending:5:100:1";
  const terminalReplayDigest = "c".repeat(64);
  const terminal = {
    conclusion: "failure",
    id: 8,
    output: {
      summary: JSON.stringify({
        casKey: terminalCasKey,
        replayDigest: terminalReplayDigest,
        status: "terminal-failure",
      }),
    },
    status: "completed",
  };
  const legacyStormFailure = {
    conclusion: "failure",
    id: 9,
    output: { summary: "child evidence workflow failed" },
    status: "completed",
  };

  assert.equal(
    classifyCheckReplay({
      casKey: terminalCasKey,
      checks: [terminal, legacyStormFailure],
      conclusion: "failure",
      replayDigest: terminalReplayDigest,
      status: "completed",
    }),
    "idempotent",
  );
});

test("独立 lifecycle key 允许 success 用不同 result CAS 原位接管 pending", () => {
  const pending = {
    conclusion: null,
    id: 10,
    output: {
      summary: JSON.stringify({
        casKey: "1303415307:head:pending:9:30592045649:1",
        checkLifecycleKey: lifecycleKey,
        replayDigest: "a".repeat(64),
        status: "pending",
      }),
    },
    status: "in_progress",
  };
  const plan = planCheckLifecycle({
    casKey,
    checkLifecycleKey: lifecycleKey,
    checks: [pending],
    conclusion: "success",
    headOid: "head",
    pullNumber: 9,
    replayDigest: "b".repeat(64),
    status: "completed",
  });

  assert.equal(plan.action, "transition");
  assert.equal(plan.check, pending);
  assert.deepEqual(plan.supersededChecks, []);
});

test("旧 missing:none pending 在首个 run 出现后按 PR/head 被认领", () => {
  const missingPending = {
    conclusion: null,
    id: 11,
    output: {
      summary: JSON.stringify({
        casKey: "1303415307:head:pending:9:missing:none",
        replayDigest: "a".repeat(64),
        status: "pending",
      }),
    },
    status: "in_progress",
  };
  const plan = planCheckLifecycle({
    casKey: "1303415307:head:pending:9:30592045649:1",
    checkLifecycleKey: lifecycleKey,
    checks: [missingPending],
    conclusion: null,
    headOid: "head",
    pullNumber: 9,
    replayDigest: "b".repeat(64),
    status: "in_progress",
  });

  assert.equal(plan.action, "transition");
  assert.equal(plan.check.id, 11);
});

test("旧 orphan pending 会被已存在的同 run terminal success 结构化 supersede", () => {
  const orphan = {
    conclusion: null,
    id: 91036295709,
    output: {
      summary: JSON.stringify({
        casKey: "1303415307:head:pending:9:30592045649:1",
        replayDigest: "a".repeat(64),
        status: "pending",
      }),
    },
    status: "in_progress",
  };
  const terminal = {
    conclusion: "success",
    id: 91036644980,
    output: {
      summary: JSON.stringify({
        providerEvidenceRecord: {
          headOid: "head",
          workflowRef: "Rockyyy-S/code-graph/.github/workflows/architecture-required.yml@refs/pull/9/merge",
        },
        replayDigest: "b".repeat(64),
        result: { casKey },
      }),
    },
    status: "completed",
  };
  const plan = planCheckLifecycle({
    casKey,
    checkLifecycleKey: lifecycleKey,
    checks: [orphan, terminal],
    conclusion: "success",
    headOid: "head",
    pullNumber: 9,
    replayDigest: "b".repeat(64),
    status: "completed",
  });

  assert.equal(plan.check.id, 91036644980);
  assert.deepEqual(plan.supersededChecks.map((check) => check.id), [91036295709]);
  assert.equal(plan.action, "transition");
});

test("旧 controller-invalid terminal 会归属当前唯一 PR/head lifecycle 并被 success supersede", () => {
  const success = {
    conclusion: "success",
    id: 20,
    output: {
      summary: JSON.stringify({
        casKey,
        checkLifecycleKey: lifecycleKey,
        replayDigest: "b".repeat(64),
      }),
    },
    status: "completed",
  };
  const legacyDriftFailure = {
    conclusion: "failure",
    id: 21,
    output: {
      summary: JSON.stringify({
        casKey: "1303415307:head:controller-invalid:23",
        replayDigest: "c".repeat(64),
        status: "drift-monitor-invalid",
      }),
    },
    status: "completed",
  };
  const plan = planCheckLifecycle({
    casKey,
    checkLifecycleKey: lifecycleKey,
    checks: [success, legacyDriftFailure],
    conclusion: "success",
    headOid: "head",
    pullNumber: 9,
    replayDigest: "b".repeat(64),
    status: "completed",
  });

  assert.equal(plan.action, "idempotent");
  assert.equal(plan.check.id, 20);
  assert.deepEqual(plan.supersededChecks.map((check) => check.id), [21]);
});

test("重启或 lease successor 读取完整 lifecycle summary 后精确幂等", () => {
  const terminal = {
    completed_at: "2026-07-31T00:00:00Z",
    conclusion: "failure",
    id: 12,
    output: {
      summary: JSON.stringify({
        casKey,
        checkLifecycleKey: lifecycleKey,
        replayDigest: "c".repeat(64),
      }),
    },
    status: "completed",
  };
  const plan = planCheckLifecycle({
    casKey,
    checkLifecycleKey: lifecycleKey,
    checks: [terminal],
    conclusion: "failure",
    headOid: "head",
    pullNumber: 9,
    replayDigest: "c".repeat(64),
    status: "completed",
  });

  assert.equal(plan.action, "idempotent");
  assert.equal(plan.check.id, 12);
});

test("无法结构化归属的活动 Controller check 必须报告 lifecycle conflict", () => {
  const unknown = {
    conclusion: null,
    id: 13,
    output: { summary: "legacy unknown pending" },
    status: "in_progress",
  };
  const plan = planCheckLifecycle({
    casKey,
    checkLifecycleKey: lifecycleKey,
    checks: [unknown],
    conclusion: "success",
    headOid: "head",
    pullNumber: 9,
    replayDigest: "d".repeat(64),
    status: "completed",
  });

  assert.deepEqual(plan.conflictingChecks, [unknown]);
  assert.equal(plan.action, "publish");
});
