import assert from "node:assert/strict";
import test from "node:test";
import {
  classifyCheckReplay,
  planCheckReplay,
} from "../lib/check-replay-policy.mjs";

const casKey = "1303415307:head:context:implementation:3";

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
