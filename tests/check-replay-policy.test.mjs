import assert from "node:assert/strict";
import test from "node:test";
import { classifyCheckReplay } from "../lib/check-replay-policy.mjs";

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
