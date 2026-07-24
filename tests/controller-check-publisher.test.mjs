import assert from "node:assert/strict";
import test from "node:test";
import { publishControllerCheck } from "../lib/controller-check-publisher.mjs";

const casKey = "1303415307:head:context:implementation:16";
const replayDigest = "a".repeat(64);

/** 创建包含指定 CAS 与 replay digest 的历史 success check。 */
function createSuccessCheck() {
  return {
    conclusion: "success",
    id: 1,
    output: {
      summary: JSON.stringify({ replayDigest, result: { casKey } }),
    },
    status: "completed",
  };
}

test("保留幂等 success 前必须重新验证 monitor freshness", async () => {
  let freshnessChecks = 0;
  let posts = 0;
  const action = await publishControllerCheck({
    assertFreshMonitor: async () => {
      freshnessChecks += 1;
    },
    casKey,
    conclusion: "success",
    headOid: "b".repeat(40),
    loadChecks: async () => [createSuccessCheck()],
    postCheck: async () => {
      posts += 1;
    },
    replayDigest,
    status: "completed",
    summary: "accepted",
  });

  assert.equal(action, "idempotent");
  assert.equal(freshnessChecks, 1);
  assert.equal(posts, 0);
});

test("发布 success 前 monitor 失效时不得调用 Checks API", async () => {
  let posts = 0;
  await assert.rejects(
    () =>
      publishControllerCheck({
        assertFreshMonitor: async () => {
          throw new Error("monitor expired");
        },
        casKey,
        conclusion: "success",
        headOid: "b".repeat(40),
        loadChecks: async () => [],
        postCheck: async () => {
          posts += 1;
        },
        replayDigest,
        status: "completed",
        summary: "accepted",
      }),
    /monitor expired/u,
  );
  assert.equal(posts, 0);
});

test("drift failure 在历史 check 分页失败时仍直接追加失败结论", async () => {
  const posts = [];
  const action = await publishControllerCheck({
    allowFailureOnHistoryError: true,
    assertFreshMonitor: async () => {},
    casKey,
    conclusion: "failure",
    headOid: "b".repeat(40),
    loadChecks: async () => {
      throw new Error("page 2 failed");
    },
    postCheck: async (body) => posts.push(body),
    replayDigest,
    status: "completed",
    summary: JSON.stringify({ status: "drift-monitor-invalid" }),
  });

  assert.equal(action, "published");
  assert.equal(posts.length, 1);
  assert.equal(posts[0].conclusion, "failure");
  assert.equal(posts[0].output.title, "Architecture gates failed closed");
});

test("普通结论在历史 check 不完整时继续 fail closed", async () => {
  await assert.rejects(
    () =>
      publishControllerCheck({
        assertFreshMonitor: async () => {},
        casKey,
        conclusion: "failure",
        headOid: "b".repeat(40),
        loadChecks: async () => {
          throw new Error("history incomplete");
        },
        postCheck: async () => {},
        replayDigest,
        status: "completed",
        summary: "rejected",
      }),
    /history incomplete/u,
  );
});
