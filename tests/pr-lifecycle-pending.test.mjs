import assert from "node:assert/strict";
import test from "node:test";
import { publishPullLifecyclePending } from "../bin/publish-pr-pending.mjs";

const input = {
  controllerAppId: "4372284",
  controllerWorkflowSha: "a".repeat(40),
  headOid: "b".repeat(40),
  lifecycleAction: "reopened",
  providerRepositoryId: "1303415307",
  pullNumber: 5,
  repository: "Rockyyy-S/code-graph",
};

/** 创建可观察 PR 快照、历史查询和 Checks API 发布的依赖。 */
function createDependencies() {
  const posts = [];
  const pull = {
    base: { repo: { id: 1303415307 } },
    head: { sha: input.headOid },
    number: input.pullNumber,
    state: "open",
  };
  return {
    posts,
    request: async (endpoint, options = {}) => {
      if (endpoint.endsWith(`/pulls/${input.pullNumber}`)) {
        return structuredClone(pull);
      }
      if (endpoint.includes("/commits/") && endpoint.includes("/check-runs?")) {
        return { check_runs: [] };
      }
      if (endpoint.endsWith("/check-runs") && options.method === "POST") {
        posts.push(options.body);
        return { id: 1 };
      }
      throw new Error(`unexpected endpoint: ${endpoint}`);
    },
  };
}

test("PR reopen 使用 Controller App 发布稳定 architecture-required pending", async () => {
  const fixture = createDependencies();
  const result = await publishPullLifecyclePending(input, { request: fixture.request });

  assert.equal(result.action, "published");
  assert.match(result.casKey, /:pr-lifecycle:5:reopened$/u);
  assert.equal(fixture.posts.length, 1);
  assert.equal(fixture.posts[0].name, "architecture-required");
  assert.equal(fixture.posts[0].status, "in_progress");
  assert.equal(Object.hasOwn(fixture.posts[0], "conclusion"), false);
});

test("PR base 编辑进入与 reopen 相同的 fail-closed pending 路径", async () => {
  const fixture = createDependencies();
  const result = await publishPullLifecyclePending(
    { ...input, lifecycleAction: "edited" },
    { request: fixture.request },
  );

  assert.match(result.casKey, /:pr-lifecycle:5:edited$/u);
  assert.equal(fixture.posts.length, 1);
  assert.equal(fixture.posts[0].status, "in_progress");
});

test("PR 生命周期 publisher 拒绝非白名单 action 与漂移 head", async () => {
  await assert.rejects(
    publishPullLifecyclePending({ ...input, lifecycleAction: "closed" }, createDependencies()),
    /合同闭合/u,
  );
  const fixture = createDependencies();
  await assert.rejects(
    publishPullLifecyclePending(
      { ...input, headOid: "c".repeat(40) },
      { request: fixture.request },
    ),
    /快照已变化/u,
  );
});
