import assert from "node:assert/strict";
import test from "node:test";
import {
  collectGithubPages,
  collectGithubPagesBestEffort,
} from "../lib/github-pagination.mjs";

test("分页读取合并对象字段并保留既有查询参数", async () => {
  const endpoints = [];
  const firstPage = Array.from({ length: 100 }, (_, index) => index);
  const values = await collectGithubPages({
    endpoint: "repos/owner/repository/commits/head/check-runs?filter=all",
    field: "check_runs",
    options: { token: "token" },
    request: async (endpoint, options) => {
      endpoints.push({ endpoint, options });
      return { check_runs: endpoint.endsWith("page=1") ? firstPage : [100] };
    },
  });

  assert.deepEqual(values, [...firstPage, 100]);
  assert.deepEqual(endpoints, [
    {
      endpoint:
        "repos/owner/repository/commits/head/check-runs?filter=all&per_page=100&page=1",
      options: { token: "token" },
    },
    {
      endpoint:
        "repos/owner/repository/commits/head/check-runs?filter=all&per_page=100&page=2",
      options: { token: "token" },
    },
  ]);
});

test("分页读取支持顶层数组并拒绝缺失数组字段", async () => {
  assert.deepEqual(
    await collectGithubPages({
      endpoint: "repos/owner/repository/pulls?state=open",
      field: null,
      request: async () => [{ number: 1 }],
    }),
    [{ number: 1 }],
  );

  await assert.rejects(
    () =>
      collectGithubPages({
        endpoint: "repos/owner/repository/actions/runs/1/artifacts",
        field: "artifacts",
        request: async () => ({}),
      }),
    /未返回数组字段/u,
  );
});

test("分页读取在响应持续满页时按安全上限失败", async () => {
  await assert.rejects(
    () =>
      collectGithubPages({
        endpoint: "repos/owner/repository/pulls",
        field: null,
        maxPages: 2,
        request: async () => Array.from({ length: 100 }, (_, index) => index),
      }),
    /安全页数上限/u,
  );
});

test("best-effort 分页在后续页失败时保留已读取元素", async () => {
  const firstPage = Array.from({ length: 100 }, (_, index) => index);
  let pageTwoAttempts = 0;
  const result = await collectGithubPagesBestEffort({
    endpoint: "repos/owner/repository/pulls?state=open",
    field: null,
    request: async (endpoint) => {
      if (endpoint.endsWith("page=1")) {
        return firstPage;
      }
      pageTwoAttempts += 1;
      throw new Error("page 2 failed");
    },
  });

  assert.deepEqual(result.values, firstPage);
  assert.match(result.error?.message ?? "", /page 2 failed/u);
  assert.equal(pageTwoAttempts, 3);
});
