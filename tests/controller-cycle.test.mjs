import assert from "node:assert/strict";
import test from "node:test";
import {
  assertDriftMonitorLease,
  assertControllerDefaultBranchCurrent,
  assertPullOwnsUniqueOpenHead,
  assertUniqueOpenPullHeads,
  closePublishedSuccess,
  createPendingCheckRecord,
  executeControllerCycle,
  revalidatePublishedSuccess,
  sameCurrentPullSnapshot,
  samePullIdentity,
  sameWorkflowRunIdentity,
} from "../bin/run-controller.mjs";

const monitorOptions = {
  defaultBranch: "main",
  now: Date.parse("2026-07-23T07:00:00Z"),
  repository: "Rockyyy-S/code-graph-gate-controller",
  trustedHeadSha: "f".repeat(40),
  workflowPath: ".github/workflows/drift-monitor.yml",
};

/** 创建与 Controller 可信 monitor 身份闭合的测试运行。 */
function monitorRun(overrides = {}) {
  return {
    conclusion: "success",
    event: "schedule",
    head_branch: "main",
    head_sha: "f".repeat(40),
    id: 1,
    path: ".github/workflows/drift-monitor.yml",
    repository: { full_name: "Rockyyy-S/code-graph-gate-controller" },
    status: "completed",
    updated_at: "2026-07-23T06:54:00Z",
    ...overrides,
  };
}

/** 创建可观察全局撤销调用的 Controller cycle 依赖。 */
function createDependencies(overrides = {}) {
  const revocations = [];
  return {
    dependencies: {
      assertFresh: async () => undefined,
      listPulls: async () => [{ head: { sha: "b" }, number: 5 }],
      loadState: async () => ({ sequence: 16 }),
      processPull: async () => undefined,
      revokePulls: async (...args) => {
        revocations.push(args);
        return [];
      },
      ...overrides,
    },
    revocations,
  };
}

test("可信配置加载失败也进入全局撤销路径", async () => {
  const fixture = createDependencies({
    loadState: async () => {
      throw new Error("trusted record invalid");
    },
  });

  await assert.rejects(executeControllerCycle(fixture.dependencies), /trusted record invalid/u);
  assert.equal(fixture.revocations.length, 1);
  assert.equal(fixture.revocations[0][1], null);
});

test("普通 provider API 故障撤销已经读取的开放 PR", async () => {
  const pulls = [{ head: { sha: "b" }, number: 5 }];
  const fixture = createDependencies({
    listPulls: async () => pulls,
    processPull: async () => {
      throw new Error("provider api failed");
    },
  });

  await assert.rejects(executeControllerCycle(fixture.dependencies), /provider api failed/u);
  assert.deepEqual(fixture.revocations[0][0], pulls);
});

test("多个开放 PR 复用同一 head 时 fail closed 并进入全局撤销", async () => {
  const pulls = [
    { head: { sha: "b" }, number: 5 },
    { head: { sha: "b" }, number: 6 },
  ];
  const fixture = createDependencies({ listPulls: async () => pulls });

  await assert.rejects(
    executeControllerCycle(fixture.dependencies),
    /同一 head|多个开放 PR/u,
  );
  assert.deepEqual(fixture.revocations[0][0], pulls);
  assert.throws(() => assertUniqueOpenPullHeads(pulls), /同一 head|多个开放 PR/u);
});

test("PR head/base 变化与撤销前后快照变化均会被识别", () => {
  const original = {
    base: { sha: "a" },
    head: { sha: "b" },
    merge_commit_sha: "c",
    number: 5,
  };
  const forcePushed = { ...original, head: { sha: "d" } };
  const rebased = { ...original, base: { sha: "e" } };
  const mergeRefChanged = { ...original, merge_commit_sha: "f" };

  assert.equal(samePullIdentity(original, structuredClone(original)), true);
  assert.equal(samePullIdentity(original, forcePushed), false);
  assert.equal(samePullIdentity(original, rebased), false);
  assert.equal(samePullIdentity(original, mergeRefChanged), false);
  assert.equal(sameCurrentPullSnapshot([original], [forcePushed]), false);
  assert.equal(sameCurrentPullSnapshot([original], [mergeRefChanged]), false);
});

test("发布前重新枚举全部开放 PR 并拒绝同 head 新增 ownership", () => {
  const expected = {
    base: { sha: "a" },
    head: { sha: "b" },
    merge_commit_sha: "c",
    number: 5,
  };

  assert.deepEqual(assertPullOwnsUniqueOpenHead(expected, [structuredClone(expected)]), expected);
  assert.throws(
    () => assertPullOwnsUniqueOpenHead(expected, [expected, { ...expected, number: 6 }]),
    /同一 head|多个开放 PR/u,
  );
});

test("workflow run 发布前必须保持同一 run ID、attempt 和结论", () => {
  const expected = { conclusion: "success", id: 100, run_attempt: 1, status: "completed" };
  assert.equal(sameWorkflowRunIdentity(expected, structuredClone(expected)), true);
  assert.equal(sameWorkflowRunIdentity(expected, { ...expected, id: 101 }), false);
  assert.equal(sameWorkflowRunIdentity(expected, { ...expected, run_attempt: 2 }), false);
  assert.equal(sameWorkflowRunIdentity(expected, { ...expected, conclusion: "failure" }), false);
});

test("同一 PR/head/child run 的 pending check 使用稳定幂等键", () => {
  const input = {
    headOid: "b".repeat(40),
    pullNumber: 5,
    repositoryId: "1303415307",
    run: { id: 100, run_attempt: 2, status: "in_progress" },
  };
  const first = createPendingCheckRecord(input);
  const second = createPendingCheckRecord({
    ...input,
    run: { ...input.run, status: "queued" },
  });
  assert.deepEqual(second, first);
  assert.notEqual(
    createPendingCheckRecord({ ...input, run: { ...input.run, id: 101 } }).casKey,
    first.casKey,
  );
});

test("success 发布后按 run、PR、monitor 顺序再次闭合 provider 状态", async () => {
  const calls = [];
  const pull = { base: { sha: "a" }, head: { sha: "b" }, number: 5 };
  const run = { conclusion: "success", id: 100, run_attempt: 1, status: "completed" };

  const result = await revalidatePublishedSuccess({
    assertFresh: async () => calls.push("monitor"),
    assertProposal: async () => calls.push("proposal"),
    assertPull: async (expected) => {
      calls.push("pull");
      return expected;
    },
    assertRun: async () => calls.push("run"),
    assertUnique: async () => calls.push("unique-head"),
    expectedPull: pull,
    expectedRun: run,
    headOid: pull.head.sha,
  });

  assert.equal(result, pull);
  assert.deepEqual(calls, ["run", "pull", "unique-head", "proposal", "monitor"]);
});

test("monitor freshness 先绑定 Controller 默认分支当前 SHA", async () => {
  const calls = [];
  const trustedSha = "a".repeat(40);

  const response = await assertControllerDefaultBranchCurrent({
    defaultBranch: "main",
    repository: "owner/controller",
    request: async (endpoint, options) => {
      calls.push([endpoint, options]);
      return { sha: trustedSha };
    },
    token: "controller-token",
    trustedSha,
  });

  assert.equal(response.sha, trustedSha);
  assert.deepEqual(calls, [["repos/owner/controller/commits/main", { token: "controller-token" }]]);
  await assert.rejects(
    assertControllerDefaultBranchCurrent({
      defaultBranch: "main",
      repository: "owner/controller",
      request: async () => ({ sha: "b".repeat(40) }),
      token: "controller-token",
      trustedSha,
    }),
    /默认分支|可信.*SHA|漂移/u,
  );
});

test("monitor 进入预刷新窗口时同一 cycle 只 dispatch 一次", async () => {
  const refreshState = { attemptedAt: null };
  let dispatches = 0;
  const options = {
    dispatchRefresh: async () => {
      dispatches += 1;
    },
    monitorRuns: [monitorRun()],
    options: monitorOptions,
    refreshState,
  };

  await assertDriftMonitorLease(options);
  await assertDriftMonitorLease(options);

  assert.equal(dispatches, 1);
});

test("新鲜或已有可信 active monitor 时不 dispatch", async () => {
  let dispatches = 0;
  const dispatchRefresh = async () => {
    dispatches += 1;
  };
  await assertDriftMonitorLease({
    dispatchRefresh,
    monitorRuns: [monitorRun({ updated_at: "2026-07-23T06:54:00.001Z" })],
    options: monitorOptions,
    refreshState: { attemptedAt: null },
  });

  await assert.rejects(
    assertDriftMonitorLease({
      dispatchRefresh,
      monitorRuns: [
        monitorRun({ updated_at: "2026-07-23T06:45:00Z" }),
        monitorRun({
          conclusion: null,
          event: "workflow_dispatch",
          id: 2,
          status: "in_progress",
          updated_at: "2026-07-23T06:59:00Z",
        }),
      ],
      options: monitorOptions,
      refreshState: { attemptedAt: null },
    }),
    /drift monitor|fail closed/u,
  );

  assert.equal(dispatches, 0);
});

test("未过期 monitor 的 dispatch 失败只记录并继续复用 success", async () => {
  const errors = [];
  const freshRun = monitorRun();
  const selected = await assertDriftMonitorLease({
    dispatchRefresh: async () => {
      throw new Error("dispatch unavailable");
    },
    logError: (message) => errors.push(message),
    monitorRuns: [freshRun],
    options: monitorOptions,
    refreshState: { attemptedAt: null },
  });

  assert.equal(selected, freshRun);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /dispatch unavailable/u);
});

test("过期 monitor 即使 dispatch 成功也继续 fail closed", async () => {
  let dispatches = 0;
  await assert.rejects(
    assertDriftMonitorLease({
      dispatchRefresh: async () => {
        dispatches += 1;
      },
      monitorRuns: [monitorRun({ updated_at: "2026-07-23T06:45:00Z" })],
      options: monitorOptions,
      refreshState: { attemptedAt: null },
    }),
    /drift monitor|fail closed/u,
  );
  assert.equal(dispatches, 1);
});

test("进程内六分钟冷却覆盖 runs API 最终一致性间隙", async () => {
  const refreshState = { attemptedAt: null };
  let dispatches = 0;
  const dispatchRefresh = async () => {
    dispatches += 1;
  };

  await assertDriftMonitorLease({
    dispatchRefresh,
    monitorRuns: [monitorRun()],
    options: monitorOptions,
    refreshState,
  });
  await assertDriftMonitorLease({
    dispatchRefresh,
    monitorRuns: [monitorRun()],
    options: { ...monitorOptions, now: monitorOptions.now + 5 * 60 * 1000 },
    refreshState,
  });
  await assertDriftMonitorLease({
    dispatchRefresh,
    monitorRuns: [monitorRun()],
    options: { ...monitorOptions, now: monitorOptions.now + 6 * 60 * 1000 },
    refreshState,
  });

  assert.equal(dispatches, 2);
});

test("日志适配器失败不能覆盖仍有效的 monitor success", async () => {
  const freshRun = monitorRun();
  const selected = await assertDriftMonitorLease({
    dispatchRefresh: async () => {
      throw new Error("dispatch unavailable");
    },
    logError: () => {
      throw new Error("logger unavailable");
    },
    monitorRuns: [freshRun],
    options: monitorOptions,
    refreshState: { attemptedAt: null },
  });

  assert.equal(selected, freshRun);
});

test("success 后复验失败时先撤销绿色再传播原错误", async () => {
  const calls = [];
  const original = new Error("workflow run changed");

  await assert.rejects(
    closePublishedSuccess({
      revalidate: async () => {
        calls.push("revalidate");
        throw original;
      },
      revoke: async (error) => {
        calls.push(`revoke:${error.message}`);
      },
    }),
    (error) => error === original,
  );
  assert.deepEqual(calls, ["revalidate", "revoke:workflow run changed"]);
});

test("success 撤销发布失败时传播复合错误供全局撤销处理", async () => {
  await assert.rejects(
    closePublishedSuccess({
      revalidate: async () => {
        throw new Error("workflow run changed");
      },
      revoke: async () => {
        throw new Error("cannot revoke success");
      },
    }),
    /撤销.*失败|cannot revoke success/u,
  );
});
