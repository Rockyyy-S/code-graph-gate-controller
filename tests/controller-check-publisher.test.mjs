import assert from "node:assert/strict";
import test from "node:test";
import {
  ControllerCheckPublicationError,
  publishControllerCheck,
} from "../lib/controller-check-publisher.mjs";

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

test("pending 到 terminal failure 原位更新且重复 guardian cycle 不新增 check", async () => {
  const terminalCasKey = "1303415307:head:pending:9:30535583048:1";
  const pendingReplayDigest = "b".repeat(64);
  const terminalReplayDigest = "c".repeat(64);
  const checks = [{
    conclusion: null,
    id: 90848010628,
    output: {
      summary: JSON.stringify({
        casKey: terminalCasKey,
        replayDigest: pendingReplayDigest,
        status: "pending",
      }),
    },
    status: "in_progress",
  }];
  const posts = [];
  const updates = [];
  const input = {
    assertFreshMonitor: async () => {},
    casKey: terminalCasKey,
    conclusion: "failure",
    headOid: "b".repeat(40),
    loadChecks: async () => checks,
    postCheck: async (body) => posts.push(body),
    replayDigest: terminalReplayDigest,
    status: "completed",
    summary: JSON.stringify({
      casKey: terminalCasKey,
      replayDigest: terminalReplayDigest,
      status: "terminal-failure",
    }),
    updateCheck: async (checkId, body) => {
      updates.push({ body, checkId });
      Object.assign(checks[0], body);
      checks[0].output = body.output;
    },
  };

  assert.equal(await publishControllerCheck(input), "transitioned");
  assert.equal(await publishControllerCheck(input), "idempotent");
  assert.equal(posts.length, 0);
  assert.equal(updates.length, 1);
  assert.equal(updates[0].checkId, 90848010628);
  assert.equal(updates[0].body.status, "completed");
  assert.equal(updates[0].body.conclusion, "failure");
  assert.equal("head_sha" in updates[0].body, false);
});

test("并发 terminal replay 只会幂等更新同一个 pending check ID", async () => {
  const terminalCasKey = "1303415307:head:pending:9:30535583048:1";
  const checks = [{
    conclusion: null,
    id: 90848010628,
    output: {
      summary: JSON.stringify({
        casKey: terminalCasKey,
        replayDigest: "b".repeat(64),
        status: "pending",
      }),
    },
    status: "in_progress",
  }];
  const posts = [];
  const updatedIds = [];
  const createInput = () => ({
    assertFreshMonitor: async () => {},
    casKey: terminalCasKey,
    conclusion: "failure",
    headOid: "b".repeat(40),
    loadChecks: async () => structuredClone(checks),
    postCheck: async (body) => posts.push(body),
    replayDigest: "c".repeat(64),
    status: "completed",
    summary: JSON.stringify({
      casKey: terminalCasKey,
      replayDigest: "c".repeat(64),
      status: "terminal-failure",
    }),
    updateCheck: async (checkId) => updatedIds.push(checkId),
  });

  assert.deepEqual(
    await Promise.all([
      publishControllerCheck(createInput()),
      publishControllerCheck(createInput()),
    ]),
    ["transitioned", "transitioned"],
  );
  assert.deepEqual(updatedIds, [90848010628, 90848010628]);
  assert.equal(posts.length, 0);
});

const lifecycleKey = "check-lifecycle-v1:1303415307:9:head:architecture-required";

/** 模拟 GitHub Checks 的 POST/PATCH/按 ID readback 与历史扫描。 */
function createLifecycleHarness(initialChecks = []) {
  const checks = structuredClone(initialChecks);
  const posts = [];
  const updates = [];
  let nextId = Math.max(100, ...checks.map((check) => Number(check.id) || 0)) + 1;
  return {
    checks,
    input(overrides = {}) {
      return {
        assertFreshMonitor: async () => {},
        assertFreshMonitorReadOnly: async () => {},
        casKey,
        checkLifecycleKey: lifecycleKey,
        conclusion: "success",
        headOid: "head",
        loadCheck: async (checkId) => structuredClone(
          checks.find((check) => check.id === checkId),
        ),
        loadChecks: async () => structuredClone(checks),
        postCheck: async (body) => {
          const check = applyBody({ id: nextId++ }, body);
          checks.push(check);
          posts.push({ body, checkId: check.id });
          return structuredClone(check);
        },
        pullNumber: 9,
        replayDigest,
        status: "completed",
        summary: JSON.stringify({ replayDigest, result: { casKey } }),
        updateCheck: async (checkId, body) => {
          const check = checks.find((candidate) => candidate.id === checkId);
          if (check === undefined) {
            throw new Error(`missing check ${checkId}`);
          }
          applyBody(check, body);
          updates.push({ body, checkId });
          return structuredClone(check);
        },
        ...overrides,
      };
    },
    posts,
    updates,
  };
}

function applyBody(check, body) {
  Object.assign(check, body);
  check.conclusion = body.status === "in_progress" ? null : body.conclusion;
  check.completed_at = body.status === "completed" ? "2026-07-31T00:00:00Z" : null;
  check.output = structuredClone(body.output);
  return check;
}

function createLifecyclePending({
  checkLifecycleKey = lifecycleKey,
  id = 200,
  pendingCasKey = "1303415307:head:pending:9:30592045649:1",
  pendingDigest = "b".repeat(64),
} = {}) {
  return {
    completed_at: null,
    conclusion: null,
    id,
    output: {
      summary: JSON.stringify({
        casKey: pendingCasKey,
        ...(checkLifecycleKey === null ? {} : { checkLifecycleKey }),
        replayDigest: pendingDigest,
        status: "pending",
      }),
    },
    status: "in_progress",
  };
}

test("fresh success PATCH 原 pending，精确重放零 POST/零重复 PATCH", async () => {
  const harness = createLifecycleHarness([createLifecyclePending()]);
  let writeFreshnessChecks = 0;
  let readOnlyFreshnessChecks = 0;
  const input = harness.input({
    assertFreshMonitor: async () => {
      writeFreshnessChecks += 1;
    },
    assertFreshMonitorReadOnly: async () => {
      readOnlyFreshnessChecks += 1;
    },
  });

  assert.equal(await publishControllerCheck(input), "transitioned");
  assert.equal(await publishControllerCheck(input), "idempotent");
  assert.equal(harness.posts.length, 0);
  assert.equal(harness.updates.length, 1);
  assert.equal(harness.updates[0].checkId, 200);
  assert.equal(harness.checks[0].conclusion, "success");
  assert.equal(writeFreshnessChecks, 1);
  assert.equal(readOnlyFreshnessChecks, 1);
});

test("同一 result CAS 的 digest 冲突原位 fail closed，后续 cycle 保持冲突终态", async () => {
  const firstDigest = "1".repeat(64);
  const conflictingDigest = "2".repeat(64);
  const harness = createLifecycleHarness([{
    completed_at: "2026-07-31T00:00:00Z",
    conclusion: "success",
    id: 207,
    output: {
      summary: JSON.stringify({
        casKey,
        checkLifecycleKey: lifecycleKey,
        replayDigest: firstDigest,
        result: { casKey },
      }),
    },
    status: "completed",
  }]);
  const input = harness.input({
    replayDigest: conflictingDigest,
    summary: JSON.stringify({ replayDigest: conflictingDigest, result: { casKey } }),
  });

  assert.equal(await publishControllerCheck(input), "transitioned");
  assert.equal(await publishControllerCheck(input), "idempotent-conflict");
  assert.equal(harness.checks[0].conclusion, "failure");
  assert.equal(JSON.parse(harness.checks[0].output.summary).replayConflict, true);
  assert.equal(harness.updates.length, 1);
  assert.equal(harness.posts.length, 0);
});

for (const conclusion of ["failure", "timed_out", "cancelled"]) {
  test(`fresh ${conclusion} PATCH 原 pending，restart 后保持同一 check ID`, async () => {
    const digest = conclusion[0].repeat(64);
    const harness = createLifecycleHarness([createLifecyclePending()]);
    const firstProcess = harness.input({
      conclusion,
      replayDigest: digest,
      summary: JSON.stringify({ replayDigest: digest, status: `terminal-${conclusion}` }),
    });
    assert.equal(await publishControllerCheck(firstProcess), "transitioned");

    const successorProcess = harness.input({
      conclusion,
      replayDigest: digest,
      summary: JSON.stringify({ replayDigest: digest, status: `terminal-${conclusion}` }),
    });
    assert.equal(await publishControllerCheck(successorProcess), "idempotent");
    assert.equal(harness.posts.length, 0);
    assert.deepEqual(harness.updates.map((entry) => entry.checkId), [200]);
  });
}

test("missing:none pending 在 known run 出现时保留原 check ID", async () => {
  const harness = createLifecycleHarness([createLifecyclePending({
    checkLifecycleKey: null,
    id: 201,
    pendingCasKey: "1303415307:head:pending:9:missing:none",
  })]);
  const knownCasKey = "1303415307:head:pending:9:30592045649:1";
  const knownDigest = "d".repeat(64);

  assert.equal(await publishControllerCheck(harness.input({
    casKey: knownCasKey,
    conclusion: null,
    replayDigest: knownDigest,
    status: "in_progress",
    summary: JSON.stringify({
      casKey: knownCasKey,
      replayDigest: knownDigest,
      runAttempt: "1",
      runId: "30592045649",
      status: "pending",
    }),
  })), "transitioned");
  assert.equal(harness.posts.length, 0);
  assert.equal(harness.updates[0].checkId, 201);
});

test("现存 orphan 91036295709 由 terminal 91036644980 正常 supersede closure", async () => {
  const orphanDigest = "8".repeat(64);
  const terminalDigest = "4".repeat(64);
  const terminalCasKey = "1303415307:head:context:implementation:24";
  const harness = createLifecycleHarness([
    createLifecyclePending({
      checkLifecycleKey: null,
      id: 91036295709,
      pendingCasKey: "1303415307:head:pending:9:30592045649:1",
      pendingDigest: orphanDigest,
    }),
    {
      completed_at: "2026-07-30T23:58:58Z",
      conclusion: "success",
      id: 91036644980,
      output: {
        summary: JSON.stringify({
          providerEvidenceRecord: {
            headOid: "head",
            workflowRef: "Rockyyy-S/code-graph/.github/workflows/architecture-required.yml@refs/pull/9/merge",
          },
          replayDigest: terminalDigest,
          result: { casKey: terminalCasKey },
        }),
      },
      status: "completed",
    },
  ]);

  assert.equal(await publishControllerCheck(harness.input({
    casKey: terminalCasKey,
    replayDigest: terminalDigest,
    summary: JSON.stringify({ replayDigest: terminalDigest, result: { casKey: terminalCasKey } }),
  })), "transitioned");
  const orphan = harness.checks.find((check) => check.id === 91036295709);
  const orphanSummary = JSON.parse(orphan.output.summary);
  assert.equal(orphan.status, "completed");
  assert.equal(orphan.conclusion, "neutral");
  assert.equal(orphan.completed_at, "2026-07-31T00:00:00Z");
  assert.equal(orphanSummary.supersededByCheckId, 91036644980);
  assert.equal(harness.posts.length, 0);
});

test("旧 main-drift failure 91052594278 被现有权威 success 明确 supersede", async () => {
  const terminalDigest = "4".repeat(64);
  const harness = createLifecycleHarness([
    {
      completed_at: "2026-07-30T23:58:58Z",
      conclusion: "success",
      id: 91036644980,
      output: {
        summary: JSON.stringify({
          casKey,
          checkLifecycleKey: lifecycleKey,
          replayDigest: terminalDigest,
        }),
      },
      status: "completed",
    },
    {
      completed_at: "2026-07-31T01:49:59Z",
      conclusion: "failure",
      id: 91052594278,
      output: {
        summary: JSON.stringify({
          casKey: "1303415307:head:controller-invalid:23",
          replayDigest: "5".repeat(64),
          status: "drift-monitor-invalid",
        }),
      },
      status: "completed",
    },
  ]);

  assert.equal(await publishControllerCheck(harness.input({
    replayDigest: terminalDigest,
    summary: JSON.stringify({ casKey, replayDigest: terminalDigest }),
  })), "idempotent");
  const driftFailure = harness.checks.find((check) => check.id === 91052594278);
  assert.equal(driftFailure.conclusion, "neutral");
  assert.equal(JSON.parse(driftFailure.output.summary).supersededByCheckId, 91036644980);
  assert.equal(harness.posts.length, 0);
});

test("并发 successor replay 只 PATCH 同一 pending ID，不产生平行 POST", async () => {
  const harness = createLifecycleHarness([createLifecyclePending({ id: 202 })]);
  await Promise.all([
    publishControllerCheck(harness.input()),
    publishControllerCheck(harness.input()),
  ]);
  assert.equal(harness.posts.length, 0);
  assert.deepEqual(new Set(harness.updates.map((entry) => entry.checkId)), new Set([202]));
});

test("并发首次 POST 最终只保留一个权威 terminal，其余记录明确 superseded", async () => {
  const harness = createLifecycleHarness();
  const actions = await Promise.all([
    publishControllerCheck(harness.input()),
    publishControllerCheck(harness.input()),
  ]);
  const authoritative = harness.checks.filter((check) => check.conclusion === "success");
  const superseded = harness.checks.filter((check) => check.conclusion === "neutral");

  assert.equal(harness.posts.length, 2);
  assert.equal(authoritative.length, 1);
  assert.equal(superseded.length, 1);
  assert.equal(JSON.parse(superseded[0].output.summary).supersededByCheckId, authoritative[0].id);
  assert.deepEqual(new Set(actions), new Set(["published", "published-superseded"]));
});

test("无法归属的活动 check 先 neutral closure，再结构化拒绝 success", async () => {
  const harness = createLifecycleHarness([{
    completed_at: null,
    conclusion: null,
    id: 205,
    output: { summary: "unstructured legacy pending" },
    status: "in_progress",
  }]);
  await assert.rejects(
    () => publishControllerCheck(harness.input()),
    (error) =>
      error instanceof ControllerCheckPublicationError &&
      error.phase === "lifecycle-conflict",
  );
  assert.equal(harness.checks[0].status, "completed");
  assert.equal(harness.checks[0].conclusion, "neutral");
  assert.equal(
    JSON.parse(harness.checks[0].output.summary).supersededByLifecycleKey,
    lifecycleKey,
  );
  assert.equal(harness.posts.length, 0);
});

test("GET history 失败结构化 fail closed 且不得发布 success", async () => {
  const harness = createLifecycleHarness();
  await assert.rejects(
    () => publishControllerCheck(harness.input({
      loadChecks: async () => {
        throw new Error("history unavailable");
      },
    })),
    (error) =>
      error instanceof ControllerCheckPublicationError &&
      error.phase === "GET-history",
  );
  assert.equal(harness.posts.length, 0);
});

test("PATCH 失败后下一 cycle 从同一 pending ID 确定性恢复", async () => {
  const harness = createLifecycleHarness([createLifecyclePending({ id: 203 })]);
  let failPatch = true;
  const input = harness.input({
    updateCheck: async (checkId, body) => {
      if (failPatch) {
        failPatch = false;
        throw new Error("PATCH unavailable");
      }
      const check = harness.checks.find((candidate) => candidate.id === checkId);
      applyBody(check, body);
      harness.updates.push({ body, checkId });
      return structuredClone(check);
    },
  });
  await assert.rejects(() => publishControllerCheck(input), /PATCH unavailable/u);
  assert.equal(await publishControllerCheck(input), "transitioned");
  assert.equal(harness.posts.length, 0);
  assert.deepEqual(harness.updates.map((entry) => entry.checkId), [203]);
});

test("PATCH readback 失败后下一 cycle 识别已完成终态且不重复写", async () => {
  const harness = createLifecycleHarness([createLifecyclePending({ id: 204 })]);
  let failReadback = true;
  const input = harness.input({
    loadCheck: async (checkId) => {
      if (failReadback) {
        failReadback = false;
        throw new Error("readback unavailable");
      }
      return structuredClone(harness.checks.find((check) => check.id === checkId));
    },
  });
  await assert.rejects(() => publishControllerCheck(input), /readback unavailable/u);
  assert.equal(await publishControllerCheck(input), "idempotent");
  assert.equal(harness.updates.length, 1);
  assert.equal(harness.posts.length, 0);
});

test("PATCH readback 字段不一致时结构化拒绝成功发布", async () => {
  const harness = createLifecycleHarness([createLifecyclePending({ id: 206 })]);
  await assert.rejects(
    () => publishControllerCheck(harness.input({
      loadCheck: async (checkId) => ({
        ...structuredClone(harness.checks.find((check) => check.id === checkId)),
        completed_at: null,
      }),
    })),
    (error) =>
      error instanceof ControllerCheckPublicationError &&
      error.phase === "GET-readback-verify" &&
      error.checkId === 206,
  );
  assert.equal(harness.posts.length, 0);
});

test("POST 失败不伪造 success，下一 cycle 只创建一个可 readback check", async () => {
  const harness = createLifecycleHarness();
  let failPost = true;
  const input = harness.input();
  const originalPost = input.postCheck;
  input.postCheck = async (body) => {
    if (failPost) {
      failPost = false;
      throw new Error("POST unavailable");
    }
    return originalPost(body);
  };
  await assert.rejects(() => publishControllerCheck(input), /POST unavailable/u);
  assert.equal(await publishControllerCheck(input), "published");
  assert.equal(harness.posts.length, 1);
});
