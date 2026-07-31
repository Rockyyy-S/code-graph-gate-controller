import {
  parseControllerCheckSummary,
  planCheckLifecycle,
  planCheckReplay,
} from "./check-replay-policy.mjs";

/** 带阶段与 check ID 的 provider 边界错误，供 guardian 下一 cycle 确定性恢复。 */
export class ControllerCheckPublicationError extends Error {
  constructor(phase, cause, checkId = null) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    super(`Controller check ${phase} 失败${checkId === null ? "" : `（check ${checkId}）`}：${reason}`, {
      cause,
    });
    this.checkId = checkId;
    this.code = "controller-check-publication-failed";
    this.name = "ControllerCheckPublicationError";
    this.phase = phase;
  }
}

/**
 * 发布或保留 Controller App umbrella check，并集中执行 monitor freshness 与历史读取策略。
 *
 * @param {object} input 发布参数与可注入外部依赖。
 * @returns {Promise<string>} 最终动作：published、transitioned、idempotent 或 idempotent-conflict。
 */
export async function publishControllerCheck({
  allowFailureOnHistoryError = false,
  assertFreshMonitor,
  assertFreshMonitorReadOnly = assertFreshMonitor,
  casKey,
  checkLifecycleKey = null,
  conclusion: requestedConclusion,
  headOid,
  loadCheck,
  loadChecks,
  postCheck,
  pullNumber = null,
  replayDigest = null,
  status: requestedStatus,
  summary: requestedSummary,
  updateCheck,
}) {
  if (checkLifecycleKey !== null) {
    return publishLifecycleControllerCheck({
      allowFailureOnHistoryError,
      assertFreshMonitor,
      assertFreshMonitorReadOnly,
      casKey,
      checkLifecycleKey,
      headOid,
      loadCheck,
      loadChecks,
      postCheck,
      pullNumber,
      replayDigest,
      requestedConclusion,
      requestedStatus,
      requestedSummary,
      updateCheck,
    });
  }
  let checks;
  try {
    checks = await loadChecks();
  } catch (error) {
    if (
      !allowFailureOnHistoryError ||
      requestedStatus !== "completed" ||
      requestedConclusion !== "failure"
    ) {
      throw error;
    }
    // drift 撤销优先追加 failure；历史不可读不能成为保留旧 success 的理由。
    checks = [];
  }

  let status = requestedStatus;
  let conclusion = requestedConclusion;
  let summary = requestedSummary;
  const replayPlan = planCheckReplay({
    casKey,
    checks,
    conclusion,
    replayDigest,
    status,
  });
  const replayAction = replayPlan.action;
  if (replayAction === "idempotent" && conclusion === "success") {
    await assertFreshMonitor();
  }
  if (["idempotent", "idempotent-conflict"].includes(replayAction)) {
    return replayAction;
  }
  if (replayAction === "conflict") {
    status = "completed";
    conclusion = "failure";
    summary = JSON.stringify({
      casKey,
      reason: "同一 umbrella CAS 出现不同 artifact/evidence digest，Controller fail closed。",
      replayConflict: true,
      replayDigest,
    });
  }
  if (conclusion === "success") {
    await assertFreshMonitor();
  }
  const body = {
    ...(conclusion === null ? {} : { conclusion }),
    head_sha: headOid,
    name: "architecture-required",
    output: {
      summary: summary.slice(0, 60_000),
      title:
        conclusion === "success"
          ? "Architecture gates passed"
          : status === "in_progress"
            ? "Architecture gates pending"
            : "Architecture gates failed closed",
    },
    status,
  };
  if (replayAction === "transition") {
    const checkId = Number(replayPlan.check?.id);
    if (!Number.isSafeInteger(checkId) || typeof updateCheck !== "function") {
      throw new Error("pending→terminal check 缺少可验证的更新目标或 Checks PATCH 边界。");
    }
    const { head_sha: _headSha, ...updateBody } = body;
    await updateCheck(checkId, updateBody);
    return "transitioned";
  }
  await postCheck(body);
  return "published";
}

/** 使用独立 lifecycle key 收敛旧 pending、进程重启和 lease successor 的同一物理 check。 */
async function publishLifecycleControllerCheck({
  allowFailureOnHistoryError,
  assertFreshMonitor,
  assertFreshMonitorReadOnly,
  casKey,
  checkLifecycleKey,
  headOid,
  loadCheck,
  loadChecks,
  postCheck,
  pullNumber,
  replayDigest,
  requestedConclusion,
  requestedStatus,
  requestedSummary,
  updateCheck,
}) {
  if (!Number.isSafeInteger(pullNumber)) {
    throw new TypeError("check lifecycle 缺少 PR number。");
  }
  if (typeof loadCheck !== "function" || typeof updateCheck !== "function") {
    throw new TypeError("check lifecycle 缺少 Checks GET/PATCH 边界。");
  }
  let status = requestedStatus;
  let conclusion = requestedConclusion;
  let summary = withLifecycleSummary(requestedSummary, {
    casKey,
    checkLifecycleKey,
    replayDigest,
  });
  let checks = await loadHistory({
    allowFailureOnHistoryError,
    conclusion,
    loadChecks,
    status,
  });

  // 发布前二次读取把并发首发窗口缩到 POST 本身；POST 后仍会再次收敛重复记录。
  for (let pass = 0; pass < 2; pass += 1) {
    const plan = planCheckLifecycle({
      casKey,
      checkLifecycleKey,
      checks,
      conclusion,
      headOid,
      pullNumber,
      replayDigest,
      status,
    });
    if (plan.conflictingChecks.length > 0) {
      for (const check of plan.conflictingChecks) {
        await supersedeCheck({
          check,
          checkLifecycleKey,
          loadCheck,
          replayDigest,
          supersededByCheckId: plan.check?.id ?? null,
          updateCheck,
        });
      }
      throw new ControllerCheckPublicationError(
        "lifecycle-conflict",
        new Error("当前 PR/head 存在无法安全归属的 Controller App in_progress check，已 neutral 收敛。"),
      );
    }
    for (const check of plan.supersededChecks) {
      await supersedeCheck({
        check,
        checkLifecycleKey,
        loadCheck,
        replayDigest,
        supersededByCheckId: plan.check?.id ?? null,
        updateCheck,
      });
    }
    if (plan.action === "conflict-transition") {
      status = "completed";
      conclusion = "failure";
      summary = withLifecycleSummary(JSON.stringify({
        reason: "同一 result CAS 出现不同 replay digest，Controller fail closed。",
        replayConflict: true,
        status: "result-replay-conflict",
      }), { casKey, checkLifecycleKey, replayDigest });
    }
    if (["transition", "conflict-transition"].includes(plan.action)) {
      if (conclusion === "success") {
        await assertFreshMonitor();
      }
      const body = createCheckBody({ conclusion, headOid, status, summary });
      const { head_sha: _headSha, ...updateBody } = body;
      const checkId = requireCheckId(plan.check, "PATCH");
      await callProvider("PATCH", () => updateCheck(checkId, updateBody), checkId);
      await readbackCheck({
        checkId,
        checkLifecycleKey,
        conclusion,
        loadCheck,
        replayDigest,
        status,
      });
      return "transitioned";
    }
    if (plan.action === "idempotent") {
      if (conclusion === "success") {
        // 精确终态重放只允许只读 freshness/readback，不能重复 dispatch monitor 或写 check。
        await assertFreshMonitorReadOnly();
      }
      const checkId = requireCheckId(plan.check, "readback");
      await readbackCheck({
        checkId,
        checkLifecycleKey,
        conclusion,
        loadCheck,
        replayDigest,
        status,
      });
      return "idempotent";
    }
    if (plan.action === "idempotent-conflict") {
      const checkId = requireCheckId(plan.check, "readback-conflict");
      await readbackCheck({
        checkId,
        checkLifecycleKey,
        conclusion: "failure",
        loadCheck,
        replayDigest,
        status: "completed",
      });
      return "idempotent-conflict";
    }
    if (pass === 0) {
      checks = await loadHistory({
        allowFailureOnHistoryError,
        conclusion,
        loadChecks,
        status,
      });
    }
  }

  if (conclusion === "success") {
    await assertFreshMonitor();
  }
  const posted = await callProvider(
    "POST",
    () => postCheck(createCheckBody({ conclusion, headOid, status, summary })),
  );
  const postedId = requireCheckId(posted, "POST-response");
  await readbackCheck({
    checkId: postedId,
    checkLifecycleKey,
    conclusion,
    loadCheck,
    replayDigest,
    status,
  });

  const afterPost = await loadHistory({
    allowFailureOnHistoryError: false,
    conclusion,
    loadChecks,
    status,
  });
  const converged = planCheckLifecycle({
    casKey,
    checkLifecycleKey,
    checks: afterPost,
    conclusion,
    headOid,
    pullNumber,
    replayDigest,
    status,
  });
  for (const check of converged.supersededChecks) {
    await supersedeCheck({
      check,
      checkLifecycleKey,
      loadCheck,
      replayDigest,
      supersededByCheckId: converged.check?.id ?? postedId,
      updateCheck,
    });
  }
  return converged.check?.id === postedId ? "published" : "published-superseded";
}

/** GET history 失败只允许既有 drift failure 兼容路径继续发布 failure。 */
async function loadHistory({
  allowFailureOnHistoryError,
  conclusion,
  loadChecks,
  status,
}) {
  try {
    return await loadChecks();
  } catch (error) {
    if (
      allowFailureOnHistoryError &&
      status === "completed" &&
      conclusion === "failure"
    ) {
      return [];
    }
    throw new ControllerCheckPublicationError("GET-history", error);
  }
}

/** summary 必须封闭携带 lifecycle、result CAS 与 replay digest，便于跨重启恢复。 */
function withLifecycleSummary(summary, { casKey, checkLifecycleKey, replayDigest }) {
  const parsed = parseControllerCheckSummary(summary);
  return JSON.stringify({
    ...(parsed ?? { detail: summary }),
    ...(casKey === null ? {} : { casKey }),
    checkLifecycleKey,
    replayDigest,
  });
}

/** 生成 POST/PATCH 共用 body，PATCH 调用方移除不可更新的 head_sha。 */
function createCheckBody({ conclusion, headOid, status, summary }) {
  return {
    ...(conclusion === null ? {} : { conclusion }),
    head_sha: headOid,
    name: "architecture-required",
    output: {
      summary: summary.slice(0, 60_000),
      title:
        conclusion === "success"
          ? "Architecture gates passed"
          : status === "in_progress"
            ? "Architecture gates pending"
            : "Architecture gates failed closed",
    },
    status,
  };
}

/** 旧活动 check 无法保留时必须 terminal neutral，并写入结构化 superseded-by 关系。 */
async function supersedeCheck({
  check,
  checkLifecycleKey,
  loadCheck,
  replayDigest,
  supersededByCheckId,
  updateCheck,
}) {
  const checkId = requireCheckId(check, "supersede");
  const previous = parseControllerCheckSummary(check?.output?.summary);
  const supersededReplayDigest = previous?.replayDigest ?? replayDigest;
  const summary = JSON.stringify({
    ...(previous ?? {}),
    checkLifecycleKey,
    reason: "旧活动 check 已由统一 lifecycle reconciliation 终结。",
    replayDigest: supersededReplayDigest,
    status: "superseded",
    ...(supersededByCheckId !== null && Number.isSafeInteger(Number(supersededByCheckId))
      ? { supersededByCheckId: Number(supersededByCheckId) }
      : { supersededByLifecycleKey: checkLifecycleKey }),
  });
  await callProvider("PATCH-supersede", () => updateCheck(checkId, {
    conclusion: "neutral",
    output: {
      summary,
      title: "Architecture gate lifecycle superseded",
    },
    status: "completed",
  }), checkId);
  await readbackCheck({
    checkId,
    checkLifecycleKey,
    conclusion: "neutral",
    loadCheck,
    replayDigest: supersededReplayDigest,
    status: "completed",
  });
}

/** PATCH/POST 后按 ID 只读确认终态字段与结构化身份，禁止仅信任写响应。 */
async function readbackCheck({
  checkId,
  checkLifecycleKey,
  conclusion,
  loadCheck,
  replayDigest,
  status,
}) {
  const check = await callProvider("GET-readback", () => loadCheck(checkId), checkId);
  const parsed = parseControllerCheckSummary(check?.output?.summary);
  const completedAtValid = status !== "completed" ||
    (typeof check?.completed_at === "string" && check.completed_at.length > 0);
  if (
    Number(check?.id) !== checkId ||
    check?.status !== status ||
    check?.conclusion !== conclusion ||
    !completedAtValid ||
    parsed?.checkLifecycleKey !== checkLifecycleKey ||
    parsed?.replayDigest !== replayDigest
  ) {
    throw new ControllerCheckPublicationError(
      "GET-readback-verify",
      new Error("provider readback 与预期 status/conclusion/completed_at/lifecycle/replayDigest 不一致。"),
      checkId,
    );
  }
  return check;
}

/** 将 provider 边界错误统一包装，保留原 cause 供日志与下一 cycle 恢复诊断。 */
async function callProvider(phase, operation, checkId = null) {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ControllerCheckPublicationError) {
      throw error;
    }
    throw new ControllerCheckPublicationError(phase, error, checkId);
  }
}

function requireCheckId(check, phase) {
  const checkId = Number(check?.id);
  if (!Number.isSafeInteger(checkId)) {
    throw new ControllerCheckPublicationError(phase, new Error("provider 未返回合法 check ID。"));
  }
  return checkId;
}
