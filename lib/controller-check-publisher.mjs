import { planCheckReplay } from "./check-replay-policy.mjs";

/**
 * 发布或保留 Controller App umbrella check，并集中执行 monitor freshness 与历史读取策略。
 *
 * @param {object} input 发布参数与可注入外部依赖。
 * @returns {Promise<string>} 最终动作：published、transitioned、idempotent 或 idempotent-conflict。
 */
export async function publishControllerCheck({
  allowFailureOnHistoryError = false,
  assertFreshMonitor,
  casKey,
  conclusion: requestedConclusion,
  headOid,
  loadChecks,
  postCheck,
  replayDigest = null,
  status: requestedStatus,
  summary: requestedSummary,
  updateCheck,
}) {
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
