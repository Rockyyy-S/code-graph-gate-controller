import { classifyCheckReplay } from "./check-replay-policy.mjs";

/**
 * 发布或保留 Controller App umbrella check，并集中执行 monitor freshness 与历史读取策略。
 *
 * @param {object} input 发布参数与可注入外部依赖。
 * @returns {Promise<string>} 最终动作：published、idempotent 或 idempotent-conflict。
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
  const replayAction = classifyCheckReplay({
    casKey,
    checks,
    conclusion,
    replayDigest,
    status,
  });
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
  await postCheck({
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
  });
  return "published";
}
