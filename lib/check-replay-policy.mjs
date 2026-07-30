/**
 * 比较同一 umbrella CAS 的历史 App check，区分幂等重放与冲突证据。
 *
 * 历史摘要只信任 Controller App 自己发布的封闭 JSON；解析失败也按冲突处理。
 */
export function classifyCheckReplay({
  casKey,
  checks,
  conclusion,
  replayDigest,
  status,
}) {
  return planCheckReplay({
    casKey,
    checks,
    conclusion,
    replayDigest,
    status,
  }).action;
}

/**
 * 生成 check replay 动作；terminal failure 只允许把同一 CAS 的 pending 原位收敛。
 *
 * @returns {{action:string;check:object|null}} transition 时携带唯一更新目标。
 */
export function planCheckReplay({
  casKey,
  checks,
  conclusion,
  replayDigest,
  status,
}) {
  if (casKey === null || replayDigest === null) {
    return { action: "publish", check: null };
  }
  const matching = [];
  for (const check of checks) {
    const parsed = parseSummary(check?.output?.summary);
    const historicalCasKey = parsed?.casKey ?? parsed?.result?.casKey;
    if (historicalCasKey === casKey) {
      matching.push({ check, parsed });
    }
  }
  if (matching.length === 0) {
    return { action: "publish", check: null };
  }
  const newestCheck = selectNewestCheck(checks);
  const exact = matching.filter(({ parsed }) => parsed?.replayDigest === replayDigest);
  const completedDigestConflict = matching.some(
    ({ check, parsed }) =>
      check.status === "completed" && parsed?.replayDigest !== replayDigest,
  );
  if (exact.length > 0 && !completedDigestConflict) {
    const newestExact = selectNewestCheck(exact.map(({ check }) => check));
    if (newestExact.status === status && newestExact.conclusion === conclusion) {
      return conclusion === "success" && newestExact !== newestCheck
        ? { action: "publish", check: null }
        : { action: "idempotent", check: newestExact };
    }
  }
  if (status === "completed" && conclusion === "failure" && !completedDigestConflict) {
    const pending = matching
      .filter(
        ({ check, parsed }) =>
          check.status === "in_progress" &&
          check.conclusion === null &&
          parsed?.status === "pending",
      )
      .map(({ check }) => check);
    if (pending.length > 0 && pending.length === matching.length) {
      return { action: "transition", check: selectNewestCheck(pending) };
    }
  }
  const hasConflict = matching.some(
    ({ parsed }) => parsed?.replayDigest !== replayDigest,
  );
  if (hasConflict) {
    const conflictAlreadyPublished = matching.some(
      ({ check, parsed }) =>
        check === newestCheck &&
        parsed?.replayConflict === true &&
        parsed?.replayDigest === replayDigest &&
        check.status === "completed" &&
        check.conclusion === "failure",
    );
    return {
      action: conflictAlreadyPublished ? "idempotent-conflict" : "conflict",
      check: null,
    };
  }
  const newestMatching = matching.find(({ check }) => check === newestCheck);
  if (newestMatching === undefined) {
    return { action: "publish", check: null };
  }
  return newestMatching.check.status === status && newestMatching.check.conclusion === conclusion
    ? { action: "idempotent", check: newestMatching.check }
    : { action: "conflict", check: null };
}

/** GitHub check-runs 通常按新到旧返回；有 ID 时仍显式选择最大 ID。 */
function selectNewestCheck(checks) {
  return checks.reduce((newest, check) => {
    const newestId = Number(newest?.id);
    const checkId = Number(check?.id);
    return Number.isSafeInteger(checkId) &&
      (!Number.isSafeInteger(newestId) || checkId > newestId)
      ? check
      : newest;
  }, checks[0]);
}

/** 解析 Controller check summary；非 JSON 历史记录不能参与幂等判断。 */
function parseSummary(summary) {
  if (typeof summary !== "string") {
    return null;
  }
  try {
    const value = JSON.parse(summary);
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? value
      : null;
  } catch {
    return null;
  }
}
