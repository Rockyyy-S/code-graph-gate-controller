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
  if (casKey === null || replayDigest === null) {
    return "publish";
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
    return "publish";
  }
  const hasConflict = matching.some(
    ({ parsed }) => parsed?.replayDigest !== replayDigest,
  );
  const newestCheck = selectNewestCheck(checks);
  if (hasConflict) {
    const conflictAlreadyPublished = matching.some(
      ({ check, parsed }) =>
        check === newestCheck &&
        parsed?.replayConflict === true &&
        parsed?.replayDigest === replayDigest &&
        check.status === "completed" &&
        check.conclusion === "failure",
    );
    return conflictAlreadyPublished ? "idempotent-conflict" : "conflict";
  }
  const newestMatching = matching.find(({ check }) => check === newestCheck);
  if (newestMatching === undefined) {
    return "publish";
  }
  return newestMatching.check.status === status && newestMatching.check.conclusion === conclusion
    ? "idempotent"
    : "conflict";
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
