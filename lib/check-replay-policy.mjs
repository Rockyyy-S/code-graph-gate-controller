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
  if (hasConflict) {
    const conflictAlreadyPublished = matching.some(
      ({ check, parsed }) =>
        parsed?.replayConflict === true &&
        parsed?.replayDigest === replayDigest &&
        check.status === "completed" &&
        check.conclusion === "failure",
    );
    return conflictAlreadyPublished ? "idempotent-conflict" : "conflict";
  }
  return matching.some(
    ({ check }) => check.status === status && check.conclusion === conclusion,
  )
    ? "idempotent"
    : "conflict";
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
