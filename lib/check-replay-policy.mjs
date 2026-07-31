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
 * 按独立 lifecycle identity 规划唯一 umbrella check；result CAS 只判断同一结果的重放冲突，
 * 不能再承担物理 check 身份。旧摘要通过 PR/head 结构字段恢复，支持进程重启与 lease 继任者。
 */
export function planCheckLifecycle({
  casKey,
  checkLifecycleKey,
  checks,
  conclusion,
  headOid,
  pullNumber,
  replayDigest,
  status,
}) {
  if (typeof checkLifecycleKey !== "string" || checkLifecycleKey.length === 0) {
    throw new TypeError("check lifecycle key 缺失。");
  }
  const records = checks.map((check) => ({
    check,
    parsed: parseControllerCheckSummary(check?.output?.summary),
  }));
  const matching = records.filter(({ parsed }) =>
    summaryMatchesLifecycle({
      checkLifecycleKey,
      headOid,
      parsed,
      pullNumber,
    }));
  const eligible = matching.filter(({ parsed }) => parsed?.status !== "superseded");
  const conflictingChecks = records
    .filter(({ check, parsed }) =>
      check?.status === "in_progress" &&
      !summaryMatchesLifecycle({
        checkLifecycleKey,
        headOid,
        parsed,
        pullNumber,
      }))
    .map(({ check }) => check);
  const exact = eligible.filter(({ check, parsed }) =>
    check?.status === status &&
    check?.conclusion === conclusion &&
    parsed?.replayDigest === replayDigest);
  const active = eligible.filter(({ check }) => check?.status === "in_progress");
  // 相同终态并发 POST 时保留最早 ID；pending→terminal 时则优先保留最早活动 check。
  const authoritativeRecord = exact.length > 0
    ? selectOldestRecord(exact)
    : active.length > 0
      ? selectOldestRecord(active)
      : selectNewestRecord(eligible);
  const authoritativeCheck = authoritativeRecord?.check ?? null;
  const supersededChecks = eligible
    .filter(({ check }) => check !== authoritativeCheck)
    .map(({ check }) => check);

  if (authoritativeRecord === undefined) {
    return {
      action: "publish",
      check: null,
      conflictingChecks,
      supersededChecks,
    };
  }
  const historicalCasKey = readHistoricalCasKey(authoritativeRecord.parsed);
  const repeatedResultConflict =
    authoritativeCheck.status === "completed" &&
    authoritativeCheck.conclusion === "failure" &&
    authoritativeRecord.parsed?.replayConflict === true &&
    historicalCasKey === casKey &&
    authoritativeRecord.parsed?.replayDigest === replayDigest;
  if (repeatedResultConflict) {
    return {
      action: "idempotent-conflict",
      check: authoritativeCheck,
      conflictingChecks,
      supersededChecks,
    };
  }
  const exactLifecycleReplay =
    authoritativeRecord.parsed?.checkLifecycleKey === checkLifecycleKey &&
    authoritativeRecord.parsed?.replayDigest === replayDigest &&
    authoritativeCheck.status === status &&
    authoritativeCheck.conclusion === conclusion;
  if (exactLifecycleReplay) {
    return {
      action: "idempotent",
      check: authoritativeCheck,
      conflictingChecks,
      supersededChecks,
    };
  }
  const completedResultConflict =
    authoritativeCheck.status === "completed" &&
    casKey !== null &&
    historicalCasKey === casKey &&
    authoritativeRecord.parsed?.replayDigest !== replayDigest;
  return {
    action: completedResultConflict ? "conflict-transition" : "transition",
    check: authoritativeCheck,
    conflictingChecks,
    supersededChecks,
  };
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

/** 选择最大 check ID；无合法 ID 时保持 provider 顺序中的最后记录。 */
function selectNewestRecord(records) {
  return records.reduce((newest, record) => {
    const newestId = Number(newest?.check?.id);
    const checkId = Number(record?.check?.id);
    return Number.isSafeInteger(checkId) &&
      (!Number.isSafeInteger(newestId) || checkId > newestId)
      ? record
      : newest;
  }, records[0]);
}

/** 并发重复创建时稳定保留最早 check ID，避免继任 cycle 在两个终态之间振荡。 */
function selectOldestRecord(records) {
  return records.reduce((oldest, record) => {
    const oldestId = Number(oldest?.check?.id);
    const checkId = Number(record?.check?.id);
    return Number.isSafeInteger(checkId) &&
      (!Number.isSafeInteger(oldestId) || checkId < oldestId)
      ? record
      : oldest;
  }, records[0]);
}

/** 兼容读取旧 success 的 result.casKey 与旧 pending/terminal 的根级 casKey。 */
function readHistoricalCasKey(parsed) {
  return parsed?.casKey ?? parsed?.result?.casKey ?? null;
}

/**
 * 精确 key 优先；旧 Controller 摘要只允许用结构化 PR/head 字段或旧 CAS 归属当前 lifecycle。
 * loadChecks 已限定同一 head/name/App，因此无法结构化归属的活动记录由发布器 fail closed。
 */
function summaryMatchesLifecycle({ checkLifecycleKey, headOid, parsed, pullNumber }) {
  if (parsed?.checkLifecycleKey === checkLifecycleKey) {
    return true;
  }
  if (typeof parsed !== "object" || parsed === null) {
    return false;
  }
  const historicalCasKey = readHistoricalCasKey(parsed);
  if (
    typeof historicalCasKey === "string" &&
    (historicalCasKey.includes(`:${headOid}:pending:${pullNumber}:`) ||
      historicalCasKey.includes(`:${headOid}:terminal:${pullNumber}:`))
  ) {
    return true;
  }
  const evidence = parsed.providerEvidenceRecord;
  return (
    (parsed.headOid === headOid && parsed.pullNumber === pullNumber) ||
    (evidence?.headOid === headOid &&
      typeof evidence?.workflowRef === "string" &&
      evidence.workflowRef.includes(`/pull/${pullNumber}/merge`))
  );
}

/** 解析 Controller check summary；非 JSON 历史记录不能参与幂等判断。 */
export function parseControllerCheckSummary(summary) {
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

const parseSummary = parseControllerCheckSummary;
