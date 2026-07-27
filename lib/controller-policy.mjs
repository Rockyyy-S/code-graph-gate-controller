import { sha256CanonicalJson } from "./canonical-json.mjs";
import { evaluateApplicability } from "./applicability.mjs";
import {
  validateRegistry,
  validateTrustedRegistryRecord,
} from "./registry.mjs";

export const DRIFT_MONITOR_REFRESH_AFTER_MS = 6 * 60 * 1000;
const driftMonitorExpiresAfterMs = 15 * 60 * 1000;
const trustedDriftMonitorEvents = new Set(["push", "schedule", "workflow_dispatch"]);
const trustedDriftMonitorActiveStatuses = new Set([
  "in_progress",
  "pending",
  "queued",
  "requested",
  "waiting",
]);

/**
 * 验证 provider API 当前状态、可信 registry 与 child evidence，并形成 umbrella 结论。
 *
 * 该函数不信任 artifact 自报的 repository/run/provenance；调用方必须先完成 provider API
 * artifact 拉取与 GitHub attestation 验证，再把重新读取的 current base/head 传入。
 */
export function evaluateControllerCandidate({
  artifact,
  currentProviderContext,
  registry,
  trustedRecord,
}) {
  validateRegistry(registry);
  validateTrustedRegistryRecord(trustedRecord);
  if (trustedRecord.sequence < 3) {
    return invalid("可信记录尚未绑定 gate 实现摘要");
  }
  if (
    !isClosedObject(artifact, [
      "affectedPaths",
      "evaluationContext",
      "evidence",
      "gateImplementationDigest",
      "gateRegistryDigest",
      "schemaVersion",
    ]) ||
    artifact.schemaVersion !== 1 ||
    !isCanonicalAffectedPaths(artifact.affectedPaths) ||
    !/^[a-f0-9]{64}$/u.test(artifact.gateImplementationDigest) ||
    artifact.gateImplementationDigest !== trustedRecord.gateImplementationDigest
  ) {
    return invalid("GateHarness artifact 形状或 gate 实现摘要未匹配可信根");
  }
  const registryDigest = sha256CanonicalJson(registry);
  if (
    registryDigest !== trustedRecord.gateRegistryDigest ||
    artifact?.gateRegistryDigest !== registryDigest
  ) {
    return invalid("registry digest 未匹配 Controller 可信根");
  }
  const context = artifact?.evaluationContext;
  if (!isValidEvaluationContext(context)) {
    return invalid("GateEvaluationContextV1 无效或 digest 漂移");
  }
  if (
    context.providerRepositoryId !== trustedRecord.providerRepositoryId ||
    context.providerRepositoryId !== currentProviderContext.providerRepositoryId ||
    context.baseOid !== currentProviderContext.baseOid ||
    context.headOid !== currentProviderContext.headOid ||
    context.gateRegistryDigest !== registryDigest
  ) {
    return invalid("provider base/head/repository 或 registry 已变化，旧结论作废");
  }
  if (!Array.isArray(artifact.evidence)) {
    return invalid("child evidence 集合缺失");
  }
  const applicableGateById = new Map();
  for (const entry of registry.gates) {
    if (evaluateApplicability(entry.gateDefinition, artifact.affectedPaths) !== "not-applicable") {
      applicableGateById.set(entry.gateDefinition.gateId, entry);
    }
  }
  const evidenceByGate = new Map();
  for (const evidence of artifact.evidence) {
    const entry = applicableGateById.get(evidence?.gateId);
    if (entry === undefined) {
      return invalid(`child evidence 包含未知或 not-applicable gate '${evidence?.gateId ?? "unknown"}'`);
    }
    const bindingError = validateEvidenceBinding(
      evidence,
      entry.gateDefinition,
      entry.gateDefinitionDigest,
      context,
    );
    if (bindingError !== null) {
      return invalid(`gate ${entry.gateDefinition.gateId} ${bindingError}`);
    }
    const existing = evidenceByGate.get(evidence?.gateId);
    if (existing !== undefined) {
      if (existing.gateEvidenceDigest !== evidence.gateEvidenceDigest) {
        return invalid(`gate ${evidence.gateId} 同 context 出现冲突 digest`);
      }
      continue;
    }
    evidenceByGate.set(evidence?.gateId, evidence);
  }
  const failedGateIds = [];
  const invalidGateIds = [];
  const missingEvidenceGateIds = [];
  for (const entry of registry.gates) {
    const definition = entry.gateDefinition;
    if (
      !definition.blocking ||
      evaluateApplicability(definition, artifact.affectedPaths) === "not-applicable"
    ) {
      continue;
    }
    const evidence = evidenceByGate.get(definition.gateId);
    if (evidence === undefined) {
      missingEvidenceGateIds.push(definition.gateId);
      continue;
    }
    if (evidence.status === "invalid") {
      invalidGateIds.push(definition.gateId);
    } else if (evidence.status === "fail") {
      failedGateIds.push(definition.gateId);
    }
  }
  const conclusion =
    failedGateIds.length === 0 &&
    invalidGateIds.length === 0 &&
    missingEvidenceGateIds.length === 0
      ? "success"
      : "failure";
  return {
    casKey: `${context.providerRepositoryId}:${context.headOid}:${context.evaluationContextDigest}`,
    conclusion,
    evaluationContextDigest: context.evaluationContextDigest,
    failedGateIds,
    gateImplementationDigest: artifact.gateImplementationDigest,
    gateEvidenceDigests: [...evidenceByGate.values()]
      .map(({ gateEvidenceDigest }) => gateEvidenceDigest)
      .sort(),
    invalidGateIds,
    missingEvidenceGateIds,
    status: conclusion === "success" ? "accepted" : "rejected",
    trustedSequence: trustedRecord.sequence,
  };
}

/** affected paths 必须是唯一、升序且安全的仓库内 POSIX 相对路径。 */
function isCanonicalAffectedPaths(value) {
  if (!Array.isArray(value)) {
    return false;
  }
  return value.every(
    (relativePath, index) =>
      typeof relativePath === "string" &&
      relativePath.length > 0 &&
      !relativePath.includes("\0") &&
      !relativePath.includes("\\") &&
      !relativePath.startsWith("/") &&
      relativePath.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..") &&
      (index === 0 || value[index - 1] < relativePath),
  );
}

/** 先按 workflow run ID 选择最新运行，再在同一 run 内选择最新 attempt。 */
export function selectLatestWorkflowRun(runs, headOid, pullNumber) {
  return [...runs]
    .filter(
      (run) =>
        run?.head_sha === headOid &&
        Number.isSafeInteger(pullNumber) &&
        pullNumber > 0 &&
        Array.isArray(run?.pull_requests) &&
        run.pull_requests.some((pull) => pull?.number === pullNumber),
    )
    .sort((left, right) => right.id - left.id || right.run_attempt - left.run_attempt)[0];
}

/**
 * 分类绑定当前 Controller revision 的 monitor 运行，并形成刷新决策。
 *
 * active run 只负责抑制重复 dispatch，不能替代最近 completed success；最新 completed
 * 失败、时间非法或满十五分钟时，旧 success 不得作为回退证据。
 */
export function evaluateDriftMonitorLease(runs, options) {
  const now = options?.now ?? Date.now();
  const allowedClockSkewMs = options?.allowedClockSkewMs ?? 30_000;
  const trustedRuns = [...runs].filter((run) => isTrustedDriftMonitorIdentity(run, options));
  const latestCompletedRun = trustedRuns
    .filter((run) => run?.status === "completed")
    .sort(compareDriftMonitorRuns)[0] ?? null;
  const activeRun = trustedRuns
    .filter((run) => isCurrentDriftMonitorRun(run, now, allowedClockSkewMs))
    .sort(compareDriftMonitorRuns)[0] ?? null;
  const completedAt = Date.parse(latestCompletedRun?.updated_at);
  const ageMs = now - completedAt;
  const freshRun =
    latestCompletedRun?.conclusion === "success" &&
    Number.isFinite(completedAt) &&
    ageMs >= -allowedClockSkewMs &&
    ageMs < driftMonitorExpiresAfterMs
      ? latestCompletedRun
      : null;
  return {
    activeRun,
    freshRun,
    latestCompletedRun,
    shouldRefresh:
      activeRun === null &&
      !isFailedDispatchCoolingDown(
        latestCompletedRun,
        freshRun,
        ageMs,
        allowedClockSkewMs,
      ) &&
      (freshRun === null || ageMs >= DRIFT_MONITOR_REFRESH_AFTER_MS),
  };
}

/** 选择默认分支可信提交上的最近成功 monitor run。 */
export function selectFreshDriftMonitorRun(runs, options) {
  const { freshRun } = evaluateDriftMonitorLease(runs, options);
  if (freshRun === null) {
    throw new Error("独立 drift monitor 缺失、失败、来自未来或已过期，Controller fail closed。\n");
  }
  return freshRun;
}

/** 验证 monitor run 的仓库、入口、分支、revision 与触发来源均属于可信边界。 */
function isTrustedDriftMonitorIdentity(run, options) {
  return (
    trustedDriftMonitorEvents.has(run?.event) &&
    run?.head_branch === options?.defaultBranch &&
    run?.head_sha === options?.trustedHeadSha &&
    run?.path === options?.workflowPath &&
    run?.repository?.full_name === options?.repository
  );
}

/** active run 只有状态与时间均合理时才能抑制恢复 dispatch。 */
function isCurrentDriftMonitorRun(run, now, allowedClockSkewMs) {
  const updatedAt = Date.parse(run?.updated_at);
  const ageMs = now - updatedAt;
  return (
    trustedDriftMonitorActiveStatuses.has(run?.status) &&
    run?.conclusion === null &&
    Number.isFinite(updatedAt) &&
    ageMs >= -allowedClockSkewMs &&
    ageMs < driftMonitorExpiresAfterMs
  );
}

/** 失败的自刷新运行按同一六分钟窗口退避，避免快速失败形成 Actions 重试环。 */
function isFailedDispatchCoolingDown(run, freshRun, ageMs, allowedClockSkewMs) {
  return (
    freshRun === null &&
    run?.event === "workflow_dispatch" &&
    Number.isFinite(ageMs) &&
    ageMs >= -allowedClockSkewMs &&
    ageMs < DRIFT_MONITOR_REFRESH_AFTER_MS
  );
}

/** 沿用 provider 完成时间选择最近 monitor，非法时间由后续 freshness 校验 fail closed。 */
function compareDriftMonitorRuns(left, right) {
  const leftUpdatedAt = Date.parse(left?.updated_at);
  const rightUpdatedAt = Date.parse(right?.updated_at);
  if (!Number.isFinite(leftUpdatedAt)) {
    return Number.isFinite(rightUpdatedAt) ? -1 : compareDriftMonitorRunIdentity(left, right);
  }
  if (!Number.isFinite(rightUpdatedAt)) {
    return 1;
  }
  return rightUpdatedAt - leftUpdatedAt || compareDriftMonitorRunIdentity(left, right);
}

/** 同秒完成时按 run ID、attempt 选择 provider 创建的较新运行。 */
function compareDriftMonitorRunIdentity(left, right) {
  const leftId = Number.isSafeInteger(left?.id) ? left.id : -1;
  const rightId = Number.isSafeInteger(right?.id) ? right.id : -1;
  const leftAttempt = Number.isSafeInteger(left?.run_attempt) ? left.run_attempt : -1;
  const rightAttempt = Number.isSafeInteger(right?.run_attempt) ? right.run_attempt : -1;
  return rightId - leftId || rightAttempt - leftAttempt;
}

/** 验证 GateEvaluationContextV1 自身摘要和封闭字段。 */
function isValidEvaluationContext(value) {
  if (
    !isClosedObject(value, [
      "baseOid",
      "comparisonBaseOid",
      "evaluationContextDigest",
      "gateRegistryDigest",
      "headOid",
      "objectFormat",
      "providerRepositoryId",
      "schemaVersion",
    ]) ||
    value.schemaVersion !== 1 ||
    !["sha1", "sha256"].includes(value.objectFormat)
  ) {
    return false;
  }
  const oidLength = value.objectFormat === "sha1" ? 40 : 64;
  if (
    ![value.baseOid, value.comparisonBaseOid, value.headOid].every(
      (oid) => typeof oid === "string" && oid.length === oidLength && /^[a-f0-9]+$/.test(oid),
    ) ||
    !/^[1-9][0-9]*$/.test(value.providerRepositoryId) ||
    !/^[a-f0-9]{64}$/.test(value.gateRegistryDigest)
  ) {
    return false;
  }
  const { evaluationContextDigest, ...digestInput } = value;
  return evaluationContextDigest === sha256CanonicalJson(digestInput);
}

/** 验证 GateEvidenceV1 与 definition/context/head 的精确绑定。 */
function validateEvidenceBinding(evidence, definition, gateDefinitionDigest, context) {
  if (
    !isClosedObject(evidence, [
      "evaluationContextDigest",
      "evidenceProducerId",
      "gateDefinitionDigest",
      "gateEvidenceDigest",
      "gateId",
      "headOid",
      "outputDigest",
      "schemaVersion",
      "status",
    ]) ||
    evidence.schemaVersion !== 1 ||
    !["pass", "fail", "invalid"].includes(evidence.status) ||
    !/^[a-f0-9]{64}$/.test(evidence.outputDigest)
  ) {
    return "evidence shape invalid";
  }
  if (
    evidence.gateId !== definition.gateId ||
    evidence.gateDefinitionDigest !== gateDefinitionDigest ||
    evidence.evidenceProducerId !== definition.evidenceProducerId ||
    evidence.evaluationContextDigest !== context.evaluationContextDigest ||
    evidence.headOid !== context.headOid
  ) {
    return "evidence binding invalid";
  }
  const { gateEvidenceDigest, ...digestInput } = evidence;
  return gateEvidenceDigest === sha256CanonicalJson(digestInput)
    ? null
    : "gateEvidenceDigest invalid";
}

/** 创建不会被解释为 pass 的稳定 invalid 结论。 */
function invalid(reason) {
  return {
    conclusion: "failure",
    reason,
    status: "invalid",
  };
}

/** 验证普通对象精确包含指定字段。 */
function isClosedObject(value, expectedKeys) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
