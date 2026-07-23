import { sha256CanonicalJson } from "./canonical-json.mjs";
import {
  validateRegistry,
  validateTrustedRegistryRecord,
} from "./registry.mjs";

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
  const evidenceByGate = new Map();
  for (const evidence of artifact.evidence) {
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
    if (!definition.blocking) {
      continue;
    }
    const evidence = evidenceByGate.get(definition.gateId);
    if (evidence === undefined) {
      missingEvidenceGateIds.push(definition.gateId);
      continue;
    }
    const bindingError = validateEvidenceBinding(
      evidence,
      definition,
      entry.gateDefinitionDigest,
      context,
    );
    if (bindingError !== null || evidence.status === "invalid") {
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
    gateEvidenceDigests: [...evidenceByGate.values()]
      .map(({ gateEvidenceDigest }) => gateEvidenceDigest)
      .sort(),
    invalidGateIds,
    missingEvidenceGateIds,
    status: conclusion === "success" ? "accepted" : "rejected",
  };
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
