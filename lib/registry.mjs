import { readFile } from "node:fs/promises";
import { sha256CanonicalJson } from "./canonical-json.mjs";

const ownerValues = new Set([
  "architecture",
  "architecture-po",
  "dev-enablement",
  "qa",
  "security",
]);
const stableIdPattern = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const digestPattern = /^[a-f0-9]{64}$/;
const producerPattern =
  /^gha-oidc:\/\/([1-9][0-9]*)\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/\.github\/workflows\/([A-Za-z0-9_.-]+\.ya?ml)@([a-f0-9]{40})#([a-z][a-z0-9]*(?:-[a-z0-9]+)*)$/;

/** sequence 1/2 尚未绑定实现摘要时使用的唯一迁移 sentinel。 */
export const UNBOUND_GATE_IMPLEMENTATION_DIGEST_V1 =
  "c68f9bf2ac47a17453229323e6dd52928150c3ef2b291d2f8b12a832851e385f";

/** 从 JSON-compatible YAML 文件加载并严格验证 GateRegistryV1。 */
export async function loadGateRegistry(registryPath) {
  const source = await readFile(registryPath, "utf8");
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error("Gate Registry 必须使用 JSON-compatible YAML，以避免加载候选解析器代码。");
  }
  validateRegistry(value);
  return {
    digest: sha256CanonicalJson(value),
    registry: value,
  };
}

/** 验证 registry 根形状、排序、唯一性及每项 definition digest。 */
export function validateRegistry(value) {
  assertClosedObject(value, ["gates", "schemaVersion"], "GateRegistryV1");
  if (value.schemaVersion !== 1 || !Array.isArray(value.gates) || value.gates.length === 0) {
    throw new Error("GateRegistryV1 的 schemaVersion/gates 无效。");
  }
  let previousGateId = "";
  const checkIds = new Set();
  for (const entry of value.gates) {
    assertClosedObject(entry, ["gateDefinition", "gateDefinitionDigest"], "GateRegistryEntryV1");
    validateDefinition(entry.gateDefinition);
    if (!digestPattern.test(entry.gateDefinitionDigest)) {
      throw new Error(`gate ${entry.gateDefinition.gateId} 的 definition digest 格式无效。`);
    }
    const expectedDigest = sha256CanonicalJson(entry.gateDefinition);
    if (entry.gateDefinitionDigest !== expectedDigest) {
      throw new Error(`gate ${entry.gateDefinition.gateId} 的 definition digest 漂移。`);
    }
    if (entry.gateDefinition.gateId <= previousGateId) {
      throw new Error("Gate Registry 必须按 gateId 严格升序且 ID 唯一。");
    }
    if (checkIds.has(entry.gateDefinition.checkId)) {
      throw new Error(`Gate Registry checkId '${entry.gateDefinition.checkId}' 重复。`);
    }
    checkIds.add(entry.gateDefinition.checkId);
    previousGateId = entry.gateDefinition.gateId;
  }
}

/** 验证受控部署持有的单调可信 registry 记录。 */
export function validateTrustedRegistryRecord(value) {
  const bindsGateImplementation = (value?.sequence ?? 0) >= 3;
  assertClosedObject(
    value,
    [
      "approvalEvidenceDigest",
      "effectiveAt",
      ...(bindsGateImplementation ? ["gateImplementationDigest"] : []),
      "gateRegistryDigest",
      "providerRepositoryId",
      "schemaVersion",
      "sequence",
      "sourceCommit",
    ],
    "TrustedGateRegistryRecordV1",
  );
  if (
    value.schemaVersion !== 1 ||
    !/^[1-9][0-9]*$/.test(value.providerRepositoryId) ||
    !Number.isSafeInteger(value.sequence) ||
    value.sequence < 1 ||
    (bindsGateImplementation && !digestPattern.test(value.gateImplementationDigest)) ||
    !digestPattern.test(value.gateRegistryDigest) ||
    !/^[a-f0-9]{40}$/.test(value.sourceCommit) ||
    !digestPattern.test(value.approvalEvidenceDigest) ||
    !Number.isFinite(Date.parse(value.effectiveAt))
  ) {
    throw new Error("TrustedGateRegistryRecordV1 字段无效。");
  }
}

/** 验证外部 owner 批准证据与当前单调可信记录、producer SHA 的摘要闭合。 */
export function validateTrustedRegistryApproval({
  approval,
  expectedProducerWorkflowSha,
  previousApproval,
  previousRecord,
  record,
}) {
  validateTrustedRegistryRecord(record);
  validateTrustedRegistryRecord(previousRecord);
  const previousProducerWorkflowSha = validateHistoricalApprovalLink(
    previousApproval,
    previousRecord,
  );
  const bindsGateImplementation = record.sequence >= 3;
  const expectedPreviousGateImplementationDigest =
    previousRecord.sequence >= 3
      ? previousRecord.gateImplementationDigest
      : UNBOUND_GATE_IMPLEMENTATION_DIGEST_V1;
  assertClosedObject(
    approval,
    [
      "approvalKind",
      "approvedAt",
      "approvedBy",
      ...(bindsGateImplementation
        ? ["gateImplementationDigest", "previousGateImplementationDigest"]
        : []),
      "gateRegistryDigest",
      "previousGateRegistryDigest",
      "previousProducerWorkflowSha",
      "producerWorkflowSha",
      "providerRepositoryId",
      "schemaVersion",
      "sequence",
      "sourceCommit",
    ],
    "TrustedGateRegistryApprovalV1",
  );
  if (
    approval.schemaVersion !== 1 ||
    approval.approvalKind !==
      (bindsGateImplementation
        ? "gate-trust-root-migration"
        : "gate-registry-producer-migration") ||
    typeof approval.approvedBy !== "string" ||
    approval.approvedBy.length === 0 ||
    !Number.isFinite(Date.parse(approval.approvedAt)) ||
    approval.providerRepositoryId !== record.providerRepositoryId ||
    previousRecord.providerRepositoryId !== record.providerRepositoryId ||
    record.sequence !== previousRecord.sequence + 1 ||
    approval.sequence !== record.sequence ||
    approval.sourceCommit !== record.sourceCommit ||
    approval.gateRegistryDigest !== record.gateRegistryDigest ||
    (bindsGateImplementation &&
      (approval.gateImplementationDigest !== record.gateImplementationDigest ||
        approval.previousGateImplementationDigest !==
          expectedPreviousGateImplementationDigest)) ||
    approval.previousGateRegistryDigest !== previousRecord.gateRegistryDigest ||
    approval.previousProducerWorkflowSha !== previousProducerWorkflowSha ||
    approval.producerWorkflowSha !== expectedProducerWorkflowSha ||
    !/^[a-f0-9]{40}$/u.test(approval.producerWorkflowSha) ||
    Date.parse(approval.approvedAt) < Date.parse(previousRecord.effectiveAt) ||
    Date.parse(record.effectiveAt) < Date.parse(approval.approvedAt) ||
    sha256CanonicalJson(approval) !== record.approvalEvidenceDigest
  ) {
    throw new Error("TrustedGateRegistryApprovalV1 未与可信记录和 producer SHA 闭合。\n");
  }
}

/** 验证前序批准文件自身摘要、记录绑定和 producer SHA，作为当前迁移 CAS 输入。 */
function validateHistoricalApprovalLink(approval, record) {
  const isBootstrap = record.sequence === 1;
  const bindsGateImplementation = record.sequence >= 3;
  const expectedKeys = isBootstrap
    ? [
        "approvalKind",
        "approvedAt",
        "approvedBy",
        "gateRegistryDigest",
        "producerWorkflowSha",
        "providerRepositoryId",
        "schemaVersion",
        "sourceCommit",
      ]
    : [
        "approvalKind",
        "approvedAt",
        "approvedBy",
        ...(bindsGateImplementation
          ? ["gateImplementationDigest", "previousGateImplementationDigest"]
          : []),
        "gateRegistryDigest",
        "previousGateRegistryDigest",
        "previousProducerWorkflowSha",
        "producerWorkflowSha",
        "providerRepositoryId",
        "schemaVersion",
        "sequence",
        "sourceCommit",
      ];
  assertClosedObject(approval, expectedKeys, "PreviousTrustedGateRegistryApprovalV1");
  if (
    approval.schemaVersion !== 1 ||
    approval.approvalKind !==
      (isBootstrap
        ? "initial-gate-registry-bootstrap"
        : bindsGateImplementation
          ? "gate-trust-root-migration"
          : "gate-registry-producer-migration") ||
    typeof approval.approvedBy !== "string" ||
    approval.approvedBy.length === 0 ||
    !Number.isFinite(Date.parse(approval.approvedAt)) ||
    approval.providerRepositoryId !== record.providerRepositoryId ||
    (!isBootstrap && approval.sequence !== record.sequence) ||
    approval.sourceCommit !== record.sourceCommit ||
    approval.gateRegistryDigest !== record.gateRegistryDigest ||
    (bindsGateImplementation &&
      (approval.gateImplementationDigest !== record.gateImplementationDigest ||
        !digestPattern.test(approval.previousGateImplementationDigest))) ||
    !/^[a-f0-9]{40}$/u.test(approval.producerWorkflowSha) ||
    Date.parse(record.effectiveAt) < Date.parse(approval.approvedAt) ||
    sha256CanonicalJson(approval) !== record.approvalEvidenceDigest
  ) {
    throw new Error("前序 TrustedGateRegistryApprovalV1 未与前序可信记录闭合。\n");
  }
  return approval.producerWorkflowSha;
}

/** 解析并验证 evidenceProducerId 的固定语法和 gate 后缀。 */
export function parseEvidenceProducerId(value, gateId) {
  const match = producerPattern.exec(value);
  if (match === null || match[6] !== gateId) {
    throw new Error(`gate ${gateId} 的 evidenceProducerId 无效或未绑定自身 gateId。`);
  }
  return {
    candidateRepositoryId: match[1],
    owner: match[2],
    repository: match[3],
    workflowFile: match[4],
    workflowSha: match[5],
  };
}

/** 验证 GateDefinitionV1 的封闭字段和可执行约束。 */
function validateDefinition(value) {
  const allowed = [
    "blocking",
    "capabilityOwner",
    "checkId",
    "command",
    "evidenceProducerId",
    "gateId",
  ];
  if (Object.hasOwn(value ?? {}, "triggerPaths")) {
    allowed.push("triggerPaths");
  }
  assertClosedObject(value, allowed, "GateDefinitionV1");
  if (
    typeof value.blocking !== "boolean" ||
    !ownerValues.has(value.capabilityOwner) ||
    !stableIdPattern.test(value.checkId) ||
    !stableIdPattern.test(value.gateId) ||
    !Array.isArray(value.command) ||
    value.command.length === 0 ||
    value.command.some(
      (argument) => typeof argument !== "string" || argument.trim().length === 0 || argument.includes("\0"),
    )
  ) {
    throw new Error(`gate ${value.gateId ?? "unknown"} 的定义字段无效。`);
  }
  parseEvidenceProducerId(value.evidenceProducerId, value.gateId);
  if (Object.hasOwn(value, "triggerPaths")) {
    if (!Array.isArray(value.triggerPaths) || value.triggerPaths.length === 0) {
      throw new Error(`gate ${value.gateId} 的 triggerPaths 必须非空。`);
    }
    value.triggerPaths.forEach((triggerPath, index) => {
      if (
        typeof triggerPath !== "string" ||
        !isCanonicalGlob(triggerPath) ||
        (index > 0 && value.triggerPaths[index - 1] >= triggerPath)
      ) {
        throw new Error(`gate ${value.gateId} 的 triggerPaths 非法、重复或未排序。`);
      }
    });
  }
}

/** 验证对象只含允许字段且没有访问器等运行时语义。 */
function assertClosedObject(value, allowedKeys, label) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(`${label} 必须是普通对象。`);
  }
  const keys = Object.keys(value).sort();
  const expected = [...allowedKeys].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} 包含缺失或未知字段。`);
  }
}

/** trigger glob 必须保持相对、POSIX、无逃逸且无反选。 */
function isCanonicalGlob(value) {
  if (
    value.length === 0 ||
    value.startsWith("!") ||
    value.startsWith("/") ||
    value.includes("\\") ||
    value.includes("\0") ||
    value.includes("//") ||
    value.endsWith("/") ||
    /[\[\]{}]/u.test(value)
  ) {
    return false;
  }
  return value.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}
