import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { sha256CanonicalJson, sha256Hex } from "./canonical-json.mjs";
import { computeGateImplementationDigest } from "./gate-implementation-policy.mjs";
import { createEvaluationContext } from "./git-context.mjs";
import { runProcessWithDeadline } from "./run-process-with-deadline.mjs";
import {
  loadGateRegistry,
  parseEvidenceProducerId,
  validateTrustedRegistryRecord,
} from "./registry.mjs";

const outputLimitBytes = 1024 * 1024;
const gateTimeoutMs = 10 * 60 * 1000;

/** 执行受信任 GateHarness，并生成不含原始日志的 GateEvidence 集合。 */
export async function produceGateEvidence(options) {
  const trustedRecord = JSON.parse(await readFile(options.trustedRecordPath, "utf8"));
  validateTrustedRegistryRecord(trustedRecord);
  if (trustedRecord.providerRepositoryId !== options.providerRepositoryId) {
    throw new Error("providerRepositoryId 与 TrustedGateRegistryRecordV1 不一致。");
  }
  const { digest: gateRegistryDigest, registry } = await loadGateRegistry(
    path.join(options.candidateRoot, "ci", "quality-gates.v1.yaml"),
  );
  if (gateRegistryDigest !== trustedRecord.gateRegistryDigest) {
    throw new Error("候选 Gate Registry digest 未获外部 Controller 批准。");
  }
  if (trustedRecord.sequence < 3) {
    throw new Error("可信记录尚未绑定 gate 实现摘要，GateHarness fail closed。");
  }
  const { digest: gateImplementationDigest } = await computeGateImplementationDigest(
    options.candidateRoot,
    registry,
  );
  if (gateImplementationDigest !== trustedRecord.gateImplementationDigest) {
    throw new Error("候选 gate 实现摘要未获外部 Controller 批准。");
  }
  const { affectedPaths, evaluationContext } = await createEvaluationContext({
    baseOid: options.baseOid,
    candidateRoot: options.candidateRoot,
    gateRegistryDigest,
    headOid: options.headOid,
    objectFormat: options.objectFormat,
    providerRepositoryId: options.providerRepositoryId,
  });
  await mkdir(options.artifactDirectory, { recursive: true });
  const evidence = [];
  for (const entry of registry.gates) {
    const definition = entry.gateDefinition;
    const producer = parseEvidenceProducerId(definition.evidenceProducerId, definition.gateId);
    if (
      producer.candidateRepositoryId !== options.providerRepositoryId ||
      `${producer.owner}/${producer.repository}` !== options.controllerRepository ||
      producer.workflowFile !== options.workflowFile ||
      producer.workflowSha !== options.workflowSha
    ) {
      throw new Error(`gate ${definition.gateId} 的 producer 与可信 workflow identity 不匹配。`);
    }
    const applicability = evaluateApplicability(definition, affectedPaths);
    if (applicability === "not-applicable") {
      continue;
    }
    const [executable, ...args] = definition.command;
    const execution = await runProcessWithDeadline({
      args,
      cwd: options.candidateRoot,
      executable,
      outputLimitBytes,
      timeoutMs: options.gateTimeoutMs ?? gateTimeoutMs,
    });
    await writeFile(
      path.join(options.artifactDirectory, `${definition.gateId}.stdout.log`),
      execution.stdout,
    );
    await writeFile(
      path.join(options.artifactDirectory, `${definition.gateId}.stderr.log`),
      execution.stderr,
    );
    const gateOutput = {
      gateId: definition.gateId,
      schemaVersion: 1,
      stderrBytes: execution.stderrBytes,
      stderrDigest: sha256Hex(execution.stderr),
      stderrTruncated: execution.stderrTruncated,
      stdoutBytes: execution.stdoutBytes,
      stdoutDigest: sha256Hex(execution.stdout),
      stdoutTruncated: execution.stdoutTruncated,
      termination: execution.termination,
    };
    const evidenceWithoutDigest = {
      evaluationContextDigest: evaluationContext.evaluationContextDigest,
      evidenceProducerId: definition.evidenceProducerId,
      gateDefinitionDigest: entry.gateDefinitionDigest,
      gateId: definition.gateId,
      headOid: options.headOid,
      outputDigest: sha256CanonicalJson(gateOutput),
      schemaVersion: 1,
      status: execution.status,
    };
    evidence.push({
      ...evidenceWithoutDigest,
      gateEvidenceDigest: sha256CanonicalJson(evidenceWithoutDigest),
    });
  }
  if (evidence.length !== registry.gates.filter(({ gateDefinition }) => gateDefinition.blocking).length) {
    throw new Error("required gate 证据缺失，GateHarness fail closed。\n");
  }
  const artifact = {
    affectedPaths,
    evaluationContext,
    evidence,
    gateImplementationDigest,
    gateRegistryDigest,
    schemaVersion: 1,
  };
  const artifactPath = path.join(options.artifactDirectory, "gate-evidence.json");
  await writeFile(artifactPath, `${JSON.stringify(artifact)}\n`, "utf8");
  return {
    artifact,
    artifactDigest: sha256Hex(await readFile(artifactPath)),
    artifactPath,
    passed: evidence.every((entry) => entry.status === "pass"),
  };
}

/** triggerPaths 缺失表示 always applicable，否则按受限 POSIX glob 匹配。 */
export function evaluateApplicability(definition, affectedPaths) {
  if (!Object.hasOwn(definition, "triggerPaths")) {
    return "required";
  }
  return definition.triggerPaths.some((glob) => {
    const expression = globToRegExp(glob);
    return affectedPaths.some((relativePath) => expression.test(relativePath));
  })
    ? "required"
    : "not-applicable";
}

/** 将不含反选的受限 POSIX glob 转为整路径正则。 */
function globToRegExp(glob) {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    const next = glob[index + 1];
    if (character === "*" && next === "*") {
      if (glob[index + 2] === "/") {
        pattern += "(?:[^/]+/)*";
        index += 2;
      } else {
        pattern += ".*";
        index += 1;
      }
    } else if (character === "*") {
      pattern += "[^/]*";
    } else if (character === "?") {
      pattern += "[^/]";
    } else {
      pattern += character.replace(/[\\^$.*+?()[\]{}|]/gu, "\\$&");
    }
  }
  return new RegExp(`${pattern}$`, "u");
}
