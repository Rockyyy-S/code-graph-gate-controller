import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { sha256CanonicalJson, sha256Hex } from "./canonical-json.mjs";
import { createEvaluationContext } from "./git-context.mjs";
import {
  loadGateRegistry,
  parseEvidenceProducerId,
  validateTrustedRegistryRecord,
} from "./registry.mjs";

const outputLimitBytes = 1024 * 1024;

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
    const execution = await executeGate(options.candidateRoot, definition.command);
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
      pattern += ".*";
      index += 1;
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

/** 以 shell:false 执行单个 gate，并对 stdout/stderr 原始字节进行有界捕获。 */
function executeGate(candidateRoot, command) {
  return new Promise((resolve) => {
    const [executable, ...args] = command;
    let child;
    try {
      child = spawn(executable, args, {
        cwd: candidateRoot,
        env: process.env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      resolve(spawnErrorResult(error));
      return;
    }
    const stdout = createBoundedCollector();
    const stderr = createBoundedCollector();
    child.stdout.on("data", (chunk) => stdout.append(chunk));
    child.stderr.on("data", (chunk) => stderr.append(chunk));
    child.once("error", (error) => resolve(spawnErrorResult(error, stdout, stderr)));
    child.once("close", (code, signal) => {
      const status = code === 0 ? "pass" : "fail";
      resolve({
        status,
        stderr: stderr.bytes(),
        stderrBytes: stderr.totalBytes(),
        stderrTruncated: stderr.truncated(),
        stdout: stdout.bytes(),
        stdoutBytes: stdout.totalBytes(),
        stdoutTruncated: stdout.truncated(),
        termination:
          signal === null
            ? { code: code ?? 1, kind: "exit" }
            : { kind: "signal", signalName: signal },
      });
    });
  });
}

/** 为 spawn-error 生成稳定、无本地路径的终止结果。 */
function spawnErrorResult(error, stdout = createBoundedCollector(), stderr = createBoundedCollector()) {
  return {
    status: "invalid",
    stderr: stderr.bytes(),
    stderrBytes: stderr.totalBytes(),
    stderrTruncated: stderr.truncated(),
    stdout: stdout.bytes(),
    stdoutBytes: stdout.totalBytes(),
    stdoutTruncated: stdout.truncated(),
    termination: {
      kind: "spawn-error",
      stableCode:
        typeof error === "object" && error !== null && typeof error.code === "string"
          ? error.code
          : "UNKNOWN",
    },
  };
}

/** 创建记录原始总字节数但只保留固定上限的 collector。 */
function createBoundedCollector() {
  const chunks = [];
  let captured = 0;
  let total = 0;
  return {
    append(chunk) {
      const buffer = Buffer.from(chunk);
      total += buffer.length;
      const remaining = outputLimitBytes - captured;
      if (remaining > 0) {
        const slice = buffer.subarray(0, remaining);
        chunks.push(slice);
        captured += slice.length;
      }
    },
    bytes: () => Buffer.concat(chunks),
    totalBytes: () => total,
    truncated: () => total > captured,
  };
}
