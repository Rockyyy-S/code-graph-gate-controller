import { execFile } from "node:child_process";
import { chmod, chown, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { sha256CanonicalJson, sha256Hex } from "./canonical-json.mjs";
import { evaluateApplicability } from "./applicability.mjs";
import { computeGateImplementationDigest } from "./gate-implementation-policy.mjs";
import { createEvaluationContext } from "./git-context.mjs";
import { runProcessWithDeadline } from "./run-process-with-deadline.mjs";
import {
  loadGateRegistry,
  parseEvidenceProducerId,
  validateTrustedRegistryRecord,
} from "./registry.mjs";

const outputLimitBytes = 1024 * 1024;
const gateTimeoutMs = 2 * 60 * 1000;
const harnessTimeoutMs = 20 * 60 * 1000;
const execFileAsync = promisify(execFile);

export { evaluateApplicability } from "./applicability.mjs";

/** 执行受信任 GateHarness，并生成不含原始日志的 GateEvidence 集合。 */
export async function produceGateEvidence(options) {
  validateExecutionIdentity(options);
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
  const gateImplementationDigest = await assertApprovedGateImplementation({
    candidateRoot: options.candidateRoot,
    expectedDigest: trustedRecord.gateImplementationDigest,
    registry,
  });
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
  const requiredBlockingGateIds = new Set();
  const harnessDeadlineAt =
    Date.now() + (options.harnessTimeoutMs ?? harnessTimeoutMs);
  for (const [gateIndex, entry] of registry.gates.entries()) {
    await assertApprovedGateImplementation({
      candidateRoot: options.candidateRoot,
      expectedDigest: gateImplementationDigest,
      registry,
    });
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
    if (definition.blocking) {
      requiredBlockingGateIds.add(definition.gateId);
    }
    const [executable, ...args] = definition.command;
    const remainingMs = harnessDeadlineAt - Date.now();
    let execution;
    if (remainingMs <= 0) {
      execution = createHarnessTimeoutExecution();
    } else {
      const runtime = await prepareGateRuntime(options, gateIndex);
      try {
        execution = await runProcessWithDeadline({
            args: createTrustedGateArguments(executable, args),
            cwd: options.candidateRoot,
            env: createGateEnvironment({
              ...options,
              gateHome: runtime.gateHome,
              gateTempDirectory: runtime.gateTempDirectory,
            }),
            executable,
            gid: options.gateGid,
            outputLimitBytes,
            timeoutMs: Math.min(options.gateTimeoutMs ?? gateTimeoutMs, remainingMs),
            uid: options.gateUid,
          });
      } finally {
        await cleanupGateRuntime(options, runtime);
      }
    }
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
  await assertApprovedGateImplementation({
    candidateRoot: options.candidateRoot,
    expectedDigest: gateImplementationDigest,
    registry,
  });
  const evidenceGateIds = new Set(evidence.map(({ gateId }) => gateId));
  if ([...requiredBlockingGateIds].some((gateId) => !evidenceGateIds.has(gateId))) {
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
    passed: didRequiredBlockingGatesPass(evidence, requiredBlockingGateIds),
  };
}

/** 禁止 pnpm 自动执行未进入实现摘要的 pre/post lifecycle。 */
export function createTrustedGateArguments(executable, args) {
  return executable === "pnpm"
    ? [
        "--config.enable-pre-post-scripts=false",
        "--config.ignore-pnpmfile=true",
        "--config.verify-deps-before-run=false",
        ...args,
      ]
    : args;
}

/**
 * 为单个 gate 派生短且唯一的 HOME/TMP 路径。
 *
 * 使用 registry 顺序的 base36 槽位，避免完整 gateId 消耗 Unix socket 的平台路径预算。
 */
export function createGateRuntimePaths(options, gateIndex) {
  if (!Number.isSafeInteger(gateIndex) || gateIndex < 0) {
    throw new TypeError("gate 运行目录槽位必须是非负安全整数。");
  }
  const runtimeSlot = gateIndex.toString(36);
  return {
    gateHome: path.join(options.gateHome, runtimeSlot),
    gateTempDirectory: path.join(options.gateTempDirectory, runtimeSlot),
  };
}

/** non-blocking evidence 只保留诊断，不能改变 required blocking 聚合结论。 */
export function didRequiredBlockingGatesPass(evidence, requiredBlockingGateIds) {
  const evidenceByGate = new Map(evidence.map((entry) => [entry.gateId, entry]));
  return [...requiredBlockingGateIds].every(
    (gateId) => evidenceByGate.get(gateId)?.status === "pass",
  );
}

/** 每次执行前后都从只读候选快照重算实现摘要，拒绝执行期漂移。 */
async function assertApprovedGateImplementation({ candidateRoot, expectedDigest, registry }) {
  const { digest } = await computeGateImplementationDigest(candidateRoot, registry);
  if (digest !== expectedDigest) {
    throw new Error("候选 gate 实现摘要未获外部 Controller 批准或在执行期发生漂移。");
  }
  return digest;
}

/** 只向候选 gate 暴露执行所需的最小环境，排除 GitHub/OIDC/runner 凭据。 */
export function createGateEnvironment(options) {
  const gateHome = options.gateHome ?? process.env.HOME;
  const gateTempDirectory = options.gateTempDirectory ?? process.env.TMPDIR ?? gateHome;
  const environment = {
    CI: "true",
    HOME: gateHome,
    LANG: process.env.LANG ?? "C.UTF-8",
    // 同时约束子脚本再次启动的 pnpm，避免嵌套调用恢复候选 hooks。
    npm_config_enable_pre_post_scripts: "false",
    npm_config_ignore_pnpmfile: "true",
    npm_config_verify_deps_before_run: "false",
    PATH: process.env.PATH,
    PNPM_CONFIG_ENABLE_PRE_POST_SCRIPTS: "false",
    PNPM_CONFIG_IGNORE_PNPMFILE: "true",
    PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN: "false",
    TMPDIR: gateTempDirectory,
    XDG_CACHE_HOME: gateHome === undefined ? undefined : path.join(gateHome, ".cache"),
    XDG_CONFIG_HOME: gateHome === undefined ? undefined : path.join(gateHome, ".config"),
    XDG_DATA_HOME: gateHome === undefined ? undefined : path.join(gateHome, ".local", "share"),
  };
  if (process.platform === "win32") {
    environment.ComSpec = process.env.ComSpec;
    environment.PATHEXT = process.env.PATHEXT;
    environment.SystemRoot = process.env.SystemRoot;
    environment.TEMP = gateTempDirectory;
    environment.TMP = gateTempDirectory;
  }
  return Object.fromEntries(
    Object.entries(environment).filter(([, value]) => typeof value === "string"),
  );
}

/** 在 root-owned 基目录中为单个 gate 创建专属 UID 运行目录。 */
async function prepareGateRuntime(options, gateIndex) {
  if (options.gateUid === undefined) {
    return {
      gateHome: options.gateHome,
      gateTempDirectory: options.gateTempDirectory,
    };
  }
  await terminateGateIdentity(options.gateUid);
  const runtime = createGateRuntimePaths(options, gateIndex);
  await Promise.all([
    rm(runtime.gateHome, { force: true, recursive: true }),
    rm(runtime.gateTempDirectory, { force: true, recursive: true }),
  ]);
  await Promise.all([
    mkdir(runtime.gateHome, { mode: 0o700 }),
    mkdir(runtime.gateTempDirectory, { mode: 0o700 }),
  ]);
  await Promise.all([
    chown(runtime.gateHome, options.gateUid, options.gateGid),
    chown(runtime.gateTempDirectory, options.gateUid, options.gateGid),
    chmod(runtime.gateHome, 0o700),
    chmod(runtime.gateTempDirectory, 0o700),
  ]);
  return runtime;
}

/** 每个 gate 结束后清除该 UID 的逃逸进程与可持久化配置。 */
async function cleanupGateRuntime(options, runtime) {
  if (options.gateUid === undefined) {
    return;
  }
  await terminateGateIdentity(options.gateUid);
  await Promise.all([
    rm(runtime.gateHome, { force: true, recursive: true }),
    rm(runtime.gateTempDirectory, { force: true, recursive: true }),
  ]);
}

/** 同时清理 real/effective UID，并要求进程集合稳定收敛为空。 */
async function terminateGateIdentity(gateUid) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await Promise.all([
      runIdentityProcessTool("pkill", ["-KILL", "-u", `${gateUid}`]),
      runIdentityProcessTool("pkill", ["-KILL", "-U", `${gateUid}`]),
    ]);
    const remaining = await Promise.all([
      runIdentityProcessTool("pgrep", ["-u", `${gateUid}`]),
      runIdentityProcessTool("pgrep", ["-U", `${gateUid}`]),
    ]);
    if (remaining.every((matched) => !matched)) {
      return;
    }
    await delay(10);
  }
  throw new Error("gate 隔离 UID 的残留进程未稳定收敛为空。");
}

/** pkill/pgrep 返回 1 仅表示当前没有匹配进程。 */
async function runIdentityProcessTool(executable, args) {
  try {
    await execFileAsync(executable, args);
    return true;
  } catch (error) {
    if (error && typeof error === "object" && error.code === 1) {
      return false;
    }
    throw new Error("无法检查或清理 gate 隔离 UID 的残留进程。", {
      cause: error,
    });
  }
}

/** 专用 UID/GID 必须成对出现，并绑定独立 home/temp 目录。 */
function validateExecutionIdentity(options) {
  const hasUid = options.gateUid !== undefined;
  const hasGid = options.gateGid !== undefined;
  if (
    hasUid !== hasGid ||
    (hasUid &&
      (!Number.isSafeInteger(options.gateUid) ||
        options.gateUid <= 0 ||
        !Number.isSafeInteger(options.gateGid) ||
        options.gateGid <= 0 ||
        typeof options.gateHome !== "string" ||
        !path.isAbsolute(options.gateHome) ||
        typeof options.gateTempDirectory !== "string" ||
        !path.isAbsolute(options.gateTempDirectory)))
  ) {
    throw new TypeError("GateHarness 专用 UID/GID 与 home/temp 参数无效。");
  }
}

/** 总 deadline 耗尽后为剩余 gate 生成稳定 invalid，而不是等待 job 强杀。 */
function createHarnessTimeoutExecution() {
  return {
    status: "invalid",
    stderr: Buffer.alloc(0),
    stderrBytes: 0,
    stderrTruncated: false,
    stdout: Buffer.alloc(0),
    stdoutBytes: 0,
    stdoutTruncated: false,
    termination: { kind: "spawn-error", stableCode: "ETIMEDOUT" },
  };
}
