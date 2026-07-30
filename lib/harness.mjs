import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  chmod,
  chown,
  lstat,
  mkdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
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
  loadApprovedProposals,
  parseEvidenceProducerId,
  selectTrustedRecordForCandidate,
  validateTrustedRegistryRecord,
} from "./registry.mjs";

const outputLimitBytes = 1024 * 1024;
const gateTimeoutMs = 2 * 60 * 1000;
const harnessTimeoutMs = 20 * 60 * 1000;
const win32PreflightDeadlineMs = 10_000;
const execFileAsync = promisify(execFile);
export const GATE_HARNESS_CONTRACT_VERSION = 4;
export const WIN32_HOST_IDENTITY_GATE_ID = "host-path-identity-win32-v1";
export const TRUSTED_PNPM_WIN32_VERSION = "11.12.0";
export const TRUSTED_PNPM_WIN32_SIZE = 98_099_528;
export const TRUSTED_PNPM_WIN32_SHA256 =
  "0a8b6b9d6f391bb83e868a3f951eec74fb8f745c176fce523a9359f40b20fb7b";

const gateExecutionPartitions = new Set(["portable", "win32"]);

export { evaluateApplicability } from "./applicability.mjs";

/** 执行受信任 GateHarness，并生成不含原始日志的 GateEvidence 集合。 */
export async function produceGateEvidence(options) {
  validateExecutionIdentity(options);
  const trustedPnpmExecutable = options.executionPartition === "win32"
    ? await validateTrustedPnpmExecutable(options.trustedPnpmExecutable)
    : undefined;
  let validatedWin32Preflight;
  if (options.executionPartition === "win32") {
    const preflight = JSON.parse(await readFile(options.win32PreflightArtifactPath, "utf8"));
    validatedWin32Preflight = validateWin32PreflightArtifact(preflight, {
      gateTempDirectory: options.gateTempDirectory,
      platform: process.platform,
    });
  }
  const currentTrustedRecord = JSON.parse(await readFile(options.trustedRecordPath, "utf8"));
  validateTrustedRegistryRecord(currentTrustedRecord);
  if (currentTrustedRecord.providerRepositoryId !== options.providerRepositoryId) {
    throw new Error("providerRepositoryId 与 TrustedGateRegistryRecordV1 不一致。");
  }
  const { digest: gateRegistryDigest, registry } = await loadGateRegistry(
    path.join(options.candidateRoot, "ci", "quality-gates.v1.yaml"),
  );
  const proposals = await loadApprovedProposals(options.proposedRecordDirectory, {
    currentRecord: currentTrustedRecord,
    expectedProducerWorkflowSha: options.workflowSha,
  });
  const trustedRecord = selectTrustedRecordForCandidate({
    currentRecord: currentTrustedRecord,
    headOid: options.headOid,
    proposals,
    providerRepositoryId: options.providerRepositoryId,
    pullNumber: options.pullNumber,
    registryDigest: gateRegistryDigest,
    workflowSha: options.workflowSha,
  });
  if (trustedRecord.sequence < 3) {
    throw new Error("可信记录尚未绑定 gate 实现摘要，GateHarness fail closed。");
  }
  const gateImplementationDigest = await assertApprovedGateImplementation({
    candidateRoot: options.candidateRoot,
    expectedDigest: trustedRecord.gateImplementationDigest,
    registry,
  });
  const selectedEntries = selectGateEntriesForPartition(
    registry,
    options.executionPartition,
  );
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
  for (const [gateIndex, entry] of selectedEntries) {
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
      const runtime = await prepareGateRuntime(options, gateIndex, harnessDeadlineAt);
      try {
        const gateRemainingMs = harnessDeadlineAt - Date.now();
        execution = gateRemainingMs <= 0
          ? createHarnessTimeoutExecution()
          : await runProcessWithDeadline({
            args: createTrustedGateArguments(executable, args),
            cwd: options.candidateRoot,
            env: createGateEnvironment({
              ...options,
              gateHome: runtime.gateHome,
              gateTempDirectory: runtime.gateTempDirectory,
              trustedPnpmExecutable,
              validatedWin32Preflight,
            }),
            executable,
            gid: options.gateGid,
            outputLimitBytes,
            timeoutMs: Math.min(options.gateTimeoutMs ?? gateTimeoutMs, gateRemainingMs),
            uid: options.gateUid,
          });
      } finally {
        await cleanupGateRuntime(options, runtime, harnessDeadlineAt);
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
    if (
      options.executionPartition === "win32" &&
      definition.gateId === WIN32_HOST_IDENTITY_GATE_ID
    ) {
      await validateHostPathRuntimeAttestation({
        attestationPath: options.hostPathInvocationAttestationPath,
        expectedInvocationCount: execution.status === "pass" ? 2 : 1,
        sentinelMarkerPath: options.pathSentinelMarkerPath,
        trustedPnpmExecutable,
      });
    }
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

/**
 * 将 portable 与 Win32 分区产物合并回原有单一 GateHarness artifact。
 *
 * 合并只接受相同候选、registry、实现摘要与 evaluation context，且不同分区不得
 * 重复声明同一 gate，避免平台结果覆盖或歧义。
 */
export async function mergeGateEvidenceArtifacts(options) {
  if (
    !Array.isArray(options?.artifactPaths) ||
    options.artifactPaths.length < 2 ||
    options.artifactPaths.some((artifactPath) =>
      typeof artifactPath !== "string" || !path.isAbsolute(artifactPath)
    ) ||
    new Set(options.artifactPaths.map((artifactPath) => path.normalize(artifactPath))).size !==
      options.artifactPaths.length ||
    typeof options.artifactDirectory !== "string" ||
    !path.isAbsolute(options.artifactDirectory)
  ) {
    throw new TypeError("GateHarness 合并参数必须包含唯一绝对输入路径和绝对输出目录。");
  }

  const artifacts = await Promise.all(
    options.artifactPaths.map(async (artifactPath) => {
      const artifact = JSON.parse(await readFile(artifactPath, "utf8"));
      validatePartialEvidenceArtifact(artifact);
      return artifact;
    }),
  );
  const reference = artifacts[0];
  const sharedDigest = digestSharedArtifactFields(reference);
  const evidenceByGate = new Map();
  for (const artifact of artifacts) {
    if (digestSharedArtifactFields(artifact) !== sharedDigest) {
      throw new Error("GateHarness 分区 artifact 未绑定同一候选与 evaluation context。");
    }
    for (const evidence of artifact.evidence) {
      if (evidenceByGate.has(evidence.gateId)) {
        throw new Error(`GateHarness 分区重复生成 gate ${evidence.gateId} 证据。`);
      }
      evidenceByGate.set(evidence.gateId, evidence);
    }
  }

  const artifact = {
    affectedPaths: reference.affectedPaths,
    evaluationContext: reference.evaluationContext,
    evidence: [...evidenceByGate.values()].sort((left, right) =>
      left.gateId < right.gateId ? -1 : left.gateId > right.gateId ? 1 : 0
    ),
    gateImplementationDigest: reference.gateImplementationDigest,
    gateRegistryDigest: reference.gateRegistryDigest,
    schemaVersion: 1,
  };
  await mkdir(options.artifactDirectory, { recursive: true });
  const artifactPath = path.join(options.artifactDirectory, "gate-evidence.json");
  await writeFile(artifactPath, `${JSON.stringify(artifact)}\n`, "utf8");
  return {
    artifact,
    artifactDigest: sha256Hex(await readFile(artifactPath)),
    artifactPath,
  };
}

/** 根据真实 runner 平台选择互斥 gate 分区，禁止 Ubuntu 生成 Win32 gate 证据。 */
export function selectGateEntriesForPartition(
  registry,
  executionPartition,
  platform = process.platform,
) {
  if (!gateExecutionPartitions.has(executionPartition)) {
    throw new TypeError("GateHarness execution partition 无效。");
  }
  if (
    (executionPartition === "win32" && platform !== "win32") ||
    (executionPartition === "portable" && platform === "win32")
  ) {
    throw new Error("GateHarness execution partition 与真实 runner 平台不一致。");
  }
  const win32Entry = registry.gates.find(
    ({ gateDefinition }) => gateDefinition.gateId === WIN32_HOST_IDENTITY_GATE_ID,
  );
  if (win32Entry === undefined || win32Entry.gateDefinition.blocking !== true) {
    throw new Error("Win32 host identity blocking gate 缺失或被降级。");
  }
  return [...registry.gates.entries()].filter(([, entry]) =>
    executionPartition === "win32"
      ? entry.gateDefinition.gateId === WIN32_HOST_IDENTITY_GATE_ID
      : entry.gateDefinition.gateId !== WIN32_HOST_IDENTITY_GATE_ID
  );
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
    CODEGRAPH_BASE_OID: options.baseOid,
    CODEGRAPH_HEAD_OID: options.headOid,
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
  if (options.executionPartition === "win32") {
    environment.CODEGRAPH_HOST_PATH_IDENTITY_ATTESTATION_PATH =
      options.hostPathInvocationAttestationPath;
    environment.CODEGRAPH_TRUSTED_PNPM_EXE = options.trustedPnpmExecutable;
    // 只转交 Harness 已验证的外层证明，候选不得读取 artifact 路径或自行信任 workflow 输入。
    environment.CODEGRAPH_TRUSTED_WIN32_PREFLIGHT_V1 =
      options.validatedWin32Preflight === undefined
        ? undefined
        : JSON.stringify(options.validatedWin32Preflight);
  }
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

/**
 * 校验 Hosted Win32 preflight 的平台、Get-Volume 结果与 dedicated NTFS 根。
 *
 * @param {object} preflight 结构化 preflight artifact。
 * @param {{gateTempDirectory:string,platform:NodeJS.Platform}} context 实际 Harness 上下文。
 * @returns {object} 已闭合的 preflight。
 */
export function validateWin32PreflightArtifact(preflight, context) {
  const fail = (code, message) => {
    const error = new Error(`${code}: ${message}`);
    error.code = code;
    error.preflight = preflight;
    throw error;
  };
  if (
    preflight === null ||
    typeof preflight !== "object" ||
    preflight.schemaVersion !== 1
  ) {
    fail("WIN32_PREFLIGHT_INVALID", "artifact schema 无效。");
  }
  if (context.platform !== "win32" || preflight.processPlatform !== "win32") {
    fail(
      "WIN32_PREFLIGHT_NON_WIN32",
      `process.platform=${context.platform}, artifact=${String(preflight.processPlatform)}`,
    );
  }
  if (preflight.getVolume?.timeout === true) {
    fail(
      "WIN32_PREFLIGHT_QUERY_TIMEOUT",
      `status=${String(preflight.getVolume.status)}, stderr=${String(preflight.getVolume.stderr)}`,
    );
  }
  if (preflight.getVolume?.status !== 0) {
    fail(
      "WIN32_PREFLIGHT_QUERY_ERROR",
      `status=${String(preflight.getVolume?.status)}, stderr=${String(preflight.getVolume?.stderr)}`,
    );
  }
  if (
    !Number.isInteger(preflight.probeDurationMs) ||
    preflight.probeDurationMs < 0 ||
    preflight.probeDurationMs > win32PreflightDeadlineMs
  ) {
    fail(
      "WIN32_PREFLIGHT_DEADLINE_DRIFT",
      `probeDurationMs=${String(preflight.probeDurationMs)}, deadlineMs=${win32PreflightDeadlineMs}`,
    );
  }
  if (preflight.fileSystem !== "NTFS") {
    fail(
      "WIN32_PREFLIGHT_NON_NTFS",
      `fileSystem=${String(preflight.fileSystem)}, drive=${String(preflight.drive)}`,
    );
  }
  if (
    preflight.driveType !== "Fixed" ||
    preflight.root?.ordinary !== true ||
    preflight.root?.reparse !== false
  ) {
    fail(
      "WIN32_PREFLIGHT_UNSAFE_ROOT",
      `driveType=${String(preflight.driveType)}, ordinary=${String(preflight.root?.ordinary)}, reparse=${String(preflight.root?.reparse)}`,
    );
  }
  if (
    typeof preflight.selectedRoot !== "string" ||
    !path.isAbsolute(preflight.selectedRoot) ||
    path.resolve(preflight.selectedRoot).toLowerCase() !==
      path.resolve(context.gateTempDirectory).toLowerCase()
  ) {
    fail(
      "WIN32_PREFLIGHT_ROOT_MISMATCH",
      `selectedRoot=${String(preflight.selectedRoot)}, gateTemp=${context.gateTempDirectory}`,
    );
  }
  return preflight;
}

/** 校验候选 verifier 的绝对 launcher 调用证明，并断言恶意 PATH sentinel 未执行。 */
async function validateHostPathRuntimeAttestation(options) {
  let sentinelExists = false;
  try {
    await lstat(options.sentinelMarkerPath);
    sentinelExists = true;
  } catch (error) {
    if (!(error && typeof error === "object" && error.code === "ENOENT")) {
      throw error;
    }
  }
  if (sentinelExists) {
    throw new Error("恶意 PATH pnpm sentinel 已被调用，Win32 launcher attestation 失败。");
  }
  const attestation = JSON.parse(await readFile(options.attestationPath, "utf8"));
  if (
    attestation.schemaVersion !== 1 ||
    attestation.processPlatform !== "win32" ||
    attestation.npmExecPathAbsent !== true ||
    attestation.pathLookupBypassed !== true ||
    attestation.trustedExecutable !== options.trustedPnpmExecutable ||
    !Array.isArray(attestation.invocations) ||
    attestation.invocations.length < options.expectedInvocationCount ||
    attestation.invocations.length > 8 ||
    attestation.invocations.some((invocation) =>
      invocation.executable !== options.trustedPnpmExecutable ||
      invocation.shell !== false ||
      !/^[a-f0-9]{64}$/u.test(invocation.argsSha256)
    )
  ) {
    throw new Error("Win32 host identity 实际 invocation executable 证明无效。");
  }
}

/**
 * 验证 Win32 专用 pnpm.exe 的绝对身份、普通文件属性、摘要、大小与精确版本。
 *
 * @param {string} executable 待验证的 pnpm.exe 绝对路径。
 * @param {{
 *   expectedSha256?: string;
 *   expectedSize?: number;
 *   expectedVersion?: string;
 *   execFileImpl?: typeof execFileAsync;
 *   lstatImpl?: typeof lstat;
 *   platform?: NodeJS.Platform;
 *   realpathImpl?: typeof realpath;
 *   sha256FileImpl?: typeof sha256File;
 * }} [dependencies] 测试可注入的受控验证边界。
 * @returns {Promise<string>} 已复验且规范化的绝对 launcher 路径。
 */
export async function validateTrustedPnpmExecutable(executable, dependencies = {}) {
  const expectedSha256 = dependencies.expectedSha256 ?? TRUSTED_PNPM_WIN32_SHA256;
  const expectedSize = dependencies.expectedSize ?? TRUSTED_PNPM_WIN32_SIZE;
  const expectedVersion = dependencies.expectedVersion ?? TRUSTED_PNPM_WIN32_VERSION;
  const platform = dependencies.platform ?? process.platform;
  if (
    typeof executable !== "string" ||
    !path.isAbsolute(executable) ||
    path.basename(executable).toLowerCase() !== "pnpm.exe" ||
    !Number.isSafeInteger(expectedSize) ||
    expectedSize <= 0 ||
    !/^[a-f0-9]{64}$/u.test(expectedSha256) ||
    typeof expectedVersion !== "string" ||
    expectedVersion.length === 0
  ) {
    throw new TypeError("可信 pnpm launcher 参数无效。");
  }
  const normalized = path.normalize(executable);
  const metadata = await (dependencies.lstatImpl ?? lstat)(normalized);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== expectedSize) {
    throw new Error("可信 pnpm launcher 不是固定大小的普通非 reparse 文件。");
  }
  const resolved = path.normalize(await (dependencies.realpathImpl ?? realpath)(normalized));
  const comparableResolved = platform === "win32" ? resolved.toLowerCase() : resolved;
  const comparableExpected = platform === "win32" ? normalized.toLowerCase() : normalized;
  if (comparableResolved !== comparableExpected) {
    throw new Error("可信 pnpm launcher 经 realpath 后发生重定向。");
  }
  const digest = await (dependencies.sha256FileImpl ?? sha256File)(normalized);
  if (digest !== expectedSha256) {
    throw new Error("可信 pnpm launcher SHA-256 漂移。");
  }
  const { stdout, stderr } = await (dependencies.execFileImpl ?? execFileAsync)(
    normalized,
    ["--version"],
    {
      encoding: "utf8",
      env: {
        SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
        TEMP: process.env.TEMP ?? path.dirname(normalized),
        TMP: process.env.TMP ?? path.dirname(normalized),
      },
      shell: false,
      timeout: 30_000,
      windowsHide: true,
    },
  );
  if (stdout.trim() !== expectedVersion || stderr.trim() !== "") {
    throw new Error("可信 pnpm launcher 版本漂移。");
  }
  return normalized;
}

/** 对普通文件按流式字节计算小写 SHA-256。 */
async function sha256File(filePath) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(filePath)) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

/** 在 root-owned 基目录中为单个 gate 创建专属 UID 运行目录。 */
async function prepareGateRuntime(options, gateIndex, deadlineAt) {
  if (options.gateUid === undefined) {
    return {
      gateHome: options.gateHome,
      gateTempDirectory: options.gateTempDirectory,
    };
  }
  assertHarnessBudget(deadlineAt);
  await terminateGateIdentity(options.gateUid, deadlineAt);
  const runtime = createGateRuntimePaths(options, gateIndex);
  assertHarnessBudget(deadlineAt);
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
async function cleanupGateRuntime(options, runtime, deadlineAt) {
  if (options.gateUid === undefined) {
    return;
  }
  assertHarnessBudget(deadlineAt);
  await terminateGateIdentity(options.gateUid, deadlineAt);
  assertHarnessBudget(deadlineAt);
  await Promise.all([
    rm(runtime.gateHome, { force: true, recursive: true }),
    rm(runtime.gateTempDirectory, { force: true, recursive: true }),
  ]);
}

/** 同时清理 real/effective UID，并要求进程集合稳定收敛为空。 */
async function terminateGateIdentity(gateUid, deadlineAt) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await Promise.all([
      runIdentityProcessTool("pkill", ["-KILL", "-u", `${gateUid}`], { deadlineAt }),
      runIdentityProcessTool("pkill", ["-KILL", "-U", `${gateUid}`], { deadlineAt }),
    ]);
    const remaining = await Promise.all([
      runIdentityProcessTool("pgrep", ["-u", `${gateUid}`], { deadlineAt }),
      runIdentityProcessTool("pgrep", ["-U", `${gateUid}`], { deadlineAt }),
    ]);
    if (remaining.every((matched) => !matched)) {
      return;
    }
    const remainingMs = deadlineAt - Date.now();
    if (remainingMs <= 0) {
      throw new Error("GateHarness UID 清理 deadline 预算已耗尽。");
    }
    await delay(Math.min(10, remainingMs));
  }
  throw new Error("gate 隔离 UID 的残留进程未稳定收敛为空。");
}

/** pkill/pgrep 返回 1 仅表示当前没有匹配进程。 */
export async function runIdentityProcessTool(
  executable,
  args,
  { deadlineAt, exec = execFileAsync, now = Date.now } = {},
) {
  const remainingMs = deadlineAt - now();
  if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
    throw new Error("GateHarness UID 清理 deadline 预算已耗尽。");
  }
  try {
    await exec(executable, args, {
      killSignal: "SIGKILL",
      timeout: Math.max(1, Math.floor(remainingMs)),
    });
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

/** 在不可取消的目录操作前复验 Harness 绝对 deadline。 */
function assertHarnessBudget(deadlineAt) {
  if (!Number.isFinite(deadlineAt) || deadlineAt <= Date.now()) {
    throw new Error("GateHarness 绝对 deadline 预算已耗尽。");
  }
}

/** 专用 UID/GID 必须成对出现，并绑定独立 home/temp 目录。 */
function validateExecutionIdentity(options) {
  const hasUid = options.gateUid !== undefined;
  const hasGid = options.gateGid !== undefined;
  if (
    hasUid !== hasGid ||
    !gateExecutionPartitions.has(options.executionPartition) ||
    !Number.isSafeInteger(options.pullNumber) ||
    options.pullNumber < 0 ||
    typeof options.proposedRecordDirectory !== "string" ||
    !path.isAbsolute(options.proposedRecordDirectory) ||
    typeof options.gateHome !== "string" ||
    !path.isAbsolute(options.gateHome) ||
    typeof options.gateTempDirectory !== "string" ||
    !path.isAbsolute(options.gateTempDirectory) ||
    (options.executionPartition === "portable" && !hasUid) ||
    (options.executionPartition === "win32" && hasUid) ||
    (options.executionPartition === "win32" &&
      (typeof options.trustedPnpmExecutable !== "string" ||
        !path.isAbsolute(options.trustedPnpmExecutable) ||
        typeof options.hostPathInvocationAttestationPath !== "string" ||
        !path.isAbsolute(options.hostPathInvocationAttestationPath) ||
        typeof options.pathSentinelMarkerPath !== "string" ||
        !path.isAbsolute(options.pathSentinelMarkerPath) ||
        typeof options.win32PreflightArtifactPath !== "string" ||
        !path.isAbsolute(options.win32PreflightArtifactPath))) ||
    (options.executionPartition === "portable" &&
      (options.trustedPnpmExecutable !== undefined ||
        options.hostPathInvocationAttestationPath !== undefined ||
        options.pathSentinelMarkerPath !== undefined ||
        options.win32PreflightArtifactPath !== undefined)) ||
    (hasUid &&
      (!Number.isSafeInteger(options.gateUid) ||
        options.gateUid <= 0 ||
        !Number.isSafeInteger(options.gateGid) ||
        options.gateGid <= 0))
  ) {
    throw new TypeError("GateHarness 分区、专用 identity 与 home/temp 参数无效。");
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

/** 校验分区 artifact 保持 Controller 已有的封闭字段与证据摘要合同。 */
function validatePartialEvidenceArtifact(artifact) {
  assertClosedKeys(
    artifact,
    [
      "affectedPaths",
      "evaluationContext",
      "evidence",
      "gateImplementationDigest",
      "gateRegistryDigest",
      "schemaVersion",
    ],
    "GateHarnessPartitionArtifactV1",
  );
  if (
    artifact.schemaVersion !== 1 ||
    !Array.isArray(artifact.affectedPaths) ||
    !Array.isArray(artifact.evidence) ||
    !/^[a-f0-9]{64}$/u.test(artifact.gateImplementationDigest) ||
    !/^[a-f0-9]{64}$/u.test(artifact.gateRegistryDigest) ||
    typeof artifact.evaluationContext !== "object" ||
    artifact.evaluationContext === null ||
    Array.isArray(artifact.evaluationContext)
  ) {
    throw new Error("GateHarness 分区 artifact 形状无效。");
  }
  for (const evidence of artifact.evidence) {
    assertClosedKeys(
      evidence,
      [
        "evaluationContextDigest",
        "evidenceProducerId",
        "gateDefinitionDigest",
        "gateEvidenceDigest",
        "gateId",
        "headOid",
        "outputDigest",
        "schemaVersion",
        "status",
      ],
      "GateEvidenceV1",
    );
    const { gateEvidenceDigest, ...digestInput } = evidence;
    if (
      evidence.schemaVersion !== 1 ||
      !["pass", "fail", "invalid"].includes(evidence.status) ||
      typeof evidence.gateId !== "string" ||
      evidence.gateId.length === 0 ||
      !/^[a-f0-9]{64}$/u.test(gateEvidenceDigest) ||
      gateEvidenceDigest !== sha256CanonicalJson(digestInput)
    ) {
      throw new Error("GateHarness 分区 evidence 形状或摘要无效。");
    }
  }
}

/** 对分区间必须完全相同的候选绑定字段生成稳定比较摘要。 */
function digestSharedArtifactFields(artifact) {
  return sha256CanonicalJson({
    affectedPaths: artifact.affectedPaths,
    evaluationContext: artifact.evaluationContext,
    gateImplementationDigest: artifact.gateImplementationDigest,
    gateRegistryDigest: artifact.gateRegistryDigest,
    schemaVersion: artifact.schemaVersion,
  });
}

/** 校验普通对象只包含指定字段，拒绝分区合并时的隐式扩展。 */
function assertClosedKeys(value, expectedKeys, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} 必须是普通对象。`);
  }
  const actualKeys = Object.keys(value).sort();
  const sortedExpectedKeys = [...expectedKeys].sort();
  if (
    actualKeys.length !== sortedExpectedKeys.length ||
    actualKeys.some((key, index) => key !== sortedExpectedKeys[index])
  ) {
    throw new Error(`${label} 包含缺失或未知字段。`);
  }
}
