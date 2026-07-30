import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  mergeGateEvidenceArtifacts,
  produceGateEvidence,
} from "../lib/harness.mjs";

/** GateHarness V3 的跨平台公共参数合同。 */
export const GATE_HARNESS_COMMON_ARGUMENT_NAMES_V3 = Object.freeze([
  "--artifact-directory",
  "--base-oid",
  "--candidate-root",
  "--controller-repository",
  "--execution-partition",
  "--gate-home",
  "--gate-temp-directory",
  "--head-oid",
  "--object-format",
  "--provider-repository-id",
  "--proposed-record-directory",
  "--pull-number",
  "--trusted-record",
  "--workflow-file",
  "--workflow-sha",
]);

/** Portable 分区额外要求专用 UID/GID；Win32 分区显式禁止伪造该 Unix identity。 */
export const GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V3 = Object.freeze([
  ...GATE_HARNESS_COMMON_ARGUMENT_NAMES_V3,
  "--gate-gid",
  "--gate-uid",
].sort());
export const GATE_HARNESS_WIN32_ARGUMENT_NAMES_V3 = Object.freeze([
  ...GATE_HARNESS_COMMON_ARGUMENT_NAMES_V3,
].sort());

/** GateHarness V4 显式声明版本，并仅为 Win32 分区增加专用可信 launcher。 */
export const GATE_HARNESS_COMMON_ARGUMENT_NAMES_V4 = Object.freeze([
  ...GATE_HARNESS_COMMON_ARGUMENT_NAMES_V3,
  "--harness-contract-version",
].sort());
export const GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V4 = Object.freeze([
  ...GATE_HARNESS_COMMON_ARGUMENT_NAMES_V4,
  "--gate-gid",
  "--gate-uid",
].sort());
export const GATE_HARNESS_WIN32_ARGUMENT_NAMES_V4 = Object.freeze([
  ...GATE_HARNESS_COMMON_ARGUMENT_NAMES_V4,
  "--host-path-invocation-attestation",
  "--path-sentinel-marker",
  "--trusted-pnpm-executable",
  "--win32-preflight-artifact",
].sort());

/** 合并命令只接受绝对输出目录与 JSON 编码的绝对输入路径数组。 */
export const GATE_EVIDENCE_MERGE_ARGUMENT_NAMES_V1 = Object.freeze([
  "--artifact-directory",
  "--input-artifacts-json",
]);

/** 将成对 CLI 参数解析为封闭选项对象。 */
export function parseArguments(argv) {
  return parseArgumentsForContract(argv, 4);
}

/** 保留既有 V3 参数解析语义，供不可变历史 producer 与兼容测试明确引用。 */
export function parseArgumentsV3(argv) {
  return parseArgumentsForContract(argv, 3);
}

/** 按显式合同版本解析平台分区参数，禁止 V3/V4 字段静默混用。 */
function parseArgumentsForContract(argv, contractVersion) {
  const values = parsePairs(argv, "GateHarness");
  const executionPartition = values.get("--execution-partition");
  const expectedNames = contractVersion === 4
    ? executionPartition === "portable"
      ? GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V4
      : executionPartition === "win32"
        ? GATE_HARNESS_WIN32_ARGUMENT_NAMES_V4
        : null
    : executionPartition === "portable"
      ? GATE_HARNESS_PORTABLE_ARGUMENT_NAMES_V3
      : executionPartition === "win32"
        ? GATE_HARNESS_WIN32_ARGUMENT_NAMES_V3
      : null;
  if (
    expectedNames === null ||
    values.size !== expectedNames.length ||
    expectedNames.some((key) => !values.has(key)) ||
    (contractVersion === 4 && values.get("--harness-contract-version") !== "4")
  ) {
    throw new Error("GateHarness 参数缺失或包含未知字段。\n");
  }
  return {
    artifactDirectory: path.resolve(values.get("--artifact-directory")),
    baseOid: values.get("--base-oid"),
    candidateRoot: path.resolve(values.get("--candidate-root")),
    controllerRepository: values.get("--controller-repository"),
    executionPartition,
    gateGid: executionPartition === "portable"
      ? parsePositiveInteger(values.get("--gate-gid"), "--gate-gid")
      : undefined,
    gateHome: path.resolve(values.get("--gate-home")),
    gateTempDirectory: path.resolve(values.get("--gate-temp-directory")),
    gateUid: executionPartition === "portable"
      ? parsePositiveInteger(values.get("--gate-uid"), "--gate-uid")
      : undefined,
    headOid: values.get("--head-oid"),
    hostPathInvocationAttestationPath: executionPartition === "win32" && contractVersion === 4
      ? parseAbsolutePath(
          values.get("--host-path-invocation-attestation"),
          "--host-path-invocation-attestation",
        )
      : undefined,
    objectFormat: values.get("--object-format"),
    providerRepositoryId: values.get("--provider-repository-id"),
    proposedRecordDirectory: parseAbsolutePath(
      values.get("--proposed-record-directory"),
      "--proposed-record-directory",
    ),
    pullNumber: parseNonNegativeInteger(values.get("--pull-number"), "--pull-number"),
    pathSentinelMarkerPath: executionPartition === "win32" && contractVersion === 4
      ? parseAbsolutePath(values.get("--path-sentinel-marker"), "--path-sentinel-marker")
      : undefined,
    trustedRecordPath: path.resolve(values.get("--trusted-record")),
    trustedPnpmExecutable: executionPartition === "win32" && contractVersion === 4
      ? parseAbsolutePath(
          values.get("--trusted-pnpm-executable"),
          "--trusted-pnpm-executable",
        )
      : undefined,
    win32PreflightArtifactPath: executionPartition === "win32" && contractVersion === 4
      ? parseAbsolutePath(
          values.get("--win32-preflight-artifact"),
          "--win32-preflight-artifact",
        )
      : undefined,
    workflowFile: values.get("--workflow-file"),
    workflowSha: values.get("--workflow-sha"),
  };
}

/** 将两个平台的分区 artifact 参数解析为封闭合并选项。 */
export function parseMergeArguments(argv) {
  const values = parsePairs(argv, "GateHarness 合并");
  if (
    values.size !== GATE_EVIDENCE_MERGE_ARGUMENT_NAMES_V1.length ||
    GATE_EVIDENCE_MERGE_ARGUMENT_NAMES_V1.some((key) => !values.has(key))
  ) {
    throw new Error("GateHarness 合并参数缺失或包含未知字段。\n");
  }
  let artifactPaths;
  try {
    artifactPaths = JSON.parse(values.get("--input-artifacts-json"));
  } catch {
    throw new Error("--input-artifacts-json 必须是 JSON 数组。");
  }
  if (
    !Array.isArray(artifactPaths) ||
    artifactPaths.length < 2 ||
    artifactPaths.some((artifactPath) =>
      typeof artifactPath !== "string" || !path.isAbsolute(artifactPath)
    )
  ) {
    throw new Error("--input-artifacts-json 必须包含至少两个绝对路径。");
  }
  return {
    artifactDirectory: path.resolve(values.get("--artifact-directory")),
    artifactPaths: artifactPaths.map((artifactPath) => path.normalize(artifactPath)),
  };
}

/** 将成对 CLI 参数解析为唯一键值映射。 */
function parsePairs(argv, label) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || values.has(key)) {
      throw new Error(`${label} 参数必须是唯一的 --key value 对。\n`);
    }
    values.set(key, value);
  }
  return values;
}

/** proposed 可信状态目录必须由 producer 传入绝对路径，禁止隐式依赖 cwd。 */
function parseAbsolutePath(value, name) {
  if (typeof value !== "string" || !path.isAbsolute(value)) {
    throw new Error(`${name} 必须是绝对路径。`);
  }
  return path.normalize(value);
}

/** 将 PR 编号解析为非负安全整数；push 使用 0，PR 使用真实编号。 */
function parseNonNegativeInteger(value, name) {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value ?? "")) {
    throw new Error(`${name} 必须是非负整数。`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${name} 超出安全整数范围。`);
  }
  return parsed;
}

/** 将 UID/GID 参数收敛为正安全整数，避免平台隐式转换。 */
function parsePositiveInteger(value, name) {
  if (!/^[1-9][0-9]*$/u.test(value ?? "")) {
    throw new Error(`${name} 必须是正整数。`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${name} 超出安全整数范围。`);
  }
  return parsed;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const argv = process.argv.slice(2);
    if (argv[0] === "merge") {
      const result = await mergeGateEvidenceArtifacts(parseMergeArguments(argv.slice(1)));
      console.log(JSON.stringify({
        artifactDigest: result.artifactDigest,
        evidenceCount: result.artifact.evidence.length,
        merged: true,
      }));
    } else {
      const result = await produceGateEvidence(parseArguments(argv));
      console.log(
        JSON.stringify({
          artifactDigest: result.artifactDigest,
          evidenceCount: result.artifact.evidence.length,
          passed: result.passed,
        }),
      );
      process.exitCode = result.passed ? 0 : 1;
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : "GateHarness 发生未知错误。");
    process.exitCode = 1;
  }
}
