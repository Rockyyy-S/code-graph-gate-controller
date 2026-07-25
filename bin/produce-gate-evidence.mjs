import path from "node:path";
import { fileURLToPath } from "node:url";
import { produceGateEvidence } from "../lib/harness.mjs";

/** GateHarness V2 的封闭 CLI 参数合同；producer 必须与不可变 Harness SHA 同步升级。 */
export const GATE_HARNESS_ARGUMENT_NAMES_V2 = Object.freeze([
  "--artifact-directory",
  "--base-oid",
  "--candidate-root",
  "--controller-repository",
  "--gate-gid",
  "--gate-home",
  "--gate-temp-directory",
  "--gate-uid",
  "--head-oid",
  "--object-format",
  "--provider-repository-id",
  "--proposed-record-directory",
  "--pull-number",
  "--trusted-record",
  "--workflow-file",
  "--workflow-sha",
]);

/** 将成对 CLI 参数解析为封闭选项对象。 */
export function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || values.has(key)) {
      throw new Error("GateHarness 参数必须是唯一的 --key value 对。\n");
    }
    values.set(key, value);
  }
  if (
    values.size !== GATE_HARNESS_ARGUMENT_NAMES_V2.length ||
    GATE_HARNESS_ARGUMENT_NAMES_V2.some((key) => !values.has(key))
  ) {
    throw new Error("GateHarness 参数缺失或包含未知字段。\n");
  }
  return {
    artifactDirectory: path.resolve(values.get("--artifact-directory")),
    baseOid: values.get("--base-oid"),
    candidateRoot: path.resolve(values.get("--candidate-root")),
    controllerRepository: values.get("--controller-repository"),
    gateGid: parsePositiveInteger(values.get("--gate-gid"), "--gate-gid"),
    gateHome: path.resolve(values.get("--gate-home")),
    gateTempDirectory: path.resolve(values.get("--gate-temp-directory")),
    gateUid: parsePositiveInteger(values.get("--gate-uid"), "--gate-uid"),
    headOid: values.get("--head-oid"),
    objectFormat: values.get("--object-format"),
    providerRepositoryId: values.get("--provider-repository-id"),
    proposedRecordDirectory: parseAbsolutePath(
      values.get("--proposed-record-directory"),
      "--proposed-record-directory",
    ),
    pullNumber: parseNonNegativeInteger(values.get("--pull-number"), "--pull-number"),
    trustedRecordPath: path.resolve(values.get("--trusted-record")),
    workflowFile: values.get("--workflow-file"),
    workflowSha: values.get("--workflow-sha"),
  };
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
    const result = await produceGateEvidence(parseArguments(process.argv.slice(2)));
    console.log(
      JSON.stringify({
        artifactDigest: result.artifactDigest,
        evidenceCount: result.artifact.evidence.length,
        passed: result.passed,
      }),
    );
    process.exitCode = result.passed ? 0 : 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : "GateHarness 发生未知错误。");
    process.exitCode = 1;
  }
}
