import path from "node:path";
import { TextDecoder } from "node:util";
import { sha256CanonicalJson } from "./canonical-json.mjs";
import { runProcessWithDeadline } from "./run-process-with-deadline.mjs";

const gitTimeoutMs = 30_000;

/** 固定 provider 输入和 Git OID，构造确定性的 GateEvaluationContextV1。 */
export async function createEvaluationContext({
  baseOid,
  candidateRoot,
  gateRegistryDigest,
  headOid,
  objectFormat,
  providerRepositoryId,
}) {
  assertProviderContext({ baseOid, headOid, objectFormat, providerRepositoryId });
  const repositoryFormat = (await runGit(candidateRoot, ["rev-parse", "--show-object-format"]))
    .toString("utf8")
    .trim();
  if (repositoryFormat !== objectFormat) {
    throw new Error(`provider objectFormat=${objectFormat} 与候选 Git 仓库 ${repositoryFormat} 不一致。`);
  }
  const mergeBaseOutput = await runGit(candidateRoot, ["merge-base", "--all", baseOid, headOid]);
  const mergeBases = mergeBaseOutput
    .toString("utf8")
    .split(/\r?\n/u)
    .filter(Boolean)
    .sort();
  if (mergeBases.length === 0 || mergeBases.some((oid) => !isFullOid(oid, objectFormat))) {
    throw new Error("git merge-base --all 未返回合法完整 OID。\n");
  }
  const comparisonBaseOid = mergeBases[0];
  const contextWithoutDigest = {
    baseOid,
    comparisonBaseOid,
    gateRegistryDigest,
    headOid,
    objectFormat,
    providerRepositoryId,
    schemaVersion: 1,
  };
  return {
    affectedPaths: await readAffectedPaths(candidateRoot, comparisonBaseOid, headOid),
    evaluationContext: {
      ...contextWithoutDigest,
      evaluationContextDigest: sha256CanonicalJson(contextWithoutDigest),
    },
  };
}

/** 从固定 OID 的 NUL diff 读取相对 POSIX affected paths。 */
export async function readAffectedPaths(candidateRoot, comparisonBaseOid, headOid) {
  const output = await runGit(candidateRoot, [
    "diff",
    "--name-status",
    "-z",
    "--no-renames",
    comparisonBaseOid,
    headOid,
  ]);
  return [...new Set(parseNameStatusZ(output).map(({ path: relativePath }) => relativePath))].sort();
}

/** 严格解析 NUL name-status 字节，拒绝非法 UTF-8、状态和路径。 */
export function parseNameStatusZ(output) {
  if (output.length > 0 && output.at(-1) !== 0) {
    throw new Error("git diff --name-status -z 输出缺少末尾 NUL，可能已截断。");
  }
  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(output);
  } catch (error) {
    throw new Error("git diff 返回非法 UTF-8 路径字节。", { cause: error });
  }
  const tokens = decoded.split("\0");
  if (tokens.at(-1) === "") {
    tokens.pop();
  }
  if (tokens.length % 2 !== 0) {
    throw new Error("git diff --name-status -z 输出结构无效。");
  }
  const entries = [];
  for (let index = 0; index < tokens.length; index += 2) {
    const status = tokens[index];
    const relativePath = tokens[index + 1];
    if (!/^[ADMTCUXB]$/u.test(status) || !isSafeRelativePath(relativePath)) {
      throw new Error("git diff 返回未知状态或非法路径。");
    }
    entries.push({ path: relativePath, status });
  }
  return entries;
}

/** 校验 provider identity 与完整 Git OID。 */
function assertProviderContext({ baseOid, headOid, objectFormat, providerRepositoryId }) {
  if (
    !/^[1-9][0-9]*$/.test(providerRepositoryId) ||
    !["sha1", "sha256"].includes(objectFormat) ||
    !isFullOid(baseOid, objectFormat) ||
    !isFullOid(headOid, objectFormat)
  ) {
    throw new Error("provider repository identity、objectFormat 或完整 base/head OID 无效。\n");
  }
}

/** @param {string} oid @param {"sha1" | "sha256"} objectFormat */
function isFullOid(oid, objectFormat) {
  const length = objectFormat === "sha1" ? 40 : 64;
  return typeof oid === "string" && oid.length === length && /^[a-f0-9]+$/.test(oid);
}

/** 路径只能是仓库内相对 POSIX path。 */
function isSafeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !value.includes("\0") &&
    !value.includes("\\") &&
    !path.posix.isAbsolute(value) &&
    value.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..")
  );
}

/** 以 shell:false 执行固定 Git argv，并返回原始 stdout。 */
async function runGit(candidateRoot, args) {
  const result = await runProcessWithDeadline({
    args: createTrustedGitArguments(candidateRoot, args),
    cleanupProcessTreeOnExit: false,
    cwd: candidateRoot,
    executable: "git",
    timeoutMs: gitTimeoutMs,
  });
  if (result.stdoutTruncated || result.stderrTruncated) {
    throw new Error(`git ${args[0]} 输出超过受控上限，评估上下文 invalid。`);
  }
  if (result.status !== "pass") {
    throw new Error(
      `git ${args[0]} 失败（termination=${JSON.stringify(result.termination)}）：${result.stderr.toString("utf8").trim()}`,
    );
  }
  return result.stdout;
}

/** root Harness 仅为唯一候选路径设置命令级 safe.directory。 */
export function createTrustedGitArguments(candidateRoot, args) {
  return ["-c", `safe.directory=${candidateRoot}`, "-C", candidateRoot, ...args];
}
