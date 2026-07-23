import { spawn } from "node:child_process";
import path from "node:path";
import { sha256CanonicalJson } from "./canonical-json.mjs";

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
  const tokens = output.toString("utf8").split("\0");
  if (tokens.at(-1) === "") {
    tokens.pop();
  }
  if (tokens.length % 2 !== 0) {
    throw new Error("git diff --name-status -z 输出结构无效。");
  }
  const paths = [];
  for (let index = 0; index < tokens.length; index += 2) {
    const status = tokens[index];
    const relativePath = tokens[index + 1];
    if (!/^[ADMTCUXB]$/u.test(status) || !isSafeRelativePath(relativePath)) {
      throw new Error("git diff 返回未知状态或非法路径。");
    }
    paths.push(relativePath);
  }
  return [...new Set(paths)].sort();
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
function runGit(candidateRoot, args) {
  return new Promise((resolve, reject) => {
    const child = spawn("git", ["-C", candidateRoot, ...args], {
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code !== 0) {
        reject(
          new Error(
            `git ${args[0]} 失败（code=${code ?? "null"}, signal=${signal ?? "none"}）：${Buffer.concat(stderr).toString("utf8").trim()}`,
          ),
        );
        return;
      }
      resolve(Buffer.concat(stdout));
    });
  });
}
